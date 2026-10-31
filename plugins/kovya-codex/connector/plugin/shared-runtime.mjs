import {managedPackageConfigured,resolveManagedPackage} from "../claude-code/client/kovya-managed-process.mjs";
import path from "node:path";
import * as fs from "node:fs";
import {createHash, randomUUID} from "node:crypto";
import {Worker} from "node:worker_threads";
import {availableParallelism} from "node:os";

const SCHEMA = "kovya.plugin-runtime-admission.v2";
// Payload digest: SHA-256 of UTF-8 JSON.stringify({version,files,entrypoints}).
// files are sorted by path (code-unit order), each {path,sha256}; entrypoint keys
// are ordered node,broker,native,client. No whitespace or final newline.
const HEX = /^[a-f0-9]{64}$/;
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const fail = reason => {throw Object.assign(new Error(reason), {code:"runtime_invalid", reason});};
const inside = (root, target) => {
  const rel = path.relative(root, target);
  return rel !== "" && rel !== ".." && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
};

// Check every existing ancestor, including links above home. Missing leaves may
// be admitted only by the acquisition path, never by a successful resolution.
function ordinary(target, kind, missing = false) {
  const absolute = path.resolve(target);
  let current = path.parse(absolute).root;
  for (const component of path.relative(current, absolute).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    let stat;
    try {stat = fs.lstatSync(current);} catch (error) {
      if (missing && error.code === "ENOENT") return false;
      throw error;
    }
    if (stat.isSymbolicLink()) fail("reparse_path");
    if (current !== absolute && !stat.isDirectory()) fail("ancestor_not_directory");
    if (current === absolute && !(kind === "directory" ? stat.isDirectory() : stat.isFile())) fail("wrong_file_type");
  }
  return true;
}
function canonicalDirectory(target) {
  // Refuse reparse ancestors BEFORE resolving physical spelling/8.3 aliases.
  ordinary(target,"directory",true);
  let ancestor=path.resolve(target);
  const tail=[];
  while (!fs.existsSync(ancestor)) {
    tail.unshift(path.basename(ancestor));
    ancestor=path.dirname(ancestor);
  }
  return path.join(fs.realpathSync.native(ancestor),...tail);
}
function relative(value) {
  if (typeof value !== "string" || !value || value.includes("\\") || value.includes(":")
      || value.split("/").some(part => !part || part === "." || part === "..")) fail("payload_path");
  return value;
}
function version(value) {
  if (typeof value !== "string" || !VERSION.test(value)) fail("version");
  const parts = value.split(".").map(Number);
  if (!parts.every(Number.isSafeInteger)) fail("version");
  return parts;
}
function descriptor(value) {
  if (!value || !Array.isArray(value.files) || !value.files.length || !HEX.test(value.digest)) fail("payload_descriptor");
  version(value.version);
  const seen = new Set();
  const files = value.files.map(file => {
    relative(file.path);
    if (!HEX.test(file.sha256) || seen.has(file.path.toLowerCase())) fail("payload_file");
    seen.add(file.path.toLowerCase());
    return {path:file.path, sha256:file.sha256};
  }).sort((a,b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  if (!value.entrypoints || Object.keys(value.entrypoints).sort().join(",") !== "broker,client,native,node") fail("payload_roles");
  const entrypoints = {};
  for (const role of ["node", "broker", "native", "client"]) {
    const entry = relative(value.entrypoints?.[role]);
    if (!files.some(file => file.path === entry)) fail("entrypoint_not_admitted");
    entrypoints[role] = entry;
  }
  const normalized = {version:value.version, files, entrypoints};
  if (hash(JSON.stringify(normalized)) !== value.digest) fail("payload_digest");
  return {...normalized,digest:value.digest};
}
function requirement(value) {
  version(value?.version); version(value?.minimum);
  if (!HEX.test(value?.digest) || version(value.minimum)[0] !== version(value.version)[0]) fail("requirement");
  return value;
}
function compatible(payload, requested) {
  const current = version(payload.version), minimum = version(requested.minimum);
  if (current[0] !== version(requested.version)[0]) return false;
  if (payload.digest === requested.digest) return true;
  for (let i=0;i<3;i++) if (current[i] !== minimum[i]) return current[i] > minimum[i];
  return true;
}
function json(file) {ordinary(file,"file"); return JSON.parse(fs.readFileSync(file,"utf8"));}
function verifyFiles(root, payload) {
  ordinary(root,"directory");
  // Reuse storage only within this pass; every file is freshly read and hashed.
  const buffer=Buffer.allocUnsafe(1024*1024);
  for (const file of payload.files) {
    const target = path.join(root,file.path);
    if (!inside(root,target)) fail("payload_escape");
    ordinary(target,"file");
    const digest=createHash("sha256"),fd=fs.openSync(target,"r");
    try {
      let count;
      while ((count=fs.readSync(fd,buffer,0,buffer.length,null)) > 0)
        digest.update(buffer.subarray(0,count));
    } finally {fs.closeSync(fd);}
    if (digest.digest("hex") !== file.sha256) fail("payload_bytes");
  }
}
// Scheduling is shared by every runtime object in this fixed loaded module.
// There is no cached verdict: each queued call captures and verifies afresh.
let verificationQueue=Promise.resolve();
const workerProgram=[
  'const fs=require("node:fs"),path=require("node:path"),{createHash}=require("node:crypto"),{workerData,parentPort}=require("node:worker_threads");',
  `const fail=${fail.toString()};`, `const inside=${inside.toString()};`,
  ordinary.toString(), verifyFiles.toString(),
  'const cursor=new BigInt64Array(workerData.cursor);',
  'const files={[Symbol.iterator]:function*(){for(;;){const index=Atomics.add(cursor,0,1n);if(index>=BigInt(workerData.files.length))return;yield workerData.files[Number(index)];}}};',
  'try {verifyFiles(workerData.root,{files});parentPort.postMessage({ok:true});} catch(error) {parentPort.postMessage({ok:false,reason:error.reason??null,code:error.code??null});}'
].join("\n");
async function verifyFilesAsync(root,payload) {
  if(payload.files.length<128) {verifyFiles(root,payload);return;}
  const jobs=[];let timer=null,timedOut=false;
  try {
    // Each pass owns its allocator. Claiming work conveys no verification result.
    // The unchanged verifier checks every claimed file before a worker may exit OK.
    const workerCount=Math.max(8,Math.min(16,availableParallelism()));
    const cursor=new BigInt64Array(new SharedArrayBuffer(BigInt64Array.BYTES_PER_ELEMENT));
    for(let index=0;index<workerCount;index++) {
      const worker=new Worker(workerProgram,{eval:true,execArgv:[],argv:[],env:{},
        stdout:true,stderr:true,trackUnmanagedFds:true,workerData:{root,files:payload.files,cursor:cursor.buffer}});
      const completion=new Promise(resolve=>{
        let reply=null,messages=0,unexpected=false;
        const stop=()=>{unexpected=true;void worker.terminate();};
        worker.stdout.on("data",stop);worker.stderr.on("data",stop);
        worker.on("error",()=>{unexpected=true;});
        worker.on("message",value=>{reply=value;if(++messages!==1)stop();});
        worker.once("exit",code=>resolve({code,reply,messages,unexpected}));
      });
      jobs.push({worker,completion});
    }
    timer=setTimeout(()=>{timedOut=true;for(const job of jobs)void job.worker.terminate();},5000);
    const results=await Promise.all(jobs.map(job=>job.completion));
    if(timedOut)fail("runtime_verification_timeout");
    for(const result of results) {
      if(result.code!==0 || result.unexpected || result.messages!==1 || !result.reply
          || typeof result.reply.ok!=="boolean")fail("runtime_verification_failed");
      if(!result.reply.ok) {
        const reasons=["payload_escape","payload_bytes","reparse_path","ancestor_not_directory","wrong_file_type"];
        fail(reasons.includes(result.reply.reason)?result.reply.reason:"admission_unreadable");
      }
      if(Object.keys(result.reply).join(",")!=="ok")fail("runtime_verification_failed");
    }
    // Every clean worker made one terminal claim beyond the descriptor list.
    if(Atomics.load(cursor,0)!==BigInt(payload.files.length+workerCount))fail("runtime_verification_failed");
  } finally {
    clearTimeout(timer);
    // Exit, including unmanaged-fd cleanup, is required before releasing the queue.
    await Promise.allSettled(jobs.map(job=>job.worker.terminate()));
  }
}
// The caller supplies release-pinned descriptors, never user-entered paths or
// digests. There is intentionally no download, native execution or lock fallback.
// Entrypoints MUST resolve first and reuse an admitted compatible runtime. Call
// acquire only for a missing runtime; invalid/incomplete states require explicit
// repair (next integration slice). Acquisition is not an upgrade/repair API.
export function createSharedRuntime({home, packageRoots = [], env = {}, admitRuntime, spawnImpl, inspectAccount, inspectHost}) {
  if(managedPackageConfigured()) {
    const resolve=()=>{try{return resolveManagedPackage(home);}catch(error){return {state:"runtime_invalid",reason:error.reason??"msix_resolution_failed"};}};
    return Object.freeze({resolve,resolveAsync:async()=>resolve(),acquire:async()=>({state:"runtime_invalid",reason:"msix_deployment_required"}),
      launch:()=>({state:"runtime_invalid",reason:"msix_native_launcher_required"}),status:()=>resolve()});
  }

  if (!path.isAbsolute(home)) fail("home_relative");
  const callerHome=path.resolve(home);
  let runtime,state,admissionPath,currentPath,canonicalPackages;
  function refreshHome() {
    home=canonicalDirectory(callerHome);
    canonicalPackages=packageRoots.map(root=>{
      if (!path.isAbsolute(root)) fail("package_root_relative");
      const canonical=canonicalDirectory(root);
      if (canonical === home || inside(canonical,home) || inside(home,canonical)) fail("package_home_overlap");
      return canonical;
    });
    runtime=path.join(home,"runtime");
    state=path.join(home,"state","runtime");
    admissionPath=path.join(state,"admission.json");
    currentPath=path.join(runtime,"current");
  }
  refreshHome();

  function inspectResolution(requested) {
    requirement(requested);
    refreshHome();
    if (!ordinary(home,"directory",true)) return {state:"never_started"};
    if (fs.readdirSync(home).length === 0) return {state:"never_started"};
    if (!ordinary(currentPath,"file",true)) return {state:"runtime_missing"};
    try {
      const current = json(currentPath), admission = json(admissionPath);
      const payload = descriptor(admission.payload);
      if (admission.schema_version !== SCHEMA || admission.installation_root !== home
          || !HEX.test(admission.owner_sid_hash) || !Number.isFinite(Date.parse(admission.admitted_at))
          || current.version !== payload.version || current.digest !== payload.digest) fail("admission_binding");
      if (!compatible(payload,requested)) fail("version_skew");
      const root = path.join(runtime,payload.version);
      return {state:"runtime_admitted",root,payload,owner_sid_hash:admission.owner_sid_hash,
        paths:Object.fromEntries(Object.entries(payload.entrypoints).map(([role,file])=>[role,path.join(root,file)]))};
    } catch (error) {return {state:"runtime_invalid",reason:error.reason ?? "admission_unreadable"};}
  }

  function resolve(requested) {
    const admitted=inspectResolution(requested);
    if(admitted.state!=="runtime_admitted")return admitted;
    try {verifyFiles(admitted.root,admitted.payload);return admitted;}
    catch(error){return {state:"runtime_invalid",reason:error.reason??"admission_unreadable"};}
  }
  function resolveAsync(requested) {
    const work=async()=>{
      const admitted=inspectResolution(requested);
      if(admitted.state!=="runtime_admitted")return admitted;
      try {
        await verifyFilesAsync(admitted.root,admitted.payload);
        if(JSON.stringify(inspectResolution(requested))!==JSON.stringify(admitted))fail("admission_binding");
        return admitted;
      } catch(error){return {state:"runtime_invalid",reason:error.reason??"admission_unreadable"};}
    };
    const result=verificationQueue.then(work);
    verificationQueue=result.catch(()=>{});
    return result;
  }

  async function acquire(input, sourceRoot) {
    const payload = descriptor(input);
    if (typeof admitRuntime !== "function") fail("acquisition_adapter_required");
    if (!path.isAbsolute(sourceRoot)) fail("source_relative");
    // Refuse altered source even if another runtime is already admitted.
    verifyFiles(sourceRoot,payload);
    refreshHome();
    ordinary(home,"directory",true);
    ordinary(state,"directory",true);
    fs.mkdirSync(state,{recursive:true});
    // A concurrent creator may have chosen different physical casing for home.
    refreshHome();
    ordinary(state,"directory");
    ordinary(runtime,"directory",true); fs.mkdirSync(runtime,{recursive:true});
    const stage=path.join(runtime,`${payload.version}.staging-${randomUUID().replaceAll("-","")}`);
    fs.mkdirSync(stage);
    // Node owns only its unique stage. It never renames a target or writes
    // admission/current, including after helper timeout or owner death.
    for (const file of payload.files) {
      const source=path.join(sourceRoot,file.path), destination=path.join(stage,file.path);
      ordinary(source,"file");fs.mkdirSync(path.dirname(destination),{recursive:true});
      ordinary(path.dirname(destination),"directory");
      fs.copyFileSync(source,destination,fs.constants.COPYFILE_EXCL);
    }
    verifyFiles(stage,payload);
    let reply;
    try {reply=await admitRuntime({home,stage,payload});}
    catch(error) {
      if(error?.reason!=="native_admission_unconfirmed") throw error;
      // A transport timeout may occur after publication. Inspect before any
      // retry; this call never blindly acquires again or deletes its stage.
      const observed=resolve({version:payload.version,minimum:payload.version,digest:payload.digest});
      return {state:"runtime_invalid",reason:"native_admission_unconfirmed",observed_runtime:observed.state,stage};
    }
    if (!["published","current_present"].includes(reply?.state)) return {state:"runtime_invalid",reason:reply?.state==="refused" ? reply.reason : reply?.state ?? "native_admission_unconfirmed",stage};
    const result=resolve({version:payload.version,minimum:payload.version,digest:payload.digest});
    if(result.state!=="runtime_admitted") return {...result,requested_version:payload.version,current_version:reply.current?.version};
    return {...result,leftover_stages:reply.leftover_stages ?? []};
  }

  function launch(requested) {
    const admitted = resolve(requested);
    if (admitted.state !== "runtime_admitted") return admitted;
    if (typeof spawnImpl !== "function") fail("launch_adapter_required");
    const systemRoot=env.SystemRoot ?? env.WINDIR;
    if (typeof systemRoot !== "string" || !path.isAbsolute(systemRoot)) fail("system_root_required");
    const launchEnv={};
    for (const key of ["SystemRoot","WINDIR","ProgramFiles","USERPROFILE","HOME","USERDOMAIN","USERNAME","SESSIONNAME"]) {
      if (typeof env[key] === "string") launchEnv[key]=env[key];
    }
    launchEnv.SystemRoot=systemRoot;
    launchEnv.WINDIR=env.WINDIR ?? systemRoot;
    launchEnv.PATH=[path.dirname(admitted.paths.node),path.join(systemRoot,"System32")].join(path.delimiter);
    launchEnv.KOVYA_HOME=home;
    launchEnv.KOVYA_WINDOWS_AUTH_MANIFEST=path.join(home,"windows-device-auth.json");
    launchEnv.KOVYA_WINDOWS_OWNER_SID_HASH=admitted.owner_sid_hash;
    // The allowlist excludes NODE_OPTIONS and caller PATH. Also reject a cache
    // supplied as a normally legitimate profile/system environment path.
    for (const value of Object.values(launchEnv)) {
      for (const segment of value.split(path.delimiter)) {
        if (!path.isAbsolute(segment)) continue;
        let candidate;
        if (fs.existsSync(segment) && fs.lstatSync(segment).isFile()) {
          ordinary(segment,"file");
          candidate=fs.realpathSync.native(segment);
        } else candidate=canonicalDirectory(segment);
        if (canonicalPackages.some(root=>candidate === root || inside(root,candidate))) fail("package_environment_path");
      }
    }
    const child = spawnImpl(admitted.paths.node,[admitted.paths.broker,"--serve","--home",home],{
      detached:true,shell:false,windowsHide:true,stdio:"ignore",env:launchEnv});
    child.unref();
    return {state:"runtime_admitted",child};
  }
  function status(requested, host) {
    const admitted = resolve(requested);
    const report = {state:admitted.state,runtime:admitted.state,saving:"unverified",recall:"unverified"};
    if (admitted.state !== "runtime_admitted") return report;
    // A manifest's existence is not authentication evidence. The owning account
    // adapter must validate the manifest and broker paths before returning true.
    if (inspectAccount?.({home,admitted}) !== true) return report;
    report.state = "signed_in";
    if (inspectHost?.({home,admitted,host}) === true) report.state = "host_ready";
    return report;
  }
  return Object.freeze({resolve,resolveAsync,acquire,launch,status});
}

export function verifyRuntimePayload(root,value){const payload=descriptor(value);verifyFiles(root,payload);return payload;}
