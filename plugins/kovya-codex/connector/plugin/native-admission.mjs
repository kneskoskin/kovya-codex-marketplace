import {verifyNativeBinding} from "../claude-code/client/kovya-native-binding.mjs";
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {lstatSync,readFileSync} from "node:fs";
import path from "node:path";
import {TextDecoder} from "node:util";

const error = reason => Object.assign(new Error(reason),{code:"runtime_invalid",reason});
function ordinaryFile(file) {
  let cursor=path.parse(file).root;
  for(const part of path.relative(cursor,file).split(path.sep)) {
    cursor=path.join(cursor,part);const stat=lstatSync(cursor);
    if(stat.isSymbolicLink() || (cursor===file ? !stat.isFile() : !stat.isDirectory())) throw error("native_admission_path");
  }
  return lstatSync(file);
}
function processBudget(request,waitMs) {
  const root=request.stage ?? request.source_root;
  if(typeof root!=="string" || !path.isAbsolute(root) || !Array.isArray(request.payload?.files)) throw error("native_admission_input");
  let size=0;
  for(const file of request.payload.files) {
    if(typeof file.path!=="string" || file.path.includes("\\") || file.path.includes(":")
        || file.path.split("/").some(part=>!part || part==="." || part==="..")) throw error("native_admission_input");
    size+=ordinaryFile(path.join(root,file.path)).size;
    if(!Number.isSafeInteger(size)) throw error("native_admission_input_size");
  }
  // The descriptor contains paths/hashes, not byte counts. Measure the local
  // payload without changing its digest schema. Mutex wait and work budgets
  // are independent: at least 2 minutes, 2 seconds/MiB, capped at 15 minutes.
  return waitMs+10000+Math.min(900000,Math.max(120000,Math.ceil(size/(1024*1024))*2000));
}
// Selection and pin come from the release/bootstrap owner, not CLI/env input.
// This function never searches PATH, downloads, or falls back to another helper.
export function createNativeRuntimeAdmission({executablePath,expectedSha256,env={},spawnSyncImpl=spawnSync,waitMs=1000}) {
  if (!path.isAbsolute(executablePath) || path.basename(executablePath)!=="kovya_windows_broker_native.exe"
      || !/^[a-f0-9]{64}$/.test(expectedSha256) || !Number.isInteger(waitMs) || waitMs<0 || waitMs>30000) throw error("native_admission_configuration");
  return async function admitRuntime(request) {
    try {verifyNativeBinding(executablePath,["bootstrap"]);} catch {throw error("native_admission_digest");}
    ordinaryFile(executablePath);
    if(createHash("sha256").update(readFileSync(executablePath)).digest("hex")!==expectedSha256) throw error("native_admission_digest");
    const childEnv={};
    for(const key of ["SystemRoot","WINDIR"]) if(typeof env[key]==="string") childEnv[key]=env[key];
    if(!childEnv.SystemRoot && !childEnv.WINDIR) throw error("system_root_required");
    const bytes=Buffer.from(JSON.stringify({...request,wait_ms:waitMs}),"utf8");
    if(bytes.length>262144) throw error("native_admission_input_size");
    const child=spawnSyncImpl(executablePath,["admit-runtime",String(process.pid)],{
      env:childEnv,shell:false,windowsHide:true,encoding:"buffer",maxBuffer:512*1024,
      timeout:processBudget(request,waitMs),input:Buffer.from(bytes.toString("base64")+"\n","ascii"),stdio:["pipe","pipe","pipe"]});
    if(child.error || child.status!==0 || child.signal || child.stderr?.length) throw error("native_admission_unconfirmed");
    const text=new TextDecoder("utf-8",{fatal:true}).decode(child.stdout);
    const match=/^KOVYA_NATIVE_ADMISSION_V1\t([A-Za-z0-9+/]+={0,2})\n$/.exec(text);
    if(!match) throw error("native_admission_protocol");
    const encoded=Buffer.from(match[1],"base64");
    if(encoded.toString("base64")!==match[1]) throw error("native_admission_protocol");
    const reply=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(encoded));
    if(!Number.isInteger(child.pid) || reply.pid!==child.pid || reply.parent_pid!==process.pid
        || !["published","upgraded","current_present","admission_timeout","incomplete_acquisition","refused"].includes(reply.state)) throw error("native_admission_identity");
    if(reply.state==="refused" && (typeof reply.reason!=="string" || !/^[a-z][a-z0-9_]{0,63}$/.test(reply.reason))) throw error("native_admission_protocol");
    return reply;
  };
}
