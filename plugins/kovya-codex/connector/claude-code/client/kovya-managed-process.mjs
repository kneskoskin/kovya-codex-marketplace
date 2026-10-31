import profileBinding from "./kovya-profile-binding.generated.mjs";
import packageBinding from "./kovya-package-binding.generated.mjs";
import {createRequire} from "node:module";
import {spawn,spawnSync} from "node:child_process";
import {readFileSync,lstatSync,realpathSync} from "node:fs";
import {createHash} from "node:crypto";
import {fileURLToPath} from "node:url";
import path from "node:path";
import {createManagedProcessStreams} from "./kovya-managed-process-streams.mjs";
import {validateMsixRelease,validateMsixSelection} from "../../plugin/msix-contract.mjs";
import {verifyRuntimePayload} from "../../plugin/shared-runtime.mjs";

const hash=b=>createHash("sha256").update(b).digest("hex");
const fail=reason=>{throw Object.assign(new Error(reason),{code:"runtime_invalid",reason});};
const same=(a,b)=>typeof a==="string" && typeof b==="string" && path.resolve(a).toLowerCase()===path.resolve(b).toLowerCase();
const root=path.resolve(fileURLToPath(new URL("../../../",import.meta.url)));
let owned;
export const managedPackageConfigured=()=>packageBinding!==null;
function ordinary(file) {
  let current=path.parse(file).root;
  for(const part of path.relative(current,file).split(path.sep).filter(Boolean)) {
    current=path.join(current,part);const stat=lstatSync(current);
    if(stat.isSymbolicLink() || (current===file?!stat.isFile():!stat.isDirectory()))fail("msix_nonordinary");
  }
}
function json(file){ordinary(file);const bytes=readFileSync(file);if(bytes.length>262144)fail("msix_record_size");return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));}
function identity(release) {
  if(!packageBinding || packageBinding.schema_version!=="kovya.package-binding.v1" || !Object.isFrozen(packageBinding)
    || !/^[a-f0-9]{64}$/.test(packageBinding.addon_sha256))fail("msix_binding_required");
  for(const key of ["name","publisher","family","full_name","version","architecture","alias"])
    if(packageBinding.identity?.[key]!==release[key])fail("msix_fixed_identity_disagreement");
}
function load() {
  if(owned)return owned;
  if(!managedPackageConfigured())fail("msix_binding_required");
  const addonPath=fileURLToPath(new URL("./kovya_managed_process.node",import.meta.url));ordinary(addonPath);
  if(hash(readFileSync(addonPath))!==packageBinding.addon_sha256)fail("msix_addon_bytes");
  const native=createRequire(import.meta.url)(addonPath);
  if(native.test_build!==false)fail("msix_test_build_refused");
  const observation=native.load(),context=JSON.parse(observation.handoff);
  if(context.schema_version!=="kovya.msix-custody.v1" || !same(context.root,root)
    || !same(realpathSync.native(process.execPath),path.join(root,"runtime/node/node.exe"))
    || observation.process_package_full_name!==packageBinding.identity?.full_name
    || context.package_full_name!==observation.process_package_full_name || !/^[a-f0-9]{64}$/.test(context.owner_sid_hash)
    || !Array.isArray(context.guards) || context.guards.length>4096)fail("msix_custody_disagreement");
  const release=validateMsixRelease(json(path.join(root,"../kovya-release.json")));identity(release);
  if(context.payload_digest!==release.payload_digest)fail("msix_custody_disagreement");
  const payload=json(path.join(root,"../kovya-descriptor.json"));verifyRuntimePayload(root,payload);
  const guards=new Set(context.guards.map(g=>path.resolve(g.path).toLowerCase()));
  if(guards.size!==context.guards.length)fail("msix_custody_duplicate");
  for(const name of [...payload.files.map(f=>path.join(root,f.path)),path.join(root,"../AppxManifest.xml"),path.join(root,"../kovya-release.json"),path.join(root,"../kovya-descriptor.json")]) {
    let target=path.resolve(name);
    for(;;){if(!guards.has(target.toLowerCase()))fail("msix_custody_incomplete");const parent=path.dirname(target);if(parent===target)break;target=parent;}
  }
  native.adopt(context);
  owned={native,context:Object.freeze({...context}),streams:createManagedProcessStreams(native)};
  return owned;
}
export function resolveManagedPackage(home) {
  const {native,context}=load();
  if(home!==undefined&&!same(home,context.home))fail("msix_home_disagreement");
  const observation=native.observe();
  if(observation.package_full_name!==context.package_full_name || observation.package_family_name!==packageBinding.identity.family
    || observation.publisher!==packageBinding.identity.publisher || observation.registered!==true
    || !same(observation.install_path,path.dirname(root)) || observation.development_mode!==false
    || observation.main_package!==true || observation.filesystem!=="NTFS" || observation.drive_type!==3
    || !same(observation.install_path,observation.effective_path))fail("msix_registration_unconfirmed");
  const release=validateMsixRelease(json(path.join(root,"../kovya-release.json")));identity(release);
  const payload=json(path.join(root,"../kovya-descriptor.json"));verifyRuntimePayload(root,payload);
  if(payload.digest!==release.payload_digest || payload.digest!==context.payload_digest)fail("msix_descriptor_disagreement");
  validateMsixSelection(json(path.join(context.home,"state/runtime/selection-v3.json")),{release,home:context.home,ownerSidHash:context.owner_sid_hash});
  return {state:"runtime_admitted",root,home:context.home,payload,owner_sid_hash:context.owner_sid_hash,
    paths:Object.fromEntries(Object.entries(payload.entrypoints).map(([role,name])=>[role,path.join(root,name)])),msix:release};
}
export function spawnNative(executable,argv,configuration,fallback=spawn) {
  if(profileBinding!==null)fail("profile_work_owner_required");
  if(!managedPackageConfigured())return fallback(executable,argv,configuration);
  const admitted=resolveManagedPackage();
  if(!same(executable,admitted.paths.native))fail("msix_native_target_refused");
  return load().streams.spawn(executable,argv,configuration);
}
export function spawnNativeSync(executable,argv,configuration,fallback=spawnSync) {
  if(profileBinding!==null)fail("profile_work_owner_required");
  if(!managedPackageConfigured())return fallback(executable,argv,configuration);
  const admitted=resolveManagedPackage();
  if(!same(executable,admitted.paths.native))fail("msix_native_target_refused");
  return load().streams.spawnSync(executable,argv,configuration);
}
