import {managedPackageConfigured,resolveManagedPackage} from "./kovya-managed-process.mjs";
import binding from "./kovya-native-binding.generated.mjs";
import {lstatSync,readFileSync,realpathSync} from "node:fs";
import path from "node:path";
import {createHash} from "node:crypto";
import {createSharedRuntime} from "../../plugin/shared-runtime.mjs";

const refuse=()=>{throw Object.assign(new Error("broker_native_identity_refused"),{code:"broker_native_identity_refused"});};
const normalize=value=>process.platform==="win32"?value.toLowerCase():value;
function ordinary(file) {
  let current=path.parse(file).root;
  for(const part of path.relative(current,file).split(path.sep).filter(Boolean)) {
    current=path.join(current,part);
    const stat=lstatSync(current);
    if(stat.isSymbolicLink() || (current===file?!stat.isFile():!stat.isDirectory())) refuse();
  }
}

// The fixed import above is the sole pin source. No argument, environment,
// admission record or executable-directory search can replace that binding.
function prepareBinding(executablePath,allowedRoles) {
  if(!binding || Object.keys(binding).sort().join(",")!=="expected_role,native_sha256"
      || !Object.isFrozen(binding) || !["bootstrap","managed_runtime","legacy_layout"].includes(binding.expected_role)
      || !allowedRoles.includes(binding.expected_role) || !/^[a-f0-9]{64}$/.test(binding.native_sha256)
      || typeof executablePath!=="string" || !path.isAbsolute(executablePath)
      || path.basename(executablePath).toLowerCase()!=="kovya_windows_broker_native.exe") refuse();
  ordinary(executablePath);
  const bytesHash=createHash("sha256").update(readFileSync(executablePath)).digest("hex");
  if(bytesHash!==binding.native_sha256)refuse();
  const codeRoot=path.resolve(path.dirname(executablePath),"..","..","..");
  let home=codeRoot,requested=null;
  if(binding.expected_role==="managed_runtime" && managedPackageConfigured()){const msixAdmitted=resolveManagedPackage();return {codeRoot,home:msixAdmitted.home,requested:null,msixAdmitted};}
  if(binding.expected_role==="managed_runtime") {
    home=path.dirname(path.dirname(codeRoot));
    const recordPath=path.join(home,"state/runtime/admission.json");
    ordinary(recordPath);
    const record=JSON.parse(readFileSync(recordPath,"utf8"));
    requested={version:record.payload.version,minimum:record.payload.version,digest:record.payload.digest};
  }
  return {codeRoot,home,requested};
}
function finishBinding(executablePath,candidate,admitted) {
  const {codeRoot}=candidate;let {home}=candidate;admitted=candidate.msixAdmitted??admitted;
  if(binding.expected_role==="bootstrap")return Object.freeze({...binding,codeRoot});
  if(binding.expected_role==="managed_runtime") {
    const nativeEntry=admitted.payload?.files.find(file=>file.path===admitted.payload.entrypoints.native);
    if(admitted.state!=="runtime_admitted" || normalize(admitted.root)!==normalize(codeRoot)
        || normalize(realpathSync.native(executablePath))!==normalize(admitted.paths.native)
        || nativeEntry?.sha256!==binding.native_sha256)refuse();
    home=admitted.home??path.dirname(path.dirname(admitted.root));
  }
  return Object.freeze({...binding,codeRoot,home,
    installationRootHash:createHash("sha256").update(home.toLowerCase(),"utf8").digest("hex")});
}
export function verifyNativeBinding(executablePath,allowedRoles) {
  try {
    const candidate=prepareBinding(executablePath,allowedRoles);
    const admitted=candidate.requested?createSharedRuntime({home:candidate.home}).resolve(candidate.requested):null;
    return finishBinding(executablePath,candidate,admitted);
  } catch {refuse();}
}
export async function verifyNativeBindingAsync(executablePath,allowedRoles) {
  try {
    const candidate=prepareBinding(executablePath,allowedRoles);
    const admitted=candidate.requested?await createSharedRuntime({home:candidate.home}).resolveAsync(candidate.requested):null;
    // Re-pin the selected file and agreement fields after the asynchronous interval.
    const current=prepareBinding(executablePath,allowedRoles);
    if(JSON.stringify(current)!==JSON.stringify(candidate))refuse();
    return finishBinding(executablePath,current,admitted);
  } catch {refuse();}
}
