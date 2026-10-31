#!/usr/bin/env node
// Installed as bin/kovya.mjs. npm only extracts files; this explicit command
// reuses native runtime admission and the existing host setup implementation.
import {readFileSync} from "node:fs";
import {createHash} from "node:crypto";
import path from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";

const root=fileURLToPath(new URL("../",import.meta.url));
const diagnosticHelp="Kovya could not finish. I will diagnose the problem before proposing a repair.";
const fail=reason=>({ok:false,state:"runtime_invalid",reason,
  message:reason==="incomplete_acquisition"?"Kovya may have updated, but completion could not be confirmed. I will diagnose it before any further action.":diagnosticHelp});
function packageLayout(){
  let layout;
  try {const bytes=readFileSync(path.join(root,"kovya-setup-layout.json"));if(bytes.length>1024)throw 0;layout=JSON.parse(bytes);}
  catch {throw Object.assign(new Error("runtime_setup_layout_invalid"),{reason:"runtime_setup_layout_invalid"});}
  const keys=Object.keys(layout).sort().join(",");
  if(layout.schema_version!=="kovya.setup-layout.v1" || !(layout.kind==="cohort"&&keys==="kind,schema_version"
    ||layout.kind==="selected_plugin"&&keys==="host,kind,node_sha256,schema_version,wrapper_sha256"&&["codex","claude_code"].includes(layout.host)
      &&/^[a-f0-9]{64}$/.test(layout.node_sha256)&&/^[a-f0-9]{64}$/.test(layout.wrapper_sha256)))
    throw Object.assign(new Error("runtime_setup_layout_invalid"),{reason:"runtime_setup_layout_invalid"});
  if(layout.kind==="selected_plugin"){
    const node=path.join(root,"runtime","payload","runtime","node","node.exe");
    const hash=bytes=>createHash("sha256").update(bytes).digest("hex");
    if(path.resolve(process.execPath).toLowerCase()!==path.resolve(node).toLowerCase()
      ||hash(readFileSync(node))!==layout.node_sha256||hash(readFileSync(fileURLToPath(import.meta.url)))!==layout.wrapper_sha256)
      throw Object.assign(new Error("runtime_setup_pin_mismatch"),{reason:"runtime_setup_pin_mismatch"});
  }
  return layout;
}

async function main() {
  const [command,host,operation,...extra]=process.argv.slice(2);
  const layout=packageLayout();
  const adapterRoot=host=>layout.kind==="selected_plugin"?root:path.join(root,"plugins",host==="codex"?"kovya-codex":"kovya-claude");
  if(command==="diagnose"){
    if(operation!==undefined||extra.length||host!==undefined&&!/^(?:[1-9]\d?|1\d\d|200)$/.test(host))
      return {ok:false,state:"arguments_invalid",message:"Use kovya diagnose [1-200]."};
    const adapter=path.join(adapterRoot("codex"),"connector","plugin");
    const {resolvePluginLayout}=await import(pathToFileURL(path.join(adapter,"layout.mjs")).href);
    const {diagnoseLocal}=await import(pathToFileURL(path.join(adapter,"diagnose.mjs")).href);
    const report=await diagnoseLocal({home:resolvePluginLayout({packageRoot:root,env:process.env}).home,limit:host===undefined?100:Number(host)});
    return {ok:report.available,...report};
  }
  if(command!=="setup" || !["codex","claude_code"].includes(host)
      || !["connect","finish","status","repair","logout"].includes(operation) || extra.length)
    return {ok:false,state:"arguments_invalid",message:"Use kovya setup <codex|claude_code> <connect|finish|status|repair|logout>."};
  if(process.platform!=="win32")return {ok:false,state:"platform_unavailable",message:"This package supports Windows only."};
  if(layout.kind==="selected_plugin"&&host!==layout.host)return fail("runtime_setup_host_mismatch");
  const adapter=adapterRoot(host);
  const load=relative=>import(pathToFileURL(path.join(adapter,relative)).href);
  const {resolvePluginLayout}=await load("connector/plugin/layout.mjs");
  const {loadRuntimeRequirement}=await load("connector/plugin/runtime-requirement.mjs");
  const {createSharedRuntime}=await load("connector/plugin/shared-runtime.mjs");
  const {createNativeRuntimeAdmission}=await load("connector/plugin/native-admission.mjs");
  const {delegatePackageSetup}=await load("connector/plugin/setup.mjs");
  const requested=loadRuntimeRequirement();
  if(!requested)return fail("runtime_configuration_required");
  const {home}=resolvePluginLayout({packageRoot:root,env:process.env});
  const runtime=createSharedRuntime({home,packageRoots:[root]});
  let resolved=runtime.resolve(requested);
  // This observation precedes every native admission/delegation in this Connect.
  // It is an offer to request consent, never ownership or servicing eligibility.
  if(operation==="connect"&&resolved.state==="runtime_invalid"&&resolved.reason==="version_skew")
    return {...fail("version_skew"),
      message:"This Connect stopped at a Kovya runtime version mismatch. With your approval, Kovya can check whether a repair is permitted.",
      repair_guidance:{observation:"current_pre_effect_connect",action:"ask_one_go",
        question:"Would you like me to repair Kovya?",eligibility:"native_controller_required"}};
  // Only never_started proves an absent or empty home. runtime_missing can
  // coexist with account/recovery state and must not claim it was cleared.
  if(operation==="logout" && resolved.state==="never_started")
    return {ok:true,state:"signed_out",account:"signed_out",runtime:"not_installed",
      saving:"unverified",recall:"unverified",remote_revocation:"not_applicable",
      message:"Kovya is already signed out. No shared runtime is installed at this location."};
  const servicing=operation==="repair";
  if(servicing||["never_started","runtime_missing"].includes(resolved.state)) {
    if(!["connect","repair"].includes(operation))
      return {ok:false,state:"runtime_missing",message:diagnosticHelp};
    const bytes=readFileSync(path.join(root,"runtime","descriptor.json"));
    if(bytes.length>262144)return fail("runtime_descriptor_size");
    const payload=JSON.parse(bytes);
    const {digest,...canonical}=payload;
    if(digest!==requested.digest || payload.version!==requested.version
        || createHash("sha256").update(JSON.stringify(canonical)).digest("hex")!==digest)
      return fail("runtime_payload_binding");
    const executablePath=path.join(adapter,"connector","claude-code","client","kovya_windows_broker_native.exe");
    const admit=createNativeRuntimeAdmission({executablePath,expectedSha256:requested.native_helper_sha256,env:process.env,waitMs:1000});
    const reply=await admit({home,source_root:path.join(root,"runtime","payload"),payload,...(servicing?{operation:"upgrade"}:{})});
    if(!["published","upgraded","current_present"].includes(reply.state))
      return fail(reply.reason??reply.state);
    resolved=runtime.resolve(requested);
  }
  if(resolved.state!=="runtime_admitted")return fail(resolved.reason??resolved.state);
  if(servicing) {
    if(resolved.payload?.digest!==requested.digest||resolved.payload?.version!==requested.version)return fail("runtime_repair_unconfirmed");
    return {ok:true,state:"runtime_ready",continuation:"connect",message:"Kovya is updated. Continuing the original request."};
  }
  // Native output and protected stdin remain inherited and unchanged.
  // Guidance cannot authorize replay of an operation with an unknown outcome.
  process.exitCode=await delegatePackageSetup(host,operation);
  if(process.exitCode!==0)process.stderr.write(diagnosticHelp+"\n");
  return null;
}

try {
  const result=await main();
  if(result!==null){process.stdout.write(JSON.stringify(result)+"\n");process.exitCode=result.ok?0:1;
    if(!result.ok&&process.argv[2]!=="diagnose")process.stderr.write(diagnosticHelp+"\n");}
} catch(error) {
  process.stdout.write(JSON.stringify(fail(error.reason??error.code??"runtime_setup_unconfirmed"))+"\n");
  process.exitCode=1;
  if(process.argv[2]!=="diagnose")process.stderr.write(diagnosticHelp+"\n");
}
