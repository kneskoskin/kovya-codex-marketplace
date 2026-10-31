// Loaded by the verified native bootstrap before the application entrypoint.
import binding from "./kovya-profile-binding.generated.mjs";
import {createRequire} from "node:module";
import {readFileSync,realpathSync} from "node:fs";
import {createHash} from "node:crypto";
import path from "node:path";
import {fileURLToPath} from "node:url";
const fail=reason=>{throw new Error(reason);};
const root=path.resolve(fileURLToPath(new URL("../../../",import.meta.url)));
const same=(a,b)=>typeof a==="string"&&typeof b==="string"&&path.resolve(a).toLowerCase()===path.resolve(b).toLowerCase();
if(!binding||!Object.isFrozen(binding)||binding.schema_version!=="kovya.profile-binding.v1"||! /^[a-f0-9]{64}$/.test(binding.addon_sha256))fail("profile_binding_required");
const addon=fileURLToPath(new URL("./kovya_profile_startup.node",import.meta.url));
if(createHash("sha256").update(readFileSync(addon)).digest("hex")!==binding.addon_sha256)fail("profile_addon_digest");
const native=createRequire(import.meta.url)(addon);
const context=native.initialize();
if(!same(context.root,root)||!same(realpathSync.native(process.execPath),path.join(root,"runtime/node/node.exe")))fail("profile_root_disagreement");
const admission=JSON.parse(readFileSync(path.join(context.home,"state/runtime/admission.json"),"utf8"));
const payload=admission.payload;
if(payload?.digest!==context.payload_digest||!same(admission.installation_root,context.home))fail("profile_admission_disagreement");
// Native startup verified every file while retaining its exact file/ancestor
// handles. Recheck the descriptor binding and coverage, not those file bytes.
const canonical={version:payload.version,files:payload.files,entrypoints:payload.entrypoints};
if(createHash("sha256").update(JSON.stringify(canonical)).digest("hex")!==context.payload_digest)fail("profile_payload_digest");
const guards=new Set(context.guards.map(g=>path.resolve(g).toLowerCase()));
for(const file of payload.files){
 let cursor=path.resolve(root,file.path);
 for(;;){if(!guards.has(cursor.toLowerCase()))fail("profile_guard_incomplete");const parent=path.dirname(cursor);if(parent===cursor)break;cursor=parent;}
}
// argv selects an attempt only; native.prepareAccountWorker verifies the
// bootstrap-sealed purpose and cannot grant startup authority to other modes.
if(same(process.argv[1],path.join(root,"connector/plugin/setup.mjs"))&&process.argv.length===4&&["connect","finish"].includes(process.argv[3])){
 const {prepareProfileAccountWorker}=await import("./kovya-profile-process.mjs");
 await prepareProfileAccountWorker();
}
globalThis.__kovyaStartupCheckpoint=stage=>{try{native.timingCheckpoint(stage);}catch{}};
globalThis.__kovyaStartupCheckpoint("preload_first_line");
native.finishStartup();
