import {fileURLToPath} from "node:url";
import path from "node:path";
import {createKovyaWindowsBrokerServer} from "../claude-code/client/kovya-windows-broker.mjs";
import * as memoryClient from "../claude-code/client/kovya-memory-client.mjs";
import {observeBrokerResidency,validateBrokerResidency} from "./broker-start.mjs";
import {profileWorkConfigured,residentProfileStartup} from "../claude-code/client/kovya-profile-process.mjs";

globalThis.__kovyaStartupCheckpoint?.("resident_first_line");
export function confirmBrokerStartup(gate,observed,pid=process.pid) {
  validateBrokerResidency(gate,pid);validateBrokerResidency(observed,pid);
  for(const field of ["broker_scope","pid","process_creation_filetime","image_path_sha256"])
    if(gate[field]!==observed[field]) throw Object.assign(new Error("broker_scope_unknown"),{code:"broker_scope_unknown"});
  return Object.freeze({...observed});
}
export async function startResidentBroker(server) {
  return server.start();
}
async function main() {
  const startup=profileWorkConfigured()?residentProfileStartup():null;
  if(profileWorkConfigured()&&!startup)throw new Error("profile_resident_required");
  const [flag,home,...extra]=process.argv.slice(2);
  if(flag!=="--home" || !path.isAbsolute(home) || extra.length) throw new Error("broker_start_refused");
  // Before account inspection, native host startup or endpoint publication.
  // An unpublished child exits on EOF/missing gate or a dead/stalled starter.
  const timer=setTimeout(()=>process.exit(1),startup?startup.remainingMs():1500);
  let bytes=0;const chunks=[];
  try {
    for await(const chunk of process.stdin) {
      bytes+=chunk.length;if(bytes>8192) throw new Error("broker_scope_unknown");
      chunks.push(chunk);
    }
    if(startup)startup.remainingMs();
    const gate=JSON.parse(Buffer.concat(chunks).toString("utf8"));
    const observed=profileWorkConfigured()
      ? await startup.observe()
      : observeBrokerResidency({home});
    const residency=confirmBrokerStartup(gate,observed);
    clearTimeout(timer);
    const server=createKovyaWindowsBrokerServer({home,memoryClient,brokerResidency:residency});
    await startResidentBroker(server);
    const stop=()=>server.stop().catch(()=>{});
    process.once("SIGINT",stop);process.once("SIGTERM",stop);
    process.exitCode=await server.waitForStop();
  } finally {clearTimeout(timer);}
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(()=>{process.exitCode=1;});
