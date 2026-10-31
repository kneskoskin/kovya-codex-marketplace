#!/usr/bin/env node
import {WORKER_EXIT_MS} from "./request-budget.mjs";
import { readFileSync, statSync } from "node:fs";
import { pathToFileURL, fileURLToPath } from "node:url";
import path from "node:path";
import { resolvePluginLayout } from "./layout.mjs";
import { dispatchHostEvent } from "./dispatch.mjs";
import {bindPluginBrokerClient} from "./broker-start.mjs";
import { requireHost } from "./host-events.mjs";
import {observeDiagnosticIngress} from "./diagnostic-lifecycle.mjs";
import {projectOutcomeEvidence,hasOutcomeEvidence} from "../claude-code/client/kovya-phase-authority.mjs";
import {diagnosticStage} from "./diagnostic-events.mjs";
import {operationTerminalReceipt} from "./terminal-operation.mjs";

globalThis.__kovyaStartupCheckpoint?.("worker_first_line");
const MAX_BYTES = 4 * 1024 * 1024;
let cleanExit = () => { process.exitCode = 0; process.stdin.destroy(); };
export function workerRefusal(error) {
  const receipt=operationTerminalReceipt(error);
  const code = receipt?.terminal.reason ?? (typeof error?.code === "string" && /^[a-z][a-z0-9_]{1,80}$/u.test(error.code) ? error.code : "broker_unavailable");
  const evidence=projectOutcomeEvidence(error,'client');
  let systemMessage;
  if (code === "broker_cold_start") systemMessage = "Kovya memory is starting; ask again in a moment.";
  else if (code === "broker_start_cooldown") systemMessage = "Kovya memory is starting; try again in a few seconds.";
  else if(code==='broker_outcome_unknown')systemMessage=evidence.retry_may_duplicate===true?'Saving is unconfirmed. A retry may duplicate this capture; do not claim it was saved.':'Kovya could not confirm the request outcome.';
  else if (code === "broker_deadline_refused") systemMessage = "Kovya memory did not answer in time; ask again.";
  else if (code === "profile_work_ended") systemMessage = "Kovya memory's request ended before it could finish; ask again.";
  else if (code === "profile_cleanup_uncertain") systemMessage = "Kovya memory could not finish safely. Restart the host and repair Kovya before trying again.";
  else if (code.startsWith("account_state_")) systemMessage = "Kovya could not verify sign-in state. Sign in again or repair Kovya.";
  else if (code.startsWith("broker_owner_") || code === "broker_native_peer_refused") systemMessage = "Kovya could not verify this Windows account. Sign in again or repair Kovya.";
  else if (code === "profile_work_owner_required") systemMessage = "Kovya could not verify request ownership. Restart the host and repair Kovya.";
  else if (["broker_native_identity_refused", "broker_runtime_incompatible", "broker_scope_unknown"].includes(code)) systemMessage = "Kovya could not verify this installation. Repair Kovya before trying again.";
  else systemMessage = "Kovya memory is unavailable; check sign-in or repair the installation.";
  return {ok:false,state:"unavailable",error_code:code,systemMessage,...((code==='broker_outcome_unknown'||hasOutcomeEvidence(error))?{last_verified_phase:evidence.last_verified_phase,retry_may_duplicate:evidence.retry_may_duplicate,phase_observation:evidence}:{}),...(receipt?{ok:receipt.terminal.ok,state:receipt.terminal.state,reason:receipt.terminal.reason,stage:receipt.terminal.phase,diagnostics:receipt}:{})};
}
export async function runWorker({ host, event, input }) {
  const env = process.env;
  requireHost(host);
  const layout = resolvePluginLayout({ env });
  // This worker is a short-lived subprocess, never imported into a harness process.
  // Existing connector modules still use env configuration; never set plugin roots as state.
  env.KOVYA_HOME = layout.home;
  env.KOVYA_WINDOWS_AUTH_MANIFEST = layout.authManifest;
  env.KOVYA_MEMORY_CLIENT_PATH = process.platform === "win32" ? layout.brokerClient : layout.client;
  const common = await import("../claude-code/hooks/lib/kovya_hook_common.mjs");
  cleanExit = common.exitHookCleanly;
  let entries = input.entries ?? [];
  if (event === "Stop" && host !== "omp" && !(host === "codex" && input.transcript_path == null)) {
    try {
      if (typeof input.transcript_path !== "string" || !path.isAbsolute(input.transcript_path)) throw new Error("kovya_transcript_required");
      if (statSync(input.transcript_path).size > MAX_BYTES) throw new Error("kovya_transcript_too_large");
      entries = readFileSync(input.transcript_path, "utf8").split("\n").filter(line => line.trim()).map(line => JSON.parse(line));
    } catch (error) {
      if (host !== "codex") throw error;
      entries = []; // Codex's documented fields and resident join remain usable.
    }
  }
  const rawClient = await import(pathToFileURL(env.KOVYA_MEMORY_CLIENT_PATH));
  let brokerFailure=null;
  const client = process.platform === "win32" ? bindPluginBrokerClient(rawClient,{onFailure:error=>{brokerFailure=error;}}) : rawClient;
  const result = await dispatchHostEvent({ host, event, input, entries }, { client, formatRecallPack: common.formatRecallPack, prepareHookContext: common.prepareHookContext });
  return result?.ok === false && brokerFailure ? {...result,...workerRefusal(brokerFailure),state:result.state} : result;
}

async function main() {
  const [host, event] = process.argv.slice(2);
  return observeDiagnosticIngress({operation:"worker",host,host_event:event},async()=>{
  const input=await diagnosticStage("framing",async()=>{
  let bytes = 0;
  const chunks = [];
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > MAX_BYTES) throw new Error("kovya_input_too_large");
    chunks.push(chunk);
  }
    try{return JSON.parse(Buffer.concat(chunks).toString("utf8"));}
    catch{throw Object.assign(new Error("worker_input_invalid"),{code:"worker_input_invalid"});}
  });
  return runWorker({ host, event, input });
  },{unavailable:()=>process.stderr.write("Kovya diagnostics are unavailable for this event.\n")});
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let finished = false;
  const finish = result => {
    if (finished) return;
    finished = true;
    clearTimeout(deadline);
    process.stdout.write(JSON.stringify(result) + "\n");
    cleanExit();
  };
  const deadline = setTimeout(() => {
    finish({ ok: false, state: "timeout", systemMessage: "Kovya memory did not finish. Saving or recall is unconfirmed." });
  }, WORKER_EXIT_MS);
  main().then(finish).catch(error => finish(workerRefusal(error)));
}
