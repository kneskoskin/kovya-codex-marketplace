import { requireHost, normalizeCapture, codexAssistant } from "./host-events.mjs";
import { inferRecallFreshnessPurpose, includeHistoryForRecallPurpose } from "../kovya-memory-wire-contract.mjs";

const OFFLINE = "Kovya memory is not active; saving and recall are unavailable.";

// Host adapters share the existing connector operations and recall renderer.
// Dependencies are explicit so synthetic acceptance never discovers credentials.
export async function dispatchHostEvent({ host, event, input, entries = [] }, { client, formatRecallPack, prepareHookContext }) {
  requireHost(host);
  if (!["SessionStart", "UserPromptSubmit", "Stop", "SessionEnd"].includes(event)) throw new Error("kovya_event_unsupported");
  if (typeof input?.session_id !== "string" || !input.session_id.trim()) throw new Error("kovya_event_identity_required");
  if (event === "SessionEnd") {
    if (host !== "codex" || typeof client.endTurnSession !== "function") return {ok:true,state:"skipped"};
    await client.endTurnSession({host,session_id:input.session_id,session_ended:true});
    return {ok:true,state:"session_released"};
  }
  if (event === "Stop") {
    let content;
    if (host === "codex" && (typeof client.retainTurnPrompt === "function" || entries.length === 0)) {
      if (typeof client.retainTurnPrompt !== "function") {
        return {ok:false,state:"capture_unconfirmed",reason:"runtime_missing",systemMessage:OFFLINE};
      }
      let assistant;
      try { assistant = codexAssistant(input,entries); }
      catch { return {ok:false,state:"capture_unconfirmed",reason:"kovya_assistant_missing",systemMessage:OFFLINE}; }
      content = {host,session_id:input.session_id,turn_id:input.turn_id,
        assistant_text:assistant,transcript_bound:false};
    } else content = normalizeCapture(host, input, { entries });
    const transcriptFallback=(result,error)=>!error&&content.transcript_bound===false&&entries.length>0
      &&["prompt_missing","prompt_expired","runtime_missing"].includes(result?.reason);
    let result;
    try { result = await client.capturePrivateMemory(content, { fetchTimeoutMs: 900,terminalFollowup:transcriptFallback }); }
    catch (error) {
      if(client.isTerminalEventFailure?.(error))throw error;
      const runtimeMissing = ["broker_unavailable","broker_native_missing","broker_start_failed"].includes(error?.code);
      return {ok:false,state:"capture_unconfirmed",reason:runtimeMissing ? "runtime_missing" : "capture_unconfirmed",systemMessage:OFFLINE};
    }
    if (transcriptFallback(result)) {
      result = await client.capturePrivateMemory(normalizeCapture(host,input,{entries}),{fetchTimeoutMs:900});
    }
    const saved = result?.ok === true && result.body?.durable_content === true
      && typeof result.content_sha256 === "string" && result.body.content_sha256 === result.content_sha256;
    return { ok: saved, state: saved ? "saved" : "capture_unconfirmed", ...(saved ? {} : { reason:result?.reason ?? "capture_unconfirmed", systemMessage: OFFLINE }) };
  }
  const query = event === "UserPromptSubmit" ? input.prompt : undefined;
  if (event === "UserPromptSubmit" && (typeof query !== "string" || !query.trim())) return { ok: true, state: "skipped" };
  let promptUnavailable = false;
  if (host === "codex" && event === "UserPromptSubmit" && typeof client.retainTurnPrompt === "function") {
    try {
      const retained = await client.retainTurnPrompt({host,session_id:input.session_id,turn_id:input.turn_id,prompt:query},{terminalFollowup:()=>true});
      promptUnavailable = !["accepted","duplicate"].includes(retained?.state);
    } catch (error) {
      if(client.isTerminalEventFailure?.(error))throw error;
      promptUnavailable = true;
    }
  }
  const purpose = event === "SessionStart" ? "agent_boot"
    : inferRecallFreshnessPurpose(query, { fallbackPurpose: "current_context" });
  const result = await client.recallMemory({ ...(query === undefined ? {} : { query }),
    retrieval_purpose: purpose, include_history: includeHistoryForRecallPurpose(purpose) },
  { fetchTimeoutMs: 700, sessionId: `${host}:${input.session_id}` });
  if (result?.ok !== true) return { ok: false, state: "recall_unavailable", systemMessage: OFFLINE };
  const formatted = formatRecallPack(result);
  if (formatted.degraded) return { ok: false, state: "recall_unverified", systemMessage: OFFLINE };
  return { ok: true, state: "recalled", ...(promptUnavailable ? {systemMessage:"Kovya recall succeeded, but this turn's saving is unconfirmed."} : {}), hookSpecificOutput: { hookEventName: event, additionalContext: prepareHookContext(event, formatted.text ?? "") } };
}
