import { createHash } from "node:crypto";
import { PRIVATE_MEMORY_MAX_TEXT_BYTES } from "../kovya-memory-wire-contract.mjs";
import { normalizeCapture } from "./host-events.mjs";

const TTL = 4 * 60 * 60 * 1000;
const digest = text => createHash("sha256").update(text).digest("hex");
const failure = reason => ({ ok: false, state: "capture_unconfirmed", reason });
function identity(input) {
  if (input?.host !== "codex" || [input.session_id, input.turn_id].some(value =>
    typeof value !== "string" || !value.trim() || value.length > 512 || /[\u0000-\u001f]/u.test(value))) {
    throw Object.assign(new Error("Invalid turn identity"), {code:"kovya_event_identity_required"});
  }
  return JSON.stringify([input.host,input.session_id,input.turn_id]);
}
function exact(input, keys) {
  if (Object.keys(input).sort().join(",") !== keys.sort().join(",")) {
    throw Object.assign(new Error("Invalid turn payload"), {code:"kovya_turn_payload_invalid"});
  }
}

// Owned by the resident broker, never by an individual hook process. No disk IO.
export function createTurnJoin({ capture, account, now = Date.now }) {
  const records = new Map(), expired = new Map();
  let binding = null;
  function discard(key, record) {
    record.prompt?.fill(0);
    records.delete(key);
  }
  function clear() {
    for (const [key,record] of records) discard(key,record);
    expired.clear();
    binding = null;
  }
  function sweep() {
    let current;
    try { current = account(); } catch { current = null; }
    if (!current || current !== binding) { clear(); binding = current; }
    for (const [key,record] of records) if (now() >= record.expires) {
      discard(key,record); expired.set(key,now()+TTL);
    }
    for (const [key,until] of expired) if (now() >= until) expired.delete(key);
    while (expired.size > 64) expired.delete(expired.keys().next().value);
    return Boolean(binding);
  }
  function prompt(input) {
    const key = identity(input);
    exact(input,["host","session_id","turn_id","prompt"]);
    if (typeof input.prompt !== "string" || !input.prompt.trim()
      || Buffer.byteLength(input.prompt,"utf8") > PRIVATE_MEMORY_MAX_TEXT_BYTES) {
      throw Object.assign(new Error("Invalid prompt"),{code:"kovya_prompt_invalid"});
    }
    if (!sweep()) return {state:"unavailable",turn_id:input.turn_id};
    const hash = digest(input.prompt), old = records.get(key);
    if (old) {
      records.delete(key); records.set(key,old);
      return {state:old.promptHash === hash ? "duplicate" : "conflict",turn_id:input.turn_id};
    }
    if (records.size >= 64) {
      const victim = [...records].find(([,record])=>!record.work);
      if (!victim) return {state:"unavailable",turn_id:input.turn_id};
      discard(...victim); expired.set(victim[0],now()+TTL);
    }
    expired.delete(key);
    records.set(key,{prompt:Buffer.from(input.prompt,"utf8"),promptHash:hash,expires:now()+TTL});
    return {state:"accepted",turn_id:input.turn_id};
  }
  async function join(input, options) {
    const key = identity(input);
    exact(input,["host","session_id","turn_id","assistant_text","transcript_bound"]);
    if (input.transcript_bound !== false || typeof input.assistant_text !== "string"
      || !input.assistant_text.trim() || Buffer.byteLength(input.assistant_text,"utf8") > PRIVATE_MEMORY_MAX_TEXT_BYTES) {
      return failure("kovya_assistant_missing");
    }
    if (!sweep()) return failure("runtime_missing");
    const record = records.get(key);
    if (!record) return failure(expired.has(key) ? "prompt_expired" : "prompt_missing");
    const assistantHash = digest(input.assistant_text.trim());
    if (record.assistantHash && record.assistantHash !== assistantHash) return failure("turn_conflict");
    if (record.receipt) return structuredClone(record.receipt);
    if (record.work) return record.work;
    record.assistantHash = assistantHash;
    const originalBinding = binding;
    const content = normalizeCapture("codex",{...input,last_assistant_message:input.assistant_text},
      {prompt:record.prompt.toString("utf8")});
    record.work = Promise.resolve().then(()=> {
      if (!sweep() || binding !== originalBinding || records.get(key) !== record) return failure("prompt_expired");
      return capture(content,options);
    }).then(result=>{
      if (!sweep() || binding !== originalBinding || records.get(key) !== record) return failure("prompt_expired");
      if (result?.ok === true && typeof result.content_sha256 === "string"
        && result.body?.durable_content === true && result.body.content_sha256 === result.content_sha256) {
        record.prompt.fill(0); delete record.prompt;
        record.receipt = {ok:true,content_sha256:result.content_sha256,
          body:{durable_content:true,content_sha256:result.content_sha256,
            ...(typeof result.body.capture_id === "string" && result.body.capture_id.length <= 512 ? {capture_id:result.body.capture_id} : {})}};
        return structuredClone(record.receipt);
      }
      return failure("capture_unconfirmed");
    }).finally(()=>{delete record.work;});
    return record.work;
  }
  function end(input) {
    identity({...input,turn_id:"session-end"});
    exact(input,["host","session_id","session_ended"]);
    if (input.session_ended !== true) throw Object.assign(new Error("Invalid session end"),{code:"kovya_turn_payload_invalid"});
    sweep();
    for (const [key,record] of records) {
      const [host,session] = JSON.parse(key);
      if (host === input.host && session === input.session_id) {discard(key,record);expired.set(key,now()+TTL);}
    }
  }
  return Object.freeze({prompt,join,sweep,clear,end});
}
