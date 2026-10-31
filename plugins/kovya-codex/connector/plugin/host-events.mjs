import { createHash } from "node:crypto";
import { PRIVATE_MEMORY_SOURCE_HOSTS } from "../kovya-memory-wire-contract.mjs";
import { buildCanonicalPrivateTurnContent } from "../claude-code/client/kovya-memory-client.mjs";

function identity(value) {
  if (typeof value !== "string" || !value.trim() || value.length > 512 || /[\u0000-\u001f]/u.test(value)) {
    throw new Error("kovya_event_identity_required");
  }
  return value;
}

export function requireHost(host) {
  if (!PRIVATE_MEMORY_SOURCE_HOSTS.includes(host)) throw new Error("kovya_host_required");
  return host;
}

export function messageText(content) {
  if (typeof content === "string") return content.trim() || null;
  if (!Array.isArray(content)) return null;
  return content.filter(block => ["text", "input_text", "output_text"].includes(block?.type) && typeof block.text === "string")
    .map(block => block.text.trim()).filter(Boolean).join("\n") || null;
}

// Only selected transcript data supplied by the host adapter, never an ambient corpus.
export function transcriptExchange(entries) {
  const rows = entries.filter(entry => !entry?.isMeta && !entry?.isCompactSummary && !entry?.isHarnessControl)
    .map(entry => ({ entry, role: entry?.message?.role ?? entry?.payload?.role ?? entry?.type,
      text: messageText(entry?.message?.content ?? entry?.payload?.content ?? entry?.content) }))
    .filter(row => ["user", "assistant"].includes(row.role) && row.text
      && !(row.role === "user" && /^(<command-|<local-command-|Caveat:)/u.test(row.text)));
  const last = rows.findLastIndex(row => row.role === "assistant");
  if (last < 0) throw new Error("kovya_assistant_missing");
  const user = rows.slice(0, last).findLast(row => row.role === "user");
  if (!user) throw new Error("kovya_user_missing");
  return { user_text: user.text, assistant_text: rows[last].text, assistant_id: rows[last].entry.uuid ?? rows[last].entry.id };
}

export function codexAssistant(input, entries = []) {
  const documented = messageText(input.last_assistant_message);
  if (documented) return documented;
  // A nullable Stop field cannot authorize the last answer from an older turn.
  const bound = entries.filter(entry => (entry?.turn_id ?? entry?.payload?.turn_id) === input.turn_id);
  const assistant = bound.findLast(entry => (entry?.message?.role ?? entry?.payload?.role ?? entry?.type) === "assistant");
  const text = messageText(assistant?.message?.content ?? assistant?.payload?.content ?? assistant?.content);
  if (!text) throw new Error("kovya_assistant_missing");
  return text;
}

export function normalizeCapture(host, input, { entries = [], prompt } = {}) {
  requireHost(host);
  const session = identity(input?.session_id);
  let turn;
  let exchange;
  if (host === "claude_code") {
    exchange = transcriptExchange(entries);
    turn = identity(exchange.assistant_id);
  } else if (host === "codex") {
    turn = identity(input?.turn_id);
    const assistant = codexAssistant(input,entries);
    if (prompt !== undefined) {
      if (!messageText(prompt)) throw new Error("kovya_user_missing");
      exchange = {user_text:prompt,assistant_text:assistant};
    } else {
      exchange = transcriptExchange(entries);
      if (assistant !== exchange.assistant_text) throw new Error("kovya_transcript_turn_mismatch");
    }
  } else {
    // OMP 18.1.11 exposes numeric loop turn_id; the persisted assistant entry id
    // additionally distinguishes loop restarts/resumes with repeated numeric ids.
    turn = identity(input?.assistant_entry_id);
    if (!Number.isSafeInteger(input.turn_id) || input.turn_id < 0) throw new Error("kovya_event_identity_required");
    exchange = transcriptExchange(entries);
    if (exchange.assistant_id !== turn || messageText(input.last_assistant_message?.content) !== exchange.assistant_text) {
      throw new Error("kovya_transcript_turn_mismatch");
    }
  }
  const content = buildCanonicalPrivateTurnContent({ source_host: host, ...exchange });
  const idempotency_key = `sha256:${createHash("sha256").update(JSON.stringify([host, session, turn, content])).digest("hex")}`;
  return { ...content, idempotency_key };
}
