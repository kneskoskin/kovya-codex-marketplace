import {verifyNativeBinding} from "../claude-code/client/kovya-native-binding.mjs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import {loadRuntimeRequirement, runtimeConfigurationRequired} from "../plugin/runtime-requirement.mjs";
const launcher = fileURLToPath(new URL("../claude-code/client/kovya_windows_broker_native.exe", import.meta.url));
const OFFLINE = "Kovya memory is not active. The shared runtime or account needs repair.";

export function invokeWorker(event, input, { spawnImpl = spawn, requirementLoader = loadRuntimeRequirement, platform = process.platform } = {}) {
  if (!requirementLoader()) return Promise.resolve(runtimeConfigurationRequired());
  if (platform !== "win32") return Promise.resolve({ok:false,state:"platform_unavailable",systemMessage:OFFLINE});
  return new Promise(resolve => {
    let done = false;
    let output = "";
    let child;
    let timer;
    const finish = result => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(result);
    };
    const fail = () => finish({ ok: false, state: "unavailable", systemMessage: OFFLINE });
    try {
      // OMP runs on Bun; process.execPath would launch Bun, not the declared Node runtime.
      verifyNativeBinding(launcher,["bootstrap"]);
      child = spawnImpl(launcher, ["launch", "worker", "omp", event], { windowsHide: true, shell: false, stdio: ["pipe", "pipe", "pipe"] });
      timer = setTimeout(() => { child.kill(); fail(); }, 3000);
      child.on("error", error => {
        if (error.code === "ENOENT") finish({ok:false,state:"runtime_missing",systemMessage:"The Kovya package launcher is missing. Obtain a complete configured release."});
        else fail();
      });
      child.stdin.on("error", fail);
      child.stderr.on("data", () => {}); // Never expose credential/transport internals.
      child.stdout.on("data", chunk => {
        output += chunk.toString();
        if (Buffer.byteLength(output) > 128 * 1024) { child.kill(); fail(); }
      });
      child.on("close", code => {
        try {
          const result=JSON.parse(output);
          if (typeof result?.state !== "string" || typeof result?.ok !== "boolean") return fail();
          if (code !== 0 && result.ok) return fail();
          finish(result);
        } catch { fail(); }
      });
      child.stdin.end(JSON.stringify(input));
    } catch { fail(); }
  });
}

export default function kovya(pi, { invoke = invokeWorker } = {}) {
  const report = (ctx, result) => {
    ctx.ui.setStatus("kovya", result.ok ? `Kovya: ${result.state}` : "Kovya: not active");
    if (!result.ok) ctx.ui.notify(result.systemMessage || OFFLINE, "warning");
  };
  pi.on("session_start", async (_event, ctx) => {
    const result = await invoke("SessionStart", { session_id: ctx.sessionManager.getSessionId() });
    report(ctx, result);
    const text = result.hookSpecificOutput?.additionalContext;
    if (text) pi.sendMessage({ customType: "kovya-recall", content: text, display: false }, { deliverAs: "nextTurn", triggerTurn: false });
  });
  pi.on("before_agent_start", async (event, ctx) => {
    const result = await invoke("UserPromptSubmit", { session_id: ctx.sessionManager.getSessionId(), prompt: event.prompt });
    report(ctx, result);
    const text = result.hookSpecificOutput?.additionalContext;
    if (text) return { message: { customType: "kovya-recall", content: text, display: false } };
  });
  pi.on("session_stop", async (event, ctx) => {
    if (event.signal?.aborted) return;
    const branch = ctx.sessionManager.getBranch();
    const last = branch.findLast(entry => entry.type === "message" && entry.message?.role === "assistant");
    const result = await invoke("Stop", { session_id: event.session_id, turn_id: event.turn_id,
      assistant_entry_id: last?.id, last_assistant_message: event.last_assistant_message,
      entries: branch.filter(entry => entry.type === "message") });
    report(ctx, result);
    // No continuation and no account/helper cleanup on host shutdown/removal.
  });
}
