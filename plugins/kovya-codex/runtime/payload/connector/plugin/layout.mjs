import os from "node:os";
import path from "node:path";
import { existsSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

function physicalPath(value) {
  let parent = path.resolve(value);
  const tail = [];
  while (!existsSync(parent)) {
    const next = path.dirname(parent);
    if (next === parent) throw new Error("kovya_home_invalid");
    tail.unshift(path.basename(parent));
    parent = next;
  }
  return path.join(realpathSync.native(parent), ...tail);
}
function within(parent, child) {
  const relative = path.relative(parent, child);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

export function resolvePluginLayout({ packageRoot = fileURLToPath(new URL("../../", import.meta.url)), env = process.env, userHome = os.homedir(), nodeExecutable = process.execPath } = {}) {
  if (!path.isAbsolute(packageRoot) || (env.KOVYA_HOME && !path.isAbsolute(env.KOVYA_HOME))) throw new Error("kovya_home_invalid");
  const codeRoot = physicalPath(packageRoot);
  const home = physicalPath(env.KOVYA_HOME || path.join(userHome, ".kovya"));
  // Native launch verifies admission before executing these modules. Permit
  // that precise runtime layout; arbitrary package caches inside home remain invalid.
  const admittedExecution = path.dirname(codeRoot) === path.join(home,"runtime")
    && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(path.basename(codeRoot))
    && physicalPath(nodeExecutable) === path.join(codeRoot,"runtime","node","node.exe");
  if ((within(codeRoot, home) || within(home, codeRoot)) && !admittedExecution) throw new Error("kovya_package_state_overlap");
  return Object.freeze({ codeRoot, home, state: path.join(home, "state"),
    authManifest: path.join(home, "windows-device-auth.json"),
    client: path.join(codeRoot, "connector", "claude-code", "client", "kovya-memory-client.mjs"),
    brokerClient: path.join(codeRoot, "connector", "claude-code", "client", "kovya-windows-broker-client.mjs") });
}
