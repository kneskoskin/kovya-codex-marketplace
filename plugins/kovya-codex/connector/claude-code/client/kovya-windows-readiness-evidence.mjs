#!/usr/bin/env node

import {requireBrokerMetadataDirectory} from "./kovya-windows-broker.mjs";
import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync
} from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";

export const WINDOWS_READINESS_EVIDENCE_SCHEMA = "kovya.windows-readiness-evidence.v2";
export const WINDOWS_READINESS_RUN_SCHEMA = "kovya.windows-readiness-run.v1";
export const WINDOWS_READINESS_OBSERVATION_SCHEMA = "kovya.windows-readiness-observation.v1";

const MODULE_PATH = path.resolve(fileURLToPath(import.meta.url));
const INSTALLED_HOME = path.resolve(path.dirname(MODULE_PATH), "..", "..", "..");
const PUBLISHER_ROLE = "readiness_evidence_publisher";
const FROZEN_AUTH_CONTRACT_SHA256 = "a97ca3362052aab11dc279ab7a07e20d0eff70bb29cf61e1f8373ef0746e58a6";
const RUN_MAX_AGE_MS = 2 * 60 * 60 * 1000;
const EVIDENCE_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const LOCK_MAX_AGE_MS = 10 * 60 * 1000;
const JSON_MAX_BYTES = 1024 * 1024;
const PROGRAM_MAX_BYTES = 8 * 1024 * 1024;
const MAX_OBSERVATIONS = 2048;
const HASH = /^[a-f0-9]{64}$/u;
const RUN_ID = /^[a-f0-9]{32}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const OUTCOMES = new Set(["succeeded", "degraded", "failed", "refused"]);
const REFUSAL_CODES = new Set([
  "broker_unavailable", "broker_start_cooldown", "broker_deadline_refused",
  "broker_owner_invalid", "broker_endpoint_invalid", "broker_peer_invalid",
  "broker_protocol_invalid", "broker_frame_invalid"
]);
const GATES = Object.freeze({
  broker: Object.freeze([
    "warm_broker_recall", "cold_authenticated_ready", "unavailable_refused_exit"
  ]),
  codex: Object.freeze([
    "warm_user_prompt_recall", "warm_session_start_recall", "cold_authenticated_ready",
    "normal_stop_capture", "unavailable_refused_exit"
  ]),
  claude_code: Object.freeze([
    "warm_user_prompt_recall", "warm_session_start_recall", "cold_authenticated_ready",
    "normal_stop_capture", "unavailable_refused_exit", "paired_pong_overhead"
  ]),
  security: Object.freeze(["authenticated_status"])
});
const REQUIRED = Object.freeze({
  "broker:warm_broker_recall": 30,
  "broker:cold_authenticated_ready": 10,
  "broker:unavailable_refused_exit": 1,
  "codex:warm_user_prompt_recall": 30,
  "codex:warm_session_start_recall": 30,
  "codex:cold_authenticated_ready": 10,
  "codex:normal_stop_capture": 30,
  "codex:unavailable_refused_exit": 1,
  "claude_code:warm_user_prompt_recall": 30,
  "claude_code:warm_session_start_recall": 30,
  "claude_code:cold_authenticated_ready": 10,
  "claude_code:normal_stop_capture": 30,
  "claude_code:unavailable_refused_exit": 1,
  "claude_code:paired_pong_overhead": 10,
  "security:authenticated_status": 1
});

function fail(code) {
  const error = new Error("Windows readiness evidence is unavailable.");
  error.code = code;
  return error;
}

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && canonical(Object.keys(value).sort()) === canonical([...keys].sort());
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function samePath(left, right) {
  const a = path.resolve(String(left ?? ""));
  const b = path.resolve(String(right ?? ""));
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function isWithin(root, candidate) {
  const base = path.resolve(root);
  const full = path.resolve(candidate);
  const relative = path.relative(base, full);
  return relative.length > 0 && relative !== ".." && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative);
}

function assertNoReparseComponents(targetPath, { allowMissingLeaf = false } = {}) {
  const full = path.resolve(targetPath);
  const parsed = path.parse(full);
  let current = parsed.root;
  for (const segment of full.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (!existsSync(current)) {
      if (allowMissingLeaf) break;
      throw fail("readiness_path_missing");
    }
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || (stat.mode & 0o170000) === 0o120000) {
      throw fail("readiness_path_reparse_refused");
    }
  }
  return full;
}

function processIsAlive(processId) {
  if (!Number.isSafeInteger(processId) || processId < 1) return false;
  try { process.kill(processId, 0); return true; } catch { return false; }
}

function readJson(targetPath, maxBytes = JSON_MAX_BYTES) {
  const full = assertNoReparseComponents(targetPath);
  const stat = lstatSync(full);
  if (!stat.isFile() || stat.size < 2 || stat.size > maxBytes) throw fail("readiness_json_invalid");
  return JSON.parse(readFileSync(full, "utf8"));
}

function assertWindowsBrokerStateAcl(directoryPath, expectedOwnerSidHash) {
  if (process.platform !== "win32") return;
  if (!HASH.test(String(expectedOwnerSidHash ?? ""))) throw fail("readiness_state_acl_invalid");
  const script = [
    "$ErrorActionPreference='Stop'",
    "$p=[IO.Path]::GetFullPath($env:KOVYA_READINESS_ACL_PATH)",
    "$expected=[string]$env:KOVYA_READINESS_OWNER_HASH",
    "$item=Get-Item -LiteralPath $p -Force",
    "if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'path'}",
    "$identity=[Security.Principal.WindowsIdentity]::GetCurrent()",
    "try{$sid=$identity.User.Value}finally{$identity.Dispose()}",
    "$sha=[Security.Cryptography.SHA256]::Create()",
    "try{$sidHash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sid)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}",
    "if($sidHash -ne $expected){throw 'owner'}",
    "$acl=[IO.Directory]::GetAccessControl($p)",
    "if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid){throw 'protection'}",
    "$allowed=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)",
    "foreach($v in @($sid,'S-1-5-18','S-1-5-32-544')){[void]$allowed.Add($v)}",
    "$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))",
    "$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit",
    "foreach($r in $rules){if($r.IsInherited -or $r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or -not $allowed.Remove($r.IdentityReference.Value) -or $r.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $r.InheritanceFlags -ne $inherit -or $r.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None){throw 'rule'}}",
    "if($allowed.Count -ne 0 -or $rules.Count -ne 3){throw 'count'}",
    "[Console]::Out.Write('{\"ok\":true}')"
  ].join("; ");
  const windowsRoot = process.env.SystemRoot || process.env.WINDIR;
  if (typeof windowsRoot !== "string" || windowsRoot.length < 3) throw fail("readiness_state_acl_invalid");
  const powershellPath = path.join(windowsRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const childEnvironment = {
    SystemRoot: windowsRoot,
    WINDIR: process.env.WINDIR || windowsRoot,
    KOVYA_READINESS_ACL_PATH: directoryPath,
    KOVYA_READINESS_OWNER_HASH: expectedOwnerSidHash
  };
  const result = spawnSync(powershellPath, [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script
  ], { encoding: "utf8", env: childEnvironment, windowsHide: true, timeout: 5000 });
  if (result.status !== 0 || result.signal !== null || result.stderr !== "" || result.stdout !== '{"ok":true}') {
    throw fail("readiness_state_acl_invalid");
  }
}

function pathsFor(home = process.env.KOVYA_HOME || INSTALLED_HOME) {
  const canonicalHome = assertNoReparseComponents(path.resolve(home));
  const broker = path.join(canonicalHome, "state", "broker");
  return Object.freeze({
    home: canonicalHome,
    broker,
    ledger: path.join(canonicalHome, "windows-host-integration.json"),
    manifest: process.env.KOVYA_WINDOWS_AUTH_MANIFEST || path.join(canonicalHome, "windows-device-auth.json"),
    endpoint: path.join(broker, "endpoint.json"),
    evidence: path.join(broker, "readiness-evidence.json"),
    active: path.join(broker, "readiness-run.json"),
    publishLock: path.join(broker, "readiness-publish.lock"),
    runs: path.join(broker, "readiness-runs")
  });
}

function hashHostConfiguration(ledger) {
  const hashes = [];
  for (const surface of ["claude_code", "codex"]) {
    const entry = ledger.config?.[surface];
    if (!entry || typeof entry !== "object") continue;
    for (const key of ["settings_path", "config_path", "hooks_path"]) {
      if (typeof entry[key] !== "string" || entry[key].length === 0) continue;
      const full = assertNoReparseComponents(entry[key]);
      const stat = lstatSync(full);
      if (!stat.isFile() || stat.size > JSON_MAX_BYTES) throw fail("readiness_host_config_invalid");
      hashes.push({ surface, key, sha256: sha256(readFileSync(full)) });
    }
  }
  hashes.sort((a, b) => `${a.surface}:${a.key}`.localeCompare(`${b.surface}:${b.key}`));
  return sha256(canonical(hashes));
}

export function endpointProjection(endpoint) {
  const requiredStrings = [
    "broker_binding", "broker_instance", "owner_sid_hash", "process_creation_filetime",
    "image_path_sha256", "installation_root_sha256", "parent_process_creation_filetime",
    "parent_image_path_sha256", "authentication_id_hash", "protocol_version", "pipe_name"
  ];
  if ((Object.hasOwn(endpoint,"broker_scope") && !["machine","harness_session"].includes(endpoint.broker_scope))
      || !requiredStrings.every((key) => typeof endpoint[key] === "string" && endpoint[key].length > 0)
      || !Number.isInteger(endpoint.pid) || endpoint.pid < 1
      || !Number.isInteger(endpoint.parent_pid) || endpoint.parent_pid < 1
      || !Number.isInteger(endpoint.windows_session_id) || endpoint.windows_session_id < 0) {
    throw fail("readiness_endpoint_invalid");
  }
  return Object.freeze({
    ...(Object.hasOwn(endpoint,"broker_scope") ? {broker_scope:endpoint.broker_scope} : {}),
    authentication_id_hash: endpoint.authentication_id_hash,
    broker_binding: endpoint.broker_binding,
    broker_instance: endpoint.broker_instance,
    image_path_sha256: endpoint.image_path_sha256,
    installation_root_sha256: endpoint.installation_root_sha256,
    owner_sid_hash: endpoint.owner_sid_hash,
    parent_image_path_sha256: endpoint.parent_image_path_sha256,
    parent_process_creation_filetime: endpoint.parent_process_creation_filetime,
    parent_process_id: endpoint.parent_pid,
    pipe_name_sha256: sha256(endpoint.pipe_name),
    process_creation_filetime: endpoint.process_creation_filetime,
    process_id: endpoint.pid,
    protocol_version: endpoint.protocol_version,
    windows_session_id: endpoint.windows_session_id
  });
}

function readCurrentEndpoint(p) {
  const endpoint = readJson(p.endpoint);
  const projection = endpointProjection(endpoint);
  return Object.freeze({ projection, binding_sha256: sha256(canonical(projection)) });
}

function currentSnapshot(p = pathsFor()) {
  const ledger = readJson(p.ledger);
  const manifest = readJson(p.manifest);
  if (ledger.schema !== "kovya.windows-host-integration.v1"
      || ledger.frozen_auth_contract_sha256 !== FROZEN_AUTH_CONTRACT_SHA256
      || manifest.schema_version !== "kovya.windows-device-auth.v1"
      || !samePath(ledger.installation_root, p.home)
      || !samePath(ledger.ledger_path, p.ledger)
      || !samePath(ledger.broker?.state_directory, p.broker)
      || !samePath(ledger.broker?.readiness_evidence_path, p.evidence)
      || !samePath(ledger.broker?.readiness_run_path, p.active)
      || !samePath(ledger.broker?.readiness_publish_lock_path, p.publishLock)
      || !samePath(ledger.broker?.readiness_runs_directory, p.runs)
      || !samePath(ledger.broker?.readiness_publisher_path, MODULE_PATH)
      || !samePath(ledger.broker?.endpoint_path, p.endpoint)
      || !HASH.test(String(ledger.broker?.owner_sid_hash ?? ""))) {
    throw fail("readiness_ledger_invalid");
  }
  assertWindowsBrokerStateAcl(p.broker, ledger.broker.owner_sid_hash);
  const receipts = Array.isArray(ledger.program_file_receipts) ? ledger.program_file_receipts : [];
  const programFiles = Array.isArray(ledger.program_files) ? ledger.program_files : [];
  if (receipts.length < 1 || receipts.length > 256 || programFiles.length !== receipts.length) {
    throw fail("readiness_receipts_invalid");
  }
  const programFileSet = new Set();
  for (const file of programFiles) {
    const full = assertNoReparseComponents(file);
    const key = process.platform === "win32" ? full.toLowerCase() : full;
    if (!isWithin(p.home, full) || programFileSet.has(key)) throw fail("readiness_receipts_invalid");
    programFileSet.add(key);
  }
  const normalized = [];
  const seen = new Set();
  for (const receipt of receipts) {
    const full = assertNoReparseComponents(receipt?.path);
    const key = process.platform === "win32" ? full.toLowerCase() : full;
    if (!isWithin(p.home, full) || !programFileSet.has(key) || seen.has(key) || !HASH.test(String(receipt?.sha256 ?? ""))
        || !/^[a-z][a-z0-9_.-]{1,63}$/u.test(String(receipt?.role ?? ""))
        || !/^[a-z0-9][a-z0-9_.-]{1,31}$/u.test(String(receipt?.architecture ?? ""))) {
      throw fail("readiness_receipts_invalid");
    }
    seen.add(key);
    const stat = lstatSync(full);
    if (!stat.isFile() || stat.size < 1 || stat.size > PROGRAM_MAX_BYTES
        || sha256(readFileSync(full)) !== receipt.sha256) throw fail("readiness_program_drift");
    normalized.push({
      architecture: receipt.architecture,
      path_binding_sha256: sha256((process.platform === "win32" ? full.toLowerCase() : full)),
      role: receipt.role,
      sha256: receipt.sha256
    });
  }
  const publisher = receipts.filter((receipt) => receipt.role === PUBLISHER_ROLE);
  if (publisher.length !== 1 || !samePath(publisher[0].path, MODULE_PATH)
      || sha256(readFileSync(MODULE_PATH)) !== publisher[0].sha256
      || ledger.broker.readiness_publisher_sha256 !== publisher[0].sha256) {
    throw fail("readiness_publisher_receipt_invalid");
  }
  normalized.sort((a, b) => a.path_binding_sha256.localeCompare(b.path_binding_sha256));
  const rootBinding = sha256(p.home.toLowerCase());
  if (ledger.root_binding_sha256 !== rootBinding) {
    throw fail("readiness_root_binding_invalid");
  }
  return Object.freeze({
    configuration_sha256: hashHostConfiguration(ledger),
    host_ledger_sha256: sha256(readFileSync(p.ledger)),
    installation_root_binding_sha256: rootBinding,
    device_manifest_sha256: sha256(readFileSync(p.manifest)),
    program_receipt_count: normalized.length,
    program_path_bindings: Object.freeze(normalized.map((receipt) => Object.freeze({
      path_binding_sha256: receipt.path_binding_sha256,
      role: receipt.role,
      sha256: receipt.sha256
    }))),
    program_receipts_sha256: sha256(canonical(normalized)),
    publisher_sha256: publisher[0].sha256,
    manifest_schema: manifest.schema_version
  });
}

function writeExclusiveJson(targetPath, value) {
  assertNoReparseComponents(path.dirname(targetPath));
  if (existsSync(targetPath)) assertNoReparseComponents(targetPath);
  const fd = openSync(targetPath, "wx", 0o600);
  try {
    writeFileSync(fd, `${canonical(value)}\n`, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function atomicJson(targetPath, value, failpoint = null) {
  assertNoReparseComponents(path.dirname(targetPath));
  if (existsSync(targetPath)) assertNoReparseComponents(targetPath);
  const temporary = `${targetPath}.tmp-${process.pid}-${randomBytes(16).toString("hex")}`;
  let fd;
  try {
    fd = openSync(temporary, "wx", 0o600);
    writeFileSync(fd, `${canonical(value)}\n`, "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    if (failpoint === "before_rename") throw fail("readiness_publish_interrupted");
    renameSync(temporary, targetPath);
    try {
      const directoryFd = openSync(path.dirname(targetPath), "r");
      try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
    } catch {}
  } finally {
    if (fd !== undefined) closeSync(fd);
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

function exactPublishLock(value) {
  if (!exactKeys(value, [
    "schema_version", "lock_id", "operation", "owner_pid", "acquired_at", "expires_at", "run_id"
  ]) || value.schema_version !== "kovya.windows-readiness-publish-lock.v1"
      || !RUN_ID.test(String(value.lock_id ?? ""))
      || !["begin", "observation_admission", "paired_pong", "finalize", "abort"].includes(value.operation)
      || !Number.isSafeInteger(value.owner_pid) || value.owner_pid < 1
      || !TIMESTAMP.test(String(value.acquired_at ?? ""))
      || !TIMESTAMP.test(String(value.expires_at ?? ""))
      || !(value.run_id === null || RUN_ID.test(String(value.run_id)))) {
    throw fail("readiness_publish_lock_invalid");
  }
  const acquired = Date.parse(value.acquired_at);
  const expires = Date.parse(value.expires_at);
  if (!Number.isFinite(acquired) || !Number.isFinite(expires)
      || expires <= acquired || expires - acquired > LOCK_MAX_AGE_MS) {
    throw fail("readiness_publish_lock_invalid");
  }
  return value;
}

function acquirePublishLock(p, operation, runId = null) {
  const acquiredAt = new Date().toISOString();
  const owner = Object.freeze({
    schema_version: "kovya.windows-readiness-publish-lock.v1",
    lock_id: randomBytes(16).toString("hex"),
    operation,
    owner_pid: process.pid,
    acquired_at: acquiredAt,
    expires_at: new Date(Date.parse(acquiredAt) + LOCK_MAX_AGE_MS).toISOString(),
    run_id: runId
  });
  try {
    writeExclusiveJson(p.publishLock, owner);
    return owner;
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    const existing = exactPublishLock(readJson(p.publishLock, 16 * 1024));
    const expired = Date.parse(existing.expires_at) <= Date.now();
    throw fail(expired && !processIsAlive(existing.owner_pid)
      ? "readiness_publish_lock_stale"
      : "readiness_publish_busy");
  }
}

function releasePublishLock(p, owner) {
  if (!existsSync(p.publishLock)) return false;
  const current = exactPublishLock(readJson(p.publishLock, 16 * 1024));
  if (canonical(current) !== canonical(owner)) return false;
  unlinkSync(p.publishLock);
  return true;
}

function ownedRun(p = pathsFor()) {
  const run = readJson(p.active);
  if (!exactKeys(run, [
    "schema_version", "run_id", "mode", "state", "started_at", "collect_not_after",
    "snapshot_sha256", "program_receipts_sha256", "publisher_sha256", "configuration_sha256",
    "host_ledger_sha256", "device_manifest_sha256"
  ]) || run.schema_version !== WINDOWS_READINESS_RUN_SCHEMA || !RUN_ID.test(String(run.run_id ?? ""))
      || run.mode !== "native_live" || run.state !== "collecting"
      || !TIMESTAMP.test(String(run.started_at ?? "")) || !TIMESTAMP.test(String(run.collect_not_after ?? ""))
      || ![run.snapshot_sha256, run.program_receipts_sha256, run.publisher_sha256,
        run.configuration_sha256, run.host_ledger_sha256, run.device_manifest_sha256].every((value) => HASH.test(String(value)))) {
    throw fail("readiness_run_invalid");
  }
  const retained = readJson(path.join(p.runs, run.run_id, "run.json"));
  if (canonical(retained) !== canonical(run)) throw fail("readiness_run_binding_invalid");
  return { p, run };
}

function exactRun(p = pathsFor()) {
  const { run } = ownedRun(p);
  const started = Date.parse(run.started_at);
  const expires = Date.parse(run.collect_not_after);
  if (!Number.isFinite(started) || !Number.isFinite(expires) || expires <= Date.now()
      || expires - started > RUN_MAX_AGE_MS) throw fail("readiness_run_stale");
  const snapshot = currentSnapshot(p);
  if (sha256(canonical(snapshot)) !== run.snapshot_sha256
      || run.program_receipts_sha256 !== snapshot.program_receipts_sha256
      || run.publisher_sha256 !== snapshot.publisher_sha256
      || run.configuration_sha256 !== snapshot.configuration_sha256
      || run.host_ledger_sha256 !== snapshot.host_ledger_sha256
      || run.device_manifest_sha256 !== snapshot.device_manifest_sha256) {
    throw fail("readiness_snapshot_drift");
  }
  return { p, run, snapshot };
}

function observationRun(p = pathsFor()) {
  const { run } = ownedRun(p);
  const started = Date.parse(run.started_at);
  const expires = Date.parse(run.collect_not_after);
  if (!Number.isFinite(started) || !Number.isFinite(expires) || expires <= Date.now()
      || expires - started > RUN_MAX_AGE_MS
      || !HASH.test(String(run.program_receipts_sha256 ?? ""))
      || !HASH.test(String(run.publisher_sha256 ?? ""))
      || !HASH.test(String(run.configuration_sha256 ?? ""))) throw fail("readiness_run_stale");
  return { p, run };
}

export function begin() {
  const p = pathsFor();
  requireBrokerMetadataDirectory(p.broker);
  mkdirSync(p.runs, { recursive: true, mode: 0o700 });
  assertNoReparseComponents(p.broker);
  assertNoReparseComponents(p.runs);
  const lock = acquirePublishLock(p, "begin");
  try {
    const snapshot = currentSnapshot(p);
    if (existsSync(p.active)) throw fail("readiness_run_active");
    const runId = randomBytes(16).toString("hex");
    const runDirectory = path.join(p.runs, runId);
    mkdirSync(runDirectory, { mode: 0o700 });
    assertNoReparseComponents(runDirectory);
    const startedAt = new Date().toISOString();
    const run = Object.freeze({
      schema_version: WINDOWS_READINESS_RUN_SCHEMA,
      run_id: runId,
      mode: "native_live",
      state: "collecting",
      started_at: startedAt,
      collect_not_after: new Date(Date.parse(startedAt) + RUN_MAX_AGE_MS).toISOString(),
      snapshot_sha256: sha256(canonical(snapshot)),
      program_receipts_sha256: snapshot.program_receipts_sha256,
      publisher_sha256: snapshot.publisher_sha256,
      configuration_sha256: snapshot.configuration_sha256,
      host_ledger_sha256: snapshot.host_ledger_sha256,
      device_manifest_sha256: snapshot.device_manifest_sha256
    });
    try {
      writeExclusiveJson(path.join(runDirectory, "run.json"), run);
      writeExclusiveJson(p.active, run);
    } catch (error) {
      rmSync(runDirectory, { recursive: true, force: true });
      throw error;
    }
    return Object.freeze({ schema_version: WINDOWS_READINESS_RUN_SCHEMA, state: "collecting", run_id: runId });
  } finally {
    releasePublishLock(p, lock);
  }
}

export function status() {
  const { run } = exactRun();
  return Object.freeze({ schema_version: WINDOWS_READINESS_RUN_SCHEMA, state: run.state, run_id: run.run_id });
}

function classify(result, error, expectedRefusal) {
  if (error) return expectedRefusal && REFUSAL_CODES.has(String(error?.code ?? "")) ? "refused" : "failed";
  if (expectedRefusal) return "failed";
  if (result === null || typeof result !== "object") return "failed";
  if (result?.degraded === true || result?.availability_status === "warming") return "degraded";
  if (result?.ok === false || result?.ready === false) return "failed";
  return "succeeded";
}

function expectedProducerLeaf(host, gate) {
  return host === "broker" ? "kovya-windows-broker-client.mjs"
    : gate === "warm_session_start_recall" ? "kovya_session_start.mjs"
    : gate === "warm_user_prompt_recall" ? "kovya_turn_recall.mjs"
    : gate === "normal_stop_capture" ? "kovya_capture.mjs"
    : gate === "cold_authenticated_ready" || gate === "unavailable_refused_exit" ? path.basename(MODULE_PATH)
    : host === "security" && gate === "authenticated_status" ? path.basename(MODULE_PATH)
    : host === "claude_code" && gate === "paired_pong_overhead" ? path.basename(MODULE_PATH)
    : null;
}

function producerFor(host, gate, run, p) {
  const entry = path.resolve(process.argv[1] || MODULE_PATH);
  const expectedLeaf = expectedProducerLeaf(host, gate);
  if (expectedLeaf && path.basename(entry) !== expectedLeaf) throw fail("readiness_observation_producer_invalid");
  const entryBinding = sha256(process.platform === "win32" ? entry.toLowerCase() : entry);
  const ledger = readJson(p.ledger);
  const receipts = Array.isArray(ledger.program_file_receipts) ? ledger.program_file_receipts : [];
  const receipt = receipts.filter((candidate) => samePath(candidate?.path, entry));
  if (sha256(readFileSync(p.ledger)) !== run.host_ledger_sha256 || receipt.length !== 1
      || !HASH.test(String(receipt[0].sha256 ?? ""))
      || sha256(readFileSync(assertNoReparseComponents(entry))) !== receipt[0].sha256) {
    throw fail("readiness_observation_producer_invalid");
  }
  return Object.freeze({
    producer_path_binding_sha256: entryBinding,
    producer_sha256: receipt[0].sha256,
    program_receipts_sha256: run.program_receipts_sha256,
    publisher_sha256: run.publisher_sha256
  });
}

async function measure(host, gate, operation, { expectedRefusal = false, pair = false } = {}) {
  if (typeof operation !== "function") throw new TypeError("A fixed readiness operation is required.");
  const processExitGate = (host === "codex" || host === "claude_code")
    && ["warm_user_prompt_recall", "warm_session_start_recall", "normal_stop_capture"].includes(gate);
  // Installed hook evidence covers the whole Node process lifetime. This
  // includes module loading and binding checks that happen before the hook can
  // call the recorder; the completion is written synchronously at natural
  // beforeExit so stdout flush and teardown remain inside the measured gate.
  const startedAt = processExitGate ? new Date(performance.timeOrigin).toISOString() : new Date().toISOString();
  const startedTickUs = processExitGate ? 0 : Math.round(performance.now() * 1000);
  const p = pathsFor();
  const admission = acquirePublishLock(p, "observation_admission");
  let run;
  let sampleId;
  let runDirectory;
  let startingEndpoint;
  let start;
  try {
    ({ run } = observationRun(p));
    if (!GATES[host]?.includes(gate)) throw fail("readiness_gate_invalid");
    sampleId = randomBytes(16).toString("hex");
    runDirectory = assertNoReparseComponents(path.join(p.runs, run.run_id));
    const producer = producerFor(host, gate, run, p);
    startingEndpoint = existsSync(p.endpoint) ? readCurrentEndpoint(p) : null;
    start = Object.freeze({
      schema_version: WINDOWS_READINESS_OBSERVATION_SCHEMA,
      record_type: "start",
      run_id: run.run_id,
      sample_id: sampleId,
      host,
      gate,
      started_at: startedAt,
      started_tick_us: startedTickUs,
      endpoint_binding_sha256: startingEndpoint?.binding_sha256 ?? null,
      snapshot_sha256: run.snapshot_sha256,
      ...producer
    });
    writeExclusiveJson(path.join(runDirectory, `start-${sampleId}.json`), start);
  } finally {
    releasePublishLock(p, admission);
  }
  let result;
  let caught;
  try { result = await operation(); } catch (error) { caught = error; }
  const complete = () => {
    let endingEndpoint = null;
    try { if (existsSync(p.endpoint)) endingEndpoint = readCurrentEndpoint(p); } catch (error) { caught ??= error; }
    const stableEndpointRequired = gate.startsWith("warm_") || gate === "normal_stop_capture"
      || host === "security";
    if (stableEndpointRequired && startingEndpoint?.binding_sha256 !== endingEndpoint?.binding_sha256) {
      caught ??= fail("readiness_endpoint_changed_during_sample");
    }
    const completedTickUs = Math.round(performance.now() * 1000);
    const completion = Object.freeze({
      schema_version: WINDOWS_READINESS_OBSERVATION_SCHEMA,
      record_type: "completion",
      run_id: run.run_id,
      sample_id: sampleId,
      host,
      gate,
      completed_at: new Date().toISOString(),
      completed_tick_us: completedTickUs,
      duration_us: Math.max(0, completedTickUs - startedTickUs),
      outcome: classify(result, caught, expectedRefusal),
      endpoint_binding_sha256: endingEndpoint?.binding_sha256 ?? null,
      broker_endpoint: endingEndpoint?.projection ?? null,
      start_sha256: sha256(canonical(start)),
      pair_order: pair ? result?.pair_order ?? null : null,
      normal_duration_us: pair ? result?.normal_duration_us ?? null : null,
      safe_mode_duration_us: pair ? result?.safe_mode_duration_us ?? null : null
    });
    writeExclusiveJson(path.join(runDirectory, `completion-${sampleId}.json`), completion);
  };
  if (processExitGate) {
    process.once("beforeExit", () => {
      try { complete(); } catch {}
    });
  } else {
    complete();
  }
  if (caught) throw caught;
  return result;
}

async function measurePairedPong(normalOperation, safeModeOperation) {
  if (typeof normalOperation !== "function" || typeof safeModeOperation !== "function") {
    throw new TypeError("The fixed normal and safe-mode readiness operations are required.");
  }
  const startedAt = new Date().toISOString();
  const startedTickUs = Math.round(performance.now() * 1000);
  const p = pathsFor();
  const lock = acquirePublishLock(p, "paired_pong");
  try {
    const { run } = observationRun(p);
    const runDirectory = assertNoReparseComponents(path.join(p.runs, run.run_id));
    const completedPairs = readdirSync(runDirectory)
      .filter((name) => /^completion-[a-f0-9]{32}\.json$/u.test(name))
      .map((name) => readJson(path.join(runDirectory, name), 64 * 1024))
      .filter((record) => record.host === "claude_code" && record.gate === "paired_pong_overhead")
      .length;
    const pairOrder = completedPairs % 2 === 0 ? "normal_first" : "safe_mode_first";
    const sampleId = randomBytes(16).toString("hex");
    const producer = producerFor("claude_code", "paired_pong_overhead", run, p);
    const startingEndpoint = readCurrentEndpoint(p);
    const start = Object.freeze({
      schema_version: WINDOWS_READINESS_OBSERVATION_SCHEMA,
      record_type: "start",
      run_id: run.run_id,
      sample_id: sampleId,
      host: "claude_code",
      gate: "paired_pong_overhead",
      started_at: startedAt,
      started_tick_us: startedTickUs,
      endpoint_binding_sha256: startingEndpoint.binding_sha256,
      snapshot_sha256: run.snapshot_sha256,
      ...producer
    });
    writeExclusiveJson(path.join(runDirectory, `start-${sampleId}.json`), start);
    let normalDurationUs = 0;
    let safeDurationUs = 0;
    let normalError;
    let safeError;
    const invoke = async (operation, assignDuration, assignError) => {
      const legStarted = Math.round(performance.now() * 1000);
      try { await operation(); } catch (error) { assignError(error); }
      assignDuration(Math.max(0, Math.round(performance.now() * 1000) - legStarted));
    };
    if (pairOrder === "normal_first") {
      await invoke(normalOperation, (value) => { normalDurationUs = value; }, (error) => { normalError = error; });
      await invoke(safeModeOperation, (value) => { safeDurationUs = value; }, (error) => { safeError = error; });
    } else {
      await invoke(safeModeOperation, (value) => { safeDurationUs = value; }, (error) => { safeError = error; });
      await invoke(normalOperation, (value) => { normalDurationUs = value; }, (error) => { normalError = error; });
    }
    const completedTickUs = Math.round(performance.now() * 1000);
    const endingEndpoint = readCurrentEndpoint(p);
    const endpointStable = endingEndpoint.binding_sha256 === startingEndpoint.binding_sha256;
    const completion = Object.freeze({
      schema_version: WINDOWS_READINESS_OBSERVATION_SCHEMA,
      record_type: "completion",
      run_id: run.run_id,
      sample_id: sampleId,
      host: "claude_code",
      gate: "paired_pong_overhead",
      completed_at: new Date().toISOString(),
      completed_tick_us: completedTickUs,
      duration_us: Math.max(0, completedTickUs - startedTickUs),
      outcome: normalError || safeError || !endpointStable ? "failed" : "succeeded",
      endpoint_binding_sha256: endingEndpoint.binding_sha256,
      broker_endpoint: endingEndpoint.projection,
      start_sha256: sha256(canonical(start)),
      pair_order: pairOrder,
      normal_duration_us: normalDurationUs,
      safe_mode_duration_us: safeDurationUs
    });
    writeExclusiveJson(path.join(runDirectory, `completion-${sampleId}.json`), completion);
    if (normalError) throw normalError;
    if (safeError) throw safeError;
    return undefined;
  } finally {
    releasePublishLock(p, lock);
  }
}

export function createWindowsReadinessRecorder() {
  return Object.freeze({
    broker: Object.freeze({
      warmRecall: (operation) => measure("broker", "warm_broker_recall", operation),
      coldAuthenticatedReady: (operation) => measure("broker", "cold_authenticated_ready", operation),
      unavailableRefused: (operation) => measure("broker", "unavailable_refused_exit", operation, { expectedRefusal: true })
    }),
    codex: Object.freeze({
      warmUserPromptRecall: (operation) => measure("codex", "warm_user_prompt_recall", operation),
      warmSessionStartRecall: (operation) => measure("codex", "warm_session_start_recall", operation),
      coldAuthenticatedReady: (operation) => measure("codex", "cold_authenticated_ready", operation),
      normalStopCapture: (operation) => measure("codex", "normal_stop_capture", operation),
      unavailableRefused: (operation) => measure("codex", "unavailable_refused_exit", operation, { expectedRefusal: true })
    }),
    claude_code: Object.freeze({
      warmUserPromptRecall: (operation) => measure("claude_code", "warm_user_prompt_recall", operation),
      warmSessionStartRecall: (operation) => measure("claude_code", "warm_session_start_recall", operation),
      coldAuthenticatedReady: (operation) => measure("claude_code", "cold_authenticated_ready", operation),
      normalStopCapture: (operation) => measure("claude_code", "normal_stop_capture", operation),
      unavailableRefused: (operation) => measure("claude_code", "unavailable_refused_exit", operation, { expectedRefusal: true }),
      pairedPong: (normalOperation, safeModeOperation) => measurePairedPong(normalOperation, safeModeOperation)
    }),
    security: Object.freeze({ authenticatedStatus: (operation) => measure("security", "authenticated_status", operation) })
  });
}

function exactEndpointProjection(value) {
  const keys = [
    "authentication_id_hash", "broker_binding", "broker_instance", "image_path_sha256",
    "installation_root_sha256", "owner_sid_hash", "parent_image_path_sha256",
    "parent_process_creation_filetime", "parent_process_id", "pipe_name_sha256",
    "process_creation_filetime", "process_id", "protocol_version", "windows_session_id"
  ];
  if (Object.hasOwn(value ?? {}, "broker_scope")) keys.push("broker_scope");
  if ((Object.hasOwn(value ?? {}, "broker_scope") && !["machine", "harness_session"].includes(value.broker_scope))
      || !exactKeys(value, keys)
      || ![value.authentication_id_hash, value.broker_binding, value.image_path_sha256,
        value.installation_root_sha256, value.owner_sid_hash, value.parent_image_path_sha256,
        value.pipe_name_sha256].every((item) => HASH.test(String(item)))
      || !RUN_ID.test(String(value.broker_instance ?? ""))
      || !/^[1-9][0-9]{0,19}$/u.test(String(value.process_creation_filetime ?? ""))
      || !/^[1-9][0-9]{0,19}$/u.test(String(value.parent_process_creation_filetime ?? ""))
      || !Number.isSafeInteger(value.process_id) || value.process_id < 1
      || !Number.isSafeInteger(value.parent_process_id) || value.parent_process_id < 1
      || !Number.isSafeInteger(value.windows_session_id) || value.windows_session_id < 0
      || value.protocol_version !== "kovya.windows-memory-broker.v1") {
    throw fail("readiness_observation_endpoint_invalid");
  }
  return value;
}

function exactObservationProducer(start, p, run) {
  const expectedLeaf = expectedProducerLeaf(start.host, start.gate);
  const ledger = readJson(p.ledger);
  const receipts = Array.isArray(ledger.program_file_receipts) ? ledger.program_file_receipts : [];
  const matches = receipts.filter((receipt) => {
    if (typeof receipt?.path !== "string") return false;
    const full = path.resolve(receipt.path);
    const binding = sha256(process.platform === "win32" ? full.toLowerCase() : full);
    return binding === start.producer_path_binding_sha256;
  });
  if (!expectedLeaf || matches.length !== 1 || path.basename(matches[0].path) !== expectedLeaf
      || matches[0].sha256 !== start.producer_sha256
      || start.snapshot_sha256 !== run.snapshot_sha256
      || start.program_receipts_sha256 !== run.program_receipts_sha256
      || start.publisher_sha256 !== run.publisher_sha256
      || ((expectedLeaf === path.basename(MODULE_PATH)) !== (matches[0].role === PUBLISHER_ROLE))) {
    throw fail("readiness_observation_producer_invalid");
  }
}

function exactObservationRow(start, completion, p, run) {
  const startKeys = [
    "schema_version", "record_type", "run_id", "sample_id", "host", "gate", "started_at",
    "started_tick_us", "endpoint_binding_sha256", "snapshot_sha256",
    "producer_path_binding_sha256", "producer_sha256", "program_receipts_sha256", "publisher_sha256"
  ];
  const completionKeys = [
    "schema_version", "record_type", "run_id", "sample_id", "host", "gate", "completed_at",
    "completed_tick_us", "duration_us", "outcome", "endpoint_binding_sha256", "broker_endpoint",
    "start_sha256", "pair_order", "normal_duration_us", "safe_mode_duration_us"
  ];
  const hookProcessGate = (start.host === "codex" || start.host === "claude_code")
    && ["warm_user_prompt_recall", "warm_session_start_recall", "normal_stop_capture"].includes(start.gate);
  if (!exactKeys(start, startKeys) || !exactKeys(completion, completionKeys)
      || start.schema_version !== WINDOWS_READINESS_OBSERVATION_SCHEMA || start.record_type !== "start"
      || completion.schema_version !== WINDOWS_READINESS_OBSERVATION_SCHEMA || completion.record_type !== "completion"
      || start.run_id !== run.run_id || completion.run_id !== run.run_id
      || !RUN_ID.test(String(start.sample_id ?? "")) || completion.sample_id !== start.sample_id
      || !GATES[start.host]?.includes(start.gate)
      || completion.host !== start.host || completion.gate !== start.gate
      || !TIMESTAMP.test(String(start.started_at ?? "")) || !TIMESTAMP.test(String(completion.completed_at ?? ""))
      || !Number.isSafeInteger(start.started_tick_us) || start.started_tick_us < 0
      || (hookProcessGate && start.started_tick_us !== 0)
      || !Number.isSafeInteger(completion.completed_tick_us)
      || completion.completed_tick_us < start.started_tick_us
      || !Number.isSafeInteger(completion.duration_us) || completion.duration_us < 0
      || completion.duration_us > 300_000_000
      || completion.duration_us !== completion.completed_tick_us - start.started_tick_us
      || !OUTCOMES.has(completion.outcome)
      || completion.start_sha256 !== sha256(canonical(start))
      || ![start.snapshot_sha256, start.producer_path_binding_sha256, start.producer_sha256,
        start.program_receipts_sha256, start.publisher_sha256, completion.start_sha256]
        .every((value) => HASH.test(String(value)))) {
    throw fail("readiness_observation_invalid");
  }
  const runStarted = Date.parse(run.started_at);
  const runExpires = Date.parse(run.collect_not_after);
  const started = Date.parse(start.started_at);
  const completed = Date.parse(completion.completed_at);
  if (started < runStarted || completed < started || completed > runExpires) {
    throw fail("readiness_observation_time_invalid");
  }
  exactObservationProducer(start, p, run);

  const startBinding = start.endpoint_binding_sha256;
  const endBinding = completion.endpoint_binding_sha256;
  if (!(startBinding === null || HASH.test(String(startBinding)))
      || !(endBinding === null || HASH.test(String(endBinding)))) {
    throw fail("readiness_observation_endpoint_invalid");
  }
  if (completion.broker_endpoint !== null) {
    exactEndpointProjection(completion.broker_endpoint);
    if (sha256(canonical(completion.broker_endpoint)) !== endBinding) {
      throw fail("readiness_observation_endpoint_invalid");
    }
  } else if (endBinding !== null) {
    throw fail("readiness_observation_endpoint_invalid");
  }

  const stableEndpointGate = start.gate.startsWith("warm_") || start.gate === "normal_stop_capture"
    || start.gate === "paired_pong_overhead" || start.host === "security";
  if ((completion.outcome === "succeeded" || completion.outcome === "degraded")
      && stableEndpointGate
      && (!HASH.test(String(startBinding)) || startBinding !== endBinding || completion.broker_endpoint === null)) {
    throw fail("readiness_observation_endpoint_changed");
  }
  if ((completion.outcome === "succeeded" || completion.outcome === "degraded")
      && start.gate === "cold_authenticated_ready"
      && (startBinding !== null || !HASH.test(String(endBinding)) || completion.broker_endpoint === null)) {
    throw fail("readiness_cold_start_invalid");
  }
  if (start.gate === "unavailable_refused_exit"
      && (completion.outcome !== "refused" || startBinding !== null || endBinding !== null
        || completion.broker_endpoint !== null)) {
    throw fail("readiness_refusal_invalid");
  }
  if (start.host === "security" && completion.outcome !== "succeeded") {
    throw fail("readiness_security_invalid");
  }

  const paired = start.host === "claude_code" && start.gate === "paired_pong_overhead";
  if (paired) {
    if (!["normal_first", "safe_mode_first"].includes(completion.pair_order)
        || !Number.isSafeInteger(completion.normal_duration_us) || completion.normal_duration_us < 0
        || !Number.isSafeInteger(completion.safe_mode_duration_us) || completion.safe_mode_duration_us < 0) {
      throw fail("readiness_pong_pair_invalid");
    }
  } else if (completion.pair_order !== null || completion.normal_duration_us !== null
      || completion.safe_mode_duration_us !== null) {
    throw fail("readiness_observation_invalid");
  }
}

function inventoryObservations(p, run, { allowSynthetic = false } = {}) {
  const directory = assertNoReparseComponents(path.join(p.runs, run.run_id));
  const names = readdirSync(directory);
  if (names.length > MAX_OBSERVATIONS * 2 + 1) throw fail("readiness_observation_limit");
  const starts = new Map();
  const completions = new Map();
  for (const name of names) {
    if (name === "run.json") continue;
    const match = /^(start|completion)-([a-f0-9]{32})\.json$/u.exec(name);
    if (!match) throw fail("readiness_observation_artifact_invalid");
    const record = readJson(path.join(directory, name), 64 * 1024);
    if (record.schema_version !== WINDOWS_READINESS_OBSERVATION_SCHEMA
        || record.record_type !== match[1] || record.sample_id !== match[2]
        || record.run_id !== run.run_id) throw fail("readiness_observation_invalid");
    const collection = match[1] === "start" ? starts : completions;
    if (collection.has(record.sample_id)) throw fail("readiness_observation_duplicate");
    collection.set(record.sample_id, record);
  }
  if (starts.size !== completions.size || starts.size < 1) throw fail("readiness_observation_incomplete");
  const rows = [];
  for (const [sampleId, start] of starts) {
    const completion = completions.get(sampleId);
    if (!completion || completion.start_sha256 !== sha256(canonical(start))
        || completion.host !== start.host || completion.gate !== start.gate
        || !Number.isSafeInteger(completion.duration_us) || completion.duration_us < 0
        || completion.duration_us > 300_000_000 || !OUTCOMES.has(completion.outcome)) {
      throw fail("readiness_observation_invalid");
    }
    exactObservationRow(start, completion, p, run);
    rows.push({ start, completion });
  }
  rows.sort((a, b) => a.start.started_at.localeCompare(b.start.started_at)
    || a.start.sample_id.localeCompare(b.start.sample_id));
  if (!allowSynthetic) {
    for (const [key, minimum] of Object.entries(REQUIRED)) {
      const [host, gate] = key.split(":");
      if (rows.filter((row) => row.start.host === host && row.start.gate === gate).length < minimum) {
        throw fail("readiness_live_host_evidence_incomplete");
      }
    }
  }
  return rows;
}

function timedGate(rows, host, gate) {
  const selected = rows.filter((row) => row.start.host === host && row.start.gate === gate);
  return Object.freeze({
    attempt_count: selected.length,
    samples: Object.freeze(selected.map((row, index) => Object.freeze({
      sequence: index + 1,
      duration_ms: Math.ceil(row.completion.duration_us / 1000),
      outcome: row.completion.outcome
    })))
  });
}

function pairedGate(rows) {
  const selected = rows.filter((row) => row.start.host === "claude_code"
    && row.start.gate === "paired_pong_overhead");
  let expectedFirst = "normal_first";
  return Object.freeze({
    attempt_count: selected.length,
    pairs: Object.freeze(selected.map((row, index) => {
      const c = row.completion;
      if (!["normal_first", "safe_mode_first"].includes(c.pair_order)
          || c.pair_order !== expectedFirst
          || !Number.isSafeInteger(c.normal_duration_us) || c.normal_duration_us < 0
          || !Number.isSafeInteger(c.safe_mode_duration_us) || c.safe_mode_duration_us < 0) {
        throw fail("readiness_pong_pair_invalid");
      }
      expectedFirst = expectedFirst === "normal_first" ? "safe_mode_first" : "normal_first";
      const normal = Math.ceil(c.normal_duration_us / 1000);
      const safe = Math.ceil(c.safe_mode_duration_us / 1000);
      return Object.freeze({
        sequence: index + 1,
        pair_order: c.pair_order,
        normal_duration_ms: normal,
        safe_mode_duration_ms: safe,
        overhead_ms: normal - safe,
        normal_outcome: c.outcome,
        safe_mode_outcome: c.outcome
      });
    }))
  });
}

function evidenceFrom(rows, run, snapshot, mode, endpoint) {
  const completedAt = rows.reduce((latest, row) => row.completion.completed_at > latest
    ? row.completion.completed_at : latest, run.started_at);
  const generatedAt = new Date().toISOString();
  const rawSet = rows.map(({ start, completion }) => ({
    start_sha256: sha256(canonical(start)), completion_sha256: sha256(canonical(completion))
  }));
  const evidence = {
    schema_version: WINDOWS_READINESS_EVIDENCE_SCHEMA,
    run: { schema_version: WINDOWS_READINESS_RUN_SCHEMA, run_id: run.run_id, mode, state: "published" },
    provenance: {
      installation_root_binding_sha256: snapshot.installation_root_binding_sha256,
      host_ledger_sha256: snapshot.host_ledger_sha256,
      device_manifest_sha256: snapshot.device_manifest_sha256,
      publisher_sha256: snapshot.publisher_sha256,
      raw_observation_set_sha256: sha256(canonical(rawSet)),
      raw_observation_count: rows.length
    },
    measurement_window: { started_at: run.started_at, completed_at: completedAt, published_at: generatedAt },
    program_receipts: { count: snapshot.program_receipt_count, set_sha256: snapshot.program_receipts_sha256 },
    configuration: { projection_sha256: snapshot.configuration_sha256 },
    broker_endpoint: endpoint.projection,
    security: (() => {
      const authenticated = timedGate(rows, "security", "authenticated_status")
        .samples.some((sample) => sample.outcome === "succeeded");
      return {
        authenticated_status: authenticated,
        client_server_pid_verified: authenticated,
        process_creation_time_verified: authenticated,
        installed_image_path_verified: authenticated,
        pipe_acl_verified: authenticated,
        remote_clients_rejected: authenticated,
        owner_sid_verified: authenticated,
        logon_session_verified: authenticated,
        installation_root_verified: authenticated,
        manifest_binding_verified: authenticated,
        closed_ipc_surface_verified: authenticated,
        exact_program_receipts_verified: true,
        exact_host_configuration_verified: true
      };
    })(),
    broker_latency: {
      measurement_scope: "native_windows_broker",
      retained_samples: "all_including_failed_and_degraded",
      warm_broker_recall: timedGate(rows, "broker", "warm_broker_recall"),
      cold_authenticated_ready: timedGate(rows, "broker", "cold_authenticated_ready"),
      unavailable_refused_exit: timedGate(rows, "broker", "unavailable_refused_exit")
    },
    host_latency: {
      measurement_scope: "native_windows_host_end_to_end",
      retained_samples: "all_including_failed_and_degraded",
      codex: {
        warm_user_prompt_recall: timedGate(rows, "codex", "warm_user_prompt_recall"),
        warm_session_start_recall: timedGate(rows, "codex", "warm_session_start_recall"),
        cold_authenticated_ready: timedGate(rows, "codex", "cold_authenticated_ready"),
        normal_stop_capture: timedGate(rows, "codex", "normal_stop_capture"),
        unavailable_refused_exit: timedGate(rows, "codex", "unavailable_refused_exit")
      },
      claude_code: {
        warm_user_prompt_recall: timedGate(rows, "claude_code", "warm_user_prompt_recall"),
        warm_session_start_recall: timedGate(rows, "claude_code", "warm_session_start_recall"),
        cold_authenticated_ready: timedGate(rows, "claude_code", "cold_authenticated_ready"),
        normal_stop_capture: timedGate(rows, "claude_code", "normal_stop_capture"),
        unavailable_refused_exit: timedGate(rows, "claude_code", "unavailable_refused_exit"),
        paired_pong_overhead: pairedGate(rows)
      }
    },
    generated_at: generatedAt,
    expires_at: new Date(Date.parse(generatedAt) + EVIDENCE_MAX_AGE_MS).toISOString(),
    evidence_hash: ""
  };
  evidence.evidence_hash = sha256(canonical({ ...evidence, evidence_hash: "" }));
  return evidence;
}

function finalizeInternal({ allowSynthetic = false, failpoint = null } = {}) {
  const p = pathsFor();
  const lock = acquirePublishLock(p, "finalize");
  try {
    const { run, snapshot } = exactRun(p);
    const rows = inventoryObservations(p, run, { allowSynthetic });
    const endpoint = readCurrentEndpoint(p);
    if (endpoint.projection.installation_root_sha256 !== snapshot.installation_root_binding_sha256) {
      throw fail("readiness_root_binding_invalid");
    }
    const currentAuthenticatedProof = rows.some((row) => (
      row.start.host === "security"
      && row.start.gate === "authenticated_status"
      && row.completion.outcome === "succeeded"
      && row.completion.endpoint_binding_sha256 === endpoint.binding_sha256
    ));
    if (!currentAuthenticatedProof) throw fail("readiness_endpoint_drift");
    const evidence = evidenceFrom(rows, run, snapshot, allowSynthetic ? "synthetic_offline" : "native_live", endpoint);
    if (allowSynthetic) {
      // Test-only synthesis never writes, renames, or briefly exposes the live
      // evidence path. The failpoint models the pre-publication interruption
      // without creating an artifact that a crash could strand.
      if (failpoint === "before_rename") throw fail("readiness_publish_interrupted");
    } else {
      atomicJson(p.evidence, evidence, failpoint);
      // The retained run descriptor and observation receipts are immutable
      // source proof.  Only the root-level pointer denotes an active collector;
      // clear it after the evidence rename so doctor can reject every partial
      // publication state without losing the raw records it must recompute.
      unlinkSync(p.active);
      try {
        const directoryFd = openSync(path.dirname(p.active), "r");
        try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
      } catch {}
    }
    return Object.freeze({
      schema_version: WINDOWS_READINESS_EVIDENCE_SCHEMA,
      state: allowSynthetic ? "synthetic_not_published" : "published",
      evidence_hash: evidence.evidence_hash
    });
  } finally {
    releasePublishLock(p, lock);
  }
}

export function finalize() {
  return finalizeInternal();
}

export function abort() {
  const p = pathsFor();
  const lock = acquirePublishLock(p, "abort");
  try {
    const { run } = ownedRun(p);
    const runDirectory = assertNoReparseComponents(path.join(p.runs, run.run_id));
    unlinkSync(p.active);
    rmSync(runDirectory, { recursive: true, force: false });
    return Object.freeze({ schema_version: WINDOWS_READINESS_RUN_SCHEMA, state: "aborted", run_id: run.run_id });
  } finally {
    releasePublishLock(p, lock);
  }
}

// Imported tests can exercise publication atomicity with synthetic observations,
// but this seam always deletes its output and labels the result non-publishable.
export function createSyntheticWindowsReadinessTestSeam() {
  return Object.freeze({
    finalize: (options = {}) => finalizeInternal({ ...options, allowSynthetic: true })
  });
}

async function readCliStdin() {
  if (process.stdin.isTTY) return "";
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

export async function runWindowsReadinessCli(argv = process.argv.slice(2), stdout = process.stdout) {
  const allowed = new Map([["begin", begin], ["status", status], ["finalize", finalize], ["abort", abort]]);
  if (argv.length !== 1 || !allowed.has(argv[0])) return 64;
  if ((await readCliStdin()).length !== 0) return 64;
  try {
    const result = allowed.get(argv[0])();
    stdout.write(`${canonical(result)}\n`);
    return 0;
  } catch {
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runWindowsReadinessCli();
}
