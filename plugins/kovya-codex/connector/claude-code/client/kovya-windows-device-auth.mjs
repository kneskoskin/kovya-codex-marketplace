import {finishStage,finishStageSync} from "../../plugin/diagnostic-events.mjs";
import {submitServerEffect} from "./kovya-phase-authority.mjs";
import {spawnNative} from "./kovya-managed-process.mjs";
import {bindDiagnosticAttempt,diagnosticStage,diagnosticStageSync,diagnosticObservation,diagnosticRecovery,captureDiagnosticNetwork,diagnosticAcceptance,classifyDiagnosticError} from "../../plugin/diagnostic-events.mjs";
import {observeProfileWorkConsumer} from "./kovya-profile-process.mjs";
import nativeCredentialBinding from "./kovya-native-binding.generated.mjs";
import {verifyNativeBindingAsync} from "./kovya-native-binding.mjs";
import { AsyncLocalStorage } from "node:async_hooks";
import { withKovyaWindowsAccountState, WINDOWS_CREDENTIAL_WITNESS_SCHEMA } from "./kovya-windows-broker-native.mjs";
import { validateWindowsBrowserAuthJournal, WINDOWS_BROWSER_AUTH_SECRET_PREFIX } from "./kovya-windows-browser-auth.mjs";
import { spawn } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  timingSafeEqual
} from "node:crypto";
import {
  constants as fsConstants,
  closeSync,
  existsSync,
  fstatSync,
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
import { fileURLToPath } from "node:url";

import { stableJson } from "../../../packages/memory-gateway/src/canonical-json.mjs";
import { consumerRequestSignaturePayload } from "../../kovya-memory-wire-contract.mjs";

export const WINDOWS_AUTH_MANIFEST_SCHEMA = "kovya.windows-device-auth.v1";
export const WINDOWS_AUTH_JOURNAL_SCHEMA = "kovya.windows-device-auth-journal.v1";
export const WINDOWS_CREDENTIAL_TARGET_PREFIX = "Kovya.DeviceAuth/v1/";
export const WINDOWS_AUTH_RECOVERY_WINDOW_MS = 120_000;
export const WINDOWS_PROFILE_MANUAL_COMPLETION_WINDOW_MS = 300_000;
export const WINDOWS_ACCESS_REFRESH_MARGIN_MS = 30_000;

const DEVICE_AUTH_PATHS = Object.freeze({
  sign_in: "/device-auth.v1/sign-in",
  legacy_exchange: "/device-auth.v1/legacy-exchange",
  refresh: "/device-auth.v1/refresh",
  refresh_ack: "/device-auth.v1/refresh",
  logout: "/device-auth.v1/logout",
  browser_sign_in: "/device-auth.v2/browser-authorization/exchange"
});
const MAX_BRIDGE_FRAME_BYTES = 16 * 1024;
const MAX_SECRET_BYTES = 8 * 1024;
const accountTransactions = new AsyncLocalStorage();
const accountQueues = new Map();
const LOCK_STALE_MS = 2 * 60 * 1000;
const ACCESS_TOKEN_PATTERN = /^kva_(?:live|sandbox|test)_[A-Za-z0-9_-]{43,128}$/u;
const REFRESH_TOKEN_PATTERN = /^kvr_(?:live|sandbox|test)_[A-Za-z0-9_-]{43,128}$/u;

export function defaultWindowsAuthManifestPath(env = process.env) {
  const base = env.KOVYA_HOME || path.join(env.USERPROFILE || env.HOME || "", ".kovya");
  if (!path.isAbsolute(base)) throw localError("Kovya home must be an absolute path.", "home_invalid");
  return path.join(base, "windows-device-auth.json");
}

export function loadWindowsAuthManifestSync(manifestPath) {
  const parsed = JSON.parse(readFileSync(manifestPath, "utf8"));
  validateManifest(parsed);
  return Object.freeze(parsed);
}

function stateKey(value) {
  const absolute = path.resolve(value);
  return process.platform === "win32" ? absolute.toLowerCase() : absolute;
}

// Absence is established from directory entries, never from a failed file read.
// These checks also apply to ancestors, including a missing target behind a link.
function ordinaryEntry(targetPath, directory = false) {
  const absolute = path.resolve(targetPath);
  const root = path.parse(absolute).root;
  const components = path.relative(root, absolute).split(path.sep).filter(Boolean);
  let current = root, entry;
  for (let index = 0; index <= components.length; index++) {
    if (index) current = path.join(current, components[index - 1]);
    try { entry = lstatSync(current); }
    catch (error) { if (error?.code === "ENOENT") return null; throw error; }
    const isDirectory = index < components.length || directory;
    if (entry.isSymbolicLink() || (isDirectory ? !entry.isDirectory() : !entry.isFile())) {
      throw localError("Account state path is not ordinary.", "state_path_refused");
    }
  }
  return entry;
}

function readOrdinaryDocument(targetPath, validator) {
  const entry = ordinaryEntry(targetPath);
  if (!entry) return null;
  const descriptor = openSync(targetPath, fsConstants.O_RDONLY);
  try {
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.dev !== entry.dev || opened.ino !== entry.ino) {
      throw localError("Account state changed while opening.", "state_changed");
    }
    if(opened.size>131072)throw localError("Account state is too large.","state_invalid");
    const bytes = new TextDecoder("utf-8",{fatal:true}).decode(readFileSync(descriptor));
    const after = fstatSync(descriptor), named = ordinaryEntry(targetPath);
    if (!named || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs
        || named.dev !== opened.dev || named.ino !== opened.ino) {
      throw localError("Account state changed while reading.", "state_changed");
    }
    return validator(JSON.parse(bytes));
  } finally { closeSync(descriptor); }
}

export function readWindowsAuthDocument(targetPath, validator) {
  const transaction = accountTransactions.getStore();
  if (!transaction || transaction.observing) return readOrdinaryDocument(targetPath, validator);
  const key = stateKey(targetPath);
  if (!transaction.active || !transaction.values.has(key)) {
    throw localError("Account state is outside the owned transaction.", "transaction_scope_invalid");
  }
  const value = transaction.values.get(key);
  return value === null ? null : validator(structuredClone(value));
}

// A new broker transport request is independent of the startup operation that
// created its socket. Use only at request ingress, never to resume account work.
export function runWindowsAuthRequest(work) {
  return accountTransactions.exit(work);
}

export function observeWindowsAuthState(work) {
  const current=accountTransactions.getStore();
  return current && !current.active
    ? accountTransactions.run({...current,observing:true},work) : work();
}

// Observation can read current state, but cannot turn a captured inactive scope
// into fresh mutation authority. Temporary paths use their owning document.
export function assertWindowsAuthEffect(targetPath = null) {
  const transaction = accountTransactions.getStore();
  if (!transaction) return;
  if (!transaction.active || transaction.observing
      || (targetPath !== null && !transaction.values.has(stateKey(targetPath)))) {
    throw localError("Account effect is outside the owned transaction.", "transaction_scope_invalid");
  }
  if (transaction.remainingMs !== null) {
    try { requireWitnessBudget(transaction.remainingMs); }
    catch (error) { transaction.active=false;transaction.values.clear();throw error; }
  }
}

export function rethrowInactiveWindowsAuthError(error) {
  const transaction = accountTransactions.getStore();
  if (transaction && (!transaction.active || transaction.observing)) throw error;
}

export function guardWindowsAuthCredentialBridge(bridge, manifestPath) {
  const guarded = {...bridge, read: (...args) => bridge.read(...args)};
  for (const method of ["write", "writeAndRead", "delete"]) {
    if (typeof bridge[method] !== "function") continue;
    guarded[method] = async (...args) => {
      assertWindowsAuthEffect(manifestPath);
      assertOwnedTarget(args[0]);
      return bridge[method](...args);
    };
  }
  return Object.freeze(guarded);
}

export function recordWindowsAuthDocument(targetPath, value) {
  const transaction = accountTransactions.getStore();
  if (!transaction) return;
  const key = stateKey(targetPath);
  if (!transaction.active || !transaction.values.has(key)) {
    throw localError("Account write is outside the owned transaction.", "transaction_scope_invalid");
  }
  transaction.values.set(key, value === null ? null : structuredClone(value));
}

export async function withWindowsAuthState(manifestPath, origin, work, {
  installationLockHeld = false, accountStateProvider = withKovyaWindowsAccountState,
  credentialWitness = null, remainingMs = null, failFast = false
} = {}) {
  if (path.basename(manifestPath) !== "windows-device-auth.json") throw localError("Account manifest name is invalid.", "manifest_path_invalid");
  const home = path.dirname(manifestPath), key = stateKey(home), current = accountTransactions.getStore();
  authWorkRemaining(remainingMs);
  if (current) {
    if (credentialWitness !== null) throw localError("Credential witness requires fresh ownership.", "account_state_conflict");
    if (!current.active || current.home !== key || current.origin !== origin) throw localError("Account transaction does not match.", "transaction_scope_invalid");
    return work();
  }
  if(failFast && accountQueues.has(key))throw localError("Account repair is busy.","account_state_conflict");
  const previous = accountQueues.get(key) ?? Promise.resolve();
  let unlock;
  const pending = new Promise(resolve => {unlock=resolve;});
  accountQueues.set(key,pending);
  await previous;
  try {
    authWorkRemaining(remainingMs);
    return await accountStateProvider(async (snapshot,nativeSession) => {
      if (credentialWitness !== null) {
        requireWitnessBudget(remainingMs);
        if (installationLockHeld || !nativeSession || nativeSession.role!=="managed_runtime"
            || typeof nativeSession.home!=="string" || stateKey(nativeSession.home)!==key
            || nativeSession.credentialWitnessSchema!==WINDOWS_CREDENTIAL_WITNESS_SCHEMA
            || typeof nativeSession.compareCredentialWitness!=="function")
          throw localError("Credential comparison is unavailable.","account_state_conflict");
        if (await nativeSession.compareCredentialWitness(credentialWitness,{remainingMs}) !== true)
          throw localError("Account state changed.","account_state_conflict");
        requireWitnessBudget(remainingMs);
      }
      const values=decodeAccountSnapshot(manifestPath,origin,snapshot);
      const transaction={home:key,origin,values,active:true,manifestPath,accountStateProvider,nativeSession,remainingMs};
      try {return await accountTransactions.run(transaction,work);}
      finally {transaction.active=false;values.clear();}
    }, {expectedHome:home,installationLockHeld});
  } finally {unlock();if(accountQueues.get(key)===pending)accountQueues.delete(key);}
}

function requireWitnessBudget(remainingMs) {
  const budget=typeof remainingMs==="function" ? Math.floor(Math.min(1000,remainingMs())) : NaN;
  if (!Number.isFinite(budget) || budget<1) throw localError("Account deadline expired.","account_state_conflict");
}

// Capture inside the first owned scope. Return from that scope before external
// work, then supply the witness to a fresh withWindowsAuthState entry.
export async function captureWindowsAuthCredentialWitness({remainingMs}={}) {
  const current=accountTransactions.getStore();
  try {
    requireWitnessBudget(remainingMs);
    if (!current || current.observing) throw localError("Account ownership is unavailable.","account_state_conflict");
    const session=ownedNativeSession(current);
    if (session.credentialWitnessSchema!==WINDOWS_CREDENTIAL_WITNESS_SCHEMA || typeof session.captureCredentialWitness!=="function")
      throw localError("Credential capture is unavailable.","account_state_conflict");
    const witness=await session.captureCredentialWitness({remainingMs});
    assertWindowsAuthEffect(current.manifestPath);
    requireWitnessBudget(remainingMs);
    return witness;
  } catch(error) {
    if(current){current.active=false;current.values.clear();}
    throw error;
  }
}

function decodeAccountSnapshot(manifestPath,origin,snapshot) {
  const names=["manifest","manifest_previous","device_journal","device_journal_previous","browser_journal"];
  if (!snapshot || Object.keys(snapshot).sort().join(",")!==[...names].sort().join(",")) throw localError("Invalid account snapshot.","state_invalid");
  return new Map(accountDocuments(manifestPath,origin).map((doc,index)=>{
    const encoded=snapshot[names[index]];
    if(encoded===null)return [stateKey(doc.path),null];
    if(typeof encoded!=="string" || encoded.length>174764)throw localError("Invalid account snapshot.","state_invalid");
    const bytes=Buffer.from(encoded,"base64");
    try {
      if(bytes.length>131072 || bytes.toString("base64")!==encoded)throw localError("Invalid account snapshot.","state_invalid");
      return [stateKey(doc.path),doc.validate(JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes)))];
    } finally {bytes.fill(0);}
  }));
}

async function refreshOwnedSnapshot() {
  const current=accountTransactions.getStore();
  if(!current?.active)return;
  if(current.nativeSession) {
    const session=ownedNativeSession(current);
    const values=decodeAccountSnapshot(current.manifestPath,current.origin,await session.refreshSnapshot());
    current.values.clear();for(const [key,value] of values)current.values.set(key,value);
    return;
  }
  // The exact active transaction already owns the account lease while a legacy
  // session owner finishes. Refresh through the same guarded native boundary.
  await current.accountStateProvider(snapshot=>{
    const values=decodeAccountSnapshot(current.manifestPath,current.origin,snapshot);
    current.values.clear();for(const [key,value] of values)current.values.set(key,value);
  },{expectedHome:path.dirname(current.manifestPath),installationLockHeld:true});
}

function accountDocuments(manifestPath, origin) {
  const directory = path.join(path.dirname(manifestPath), "state", "device-auth");
  const manifest = value => {
    validateManifest(value);
    if (origin && (value.api_base_url !== origin || value.audience !== origin)) {
      throw localError("Release/account origin mismatch.", "release_account_mismatch");
    }
    return value;
  };
  const journal = value => {
    validateJournal(value);
    if (origin && value.request.audience !== origin) {
      throw localError("Release/account origin mismatch.", "release_account_mismatch");
    }
    return value;
  };
  return [
    {path:manifestPath, validate:manifest},
    {path:`${manifestPath}.previous`, validate:manifest},
    {path:path.join(directory,"pending.json"), validate:journal},
    {path:path.join(directory,"pending.json.previous"), validate:journal},
    {path:path.join(directory,"browser-pending.json"), validate:value => validateWindowsBrowserAuthJournal(value,origin)}
  ];
}

export function createFakeCredentialManagerBridge({ failWriteTargets = [], failDeleteTargets = [] } = {}) {
  const secrets = new Map();
  const writes = [];
  const reads = [];
  const deletions = [];
  const failWrites = new Set(failWriteTargets);
  const failDeletes = new Set(failDeleteTargets);
  return Object.freeze({
    async write(target, value) {
      assertOwnedTarget(target);
      const secret = secretBuffer(value);
      try {
        writes.push(target);
        if (failWrites.has(target)) throw localError("Credential write failed.", "credential_write_failed");
        secrets.set(target, Buffer.from(secret));
      } finally {
        secret.fill(0);
      }
    },
    async read(target) {
      assertOwnedTarget(target);
      reads.push(target);
      const value = secrets.get(target);
      return value ? Buffer.from(value) : null;
    },
    async delete(target) {
      assertOwnedTarget(target);
      deletions.push(target);
      if (failDeletes.has(target)) throw localError("Credential delete failed.", "credential_delete_failed");
      const value = secrets.get(target);
      value?.fill(0);
      return secrets.delete(target);
    },
    seed(target, value) {
      assertOwnedTarget(target);
      const secret = secretBuffer(value);
      try { secrets.set(target, Buffer.from(secret)); } finally { secret.fill(0); }
    },
    has(target) { return secrets.has(target); },
    targets() { return [...secrets.keys()].sort(); },
    snapshot() {
      return Object.freeze({ writes: [...writes], reads: [...reads], deletions: [...deletions] });
    }
  });
}

function credentialManagerBridge({
  bridgePath = fileURLToPath(new URL("./kovya_windows_credential_bridge.ps1", import.meta.url)),
  spawnImpl = spawn,
  timeoutMs = 30_000, exchange
} = {}) {
  if (!path.isAbsolute(bridgePath)) throw localError("Credential bridge path must be absolute.", "bridge_path_invalid");
  return Object.freeze({
    async write(target, value) {
      const response = await invokeBridge({ operation: "write", target, value, bridgePath, spawnImpl, timeoutMs, exchange });
      if (response.metadata.ok !== true || response.secret.length !== 0) {
        throw localError("Credential write failed.", "credential_write_failed");
      }
    },
    async read(target) {
      const response = await invokeBridge({ operation: "read", target, bridgePath, spawnImpl, timeoutMs, exchange });
      if (response.metadata.ok !== true) return null;
      return response.secret;
    },
    async delete(target) {
      const response = await invokeBridge({ operation: "delete", target, bridgePath, spawnImpl, timeoutMs, exchange });
      if (response.metadata.ok !== true) throw localError("Credential delete failed.", "credential_delete_failed");
      return response.metadata.deleted === true;
    }
  });
}

export function createWindowsCredentialManagerBridge(options={}) {
  return credentialManagerBridge(options);
}
function ownedNativeSession(transaction) {
  const session=transaction.nativeSession;
  if(!transaction.active || !session || session.role!=="managed_runtime"
      || stateKey(session.home)!==transaction.home || typeof session.refreshSnapshot!=="function"
      || typeof session.exchangeCredential!=="function")
    throw localError("Account session is unavailable.","transaction_scope_invalid");
  return session;
}
export function createWindowsManagedCredentialManagerBridge({spawnImpl=spawn,timeoutMs=30_000}={}) {
  const executablePath=fileURLToPath(new URL("./kovya_windows_broker_native.exe",import.meta.url));
  const bridge=credentialManagerBridge({exchange:async frame=>{
    const transaction=accountTransactions.getStore();
    if(transaction)return ownedNativeSession(transaction).exchangeCredential(frame);
    await verifyNativeBindingAsync(executablePath,["managed_runtime"]);
    const env={};
    for(const key of ["SystemRoot","WINDIR","ProgramFiles","USERPROFILE","HOME","USERDOMAIN","USERNAME","SESSIONNAME","KOVYA_HOME"])
      if(typeof process.env[key]==="string")env[key]=process.env[key];
    env.PATH=path.join(process.env.SystemRoot??"C:\\Windows","System32");
    return runManagedCredentialProcess({executablePath,frame,spawnImpl,timeoutMs,env});
  }});
  return Object.freeze({...bridge,async writeAndRead(target,value) {
    const transaction=accountTransactions.getStore();
    if(!transaction)throw localError("Account session is unavailable.","transaction_scope_invalid");
    const session=ownedNativeSession(transaction);
    const response=await invokeBridge({operation:"write_read",target,value,
      exchange:frame=>session.exchangeCredential(frame)});
    if(response.metadata.ok!==true || response.metadata.operation!=="write_read") {
      response.secret.fill(0);
      throw localError("Credential write/read-back failed.","credential_readback_failed");
    }
    return response.secret;
  }});
}
function defaultCredentialBridge() {
  if(!nativeCredentialBinding || !Object.isFrozen(nativeCredentialBinding)
      || Object.keys(nativeCredentialBinding).sort().join(",")!=="expected_role,native_sha256"
      || !/^[a-f0-9]{64}$/.test(nativeCredentialBinding.native_sha256))
    throw localError("Credential binding is not configured.","broker_native_identity_refused");
  if(nativeCredentialBinding.expected_role==="managed_runtime")return createWindowsManagedCredentialManagerBridge();
  if(nativeCredentialBinding.expected_role==="legacy_layout")return createWindowsCredentialManagerBridge();
  throw localError("Credential role is refused.","broker_native_identity_refused");
}

export function resolveWindowsPowerShellExecutable(nodeExecutablePath = process.execPath) {
  const nodeDirectory = path.dirname(nodeExecutablePath);
  const runtimeDirectory = path.dirname(nodeDirectory);
  const packaged = path.basename(nodeExecutablePath).toLowerCase() === "node.exe"
    && path.basename(nodeDirectory).toLowerCase() === "node"
    && path.basename(runtimeDirectory).toLowerCase() === "runtime";
  if (!packaged) return "pwsh";
  const markerPath = path.join(runtimeDirectory, "kovya-runtime.json");
  const powershellPath = path.join(runtimeDirectory, "powershell", "pwsh.exe");
  try {
    if (!path.isAbsolute(nodeExecutablePath)) throw new Error("Runtime path is relative.");
    for (const target of [markerPath, powershellPath]) {
      const entry = lstatSync(target);
      if (!entry.isFile() || entry.isSymbolicLink()) throw new Error("Runtime file is unavailable.");
    }
    const marker = JSON.parse(readFileSync(markerPath, "utf8"));
    if (marker.schema_version !== "kovya.windows-packaged-runtime.v1" || marker.architecture !== "x64"
        || marker.node_relative_path !== "node/node.exe"
        || marker.powershell_relative_path !== "powershell/pwsh.exe") {
      throw new Error("Runtime binding is invalid.");
    }
    return powershellPath;
  } catch (cause) {
    throw localError("The packaged PowerShell runtime is unavailable.", "packaged_runtime_invalid", cause);
  }
}

function authWorkRemaining(remainingMs) {
  if (remainingMs === null) return Infinity;
  try {
    const remaining = typeof remainingMs === "function" ? remainingMs() : NaN;
    if (!Number.isFinite(remaining) || remaining < 1)
      throw localError("Authentication Work expired.", "broker_deadline_refused");
    return Math.floor(Math.min(1000, remaining));
  } catch (error) {
    const current = accountTransactions.getStore();
    if (current?.remainingMs === remainingMs) { current.active = false; current.values.clear(); }
    if (error?.code === "profile_work_ended")
      throw localError("Authentication Work expired.", "broker_deadline_refused");
    throw error;
  }
}

export function createPinnedDeviceAuthTransport({
  apiBaseUrl,
  fetchImpl = globalThis.fetch,
  timeoutMs = 10_000,
  remainingMs = null
} = {}) {
  const origin = validatedServiceOrigin(apiBaseUrl);
  if (typeof fetchImpl !== "function") throw localError("Device authentication transport is unavailable.", "transport_unavailable");
  return Object.freeze({
    async request({ path: requestPath, headers, body }) {
      if (!Object.values(DEVICE_AUTH_PATHS).includes(requestPath)) {
        throw localError("Device authentication route is refused.", "route_refused");
      }
      if (Buffer.byteLength(stableJson(body), "utf8") > 32_768) {
        throw localError("Device authentication request is too large.", "request_too_large");
      }
      const serializedBody = JSON.stringify(body);
      let response, dispatched = false;
      const diagnosticRoute={sign_in:"device_sign_in",legacy_exchange:"device_legacy_exchange",refresh:"device_refresh",logout:"device_logout",browser_sign_in:"browser_exchange"}[Object.keys(DEVICE_AUTH_PATHS).find(key=>DEVICE_AUTH_PATHS[key]===requestPath)]??"unknown";
      const diagnosticStarted=performance.now();
      try {
        diagnosticObservation({stage:"request",route:diagnosticRoute,request_outcome:"dispatched_no_response",outcome:"started",reason:"none"});
        const timeout = Math.floor(Math.min(timeoutMs, authWorkRemaining(remainingMs)));
        if (timeout < 1) throw localError("Authentication Work expired.", "broker_deadline_refused");
        const signal = AbortSignal.timeout(timeout);
        dispatched = true;
        const fetchUrl=`${origin}${requestPath}`;
        const fetchOptions={method:"POST",redirect:"manual",headers,body:serializedBody,signal};
        response = await submitServerEffect("account",()=>fetchImpl(fetchUrl,fetchOptions));
      } catch (cause) {
        if (!dispatched) throw cause;
        diagnosticObservation({stage:"request",route:diagnosticRoute,request_outcome:"dispatched_no_response",outcome:"failed",reason:"remote_ambiguous",elapsed_ms:performance.now()-diagnosticStarted});
        throw ambiguousError("Device authentication outcome is unknown.", cause);
      }
      authWorkRemaining(remainingMs);
      diagnosticObservation({stage:"request",route:diagnosticRoute,http_status:response.status,request_outcome:"response_observed",outcome:"unknown",reason:"none",elapsed_ms:performance.now()-diagnosticStarted});
      if (response.status >= 300 && response.status < 400) {
        throw localError("Device authentication redirects are refused.", "redirect_refused");
      }
      const contentType = response.headers?.get?.("content-type")?.split(";", 1)[0]?.trim()?.toLowerCase();
      if (contentType !== "application/json") {
        throw localError("Device authentication response type is invalid.", "response_invalid");
      }
      const payload = await readBoundedJsonResponse(response, () => authWorkRemaining(remainingMs));
      if (response.status >= 200 && response.status < 300 && payload?.ok === true) return payload;
      if (response.status >= 400 && response.status < 500) {
        if (payload?.outcome === "sign_in_required") {
          throw localError("Kovya sign-in is required.", "sign_in_required");
        }
        throw localError("Authentication failed.", "confirmed_no_effect");
      }
      throw ambiguousError("Device authentication outcome is unknown.");
    }
  });
}

async function readBoundedJsonResponse(response, check = () => {}) {
  const declaredLength = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > 32_768) {
    throw localError("Device authentication response is too large.", "response_too_large");
  }
  const reader = response.body?.getReader?.();
  if (!reader) throw localError("Device authentication response is invalid.", "response_invalid");
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      check();
      const { done, value } = await reader.read();
      check();
      if (done) break;
      total += value.byteLength;
      if (total > 32_768) {
        await reader.cancel().catch(() => {});
        throw localError("Device authentication response is too large.", "response_too_large");
      }
      chunks.push(Buffer.from(value));
    }
    const bytes = Buffer.concat(chunks);
    try { return JSON.parse(bytes.toString("utf8")); }
    catch { throw localError("Device authentication response is invalid.", "response_invalid"); }
    finally { bytes.fill(0); }
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    reader.releaseLock?.();
  }
}

export function createWindowsDeviceAuthManager({
  manifestPath = defaultWindowsAuthManifestPath(),
  bridge = null,
  transport = null,
  apiBaseUrl = null,
  audience = null,
  now = () => new Date().toISOString(),
  random = randomBytes,
  lockTimeoutMs = 8_000,
  installationLockHeld = false,
  legacyProvider = null,
  retainSigningKeyInMemory = false,
  browserAuthenticator = null,
  adaptersFactory = null,
  accountStateProvider = withKovyaWindowsAccountState,
  remainingMs = null
} = {}) {
  if (!path.isAbsolute(manifestPath)) throw localError("Auth manifest path must be absolute.", "manifest_path_invalid");
  const home = path.dirname(manifestPath);
  const stateDirectory = path.join(home, "state", "device-auth");
  const journalPath = path.join(stateDirectory, "pending.json");
  const installLockPath = path.join(stateDirectory, "install.lock");
  const documents = accountDocuments(manifestPath, apiBaseUrl);
  let effectiveTransport = transport;
  let accessCredential = null;
  let accessExpiresAtMs = null;
  let refreshBarrier = null;
  let signingKeyObject = null;
  let signingKeyTarget = null;
  let adaptersReady=false, cacheBinding=null;
  const underInstallLock = (work,{recover=true}={}) => withWindowsAuthState(manifestPath,apiBaseUrl,async()=>{
    authWorkRemaining(remainingMs);
    if(recover)recoverAtomicFiles(manifestPath,journalPath);
    const binding=stableJson(readJsonIfPresent(manifestPath,validateManifest));
    if(cacheBinding!==null && binding!==cacheBinding)clearMemorySecrets();
    if(!adaptersReady) {
      if(adaptersFactory) ({bridge,browserAuthenticator}=adaptersFactory());
      bridge = guardWindowsAuthCredentialBridge(bridge ?? defaultCredentialBridge(),manifestPath);
      effectiveTransport ??= createPinnedDeviceAuthTransport({apiBaseUrl,remainingMs});
      adaptersReady=true;
    }
    try {return await work();}
    finally {
      if (accountTransactions.getStore()?.active) cacheBinding=stableJson(readJsonIfPresent(manifestPath,validateManifest));
      else clearMemorySecrets();
    }
  },{installationLockHeld,accountStateProvider,remainingMs});

  const manager = {
    manifestPath,
    journalPath,


    async startProfileAutomatic({remainingMs,localPhase=null,observeNetwork=observeProfileWorkConsumer,deviceLabel="Kovya coding harness",host="codex"}={}) {
      const phase=(work,witness=null,name="local_preparation",network=null)=>{
        const execute=localRemaining=>{
          const run=()=>{if(network?.error)throw network.error;return finishStage("state_binding",()=>manualPhase(localRemaining,()=>work(localRemaining),witness,name));};
          return name==="local_acceptance"?diagnosticAcceptance(run):run();
        };
        return localPhase?localPhase(name,execute,network?.observation):execute(remainingMs);
      };
      let prepared,receiver,exchange;
      const current=()=>{
        const value=readJsonIfPresent(journalPath,validateJournal);
        if(!value?.profile_automatic||value.request.request_id!==prepared.journal.request.request_id
          ||stableJson(value.automatic_binding)!==stableJson(prepared.journal.automatic_binding))throw localError("Pending sign-in changed.","account_state_conflict");
        if(!["prepared","remote_ambiguous"].includes(value.phase))throw localError("Pending sign-in is retiring.","account_state_conflict");
        assertJournalRecoveryFresh(value,now);return value;
      };
      try {
        prepared=await phase(async localRemaining=>{
          let values=documents.map(doc=>readWindowsAuthDocument(doc.path,doc.validate));
          if(await retireExpiredManual(values,localRemaining))values=documents.map(doc=>readWindowsAuthDocument(doc.path,doc.validate));
          if(values[1]||values[2]||values[3]||values[4]){
            let repair_guidance;
            if(values[2]?.profile_automatic)try{
              const proof=await automaticRetirementProof(values,localRemaining,host);
              repair_guidance={observation:"current_expired_automatic_connect",action:"ask_one_go",question:"Would you like me to repair Kovya?",eligibility:"native_current_proof_required",target:proof.target};
            }catch(error){rethrowInactiveWindowsAuthError(error);}
            return {terminal:{ok:false,outcome:"pending",...diagnosticRecovery(values[2]),...(repair_guidance?{repair_guidance}:{})}};
          }
          if(values[0])return {terminal:{ok:true,outcome:"session_present",manifest:publicManifest(values[0])}};
          const keys=generateKeyPairSync("ed25519"),privateKey=Buffer.from(keys.privateKey.export({type:"pkcs8",format:"pem"}));
          const publicKeyPem=keys.publicKey.export({type:"spki",format:"pem"});
          const preparationDeadlineMono=performance.now()+35000;
          const request=newRequest("browser_sign_in",audience??apiBaseUrl,now,random,{signing_public_key_pem:publicKeyPem,device_label:boundedLabel(deviceLabel)});
          bindDiagnosticAttempt(request.body.request_id);
          const target=pendingSigningTarget(request.body.request_id),secretTarget=`${WINDOWS_BROWSER_AUTH_SECRET_PREFIX}${digest(request.body.request_id)}`;
          let journal={...createJournal({operation:"browser_sign_in",request,pendingSigningTarget:target,now}),profile_automatic:true,
            phase:"prepared",staged_targets:[target,secretTarget],automatic_timing:{schema_version:"kovya.automatic-timing.v1",start_deadline_at:new Date(Date.parse(request.body.request_time)+35000).toISOString(),accepted_at:null,page_expires_at:null},recovery_expires_at:new Date(Date.parse(request.body.request_time)+35000).toISOString()};
          writeJsonAtomic(journalPath,journal);
          try {
            await writeAndVerifyCredential(bridge,target,privateKey,value=>validatePrivateKey(value,publicKeyPem),{compound:true});
            const body=await browserAuthenticator.prepareAutomatic({requestId:request.body.request_id,devicePublicKeyPem:publicKeyPem,deviceLabel,preparation:{start_deadline_at:journal.automatic_timing.start_deadline_at,deadline_mono:preparationDeadlineMono}});
            journal={...journal,automatic_binding:{pkce_challenge:body.pkce_challenge,consent_nonce_hash:body.consent_nonce_hash,state_sha256:digest(body.state),redirect_uri:null}};
            writeJsonAtomic(journalPath,journal);
            return {body,journal,witness:await captureWindowsAuthCredentialWitness({remainingMs:localRemaining})};
          } finally {privateKey.fill(0);}
        });
        if(prepared.terminal)return prepared.terminal;
        // Each phase has completed checked native End before external effects/wait.
        receiver=await browserAuthenticator.openAutomaticReceiver(prepared.body,{timing:prepared.journal.automatic_timing});
        prepared.body.redirect_uri=receiver.redirectUri;
        prepared=await phase(async localRemaining=>{
          const pending=current();
          const journal={...pending,phase:"remote_ambiguous",automatic_binding:{...pending.automatic_binding,redirect_uri:receiver.redirectUri}};
          writeJsonAtomic(journalPath,journal);
          return {...prepared,journal,witness:await captureWindowsAuthCredentialWitness({remainingMs:localRemaining})};
        },prepared.witness);
        const started=await captureDiagnosticNetwork("browser_start",()=>observeNetwork("authorization_request",()=>browserAuthenticator.requestAutomaticStart(prepared.body,{authentication:!!localPhase,remainingMs:localPhase?null:remainingMs})));
        const accepted=await phase(async localRemaining=>{
          const pending=current();
          const info=await browserAuthenticator.acceptAutomaticStart(prepared.body,started.value,pending.created_at,pending.recovery_expires_at,{timing:pending.automatic_timing,beforePublish:timing=>{
            const next={...pending,automatic_timing:timing,recovery_expires_at:new Date(Date.parse(timing.page_expires_at)+35000).toISOString()};
            writeJsonAtomic(journalPath,next);prepared.journal=next;
          }});
          return {...info,witness:await captureWindowsAuthCredentialWitness({remainingMs:localRemaining})};
        },prepared.witness,"local_acceptance",started);
        receiver.arm(accepted.policy);
        await receiver.open(accepted.authorization_url);
        let callback;
        try {callback=await receiver.result;}
        catch(error){
          if(["callback_cancelled","callback_timeout"].includes(error?.reason))return {ok:false,outcome:error.reason==="callback_cancelled"?"cancelled":"pending",...diagnosticRecovery(prepared.journal)};
          throw error;
        }
        exchange=await phase(async localRemaining=>{
          const pending=current();
          const value=await browserAuthenticator.prepareAutomaticExchange(pending.request.request_id,callback,pending.automatic_binding);
          return {...value,witness:await captureWindowsAuthCredentialWitness({remainingMs:localRemaining})};
        },accepted.witness);
        const network=exchange.result?null:await captureDiagnosticNetwork("browser_exchange",()=>observeNetwork("authorization_request",()=>browserAuthenticator.requestAutomaticExchange(exchange.body,{authentication:!!localPhase,remainingMs:localPhase?null:remainingMs,attemptHint:exchange.attemptHint??null,admission:exchange.admission})));
        const result=exchange.result??network.value;
        return await phase(async()=>{
          const pending=current();
          validateManualExchangeTypes(result);validateAuthResult(result,"browser_sign_in");validateAuthorityResult(result,validatedServiceOrigin(apiBaseUrl));
          if(audience!=null&&validatedAudience(audience)!==apiBaseUrl)throw localError("Authority mismatch.","authority_mismatch");
          if(Object.hasOwn(result,"memory_api_base_url"))validatedMemoryOrigin(result.memory_api_base_url);
          await browserAuthenticator.acceptAutomaticResult(pending.request.request_id,result,pending.automatic_binding,exchange.admission);
          const key=await requiredCredential(bridge,pending.pending_signing_target,"credential_missing");
          try {
            validatePrivateKey(key,pending.request.signing_public_key_pem);
            const committed=await commitSession({operation:"browser_sign_in",result,privateKey:key,publicKeyPem:pending.request.signing_public_key_pem,journal:pending,stagedTarget:pending.pending_signing_target,keepJournal:true});
            await browserAuthenticator.clearPending();removeIfPresent(journalPath);return committed;
          } finally {key.fill(0);}
        },exchange.witness,"local_acceptance",network);
      } finally {
        try {receiver?.close();} finally {
          if(prepared?.body)prepared.body.state=null;
          if(exchange?.body){exchange.body.code=null;exchange.body.pkce_verifier=null;exchange.body.consent_nonce=null;}
          if(exchange)exchange.result=null;
        }
      }
    },

    async startProfileManual({remainingMs,localPhase=null,observeNetwork=observeProfileWorkConsumer,deviceLabel="Kovya coding harness"}={}) {
      const phase=(work,witness=null,name="local_preparation",network=null)=>{
        const execute=localRemaining=>{
          const run=()=>{if(network?.error)throw network.error;return finishStage("state_binding",()=>manualPhase(localRemaining,()=>work(localRemaining),witness,name));};
          return name==="local_acceptance"?diagnosticAcceptance(run):run();
        };
        return localPhase?localPhase(name,execute,network?.observation):execute(remainingMs);
      };
      let staged;
      try {
        staged=await phase(async localRemaining=>{
          let values=documents.map(doc=>readWindowsAuthDocument(doc.path,doc.validate));
          if(await retireExpiredManual(values,localRemaining))values=documents.map(doc=>readWindowsAuthDocument(doc.path,doc.validate));
          if(values[1]||values[3])return {terminal:{ok:false,outcome:"pending"}};
          const pending=values[2];
          if(pending) {
            if(!pending.profile_manual||pending.phase!=="manual_required")return {terminal:{ok:false,outcome:pending.profile_manual?"ambiguous":"pending",...diagnosticRecovery(pending)}};
            requireManualJournal(pending,values[4]);
            bindDiagnosticAttempt(pending.request.request_id,{created_at:pending.created_at,expires_at:values[4]?.expires_at});
            return {terminal:manualPublic(await browserAuthenticator.manualPending(pending.request.request_id),pending)};
          }
          if(values[4])return {terminal:{ok:false,outcome:"pending"}};
          if(values[0])return {terminal:{ok:true,outcome:"session_present",manifest:publicManifest(values[0])}};
          const keys=generateKeyPairSync("ed25519"),privateKey=Buffer.from(keys.privateKey.export({type:"pkcs8",format:"pem"}));
          const publicKeyPem=keys.publicKey.export({type:"spki",format:"pem"});
          const request=newRequest("browser_sign_in",audience??apiBaseUrl,now,random,{signing_public_key_pem:publicKeyPem,device_label:boundedLabel(deviceLabel)});
          bindDiagnosticAttempt(request.body.request_id);
          const target=pendingSigningTarget(request.body.request_id),secretTarget=`${WINDOWS_BROWSER_AUTH_SECRET_PREFIX}${digest(request.body.request_id)}`;
          let journal={...createJournal({operation:"browser_sign_in",request,pendingSigningTarget:target,now}),profile_manual:true,
            phase:"manual_start_pending",staged_targets:[target,secretTarget]};
          // Both references exist durably before either credential can be written.
          diagnosticStageSync("journal_publication",()=>writeJsonAtomic(journalPath,journal));
          diagnosticObservation({...diagnosticRecovery(journal),created_at:journal.created_at,journals:["state/device-auth/pending.json"],outcome:"succeeded",stage:"journal_publication",reason:"none"});
          try {
            await diagnosticStage("signing_key_staging",()=>writeAndVerifyCredential(bridge,target,privateKey,value=>validatePrivateKey(value,publicKeyPem),{compound:true}));
            const body=await browserAuthenticator.prepareManual({requestId:request.body.request_id,devicePublicKeyPem:publicKeyPem,deviceLabel});
            journal={...journal,manual_binding:{pkce_challenge:body.pkce_challenge,consent_nonce_hash:body.consent_nonce_hash,state_sha256:digest(body.state)}};
            diagnosticStageSync("binding_publication",()=>writeJsonAtomic(journalPath,journal));
            return {body,journal,witness:await diagnosticStage("credential_witness",()=>captureWindowsAuthCredentialWitness({remainingMs:localRemaining}))};
          } finally {privateKey.fill(0);}
        },null,"local_preparation");
        if(staged.terminal)return staged.terminal;
        if(!localPhase)remainingMs();
        const network=await captureDiagnosticNetwork("browser_start",()=>observeNetwork("authorization_request",()=>diagnosticStage("request",()=>browserAuthenticator.requestManualStart(staged.body,localPhase?null:remainingMs,{authentication:!!localPhase}))));
        if(!localPhase)remainingMs();
        return await phase(async()=>{
          const pending=readJsonIfPresent(journalPath,validateJournal);
          if(pending?.request.request_id!==staged.journal.request.request_id)throw localError("Pending sign-in changed.","account_state_conflict");
          assertJournalRecoveryFresh(pending,now);
          const completionExpiresAt=new Date(Date.parse(pending.request.request_time)+WINDOWS_PROFILE_MANUAL_COMPLETION_WINDOW_MS).toISOString();
          const result=await diagnosticStage("response_acceptance",()=>browserAuthenticator.acceptManualStart(staged.body,network.value,staged.journal.created_at,completionExpiresAt));
          const published={...pending,phase:"manual_required"};
          try{writeJsonAtomic(journalPath,published);}catch(error){throw classifyDiagnosticError(error,"state_write_failed");}
          return manualPublic(result,published);
        },staged.witness,"local_acceptance",network);
      } finally {if(staged?.body)staged.body.state=null;}
    },

    async finishProfileManual({remainingMs,localPhase=null,observeNetwork=observeProfileWorkConsumer,inputProvider=null,pendingRef,code}={}) {
      const phase=(work,witness=null,name="local_preparation",network=null)=>{
        const execute=localRemaining=>{
          const run=()=>{if(network?.error)throw network.error;return finishStage("state_binding",()=>manualPhase(localRemaining,()=>work(localRemaining),witness,name));};
          return name==="local_acceptance"?diagnosticAcceptance(run):run();
        };
        return localPhase?localPhase(name,execute,network?.observation):execute(remainingMs);
      };
      let prepared;
      try {
        if(!inputProvider&&pendingRef==null)throw localError("Pending sign-in reference is required.","account_state_conflict");
        prepared=await phase(async localRemaining=>{
          if(inputProvider){const input=await finishStage("protected_input",()=>inputProvider(localRemaining));pendingRef=input.pending_ref;code=input.code;}
          if(pendingRef==null)throw localError("Pending sign-in reference is required.","account_state_conflict");
          const values=finishStageSync("state_binding",()=>documents.map(doc=>readWindowsAuthDocument(doc.path,doc.validate))),pending=values[2];
          if(await retireExpiredManual(values,localRemaining,pendingRef))return {terminal:{ok:false,outcome:"sign_in_required"}};
          if(values[0]||values[1]||values[3]||!pending?.profile_manual
              ||!["manual_required","manual_exchange_pending","local_write_failed"].includes(pending.phase))return {terminal:{ok:false,outcome:"pending"}};
          requireManualJournal(pending,values[4]);
          if(pending.request.request_id!==pendingRef)throw localError("Pending sign-in changed.","account_state_conflict");
          bindDiagnosticAttempt(pending.request.request_id,{created_at:pending.created_at,expires_at:values[4]?.expires_at});
          const key=await finishStage("signing_key_read",()=>requiredCredential(bridge,pending.pending_signing_target,"credential_missing"));
          try {finishStageSync("signing_key_validate",()=>validatePrivateKey(key,pending.request.signing_public_key_pem));}finally{key.fill(0);}
          const exchange=await finishStage("exchange_prepare",()=>browserAuthenticator.prepareManualExchange(pendingRef,code,pending.manual_binding));
          finishStageSync("exchange_journal",()=>writeJsonAtomic(journalPath,{...pending,phase:"manual_exchange_pending"}));
          return {...exchange,pending,witness:await finishStage("credential_witness",()=>captureWindowsAuthCredentialWitness({remainingMs:localRemaining}))};
        });
        if(prepared.terminal)return prepared.terminal;
        if(!localPhase)remainingMs();
        const network=prepared.result?null:await captureDiagnosticNetwork("browser_exchange",()=>observeNetwork("authorization_request",()=>finishStage("exchange_http",()=>browserAuthenticator.requestManualExchange(prepared.body,localPhase?null:remainingMs,{authentication:!!localPhase,attemptHint:prepared.attemptHint??null}))));
        const result=prepared.result??network.value;
        if(!localPhase)remainingMs();
        return await phase(async()=>{
          const pending=readJsonIfPresent(journalPath,validateJournal);
          const browserPending=readWindowsAuthDocument(documents[4].path,documents[4].validate);
          requireManualJournal(pending,browserPending);
          if(pending.request.request_id!==pendingRef)throw localError("Pending sign-in changed.","account_state_conflict");
          bindDiagnosticAttempt(pending.request.request_id,{created_at:pending.created_at,expires_at:browserPending?.expires_at});
          // Reject routing before commitSession's legacy compensating-network path.
          finishStageSync("exchange_response_validate",()=>validateManualExchangeTypes(result));
          finishStageSync("exchange_response_validate",()=>{validateAuthResult(result,"browser_sign_in");validateAuthorityResult(result,validatedServiceOrigin(apiBaseUrl));});
          if(audience!=null&&validatedAudience(audience)!==apiBaseUrl)throw localError("Authority mismatch.","authority_mismatch");
          if(Object.hasOwn(result,"memory_api_base_url"))validatedMemoryOrigin(result.memory_api_base_url);
          await finishStage("browser_result_accept",()=>browserAuthenticator.acceptManualResult(pendingRef,result));
          const key=await finishStage("signing_key_read",()=>requiredCredential(bridge,pending.pending_signing_target,"credential_missing"));
          try {
            finishStageSync("signing_key_validate",()=>validatePrivateKey(key,pending.request.signing_public_key_pem));
            const committed=await commitSession({operation:"browser_sign_in",result,privateKey:key,publicKeyPem:pending.request.signing_public_key_pem,
              journal:pending,stagedTarget:pending.pending_signing_target,keepJournal:true});
            await finishStage("browser_pending_retire",()=>browserAuthenticator.clearPending());finishStageSync("pending_journal_retire",()=>removeIfPresent(journalPath));
            return committed;
          } finally {key.fill(0);}
        },prepared.witness,"local_acceptance",network);
      } finally {
        if(prepared?.body){prepared.body.code=null;prepared.body.pkce_verifier=null;prepared.body.consent_nonce=null;}
        if(prepared)prepared.result=null;
        if(Buffer.isBuffer(code))code.fill(0);
      }
    },

    inspect() {
      if(accountTransactions.getStore() && !accountTransactions.getStore().active)return observeWindowsAuthState(()=>manager.inspect());
      const values=documents.map(doc=>readWindowsAuthDocument(doc.path,doc.validate));
      const journal=values[2] ?? values[3];
      if (journal) return Object.freeze({ state: "pending", operation: journal.operation, ...diagnosticRecovery(journal), phase:journal.phase });
      if(values[4])return Object.freeze({state:"pending",operation:"browser_sign_in",phase:"browser_pending"});
      const manifest = values[0] ?? values[1];
      if (!manifest) {
        return Object.freeze({ state: legacyProvider?.isPresent?.() ? "legacy_exchange" : "sign_in" });
      }
      return Object.freeze({ state: "existing_session", manifest: publicManifest(manifest) });
    },

    async install({ accountAccessKeyProvider = null, manualCodeProvider = null, deviceLabel = "Windows device" } = {}) {
      return underInstallLock(async () => {
        recoverAtomicFiles(manifestPath, journalPath);
        const pending = readJsonIfPresent(journalPath, validateJournal);
        if (pending) {
          const resumed = await resumePending(pending, { accountAccessKeyProvider, manualCodeProvider });
          if (resumed.outcome !== "sign_in_required") return resumed;
        }
        let manifest = readJsonIfPresent(manifestPath, validateManifest);
        if (manifest) {
          const refreshed = await withFileLock(sessionLockPath(stateDirectory, manifest), lockTimeoutMs, async () => {
            const latest = readJsonIfPresent(manifestPath, validateManifest);
            if (!latest) throw localError("Kovya sign-in is required.", "sign_in_required");
            if (!(await credentialPairPresent(latest))) {
              await deleteLocalAuth({ manifest: latest, pending: null });
              return null;
            }
            return refreshUnderLock(await cleanupRetiredTargets(latest));
          });
          if (refreshed) return Object.freeze({ ...refreshed, path: "existing_session" });
          manifest = null;
        }
        if (legacyProvider?.isPresent?.()) return legacyExchange({ deviceLabel });
        if (browserAuthenticator) return browserSignIn({ deviceLabel });
        if (typeof accountAccessKeyProvider !== "function") {
          return Object.freeze({ ok: false, outcome: "sign_in_required", path: "sign_in" });
        }
        return signIn({ accountAccessKeyProvider, deviceLabel });
      });
    },

    async retryPending({ adjudicate = null } = {}) {
      return underInstallLock(async () => {
        const pending = readJsonIfPresent(journalPath, validateJournal);
        if (!pending) return Object.freeze({ ok: true, outcome: "nothing_pending" });
        return resumePending(pending, { adjudicate });
      });
    },

    // This entry never delegates to resumptive auth work. The caller supplies
    // one live account/request scope; classification precedes backup recovery.
    async repairLocal({target=null,host="codex"}={}) {
      return underInstallLock(async () => {
        if(target!==null)return retireAutomatic(target,host);
        const transaction=accountTransactions.getStore();
        const session=ownedNativeSession(transaction);
        if(typeof transaction.remainingMs!=="function")throw localError("Repair request ownership is required.","transaction_scope_invalid");
        assertWindowsAuthEffect(manifestPath);
        const values=documents.map(doc=>readWindowsAuthDocument(doc.path,doc.validate));
        const manifest=values[0]??values[1],pending=values[2]??values[3],browser=values[4];
        const unresolved=()=>Object.freeze({ok:false,outcome:pending?.phase==="manual_required"?"manual_required":"pending"});
        if(!pending) {
          if(browser)return unresolved();
          if(!manifest || !(await validLocalCredentials(manifest)))return Object.freeze({ok:false,outcome:"sign_in_required"});
          assertWindowsAuthEffect(manifestPath);
          return Object.freeze({ok:true,outcome:"existing"});
        }
        const refresh=pending.operation==="refresh"&&pending.phase==="local_commit_cleanup_pending";
        const enrollment=pending.operation==="browser_sign_in"&&pending.phase==="local_committed_cleanup_pending";
        if(!refresh&&!enrollment)return unresolved();
        const refuse=()=>{throw localError("Committed recovery binding changed.","account_state_conflict");};
        if(!manifest || pending.request.audience!==apiBaseUrl || manifest.signing_key_target!==signingTargetFor(manifest))refuse();
        if(values[1] && ["consumer_id","tenant_id","namespace_id","device_id","session_id","signing_public_key_pem"].some(key=>values[1][key]!==manifest[key]))refuse();
        if(values[3] && (values[3].operation!==pending.operation || values[3].request.request_id!==pending.request.request_id))refuse();
        const requestId=pending.request.request_id,retired=[...new Set(manifest.retired_targets??[])];
        if(refresh) {
          if(browser || pending.session_id!==manifest.session_id || pending.committed_refresh_target!==manifest.refresh_target
            || pending.successor_refresh_target!==manifest.refresh_target || typeof pending.prior_refresh_target!=="string"
            || refreshTarget({...manifest,refresh_target:pending.prior_refresh_target},requestId)!==manifest.refresh_target)refuse();
          const prefix=`${WINDOWS_CREDENTIAL_TARGET_PREFIX}${identityKey(manifest)}/refresh/`;
          if(!pending.prior_refresh_target.startsWith(prefix) || retired.some(target=>!target.startsWith(prefix)))refuse();
        } else {
          const keyTarget=pendingSigningTarget(requestId);
          if(pending.pending_signing_target!==keyTarget || pending.request.signing_public_key_pem!==manifest.signing_public_key_pem
            || refreshTarget({...manifest,refresh_target:null},requestId)!==manifest.refresh_target
            || retired.some(target=>target!==keyTarget))refuse();
          if(browser && (browser.request_id!==requestId || browser.device_public_key_pem!==manifest.signing_public_key_pem
            || browser.secret_target!==`Kovya.DeviceAuth/v1/browser-pending/${digest(requestId)}`))refuse();
        }
        if(retired.some(target=>target===manifest.signing_key_target||target===manifest.refresh_target))refuse();
        const witness=await captureWindowsAuthCredentialWitness({remainingMs:transaction.remainingMs});
        if(!(await validLocalCredentials(manifest)))refuse();
        if(await session.compareCredentialWitness(witness,{remainingMs:transaction.remainingMs})!==true)refuse();
        assertWindowsAuthEffect(manifestPath);
        // Only the proved committed state can recover its coupled backups.
        recoverAtomicFiles(manifestPath,journalPath);
        for(const target of retired) {
          try { await bridge.delete(target);assertWindowsAuthEffect(manifestPath); }
          catch(error) {rethrowInactiveWindowsAuthError(error);return unresolved();}
        }
        if(retired.length)writeJsonAtomic(manifestPath,{...manifest,retired_targets:[],updated_at:now()});
        if(enrollment && browser) {
          try {
            await bridge.delete(browser.secret_target);
            assertWindowsAuthEffect(manifestPath);
            removeIfPresent(documents[4].path);
          } catch(error) {rethrowInactiveWindowsAuthError(error);return unresolved();}
        }
        removeIfPresent(journalPath);
        return Object.freeze({ok:true,outcome:"existing"});
      },{recover:false});
    },

    async getAccessCredential({requireAcknowledgement=false}={}) {
      if (accessCredentialIsFresh()) return accessCredential;
      if (refreshBarrier) return refreshBarrier;
      const manifest = readJsonIfPresent(manifestPath, validateManifest);
      if (!manifest) throw localError("Kovya sign-in is required.", "sign_in_required");
      const lockPath = sessionLockPath(stateDirectory, manifest);
      const barrier = withFileLock(lockPath, lockTimeoutMs, async () => {
        if (accessCredentialIsFresh()) return accessCredential;
        const latest = readJsonIfPresent(manifestPath, validateManifest);
        if (!latest) throw localError("Kovya sign-in is required.", "sign_in_required");
        const refreshed = await refreshUnderLock(latest,{requireAcknowledgement});
        if (!refreshed.access_credential) {
          throw localError("Committed refresh cleanup completed; access refresh is required.",
            "access_refresh_required");
        }
        return refreshed.access_credential;
      });
      refreshBarrier = barrier;
      try { return await barrier; }
      finally { if (refreshBarrier === barrier) refreshBarrier = null; }
    },

    invalidateAccessCredential() {
      accessCredential = null;
      accessExpiresAtMs = null;
    },

    prepareResidentAccess() {
      return underInstallLock(async () => {
        await rawGetAccessCredential({requireAcknowledgement:true});
        authWorkRemaining(remainingMs);
        return Object.freeze({ok:true,access_ready:accessCredentialIsFresh()});
      });
    },

    async signMemoryScope(scope) {
      const manifest = readJsonIfPresent(manifestPath, validateManifest);
      if (!manifest) throw localError("Kovya sign-in is required.", "sign_in_required");
      const key = await signingKeyForManifest(manifest);
      const signature = sign(null, Buffer.from(consumerRequestSignaturePayload(scope)), key);
      return `ed25519:${signature.toString("base64url")}`;
    },

    shutdown() {
      clearMemorySecrets();
    },

    async logout() {
      return underInstallLock(async () => {
        const initial = readJsonIfPresent(manifestPath, validateManifest);
        if (!initial) {
          clearMemorySecrets();
          const pending=readJsonIfPresent(journalPath,validateJournal);
          await browserAuthenticator?.clearPending?.();
          await deleteLocalAuth({ manifest: null, pending });
          return Object.freeze({ ok: true, outcome: "signed_out", remote_status: pending?.profile_automatic?"unknown":"not_applicable" });
        }
        return withFileLock(sessionLockPath(stateDirectory, initial), lockTimeoutMs, async () => {
          const manifest = readJsonIfPresent(manifestPath, validateManifest);
          if (!manifest) return Object.freeze({ ok: true, outcome: "signed_out", remote_status: "not_applicable" });
          let remoteStatus = "unknown";
          try {
            const access = accessCredential ?? (await refreshUnderLock(manifest)).access_credential;
            const request = newRequest("logout", manifest.audience, now, random);
            const privateKey = await signingKeyForManifest(manifest);
            const body = request.body;
            const headers = signedHeaders({ operation: "logout", body, privateKey, signingKeyId: manifest.device_id, access });
            await effectiveTransport.request({ path: DEVICE_AUTH_PATHS.logout, headers, body });
            remoteStatus = "revoked";
          } catch (error) {
            rethrowInactiveWindowsAuthError(error);
            remoteStatus = error?.code === "confirmed_no_effect" ? "refused" : "unknown";
          } finally {
            clearMemorySecrets();
            if (accountTransactions.getStore()?.active) {
              await browserAuthenticator?.clearPending?.();
              // Refresh may have committed a successor while obtaining the
              // access credential for revocation. Cleanup owns the current
              // manifest, not the pre-refresh credential target.
              const currentManifest = readJsonIfPresent(manifestPath, validateManifest);
              await deleteLocalAuth({ manifest: currentManifest ?? manifest,
                pending: readJsonIfPresent(journalPath, validateJournal) });
            }
          }
          assertWindowsAuthEffect(manifestPath);
          return Object.freeze({ ok: true, outcome: "signed_out", remote_status: remoteStatus });
        });
      });
    },

    async uninstall() {
      return underInstallLock(async () => {
        const initial = readJsonIfPresent(manifestPath, validateManifest);
        const remove = async () => {
          const manifest = readJsonIfPresent(manifestPath, validateManifest);
          const pending = readJsonIfPresent(journalPath, validateJournal);
          clearMemorySecrets();
          await browserAuthenticator?.clearPending?.();
          await deleteLocalAuth({ manifest, pending });
          const legacyPaths = legacyProvider?.ownedPaths?.() ?? [];
          if (legacyPaths.length > 0) await legacyProvider.removeExact(legacyPaths);
          return Object.freeze({ ok: true, outcome: "local_auth_removed", remote_status: "unknown" });
        };
        return initial
          ? withFileLock(sessionLockPath(stateDirectory, initial), lockTimeoutMs, remove)
          : remove();
      });
    }
  };


  function automaticIdentity(p){
    const keys="audience,device_label,nonce,request_id,request_time,signing_public_key_pem";
    if(!p||p.profile_automatic!==true||p.profile_manual||p.operation!=="browser_sign_in"
      ||Object.keys(p.request??{}).sort().join(",")!==keys||!Object.values(p.request).every(v=>typeof v==="string")
      ||!/^authreq_[a-f0-9]{36}$/.test(p.request.request_id)||p.request.audience!==apiBaseUrl
      ||!Number.isFinite(Date.parse(p.created_at))||createPublicKey(p.request.signing_public_key_pem).asymmetricKeyType!=="ed25519")throw localError("Automatic repair binding refused.","account_state_conflict");
    const key=pendingSigningTarget(p.request.request_id),secret=WINDOWS_BROWSER_AUTH_SECRET_PREFIX+digest(p.request.request_id);
    const allowed=new Set(["schema_version","operation","phase","request","created_at","recovery_expires_at","staged_targets","pending_signing_target","profile_automatic","automatic_binding","automatic_timing","retirement"]);
    if(Object.keys(p).some(k=>!allowed.has(k))||p.pending_signing_target!==key||!Array.isArray(p.staged_targets)
      ||p.staged_targets.length!==2||new Set(p.staged_targets).size!==2||!p.staged_targets.includes(key)||!p.staged_targets.includes(secret))throw localError("Automatic repair target refused.","account_state_conflict");
    return {key,secret};
  }
  async function automaticRetirementProof(values,remaining,host){
    const refuse=()=>{throw localError("Automatic repair state changed.","account_state_conflict");};
    if(!["codex","claude_code"].includes(host)||values[0]||values[1]||!values[2])refuse();
    if(readdirSync(stateDirectory).some(name=>name.startsWith("pending.json.tmp-")))refuse();
    const p=values[2],{key,secret}=automaticIdentity(p),retiring=p.phase==="automatic_retiring";
    if(!retiring&&!["prepared","remote_ambiguous"].includes(p.phase))refuse();
    if(!Number.isFinite(Date.parse(now()))||Date.parse(now())<Date.parse(p.recovery_expires_at))refuse();
    const r=p.retirement;
    const hex=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
    if(retiring&&(!r||Object.keys(r).sort().join(",")!=="browser_sha256,key_sha256,schema_version,secret_sha256,source_journal_sha256,source_phase,target_observation_sha256"
      ||r.schema_version!=="kovya.automatic-retirement.v1"||!["prepared","remote_ambiguous"].includes(r.source_phase)
      ||!hex(r.source_journal_sha256)||!hex(r.target_observation_sha256)||![r.key_sha256,r.secret_sha256,r.browser_sha256].every(x=>x===null||hex(x))))refuse();
    const binding=p.automatic_binding;
    if(!retiring&&p.retirement!==undefined)refuse();
    if(binding){
      if(Object.keys(binding).sort().join(",")!=="consent_nonce_hash,pkce_challenge,redirect_uri,state_sha256"
        ||!/^sha256:[a-f0-9]{64}$/.test(binding.consent_nonce_hash)||!/^[A-Za-z0-9_-]{43}$/.test(binding.pkce_challenge)||!hex(binding.state_sha256))refuse();
      if(binding.redirect_uri!==null){const u=new URL(binding.redirect_uri);if(u.protocol!=="http:"||u.hostname!=="127.0.0.1"||!u.port||u.pathname!=="/kovya/device-authorization/callback"||u.search||u.hash||u.username||u.password)refuse();}
    }else if((retiring?r.source_phase:p.phase)!=="prepared"||values[4])refuse();
    const sourcePhase=retiring?r.source_phase:p.phase;
    if(sourcePhase==="remote_ambiguous"&&(!binding||binding.redirect_uri===null)||sourcePhase==="prepared"&&binding&&binding.redirect_uri!==null)refuse();
    const previous=values[3];
    if(previous&&!retiring){
      automaticIdentity(previous);
      if(stableJson(previous.request)!==stableJson(p.request)||previous.created_at!==p.created_at||previous.pending_signing_target!==key
        ||previous.phase==="automatic_retiring"||!["prepared","remote_ambiguous"].includes(previous.phase))refuse();
      if(stableJson(previous)!==stableJson(p)){
        if(previous.phase!=="prepared"&&!(previous.phase==="remote_ambiguous"&&p.automatic_timing?.accepted_at&&previous.automatic_timing?.accepted_at===null))refuse();
        if(previous.automatic_binding&&stableJson({...previous.automatic_binding,redirect_uri:binding?.redirect_uri})!==stableJson(binding))refuse();
        const lifted={...previous,phase:p.phase,...(p.automatic_binding?{automatic_binding:p.automatic_binding}:{})};
        if(previous.automatic_timing?.accepted_at===null&&p.automatic_timing?.accepted_at){lifted.automatic_timing=p.automatic_timing;lifted.recovery_expires_at=p.recovery_expires_at;}
        if(stableJson(lifted)!==stableJson(p))refuse();
      }
    }
    const b=values[4];
    if(retiring&&(r.key_sha256===null&&r.secret_sha256!==null||r.secret_sha256===null&&r.browser_sha256!==null))refuse();
    if(b&&Object.keys(b).some(k=>!["schema_version","transaction_id","authorization_url","expires_at","request_id","redirect_uri","device_public_key_pem","device_label","secret_target","created_at","automatic_timing"].includes(k)))refuse();
    if(b&&(b.delivery_mode!==undefined||b.request_id!==p.request.request_id||b.secret_target!==secret||b.device_public_key_pem!==p.request.signing_public_key_pem
      ||b.device_label!==p.request.device_label||b.created_at!==p.created_at||b.redirect_uri!==binding?.redirect_uri
      ||new URL(b.authorization_url).origin!==apiBaseUrl||!p.automatic_timing&&Date.parse(b.expires_at)>Date.parse(p.recovery_expires_at)||stableJson(b.automatic_timing??null)!==stableJson(p.automatic_timing??null)))refuse();
    const tx=accountTransactions.getStore(),session=ownedNativeSession(tx),witness=await captureWindowsAuthCredentialWitness({remainingMs:remaining});
    let privateKey,protectedBytes;
    try{
      privateKey=await bridge.read(key);protectedBytes=await bridge.read(secret);
      if(privateKey)validatePrivateKey(privateKey,p.request.signing_public_key_pem);
      if(protectedBytes){
        const v=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(protectedBytes));
        if(!v||Object.keys(v).sort().join(",")!=="consent_nonce,exchange_code,exchange_result,pkce_verifier,state"
          ||v.exchange_code!==null||v.exchange_result!==null||!["state","pkce_verifier","consent_nonce"].every(k=>typeof v[k]==="string"&&/^[A-Za-z0-9_-]{43}$/.test(v[k])))refuse();
        if(binding&&(binding.state_sha256!==digest(v.state)||binding.pkce_challenge!==createHash("sha256").update(v.pkce_verifier).digest("base64url")||binding.consent_nonce_hash!=="sha256:"+digest(v.consent_nonce)))refuse();
      }
      if(retiring){
        if(privateKey&&(r.key_sha256===null||digest(privateKey)!==r.key_sha256)||protectedBytes&&(r.secret_sha256===null||digest(protectedBytes)!==r.secret_sha256))refuse();
        if(!protectedBytes&&r.secret_sha256!==null&&privateKey||!b&&r.browser_sha256!==null&&protectedBytes)refuse();
        if(b&&(r.browser_sha256===null||witness.documents.browser_journal!==r.browser_sha256))refuse();
        if(previous&&witness.documents.device_journal_previous!==r.source_journal_sha256)refuse();
      }else if(binding&&(!privateKey||!protectedBytes)||!binding&&protectedBytes&&!privateKey)refuse();
      if(await session.compareCredentialWitness(witness,{remainingMs:remaining})!==true)refuse();
      const target={schema_version:"kovya.automatic-repair-target.v1",host,request_ref:p.request.request_id,
        observation_sha256:digest(stableJson({schema_version:"kovya.automatic-repair-observation.v1",host,home:stateKey(home),origin:apiBaseUrl,documents:values,credential_witness:witness}))};
      return {target,p,witness,session,key,secret};
    }finally{privateKey?.fill(0);protectedBytes?.fill(0);}
  }
  async function retireAutomatic(target,host){
    if(!target||Object.keys(target).sort().join(",")!=="host,observation_sha256,request_ref,schema_version"
      ||target.schema_version!=="kovya.automatic-repair-target.v1"||target.host!==host)throw localError("Repair target refused.","account_state_conflict");
    const tx=accountTransactions.getStore(),remaining=tx.remainingMs;
    const proof=await automaticRetirementProof(documents.map(d=>readWindowsAuthDocument(d.path,d.validate)),remaining,host);
    if(stableJson(target)!==stableJson(proof.target))throw localError("Repair offer is stale.","account_state_conflict");
    let marker=proof.p;
    if(marker.phase!=="automatic_retiring"){
      marker={...marker,phase:"automatic_retiring",retirement:{schema_version:"kovya.automatic-retirement.v1",source_phase:marker.phase,
        target_observation_sha256:target.observation_sha256,source_journal_sha256:proof.witness.documents.device_journal,
        key_sha256:proof.witness.credentials[proof.key]??null,secret_sha256:proof.witness.credentials[proof.secret]??null,browser_sha256:proof.witness.documents.browser_journal}};
      writeJsonAtomic(journalPath,marker);
    }
    await refreshOwnedSnapshot();
    const fresh=await captureWindowsAuthCredentialWitness({remainingMs:remaining});
    const expected=digest(Buffer.from(JSON.stringify(marker,null,2)+"\n","utf8"));
    if(fresh.home_sha256!==proof.witness.home_sha256||stableJson(fresh.credentials)!==stableJson(proof.witness.credentials)||fresh.documents.browser_journal!==proof.witness.documents.browser_journal||fresh.documents.device_journal!==expected||fresh.documents.manifest!==null||fresh.documents.manifest_previous!==null
      ||fresh.documents.device_journal_previous!==null&&fresh.documents.device_journal_previous!==marker.retirement.source_journal_sha256)throw localError("Retirement publication unconfirmed.","account_state_conflict");
    await automaticRetirementProof(documents.map(d=>readWindowsAuthDocument(d.path,d.validate)),remaining,host);
    for(const credential of [proof.key,proof.secret]){
      assertWindowsAuthEffect(manifestPath);await bridge.delete(credential);assertWindowsAuthEffect(manifestPath);
      const bytes=await bridge.read(credential);if(bytes){bytes.fill(0);throw localError("Credential retirement unconfirmed.","credential_delete_failed");}
      await refreshOwnedSnapshot();await automaticRetirementProof(documents.map(d=>readWindowsAuthDocument(d.path,d.validate)),remaining,host);
    }
    for(const file of [documents[4].path,documents[3].path,journalPath]){
      assertWindowsAuthEffect(manifestPath);removeIfPresent(file);await refreshOwnedSnapshot();
      const snapshot=documents.map(d=>readWindowsAuthDocument(d.path,d.validate));
      if(readWindowsAuthDocument(file,x=>x)!==null)throw localError("Journal retirement unconfirmed.","account_state_conflict");
      if(file!==journalPath)await automaticRetirementProof(snapshot,remaining,host);
    }
    return Object.freeze({ok:true,outcome:"automatic_retired",repair:Object.freeze({schema_version:"kovya.automatic-repair-completion.v1",request_ref:target.request_ref,observation_sha256:target.observation_sha256,postcondition:"owned_automatic_transients_absent"})});
  }

  function manualPhase(remainingMs,work,credentialWitness=null,consumer=null) {
    requireWitnessBudget(remainingMs);
    return observeProfileWorkConsumer("account_lease",()=>withWindowsAuthState(manifestPath,apiBaseUrl,()=>underInstallLock(()=>{
      ownedNativeSession(accountTransactions.getStore());assertWindowsAuthEffect(manifestPath);return consumer?observeProfileWorkConsumer(consumer,work):work();
    },{recover:false}),{accountStateProvider,remainingMs,credentialWitness}));
  }
  async function retireExpiredManual(values,remainingMs,pendingRef=null) {
    const pending=values[2]??values[3],browser=values[4];
    if(!pending?.profile_manual||!["manual_start_pending","manual_required"].includes(pending.phase))return false;
    const refuse=()=>{throw localError("Pending sign-in recovery binding changed.","account_state_conflict");};
    // A newer published backup must never be downgraded to an unpublished clock.
    if(values[2]?.phase==="manual_start_pending"&&values[3]&&values[3].phase!=="manual_start_pending")refuse();
    const current=Date.parse(now()),expiry=profileManualDeadline(pending,browser);
    if(!Number.isFinite(current)||!Number.isFinite(expiry))refuse();
    if(current<expiry)return false;
    if(values[0]||values[1]||(pendingRef!==null&&pendingRef!==pending.request.request_id))refuse();
    const id=pending.request.request_id,keyTarget=pendingSigningTarget(id),secretTarget=`${WINDOWS_BROWSER_AUTH_SECRET_PREFIX}${digest(id)}`;
    const journalFields=new Set(["schema_version","operation","phase","request","created_at","recovery_expires_at","staged_targets","pending_signing_target","profile_manual","manual_binding"]);
    let binding=null;
    for(const item of [values[2],values[3]].filter(Boolean)) {
      validateJournal(item);
      if(Object.keys(item).some(key=>!journalFields.has(key))||item.profile_manual!==true||item.operation!=="browser_sign_in"
        ||!["manual_start_pending","manual_required"].includes(item.phase)||!/^authreq_[a-f0-9]{36}$/u.test(id)
        ||stableJson(item.request)!==stableJson(pending.request)||item.request.audience!==apiBaseUrl
        ||Object.keys(item.request).sort().join(",")!=="audience,device_label,nonce,request_id,request_time,signing_public_key_pem"
        ||item.created_at!==pending.created_at||!Number.isFinite(Date.parse(item.created_at))
        ||item.recovery_expires_at!==pending.recovery_expires_at||item.pending_signing_target!==keyTarget
        ||!Array.isArray(item.staged_targets)||item.staged_targets.length!==2
        ||!item.staged_targets.includes(keyTarget)||!item.staged_targets.includes(secretTarget))refuse();
      if(createPublicKey(item.request.signing_public_key_pem).asymmetricKeyType!=="ed25519")refuse();
      if(item.manual_binding!==undefined) {
        const b=item.manual_binding;
        if(!b||Object.keys(b).sort().join(",")!=="consent_nonce_hash,pkce_challenge,state_sha256"
          ||!/^sha256:[a-f0-9]{64}$/u.test(b.consent_nonce_hash)||!/^[A-Za-z0-9_-]{43}$/u.test(b.pkce_challenge)
          ||!/^[a-f0-9]{64}$/u.test(b.state_sha256)||(binding&&stableJson(binding)!==stableJson(b)))refuse();
        binding=b;
      } else if(item.phase!=="manual_start_pending")refuse();
    }
    if(browser&&(browser.delivery_mode!=="manual_code"||browser.request_id!==id||browser.secret_target!==secretTarget
      ||browser.device_public_key_pem!==pending.request.signing_public_key_pem||browser.created_at!==pending.created_at
      ||browser.device_label!==pending.request.device_label||!binding))refuse();
    const transaction=accountTransactions.getStore(),session=ownedNativeSession(transaction);
    const witness=await captureWindowsAuthCredentialWitness({remainingMs});
    let key,secret,protectedPending;
    try {
      key=await bridge.read(keyTarget);
      if(key)validatePrivateKey(key,pending.request.signing_public_key_pem);
      secret=await bridge.read(secretTarget);
      if(secret) {
        protectedPending=JSON.parse(secret.toString("utf8"));
        if(!protectedPending||Object.keys(protectedPending).sort().join(",")!=="consent_nonce,exchange_code,exchange_result,pkce_verifier,state"
          ||protectedPending.exchange_result!==null
          ||!["state","pkce_verifier","consent_nonce"].every(name=>typeof protectedPending[name]==="string"&&/^[A-Za-z0-9_-]{43}$/u.test(protectedPending[name]))
          ||(protectedPending.exchange_code!==null&&!/^[a-f0-9]{32}$/u.test(protectedPending.exchange_code)))refuse();
        if(binding&&(binding.pkce_challenge!==createHash("sha256").update(protectedPending.pkce_verifier).digest("base64url")
          ||binding.consent_nonce_hash!==`sha256:${digest(protectedPending.consent_nonce)}`||binding.state_sha256!==digest(protectedPending.state)))refuse();
        if(!binding&&protectedPending.exchange_code!==null)refuse();
      }
      if(await session.compareCredentialWitness(witness,{remainingMs})!==true)refuse();
      assertWindowsAuthEffect(manifestPath);
      // Missing credentials are valid interrupted prefixes. Retain the owning
      // journal until every deletion completes, so timeout/failure is retryable.
      await bridge.delete(keyTarget);await bridge.delete(secretTarget);
      removeIfPresent(documents[4].path);
      removeIfPresent(documents[3].path);
      removeIfPresent(journalPath);
      return true;
    } finally {
      key?.fill(0);secret?.fill(0);
      if(protectedPending)for(const field of Object.keys(protectedPending))protectedPending[field]=null;
    }
  }
  function profileManualDeadline(pending,browser) {
    validateJournal(pending);
    if(pending?.profile_manual!==true||pending.operation!=="browser_sign_in")
      throw localError("Pending sign-in binding is invalid.","account_state_conflict");
    if(pending.phase==="manual_start_pending")return Date.parse(pending.recovery_expires_at);
    const expiry=Date.parse(browser?.expires_at),requestAt=Date.parse(pending.request.request_time),binding=pending.manual_binding;
    if(!["manual_required","manual_exchange_pending","local_write_failed"].includes(pending.phase)
      ||!browser||browser.delivery_mode!=="manual_code"
      ||browser.request_id!==pending.request.request_id||browser.device_public_key_pem!==pending.request.signing_public_key_pem
      ||browser.created_at!==pending.created_at||browser.device_label!==pending.request.device_label
      ||pending.pending_signing_target!==pendingSigningTarget(pending.request.request_id)
      ||browser.secret_target!==`${WINDOWS_BROWSER_AUTH_SECRET_PREFIX}${digest(pending.request.request_id)}`
      ||!pending.staged_targets.includes(pending.pending_signing_target)||!pending.staged_targets.includes(browser.secret_target)
      ||!binding||Object.keys(binding).sort().join(",")!=="consent_nonce_hash,pkce_challenge,state_sha256"
      ||!/^sha256:[a-f0-9]{64}$/u.test(binding.consent_nonce_hash)||!/^[A-Za-z0-9_-]{43}$/u.test(binding.pkce_challenge)
      ||!/^[a-f0-9]{64}$/u.test(binding.state_sha256)
      ||!Number.isFinite(expiry)||!Number.isFinite(requestAt)||expiry<=requestAt||expiry>requestAt+WINDOWS_PROFILE_MANUAL_COMPLETION_WINDOW_MS)
      throw localError("Pending sign-in binding is invalid.","account_state_conflict");
    return expiry;
  }
  function requireManualJournal(pending,browser) {
    const expires=profileManualDeadline(pending,browser),current=Date.parse(now());
    if(!Number.isFinite(current)||current>=expires)
      throw localError("The retained authentication result is outside its safe recovery window.","account_interaction_required");
    return expires;
  }
  function manualPublic(result,pending) {
    const expires=requireManualJournal(pending,readWindowsAuthDocument(documents[4].path,documents[4].validate));
    return {...result,expires_at:new Date(expires).toISOString()};
  }

  async function signIn({ accountAccessKeyProvider, deviceLabel }) {
    const keys = generateKeyPairSync("ed25519");
    const privateKey = Buffer.from(keys.privateKey.export({ type: "pkcs8", format: "pem" }));
    const publicKeyPem = keys.publicKey.export({ type: "spki", format: "pem" });
    const request = newRequest("sign_in", audience ?? apiBaseUrl, now, random, {
      signing_public_key_pem: publicKeyPem,
      device_label: boundedLabel(deviceLabel)
    });
    const pendingTarget = pendingSigningTarget(request.body.request_id);
    const journal = createJournal({ operation: "sign_in", request, pendingSigningTarget: pendingTarget, now });
    let accountKey = null;
    let suppliedAccountKey = null;
    try {
      await writeAndVerifyCredential(bridge, pendingTarget, privateKey, (value) => validatePrivateKey(value, publicKeyPem));
      writeJsonAtomic(journalPath, { ...journal, phase: "prepared", staged_targets: [pendingTarget] });
      try {
        suppliedAccountKey = await accountAccessKeyProvider();
        accountKey = secretBuffer(suppliedAccountKey);
        if (accountKey.length < 16 || accountKey.length > 512) throw localError("Account access key is invalid.", "account_key_invalid");
      } catch (error) {
        rethrowInactiveWindowsAuthError(error);
        await deleteTargets([pendingTarget]);
        removeIfPresent(journalPath);
        throw error;
      }
      const body = { ...request.body, account_access_key: accountKey.toString("utf8") };
      const headers = signedHeaders({ operation: "sign_in", body, privateKey });
      writeJsonAtomic(journalPath, { ...journal, phase: "remote_in_flight", staged_targets: [pendingTarget] });
      let result;
      try {
        result = await effectiveTransport.request({ path: DEVICE_AUTH_PATHS.sign_in, headers, body });
      } catch (error) {
        rethrowInactiveWindowsAuthError(error);
        if (error?.ambiguous === true) {
          writeJsonAtomic(journalPath, { ...journal, phase: "remote_ambiguous", staged_targets: [pendingTarget] });
          try {
            result = await effectiveTransport.request({ path: DEVICE_AUTH_PATHS.sign_in, headers, body });
          } catch (retryError) {
            rethrowInactiveWindowsAuthError(retryError);
            body.account_access_key = null;
            if (retryError?.ambiguous === true) {
              return Object.freeze({ ok: false, outcome: "ambiguous", path: "sign_in", retry_request_id: request.body.request_id });
            }
            await deleteTargets([pendingTarget]);
            removeIfPresent(journalPath);
            throw retryError;
          }
        } else {
          body.account_access_key = null;
          await deleteTargets([pendingTarget]);
          removeIfPresent(journalPath);
          throw error;
        }
      }
      body.account_access_key = null;
      return commitSession({ operation: "sign_in", result, privateKey, publicKeyPem, journal, stagedTarget: pendingTarget });
    } finally {
      accountKey?.fill(0);
      if (Buffer.isBuffer(suppliedAccountKey)) suppliedAccountKey.fill(0);
      privateKey.fill(0);
    }
  }

  async function browserSignIn({ deviceLabel }) {
    const keys = generateKeyPairSync("ed25519");
    const privateKey = Buffer.from(keys.privateKey.export({ type: "pkcs8", format: "pem" }));
    const publicKeyPem = keys.publicKey.export({ type: "spki", format: "pem" });
    const request = newRequest("browser_sign_in", audience ?? apiBaseUrl, now, random, {
      signing_public_key_pem: publicKeyPem,
      device_label: boundedLabel(deviceLabel)
    });
    const pendingTarget = pendingSigningTarget(request.body.request_id);
    const journal = createJournal({ operation: "browser_sign_in", request, pendingSigningTarget: pendingTarget, now });
    try {
      await writeAndVerifyCredential(bridge, pendingTarget, privateKey, (value) => validatePrivateKey(value, publicKeyPem));
      writeJsonAtomic(journalPath, { ...journal, phase: "prepared", staged_targets: [pendingTarget] });
      let result;
      try {
        result = await browserAuthenticator.begin({ requestId: request.body.request_id,
          devicePublicKeyPem: publicKeyPem, deviceLabel });
      } catch (error) {
        rethrowInactiveWindowsAuthError(error);
        if (error?.ambiguous === true) {
          writeJsonAtomic(journalPath, { ...journal, phase: "remote_ambiguous", staged_targets: [pendingTarget] });
          return Object.freeze({ ok: false, outcome: "ambiguous", path: "browser_sign_in" });
        }
        await browserAuthenticator.clearPending?.().catch(() => {});
        await deleteTargets([pendingTarget]);
        removeIfPresent(journalPath);
        throw error;
      }
      if (result?.outcome === "manual_required") {
        writeJsonAtomic(journalPath, { ...journal, phase: "manual_required", staged_targets: [pendingTarget] });
        return Object.freeze({ ok: false, outcome: "manual_required", path: "browser_sign_in" });
      }
      const committed = await commitSession({ operation: "browser_sign_in", result, privateKey, publicKeyPem,
        journal, stagedTarget: pendingTarget, keepJournal: true });
      await browserAuthenticator.commit();
      removeIfPresent(journalPath);
      return committed;
    } finally { privateKey.fill(0); }
  }

  async function legacyExchange({ deviceLabel }) {
    const legacy = await legacyProvider.read();
    const privateKey = secretBuffer(legacy.private_key_pem);
    try {
      validatePrivateKey(privateKey, legacy.public_key_pem);
      const request = newRequest("legacy_exchange", audience ?? apiBaseUrl, now, random, {
        device_label: boundedLabel(deviceLabel)
      });
      const journal = createJournal({ operation: "legacy_exchange", request, legacy, now });
      writeJsonAtomic(journalPath, journal);
      let result;
      try {
        const headers = signedHeaders({ operation: "legacy_exchange", body: request.body, privateKey,
          signingKeyId: legacy.signing_key_id });
        result = await effectiveTransport.request({ path: DEVICE_AUTH_PATHS.legacy_exchange, headers, body: request.body });
      } catch (error) {
        rethrowInactiveWindowsAuthError(error);
        if (error?.ambiguous === true) {
          writeJsonAtomic(journalPath, { ...journal, phase: "remote_ambiguous" });
          return Object.freeze({ ok: false, outcome: "ambiguous", path: "legacy_exchange", retry_request_id: request.body.request_id });
        }
        removeIfPresent(journalPath);
        throw error;
      }
      const committed = await commitSession({ operation: "legacy_exchange", result, privateKey,
        publicKeyPem: legacy.public_key_pem, journal, keepJournal: true });
      await legacyProvider.removeExact?.(legacy.paths ?? []);
      removeIfPresent(journalPath);
      return committed;
    } finally {
      privateKey.fill(0);
      legacy?.clear?.();
    }
  }

  async function refreshUnderLock(manifest,{requireAcknowledgement=false}={}) {
    const currentRefresh = await requiredCredential(bridge, manifest.refresh_target, "credential_missing");
    const privateKey = await signingKeyForManifest(manifest);
    let journal = readJsonIfPresent(journalPath, validateJournal);
    try {
      if (journal?.phase === "local_commit_cleanup_pending") {
        if (manifest.refresh_target !== journal.committed_refresh_target) {
          throw localError("Committed refresh recovery binding is invalid.", "manifest_mismatch");
        }
        manifest = await cleanupRetiredTargets(manifest);
        removeIfPresent(journalPath);
        return Object.freeze({ ok: true, outcome: "existing", path: "refresh",
          manifest: publicManifest(manifest) });
      }
      if (journal && journal.operation !== "refresh") {
        throw localError("A different authentication transaction is pending.", "transaction_pending");
      }
      if (!journal) {
        const request = newRequest("refresh", manifest.audience, now, random);
        const successorTarget = refreshTarget(manifest, request.body.request_id);
        journal = createJournal({ operation: "refresh", request, manifest, successorTarget, now });
        writeJsonAtomic(journalPath, journal);
      }
      assertJournalRecoveryFresh(journal, now);
      const body = { ...journal.request, refresh_credential: currentRefresh.toString("utf8") };
      const headers = signedHeaders({ operation: "refresh", body, privateKey,
        signingKeyId: manifest.device_id });
      let result;
      try {
        result = await effectiveTransport.request({ path: DEVICE_AUTH_PATHS.refresh, headers, body });
      } catch (error) {
        rethrowInactiveWindowsAuthError(error);
        body.refresh_credential = null;
        if (error?.code === "sign_in_required") {
          await deleteLocalAuth({ manifest, pending: journal });
          clearMemorySecrets();
          throw error;
        }
        if (error?.ambiguous === true) {
          writeJsonAtomic(journalPath, { ...journal, phase: "remote_ambiguous" });
          throw localError("Refresh outcome is unknown; the same request is retained for recovery.", "refresh_ambiguous");
        }
        removeIfPresent(journalPath);
        throw error;
      }
      body.refresh_credential = null;
      validateAuthResult(result, "refresh", manifest);
      validateAuthorityResult(result, manifest.api_base_url);
      const memoryOrigin = Object.hasOwn(result,"memory_api_base_url")
        ? validatedMemoryOrigin(result.memory_api_base_url) : manifest.memory_api_base_url;
      const successor = secretBuffer(result.refresh_credential);
      try {
        await writeAndVerifyCredential(bridge, journal.successor_refresh_target, successor, validateRefreshCredential, {compound:true});
      } catch (error) {
        rethrowInactiveWindowsAuthError(error);
        writeJsonAtomic(journalPath, { ...journal, phase: "local_write_failed" });
        throw error;
      } finally {
        successor.fill(0);
      }
      const nextManifest = {
        ...manifest,
        ...(memoryOrigin === undefined ? {} : {memory_api_base_url:memoryOrigin}),
        refresh_target: journal.successor_refresh_target,
        refresh_expires_at: result.refresh_expires_at,
        access_expires_at: result.access_expires_at,
        retired_targets: [...new Set([
          ...(manifest.retired_targets ?? []),
          ...(manifest.refresh_target !== journal.successor_refresh_target ? [manifest.refresh_target] : [])
        ])],
        updated_at: now()
      };
      validateManifest(nextManifest);
      writeJsonAtomic(manifestPath, nextManifest);
      writeJsonAtomic(journalPath, { ...journal, phase: "local_commit_cleanup_pending",
        committed_refresh_target: nextManifest.refresh_target });
      try {
        const acknowledgement = newRequest("refresh_ack", manifest.audience, now, random, {
          refresh_credential: currentRefresh.toString("utf8"),
          acknowledge_rotation_request_id: journal.request.request_id
        });
        const acknowledgementHeaders = signedHeaders({ operation: "refresh_ack",
          body: acknowledgement.body, privateKey, signingKeyId: manifest.device_id,
          access: result.access_credential });
        await effectiveTransport.request({ path: DEVICE_AUTH_PATHS.refresh,
          headers: acknowledgementHeaders, body: acknowledgement.body });
      } catch (error) {
        // Expiry maintenance remains the bounded fallback after durable local commit.
        rethrowInactiveWindowsAuthError(error);
        authWorkRemaining(remainingMs);
        if (requireAcknowledgement) {
          clearMemorySecrets();
          throw localError("Resident refresh acknowledgement is unconfirmed.", "resident_refresh_ack_required");
        }
      }
      const cleanedManifest = await cleanupRetiredTargets(nextManifest);
      removeIfPresent(journalPath);
      accessCredential = finishStageSync("access_result_construct",()=>commitAccessCredential(result));
      return Object.freeze({ ok: true, outcome: result.outcome, access_credential: accessCredential,
        manifest: publicManifest(cleanedManifest) });
    } finally {
      currentRefresh.fill(0);
    }
  }

  async function resumePending(pending, { adjudicate = null, manualCodeProvider = null } = {}) {
    if (pending.operation === "refresh") {
      if (pending.phase === "local_commit_cleanup_pending") {
        const committed = readJsonIfPresent(manifestPath, validateManifest);
        if (!committed || committed.refresh_target !== pending.committed_refresh_target) {
          throw localError("Committed refresh recovery binding is invalid.", "manifest_mismatch");
        }
        const cleaned = await cleanupRetiredTargets(committed);
        removeIfPresent(journalPath);
        return Object.freeze({ ok: true, outcome: "existing", path: "refresh",
          manifest: publicManifest(cleaned) });
      }
      assertJournalRecoveryFresh(pending, now);
      const manifest = readJsonIfPresent(manifestPath, validateManifest);
      if (!manifest) throw localError("Refresh recovery has no committed session.", "manifest_missing");
      if (!(await credentialPairPresent(manifest))) {
        await deleteLocalAuth({ manifest, pending });
        return Object.freeze({ ok: false, outcome: "sign_in_required", prompt_allowed: true });
      }
      return withFileLock(sessionLockPath(stateDirectory, manifest), lockTimeoutMs, async () => {
        const latest = readJsonIfPresent(manifestPath, validateManifest);
        if (!latest) throw localError("Refresh recovery has no committed session.", "manifest_missing");
        return refreshUnderLock(latest);
      });
    }
    if (pending.operation === "legacy_exchange") {
      if (pending.phase === "local_committed_cleanup_pending") {
        const manifest = readJsonIfPresent(manifestPath, validateManifest);
        if (!manifest) throw localError("Committed legacy migration manifest is missing.", "manifest_missing");
        await legacyProvider?.removeExact?.(pending.legacy_paths ?? []);
        removeIfPresent(journalPath);
        return Object.freeze({ ok: true, outcome: "existing", path: "legacy_exchange",
          manifest: publicManifest(manifest) });
      }
      if (!legacyProvider?.isPresent?.()) {
        removeIfPresent(journalPath);
        return Object.freeze({ ok: false, outcome: "sign_in_required", prompt_allowed: true });
      }
      if (["remote_in_flight", "remote_ambiguous"].includes(pending.phase)) {
        assertJournalRecoveryFresh(pending, now);
      }
      return legacyExchangeFromJournal(pending);
    }
    if (pending.operation === "sign_in") {
      if (!(await credentialPresent(pending.pending_signing_target))) {
        removeIfPresent(journalPath);
        return Object.freeze({ ok: false, outcome: "sign_in_required", prompt_allowed: true });
      }
      if (pending.phase === "prepared") {
        await deleteTargets(pending.staged_targets ?? [pending.pending_signing_target]);
        removeIfPresent(journalPath);
        return Object.freeze({ ok: false, outcome: "sign_in_required", prompt_allowed: true });
      }
      if (["remote_in_flight", "remote_ambiguous"].includes(pending.phase)) {
        assertJournalRecoveryFresh(pending, now);
      }
      const privateKey = await requiredCredential(bridge, pending.pending_signing_target, "credential_missing");
      try {
        const publicKeyPem = createPublicKey(createPrivateKey(privateKey)).export({ type: "spki", format: "pem" });
        const result = typeof adjudicate === "function"
          ? await adjudicate({ request_id: pending.request.request_id, operation: "sign_in" })
          : await adjudicateSignInWithServer({ pending, privateKey, publicKeyPem });
        if (result?.outcome === "confirmed_no_effect") {
          await deleteTargets(pending.staged_targets ?? []);
          removeIfPresent(journalPath);
          return Object.freeze({ ok: false, outcome: "confirmed_no_effect", prompt_allowed: true });
        }
        if (result?.outcome === "sign_in_required") {
          await deleteTargets(pending.staged_targets ?? []);
          removeIfPresent(journalPath);
          return Object.freeze({ ok: false, outcome: "sign_in_required", prompt_allowed: true });
        }
        if (result?.outcome === "temporarily_unavailable") {
          return Object.freeze({ ok: false, outcome: "ambiguous", path: "sign_in",
            retry_request_id: pending.request.request_id, prompt_allowed: false });
        }
        return commitSession({ operation: "sign_in", result, privateKey, publicKeyPem, journal: pending,
          stagedTarget: pending.pending_signing_target });
      } finally {
        privateKey.fill(0);
      }
    }
    if (pending.operation === "browser_sign_in") {
      if(pending.profile_manual||pending.profile_automatic)return Object.freeze({ok:false,outcome:"pending",path:"browser_sign_in",...diagnosticRecovery(pending)});
      if (pending.phase === "local_committed_cleanup_pending") {
        const manifest = readJsonIfPresent(manifestPath, validateManifest);
        if (!manifest) throw localError("Committed browser sign-in manifest is missing.", "manifest_missing");
        await browserAuthenticator?.commit?.();
        removeIfPresent(journalPath);
        return Object.freeze({ ok: true, outcome: "existing", path: "browser_sign_in", manifest: publicManifest(manifest) });
      }
      if (!browserAuthenticator || !(await credentialPresent(pending.pending_signing_target))) {
        await browserAuthenticator?.clearPending?.().catch(() => {});
        await deleteTargets(pending.staged_targets ?? []);
        removeIfPresent(journalPath);
        return Object.freeze({ ok: false, outcome: "sign_in_required", prompt_allowed: true });
      }
      const privateKey = await requiredCredential(bridge, pending.pending_signing_target, "credential_missing");
      try {
        const publicKeyPem = createPublicKey(createPrivateKey(privateKey)).export({ type: "spki", format: "pem" });
        let result;
        try { result = await browserAuthenticator.resumeManual(manualCodeProvider); }
        catch (error) {
        rethrowInactiveWindowsAuthError(error);
          if (error?.ambiguous === true) return Object.freeze({ ok: false, outcome: "ambiguous", path: "browser_sign_in" });
          await browserAuthenticator.clearPending?.().catch(() => {});
          await deleteTargets(pending.staged_targets ?? []);
          removeIfPresent(journalPath);
          throw error;
        }
        if (result?.outcome === "manual_required") return Object.freeze({ ok: false, outcome: "manual_required", path: "browser_sign_in" });
        const committed = await commitSession({ operation: "browser_sign_in", result, privateKey, publicKeyPem,
          journal: pending, stagedTarget: pending.pending_signing_target, keepJournal: true });
        await browserAuthenticator.commit();
        removeIfPresent(journalPath);
        return committed;
      } finally { privateKey.fill(0); }
    }
    throw localError("Unsupported pending authentication transaction.", "journal_invalid");
  }

  async function adjudicateSignInWithServer({ pending, privateKey, publicKeyPem }) {
    const body = {
      request_id: pending.request.request_id,
      audience: pending.request.audience,
      request_time: now(),
      nonce: `authnonce_${random(18).toString("hex")}`,
      adjudicate_only: true,
      signing_public_key_pem: publicKeyPem
    };
    const headers = signedHeaders({ operation: "sign_in", body, privateKey });
    try {
      return await effectiveTransport.request({ path: DEVICE_AUTH_PATHS.sign_in, headers, body });
    } catch (error) {
      rethrowInactiveWindowsAuthError(error);
      if (error?.ambiguous === true) {
        return Object.freeze({ outcome: "temporarily_unavailable" });
      }
      throw error;
    }
  }

  async function legacyExchangeFromJournal(journal) {
    if (!legacyProvider?.isPresent?.()) {
      return Object.freeze({ ok: false, outcome: "ambiguous", path: "legacy_exchange", prompt_allowed: false });
    }
    const legacy = await legacyProvider.read();
    const privateKey = secretBuffer(legacy.private_key_pem);
    try {
      const headers = signedHeaders({ operation: "legacy_exchange", body: journal.request, privateKey,
        signingKeyId: journal.legacy_signing_key_id });
      const result = await effectiveTransport.request({ path: DEVICE_AUTH_PATHS.legacy_exchange, headers, body: journal.request });
      const committed = await commitSession({ operation: "legacy_exchange", result, privateKey,
        publicKeyPem: legacy.public_key_pem, journal, keepJournal: true });
      await legacyProvider.removeExact?.(legacy.paths ?? []);
      removeIfPresent(journalPath);
      return committed;
    } catch (error) {
      rethrowInactiveWindowsAuthError(error);
      if (error?.ambiguous === true) return Object.freeze({ ok: false, outcome: "ambiguous", path: "legacy_exchange" });
      throw error;
    } finally {
      privateKey.fill(0);
      legacy?.clear?.();
    }
  }

  async function commitSession({ operation, result, privateKey, publicKeyPem, journal, stagedTarget = null,
    keepJournal = false }) {
    validateAuthResult(result, operation);
    const signingTarget = signingTargetFor(result);
    const newRefreshTarget = refreshTarget(result, journal.request.request_id);
    const staged = [signingTarget, newRefreshTarget];
    let manifestCommitted = false;
    let routing;
    try {
      const authority = validatedServiceOrigin(apiBaseUrl);
      validateAuthorityResult(result, authority);
      if (audience != null && validatedAudience(audience) !== authority) throw localError("Authority audience mismatch.","authority_mismatch");
      routing = {api_base_url:authority,audience:authority,
        ...(Object.hasOwn(result,"memory_api_base_url") ? {memory_api_base_url:validatedMemoryOrigin(result.memory_api_base_url)} : {})};
    } catch (error) {
      rethrowInactiveWindowsAuthError(error);
      // Malformed routing is not a retryable local credential-write interruption.
      // Remove this enrollment's staged key and protected browser result only.
      await deleteTargets([stagedTarget].filter(Boolean));
      if (operation === "browser_sign_in") await browserAuthenticator?.clearPending?.();
      removeIfPresent(journalPath);
      await bestEffortRevokeNewSession({result,privateKey});
      throw error;
    }
    const refresh = secretBuffer(result.refresh_credential);
    try {
      await finishStage("final_signing_write_readback",()=>writeAndVerifyCredential(bridge, signingTarget, privateKey, (value) => validatePrivateKey(value, publicKeyPem)));
      await finishStage("final_refresh_write_readback",()=>writeAndVerifyCredential(bridge, newRefreshTarget, refresh, validateRefreshCredential));
      const manifest = {
        schema_version: WINDOWS_AUTH_MANIFEST_SCHEMA,
        ...routing,
        consumer_id: result.consumer_id,
        tenant_id: result.tenant_id,
        namespace_id: result.namespace_id,
        device_id: result.device_id,
        session_id: result.session_id,
        signing_key_id: result.device_id,
        signing_public_key_pem: publicKeyPem,
        signing_key_target: signingTarget,
        refresh_target: newRefreshTarget,
        refresh_expires_at: result.refresh_expires_at,
        access_expires_at: result.access_expires_at,
        retired_targets: stagedTarget && stagedTarget !== signingTarget ? [stagedTarget] : [],
        created_at: now(),
        updated_at: now(),
        migrated_from_legacy: operation === "legacy_exchange"
      };
      validateManifest(manifest);
      finishStageSync("manifest_publish",()=>writeJsonAtomic(manifestPath, manifest));
      manifestCommitted = true;
      if (keepJournal) {
        finishStageSync("commit_journal_publish",()=>writeJsonAtomic(journalPath, { ...journal, phase: "local_committed_cleanup_pending" }));
      } else {
        removeIfPresent(journalPath);
      }
      const cleanedManifest = await finishStage("retired_key_cleanup",()=>cleanupRetiredTargets(manifest));
      accessCredential = finishStageSync("access_result_construct",()=>commitAccessCredential(result));
      return finishStageSync("access_result_construct",()=>Object.freeze({ ok: true, outcome: result.outcome, path: operation,
        access_credential: accessCredential, manifest: publicManifest(cleanedManifest) }));
    } catch (error) {
      rethrowInactiveWindowsAuthError(error);
      if (!manifestCommitted) {
        writeJsonAtomic(journalPath, { ...journal, phase: "local_write_failed", staged_targets: (journal.profile_manual||journal.profile_automatic)?[...new Set([...journal.staged_targets,...staged])]:staged });
        await deleteTargets(staged);
        if (result?.access_credential && operation !== "browser_sign_in") await bestEffortRevokeNewSession({ result, privateKey });
      }
      throw error;
    } finally {
      refresh.fill(0);
    }
  }

  async function bestEffortRevokeNewSession({ result, privateKey }) {
    try {
      const request = newRequest("logout", audience ?? apiBaseUrl, now, random);
      const headers = signedHeaders({ operation: "logout", body: request.body, privateKey,
        signingKeyId: result.device_id, access: result.access_credential });
      await effectiveTransport.request({ path: DEVICE_AUTH_PATHS.logout, headers, body: request.body });
    } catch {}
  }

  async function deleteLocalAuth({ manifest, pending }) {
    clearMemorySecrets();
    const targets = new Set();
    if (manifest) {
      targets.add(manifest.signing_key_target);
      targets.add(manifest.refresh_target);
      for (const target of manifest.retired_targets ?? []) targets.add(target);
    }
    for (const target of pending?.staged_targets ?? []) targets.add(target);
    if (pending?.pending_signing_target) targets.add(pending.pending_signing_target);
    if (pending?.successor_refresh_target) targets.add(pending.successor_refresh_target);
    await deleteTargets([...targets]);
    removeIfPresent(journalPath);
    removeIfPresent(manifestPath);
  }

  async function signingKeyForManifest(manifest) {
    if (retainSigningKeyInMemory && signingKeyObject && signingKeyTarget === manifest.signing_key_target) {
      return signingKeyObject;
    }
    const secret = await requiredCredential(bridge, manifest.signing_key_target, "credential_missing");
    try {
      validatePrivateKey(secret, manifest.signing_public_key_pem);
      const key = createPrivateKey(secret);
      if (retainSigningKeyInMemory) {
        signingKeyObject = key;
        signingKeyTarget = manifest.signing_key_target;
      }
      return key;
    } finally {
      secret.fill(0);
    }
  }

  function clearMemorySecrets() {
    accessCredential = null;
    accessExpiresAtMs = null;
    refreshBarrier = null;
    signingKeyObject = null;
    signingKeyTarget = null;
  }

  function commitAccessCredential(result) {
    const credential = validateAccessCredential(result.access_credential);
    accessExpiresAtMs = requiredTimestamp(result.access_expires_at, "access_expires_at");
    return credential;
  }

  function accessCredentialIsFresh() {
    if (!accessCredential || !Number.isFinite(accessExpiresAtMs)) return false;
    const current = Date.parse(now());
    return Number.isFinite(current) && current < accessExpiresAtMs - WINDOWS_ACCESS_REFRESH_MARGIN_MS;
  }

  async function credentialPairPresent(manifest) {
    const signing = await bridge.read(manifest.signing_key_target);
    const refresh = await bridge.read(manifest.refresh_target);
    try { return Boolean(signing && refresh); } finally {
      signing?.fill(0);
      refresh?.fill(0);
    }
  }

  async function validLocalCredentials(manifest) {
    let signing,refresh;
    try {
      signing=await bridge.read(manifest.signing_key_target);
      assertWindowsAuthEffect(manifestPath);
      refresh=await bridge.read(manifest.refresh_target);
      assertWindowsAuthEffect(manifestPath);
      if(!signing||!refresh)return false;
      validatePrivateKey(signing,manifest.signing_public_key_pem);
      validateRefreshCredential(refresh);
      return true;
    } finally {signing?.fill(0);refresh?.fill(0);}
  }

  async function cleanupRetiredTargets(manifest) {
    const retired = [...new Set(manifest.retired_targets ?? [])];
    if (retired.length === 0) return manifest;
    const remaining = [];
    for (const target of retired) {
      try { await bridge.delete(target); } catch { remaining.push(target); }
    }
    if (remaining.length === retired.length) return manifest;
    const next = { ...manifest, retired_targets: remaining, updated_at: now() };
    validateManifest(next);
    writeJsonAtomic(manifestPath, next);
    return next;
  }

  async function credentialPresent(target) {
    if (!target) return false;
    const value = await bridge.read(target);
    try { return Boolean(value); } finally { value?.fill(0); }
  }

  async function deleteTargets(targets) {
    for (const target of targets) {
      assertOwnedTarget(target);
      await bridge.delete(target);
    }
  }

  const rawGetAccessCredential = manager.getAccessCredential;
  const rawSignMemoryScope = manager.signMemoryScope;
  manager.authorizeMemoryRequest = ({ expectedAccountFields = null, scope }) => underInstallLock(async () => {
    const token = await rawGetAccessCredential();
    let memoryApiBaseUrl = null;
    if (expectedAccountFields !== null) {
      const current = readJsonIfPresent(manifestPath, validateManifest);
      for (const key of ["consumer_id", "tenant_id", "namespace_id", "device_id", "session_id", "api_base_url", "audience"]) {
        if (current?.[key] !== expectedAccountFields[key]) {
          throw new Error("Kovya account changed while preparing the memory request.");
        }
      }
      memoryApiBaseUrl = normalizeMemoryApiBaseUrl(
        `${current.memory_api_base_url ?? current.api_base_url}/memory-api.v1`
      );
    }
    const signature = await rawSignMemoryScope(scope);
    return Object.freeze({ token, signature, memoryApiBaseUrl });
  });

  for(const name of ["getAccessCredential","signMemoryScope"]) {
    const operation=manager[name];
    manager[name]=(...args)=>underInstallLock(()=>operation(...args));
  }
  return Object.freeze(manager);
}

function newRequest(operation, audience, now, random, extras = {}) {
  const bytes = random(18).toString("hex");
  return Object.freeze({
    operation,
    body: Object.freeze({
      request_id: `authreq_${bytes}`,
      audience: validatedAudience(audience),
      request_time: now(),
      nonce: `authnonce_${random(18).toString("hex")}`,
      ...extras
    })
  });
}

function createJournal({ operation, request, pendingSigningTarget = null, legacy = null,
  manifest = null, successorTarget = null, now }) {
  const journal = {
    schema_version: WINDOWS_AUTH_JOURNAL_SCHEMA,
    operation,
    phase: "prepared",
    request: request.body,
    created_at: now(),
    recovery_expires_at: new Date(
      Date.parse(request.body.request_time) + WINDOWS_AUTH_RECOVERY_WINDOW_MS
    ).toISOString(),
    staged_targets: []
  };
  if (pendingSigningTarget) journal.pending_signing_target = pendingSigningTarget;
  if (legacy) {
    journal.legacy_signing_key_id = legacy.signing_key_id;
    journal.legacy_paths = [...(legacy.paths ?? [])];
  }
  if (manifest) {
    journal.prior_refresh_target = manifest.refresh_target;
    journal.session_id = manifest.session_id;
    journal.successor_refresh_target = successorTarget;
  }
  validateJournal(journal);
  return journal;
}

function signedHeaders({ operation, body, privateKey, signingKeyId = null, access = null }) {
  const requestPath = DEVICE_AUTH_PATHS[operation];
  const payload = stableJson({
    schema_version: "device-auth.request.v1",
    method: "POST",
    path: requestPath,
    audience: body.audience,
    request_id: body.request_id,
    request_time: body.request_time,
    nonce: body.nonce,
    body_sha256: `sha256:${createHash("sha256").update(stableJson(body)).digest("hex")}`
  });
  const signingKey = privateKey?.type === "private" ? privateKey : createPrivateKey(privateKey);
  const signature = sign(null, Buffer.from(payload), signingKey).toString("base64url");
  const headers = {
    "content-type": "application/json",
    "x-request-id": body.request_id,
    "x-kovya-request-signature": `ed25519:${signature}`
  };
  if (signingKeyId) headers["x-kovya-signing-key-id"] = signingKeyId;
  if (access) headers.authorization = `Bearer ${validateAccessCredential(access)}`;
  return Object.freeze(headers);
}

// This profile boundary also precedes caching the whole response for retry.
// Optional fields cover the production issuer metadata without admitting extras.
function validateManualExchangeTypes(value) {
  if(!value||typeof value!=="object"||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype)
    throw localError("Authentication result is invalid.","result_invalid");
  const required={ok:["boolean","result_invalid"],outcome:["string","result_invalid"],
    consumer_id:["string","value_invalid"],tenant_id:["string","value_invalid"],namespace_id:["string","value_invalid"],
    device_id:["string","value_invalid"],session_id:["string","value_invalid"],
    access_credential:["string","access_invalid"],refresh_credential:["string","refresh_invalid"],
    access_expires_at:["string","value_invalid"],refresh_expires_at:["string","value_invalid"]};
  const optional={api_base_url:"origin_invalid",audience:"origin_invalid",memory_api_base_url:"origin_invalid",
    refresh_family_id:"value_invalid",request_id:"value_invalid"};
  if(Object.keys(value).some(key=>!Object.hasOwn(required,key)&&!Object.hasOwn(optional,key)))
    throw localError("Authentication result is invalid.","result_invalid");
  for(const [key,[type,reason]] of Object.entries(required))
    if(!Object.hasOwn(value,key)||typeof value[key]!==type)throw localError("Authentication result is invalid.",reason);
  for(const [key,reason] of Object.entries(optional))
    if(Object.hasOwn(value,key)&&typeof value[key]!=="string")throw localError("Authentication result is invalid.",reason);
}

function validateAuthResult(result, operation, priorManifest = null) {
  if (!result || result.ok !== true || !["created", "existing", "rotated"].includes(result.outcome)) {
    throw localError("Authentication result is invalid.", "result_invalid");
  }
  const identityFields = ["consumer_id", "device_id", "session_id", "access_expires_at", "refresh_expires_at"];
  const enrollmentFields = operation === "refresh" ? [] : ["tenant_id", "namespace_id"];
  for (const field of [...identityFields, ...enrollmentFields]) {
    boundedString(result[field], field, 1, 512);
  }
  validateAccessCredential(result.access_credential);
  requiredTimestamp(result.access_expires_at, "access_expires_at");
  const refresh = secretBuffer(result.refresh_credential);
  try { validateRefreshCredential(refresh); } finally { refresh.fill(0); }
  if (priorManifest && (result.consumer_id !== priorManifest.consumer_id
      || result.device_id !== priorManifest.device_id || result.session_id !== priorManifest.session_id)) {
    throw localError("Refresh changed the committed identity.", "identity_changed");
  }
}

function validateManifest(manifest) {
  if (!manifest || manifest.schema_version !== WINDOWS_AUTH_MANIFEST_SCHEMA) throw localError("Auth manifest is invalid.", "manifest_invalid");
  for (const field of ["api_base_url", "audience", "consumer_id", "tenant_id", "namespace_id", "device_id",
    "session_id", "signing_key_id", "signing_public_key_pem", "signing_key_target", "refresh_target",
    "access_expires_at", "refresh_expires_at"]) {
    boundedString(manifest[field], field, 1, 4096);
  }
  validatedServiceOrigin(manifest.api_base_url);
  if (Object.hasOwn(manifest,"memory_api_base_url")) validatedMemoryOrigin(manifest.memory_api_base_url);
  assertOwnedTarget(manifest.signing_key_target);
  assertOwnedTarget(manifest.refresh_target);
  if (manifest.signing_key_id !== manifest.device_id) throw localError("Auth manifest signing identity is invalid.", "manifest_invalid");
  if (manifest.signing_key_target === manifest.refresh_target) throw localError("Auth credential targets must be separate.", "manifest_invalid");
  requiredTimestamp(manifest.access_expires_at, "access_expires_at");
  requiredTimestamp(manifest.refresh_expires_at, "refresh_expires_at");
  if (manifest.retired_targets !== undefined
      && (!Array.isArray(manifest.retired_targets) || manifest.retired_targets.length > 64)) {
    throw localError("Auth cleanup ledger is invalid.", "manifest_invalid");
  }
  for (const target of manifest.retired_targets ?? []) assertOwnedTarget(target);
  return manifest;
}

function validateJournal(journal) {
  if (!journal || journal.schema_version !== WINDOWS_AUTH_JOURNAL_SCHEMA
      || !Object.hasOwn(DEVICE_AUTH_PATHS, journal.operation)) {
    throw localError("Auth recovery journal is invalid.", "journal_invalid");
  }
  if(Object.hasOwn(journal,"profile_manual")&&journal.profile_manual!==true)throw localError("Auth recovery journal is invalid.","journal_invalid");
  if(Object.hasOwn(journal,"profile_automatic")&&(journal.profile_automatic!==true||journal.profile_manual))throw localError("Auth recovery journal is invalid.","journal_invalid");
  if (!journal.request || typeof journal.request !== "object") throw localError("Auth recovery journal is invalid.", "journal_invalid");
  for (const field of ["request_id", "audience", "request_time", "nonce"]) boundedString(journal.request[field], field, 1, 512);
  if (!Object.hasOwn(journal, "recovery_expires_at")) {
    throw localError(
      "The retained authentication result has no provable recovery window.",
      "account_interaction_required"
    );
  }
  boundedString(journal.recovery_expires_at, "recovery_expires_at", 20, 64);
  const requestAt = Date.parse(journal.request.request_time);
  const recoveryExpiresAt = Date.parse(journal.recovery_expires_at);
  const timing=journal.automatic_timing;
  let expectedRecovery=requestAt+WINDOWS_AUTH_RECOVERY_WINDOW_MS;
  if(timing!==undefined){
    if(journal.profile_automatic!==true||!timing||Object.keys(timing).sort().join(",")!=="accepted_at,page_expires_at,schema_version,start_deadline_at"
      ||timing.schema_version!=="kovya.automatic-timing.v1"||Date.parse(timing.start_deadline_at)!==requestAt+35000)throw localError("Automatic timing is invalid.","journal_invalid");
    if(timing.accepted_at===null&&timing.page_expires_at===null)expectedRecovery=requestAt+35000;
    else{
      const accepted=Date.parse(timing.accepted_at),page=Date.parse(timing.page_expires_at);
      if(!Number.isFinite(accepted)||!Number.isFinite(page)||accepted<requestAt||accepted>requestAt+35000||page<=accepted||page-accepted>305000)throw localError("Automatic timing is invalid.","journal_invalid");
      expectedRecovery=page+35000;
    }
  }
  if (!Number.isFinite(requestAt) || !Number.isFinite(recoveryExpiresAt)
      || recoveryExpiresAt !== expectedRecovery) {
    throw localError("Auth recovery journal expiry is invalid.", "journal_invalid");
  }
  if (Object.hasOwn(journal.request, "account_access_key") || Object.hasOwn(journal.request, "refresh_credential")) {
    throw localError("Auth recovery journal contains a secret field.", "journal_secret_refused");
  }
  for (const target of journal.staged_targets ?? []) assertOwnedTarget(target);
  if (journal.pending_signing_target) assertOwnedTarget(journal.pending_signing_target);
  if (journal.successor_refresh_target) assertOwnedTarget(journal.successor_refresh_target);
  if (journal.committed_refresh_target) assertOwnedTarget(journal.committed_refresh_target);
  return journal;
}

function assertJournalRecoveryFresh(journal, now) {
  validateJournal(journal);
  const current = Date.parse(now());
  const expires = Date.parse(journal.recovery_expires_at);
  if (!Number.isFinite(current) || !Number.isFinite(expires) || current >= expires) {
    throw localError(
      "The retained authentication result is outside its safe recovery window.",
      "account_interaction_required"
    );
  }
}

function publicManifest(manifest) {
  const { signing_public_key_pem: _publicKey, ...safe } = manifest;
  return Object.freeze({ ...safe });
}

function signingTargetFor(result) {
  return `${WINDOWS_CREDENTIAL_TARGET_PREFIX}${identityKey(result)}/private-key`;
}

function refreshTarget(value, requestId) {
  const predecessor = value.refresh_target ?? "enrollment";
  return `${WINDOWS_CREDENTIAL_TARGET_PREFIX}${identityKey(value)}/refresh/${digest(`${predecessor}\0${requestId}`).slice(0, 24)}`;
}

function pendingSigningTarget(requestId) {
  return `${WINDOWS_CREDENTIAL_TARGET_PREFIX}pending/${digest(requestId).slice(0, 32)}/private-key`;
}

function identityKey(value) {
  const identity = `${value.consumer_id}\0${value.device_id}\0${value.session_id}`;
  return digest(identity).slice(0, 40);
}

function sessionLockPath(stateDirectory, manifest) {
  return path.join(stateDirectory, `session-${identityKey(manifest)}.lock`);
}

async function writeAndVerifyCredential(bridge, target, value, validator, {compound=false}={}) {
  assertOwnedTarget(target);
  const secret = secretBuffer(value);
  let readback = null;
  try {
    if(compound && accountTransactions.getStore()?.nativeSession?.role==="managed_runtime"
        && typeof bridge.writeAndRead==="function") {
      readback=await bridge.writeAndRead(target,secret);
    } else {
      await bridge.write(target, secret);
      readback = await bridge.read(target);
    }
    if (!readback || readback.length !== secret.length || !timingSafeEqual(readback, secret)) {
      throw localError("Credential read-back failed.", "credential_readback_failed");
    }
    validator(readback);
  } catch (error) {
    await bridge.delete(target).catch(() => {});
    throw error;
  } finally {
    secret.fill(0);
    readback?.fill(0);
  }
}

async function requiredCredential(bridge, target, reason) {
  assertOwnedTarget(target);
  const value = await bridge.read(target);
  if (!value) throw localError("Kovya credential is unavailable.", reason);
  return value;
}

function validatePrivateKey(value, expectedPublicKeyPem) {
  const derived = createPublicKey(createPrivateKey(value)).export({ type: "spki", format: "pem" });
  if (derived !== expectedPublicKeyPem) throw localError("Signing credential validation failed.", "signing_key_invalid");
  return true;
}

function validateRefreshCredential(value) {
  const secret = Buffer.isBuffer(value) ? value.toString("utf8") : String(value);
  if (!REFRESH_TOKEN_PATTERN.test(secret)) throw localError("Refresh credential is invalid.", "refresh_invalid");
  return secret;
}

function validateAccessCredential(value) {
  if (!ACCESS_TOKEN_PATTERN.test(String(value ?? ""))) throw localError("Access credential is invalid.", "access_invalid");
  return String(value);
}

function assertOwnedTarget(target) {
  boundedString(target, "credential target", WINDOWS_CREDENTIAL_TARGET_PREFIX.length + 8, 512);
  if (!target.startsWith(WINDOWS_CREDENTIAL_TARGET_PREFIX)
      || target.includes("\\") || target.includes("..") || /[\r\n\0]/u.test(target)) {
    throw localError("Credential target is outside Kovya's allowlist.", "credential_target_refused");
  }
}

function validateAuthorityResult(result, authority) {
  if ((Object.hasOwn(result,"api_base_url") && validatedServiceOrigin(result.api_base_url) !== authority)
    || (Object.hasOwn(result,"audience") && validatedAudience(result.audience) !== authority)) {
    throw localError("Authentication authority changed.","authority_mismatch");
  }
}

function validatedMemoryOrigin(value) {
  const origin=validatedServiceOrigin(value);
  if (new URL(origin).pathname !== "/") throw localError("Memory service must be an origin.","origin_invalid");
  return origin;
}

function validatedServiceOrigin(value) {
  let url;
  try { url = new URL(String(value ?? "")); } catch { throw localError("Service origin is invalid.", "origin_invalid"); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw localError("Service origin must be credential-free HTTPS.", "origin_invalid");
  }
  return url.href.replace(/\/$/u, "");
}

function validatedAudience(value) {
  return validatedServiceOrigin(value);
}

function boundedLabel(value) {
  const label = String(value ?? "Windows device").trim();
  return Buffer.byteLength(label) <= 128 && label.length > 0 ? label : "Windows device";
}

function boundedString(value, field, minimum, maximum) {
  if (typeof value !== "string") throw localError(`${field} is invalid.`, "value_invalid");
  const size = Buffer.byteLength(value);
  if (size < minimum || size > maximum) throw localError(`${field} is invalid.`, "value_invalid");
}

function requiredTimestamp(value, field) {
  boundedString(value, field, 20, 64);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw localError(`${field} is invalid.`, "value_invalid");
  return milliseconds;
}

function secretBuffer(value) {
  const buffer = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(String(value ?? ""), "utf8");
  if (buffer.length < 1 || buffer.length > MAX_SECRET_BYTES) {
    buffer.fill(0);
    throw localError("Secret frame is invalid.", "secret_frame_invalid");
  }
  return buffer;
}

function writeJsonAtomic(targetPath, value, {recovering=false}={}) {
  assertWindowsAuthEffect(targetPath);
  mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  const temporary = `${targetPath}.tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
  const backup = `${targetPath}.previous`;
  writeFileSync(temporary, serialized, { encoding: "utf8", flag: "wx", mode: 0o600 });
  const descriptor = openSync(temporary, fsConstants.O_RDWR);
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
  const parsed = JSON.parse(readFileSync(temporary, "utf8"));
  if (stableJson(parsed) !== stableJson(value)) {
    removeIfPresent(temporary,targetPath);
    throw localError("Local auth state verification failed.", "state_write_failed");
  }
  if(!recovering) {
    removeIfPresent(backup);
    if (existsSync(targetPath)) renameSync(targetPath, backup);
  }
  try {
    renameSync(temporary, targetPath);
    recordWindowsAuthDocument(targetPath,value);
    removeIfPresent(backup);
  } catch (error) {
    removeIfPresent(temporary,targetPath);
    if (!recovering && !existsSync(targetPath) && existsSync(backup)) renameSync(backup, targetPath);
    throw error;
  }
}

function recoverAtomicFiles(...paths) {
  for(const targetPath of paths) {
    const backup=`${targetPath}.previous`;
    const current=readWindowsAuthDocument(targetPath,value=>value);
    const previous=readWindowsAuthDocument(backup,value=>value);
    if(current===null && previous!==null)writeJsonAtomic(targetPath,previous,{recovering:true});
    else if(previous!==null)removeIfPresent(backup);
  }
}
function readJsonIfPresent(targetPath,validator) {return readWindowsAuthDocument(targetPath,validator);}
function removeIfPresent(targetPath, documentPath = targetPath) {
  assertWindowsAuthEffect(documentPath);
  try {unlinkSync(targetPath);}catch(error){if(error?.code!=="ENOENT")throw error;}
  const tx=accountTransactions.getStore();
  if(tx?.values.has(stateKey(targetPath)))recordWindowsAuthDocument(targetPath,null);
}

async function withFileLock(lockPath, timeoutMs, work) {
  const remaining = accountTransactions.getStore()?.remainingMs ?? null;
  authWorkRemaining(remaining);
  mkdirSync(path.dirname(lockPath), { recursive: true, mode: 0o700 });
  const deadline = Date.now() + timeoutMs;
  let descriptor;
  try {
    while (descriptor === undefined) {
      authWorkRemaining(remaining);
      try {
        descriptor = openSync(lockPath, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600);
        authWorkRemaining(remaining);
        writeFileSync(descriptor, JSON.stringify({ pid: process.pid, created_at: new Date().toISOString() }));
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        try {
          authWorkRemaining(remaining);
          if (Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS) {
            authWorkRemaining(remaining);
            unlinkSync(lockPath);
          }
        } catch (probeError) {
          if (probeError?.code !== "ENOENT") throw probeError;
        }
        if (Date.now() >= deadline) throw localError("Kovya authentication is busy.", "lock_timeout");
        await new Promise((resolve) => setTimeout(resolve, Math.min(15, authWorkRemaining(remaining))));
      }
    }
    authWorkRemaining(remaining);
    await refreshOwnedSnapshot();
    authWorkRemaining(remaining);
    return await work();
  } finally {
    // Only this invocation's acquired file may be removed. Expiry retains the
    // recovery marker; closing the handle grants no new persistence authority.
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch {}
      authWorkRemaining(remaining);
      rmSync(lockPath, { force: true });
    }
  }
}

async function invokeBridge({ operation, target, value = null, bridgePath, spawnImpl, timeoutMs, exchange }) {
  assertOwnedTarget(target);
  const secret = value == null ? Buffer.alloc(0) : secretBuffer(value);
  const metadata = Buffer.from(JSON.stringify({ schema_version: "kovya.credential-bridge.v1", operation, target,
    secret_length: secret.length }), "utf8");
  let frame = null;
  try {
    if (metadata.length > MAX_BRIDGE_FRAME_BYTES) throw localError("Credential bridge frame is too large.", "bridge_frame_invalid");
    frame = Buffer.allocUnsafe(8 + metadata.length + secret.length);
    frame.writeUInt32LE(metadata.length, 0);
    metadata.copy(frame, 4);
    frame.writeUInt32LE(secret.length, 4 + metadata.length);
    secret.copy(frame, 8 + metadata.length);
    const result = exchange ? await exchange(frame) : await runBridgeProcess({ bridgePath, frame, spawnImpl, timeoutMs });
    return decodeBridgeResponse(result);
  } finally {
    secret.fill(0);
    metadata.fill(0);
    frame?.fill(0);
  }
}

function runManagedCredentialProcess({executablePath,frame,spawnImpl,timeoutMs,env}) {
  return new Promise((resolve,reject)=>{
    let child;
    try {child=spawnNative(executablePath,["credential",String(process.pid)],{
      shell:false,windowsHide:true,stdio:["pipe","pipe","pipe"],env},spawnImpl);}
    catch {return reject(localError("Credential bridge failed.","bridge_failed"));}
    const chunks=[];let length=0,failure=null;
    const stop=code=>{failure??=code;child.kill();};
    const timer=setTimeout(()=>stop("bridge_timeout"),Math.min(30_000,Math.max(1,timeoutMs)));
    child.stdout.on("data",chunk=>{
      length+=chunk.length;
      if(length>MAX_BRIDGE_FRAME_BYTES+MAX_SECRET_BYTES+8)stop("bridge_frame_invalid");
      else chunks.push(Buffer.from(chunk));
      chunk.fill(0);
    });
    child.stderr.on("data",chunk=>{if(chunk.length)stop("bridge_failed");chunk.fill(0);});
    child.once("error",()=>{failure??="bridge_failed";});
    child.stdin.on("error",()=>stop("bridge_failed"));
    child.once("close",code=>{
      clearTimeout(timer);
      const result=failure || code!==0?null:Buffer.concat(chunks);
      for(const chunk of chunks)chunk.fill(0);
      if(result)resolve(result);else reject(localError("Credential bridge failed.",failure??"bridge_failed"));
    });
    child.stdin.end(frame);
  });
}

function runBridgeProcess({ bridgePath, frame, spawnImpl, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const child = spawnImpl(resolveWindowsPowerShellExecutable(), ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", bridgePath], {
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      env: Object.freeze({
        SystemRoot: process.env.SystemRoot,
        WINDIR: process.env.WINDIR,
        PATH: process.env.PATH,
        ProgramFiles: process.env.ProgramFiles
      })
    });
    const stdout = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    const timer = setTimeout(() => {
      child.kill();
      reject(localError("Credential bridge timed out.", "bridge_timeout"));
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_BRIDGE_FRAME_BYTES + MAX_SECRET_BYTES + 8) child.kill();
      else stdout.push(Buffer.from(chunk));
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > 0) child.kill();
    });
    child.once("error", (error) => { clearTimeout(timer); reject(localError("Credential bridge failed.", "bridge_failed", error)); });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code !== 0 || stderrBytes !== 0) {
        for (const chunk of stdout) chunk.fill(0);
        return reject(localError("Credential bridge failed.", "bridge_failed"));
      }
      const combined = Buffer.concat(stdout);
      for (const chunk of stdout) chunk.fill(0);
      resolve(combined);
    });
    child.stdin.end(frame);
  });
}

function decodeBridgeResponse(frame) {
  if (frame.length < 8 || frame.length > MAX_BRIDGE_FRAME_BYTES + MAX_SECRET_BYTES + 8) {
    frame.fill(0);
    throw localError("Credential bridge returned an invalid frame.", "bridge_frame_invalid");
  }
  const metadataLength = frame.readUInt32LE(0);
  if (metadataLength < 2 || metadataLength > MAX_BRIDGE_FRAME_BYTES || frame.length < 8 + metadataLength) {
    frame.fill(0);
    throw localError("Credential bridge returned an invalid frame.", "bridge_frame_invalid");
  }
  const secretLength = frame.readUInt32LE(4 + metadataLength);
  if (secretLength > MAX_SECRET_BYTES || frame.length !== 8 + metadataLength + secretLength) {
    frame.fill(0);
    throw localError("Credential bridge returned an invalid frame.", "bridge_frame_invalid");
  }
  try {
    const metadata = JSON.parse(frame.subarray(4, 4 + metadataLength).toString("utf8"));
    const secret = Buffer.from(frame.subarray(8 + metadataLength));
    return { metadata, secret };
  } finally {frame.fill(0);}
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function ambiguousError(message, cause = null) {
  const error = localError(message, "ambiguous_result", cause);
  error.ambiguous = true;
  return error;
}

function localError(message, code, cause = null) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  error.kovyaDeviceAuth = true;
  return error;
}

export function normalizeMemoryApiBaseUrl(value) {
  if (typeof value !== "string" || value.length === 0) throw new Error("KOVYA_MEMORY_API_BASE_URL is required.");
  const raw = value;
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    const error = new Error("KOVYA_MEMORY_API_BASE_URL must be a valid http(s) URL.");
    error.code = "KOVYA_MEMORY_CLIENT_CONFIG_ERROR";
    error.failure_reason = "api_base_url_invalid";
    throw error;
  }
  if (parsed.protocol !== "https:") {
    const error = new Error("KOVYA_MEMORY_API_BASE_URL must use HTTPS.");
    error.code = "KOVYA_MEMORY_CLIENT_CONFIG_ERROR";
    error.failure_reason = "api_base_url_invalid";
    throw error;
  }
  if (parsed.username || parsed.password) {
    const error = new Error("KOVYA_MEMORY_API_BASE_URL must not include userinfo credentials.");
    error.code = "KOVYA_MEMORY_CLIENT_CONFIG_ERROR";
    error.failure_reason = "api_base_url_invalid";
    throw error;
  }
  if (parsed.search || parsed.hash) {
    const error = new Error("KOVYA_MEMORY_API_BASE_URL must not include query strings or fragments.");
    error.code = "KOVYA_MEMORY_CLIENT_CONFIG_ERROR";
    error.failure_reason = "api_base_url_invalid";
    throw error;
  }
  const pathSegments = decodedUrlPathSegments(parsed.pathname)
    .map((segment) => segment.toLowerCase());
  if (pathSegments.includes("activation")) {
    const error = new Error("KOVYA_MEMORY_API_BASE_URL must point to Memory API, not /activation.");
    error.code = "KOVYA_MEMORY_CLIENT_CONFIG_ERROR";
    error.failure_reason = "api_base_url_invalid";
    throw error;
  }
  return raw.replace(/\/$/, "");
}

function decodedUrlPathSegments(pathname) {
  let decoded = pathname;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const next = safeDecodeURIComponent(decoded);
    if (next === decoded) break;
    decoded = next;
  }
  return decoded.split(/[\\/]+/).filter(Boolean);
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
