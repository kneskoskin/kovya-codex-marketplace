import {COLD_PATH_WORK_MS} from "../../plugin/request-budget.mjs";
import {attachOutcomeEvidence} from "./kovya-phase-authority.mjs";
import {diagnosticCheckpoint,propagateDiagnosticFailure} from "../../plugin/diagnostic-events.mjs";
import { randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync
} from "node:fs";
import net from "node:net";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import { TextDecoder } from "node:util";

import { stableJson } from "../../../packages/memory-gateway/src/canonical-json.mjs";
import {
  WINDOWS_BROKER_MAX_FRAME_BYTES,
  WINDOWS_BROKER_OPERATION_BUDGET_MAX_MS,
  WINDOWS_BROKER_SIGNED_OPERATION_BUDGET_MAX_MS,
  WINDOWS_BROKER_PROTOCOL,
  bindKovyaBrokerRuntime,
  createKovyaBrokerControlProof,
  kovyaBrokerPaths,
  requireBrokerMetadataDirectory,
  readKovyaBrokerEndpoint,
  validateKovyaBrokerEndpoint,
  spawnKovyaBroker
} from "./kovya-windows-broker.mjs";
import {
  exchangeKovyaWindowsBrokerNative,
  readKovyaWindowsBrokerNativeIdentity,
  resolveKovyaWindowsBrokerNativePath
} from "./kovya-windows-broker-native.mjs";
import { createWindowsReadinessRecorder } from "./kovya-windows-readiness-evidence.mjs";
import {profileWorkConfigured, profileCleanupFailed, borrowProfileWorkRequest, prepareProfileBrokerBudget} from "./kovya-profile-process.mjs";
import {runObservedClientWorkRequest as runProfileWorkRequest} from "../../plugin/diagnostic-lifecycle.mjs";
import {diagnosticStage} from "../../plugin/diagnostic-events.mjs";
import {
  buildCanonicalPrivateTurnContent,
  handleMcpMessage as handleMemoryMcpMessage,
  startKovyaMcpStdio
} from "./kovya-memory-client.mjs";

export { buildCanonicalPrivateTurnContent };

export const WINDOWS_BROKER_START_COOLDOWN_MS = 5000;
export const WINDOWS_BROKER_COLD_START_BUDGET_MS = 2000;
export { WINDOWS_BROKER_OPERATION_BUDGET_MAX_MS, WINDOWS_BROKER_SIGNED_OPERATION_BUDGET_MAX_MS };
const WINDOWS_BROKER_START_CLAIM_STALE_MS = 2000;
const WINDOWS_BROKER_ENDPOINT_POLL_MS = 20;
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });

async function observeBrokerReadiness(methodName, operation) {
  const record = createWindowsReadinessRecorder()?.broker?.[methodName];
  if (typeof record !== "function") return operation();
  let invoked = false;
  let result;
  let operationError;
  try {
    return await record(async () => {
      invoked = true;
      try {
        result = await operation();
        return result;
      } catch (error) {
        operationError = error;
        throw error;
      }
    });
  } catch (error) {
    // No exact active run (including a mixed/stale run) is deliberately
    // zero-effect. If the private operation already ran, never repeat it only
    // because its content-free evidence completion could not be persisted.
    if (!invoked) return operation();
    if (operationError) throw operationError;
    return result;
  }
}

export async function recallMemory(args = {}, options = {}) {
  return brokerOperation("recall", args, options);
}

export async function capturePrivateMemory(args = {}, options = {}) {
  return brokerOperation("capture", args, options);
}
export async function retainTurnPrompt(args = {}, options = {}) {
  return brokerOperation("turn_prompt", args, options);
}
export async function endTurnSession(args, options = {}) {
  return brokerRequest("status", args, {...options,autoStart:false});
}

export async function writeFixtureMemory(args = {}, options = {}) {
  void args;
  void options;
  throw clientError("Kovya broker generic writes are refused.", "broker_operation_refused");
}

export async function handleBrokerMcpMessage(message, options = {}) {
  const brokerRecall = options.brokerRecall ?? ((args) => recallMemory(args, options));
  const brokerWriteFixture = options.brokerWriteFixture ?? ((args) => writeFixtureMemory(args, options));
  return handleMemoryMcpMessage(message, {
    toolRouter: Object.freeze({
      recallMemory: brokerRecall,
      writeFixtureMemory: brokerWriteFixture
    })
  });
}

export async function inspectKovyaBroker(options = {}) {
  return brokerRequest("hello", {}, options);
}

export async function inspectKovyaBrokerStatus(options = {}) {
  return brokerRequest("status", {}, options);
}

export async function shutdownKovyaBroker({ controlRole = "uninstaller", ...options } = {}) {
  const home = options.home ?? process.env.KOVYA_HOME;
  const manifestPath = options.manifestPath ?? process.env.KOVYA_WINDOWS_AUTH_MANIFEST;
  const env = options.env ?? process.env;
  const basePaths = kovyaBrokerPaths({
    home,
    manifestPath: manifestPath ?? path.join(home, "windows-device-auth.json"),
    env
  });
  const nativeExecutablePath = options.nativeExecutablePath ?? resolveKovyaWindowsBrokerNativePath();
  const endpoint = readKovyaBrokerEndpoint(basePaths, { nativeExecutablePath });
  if (!endpoint) throw clientError("Kovya broker is unavailable.", "broker_unavailable");
  const paths = effectiveEndpointPaths(basePaths, endpoint);
  const proof = createKovyaBrokerControlProof(paths, controlRole);
  return brokerRequest("shutdown", proof, {
    ...options, home, manifestPath, env, nativeExecutablePath, autoStart: false
  });
}

async function brokerOperation(operation, payload, options) {
  const response = await brokerRequest(operation, payload, options);
  if (response.ok !== true || !Object.hasOwn(response, "result")) {
    const error = new Error("Kovya broker request failed.");
    error.code = response.error_code ?? "broker_failed";
    if(response.phase_observation!==undefined)attachOutcomeEvidence(error,response.phase_observation);
    throw error;
  }
  if(response.result&&typeof response.result==='object'&&response.phase_observation!==undefined)
    attachOutcomeEvidence(response.result,response.phase_observation);
  return response.result;
}

export async function brokerRequest(operation, payload, options = {}) {
  if (!profileWorkConfigured()) return executeBrokerRequest(operation, payload, options);
  const startedWallMs = Date.now();
  const started = performance.now();
  const maximum = ["recall", "capture"].includes(operation)
    ? WINDOWS_BROKER_SIGNED_OPERATION_BUDGET_MAX_MS : WINDOWS_BROKER_OPERATION_BUDGET_MAX_MS;
  const selection=prepareProfileBrokerBudget(operation);
  const selectedHome=options.home??process.env.KOVYA_HOME;
  const selectedPaths=kovyaBrokerPaths({home:selectedHome,manifestPath:options.manifestPath??process.env.KOVYA_WINDOWS_AUTH_MANIFEST??path.join(selectedHome,"windows-device-auth.json"),env:options.env??process.env});
  const selectedEndpoint=selection.cold?null:validateKovyaBrokerEndpoint(selectedPaths,JSON.parse(selection.endpoint_json),{nativeExecutablePath:options.nativeExecutablePath??resolveKovyaWindowsBrokerNativePath()});
  const preflight=Object.freeze({cold:selection.cold,endpoint:selectedEndpoint});
  const budget = selection.cold?selection.budget_ms:Math.min(selection.budget_ms, requireBudget(options.timeoutMs ?? (maximum === WINDOWS_BROKER_SIGNED_OPERATION_BUDGET_MAX_MS ? maximum : 900), maximum));
  const remaining=()=>budget-(performance.now()-started);
  Object.defineProperty(remaining,"budgetAdmission",{value:selection});
  const event = options.brokerEvent;
  try {
    return await runProfileWorkRequest(remaining, async () => {
      try {
        return await executeBrokerRequest(operation, payload, options, borrowProfileWorkRequest(), startedWallMs + budget, preflight);
      } catch (error) {
        // Admission refusals before this callback are temporary unless cleanup failed.
        throw resolveBrokerEventFailure(error, event, {remember: event?.isCold() === true});
      }
    },{operation:"broker",terminal_candidate:(value,error)=>event?.isCold()===true||options.terminalFollowup?.(value?.result,error)!==true},operation);
  } catch (error) {
    throw resolveBrokerEventFailure(error, event);
  }
}

async function executeBrokerRequest(operation, payload, {
  home = process.env.KOVYA_HOME,
  manifestPath = process.env.KOVYA_WINDOWS_AUTH_MANIFEST,
  env = process.env,
  timeoutMs = ["recall", "capture"].includes(operation)
    ? WINDOWS_BROKER_SIGNED_OPERATION_BUDGET_MAX_MS : 900,
  autoStart = true,
  brokerEvent = null,
  spawnBroker = spawnKovyaBroker,
  connectImpl = net.createConnection,
  nativeTransport = process.platform === "win32",
  nativeExecutablePath = nativeTransport ? resolveKovyaWindowsBrokerNativePath() : null,
  nativeExchange = exchangeKovyaWindowsBrokerNative,
  nativeIdentity = readKovyaWindowsBrokerNativeIdentity,
  readEndpoint = readKovyaBrokerEndpoint,
  now = () => Date.now(),
  monotonicNow = () => performance.now(),
  sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  isProcessAlive = defaultIsProcessAlive,
  coldStartTimeoutMs = WINDOWS_BROKER_COLD_START_BUDGET_MS,
  startWaitMs = WINDOWS_BROKER_OPERATION_BUDGET_MAX_MS
} = {}, profileRequest = null, profileDeadlineAt = null, preflight = null) {
  const checkpoint=(stage,work)=>profileRequest?diagnosticStage(stage,work):work();
  if (!home || !path.isAbsolute(home)) throw clientError("Kovya home is unavailable.", "broker_home_invalid");
  if (profileRequest && !nativeTransport) throw clientError("Kovya profile requires native transport.", "broker_native_transport_required");
  const requestedBudgetMs = preflight?.cold && profileRequest ? profileRequest.remainingMs() : requireBudget(timeoutMs, ["recall", "capture"].includes(operation)
    ? WINDOWS_BROKER_SIGNED_OPERATION_BUDGET_MAX_MS : WINDOWS_BROKER_OPERATION_BUDGET_MAX_MS);
  const operationBudgetMs = Math.min(requestedBudgetMs, profileRequest?.remainingMs() ?? requestedBudgetMs);
  if (profileRequest && brokerEvent?.isCold()) throw coldEventRefusal(brokerEvent);
  const coldBudgetMs = requireBudget(coldStartTimeoutMs, WINDOWS_BROKER_COLD_START_BUDGET_MS);
  const endpointWaitBudgetMs = requireBudget(startWaitMs, WINDOWS_BROKER_OPERATION_BUDGET_MAX_MS);
  const startedWallMs = now();
  const startedMonotonicMs = monotonicNow();
  const paths = kovyaBrokerPaths({ home, manifestPath: manifestPath ?? path.join(home, "windows-device-auth.json"), env });
  let startPaths = paths;
  let endpoint = null;
  try { endpoint = preflight ? preflight.endpoint : readEndpoint(paths, { nativeExecutablePath }); }
  catch(error) {if(error?.code==="broker_runtime_incompatible") throw error;}
  const coldStart = !endpoint;
  if (coldStart && profileRequest) brokerEvent?.markCold();
  if (coldStart && profileRequest && !autoStart) throw clientError("Kovya broker is unavailable.", "broker_unavailable");
  const profileDeadlineMonotonicMs = profileRequest ? startedMonotonicMs + operationBudgetMs : Number.POSITIVE_INFINITY;
  const coldReadyDeadlineMonotonicMs = Math.min(startedMonotonicMs + coldBudgetMs,profileDeadlineMonotonicMs);
  const coldReadyDeadlineWallMs = profileDeadlineAt ?? startedWallMs + coldBudgetMs;
  const unavailableDeadlineMonotonicMs = startedMonotonicMs
    + Math.min(preflight?.cold?COLD_PATH_WORK_MS:WINDOWS_BROKER_OPERATION_BUDGET_MAX_MS,profileRequest ? operationBudgetMs : Number.POSITIVE_INFINITY);
  let effectivePaths;
  if (coldStart) {
    const establishColdReady = async () => {
      if (!endpoint && autoStart) {
        if (nativeTransport) {
          const identityTimeoutMs = remainingBudget(
            unavailableDeadlineMonotonicMs,
            monotonicNow,
            WINDOWS_BROKER_OPERATION_BUDGET_MAX_MS
          );
          const identity = await checkpoint("identity",()=>profileRequest&&nativeIdentity===readKovyaWindowsBrokerNativeIdentity
            ? profileRequest.observeBroker("identity",nativeExecutablePath,paths.canonicalHome)
            : nativeIdentity({
            executablePath: nativeExecutablePath,
            env,
            timeoutMs: requireNativeBudget(identityTimeoutMs),
            ...(profileRequest ? {remainingMs:profileRequest.remainingMs} : {})
          }));
          if (identity.owner_sid_hash !== paths.ownerBinding) {
            throw clientError("Kovya native owner identity is invalid.", "broker_owner_invalid");
          }
          startPaths = bindKovyaBrokerRuntime(paths, {
            authenticationIdHash: identity.authentication_id_hash,
            sessionId: identity.windows_session_id
          });
        }
        assertStartCooldownElapsed(startPaths, now());
        const claim = acquireStartClaim(startPaths, startedWallMs);
        let keepProgressClaim = false;
        let launchedProcessId = null;
        try {
          profileRequest?.remainingMs();
          if (claim) launchedProcessId = await checkpoint("launch",()=>spawnBroker({ home: paths.canonicalHome, env }));
          if (profileRequest && (!claim || isLiveProcessId(launchedProcessId, isProcessAlive))) {
            profileRequest.remainingMs();
            if (monotonicNow() >= profileDeadlineMonotonicMs)
              throw clientError("Kovya broker timed out.", "broker_deadline_refused");
            // Verified handoff lets the resident finish startup independently.
            // Preserve the existing claim while it starts; this event stays cold.
            keepProgressClaim = Boolean(claim);
            throw coldEventRefusal();
          }
          const waitDeadlineMonotonicMs = Math.min(
            unavailableDeadlineMonotonicMs,
            monotonicNow() + endpointWaitBudgetMs
          );
          endpoint = await checkpoint("wait",()=>waitForEndpoint(paths, waitDeadlineMonotonicMs, {
            nativeExecutablePath,
            monotonicNow,
            readEndpoint,
            sleep
          }));
          if (!endpoint && claim) {
            keepProgressClaim = monotonicNow() < coldReadyDeadlineMonotonicMs
              && isLiveProcessId(launchedProcessId, isProcessAlive);
            if (!keepProgressClaim) recordStartFailure(startPaths, now());
          }
          if (endpoint) clearOwnedStartFailure(startPaths);
        } finally {
          if (claim && !keepProgressClaim) releaseStartClaim(startPaths, claim);
        }
      }
      if (profileRequest) {
        profileRequest.remainingMs();
        if (monotonicNow() >= profileDeadlineMonotonicMs)
          throw clientError("Kovya broker timed out.", "broker_deadline_refused");
      }
      if (!endpoint) throw clientError("Kovya broker is unavailable.", "broker_unavailable");
      if (profileRequest) {
        clearCompletedStartClaim(startPaths);
        // Endpoint readiness cannot turn the initiating cold event into a warm one.
        throw coldEventRefusal();
      }
      const readyPaths = effectiveEndpointPaths(paths, endpoint);
      const readyRequest = createRequest("hello", {}, readyPaths, endpoint, coldReadyDeadlineWallMs);
      const readyResponse = await checkpoint("dispatch",()=>dispatchRequest({
        endpoint,
        request: readyRequest,
        timeoutMs: remainingBudget(coldReadyDeadlineMonotonicMs, monotonicNow),
        remainingMs: () => remainingBudget(coldReadyDeadlineMonotonicMs, monotonicNow),
        nativeTransport,
        nativeExecutablePath,
        env,
        nativeExchange,
        connectImpl
      }));
      await validateBoundResponse(readyResponse, readyRequest, endpoint);
      validateResponseShape(readyResponse, "hello", endpoint);
      remainingBudget(coldReadyDeadlineMonotonicMs, monotonicNow);
      clearCompletedStartClaim(startPaths);
      return { effectivePaths: readyPaths, readyResponse };
    };
    const ready = await observeBrokerReadiness(
      autoStart ? "coldAuthenticatedReady" : "unavailableRefused",
      establishColdReady
    );
    effectivePaths = ready.effectivePaths;
    if (operation === "hello") return ready.readyResponse;
  } else {
    effectivePaths = effectiveEndpointPaths(paths, endpoint);
  }

  const operationStartedWallMs = coldStart ? now() : startedWallMs;
  const operationDeadlineMonotonicMs = profileRequest ? profileDeadlineMonotonicMs : coldStart
    ? monotonicNow() + operationBudgetMs
    : startedMonotonicMs + operationBudgetMs;
  const requestBudgetMs = remainingBudget(operationDeadlineMonotonicMs, monotonicNow);
  const deadlineAt = new Date(profileDeadlineAt ?? operationStartedWallMs + operationBudgetMs).toISOString();
  const executeOperation = async () => {
    const request = createRequest(operation, payload, effectivePaths, endpoint, deadlineAt);
    const response = await checkpoint("dispatch",()=>dispatchRequest({
      endpoint,
      request,
      timeoutMs: requestBudgetMs,
      remainingMs: () => remainingBudget(operationDeadlineMonotonicMs, monotonicNow),
      nativeTransport,
      nativeExecutablePath,
      env,
      nativeExchange,
      connectImpl
    }));
    await validateBoundResponse(response, request, endpoint);
    validateResponseShape(response, operation, endpoint);
    if (response.ok === true) remainingBudget(operationDeadlineMonotonicMs, monotonicNow);
    return response;
  };
  const response = await (!coldStart && operation === "recall"
    ? observeBrokerReadiness("warmRecall", executeOperation)
    : executeOperation());
  if (response.ok === true) remainingBudget(operationDeadlineMonotonicMs, monotonicNow);
  return response;
}

function createRequest(operation, payload, effectivePaths, endpoint, deadline) {
  const deadlineAt = typeof deadline === "number" ? new Date(deadline).toISOString() : deadline;
  const request = {
    schema_version: WINDOWS_BROKER_PROTOCOL,
    broker_binding: effectivePaths.brokerBinding,
    broker_instance: endpoint.broker_instance,
    deadline_at: deadlineAt,
    operation,
    payload,
    request_id: randomUUID()
  };
  return request;
}

async function dispatchRequest({
  endpoint,
  request,
  timeoutMs,
  remainingMs,
  nativeTransport,
  nativeExecutablePath,
  env,
  nativeExchange,
  connectImpl
}) {
  return nativeTransport
    ? exchangeNative(
      endpoint,
      request,
      requireNativeBudget(timeoutMs),
      nativeExecutablePath,
      env,
      nativeExchange,
      remainingMs
    )
    : exchange(endpoint.pipe_name, request, timeoutMs, connectImpl);
}

async function validateBoundResponse(response, request, endpoint) {
  if (!response || response.schema_version !== WINDOWS_BROKER_PROTOCOL
      || response.broker_instance !== endpoint.broker_instance
      || response.operation !== request.operation
      || response.request_id !== request.request_id) {
    await diagnosticCheckpoint({stage:"native_frame_validation",outcome:"failed",reason:response?.request_id!==request.request_id?"native_response_request_id_mismatch":"native_response_binding_mismatch",transport_operation:request.operation,transport_request_id:request.request_id});
    throw clientError("Kovya broker response binding is invalid.", "broker_response_invalid");
  }
}

function startStatePaths(paths) {
  return Object.freeze({
    claimPath: path.join(paths.stateDirectory, "start-claim.json"),
    failurePath: path.join(paths.stateDirectory, "last-start-failure.json")
  });
}

function readStartRecord(targetPath, paths) {
  if (!existsSync(targetPath)) return null;
  try {
    const value = JSON.parse(readFileSync(targetPath, "utf8"));
    return value?.schema_version === "kovya.windows-broker-start.v1"
      && value.broker_binding === paths.brokerBinding
      && Number.isFinite(Date.parse(value.written_at))
      ? value : null;
  } catch { return null; }
}

function assertStartCooldownElapsed(paths, currentMs) {
  const { failurePath } = startStatePaths(paths);
  const record = readStartRecord(failurePath, paths);
  if (record && currentMs - Date.parse(record.written_at) < WINDOWS_BROKER_START_COOLDOWN_MS) {
    throw clientError("Kovya broker restart is cooling down.", "broker_start_cooldown");
  }
  if (record) {
    try { unlinkSync(failurePath); } catch {}
  }
}

function acquireStartClaim(paths, currentMs) {
  const { claimPath } = startStatePaths(paths);
  requireBrokerMetadataDirectory(paths.stateDirectory);
  const existing = readStartRecord(claimPath, paths);
  if (existing && currentMs - Date.parse(existing.written_at) >= WINDOWS_BROKER_START_CLAIM_STALE_MS) {
    try { unlinkSync(claimPath); } catch {}
  }
  const claim = Object.freeze({
    schema_version: "kovya.windows-broker-start.v1",
    broker_binding: paths.brokerBinding,
    claim_id: randomUUID(),
    written_at: new Date(currentMs).toISOString()
  });
  let descriptor;
  try {
    descriptor = openSync(claimPath, "wx", 0o600);
    writeFileSync(descriptor, `${JSON.stringify(claim)}\n`, "utf8");
    return claim;
  } catch (error) {
    if (error?.code === "EEXIST") return null;
    throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function releaseStartClaim(paths, claim) {
  const { claimPath } = startStatePaths(paths);
  const current = readStartRecord(claimPath, paths);
  if (current?.claim_id === claim.claim_id) {
    try { unlinkSync(claimPath); } catch {}
  }
}

function clearCompletedStartClaim(paths) {
  const { claimPath } = startStatePaths(paths);
  const current = readStartRecord(claimPath, paths);
  if (current) {
    try { unlinkSync(claimPath); } catch {}
  }
}

function recordStartFailure(paths, currentMs) {
  const { failurePath } = startStatePaths(paths);
  const record = {
    schema_version: "kovya.windows-broker-start.v1",
    broker_binding: paths.brokerBinding,
    failure_code: "broker_unavailable",
    written_at: new Date(currentMs).toISOString()
  };
  const temporary = `${failurePath}.tmp-${process.pid}-${randomUUID()}`;
  writeFileSync(temporary, `${JSON.stringify(record)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  try { renameSync(temporary, failurePath); }
  catch (error) { if (!existsSync(failurePath)) throw error; }
  finally { try { unlinkSync(temporary); } catch {} }
}

function clearOwnedStartFailure(paths) {
  const { failurePath } = startStatePaths(paths);
  if (readStartRecord(failurePath, paths)) {
    try { unlinkSync(failurePath); } catch {}
  }
}

async function waitForEndpoint(paths, deadlineMonotonicMs, {
  nativeExecutablePath,
  monotonicNow,
  readEndpoint,
  sleep
}) {
  while (monotonicNow() < deadlineMonotonicMs) {
    try {
      const endpoint = readEndpoint(paths, { nativeExecutablePath });
      if (endpoint) return endpoint;
    } catch(error) {if(error?.code==="broker_runtime_incompatible") throw error;}
    const remainingMs = Math.max(0, deadlineMonotonicMs - monotonicNow());
    if (remainingMs === 0) break;
    await sleep(Math.min(WINDOWS_BROKER_ENDPOINT_POLL_MS, remainingMs));
  }
  return null;
}

function requireBudget(value, maximum) {
  if (!Number.isInteger(value) || value < 1 || value > maximum) {
    throw clientError("Kovya broker timeout is invalid.", "broker_timeout_invalid");
  }
  return value;
}

function remainingBudget(deadlineMonotonicMs, monotonicNow, maximum = Number.POSITIVE_INFINITY) {
  const remainingMs = Math.min(maximum, Math.floor(deadlineMonotonicMs - monotonicNow()));
  if (!Number.isFinite(remainingMs) || remainingMs < 1) {
    throw clientError("Kovya broker timed out.", "broker_timeout");
  }
  return remainingMs;
}

function requireNativeBudget(value) {
  if (value < 50) throw clientError("Kovya broker timed out.", "broker_timeout");
  return value;
}

function isLiveProcessId(value, isProcessAlive) {
  return Number.isInteger(value) && value > 0 && isProcessAlive(value) === true;
}

function defaultIsProcessAlive(processId) {
  try {
    process.kill(processId, 0);
    return true;
  } catch {
    return false;
  }
}

function effectiveEndpointPaths(paths, endpoint) {
  if (!Object.hasOwn(endpoint, "authentication_id_hash")) return paths;
  return bindKovyaBrokerRuntime(paths, {
    authenticationIdHash: endpoint.authentication_id_hash,
    sessionId: endpoint.windows_session_id
  });
}

async function exchangeNative(endpoint, request, timeoutMs, executablePath, env, implementation, remainingMs) {
  const canonical = Buffer.from(stableJson(request), "utf8");
  let raw = null;
  try {
    raw = await implementation({
      endpoint,
      canonicalRequestBytes: canonical,
      timeoutMs,
      remainingMs,
      executablePath,
      env
    });
    if (!Buffer.isBuffer(raw) || raw.length < 2 || raw.length > WINDOWS_BROKER_MAX_FRAME_BYTES) {
      await diagnosticCheckpoint({stage:"native_frame_validation",outcome:"failed",reason:"native_frame_length_invalid",frame_failure:"native_frame_length_invalid",response_bytes:Buffer.isBuffer(raw)?raw.length:null,transport_operation:request.operation,transport_request_id:request.request_id});
      throw clientError("Kovya broker response is invalid.", "broker_frame_invalid");
    }
    let text,parsed;
    const refused=async reason=>diagnosticCheckpoint({stage:"native_frame_validation",outcome:"failed",reason,frame_failure:reason,response_bytes:raw.length,transport_operation:request.operation,transport_request_id:request.request_id});
    try{text=STRICT_UTF8.decode(raw);}catch(error){await refused("native_frame_encoding");throw error;}
    try{parsed=JSON.parse(text);}catch(error){await refused("native_frame_non_json");throw error;}
    if (text !== stableJson(parsed)) {
      await refused("native_frame_noncanonical");
      throw clientError("Kovya broker response is not canonical.", "broker_frame_invalid");
    }
    await diagnosticCheckpoint({stage:"native_frame_validation",outcome:"succeeded",reason:"none",response_bytes:raw.length,transport_operation:request.operation,transport_request_id:request.request_id});
    return parsed;
  } catch (error) {
    if (/^[a-z][a-z0-9_]{1,80}$/u.test(String(error?.code ?? ""))) throw error;
    throw clientError("Kovya broker response is invalid.", "broker_frame_invalid");
  } finally {
    canonical.fill(0);
    raw?.fill?.(0);
  }
}

export function validateResponseShape(response, operation, endpoint = null) {
  const common = ["broker_instance", "ok", "operation", "request_id", "schema_version"];
  const successExtra = operation === "hello" ? ["ready"]
    : operation === "status" ? ["accepting", "protocol_version", "ready"]
      : operation === "shutdown" ? ["outcome"]
        : (operation === "recall" || operation === "capture" || operation === "turn_prompt") ? ["result"] : [];
  const scopedStatus = operation === "status" && (Object.hasOwn(response,"broker_scope")
    || Object.hasOwn(response,"cross_harness_residency") || endpoint?.broker_scope !== undefined);
  if (scopedStatus) successExtra.push("broker_scope","cross_harness_residency");
  const required = response.ok === true
    ? [...common, ...successExtra]
    : [...common, "error_code", "failure_reason"];
  const allowed = new Set(required);
  const keys = Object.keys(response);
  if (keys.length !== required.length || required.some((key) => !Object.hasOwn(response, key))
      || keys.some((key) => !allowed.has(key))
      || typeof response.ok !== "boolean"
      || (response.ok === false && (!safeFailureCode(response.error_code)
        || response.failure_reason !== response.error_code))
      || (response.ok === true && operation === "hello" && response.ready !== true)
      || (response.ok === true && operation === "status"
        && (response.ready !== true || typeof response.accepting !== "boolean"
          || response.protocol_version !== WINDOWS_BROKER_PROTOCOL
          || (scopedStatus && (!["machine","harness_session"].includes(response.broker_scope)
            || response.cross_harness_residency !== (response.broker_scope === "machine")
            || (endpoint && response.broker_scope !== endpoint.broker_scope)))))
      || (response.ok === true && operation === "shutdown" && response.outcome !== "stopping")) {
    throw clientError("Kovya broker response shape is invalid.", "broker_response_invalid");
  }
}

function safeFailureCode(value) {
  return /^[a-z][a-z0-9_]{1,80}$/u.test(String(value ?? ""));
}

function exchange(pipeName, request, timeoutMs, connectImpl) {
  return new Promise((resolve, reject) => {
    const socket = connectImpl(pipeName);
    let response = Buffer.alloc(0);
    let expected = null;
    let settled = false;
    const timer = setTimeout(() => finish(clientError("Kovya broker timed out.", "broker_timeout")), timeoutMs);
    timer.unref?.();
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      response.fill(0);
      if (error) reject(error); else resolve(value);
    };
    socket.once("connect", () => {
      const body = Buffer.from(stableJson(request), "utf8");
      if (body.length > WINDOWS_BROKER_MAX_FRAME_BYTES) return finish(clientError("Kovya broker request is too large.", "broker_frame_invalid"));
      const frame = Buffer.allocUnsafe(body.length + 4);
      frame.writeUInt32LE(body.length, 0);
      body.copy(frame, 4);
      body.fill(0);
      socket.write(frame, (error) => {
        frame.fill(0);
        if (error) finish(error);
      });
    });
    socket.on("data", (chunk) => {
      const prior = response;
      response = Buffer.concat([response, chunk]);
      prior.fill(0);
      if (response.length >= 4 && expected === null) {
        expected = response.readUInt32LE(0);
        if (expected < 2 || expected > WINDOWS_BROKER_MAX_FRAME_BYTES) return finish(clientError("Kovya broker response is invalid.", "broker_frame_invalid"));
      }
      if (expected !== null && response.length === expected + 4) {
        try {
          const text = STRICT_UTF8.decode(response.subarray(4));
          const parsed = JSON.parse(text);
          if (text !== stableJson(parsed)) return finish(clientError("Kovya broker response is not canonical.", "broker_frame_invalid"));
          finish(null, parsed);
        } catch { finish(clientError("Kovya broker response is invalid.", "broker_frame_invalid")); }
      } else if (expected !== null && response.length > expected + 4) {
        finish(clientError("Kovya broker response has surplus bytes.", "broker_frame_invalid"));
      }
    });
    socket.once("error", (error) => finish(error));
    socket.once("end", () => {
      if (expected === null || response.length !== expected + 4) finish(clientError("Kovya broker response ended early.", "broker_frame_invalid"));
    });
  });
}

function fatalColdFailure(code) {
  return typeof code === "string" && (code.startsWith("broker_native_") || code.startsWith("broker_owner_")
    || code.startsWith("account_state_") || ["broker_runtime_incompatible", "broker_scope_unknown",
      "profile_cleanup_uncertain", "profile_work_owner_required"].includes(code));
}

export function resolveBrokerEventFailure(error, event, {remember = false} = {}) {
  if (profileCleanupFailed()) {
    event?.rememberFailure?.("profile_cleanup_uncertain");
    return propagateDiagnosticFailure(error,clientError("Kovya broker request failed.", "profile_cleanup_uncertain"));
  }
  // Temporary admission refusal must surface without permanently recording it.
  if (error?.code === "profile_cleanup_uncertain") {
    if (remember) event?.rememberFailure?.(error.code);
    return error;
  }
  if (remember && fatalColdFailure(error?.code)) event?.rememberFailure?.(error.code);
  const code = event?.failureCode?.();
  return code && code !== error?.code ? propagateDiagnosticFailure(error,clientError("Kovya broker request failed.", code)) : error;
}

function coldEventRefusal(event = null) {
  return resolveBrokerEventFailure(clientError("Kovya memory is starting; ask again.", "broker_cold_start"), event);
}

function clientError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

const executedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : null;
if (executedPath === import.meta.url) {
  if (process.argv.includes("--shutdown")) {
    shutdownKovyaBroker({ timeoutMs: 900 }).then(
      () => { process.exitCode = 0; },
      () => { process.exitCode = 1; }
    );
  } else {
    startKovyaMcpStdio({ onMessage: handleBrokerMcpMessage });
  }
}
