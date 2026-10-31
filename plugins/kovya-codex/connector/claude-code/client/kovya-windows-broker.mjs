#!/usr/bin/env node
import {managedPackageConfigured} from "./kovya-managed-process.mjs";
import {withWindowsAuthState,runWindowsAuthRequest} from "./kovya-windows-device-auth.mjs";
import {profileWorkConfigured,profileIngressRemaining,bindProfileServer,observeProfileServer,borrowProfileWorkRequest,residentProfileStartup,prepareProfileAccountWorker} from "./kovya-profile-process.mjs";
import {diagnosticCheckpoint,diagnosticStage,memoryDiagnosticEventId} from "../../plugin/diagnostic-events.mjs";
import {runObservedProfileWorkRequest as runProfileWorkRequest,runObservedServerWorkRequest} from "../../plugin/diagnostic-lifecycle.mjs";
import nativeRoleBinding from "./kovya-native-binding.generated.mjs";

import {decodePhaseRequest,createServerPhases,runServerPhases,admitServerPhase} from "./kovya-phase-authority.mjs";
import {AsyncResource} from "node:async_hooks";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync
} from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { TextDecoder } from "node:util";
import { createTurnJoin } from "../../plugin/turn-join.mjs";

import { stableJson } from "../../../packages/memory-gateway/src/canonical-json.mjs";
import {
  createWindowsDeviceAuthManager,
  loadWindowsAuthManifestSync
} from "./kovya-windows-device-auth.mjs";
import {
  createKovyaWindowsManagedAccountWorker,
  createKovyaWindowsProfileAccountStateProvider,
  launchKovyaWindowsBrokerNativeHost,
  resolveKovyaWindowsBrokerNativePath,
  stopKovyaWindowsBrokerNativeHost
} from "./kovya-windows-broker-native.mjs";

export const WINDOWS_BROKER_PROTOCOL = "kovya.windows-memory-broker.v1";
export const WINDOWS_BROKER_ENDPOINT_SCHEMA = "kovya.windows-memory-broker-endpoint.v1";
export const WINDOWS_BROKER_MAX_FRAME_BYTES = 1024 * 1024;
export const WINDOWS_BROKER_OPERATION_BUDGET_MAX_MS = 1000;
export const WINDOWS_BROKER_SIGNED_OPERATION_BUDGET_MAX_MS = 2000;
export const WINDOWS_BROKER_CONTROL_SCHEMA = "kovya.windows-memory-broker-control.v1";
const PIPE_PREFIX = "kovya-memory-v1-";
const PRIVATE_PIPE_PREFIX = "kovya-memory-private-v1-";
const INSTALL_PUBLICATION_MARKERS = Object.freeze([
  "install-publication-transaction-v1",
  "install-publication-preparing-v1"
]);
const REQUEST_KEYS = Object.freeze([
  "broker_binding", "broker_instance", "deadline_at", "operation", "payload", "request_id", "schema_version"
]);
const OPERATIONS = new Set(["capture", "hello", "recall", "shutdown", "status", "turn_prompt"]);
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });
const ROUTE_OVERRIDE_KEYS = new Set([
  "consumer_id", "consumerId", "device_id", "deviceId", "memory_namespace_id",
  "memoryNamespaceId", "namespace_id", "namespaceId", "session_id", "sessionId",
  "tenant_id", "tenantId"
]);

// Admission creates Windows publication ancestors with a protected owner DACL.
// A JS caller may use the admitted directory, but may never recreate it with
// inherited ACEs. Native startup pins it and rechecks its exact ACL.
export function requireBrokerMetadataDirectory(directory) {
  if(process.platform!=="win32")return mkdirSync(directory,{recursive:true,mode:0o700});
  let stat;try{stat=lstatSync(directory);}catch{throw brokerError("Native metadata admission is required.","runtime_owner_directory");}
  if(!stat.isDirectory()||stat.isSymbolicLink())throw brokerError("Publication directory is refused.","broker_publication_recovery_required");
}

export function kovyaBrokerPaths({ home, manifestPath = path.join(home, "windows-device-auth.json"), env = process.env } = {}) {
  const canonicalHome = canonicalInstallationRoot(home);
  const manifest = loadWindowsAuthManifestSync(manifestPath);
  if (!manifest) throw brokerError("Kovya sign-in is required.", "sign_in_required");
  const ownerBinding = boundedOwnerBinding(
    env.KOVYA_WINDOWS_OWNER_SID_HASH ?? ownerBindingFromLedger(canonicalHome)
  );
  const brokerBinding = hash(stableJson({
    schema_version: WINDOWS_BROKER_PROTOCOL,
    canonical_home_sha256: hash(canonicalHome.toLowerCase()),
    owner_sid_hash: ownerBinding,
    consumer_id: manifest.consumer_id,
    device_id: manifest.device_id,
    session_id: manifest.session_id
  }));
  const stateDirectory = path.join(canonicalHome, "state", "broker");
  return Object.freeze({
    baseBrokerBinding: brokerBinding,
    brokerBinding,
    canonicalHome,
    endpointPath: path.join(stateDirectory, "endpoint.json"),
    installationLockPath: path.join(canonicalHome, "state", "device-auth", "install.lock"),
    manifest,
    manifestPath,
    ownerBinding,
    pipeName: `\\\\.\\pipe\\${PIPE_PREFIX}${brokerBinding.slice(0, 48)}`,
    stateDirectory
  });
}

export function bindKovyaBrokerRuntime(paths, { authenticationIdHash, sessionId } = {}) {
  const authentication = boundedHash(authenticationIdHash, "broker_authentication_id_invalid");
  if (!Number.isInteger(sessionId) || sessionId < 0 || sessionId > 0xffffffff) {
    throw brokerError("Windows broker session identity is invalid.", "broker_session_invalid");
  }
  const brokerBinding = hash(stableJson({
    schema_version: WINDOWS_BROKER_PROTOCOL,
    installation_binding: paths.baseBrokerBinding ?? paths.brokerBinding,
    authentication_id_hash: authentication,
    windows_session_id: sessionId
  }));
  return Object.freeze({
    ...paths,
    authenticationIdHash: authentication,
    brokerBinding,
    pipeName: `\\\\.\\pipe\\${PIPE_PREFIX}${brokerBinding.slice(0, 48)}`,
    sessionId
  });
}

export function createKovyaBrokerControlProof(paths, role = "uninstaller") {
  if (!new Set(["installer", "logout", "uninstaller", "update"]).has(role)) {
    throw brokerError("Kovya broker control role is invalid.", "broker_control_refused");
  }
  const ledgerPath = path.join(paths.canonicalHome, "windows-host-integration.json");
  assertOrdinaryFile(ledgerPath);
  const ledgerSha256 = hash(readFileSync(ledgerPath));
  return Object.freeze({
    schema_version: WINDOWS_BROKER_CONTROL_SCHEMA,
    control_role: role,
    control_binding: hash(stableJson({
      schema_version: WINDOWS_BROKER_CONTROL_SCHEMA,
      broker_binding: paths.brokerBinding,
      canonical_home_sha256: hash(paths.canonicalHome.toLowerCase()),
      ledger_sha256: ledgerSha256
    }))
  });
}

export function readKovyaBrokerEndpoint(paths, {
  nativeExecutablePath = installedNativeExecutablePath(paths)
} = {}) {
  if (!existsSync(paths.endpointPath)) return null;
  assertOrdinaryFile(paths.endpointPath);
  const endpoint = JSON.parse(readFileSync(paths.endpointPath, "utf8"));
  return validateKovyaBrokerEndpoint(paths,endpoint,{nativeExecutablePath});
}
export function validateKovyaBrokerEndpoint(paths,endpoint,{nativeExecutablePath=installedNativeExecutablePath(paths)}={}) {
  let expectedPaths = paths;
  if (endpoint && Object.hasOwn(endpoint, "authentication_id_hash")) {
    expectedPaths = bindKovyaBrokerRuntime(paths, {
      authenticationIdHash: endpoint.authentication_id_hash,
      sessionId: endpoint.windows_session_id
    });
  }
  let expectedNativeImageHash = null;
  if (endpoint && Object.hasOwn(endpoint, "image_path_sha256")) {
    const nativePath = canonicalNativeExecutablePath(nativeExecutablePath, paths.canonicalHome);
    expectedNativeImageHash = hash(nativePath.toUpperCase());
  }
  if (!endpoint || endpoint.schema_version !== WINDOWS_BROKER_ENDPOINT_SCHEMA
      || (Object.hasOwn(endpoint,"broker_scope") && !["machine","harness_session"].includes(endpoint.broker_scope))
      || endpoint.protocol_version !== WINDOWS_BROKER_PROTOCOL
      || endpoint.broker_binding !== expectedPaths.brokerBinding
      || endpoint.owner_sid_hash !== expectedPaths.ownerBinding
      || endpoint.pipe_name !== expectedPaths.pipeName
      || !Number.isInteger(endpoint.pid) || endpoint.pid < 1
      || !/^[a-f0-9]{32}$/u.test(endpoint.broker_instance)
      || !Number.isFinite(Date.parse(endpoint.started_at))
      || (Object.hasOwn(endpoint, "authentication_id_hash") && (
        !/^[1-9][0-9]{5,19}$/u.test(String(endpoint.process_creation_filetime ?? ""))
        || !/^[a-f0-9]{64}$/u.test(String(endpoint.image_path_sha256 ?? ""))
        || endpoint.authentication_id_hash !== expectedPaths.authenticationIdHash
        || endpoint.windows_session_id !== expectedPaths.sessionId
        || endpoint.installation_root_sha256 !== hash(expectedPaths.canonicalHome.toLowerCase())
        || !Number.isInteger(endpoint.parent_pid) || endpoint.parent_pid < 1
        || endpoint.parent_pid === endpoint.pid
        || !/^[1-9][0-9]{5,19}$/u.test(String(endpoint.parent_process_creation_filetime ?? ""))
        || !/^[a-f0-9]{64}$/u.test(String(endpoint.parent_image_path_sha256 ?? ""))
        || !Number.isFinite(Date.parse(endpoint.published_at))
        || Date.parse(endpoint.published_at) < Date.parse(endpoint.started_at)
      ))) {
    throw brokerError("Kovya broker endpoint is invalid.", "broker_endpoint_invalid");
  }
  // A valid endpoint for another paired runtime at this home is occupied, not
  // missing. Refuse it without inviting the caller to start a second broker.
  if(expectedNativeImageHash!==null && endpoint.image_path_sha256!==expectedNativeImageHash)
    throw brokerError("Kovya broker belongs to an incompatible runtime.", "broker_runtime_incompatible");
  return Object.freeze(endpoint);
}

export function assertBrokerResidencyBinding(residency,endpoint) {
  if (!residency || !["machine","harness_session"].includes(residency.broker_scope)
      || residency.pid !== endpoint.parent_pid
      || residency.process_creation_filetime !== endpoint.parent_process_creation_filetime
      || residency.image_path_sha256 !== endpoint.parent_image_path_sha256)
    throw brokerError("Broker residency identity is unconfirmed.","broker_scope_unknown");
}

export function createKovyaWindowsBrokerServer({
  home,
  manifestPath = path.join(home, "windows-device-auth.json"),
  env = process.env,
  authManager = null,
  authManagerFactory = createWindowsDeviceAuthManager,
  accountStateProvider,
  memoryClient = null,
  now = () => new Date(),
  monotonicNow = () => performance.now(),
  pid = process.pid,
  pipeName = null,
  maxFrameBytes = WINDOWS_BROKER_MAX_FRAME_BYTES,
  verifyPipeAcl = null,
  nativeTransport = process.platform === "win32",
  nativeExecutablePath = null,
  nativeHostLauncher = launchKovyaWindowsBrokerNativeHost,
  nativeHostStopper = stopKovyaWindowsBrokerNativeHost,
  isNativeHostAlive = defaultIsProcessAlive,
  brokerResidency = null
} = {}) {
  const discoveredPaths = kovyaBrokerPaths({ home, manifestPath, env });
  let paths = Object.freeze({ ...discoveredPaths, pipeName: pipeName ?? discoveredPaths.pipeName });
  const brokerInstance = randomBytes(16).toString("hex");
  const startedAt = now().toISOString();
  let manager = authManager;
  let accountWorker = null;
  let clientModule = memoryClient;
  let directServer = null;
  let nativeHost = null;
  let nativePrivateTransport = null;
  let startPromise = null;
  let closing = false;
  let endpointPublished = false;
  let publishedAt = null;
  let stopped = false;
  let completionCode = 0;
  let resolveStopped;
  const stoppedPromise = new Promise((resolve) => { resolveStopped = resolve; });
  const sockets = new Set();
  const inFlight = new Set();
  // Capture broker entry before startup creates account/provider frames. Native
  // socket callbacks otherwise retain those private frames after startup ends.
  const requestEntry = new AsyncResource("KovyaBrokerIngress", {requireManualDestroy:true});
  const turnJoin = createTurnJoin({
    capture: (content, options) => clientModule.capturePrivateMemory(content, options),
    now: () => now().getTime(),
    account: () => {
      const status = manager?.inspect?.();
      if (status?.state !== "existing_session") return null;
      const fields = ["consumer_id","tenant_id","namespace_id","device_id","session_id"];
      if (fields.some(key => typeof status.manifest?.[key] !== "string")) return null;
      if (fields.some(key => status.manifest[key] !== paths.manifest[key])) return null;
      return JSON.stringify(fields.map(key=>status.manifest[key]));
    }
  });
  // Observe sign-out/account replacement and enforce the retention ceiling even
  // while idle. No credential retrieval occurs in this sweep.
  let turnSweep;

  function markStopped() {
    if (stopped) return;
    stopped = true;
    requestEntry.emitDestroy();
    resolveStopped(completionCode);
  }

  function nativeHostIsLive() {
    const child = nativeHost?.child;
    if (!child || !Number.isInteger(child.pid) || child.pid < 1
        || child.exitCode !== null || child.signalCode !== null) return false;
    try { return isNativeHostAlive(child.pid) === true; }
    catch { return false; }
  }

  async function start({ primeAuthentication = true } = {}) {
    if (closing) throw brokerError("Kovya broker is stopping.", "broker_stopping");
    if (endpointPublished) return endpoint();
    if (startPromise) return startPromise;
    startPromise = startInternal({ primeAuthentication });
    try {
      return await startPromise;
    } catch (error) {
      if (!profileWorkConfigured()) startPromise = null;
      throw error;
    }
  }

  let residentStartup=null;
  async function startInternal({ primeAuthentication }) {
    const profileStartup = profileWorkConfigured();
    residentStartup=profileStartup?residentProfileStartup():null;
    const startupDeadline = monotonicNow() + WINDOWS_BROKER_OPERATION_BUDGET_MAX_MS;
    const startupRemaining = () => residentStartup?residentStartup.remainingMs():startupDeadline - monotonicNow();
    const assertStarting = () => {
      if (closing) throw brokerError("Kovya broker is stopping.", "broker_stopping");
      const remaining = startupRemaining();
      if (profileStartup && (!Number.isFinite(remaining) || remaining < 1))
        throw brokerError("Broker startup deadline elapsed.", "broker_deadline_refused");
    };
    // Retain the actual preparation after a public timeout. Late continuations
    // must drain before failed-start cleanup; they can never publish an endpoint.
    let preparation = Promise.resolve();
    const prepare = async () => {
    assertStarting();
    assertKovyaBrokerPublicationReady(paths.canonicalHome);
    assertOrdinaryInstallation(paths.canonicalHome, paths.manifestPath);
    if(!residentStartup)requireBrokerMetadataDirectory(paths.stateDirectory);
    if(residentStartup){await residentStartup.checkpoint("worker_prepare");await prepareProfileAccountWorker();await residentStartup.checkpoint("worker_ready");}
    if (!accountStateProvider && profileStartup) {
      accountStateProvider = createKovyaWindowsProfileAccountStateProvider({
        executablePath: nativeExecutablePath ?? resolveKovyaWindowsBrokerNativePath(), env, prepared:!!residentStartup
      });
    } else if(!accountStateProvider && authManager===null && nativeTransport && nativeRoleBinding.expected_role==="managed_runtime") {
      accountWorker=createKovyaWindowsManagedAccountWorker({
        executablePath:nativeExecutablePath??resolveKovyaWindowsBrokerNativePath(),env,
        onUnavailable(){completionCode=1;if(endpointPublished)void stop().catch(()=>{});}
      });
      accountStateProvider=accountWorker.withAccountState;
      try{await accountWorker.start();}catch(error){await cleanupFailedStart();throw error;}
    }
    const prepareService=async()=>{
      assertStarting();
      manager ??= authManagerFactory({
        manifestPath: paths.manifestPath,
        apiBaseUrl: paths.manifest.api_base_url,
        audience: paths.manifest.audience,
        accountStateProvider,
        retainSigningKeyInMemory: true,
        ...(residentStartup?{remainingMs:()=>borrowProfileWorkRequest().remainingMs()}: {})
      });
      if (nativeTransport) {
        const executablePath = canonicalNativeExecutablePath(
          nativeExecutablePath ?? resolveKovyaWindowsBrokerNativePath(),
          paths.canonicalHome
        );
        const privatePipeName = `\\\\.\\pipe\\${PRIVATE_PIPE_PREFIX}${randomBytes(24).toString("hex")}`;
        const remaining = profileStartup ? startupRemaining() : WINDOWS_BROKER_SIGNED_OPERATION_BUDGET_MAX_MS;
        if (profileStartup && (!Number.isFinite(remaining) || remaining < 50))
          throw brokerError("Broker startup deadline elapsed.", "broker_deadline_refused");
        if(residentStartup)await residentStartup.checkpoint("host_prepare");
        nativeHost = await nativeHostLauncher({
          brokerInstance,
          executablePath,
          env,
          timeoutMs: Math.floor(remaining),
          profileWorkTicket: profileStartup&&!residentStartup ? borrowProfileWorkRequest().ticket : null,
          residentStartup,
          configurationForIdentity(identity) {
            assertStarting();
            if (identity.owner_sid_hash !== discoveredPaths.ownerBinding) {
              throw brokerError("Kovya native owner identity is invalid.", "broker_owner_invalid");
            }
            paths = bindKovyaBrokerRuntime(discoveredPaths, {
              authenticationIdHash: identity.authentication_id_hash,
              sessionId: identity.windows_session_id
            });
            return Object.freeze({
              publicPipeName: paths.pipeName,
              privatePipeName,
              brokerBinding: paths.brokerBinding,
              brokerInstance,
              installationRootHash: hash(paths.canonicalHome.toLowerCase())
            });
          }
        });
        assertStarting();
        validateNativeHost(nativeHost, paths, brokerInstance, executablePath);
        if(residentStartup)await residentStartup.checkpoint("host_ready");
        if (brokerResidency) assertBrokerResidencyBinding(brokerResidency,nativeHost.endpoint);
        nativePrivateTransport = attachNativePrivateTransport(
          nativeHost.privateSocket,
          processNativeRequest,
          maxFrameBytes
        );
        nativeHost.child.once("exit", () => {
          if (closing) return;
          completionCode = 1;
          stop().catch(() => { markStopped(); });
        });
      } else {
        removeStaleEndpointForDirectTest(paths.endpointPath);
        directServer = net.createServer((socket) => {
          if (closing || (profileStartup && !endpointPublished)) return socket.destroy();
          sockets.add(socket);
          socket.once("close", () => sockets.delete(socket));
          handleSocket(socket).catch(() => socket.destroy());
        });
        directServer.on("error", () => {});
        await listen(directServer, paths.pipeName);
        assertStarting();
        const aclVerifier = verifyPipeAcl ?? verifyNativePipeAcl;
        await aclVerifier({ paths, env });
      }

      assertStarting();
      if(residentStartup){
        await residentStartup.checkpoint("account_validate");
        await runProfileWorkRequest(()=>Math.min(1000,startupRemaining()),async()=>{
          const ready=await manager.prepareResidentAccess();
          if(ready?.ok!==true||ready.access_ready!==true)throw brokerError("Account access is not ready.","profile_account_unavailable");
        });
        await residentStartup.checkpoint("account_end");
      }else if (primeAuthentication) await manager.getAccessCredential();
      assertStarting();
      clientModule ??= await import(pathToFileURL(path.join(
        paths.canonicalHome, "connector", "claude-code", "client", "kovya-memory-client.mjs"
      )).href);
      assertStarting();
      return endpoint();
    };
    if(residentStartup)await prepareService();
    else await withWindowsAuthState(paths.manifestPath,paths.manifest.api_base_url,prepareService,{accountStateProvider});
    };
    try {
      if(residentStartup){preparation=prepare();await preparation;}
      else await runProfileWorkRequest(startupRemaining, () => {
        preparation = prepare();return preparation;
      });
      // Publication follows checked account STOP and native Work release.
      assertStarting();
    if(closing || (accountWorker && accountWorker.state!=="idle") || (nativeTransport && !nativeHostIsLive()))
      throw brokerError("Broker startup ownership did not settle.","broker_native_exited");
    publishedAt=now().toISOString();
    turnSweep=setInterval(()=>turnJoin.sweep(),1000);turnSweep.unref();
    if(residentStartup){await residentStartup.checkpoint("publish");await residentStartup.publish(endpoint());}
    else{writeEndpointAtomic(paths.endpointPath,endpoint());assertStarting();}
    endpointPublished=true;
    if(closing || (nativeTransport && !nativeHostIsLive()))
      throw brokerError("Kovya native broker exited during publication.","broker_native_exited");
    } catch (error) {
      if (profileStartup) {
        closing = true;
        completionCode = 1;
        if (endpointPublished&&!residentStartup) removeOwnedEndpoint(paths.endpointPath, brokerInstance);
        endpointPublished = false;
        // Keep the public deadline independent of actual drain/host cleanup.
        // A failed startup is terminal: no retry can overlap retained ownership.
        const cleanup = preparation.catch(() => {}).then(cleanupFailedStart);
        inFlight.add(cleanup);
        cleanup.catch(() => { completionCode = 1; }).finally(() => {
          inFlight.delete(cleanup);
          markStopped();
        });
        throw error;
      }
      if(error?.code==="broker_native_exited")completionCode=1;
      try{await cleanupFailedStart();}
      finally{if(closing || error?.code==="broker_native_exited")markStopped();}
      throw error;
    }
    return endpoint();
  }

  async function stop() {
    if (closing) return stoppedPromise;
    closing = true;
    clearInterval(turnSweep);
    turnJoin.clear();
    try {
      let hostStopError = null;
      for (const socket of sockets) socket.destroy();
      if (directServer) await closeServer(directServer);
      directServer = null;
      if (nativeHost) {
        try { await nativeHostStopper(nativeHost, { timeoutMs: 1000 }); }
        catch (error) { if (profileWorkConfigured()) hostStopError = error; }
      }
      await settleInFlight(new Set([...inFlight,...(startPromise?[startPromise]:[])]), 1000);
      nativePrivateTransport?.close();
      nativePrivateTransport = null;
      nativeHost = null;
      if (endpointPublished) removeOwnedEndpoint(paths.endpointPath, brokerInstance);
      endpointPublished = false;
      await accountWorker?.stop();
      await residentStartup?.stop();
      manager?.shutdown?.();
      if (hostStopError) throw hostStopError;
    } catch (error) {
      completionCode = 1;
      throw error;
    } finally {
      markStopped();
    }
  }

  async function cleanupFailedStart() {
    let hostStopError = null;
    clearInterval(turnSweep);
    turnJoin.clear();
    for (const socket of sockets) socket.destroy();
    if (directServer) await closeServer(directServer);
    directServer = null;
    nativePrivateTransport?.close();
    nativePrivateTransport = null;
    if (nativeHost) {
      try { await nativeHostStopper(nativeHost, { timeoutMs: 1000 }); }
      catch (error) { if (profileWorkConfigured()) hostStopError = error; }
    }
    nativeHost = null;
    if(!residentStartup)removeOwnedEndpoint(paths.endpointPath, brokerInstance);
    endpointPublished = false;
    await accountWorker?.stop();
    await residentStartup?.stop();
    manager?.shutdown?.();
    if (hostStopError) throw hostStopError;
  }

  function endpoint() {
    const base = {
      schema_version: WINDOWS_BROKER_ENDPOINT_SCHEMA,
      protocol_version: WINDOWS_BROKER_PROTOCOL,
      broker_binding: paths.brokerBinding,
      broker_instance: brokerInstance,
      owner_sid_hash: paths.ownerBinding,
      pipe_name: paths.pipeName,
      started_at: startedAt,
      ...(publishedAt ? { published_at: publishedAt } : {}),
      ...(brokerResidency ? {broker_scope:brokerResidency.broker_scope} : {})
    };
    if (nativeHost) return Object.freeze({ ...base, ...nativeHost.endpoint });
    return Object.freeze({ ...base, pid });
  }

  async function handleSocket(socket) {
    const raw = await readFrame(socket, maxFrameBytes, 1000);
    const response = await processNativeRequest(raw);
    await writeRawFrame(socket, response, maxFrameBytes);
    response.fill(0);
    socket.end();
  }

  async function processNativeRequest(raw,sendPhase) {
    // Both transports may inherit the ended startup frame. Only this fresh
    // request crosses the context boundary; retained account continuations do not.
    if (profileWorkConfigured() && (closing || !endpointPublished)) {
      raw.fill(0);
      throw brokerError("Kovya broker is not accepting requests.", "broker_stopping");
    }
    let phase=null;
    if(profileWorkConfigured()){
      const envelope=decodePhaseRequest(raw,brokerInstance);raw.fill(0);raw=envelope.body;
      phase=createServerPhases(envelope,sendPhase,()=>profileIngressRemaining(envelope.deadline),{bind:bindProfileServer,observe:observeProfileServer});
    }
    const work = requestEntry.runInAsyncScope(() => runWindowsAuthRequest(() => runServerPhases(phase,()=>processRequest(raw,phase))));
    inFlight.add(work);
    try { return await work; }
    finally { inFlight.delete(work); }
  }

  async function processRequest(raw,phase=null) {
    const requestBytes=raw.length;
    let request = null;
    let validationError = null;
    try {
      const text = STRICT_UTF8.decode(raw);
      request = JSON.parse(text);
      if (text !== stableJson(request)) throw brokerError("Broker request is not canonical.", "broker_frame_invalid");
      validateRequest(request, endpoint(), now());
      if(phase&&(request.request_id!==phase.envelope.requestId||request.operation!==phase.envelope.operation))throw brokerError("Broker correlation refused.","broker_native_protocol_refused");
    } catch (error) {
      validationError = /^[a-z][a-z0-9_]{1,80}$/u.test(String(error?.code ?? ""))
        ? error : brokerError("Broker request frame is invalid.", "broker_frame_invalid");
    } finally {
      raw.fill(0);
    }
    const wallDeadline = Date.parse(request?.deadline_at);
    const admissionBudgetMs = !profileWorkConfigured() && ["recall", "capture", "hello"].includes(request?.operation)
      ? WINDOWS_BROKER_SIGNED_OPERATION_BUDGET_MAX_MS : WINDOWS_BROKER_OPERATION_BUDGET_MAX_MS;
    const localDeadline = monotonicNow() + Math.max(0, Math.min(
      admissionBudgetMs, wallDeadline - now().getTime()
    ));
    const remainingMs = () => Math.min(wallDeadline - now().getTime(), localDeadline - monotonicNow(),phase?profileIngressRemaining(phase.envelope.deadline):Infinity);
    let response = validationError ? {
      ok: false,
      error_code: safeCode(validationError?.code),
      failure_reason: safeCode(validationError?.code)
    } : await runObservedServerWorkRequest(remainingMs, async ticket => {
      if(phase)await phase.bind(ticket);
      const fields={transport_operation:request.operation,transport_request_id:request.request_id,remaining_work_ms:Math.max(0,remainingMs())};
      await diagnosticCheckpoint({stage:"broker_request_read",outcome:"succeeded",reason:"none",request_bytes:requestBytes,...fields});
      const result=await diagnosticStage("broker_dispatch",()=>dispatch(request, remainingMs, ticket));
      const responseBytes=Buffer.byteLength(stableJson({schema_version:WINDOWS_BROKER_PROTOCOL,broker_instance:brokerInstance,operation:safeResponseOperation(request.operation),request_id:safeResponseRequestId(request.request_id),...result}));
      await diagnosticCheckpoint({stage:"broker_response_encode",outcome:"succeeded",reason:"none",response_bytes:responseBytes,...fields,remaining_work_ms:Math.max(0,remainingMs())});
      return result;
    },{operation:"broker",memory_event_id:memoryDiagnosticEventId(request.request_id)},request.operation).catch((error) => ({
      ok: false,
      error_code: safeCode(error?.code),
      failure_reason: safeCode(error?.code)
    }));
    const encode = value => Buffer.from(stableJson({
      schema_version: WINDOWS_BROKER_PROTOCOL,
      broker_instance: brokerInstance,
      operation: safeResponseOperation(request?.operation),
      request_id: safeResponseRequestId(request?.request_id),
      ...value
    }), "utf8");
    const expired = () => !Number.isFinite(remainingMs()) || remainingMs() <= 0;
    const refusal = {ok:false,error_code:"broker_deadline_refused",failure_reason:"broker_deadline_refused"};
    if (response.ok === true && expired()) response = refusal;
    let bytes = encode(response);
    if (response.ok === true && expired()) { bytes.fill(0); bytes = encode(refusal); }
    return phase?phase.finish(bytes):bytes;
  }

  async function dispatch(request, remainingMs, profileWorkTicket) {
    const remaining = remainingMs();
    if (!Number.isFinite(remaining) || remaining <= 0) {
      throw brokerError("Broker request deadline elapsed before dispatch.", "broker_deadline_refused");
    }
    if (["hello","status","shutdown","turn_prompt"].includes(request.operation))await admitServerPhase();
    if (request.operation === "hello") return { ok: true, ready: true };
    if (request.operation === "status") {
      if (Object.keys(request.payload).length) turnJoin.end(request.payload);
      return { ok: true, ready: true, accepting: !closing, protocol_version: WINDOWS_BROKER_PROTOCOL,
        ...(brokerResidency ? {broker_scope:brokerResidency.broker_scope,cross_harness_residency:brokerResidency.broker_scope==="machine"} : {}) };
    }
    if (request.operation === "shutdown") {
      validateControlProof(request.payload, paths);
      setImmediate(() => stop().catch(() => {}));
      return { ok: true, outcome: "stopping" };
    }
    const options = Object.freeze({
      ...(profileWorkTicket !== null ? {profileWorkTicket} : {}),
      deviceAuthSession: manager,
      fetchTimeoutMs: Math.min(remaining, 15_000),
      remainingMs,
      monotonicNow,
      windowsAuthManifestPath: paths.manifestPath
    });
    // Join payloads have their own exact schema. Their host is a harness identity,
    // never a network route override; full legacy operations retain the guard below.
    if (request.operation === "turn_prompt") {
      return { ok: true, result: turnJoin.prompt(request.payload) };
    }
    if (request.operation === "capture" && Object.hasOwn(request.payload,"transcript_bound")) {
      return { ok: true, result: await turnJoin.join(request.payload, options) };
    }
    for (const key of Object.keys(request.payload)) {
      if (ROUTE_OVERRIDE_KEYS.has(key)) {
        throw brokerError("Broker route overrides are refused.", "broker_route_refused");
      }
    }
    if (request.operation === "recall") {
      return { ok: true, result: await clientModule.recallMemory(request.payload, options) };
    }
    if (request.operation === "capture") {
      return { ok: true, result: await clientModule.capturePrivateMemory(request.payload, options) };
    }
    throw brokerError("Broker operation is refused.", "broker_operation_refused");
  }

  return Object.freeze({ endpoint, get paths() { return paths; }, start, stop, waitForStop: () => stoppedPromise });
}

export function assertKovyaBrokerPublicationReady(home) {
  const statePath = path.join(home, "state");
  const root = path.parse(statePath).root;
  let current = root;
  for (const segment of path.relative(root, statePath).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    let stat;
    try {
      stat = lstatSync(current);
    } catch (error) {
      if (error?.code === "ENOENT" && current === statePath) return true;
      throw brokerError("Kovya publication recovery state is indeterminate.", "broker_publication_recovery_required");
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw brokerError("Kovya publication recovery is required.", "broker_publication_recovery_required");
    }
  }
  for (const marker of INSTALL_PUBLICATION_MARKERS) {
    try {
      lstatSync(path.join(statePath, marker));
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw brokerError("Kovya publication recovery state is indeterminate.", "broker_publication_recovery_required");
    }
    throw brokerError("Kovya publication recovery is required.", "broker_publication_recovery_required");
  }
  return true;
}

function validateRequest(request, endpoint, current) {
  if (!request || typeof request !== "object" || Array.isArray(request)
      || stableJson(Object.keys(request).sort()) !== stableJson(REQUEST_KEYS)) {
    throw brokerError("Broker request shape is invalid.", "broker_frame_invalid");
  }
  if (request.schema_version !== WINDOWS_BROKER_PROTOCOL
      || request.broker_binding !== endpoint.broker_binding
      || request.broker_instance !== endpoint.broker_instance
      || !OPERATIONS.has(request.operation)
      || !/^[a-f0-9-]{16,64}$/u.test(request.request_id)
      || !request.payload || typeof request.payload !== "object" || Array.isArray(request.payload)) {
    throw brokerError("Broker request binding is invalid.", "broker_binding_refused");
  }
  const deadline = Date.parse(request.deadline_at);
  if (!Number.isFinite(deadline) || deadline <= current.getTime() || deadline - current.getTime() > 15_000) {
    throw brokerError("Broker request deadline is invalid.", "broker_deadline_refused");
  }
  if (request.operation === "hello"
      && Object.keys(request.payload).length !== 0) {
    throw brokerError("Broker control payload is invalid.", "broker_frame_invalid");
  }
}

function validateControlProof(payload, paths) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)
      || stableJson(Object.keys(payload).sort()) !== stableJson([
        "control_binding", "control_role", "schema_version"
      ])) {
    throw brokerError("Kovya broker control proof is invalid.", "broker_control_refused");
  }
  const expected = createKovyaBrokerControlProof(paths, payload.control_role);
  if (payload.schema_version !== expected.schema_version
      || payload.control_binding !== expected.control_binding) {
    throw brokerError("Kovya broker control proof is invalid.", "broker_control_refused");
  }
}

function validateNativeHost(host, paths, brokerInstance, executablePath) {
  const expectedImageHash = hash(executablePath.toUpperCase());
  if (!host || typeof host !== "object" || !host.child || !host.privateSocket
      || host.endpoint?.broker_binding !== paths.brokerBinding
      || host.endpoint?.broker_instance !== brokerInstance
      || host.endpoint?.pipe_name !== paths.pipeName
      || host.endpoint?.owner_sid_hash !== paths.ownerBinding
      || host.endpoint?.authentication_id_hash !== paths.authenticationIdHash
      || host.endpoint?.windows_session_id !== paths.sessionId
      || host.endpoint?.image_path_sha256 !== expectedImageHash
      || host.endpoint?.installation_root_sha256 !== hash(paths.canonicalHome.toLowerCase())
      || host.endpoint?.parent_pid !== process.pid
      || !/^[1-9][0-9]{5,19}$/u.test(String(host.endpoint?.parent_process_creation_filetime ?? ""))
      || !/^[a-f0-9]{64}$/u.test(String(host.endpoint?.parent_image_path_sha256 ?? ""))
      || host.endpoint?.pid !== host.child.pid) {
    throw brokerError("Kovya native broker identity is invalid.", "broker_native_identity_refused");
  }
}

function attachNativePrivateTransport(socket, requestHandler, maximum) {
  if (!socket || typeof socket.on !== "function" || typeof socket.write !== "function") {
    throw brokerError("Kovya native private transport is invalid.", "broker_native_private_transport_failed");
  }
  const correlationBytes = 16;
  const active = new Set();
  let buffered = Buffer.alloc(0);
  let closed = false;
  let writeQueue = Promise.resolve();

  const close = () => {
    if (closed) return;
    closed = true;
    buffered.fill(0);
    buffered = Buffer.alloc(0);
    try { socket.destroy(); } catch {}
  };
  const onError = () => close();
  const onData = (chunkValue) => {
    if (closed) return;
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue);
    if (buffered.length + chunk.length > maximum + correlationBytes + 4) {
      chunk.fill(0);
      return close();
    }
    const prior = buffered;
    buffered = Buffer.concat([prior, chunk]);
    prior.fill(0);
    chunk.fill(0);
    while (buffered.length >= 4) {
      const length = buffered.readUInt32LE(0);
      if (length < correlationBytes + 2 || length > maximum + correlationBytes) return close();
      if (buffered.length < length + 4) return;
      const body = Buffer.from(buffered.subarray(4, length + 4));
      const remainder = Buffer.from(buffered.subarray(length + 4));
      buffered.fill(0);
      buffered = remainder;
      const correlation = body.subarray(0, correlationBytes).toString("ascii");
      if (!/^[a-f0-9]{16}$/u.test(correlation) || active.has(correlation)) {
        body.fill(0);
        return close();
      }
      const request = Buffer.from(body.subarray(correlationBytes));
      body.fill(0);
      active.add(correlation);
      const sendResponse=async response => {
        if (!Buffer.isBuffer(response) || response.length < 2 || response.length > maximum) {
          response?.fill?.(0);
          throw brokerError("Kovya native response is invalid.", "broker_native_private_transport_failed");
        }
        const envelope = Buffer.allocUnsafe(correlationBytes + response.length);
        envelope.write(correlation, 0, correlationBytes, "ascii");
        response.copy(envelope, correlationBytes);
        response.fill(0);
        writeQueue = writeQueue.then(() => writeRawFrame(socket, envelope, maximum + correlationBytes))
          .finally(() => envelope.fill(0));
        return writeQueue;
      };
      Promise.resolve(requestHandler(request,sendResponse)).then(response=>response===null?undefined:sendResponse(response)).catch(() => close()).finally(() => active.delete(correlation));
    }
  };
  socket.on("data", onData);
  socket.once("error", onError);
  socket.once("end", onError);
  socket.once("close", onError);
  return Object.freeze({
    close() {
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("end", onError);
      socket.off("close", onError);
      close();
    }
  });
}

function installedNativeExecutablePath(paths) {
  return path.join(
    paths.canonicalHome,
    "connector", "claude-code", "client", "kovya_windows_broker_native.exe"
  );
}

function canonicalNativeExecutablePath(value, canonicalHome) {
  if (typeof value !== "string" || !path.isAbsolute(value)
      || path.basename(value).toLowerCase() !== "kovya_windows_broker_native.exe") {
    throw brokerError("Kovya native broker path is invalid.", "broker_native_path_invalid");
  }
  assertOrdinaryFile(value);
  const resolved = realpathSync.native(value);
  const relative = path.relative(canonicalHome, resolved);
  if (relative.length === 0 || relative === ".." || relative.startsWith(`..${path.sep}`)
      || path.isAbsolute(relative)) {
    throw brokerError("Kovya native broker is outside its installation root.", "broker_native_path_invalid");
  }
  let current = canonicalHome;
  for (const segment of relative.split(path.sep)) {
    current = path.join(current, segment);
    if (lstatSync(current).isSymbolicLink()) {
      throw brokerError("Kovya native broker path contains a reparse component.", "broker_native_path_invalid");
    }
  }
  return resolved;
}

function safeResponseOperation(value) {
  return /^[a-z][a-z0-9_]{0,31}$/u.test(String(value ?? "")) ? String(value) : "refused";
}

function safeResponseRequestId(value) {
  return /^[a-f0-9-]{16,64}$/u.test(String(value ?? ""))
    ? String(value) : "00000000-0000-0000-0000-000000000000";
}

function settleInFlight(values, timeoutMs) {
  if (values.size === 0) return Promise.resolve();
  return Promise.race([
    Promise.allSettled([...values]),
    new Promise((resolve) => {
      const timer = setTimeout(resolve, timeoutMs);
      timer.unref?.();
    })
  ]);
}

export async function runKovyaBrokerCli(argv = process.argv.slice(2), env = process.env) {
  if (!argv.includes("--serve")) return 64;
  const homeIndex = argv.indexOf("--home");
  const home = homeIndex >= 0 ? argv[homeIndex + 1] : env.KOVYA_HOME;
  if (!home || !path.isAbsolute(home)) return 64;
  const server = createKovyaWindowsBrokerServer({ home, env });
  await server.start();
  const shutdown = () => { server.stop().catch(() => {}); };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
  const completionCode = await server.waitForStop();
  process.removeListener("SIGINT", shutdown);
  process.removeListener("SIGTERM", shutdown);
  return completionCode;
}

export function spawnKovyaBroker({ home, env = process.env, spawnImpl = spawn } = {}) {
  if(managedPackageConfigured())throw brokerError("Managed broker requires native residency creation.","msix_native_launcher_required");
  const child = spawnImpl(process.execPath, [fileURLToPath(import.meta.url), "--serve", "--home", home], {
    detached: true,
    windowsHide: true,
    shell: false,
    stdio: "ignore",
    env: Object.freeze({
      SystemRoot: env.SystemRoot,
      WINDIR: env.WINDIR,
      PATH: env.PATH,
      ProgramFiles: env.ProgramFiles,
      USERPROFILE: env.USERPROFILE,
      HOME: env.HOME,
      USERDOMAIN: env.USERDOMAIN,
      USERNAME: env.USERNAME,
      SESSIONNAME: env.SESSIONNAME,
      KOVYA_HOME: home,
      KOVYA_WINDOWS_AUTH_MANIFEST: path.join(home, "windows-device-auth.json"),
      KOVYA_WINDOWS_OWNER_SID_HASH: env.KOVYA_WINDOWS_OWNER_SID_HASH
    })
  });
  child.unref();
  return child.pid;
}

function canonicalInstallationRoot(home) {
  if (!home || !path.isAbsolute(home)) throw brokerError("Kovya home must be absolute.", "broker_home_invalid");
  return realpathSync.native(home);
}

function assertOrdinaryInstallation(home, manifestPath) {
  assertOrdinaryFile(manifestPath);
  let current = path.parse(home).root;
  for (const segment of path.relative(current, home).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) throw brokerError("Kovya home contains a reparse component.", "broker_home_refused");
  }
}

function acquireBrokerStartupAdmission(lockPath) {
  mkdirSync(path.dirname(lockPath), { recursive: true, mode: 0o700 });
  try {
    return Object.freeze({ fd: openSync(lockPath, "wx", 0o600), path: lockPath });
  } catch {
    throw brokerError("A Kovya installation or removal is in progress.", "broker_installation_locked");
  }
}

function releaseBrokerStartupAdmission(admission) {
  if (!admission) return;
  try { closeSync(admission.fd); } catch {}
  try { unlinkSync(admission.path); } catch {}
}

function assertOrdinaryFile(filePath) {
  const stat = lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw brokerError("Kovya broker file is not ordinary.", "broker_file_refused");
}

function boundedOwnerBinding(value) {
  if (!/^[a-f0-9]{64}$/u.test(String(value ?? ""))) {
    throw brokerError("Windows owner binding is invalid.", "broker_owner_invalid");
  }
  return value;
}

function boundedHash(value, code) {
  if (!/^[a-f0-9]{64}$/u.test(String(value ?? ""))) {
    throw brokerError("Windows broker identity hash is invalid.", code);
  }
  return String(value);
}

function ownerBindingFromLedger(home) {
  const ledgerPath = path.join(home, "windows-host-integration.json");
  if (!existsSync(ledgerPath)) return null;
  try {
    assertOrdinaryFile(ledgerPath);
    const ledger = JSON.parse(readFileSync(ledgerPath, "utf8"));
    return ledger?.broker?.owner_sid_hash ?? null;
  } catch {
    return null;
  }
}

async function verifyNativePipeAcl({ paths, env }) {
  if (process.platform !== "win32") return true;
  const helperPath = fileURLToPath(new URL("./kovya_windows_broker_pipe_acl.ps1", import.meta.url));
  const windowsPowerShell = path.join(env.SystemRoot ?? env.WINDIR ?? "C:\\Windows",
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const result = spawnSync(windowsPowerShell, [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-File", helperPath,
    "-PipeName", paths.pipeName, "-ExpectedOwnerSidHash", paths.ownerBinding
  ], {
    windowsHide: true,
    shell: false,
    timeout: 2500,
    encoding: "utf8",
    env: Object.freeze({ SystemRoot: env.SystemRoot, WINDIR: env.WINDIR, PATH: env.PATH, ProgramFiles: env.ProgramFiles })
  });
  if (result.status !== 0 || result.stderr.length !== 0) {
    throw brokerError("Kovya broker pipe ACL could not be verified.", "broker_pipe_acl_refused");
  }
  let proof;
  try { proof = JSON.parse(result.stdout); } catch {}
  if (proof?.ok !== true || proof.owner_sid_hash !== paths.ownerBinding) {
    throw brokerError("Kovya broker pipe ACL could not be verified.", "broker_pipe_acl_refused");
  }
  return true;
}

function hash(value) {
  const input = Buffer.isBuffer(value) ? value : Buffer.from(String(value), "utf8");
  return createHash("sha256").update(input).digest("hex");
}

function safeCode(value) {
  return /^[a-z][a-z0-9_]{1,80}$/u.test(String(value ?? "")) ? String(value) : "broker_failed";
}

function brokerError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function listen(server, pipeName) {
  return new Promise((resolve, reject) => {
    const onError = (error) => { server.off("listening", onListen); reject(error); };
    const onListen = () => { server.off("error", onError); resolve(); };
    server.once("error", onError);
    server.once("listening", onListen);
    server.listen(pipeName);
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

function readFrame(socket, maximum, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    const timer = setTimeout(() => onError(brokerError("Broker frame timed out.", "broker_frame_timeout")), timeoutMs);
    timer.unref?.();
    const cleanup = () => { clearTimeout(timer); socket.off("data", onData); socket.off("error", onError); socket.off("end", onEnd); };
    const onError = (error) => { cleanup(); buffered.fill(0); reject(error); };
    const onEnd = () => { cleanup(); buffered.fill(0); reject(brokerError("Broker frame ended early.", "broker_frame_invalid")); };
    const onData = (chunk) => {
      const prior = buffered;
      buffered = Buffer.concat([buffered, chunk]);
      prior.fill(0);
      if (buffered.length < 4) return;
      const length = buffered.readUInt32LE(0);
      if (length < 2 || length > maximum || buffered.length > length + 4) return onError(brokerError("Broker frame length is invalid.", "broker_frame_invalid"));
      if (buffered.length === length + 4) {
        cleanup();
        const result = Buffer.from(buffered.subarray(4));
        buffered.fill(0);
        resolve(result);
      }
    };
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("end", onEnd);
  });
}

function writeRawFrame(socket, body, maximum) {
  if (!Buffer.isBuffer(body) || body.length < 2 || body.length > maximum) {
    throw brokerError("Broker response is too large.", "broker_frame_invalid");
  }
  const frame = Buffer.allocUnsafe(body.length + 4);
  frame.writeUInt32LE(body.length, 0);
  body.copy(frame, 4);
  return new Promise((resolve, reject) => socket.write(frame, (error) => {
    frame.fill(0);
    if (error) reject(error); else resolve();
  }));
}

function writeEndpointAtomic(targetPath, endpoint) {
  requireBrokerMetadataDirectory(path.dirname(targetPath));
  const temporary = `${targetPath}.tmp-${process.pid}-${randomUUID()}`;
  writeFileSync(temporary, `${stableJson(endpoint)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  const descriptor = openSync(temporary, "r+");
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
  renameSync(temporary, targetPath);
}

function removeStaleEndpointForDirectTest(endpointPath) {
  if (!existsSync(endpointPath)) return;
  try {
    const existing = JSON.parse(readFileSync(endpointPath, "utf8"));
    if (Number.isInteger(existing.pid) && existing.pid > 0) {
      try { process.kill(existing.pid, 0); return; } catch {}
    }
  } catch {}
  rmSync(endpointPath, { force: true });
}

function defaultIsProcessAlive(processId) {
  try { process.kill(processId, 0); return true; }
  catch { return false; }
}

function removeOwnedEndpoint(endpointPath, brokerInstance) {
  if (!existsSync(endpointPath)) return;
  try {
    const current = JSON.parse(readFileSync(endpointPath, "utf8"));
    if (current.broker_instance === brokerInstance) unlinkSync(endpointPath);
  } catch {}
}

const executedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : null;
if (executedPath === import.meta.url) {
  runKovyaBrokerCli().then((code) => {
    if (Number.isInteger(code)) process.exitCode = code;
  }).catch(() => { process.exitCode = 1; });
}
