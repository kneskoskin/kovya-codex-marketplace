import {withWindowsAuthState,readWindowsAuthDocument,recordWindowsAuthDocument,observeWindowsAuthState,assertWindowsAuthEffect,rethrowInactiveWindowsAuthError,guardWindowsAuthCredentialBridge} from "./kovya-windows-device-auth.mjs";
import {diagnosticAttemptId,bindDiagnosticAttempt,serverDiagnosticReason,noteServerDiagnostic,browserExchangeRefusalReason,diagnosticStage,diagnosticObservation,propagateDiagnosticFailure,noteAuthenticationDeadline,classifyDiagnosticError} from "../../plugin/diagnostic-events.mjs";
import { spawn } from "node:child_process";
import { createHash, randomBytes as nodeRandomBytes, timingSafeEqual } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";

import { stableJson } from "../../../packages/memory-gateway/src/canonical-json.mjs";

export const WINDOWS_BROWSER_AUTH_JOURNAL_SCHEMA = "kovya.windows-browser-auth-journal.v1";
export const WINDOWS_BROWSER_AUTH_CALLBACK_PATH = "/kovya/device-authorization/callback";
export const WINDOWS_BROWSER_AUTH_SECRET_PREFIX = "Kovya.DeviceAuth/v1/browser-pending/";

const START_PATH = "/device-auth.v2/browser-authorization/start";
const EXCHANGE_PATH = "/device-auth.v2/browser-authorization/exchange";
const OPAQUE = /^[A-Za-z0-9_-]{43,128}$/u;
const TX = /^kbat_[A-Za-z0-9_-]{43}$/u;
const MAX_JSON_BYTES = 32 * 1024;
const MAX_CALLBACK_BYTES = 2048;
const MANUAL_START_SERVER_TTL_MS = 300_000;
const MANUAL_START_CLOCK_SKEW_MS = 5_000;

export function createWindowsBrowserAuthorizationTransport({ apiBaseUrl, fetchImpl = globalThis.fetch, timeoutMs = 10_000 } = {}) {
  const origin = httpsOrigin(apiBaseUrl);
  if (typeof fetchImpl !== "function") throw browserError("transport_unavailable");
  return Object.freeze({
    async start(body, options) { return post(START_PATH, body, options); },
    async exchange(body, options) { return post(EXCHANGE_PATH, body, options); }
  });

  async function post(route, body, {remainingMs,authentication=false,attemptHint=null} = {}) {
    const started=performance.now(),attempt_id=diagnosticAttemptId(body?.request_id);
    let diagnostic_reason="unknown";
    if(attemptHint!==null&&(typeof attemptHint!=="string"||! /^[a-f0-9]{160}(?![\s\S])/u.test(attemptHint)||attemptHint.slice(0,64)!==attempt_id))throw browserError("request_refused");
    if (![START_PATH, EXCHANGE_PATH].includes(route) || Buffer.byteLength(stableJson(body), "utf8") > MAX_JSON_BYTES) {
      throw browserError("request_refused");
    }
    const clock=attemptHint===null?{}:diagnosticHintClock(attemptHint);
    const budget = authentication?30000:remainingMs ? Math.floor(Math.min(timeoutMs, remainingMs())) : timeoutMs;
    if (!Number.isFinite(budget) || budget < 1) throw browserError("deadline_expired", true);
    const until=started+budget,controller=new AbortController();let timer,expiry;
    const deadlineError=()=>{
      if(!expiry){expiry=browserError(authentication?"authentication_deadline_refused":"remote_ambiguous",true);
        if(authentication)noteAuthenticationDeadline(expiry,{scope:"authentication",consumer:route===START_PATH?"authorization_request":"token_exchange",elapsed_ms:Math.max(0,performance.now()-started),budget_ms:30000});}
      return expiry;
    };
    const check=()=>{if(expiry||performance.now()>=until)throw deadlineError();remainingMs?.();};
    if(authentication)process.stderr.write(route===START_PATH?"Kovya: waiting for authorization (limit 30000 ms).\n":"Kovya: waiting for exchange (limit 30000 ms).\n");
    const expired=new Promise((_,reject)=>{timer=setTimeout(()=>{const error=deadlineError();controller.abort();reject(error);},Math.max(0,until-performance.now()));});
    const operation=(async()=>{
      let response;
      try {check();diagnosticObservation({...clock,attempt_id,diagnostic_reason,elapsed_ms:Math.max(0,performance.now()-started),stage:"request",route:route===START_PATH?"browser_start":"browser_exchange",request_outcome:"dispatched_no_response",reason:"none",outcome:"started"});response = await fetchImpl(`${origin}${route}`, {
        method: "POST", redirect: "manual", headers: { "content-type": "application/json", accept: "application/json",...(attempt_id!=="unknown"?{"x-kovya-attempt-id":attempt_id}:{}),...(attemptHint!==null?{"x-kovya-attempt":attemptHint}:{}) },
        body: JSON.stringify(body), signal: controller.signal
      });
    } catch (cause) { throw browserError("remote_ambiguous", true, cause); }
    diagnostic_reason=serverDiagnosticReason(response.headers?.get?.("x-kovya-diagnostic-reason")??"unavailable");
    diagnosticObservation({...clock,attempt_id,diagnostic_reason,elapsed_ms:Math.max(0,performance.now()-started),stage:"request",route:route===START_PATH?"browser_start":"browser_exchange",http_status:response.status,request_outcome:"response_observed",reason:"none",outcome:"unknown"});check();
    if (response.status >= 300 && response.status < 400) throw browserError("redirect_refused");
    if (response.headers?.get?.("content-type")?.split(";", 1)[0]?.trim()?.toLowerCase() !== "application/json") {
      throw browserError("response_invalid");
    }
    const payload = await boundedJson(response,controller.signal);
    check();
    if (response.status >= 200 && response.status < 300 && payload?.ok === true) return payload;
    if (response.status >= 500) throw browserError("remote_ambiguous", true);
    throw browserError(route===EXCHANGE_PATH&&response.status>=400&&response.status<500?browserExchangeRefusalReason(payload):"authorization_refused");
    })();
    try {const result=await Promise.race([operation,expired]);check();return result;}
    catch(error){const failure=expiry||performance.now()>=until?deadlineError():error;noteServerDiagnostic(failure,diagnostic_reason,attempt_id);throw failure;}
    finally{clearTimeout(timer);controller.abort();}
  }
}

export function createWindowsBrowserLauncher({ spawnImpl = spawn } = {}) {
  return Object.freeze({
    async open(url) {
      const exact = authorizationUrl(url);
      await new Promise((resolve, reject) => {
        const child = spawnImpl("rundll32.exe", ["url.dll,FileProtocolHandler", exact], {
          windowsHide: true, stdio: "ignore", shell: false
        });
        child.once("error", reject);
        child.once("spawn", resolve);
      }).catch((cause) => { throw browserError("browser_launch_failed", false, cause); });
    }
  });
}

export async function createWindowsLoopbackReceiver({ expectedState, timeoutMs = 120_000 } = {}) {
  const state = opaque(expectedState, "state");
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) throw browserError("timeout_invalid");
  let settled = false;
  let resolveResult;
  let rejectResult;
  let expectedHost = null;
  const result = new Promise((resolve, reject) => { resolveResult = resolve; rejectResult = reject; });
  result.catch(() => {});
  const server = http.createServer((request, response) => {
    try {
      if (settled) return fixedResponse(response, 409, "This Kovya authorization return is no longer active.");
      const rawUrl = String(request.url ?? "");
      const remote = request.socket?.remoteAddress;
      if (request.method !== "GET" || !["127.0.0.1", "::ffff:127.0.0.1"].includes(remote)
          || request.headers.host !== expectedHost
          || rawUrl.length < 1 || Buffer.byteLength(rawUrl, "utf8") > MAX_CALLBACK_BYTES
          || request.headers["content-length"] !== undefined || request.headers["transfer-encoding"] !== undefined
          || request.headers.forwarded !== undefined || request.headers["x-forwarded-for"] !== undefined
          || request.headers["x-forwarded-host"] !== undefined || request.headers["x-forwarded-proto"] !== undefined) {
        throw browserError("callback_refused");
      }
      const parsed = new URL(rawUrl, "http://127.0.0.1");
      if (parsed.pathname !== WINDOWS_BROWSER_AUTH_CALLBACK_PATH || parsed.hash
          || [...parsed.searchParams.keys()].some((key) => !["code", "state"].includes(key))
          || parsed.searchParams.getAll("code").length !== 1 || parsed.searchParams.getAll("state").length !== 1) {
        throw browserError("callback_refused");
      }
      const code = opaque(parsed.searchParams.get("code"), "code");
      const returnedState = opaque(parsed.searchParams.get("state"), "state");
      if (!same(returnedState, state)) throw browserError("state_mismatch");
      settled = true;
      fixedResponse(response, 200, "Kovya authorization received. You may close this window.");
      server.close();
      resolveResult(Object.freeze({ code }));
    } catch (error) {
      settled = true;
      fixedResponse(response, 400, "Kovya authorization was refused. Return to the installer and try again.");
      server.close();
      rejectResult(error?.kovyaBrowserAuth ? error : browserError("callback_refused", false, error));
    }
  });
  server.on("clientError", () => {
    if (!settled) { settled = true; server.close(); rejectResult(browserError("callback_refused")); }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, resolve);
  }).catch((cause) => { throw browserError("listener_bind_failed", false, cause); });
  const address = server.address();
  if (!address || typeof address === "string" || address.address !== "127.0.0.1" || address.port < 1) {
    server.close(); throw browserError("listener_bind_failed");
  }
  expectedHost = `127.0.0.1:${address.port}`;
  const timer = setTimeout(() => {
    if (!settled) { settled = true; server.close(); rejectResult(browserError("callback_timeout")); }
  }, timeoutMs);
  timer.unref?.();
  result.finally(() => clearTimeout(timer)).catch(() => {});
  return Object.freeze({
    redirectUri: `http://127.0.0.1:${address.port}${WINDOWS_BROWSER_AUTH_CALLBACK_PATH}`,
    result,
    close() {
      if (!settled) { settled = true; server.close(); rejectResult(browserError("callback_cancelled")); }
    }
  });
}

export function createWindowsBrowserAuthorizationClient({
  statePath,
  credentialBridge,
  transport,
  browserLauncher = createWindowsBrowserLauncher(),
  loopbackFactory = createWindowsLoopbackReceiver,
  now = () => new Date().toISOString(),
  randomBytes = nodeRandomBytes,
  callbackTimeoutMs = 45_000,
  clientVersion = "kovya-windows-installer-v2",
  authorizationOrigin,
  installationLockHeld = false,
  accountStateProvider
} = {}) {
  if (!path.isAbsolute(statePath) || !credentialBridge || !transport
      || typeof credentialBridge.write !== "function" || typeof credentialBridge.read !== "function"
      || typeof credentialBridge.delete !== "function" || typeof browserLauncher?.open !== "function"
      || typeof loopbackFactory !== "function") throw browserError("client_configuration_invalid");
  const pinnedAuthorizationOrigin = httpsOrigin(authorizationOrigin);
  const manifestPath=path.join(path.dirname(path.dirname(path.dirname(statePath))),"windows-device-auth.json");
  if(path.resolve(statePath)!==path.join(path.dirname(manifestPath),"state","device-auth","browser-pending.json"))throw browserError("state_path_refused");
  credentialBridge=guardWindowsAuthCredentialBridge(credentialBridge,manifestPath);
  const owned=operation=>(...args)=>withWindowsAuthState(manifestPath,pinnedAuthorizationOrigin,()=>operation(...args),{installationLockHeld,accountStateProvider});
  return Object.freeze({begin:owned(begin),resumeManual:owned(resumeManual),commit:owned(clearPending),rollback:owned(clearPending),clearPending:owned(clearPending),inspect:()=>observeWindowsAuthState(inspect),
    requestAutomaticStart:(body,options)=>transport.start(body,options),requestAutomaticExchange:(body,options)=>transport.exchange(body,options),
    prepareAutomatic:owned(prepareAutomatic),openAutomaticReceiver,acceptAutomaticStart:owned(acceptAutomaticStart),
    prepareAutomaticExchange:owned(prepareAutomaticExchange),acceptAutomaticResult:owned(acceptAutomaticResult),
    prepareManual:owned(prepareManual),acceptManualStart:owned(acceptManualStart),manualPending:owned(manualPending),
    prepareManualExchange:owned(prepareManualExchange),acceptManualResult:owned(acceptManualResult),
    requestManualStart:(body,remainingMs,options)=>transport.start(body,{...options,remainingMs}),
    requestManualExchange:(body,remainingMs,options)=>transport.exchange(body,{...options,remainingMs})});

  // Profile requests own their short local phases; these methods never launch
  // a browser/listener or wait for a person. HTTP is deliberately unwrapped.
  async function prepareManual(input) { return prepareAuthorization(input); }
  async function prepareAutomatic(input) { return prepareAuthorization(input,"loopback_with_manual_fallback"); }
  async function prepareAuthorization({requestId,devicePublicKeyPem,deviceLabel},deliveryMode="manual_code") {
    bindDiagnosticAttempt(requestId);
    if (readJournal(statePath,pinnedAuthorizationOrigin)) throw browserError("transaction_pending");
    const state=entropy(randomBytes,32),verifier=entropy(randomBytes,32),nonce=entropy(randomBytes,32);
    const secretTarget=`${WINDOWS_BROWSER_AUTH_SECRET_PREFIX}${createHash("sha256").update(requestIdValue(requestId)).digest("hex")}`;
    await stageExchangeResult({secret_target:secretTarget},{state,pkce_verifier:verifier,consent_nonce:nonce},null);
    return {request_id:requestIdValue(requestId),state,pkce_challenge:createHash("sha256").update(verifier).digest("base64url"),pkce_method:"S256",
      consent_nonce_hash:`sha256:${createHash("sha256").update(nonce).digest("hex")}`,redirect_uri:null,
      device_public_key_pem:publicKey(devicePublicKeyPem),device_label:label(deviceLabel),client_version:clientVersion,platform:"windows",delivery_mode:deliveryMode};
  }

  async function acceptManualStart(...args) { return acceptAuthorizationStart(...args); }
  async function acceptAutomaticStart(...args) { return acceptAuthorizationStart(...args,true); }
  async function acceptAuthorizationStart(body,started,createdAt,recoveryExpiresAt,automatic=false) {
    validateManualStartTypes(started);
    if(started.ok!==true||started.display.product!=="Kovya"||started.display.platform!=="windows"||started.display.device_label!==body.device_label)
      throw browserError("start_response_invalid");
    // Observe the remote lifetime at acceptance, not at the earlier Work A.
    // Permit at most 5 seconds of positive clock skew; this never extends the
    // original local completion deadline. Larger skew requires a classified retry.
    const accepted=Date.parse(now()),server=Date.parse(started.expires_at),recovery=Date.parse(recoveryExpiresAt);
    if(!Number.isFinite(accepted)||!Number.isFinite(server)||server<=accepted||server-accepted>MANUAL_START_SERVER_TTL_MS+MANUAL_START_CLOCK_SKEW_MS
      ||!Number.isFinite(recovery)||recovery<=accepted)throw browserError("start_expiry_invalid");
    const journal=validateJournal({schema_version:WINDOWS_BROWSER_AUTH_JOURNAL_SCHEMA,transaction_id:started.transaction_id,
      authorization_url:started.authorization_url,expires_at:new Date(Math.min(server,recovery)).toISOString(),request_id:body.request_id,redirect_uri:automatic?loopbackUri(body.redirect_uri):null,...(automatic?{}:{delivery_mode:"manual_code"}),
      device_public_key_pem:body.device_public_key_pem,device_label:body.device_label,
      secret_target:`${WINDOWS_BROWSER_AUTH_SECRET_PREFIX}${createHash("sha256").update(body.request_id).digest("hex")}`,created_at:createdAt},pinnedAuthorizationOrigin);
    bindDiagnosticAttempt(body.request_id,{created_at:journal.created_at,expires_at:journal.expires_at});
    try{writeAtomic(statePath,journal);}catch(error){throw classifyDiagnosticError(error,"state_write_failed");}
    return automatic?{authorization_url:journal.authorization_url,expires_at:journal.expires_at}:manualPending(body.request_id);
  }

  function manualPending(requestId) {
    const journal=readJournal(statePath,pinnedAuthorizationOrigin);
    if(!journal||journal.delivery_mode!=="manual_code"||journal.request_id!==requestId||Date.parse(now())>=Date.parse(journal.expires_at))
      throw browserError("transaction_missing_or_expired");
    return {ok:false,outcome:"manual_required",pending_ref:requestId,authorization_url:journal.authorization_url,expires_at:journal.expires_at};
  }

  async function prepareManualExchange(requestId,supplied,binding) {
    manualPending(requestId);
    const journal=readJournal(statePath,pinnedAuthorizationOrigin),pending=await readProtectedPending(journal);
    try {
      if(!binding||binding.pkce_challenge!==createHash("sha256").update(opaque(pending.pkce_verifier,"pkce_verifier")).digest("base64url")
        ||binding.consent_nonce_hash!==`sha256:${createHash("sha256").update(opaque(pending.consent_nonce,"consent_nonce")).digest("hex")}`
        ||binding.state_sha256!==createHash("sha256").update(opaque(pending.state,"state")).digest("hex"))throw browserError("pending_secret_changed");
      const code=manualCode(Buffer.isBuffer(supplied)?supplied.toString("utf8"):supplied);
      if(pending.exchange_code && !same(manualCode(pending.exchange_code),code))throw browserError("pending_code_mismatch");
      if(pending.exchange_result)return {result:pending.exchange_result};
      // Commit the replay input before the first Exchange, including manual code.
      const bytes=Buffer.from(stableJson({...pending,exchange_code:code}),"utf8");
      try {
        await credentialBridge.write(journal.secret_target,bytes);
        const readback=await credentialBridge.read(journal.secret_target);
        try {if(!readback||!sameBytes(readback,bytes))throw browserError("pending_secret_readback_failed");}finally{readback?.fill(0);}
      } finally {bytes.fill(0);}
      return {attemptHint:new URL(journal.authorization_url).searchParams.get("attempt"),body:{transaction_id:journal.transaction_id,code,pkce_verifier:opaque(pending.pkce_verifier,"pkce_verifier"),request_id:journal.request_id,
        redirect_uri:null,consent_nonce:opaque(pending.consent_nonce,"consent_nonce"),device_public_key_pem:journal.device_public_key_pem,delivery_mode:"manual_code"}};
    } finally {pending.pkce_verifier=null;pending.consent_nonce=null;pending.state=null;pending.exchange_code=null;pending.exchange_result=null;}
  }

  async function acceptManualResult(requestId,result) {
    manualPending(requestId);
    const journal=readJournal(statePath,pinnedAuthorizationOrigin),pending=await readProtectedPending(journal);
    // Preserve the code as well as the result, so local retries keep its binding.
    const bytes=Buffer.from(stableJson({...pending,exchange_result:result}),"utf8");
    try {
      await credentialBridge.write(journal.secret_target,bytes);
      const readback=await credentialBridge.read(journal.secret_target);
      try {if(!readback||!sameBytes(readback,bytes))throw browserError("pending_secret_readback_failed");}finally{readback?.fill(0);}
    } finally {bytes.fill(0);pending.pkce_verifier=null;pending.consent_nonce=null;pending.state=null;pending.exchange_code=null;pending.exchange_result=null;}
  }


  // Listener/browser waiting never holds an account lease or native Work.
  async function openAutomaticReceiver(body) {
    const expectedState=body.state;
    const receiver=await loopbackFactory({expectedState,timeoutMs:callbackTimeoutMs});
    // A receiver can reject before the orchestrator reaches its wait.
    receiver.result.catch(()=>{});
    // The receiver validates returned state and exposes only {code}. Carry the
    // captured expectation after its successful validation, not an observed state.
    const validated=receiver.result.then(value=>{
      exactKeys(value,["code"]);return {code:opaque(value.code,"code"),expected_state:expectedState};
    });validated.catch(()=>{});
    try { return {redirectUri:loopbackUri(receiver.redirectUri),result:validated,
      open:url=>browserLauncher.open(url),close:()=>receiver.close()}; }
    catch(error){receiver.close();throw error;}
  }
  function automaticJournal(requestId,binding) {
    const journal=readJournal(statePath,pinnedAuthorizationOrigin);
    if(!journal||journal.delivery_mode!==undefined||journal.request_id!==requestId||Date.parse(now())>=Date.parse(journal.expires_at)
      ||!binding||journal.redirect_uri!==binding.redirect_uri)throw browserError("transaction_missing_or_expired");
    return journal;
  }
  async function prepareAutomaticExchange(requestId,callback,binding) {
    const journal=automaticJournal(requestId,binding),pending=await readProtectedPending(journal);
    try {
      if(binding.pkce_challenge!==createHash("sha256").update(opaque(pending.pkce_verifier,"pkce_verifier")).digest("base64url")
        ||binding.consent_nonce_hash!==`sha256:${createHash("sha256").update(opaque(pending.consent_nonce,"consent_nonce")).digest("hex")}`
        ||binding.state_sha256!==createHash("sha256").update(opaque(pending.state,"state")).digest("hex")
        ||!callback||typeof callback.expected_state!=="string"||!same(pending.state,callback.expected_state))throw browserError("callback_refused");
      const code=opaque(callback.code,"code");
      if(pending.exchange_code&&!same(pending.exchange_code,code))throw browserError("pending_code_mismatch");
      if(pending.exchange_result)return {result:pending.exchange_result};
      await stageExchangeCode(journal,code);
      return {attemptHint:new URL(journal.authorization_url).searchParams.get("attempt"),body:{transaction_id:journal.transaction_id,
        code,pkce_verifier:opaque(pending.pkce_verifier,"pkce_verifier"),request_id:journal.request_id,redirect_uri:journal.redirect_uri,
        consent_nonce:opaque(pending.consent_nonce,"consent_nonce"),device_public_key_pem:journal.device_public_key_pem}};
    } finally {pending.pkce_verifier=null;pending.consent_nonce=null;pending.state=null;pending.exchange_code=null;pending.exchange_result=null;}
  }
  async function acceptAutomaticResult(requestId,result,binding) {
    const journal=automaticJournal(requestId,binding),pending=await readProtectedPending(journal);
    if(!pending.exchange_code)throw browserError("pending_code_mismatch");
    const bytes=Buffer.from(stableJson({...pending,exchange_result:result}),"utf8");
    try {
      try {
        await credentialBridge.write(journal.secret_target,bytes);
        const readback=await credentialBridge.read(journal.secret_target);
        try {if(!readback||!sameBytes(readback,bytes))throw browserError("pending_secret_readback_failed");}finally{readback?.fill(0);}
      } catch(cause){rethrowInactiveWindowsAuthError(cause);throw browserError("result_stage_ambiguous",true,cause);}
    }
    finally {bytes.fill(0);pending.pkce_verifier=null;pending.consent_nonce=null;pending.state=null;pending.exchange_code=null;pending.exchange_result=null;}
  }

  function inspect() {
    const journal = readJournal(statePath, pinnedAuthorizationOrigin);
    return journal ? Object.freeze({ state: "pending", transaction_id: journal.transaction_id, expires_at: journal.expires_at })
      : Object.freeze({ state: "none" });
  }

  async function begin({ requestId, devicePublicKeyPem, deviceLabel = "Windows device" } = {}) {
    if (readJournal(statePath,pinnedAuthorizationOrigin)) throw browserError("transaction_pending");
    const state = entropy(randomBytes, 32);
    const verifier = entropy(randomBytes, 32);
    const consentNonce = entropy(randomBytes, 32);
    const receiver = await loopbackFactory({ expectedState: state, timeoutMs: callbackTimeoutMs });
    const redirectUri = loopbackUri(receiver.redirectUri);
    const secretTarget = `${WINDOWS_BROWSER_AUTH_SECRET_PREFIX}${createHash("sha256").update(requestIdValue(requestId)).digest("hex")}`;
    const secret = Buffer.from(stableJson({ state, pkce_verifier: verifier, consent_nonce: consentNonce }), "utf8");
    let journal = null;
    try {
      const started = await transport.start({
        request_id: requestIdValue(requestId), state,
        pkce_challenge: createHash("sha256").update(verifier).digest("base64url"), pkce_method: "S256",
        consent_nonce_hash: `sha256:${createHash("sha256").update(consentNonce).digest("hex")}`,
        redirect_uri: redirectUri, device_public_key_pem: publicKey(devicePublicKeyPem),
        device_label: label(deviceLabel), client_version: clientVersion, platform: "windows",
        delivery_mode: "loopback_with_manual_fallback"
      });
      exactKeys(started, ["ok", "authorization_url", "transaction_id", "expires_at", "display"]);
      if (started.ok !== true) throw browserError("start_response_invalid");
      exactKeys(started.display, ["product", "device_label", "platform"]);
      if (started.display.product !== "Kovya" || started.display.platform !== "windows"
          || started.display.device_label !== label(deviceLabel)) throw browserError("start_response_invalid");
      journal = validateJournal({
        schema_version: WINDOWS_BROWSER_AUTH_JOURNAL_SCHEMA, transaction_id: started.transaction_id,
        authorization_url: started.authorization_url, expires_at: started.expires_at,
        request_id: requestId, redirect_uri: redirectUri, device_public_key_pem: devicePublicKeyPem,
        device_label: label(deviceLabel), secret_target: secretTarget, created_at: now()
      }, pinnedAuthorizationOrigin);
      await credentialBridge.write(secretTarget, secret);
      const readback = await credentialBridge.read(secretTarget);
      try { if (!readback || !sameBytes(readback, secret)) throw browserError("pending_secret_readback_failed"); }
      finally { readback?.fill(0); }
      writeAtomic(statePath, journal);
      try { await browserLauncher.open(journal.authorization_url); }
      catch (cause) { receiver.close(); throw browserError("browser_launch_failed", false, cause); }
      let callback;
      try { callback = await receiver.result; }
      catch (error) {
        if (error?.reason === "callback_timeout") {
          await browserLauncher.open(manualUrl(journal.authorization_url));
          return Object.freeze({ ok: false, outcome: "manual_required" });
        }
        throw error;
      }
      await stageExchangeCode(journal, callback.code);
      return exchange(journal, callback.code, { retainOnAmbiguous: true });
    } catch (error) {
      receiver.close();
      rethrowInactiveWindowsAuthError(error);
      if (!error?.ambiguous) await clearPending().catch(() => {});
      throw error;
    } finally { secret.fill(0); }
  }

  async function resumeManual(codeProvider) {
    const journal = readJournal(statePath, pinnedAuthorizationOrigin);
    if (!journal) throw browserError("transaction_missing");
    if (Date.parse(now()) >= Date.parse(journal.expires_at)) { await clearPending(); throw browserError("transaction_expired"); }
    const retained = await readProtectedPending(journal);
    try {
      if (retained.exchange_result) return retained.exchange_result;
      if (retained.exchange_code) return await exchange(journal, opaque(retained.exchange_code, "code"), { retainOnAmbiguous: true });
    } finally { retained.exchange_result = null; retained.exchange_code = null; retained.pkce_verifier = null; retained.consent_nonce = null; retained.state = null; }
    await browserLauncher.open(manualUrl(journal.authorization_url));
    if (typeof codeProvider !== "function") return Object.freeze({ ok: false, outcome: "manual_required" });
    const supplied = await codeProvider();
    const code = Buffer.isBuffer(supplied) ? supplied.toString("utf8") : String(supplied ?? "");
    try { return await exchange(journal, manualCode(code), { retainOnAmbiguous: true }); }
    finally { if (Buffer.isBuffer(supplied)) supplied.fill(0); }
  }

  async function exchange(journal, code, { retainOnAmbiguous }) {
    const pending = await readProtectedPending(journal);
    const body = {
      transaction_id: journal.transaction_id, code, pkce_verifier: opaque(pending.pkce_verifier, "pkce_verifier"),
      request_id: journal.request_id, redirect_uri: journal.redirect_uri,
      consent_nonce: opaque(pending.consent_nonce, "consent_nonce"), device_public_key_pem: journal.device_public_key_pem
    };
    try {
      const result = await transport.exchange(body,{attemptHint:new URL(journal.authorization_url).searchParams.get("attempt")});
      await stageExchangeResult(journal, pending, result);
      return result;
    } catch (error) {
      rethrowInactiveWindowsAuthError(error);
      if (!(retainOnAmbiguous && error?.ambiguous)) await clearPending();
      throw error;
    } finally {
      body.code = null; body.pkce_verifier = null; body.consent_nonce = null;
      pending.exchange_code = null; pending.pkce_verifier = null; pending.consent_nonce = null; pending.state = null;
    }
  }

  async function readProtectedPending(journal) {
    const protectedSecret = await credentialBridge.read(journal.secret_target);
    if (!protectedSecret) throw browserError("pending_secret_missing");
    try { return JSON.parse(protectedSecret.toString("utf8")); }
    catch (cause) { throw browserError("pending_secret_invalid", false, cause); }
    finally { protectedSecret.fill(0); }
  }

  async function stageExchangeCode(journal, code) {
    const pending = await readProtectedPending(journal);
    const bytes = Buffer.from(stableJson({ ...pending, exchange_code: opaque(code, "code") }), "utf8");
    try {
      await credentialBridge.write(journal.secret_target, bytes);
      const readback = await credentialBridge.read(journal.secret_target);
      try { if (!readback || !sameBytes(readback, bytes)) throw browserError("pending_secret_readback_failed"); }
      finally { readback?.fill(0); }
    } finally { bytes.fill(0); pending.pkce_verifier = null; pending.consent_nonce = null; pending.state = null; }
  }

  async function stageExchangeResult(journal, pending, result) {
    const bytes = Buffer.from(stableJson({ ...pending, exchange_code: null, exchange_result: result }), "utf8");
    try {
      try {
        await diagnosticStage("browser_secret_staging",()=>credentialBridge.write(journal.secret_target, bytes));
        const readback = await diagnosticStage("browser_secret_readback",()=>credentialBridge.read(journal.secret_target));
        try { await diagnosticStage("browser_secret_readback",()=>{if (!readback || !sameBytes(readback, bytes)) throw browserError("pending_secret_readback_failed");}); }
        finally { readback?.fill(0); }
      } catch (cause) { rethrowInactiveWindowsAuthError(cause); throw browserError("result_stage_ambiguous", true, cause); }
    } finally { bytes.fill(0); }
  }

  async function clearPending() {
    const journal = readJournal(statePath, pinnedAuthorizationOrigin);
    if (journal) await credentialBridge.delete(journal.secret_target);
    removeFile(statePath);
  }
}

export function validateWindowsBrowserAuthJournal(value,expectedOrigin=null) { return validateJournal(value,expectedOrigin); }
function validateJournal(value, expectedOrigin = null) {
  if (!value || value.schema_version !== WINDOWS_BROWSER_AUTH_JOURNAL_SCHEMA || !TX.test(value.transaction_id)) throw browserError("journal_invalid");
  value.authorization_url = authorizationUrl(value.authorization_url);
  if (expectedOrigin && new URL(value.authorization_url).origin !== expectedOrigin) throw browserError("authorization_origin_mismatch");
  if (new URL(value.authorization_url).searchParams.get("transaction") !== value.transaction_id) throw browserError("journal_invalid");
  if(value.delivery_mode === "manual_code") {
    if(value.redirect_uri !== null)throw browserError("journal_invalid");
  } else {
    if(value.delivery_mode !== undefined)throw browserError("journal_invalid");
    value.redirect_uri = loopbackUri(value.redirect_uri);
  }
  value.request_id = requestIdValue(value.request_id);
  const hint=new URL(value.authorization_url).searchParams.get("attempt");if(hint!==null&&hint.slice(0,64)!==diagnosticAttemptId(value.request_id))throw browserError("journal_invalid");
  value.device_public_key_pem = publicKey(value.device_public_key_pem);
  value.device_label = label(value.device_label);
  if (!value.secret_target?.startsWith(WINDOWS_BROWSER_AUTH_SECRET_PREFIX) || !/^Kovya\.DeviceAuth\/v1\/browser-pending\/[a-f0-9]{64}$/u.test(value.secret_target)) throw browserError("journal_invalid");
  const expires = Date.parse(value.expires_at); const created = Date.parse(value.created_at);
  if (!Number.isFinite(expires) || !Number.isFinite(created) || expires <= created || expires - created > 300_000) throw browserError("journal_invalid");
  return value;
}

function readJournal(target,expectedOrigin) { return readWindowsAuthDocument(target,value=>validateJournal(value,expectedOrigin)); }
function writeAtomic(target, value) {
  assertWindowsAuthEffect(target);
  mkdirSync(path.dirname(target), { recursive: true });
  const temporary = `${target}.tmp-${process.pid}-${nodeRandomBytes(16).toString("hex")}`;
  const bytes = Buffer.from(`${stableJson(value)}\n`, "utf8");
  let descriptor, temporaryOwned=false;
  try { descriptor = openSync(temporary, "wx", 0o600); temporaryOwned=true; writeFileSync(descriptor, bytes); fsyncSync(descriptor); closeSync(descriptor); descriptor = undefined; renameSync(temporary, target); recordWindowsAuthDocument(target,value); }
  finally { bytes.fill(0); if (descriptor !== undefined) closeSync(descriptor); if(temporaryOwned)rmSync(temporary, { force: true }); }
}
function recoverAtomic(target) {
  const directory = path.dirname(target); if (!existsSync(directory)) return;
  for (const name of readdirSync(directory)) { if (name.startsWith(`${path.basename(target)}.tmp-`)) rmSync(path.join(directory, name), { force: true }); }
}
function removeFile(target) { assertWindowsAuthEffect(target); try { const s=statSync(target,{throwIfNoEntry:false}); if(s?.isSymbolicLink()||s&&!s.isFile())throw browserError("state_path_refused"); unlinkSync(target); recordWindowsAuthDocument(target,null); } catch(e){ if(e?.code!=="ENOENT")throw e; } }
function fixedResponse(response, status, text) { response.writeHead(status,{"content-type":"text/html; charset=utf-8","cache-control":"no-store","content-security-policy":"default-src 'none'; frame-ancestors 'none'","referrer-policy":"no-referrer","x-content-type-options":"nosniff","x-frame-options":"DENY"}); response.end(`<!doctype html><meta charset="utf-8"><title>Kovya</title><p>${text}</p>`); }
async function boundedJson(response,signal) {
  const declared=Number(response.headers?.get?.("content-length"));
  if(Number.isFinite(declared)&&declared>MAX_JSON_BYTES)throw browserError("response_invalid");
  const reader=response.body?.getReader?.();if(!reader)throw browserError("response_invalid");
  const cancel=()=>{reader.cancel().catch(()=>{});};
  signal?.addEventListener("abort",cancel,{once:true});
  const chunks=[];let total=0;
  try{
    while(true){const{done,value}=await reader.read();if(done)break;total+=value.byteLength;if(total>MAX_JSON_BYTES){await reader.cancel().catch(()=>{});throw browserError("response_invalid");}chunks.push(Buffer.from(value));}
    const bytes=Buffer.concat(chunks);try{return JSON.parse(bytes.toString("utf8"));}catch{throw browserError("response_invalid");}finally{bytes.fill(0);}
  }finally{signal?.removeEventListener("abort",cancel);for(const chunk of chunks)chunk.fill(0);reader.releaseLock?.();}
}
function diagnosticHintClock(hint){const created=Number.parseInt(hint.slice(64,80),16),expires=Number.parseInt(hint.slice(80,96),16);if(!Number.isSafeInteger(created)||!Number.isSafeInteger(expires)||created<0||expires<created||expires>8640000000000000)return {};return {attempt_created_at:new Date(created).toISOString(),expires_at:new Date(expires).toISOString(),transaction_age_ms:Math.max(0,Date.now()-created)};}
function httpsOrigin(value) { const u=new URL(value); if(u.protocol!=="https:"||u.username||u.password||u.pathname!=="/"||u.search||u.hash)throw browserError("origin_invalid"); return u.origin; }
function authorizationUrl(value) { let u;try{u=new URL(value);}catch{throw browserError("authorization_url_invalid");} if(u.protocol!=="https:"||u.username||u.password||u.hash||u.pathname!=="/device-authorization"||[...u.searchParams.keys()].some(k=>!["transaction","attempt"].includes(k))||u.searchParams.getAll("attempt").length>1||u.searchParams.has("attempt")&&!/^[a-f0-9]{160}(?![\s\S])/u.test(u.searchParams.get("attempt"))||u.searchParams.getAll("transaction").length!==1||!TX.test(u.searchParams.get("transaction")))throw browserError("authorization_url_invalid"); return u.toString(); }
function manualUrl(value) { const original=new URL(authorizationUrl(value)); const u=new URL("/device-authorization/manual",original.origin); u.searchParams.set("transaction",original.searchParams.get("transaction")); if(original.searchParams.has("attempt"))u.searchParams.set("attempt",original.searchParams.get("attempt")); return u.toString(); }
function loopbackUri(value) { const u=new URL(value); if(u.protocol!=="http:"||u.hostname!=="127.0.0.1"||!u.port||u.pathname!==WINDOWS_BROWSER_AUTH_CALLBACK_PATH||u.search||u.hash||u.username||u.password)throw browserError("redirect_uri_invalid"); return u.toString(); }
function publicKey(value) { const s=String(value??""); if(s.length<100||s.length>4096||!s.startsWith("-----BEGIN PUBLIC KEY-----\n")||!s.endsWith("-----END PUBLIC KEY-----\n"))throw browserError("public_key_invalid"); return s; }
function requestIdValue(value) { const s=String(value??""); if(s.length<16||s.length>160||/[\0\r\n]/u.test(s))throw browserError("request_id_invalid"); return s; }
function label(value) { const s=String(value??""); if(s.length<1||s.length>128||/[\0\r\n]/u.test(s))throw browserError("device_label_invalid"); return s; }
function opaque(value, field) { const s=String(value??""); if(!OPAQUE.test(s))throw browserError(`${field}_invalid`); return s; }
function manualCode(value) { const s=String(value??"").trim().replaceAll("-","").toLowerCase(); if(!/^[a-f0-9]{32}$/u.test(s))throw browserError("manual_code_invalid"); return s; }
function entropy(random, size) { const value=Buffer.from(random(size)); if(value.length!==size)throw browserError("entropy_invalid"); try{return value.toString("base64url");}finally{value.fill(0);} }
function same(a,b) { const x=Buffer.from(a);const y=Buffer.from(b);try{return x.length===y.length&&timingSafeEqual(x,y);}finally{x.fill(0);y.fill(0);} }
function sameBytes(a,b) { return a.length===b.length&&timingSafeEqual(a,b); }
// Validate the entire server schema before URL/date/regex coercion or publication.
function validateManualStartTypes(value) {
  exactKeys(value,["ok","authorization_url","transaction_id","expires_at","display"]);
  if(Object.getPrototypeOf(value)!==Object.prototype)throw browserError("response_invalid");
  const fields={ok:["boolean","start_response_invalid"],authorization_url:["string","authorization_url_invalid"],
    transaction_id:["string","journal_invalid"],expires_at:["string","start_expiry_invalid"]};
  for(const [key,[type,reason]] of Object.entries(fields))if(typeof value[key]!==type)throw browserError(reason);
  exactKeys(value.display,["product","device_label","platform"]);
  if(Object.getPrototypeOf(value.display)!==Object.prototype)throw browserError("response_invalid");
  for(const key of ["product","device_label","platform"])if(typeof value.display[key]!=="string")throw browserError("start_response_invalid");
}
function exactKeys(value, keys) { if(!value||typeof value!=="object"||Array.isArray(value))throw browserError("response_invalid"); const actual=Object.keys(value).sort();const expected=[...keys].sort();if(actual.length!==expected.length||actual.some((key,index)=>key!==expected[index]))throw browserError("response_invalid"); }
function browserError(reason, ambiguous=false, cause=null) { const e=new Error("Kovya browser authorization failed.",{cause});e.code="KOVYA_BROWSER_AUTH_FAILED";e.reason=reason;e.ambiguous=ambiguous;e.kovyaBrowserAuth=true;return propagateDiagnosticFailure(cause,e); }
