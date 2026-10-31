import {runTerminalOperation} from "./terminal-operation.mjs";
import {finishStage} from "./diagnostic-events.mjs";
import {readFileSync} from "node:fs";
import {diagnosticFailure,diagnosticRecovery} from "./diagnostic-events.mjs";
import path from "node:path";
import { requireHost } from "./host-events.mjs";
import { createWindowsManagedCredentialManagerBridge, createWindowsDeviceAuthManager, loadWindowsAuthManifestSync, withWindowsAuthState } from "../claude-code/client/kovya-windows-device-auth.mjs";
import { createWindowsBrowserAuthorizationClient, createWindowsBrowserAuthorizationTransport } from "../claude-code/client/kovya-windows-browser-auth.mjs";
import {profileWorkConfigured,borrowProfileWorkRequest} from "../claude-code/client/kovya-profile-process.mjs";
import {runObservedProfileWorkRequest,diagnosticReceipt} from "./diagnostic-lifecycle.mjs";
import {createKovyaWindowsProfileAccountStateProvider} from "../claude-code/client/kovya-windows-broker-native.mjs";

export function validatePluginRelease(config) {
  if (!config || Object.keys(config).sort().join(",") !== "authorization_origin,schema_version"
    || config.schema_version !== "kovya.plugin-release.v1") throw new Error("release_configuration_required");
  const origin = new URL(config.authorization_origin);
  if (origin.protocol !== "https:" || origin.username || origin.password || origin.pathname !== "/"
    || origin.search || origin.hash) throw new Error("release_configuration_invalid");
  return Object.freeze({schema_version:config.schema_version,authorization_origin:origin.origin});
}

// The admitted payload owns this input; its descriptor pins these bytes.
// moduleUrl is a test seam, never a prompt, environment or CLI override.
export function loadRuntimeRelease(moduleUrl=import.meta.url) {
  return validatePluginRelease(JSON.parse(readFileSync(new URL("./release-config.json",moduleUrl),"utf8")));
}

export function createWindowsPluginManager({layout,release},{
  bridgeFactory=createWindowsManagedCredentialManagerBridge,
  browserAuthenticatorFactory=createWindowsBrowserAuthorizationClient,
  accountStateProvider
}={}) {
  return createWindowsDeviceAuthManager({manifestPath:layout.authManifest,
    apiBaseUrl:release.authorization_origin,audience:release.authorization_origin,accountStateProvider,
    adaptersFactory:()=>{
      const bridge=bridgeFactory();
      const browserAuthenticator=browserAuthenticatorFactory({
        statePath:path.join(layout.home,"state","device-auth","browser-pending.json"),credentialBridge:bridge,
        transport:createWindowsBrowserAuthorizationTransport({apiBaseUrl:release.authorization_origin,timeoutMs:profileWorkConfigured()?30000:10000}),
        authorizationOrigin:release.authorization_origin,accountStateProvider
      });
      return {bridge,browserAuthenticator};
    }});
}

const messages = Object.freeze({
  release_configuration_required:"This preview is not configured for sign-in. Obtain the configured Kovya release through your harness marketplace or npm.",
  release_account_mismatch:"This release does not match the connected account's service. Use the matching release; the account was not changed.",
  platform_unavailable:"Kovya sign-in is not yet available for this platform in this preview.",
  sign_in_required:"Connect Kovya to sign in and authorize access in your browser.",
  session_present:"A Kovya account is connected on this computer. Saving and recall still require runtime and harness checks.",
  connected:"Kovya sign-in completed. Saving and recall still require runtime and harness checks.",
  signed_out:"Kovya is signed out on this computer. The shared runtime remains installed.",
  pending:"A previous sign-in needs attention. Kovya could not finish. I will diagnose the problem before proposing a repair.",
  ambiguous:"The sign-in outcome is unconfirmed. Kovya could not finish. I will diagnose the problem before proposing a repair.",
  manual_required:"Automatic browser return did not complete. Recovery requires the protected manual-code flow, which this preview does not yet expose.",
  approval_required:"Open the approval link and finish within 5 minutes (or sooner at the displayed expiry). After approving, supply the displayed code through the protected Finish input.",
  cancelled:"Sign-in was cancelled. Use Kovya status to check the shared account.",
  failed:"Kovya could not confirm sign-in. Kovya could not finish. I will diagnose the problem before proposing a repair."
});

// One account owner and existing installation lock, regardless of invoking harness.
// Never return manager results: they may contain access credentials or account IDs.
export function createPluginOnboarding({layout,release,platform=process.platform,managerFactory=createWindowsPluginManager,accountStateProvider}) {
  let profileStatusProvider=accountStateProvider;
  return Object.freeze({async run(operation,host,{inputProvider=null}={}) {
    return runTerminalOperation({operation,host},async()=>{
    const statusDeadline=performance.now()+1000;
    const runProfileWorkRequest=async(remaining,work)=>{
      const value=await runObservedProfileWorkRequest(remaining,work,{operation,host});
      const diagnostics=diagnosticReceipt(value);return diagnostics?{...value,diagnostics}:value;
    };
    requireHost(host);
    if (!["status","connect","repair","finish","logout"].includes(operation)) throw new Error("onboarding_operation_invalid");
    const result = (state,manifest) => ({ok:["session_present","connected","approval_required","signed_out"].includes(state),state,
      ...(manifest ? {memory_service:manifest.memory_api_base_url ?? "same as authority"} : {}),
      account:state === "connected" ? "authenticated" : state === "session_present" ? "local_session_present" : state === "signed_out" ? "signed_out" : "unconfirmed",
      runtime:"unverified",saving:"unverified",recall:"unverified",message:profileWorkConfigured()&&["pending","ambiguous","manual_required"].includes(state)
        ? "Kovya could not finish. I will diagnose the problem before proposing a repair."
        : messages[state]});
    if (platform !== "win32") return result("platform_unavailable");
    let config;
    try {config=validatePluginRelease(release);} catch {return result("release_configuration_required");}
    let manager;
    const logout = async owner => {
      const auth=await owner.logout();
      if(auth?.ok!==true || auth.outcome!=="signed_out"
          || !["revoked","not_applicable","refused","unknown"].includes(auth.remote_status)) return result("failed");
      const snapshot=owner.inspect();
      if(snapshot.state!=="sign_in")return result("failed");
      return {...result("signed_out"),remote_revocation:auth.remote_status,
        ...(["refused","unknown"].includes(auth.remote_status)
          ? {message:"Kovya is signed out on this computer. Server-side revocation was not confirmed. The shared runtime remains installed."} : {})};
    };
    try {
      if(operation==="logout" && profileWorkConfigured()) {
        profileStatusProvider ??= createKovyaWindowsProfileAccountStateProvider();
        return await runProfileWorkRequest(()=>statusDeadline-performance.now(),()=>{
          const request=borrowProfileWorkRequest();
          return withWindowsAuthState(layout.authManifest,config.authorization_origin,async()=>{
            request.remainingMs();
            const logoutManager=managerFactory({layout,release:config},{accountStateProvider:profileStatusProvider});
            try {
              request.remainingMs();
              const response=await logout(logoutManager);
              request.remainingMs();
              return response;
            } finally {logoutManager?.shutdown?.();}
          },{accountStateProvider:profileStatusProvider,remainingMs:request.remainingMs});
        });
      }
      if(["connect","finish"].includes(operation) && profileWorkConfigured()) {
        profileStatusProvider ??= createKovyaWindowsProfileAccountStateProvider({prepared:true});
        // Each local phase owns and ends its existing short Work ticket.
        // Only successful checked cleanup permits the intervening HTTP or B.
        let lastDiagnostics;
        const localPhase=async(_name,work,networkObservation)=>{
          const value=await runObservedProfileWorkRequest(()=>1000,()=>work(borrowProfileWorkRequest().remainingMs),{operation,host,phase:_name,networkObservation});
          lastDiagnostics=diagnosticReceipt(value);return value;
        };
        const response=await (async()=>{
          let input,profileManager;
          try {
            const readInput=async remainingMs=>{
              if(typeof inputProvider!=="function")throw new Error("protected_input_required");
              input=await inputProvider(remainingMs);
              remainingMs();
              if(!input||Object.keys(input).sort().join(",")!=="code,pending_ref"||!Buffer.isBuffer(input.code)
                ||typeof input.pending_ref!=="string"||!/^authreq_[a-f0-9]{36}$/u.test(input.pending_ref)||input.code.length>64)
                throw new Error("protected_input_invalid");
              return input;
            };
            profileManager=managerFactory({layout,release:config},{accountStateProvider:profileStatusProvider});
            const auth=operation==="connect"?await profileManager.startProfileAutomatic({localPhase})
              :await profileManager.finishProfileManual({localPhase,inputProvider:readInput});
            if(operation==="connect"&&auth?.outcome==="manual_required"){
              process.stderr.write("Kovya: waiting for authorization. Finish within 5 minutes; use the displayed expiry if sooner.\n");
              return {...result("approval_required"),authorization_url:auth.authorization_url,pending_ref:auth.pending_ref,expires_at:auth.expires_at};
            }
            if(auth?.ok===true)return result(auth.outcome==="session_present"?"session_present":"connected",auth.manifest);
            return {...result(["ambiguous","sign_in_required","cancelled"].includes(auth?.outcome)?auth.outcome:"pending"),...diagnosticRecovery({phase:auth?.phase,recovery_expires_at:auth?.recovery_expires_at,created_at:auth?.attempt_created_at})};
          } finally {input?.code?.fill?.(0);await finishStage("worker_cleanup",()=>profileManager?.shutdown?.());}
        })();
        return lastDiagnostics?{...response,diagnostics:lastDiagnostics}:response;
      }
      if(operation==="finish")return result("platform_unavailable");
      if(operation==="status" && profileWorkConfigured()) {
        profileStatusProvider ??= createKovyaWindowsProfileAccountStateProvider();
        return await runProfileWorkRequest(()=>statusDeadline-performance.now(),()=>
          withWindowsAuthState(layout.authManifest,config.authorization_origin,()=>{
            // A delayed provider must not create or inspect a manager after the
            // public request has expired. Keep its lifetime inside actual work.
            borrowProfileWorkRequest().remainingMs();
            const statusManager=managerFactory({layout,release:config},{accountStateProvider:profileStatusProvider});
            try {
              borrowProfileWorkRequest().remainingMs();
              const snapshot=statusManager.inspect();
              borrowProfileWorkRequest().remainingMs();
              return {...result(snapshot.state === "existing_session" ? "session_present"
                : snapshot.state === "pending" ? "pending" : "sign_in_required",snapshot.state === "existing_session" ? snapshot.manifest : undefined),
                ...(snapshot.state==="pending"?diagnosticRecovery({phase:snapshot.phase,recovery_expires_at:snapshot.recovery_expires_at,created_at:snapshot.attempt_created_at}):{})};
            } finally {statusManager?.shutdown?.();}
          },{accountStateProvider:profileStatusProvider}));
      }
      if(operation==="repair" && profileWorkConfigured()) {
        profileStatusProvider ??= createKovyaWindowsProfileAccountStateProvider();
        return await runProfileWorkRequest(()=>statusDeadline-performance.now(),()=>{
          const request=borrowProfileWorkRequest();
          return withWindowsAuthState(layout.authManifest,config.authorization_origin,async()=>{
            request.remainingMs();
            const repairManager=managerFactory({layout,release:config},{accountStateProvider:profileStatusProvider});
            try {
              request.remainingMs();
              if(typeof repairManager?.repairLocal!=="function")throw new Error("local_repair_required");
              const auth=await repairManager.repairLocal();
              request.remainingMs();
              if(auth?.ok!==true)return {...result(["pending","manual_required","sign_in_required"].includes(auth?.outcome)?auth.outcome:"failed"),...diagnosticRecovery({phase:auth?.phase,recovery_expires_at:auth?.recovery_expires_at,created_at:auth?.attempt_created_at})};
              const snapshot=repairManager.inspect();
              request.remainingMs();
              return result(snapshot.state==="existing_session"?"session_present":snapshot.state==="pending"?"pending":"sign_in_required",
                snapshot.state==="existing_session"?snapshot.manifest:undefined);
            } finally {repairManager?.shutdown?.();}
          },{accountStateProvider:profileStatusProvider,remainingMs:request.remainingMs});
        });
      }
      manager = managerFactory({layout,release:config});
      if(operation==="logout")return await logout(manager);
      if (operation === "status") {
        const snapshot = manager.inspect();
        return {...result(snapshot.state === "existing_session" ? "session_present"
          : snapshot.state === "pending" ? "pending" : "sign_in_required",snapshot.state === "existing_session" ? snapshot.manifest : undefined),
          ...(snapshot.state==="pending"?diagnosticRecovery({phase:snapshot.phase,recovery_expires_at:snapshot.recovery_expires_at,created_at:snapshot.attempt_created_at}):{})};
      }
      const auth = operation === "connect"
        ? await manager.install({deviceLabel:"Kovya coding harness"})
        : await manager.retryPending();
      if (auth?.ok === true) {
        // A successful no-op repair is not evidence of an authenticated account.
        const snapshot=manager.inspect();
        return result(snapshot.state === "existing_session"
          ? (operation === "connect" ? "connected" : "session_present") : "sign_in_required",snapshot.state === "existing_session" ? snapshot.manifest : undefined);
      }
      return result(["ambiguous","manual_required","sign_in_required"].includes(auth?.outcome) ? auth.outcome : "failed");
    } catch (error) {
      return {...result(error?.code === "release_account_mismatch" ? "release_account_mismatch" : error?.ambiguous === true || error?.code === "refresh_ambiguous" ? "ambiguous"
        : error?.reason === "callback_cancelled" ? "cancelled" : "failed"),...diagnosticFailure(error),
        ...(diagnosticReceipt(error)?{diagnostics:diagnosticReceipt(error)}:{})};
    } finally {await finishStage("worker_cleanup",()=>manager?.shutdown?.());}
    });
  }});
}
