import {diagnosticCheckpoint} from "../../plugin/diagnostic-events.mjs";
import {spawnNative} from "./kovya-managed-process.mjs";
import {AsyncLocalStorage} from "node:async_hooks";
import {borrowProfileWorkRequest,profileWorkConfigured,spawnProfileNative,observeProfileWorkConsumer,createProfileAccountAdoption,residentProfileStartup} from "./kovya-profile-process.mjs";
import {verifyNativeBinding,verifyNativeBindingAsync} from "./kovya-native-binding.mjs";
import { spawn } from "node:child_process";
import { createHash, createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { TextDecoder } from "node:util";
import { createInterface } from "node:readline";
import { isMainThread } from "node:worker_threads";

import { stableJson } from "../../../packages/memory-gateway/src/canonical-json.mjs";

export const WINDOWS_CREDENTIAL_WITNESS_SCHEMA = "kovya.credential-store-witness.v1";
const WITNESS_DOCUMENT_KEYS = "browser_journal,device_journal,device_journal_previous,manifest,manifest_previous";
function witnessBudget(remainingMs) {
  const budget=typeof remainingMs==="function" ? Math.floor(Math.min(1000,remainingMs())) : NaN;
  if(!Number.isFinite(budget)||budget<1)throw nativeError("account_state_conflict");
  return budget;
}
function credentialWitness(value) {
  const hex=v=>typeof v==="string"&&/^[a-f0-9]{64}$/.test(v);
  if(!value||Object.keys(value).sort().join(",")!=="credentials,documents,home_sha256,schema_version"
      ||value.schema_version!==WINDOWS_CREDENTIAL_WITNESS_SCHEMA||!hex(value.home_sha256)
      ||!value.documents||Object.keys(value.documents).sort().join(",")!==WITNESS_DOCUMENT_KEYS
      ||!value.credentials||Array.isArray(value.credentials)||Object.keys(value.credentials).length>256)
    throw nativeError("account_state_conflict");
  for(const digest of Object.values(value.documents))if(digest!==null&&!hex(digest))throw nativeError("account_state_conflict");
  for(const [target,digest] of Object.entries(value.credentials)) {
    if(target.length>512||!target.startsWith("Kovya.DeviceAuth/v1/")||target.includes("\\")||target.includes("..")||/[\r\n\0]/.test(target)
        ||(digest!==null&&!hex(digest)))throw nativeError("account_state_conflict");
  }
  return Object.freeze({...value,documents:Object.freeze({...value.documents}),credentials:Object.freeze({...value.credentials})});
}
function credentialWitnessBytes(value) {
  const bytes=Buffer.from(JSON.stringify(credentialWitness(value)));
  if(bytes.length>250000){bytes.fill(0);throw nativeError("account_state_conflict");}return bytes;
}
function credentialWitnessResponse(bytes,kind) {
  const response=JSON.parse(STRICT_UTF8.decode(bytes));
  if(response?.ok===false&&Object.keys(response).sort().join(",")==="error,ok"&&response.error==="account_state_conflict")throw nativeError("account_state_conflict");
  if(response?.ok!==true||Object.keys(response).sort().join(",")!==(kind===14?"ok,witness":"ok"))throw nativeError("broker_native_protocol_refused");
  return kind===14?credentialWitness(response.witness):true;
}

const IDENTITY_TAG = "KOVYA_NATIVE_IDENTITY_V2";
const CONFIG_TAG = "KOVYA_NATIVE_CONFIG_V1";
const PRIVATE_READY_TAG = "KOVYA_NATIVE_PRIVATE_READY_V1";
const PRIVATE_PREAMBLE_TAG = "KOVYA_NATIVE_PRIVATE_V1";
const PRIVATE_ACK_TAG = "KOVYA_NATIVE_PRIVATE_ACK_V1";
const READY_TAG = "KOVYA_NATIVE_READY_V1";
const ENDPOINT_TAG = "KOVYA_NATIVE_ENDPOINT_V1";
const TERMINATION_ENDPOINT_TAG = "KOVYA_NATIVE_TERMINATION_ENDPOINT_V1";
const TERMINATION_ACK_TAG = "KOVYA_NATIVE_TERMINATED_V1";
const ABSENT_TAG = "KOVYA_NATIVE_ABSENT_V1";
const FIXED_ROOT_ABSENCE_TAG = "KOVYA_NATIVE_FIXED_ROOT_ABSENCE_V1";
const FIXED_ROOT_ABSENT_TAG = "KOVYA_NATIVE_FIXED_ROOT_ABSENT_V1";
const PUBLIC_PIPE_PREFIX = "kovya-memory-v1-";
const PRIVATE_PIPE_PREFIX = "kovya-memory-private-v1-";
const MAXIMUM_CONTROL_LINE_BYTES = 2048;
const MAXIMUM_FRAME_BYTES = 1024 * 1024;
const MAXIMUM_AUXILIARY_OUTPUT_BYTES = 2048;
const MINIMUM_TIMEOUT_MILLISECONDS = 50;
const MAXIMUM_TIMEOUT_MILLISECONDS = 15000;
const MAXIMUM_STARTUP_TIMEOUT_MILLISECONDS = 5000;
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });
// A process exit may precede asynchronous native disposal. Keep the observation
// from creation, including errors delivered between exit and close.
const nativeHostClosures = new WeakMap();
function observeNativeHostClose(child) {
  let failure;
  const onError = error => { failure ??= error; };
  child.on("error", onError);
  const closed = new Promise((resolve, reject) => child.once("close", (code, signal) => {
    child.off("error", onError);
    if (failure) reject(failure); else resolve({code, signal: signal ?? null});
  }));
  closed.catch(() => {});
  nativeHostClosures.set(child, closed);
  return closed;
}

const ERROR_MESSAGES = Object.freeze({
  broker_deadline_refused: "Kovya broker startup deadline elapsed.",
  profile_work_owner_required: "Kovya broker requires the current work owner.",
  account_state_conflict: "Kovya account state changed or could not be verified.",
  broker_native_path_invalid: "Kovya native broker path is invalid.",
  broker_native_spawn_failed: "Kovya native broker could not start.",
  broker_native_handshake_timeout: "Kovya native broker handshake timed out.",
  broker_native_protocol_refused: "Kovya native broker protocol was refused.",
  broker_native_identity_refused: "Kovya native broker identity was refused.",
  broker_native_peer_refused: "Kovya native broker peer was refused.",
  broker_native_transport_failed: "Kovya native broker transport failed.",
  broker_native_private_transport_failed: "Kovya native broker private transport failed.",
  broker_native_output_refused: "Kovya native broker output was refused.",
  broker_native_exited: "Kovya native broker exited unexpectedly.",
  broker_native_frame_invalid: "Kovya native broker frame is invalid.",
  broker_native_exchange_timeout: "Kovya native broker exchange timed out.",
  broker_native_stop_timeout: "Kovya native broker did not stop in time.",
  broker_native_termination_refused: "Kovya native broker termination was refused.",
  broker_native_absence_unproven: "Kovya native broker absence could not be proven."
});

export class KovyaWindowsBrokerNativeError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES.broker_native_transport_failed);
    this.name = "KovyaWindowsBrokerNativeError";
    this.code = Object.hasOwn(ERROR_MESSAGES, code) ? code : "broker_native_transport_failed";
  }
}

export function resolveKovyaWindowsBrokerNativePath({ moduleUrl = import.meta.url } = {}) {
  let resolved;
  try {
    resolved = fileURLToPath(new URL("./kovya_windows_broker_native.exe", moduleUrl));
  } catch {
    throw nativeError("broker_native_path_invalid");
  }
  if (!path.isAbsolute(resolved) || path.basename(resolved).toLowerCase() !== "kovya_windows_broker_native.exe") {
    throw nativeError("broker_native_path_invalid");
  }
  return path.normalize(resolved);
}

// The callback consumes this immutable, base64-encoded snapshot. It must await
// its complete transaction. The helper keeps handle identities private and
// transfers guard ownership into this actual process before invoking work.
export async function withKovyaWindowsAccountState(work, {
  executablePath = resolveKovyaWindowsBrokerNativePath(), timeoutMs = 5000, env = process.env,
  installationLockHeld = false, expectedHome = null
} = {}) {
  if (!isMainThread || typeof work !== "function" || process.platform !== "win32") throw nativeError("broker_native_protocol_refused");
  const timeout=requireTimeout(timeoutMs,MAXIMUM_STARTUP_TIMEOUT_MILLISECONDS);
  const nativePath=requireExecutablePath(executablePath);
  const binding=await verifyNativeBindingAsync(nativePath,["managed_runtime","legacy_layout"]);
  if(typeof installationLockHeld!=="boolean") throw nativeError("broker_native_protocol_refused");
  if(expectedHome!==null && path.resolve(expectedHome).toLowerCase()!==path.resolve(binding.home).toLowerCase()) throw nativeError("broker_native_identity_refused");
  if(binding.expected_role==="managed_runtime")return withManagedAccountSession(work,{nativePath,binding,env,timeout,installationLockHeld});
  const ownershipMode=installationLockHeld?"external":"native";
  const child=spawnNative(nativePath,[installationLockHeld?"account-state-external":"account-state",String(process.pid)],nativeSpawnOptions(nativePath,env));
  let phase="identity",discoveryBytes=0,privateBytes=0,releaseToken=null,refused=false,released=false,begun=false;
  let socket=null,privateReader=null,responseKey=null,invocation=null,resolveReady,rejectReady,resolveRelease;
  const ready=new Promise((resolve,reject)=>{resolveReady=resolve;rejectReady=reject;});
  const release=new Promise(resolve=>{resolveRelease=resolve;});
  const closed=new Promise(resolve=>child.once("close",(code,signal)=>resolve({code,signal})));
  // Trusted main-thread execution is required; process/handle-table tampering
  // is distinct from the filesystem-writer and connected-participant boundaries.
  const failStop=()=>process.exit(74);
  const failBeforeOrAfterBegin=()=>{
    if(begun && !released && !refused) failStop();
    if(!released && !refused) rejectReady(nativeError("broker_native_exited"));
  };
  const discovery=createInterface({input:child.stdout,crlfDelay:Infinity});
  child.stderr.on("data",failStop);
  child.stdout.on("data",chunk=>{
    discoveryBytes+=chunk.length;
    if(discoveryBytes>4096 || chunk.some(value=>value>127 || value===13)) failStop();
  });
  child.once("error",()=>rejectReady(nativeError("broker_native_spawn_failed")));
  child.once("close",failBeforeOrAfterBegin);
  function receivePrivateLine(line){
    try {
      const frame=/^KOVYA_ACCOUNT_FRAME_V1\t([01])\t(STATE|REFUSED|RELEASED)\t([^\t\r\n]*)\t([a-f0-9]{64})$/.exec(line);
      if(!frame || !responseKey) failStop();
      const [,sequence,kind,payload,tagHex]=frame;
      const expected=createHmac("sha256",responseKey).update(`KOVYA_ACCOUNT_FRAME_V1\nhelper-to-caller\n${invocation}\n${sequence}\n${kind}\n${payload}`,"ascii").digest();
      const received=Buffer.from(tagHex,"hex");
      let authenticated;
      try {authenticated=timingSafeEqual(expected,received);} finally {expected.fill(0);received.fill(0);}
      if(!authenticated) failStop();
      if(phase==="snapshot" && sequence==="0"){
        if(kind==="REFUSED" && payload===""){
          refused=true;phase="refused";rejectReady(nativeError("broker_native_protocol_refused"));return;
        }
        if(kind!=="STATE") failStop();
        const response=JSON.parse(payload);
        if(Object.keys(response).sort().join(",")!=="documents,ownership_mode,release_token" || response.ownership_mode!==ownershipMode || !/^[a-f0-9]{64}$/.test(response.release_token)) failStop();
        const keys=["browser_journal","device_journal","device_journal_previous","manifest","manifest_previous"];
        if(!response.documents || Object.keys(response.documents).sort().join(",")!==keys.join(",")) failStop();
        for(const value of Object.values(response.documents)){
          if(value===null) continue;
          if(typeof value!=="string" || value.length>174764) failStop();
          const decoded=Buffer.from(value,"base64");
          try {if(decoded.length>131072 || decoded.toString("base64")!==value) failStop();} finally {decoded.fill(0);}
        }
        releaseToken=response.release_token;phase="held";resolveReady(Object.freeze({...response.documents}));return;
      }
      if(phase!=="releasing" || sequence!=="1" || kind!=="RELEASED" || payload!=="") failStop();
      released=true;phase="released";resolveRelease();
    } catch {failStop();}
  }
  discovery.on("line",line=>{
    try {
      if(!begun && !refused && line==="KOVYA_ACCOUNT_REFUSED_V1"){
        refused=true;phase="refused";rejectReady(nativeError("broker_native_protocol_refused"));return;
      }
      if(phase==="identity"){
        const identity=parseIdentityLine(line,binding.expected_role);
        if(identity.host_process.pid!==child.pid || identity.parent_process.pid!==process.pid) failStop();
        phase="discovery";return;
      }
      if(phase!=="discovery") failStop();
      const match=/^KOVYA_ACCOUNT_PEER_V2\t([a-f0-9]{64})\t([a-f0-9]{64})$/.exec(line);
      if(!match) failStop();
      invocation=match[1];responseKey=Buffer.from(match[2],"hex");phase="connecting";
      socket=net.createConnection(`\\\\.\\pipe\\kovya-account-private-v1-${invocation}`);
      // One reader owns snapshot and release ACK; no handoff or reconnect.
      socket.on("error",failBeforeOrAfterBegin);
      socket.on("end",failBeforeOrAfterBegin);
      socket.on("close",failBeforeOrAfterBegin);
      socket.on("data",chunk=>{
        privateBytes+=chunk.length;
        if(privateBytes>1024*1024+4096 || chunk.some(value=>value>127 || value===13)) failStop();
      });
      privateReader=createInterface({input:socket,crlfDelay:Infinity});
      privateReader.on("line",receivePrivateLine);
      socket.once("connect",()=>{
        // Even a partial BEGIN write may allow native transfer before a snapshot.
        begun=true;phase="snapshot";
        socket.write(`KOVYA_ACCOUNT_BEGIN_V2\t${invocation}\t${ownershipMode}\n`,error=>{if(error) failStop();});
      });
    } catch {failStop();}
  });
  try {
    let snapshot;
    try {snapshot=await withTimeout(ready,timeout,"broker_native_handshake_timeout");}
    catch(error){
      if(begun && !refused) failStop();
      if(!refused) terminateChild(child);
      throw error;
    }
    try {return await work(snapshot);}
    finally {
      phase="releasing";
      socket.write(`KOVYA_ACCOUNT_RELEASE_V1\t${releaseToken}\n`,error=>{if(error) failStop();});
      try {
        await withTimeout(release,timeout,"broker_native_stop_timeout");
        const exit=await withTimeout(closed,timeout,"broker_native_stop_timeout");
        if(exit.code!==0 || exit.signal) failStop();
      } catch {failStop();}
    }
  } finally {discovery.close();privateReader?.close();socket?.destroy();responseKey?.fill(0);responseKey=null;}
}

// One private binary reader owns every V3 response. This session lives only
// for the existing account callback; no native verdict or capability is reused.
// Broker-local process residency. Account ownership and verification never persist.
const profileAccountPhases=new AsyncLocalStorage();
export function createKovyaWindowsProfileAccountStateProvider(options={}) {
  const owner=Symbol("profile account worker");
  const frozenOptions=Object.freeze({...options,env:Object.freeze({...options.env??process.env})});
  return async function profileAccountStateProvider(work,{expectedHome=null,installationLockHeld=false}={}) {
    if(!profileWorkConfigured()||typeof work!=="function"||installationLockHeld!==false||profileAccountPhases.getStore())
      throw nativeError("broker_native_protocol_refused");
    const request=borrowProfileWorkRequest();
    return profileAccountPhases.run(true,()=>request.accountPhase(owner,
      ()=>frozenOptions.prepared===true?createProfileAccountAdoption(request):createManagedAccountWorker(frozenOptions,request),
      async worker=>{await observeProfileWorkConsumer("account_worker_start",()=>worker.start());request.remainingMs();return worker.withAccountState(work,{expectedHome});}));
  };
}
export function createKovyaWindowsManagedAccountWorker(options={}) {
  return createManagedAccountWorker(options,null);
}
export function createKovyaWindowsPreparedAccountWorker({child,binding,executablePath,remainingMs=null}) {
 return createManagedAccountWorker({executablePath},null,{child,binding,remainingMs});
}
function createManagedAccountWorker({
  executablePath=resolveKovyaWindowsBrokerNativePath(),env=process.env,timeoutMs=5000,onUnavailable=()=>{}
}={},profileRequest=null,prepared=null) {
  if(!isMainThread || process.platform!=="win32")throw nativeError("broker_native_protocol_refused");
  const nativePath=requireExecutablePath(executablePath),timeout=requireTimeout(timeoutMs,MAXIMUM_STARTUP_TIMEOUT_MILLISECONDS);
  let phase="new",binding=null,child=null,socket=null,key=null,invocation=null,sequence=0,pending=null,buffer=Buffer.alloc(0);
  let discovery=null,closed=null,startPromise=null,stopPromise=null,operation=null,owned=false,nonce=null,releaseToken=null;
  let resolveReady,rejectReady,discoveryBytes=0,witnessRejected=false,childError=null;
  const failStop=()=>process.exit(74);
  function fail(error=nativeError("broker_native_exited")) {
    if(owned)failStop();
    const notify=phase!=="broken"&&phase!=="closed";
    if(phase!=="closed")phase="broken";
    if(notify)queueMicrotask(()=>onUnavailable(error));
    if(pending){clearTimeout(pending.timer);const item=pending;pending=null;item.reject(error);}
    rejectReady?.(error);
  }
  function tag(direction,header,body) {
    return createHmac("sha256",key).update(`KOVYA_ACCOUNT_RPC_V4\n${direction}\n${invocation}\n`,"ascii").update(header).update(body).digest();
  }
  function waitFrame(seq,kind,expectedNonce=null,limit=timeout) {
    if(pending)failStop();
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{if(owned)failStop();fail(nativeError("broker_native_handshake_timeout"));terminateChild(child);},limit);
      pending={sequence:seq,kind,nonce:expectedNonce,resolve,reject,timer};
    });
  }
  function receive(chunk) {
    if(!pending || buffer.length+chunk.length>1024*1024+76){fail();return;}
    const next=Buffer.concat([buffer,chunk]);buffer.fill(0);chunk.fill(0);buffer=next;
    if(buffer.length<12)return;
    const length=buffer.readUInt32LE(8),total=length+44;
    if(length>1024*1024+32){fail();return;}
    if(buffer.length<total)return;
    if(buffer.length!==total){fail();return;}
    const item=pending,header=buffer.subarray(0,12),body=buffer.subarray(12,12+length),kind=header.readUInt32LE(4);
    const mac=tag("helper-to-caller",header,body);let valid;
    try{valid=timingSafeEqual(mac,buffer.subarray(12+length));}finally{mac.fill(0);}
    const refused=kind===2&&item.kind===19,operationRefused=kind===23&&[20,21,25,26].includes(item.kind);
    if(!valid || header.readUInt32LE(0)!==item.sequence || (kind!==item.kind&&!refused&&!operationRefused)
        || (item.nonce ? length<32||!timingSafeEqual(item.nonce,body.subarray(0,32)) : length!==0)
        || ((kind===2||kind===22||kind===23)&&length!==32) || (kind===21&&length>24616)){fail();return;}
    const result=Buffer.from(body.subarray(item.nonce?32:0));buffer.fill(0);buffer=Buffer.alloc(0);
    clearTimeout(item.timer);pending=null;
    if(refused){owned=false;phase="idle";item.reject(nativeError("broker_native_protocol_refused"));}
    else if(operationRefused)item.reject(nativeError(item.kind>=25?"account_state_conflict":"broker_native_identity_refused"));
    else {if(kind===22){owned=false;phase="idle";}item.resolve(result);}
  }
  function send(kind,value=Buffer.alloc(0),tx=nonce,limit=null) {
    if(pending || !socket || !Buffer.isBuffer(value) || value.length>(kind===15?262144:24584) || sequence>=0xfffffffe)failStop();
    const current=++sequence,header=Buffer.alloc(12),body=tx?Buffer.concat([tx,value]):Buffer.from(value);
    header.writeUInt32LE(current);header.writeUInt32LE(kind,4);header.writeUInt32LE(body.length,8);
    const mac=tag("caller-to-helper",header,body),frame=Buffer.concat([header,body,mac]);header.fill(0);body.fill(0);mac.fill(0);
    const requested=limit??(kind===11?30000:timeout);
    const bounded=kind===11&&profileRequest?Math.max(1,Math.floor(Math.min(requested,profileRequest.remainingMs()))):requested;
    const response=waitFrame(current,({9:19,10:20,11:21,12:22,13:24,14:25,15:26})[kind],tx,bounded);
    socket.write(frame,error=>{frame.fill(0);if(error)fail();});return response;
  }
  function documents(bytes) {
    const value=JSON.parse(STRICT_UTF8.decode(bytes)),keys=["browser_journal","device_journal","device_journal_previous","manifest","manifest_previous"];
    if(!value||Object.keys(value).sort().join(",")!==keys.join(","))throw nativeError("broker_native_protocol_refused");
    for(const encoded of Object.values(value)) {
      if(encoded===null)continue;
      if(typeof encoded!=="string"||encoded.length>174764)throw nativeError("broker_native_protocol_refused");
      const raw=Buffer.from(encoded,"base64");try{if(raw.length>131072||raw.toString("base64")!==encoded)throw nativeError("broker_native_protocol_refused");}finally{raw.fill(0);}
    }
    return Object.freeze(value);
  }
  async function verify() {
    const current=profileRequest?await profileRequest.verifyBinding(nativePath):await verifyNativeBindingAsync(nativePath,["managed_runtime"]);
    if(binding&&["expected_role","home","codeRoot","generation","payload_digest","native_sha256"].some(field=>current[field]!==binding[field]))throw nativeError("broker_native_identity_refused");
    return current;
  }
  const startupBudget=()=>Math.max(1,Math.floor(profileRequest?profileRequest.remainingMs():prepared?.remainingMs?prepared.remainingMs():timeout));
  function start() {
    if(startPromise)return startPromise;
    if(phase!=="new")return Promise.reject(nativeError("broker_native_protocol_refused"));
    phase="starting";
    startPromise=(async()=>{
      try {
        startupBudget();binding=prepared?prepared.binding:await verify();
        if(profileRequest)profileRequest.remainingMs();
        child=prepared?prepared.child:profileRequest?await spawnProfileNative(profileRequest.ticket,nativePath,["account-worker",String(process.pid)],nativeSpawnOptions(nativePath,env))
          :spawnNative(nativePath,["account-worker",String(process.pid)],nativeSpawnOptions(nativePath,env));
        closed=new Promise(resolve=>child.once("close",(code,signal)=>resolve({code,signal,error:childError})));
        const ready=new Promise((resolve,reject)=>{resolveReady=resolve;rejectReady=reject;});
        // Disposal may emit another error after a transport error, followed by
        // close with the original successful process exit. Retain both delivery
        // paths through close; process exit alone cannot certify native cleanup.
        child.on("error",error=>{childError??=error;fail(error);});child.once("close",()=>{if(phase!=="stopping"&&phase!=="closed")fail();});
        child.stderr.on("data",()=>fail());
        discovery=createInterface({input:child.stdout,crlfDelay:Infinity});let discovered=false;
        child.stdout.on("data",chunk=>{discoveryBytes+=chunk.length;if(discoveryBytes>4096||chunk.some(v=>v>127||v===13))fail();});
        discovery.on("line",line=>{
          try {
            if(phase!=="starting")throw Error();
            if(!discovered){const identity=parseIdentityLine(line,"managed_runtime");if(identity.host_process.pid!==child.pid||identity.parent_process.pid!==process.pid)throw Error();discovered=true;return;}
            if(socket)throw Error();
            const match=/^KOVYA_ACCOUNT_PEER_V4\t([a-f0-9]{64})\t([a-f0-9]{64})$/.exec(line);if(!match)throw Error();
            invocation=match[1];key=Buffer.from(match[2],"hex");socket=net.createConnection(`\\\\.\\pipe\\kovya-account-private-v4-${invocation}`);
            socket.on("data",receive);socket.on("error",()=>fail());socket.on("end",()=>{if(phase!=="stopping"&&phase!=="closed")fail();});
            socket.once("connect",()=>{
              let initial;try{initial=waitFrame(0,1,null,startupBudget());}catch(error){fail(error);return;}
              initial.then(bytes=>{bytes.fill(0);if(phase!=="starting"){fail();return;}try{startupBudget();}catch(error){fail(error);return;}phase="idle";resolveReady();},rejectReady);
              socket.write(`KOVYA_ACCOUNT_BEGIN_V4\t${invocation}\n`,error=>{if(error)fail();});
            });
          }catch{fail();}
        });
        await withTimeout(ready,startupBudget(),"broker_native_handshake_timeout");return api;
      }catch(error){phase="broken";socket?.destroy();if(child){terminateChild(child);await withTimeout(closed,timeout,"broker_native_stop_timeout").catch(()=>{});}throw error;}
    })();return startPromise;
  }
  function rpc(kind,input=Buffer.alloc(0),capturedNonce=nonce,remainingMs=null) {
    if(phase!=="owned"||operation||capturedNonce!==nonce)return Promise.reject(nativeError("broker_native_protocol_refused"));
    if(witnessRejected)return Promise.reject(nativeError("account_state_conflict"));
    // Validate only after this capability has been admitted to its current lease.
    let bytes;
    try{bytes=kind===15?credentialWitnessBytes(input):Buffer.from(input);}
    catch(error){if(kind===15&&error?.code==="account_state_conflict"){witnessRejected=true;profileRequest?.conflict();}return Promise.reject(error);}
    const run=(async()=>{
      await verify();if(!["owned","draining"].includes(phase)||capturedNonce!==nonce)throw nativeError("broker_native_protocol_refused");
      if(profileRequest)profileRequest.remainingMs();
      let payload=bytes,budget=null;
      try {
        if(kind===14||kind===15){budget=witnessBudget(profileRequest?()=>Math.min(profileRequest.remainingMs(),witnessBudget(remainingMs)):remainingMs);payload=Buffer.from(JSON.stringify({budget_ms:budget,...(kind===15?{witness:JSON.parse(STRICT_UTF8.decode(bytes))}:{})}));}
        const raw=await send(kind,payload,capturedNonce,budget);
        if(kind===11)return raw;
        try {
          if(kind===14||kind===15){witnessBudget(remainingMs);return credentialWitnessResponse(raw,kind);}
          return documents(raw);
        }catch(error){if(error?.code==="account_state_conflict"){witnessRejected=true;throw error;}failStop();}finally{raw.fill(0);}
      }catch(error){if((kind===14||kind===15)&&error?.code==="account_state_conflict")witnessRejected=true;throw error;}
      finally{if(payload!==bytes)payload.fill(0);}
    })();
    const settled=run.catch(error=>{if(error?.code==="account_state_conflict")profileRequest?.conflict();throw error;})
      .finally(()=>{bytes.fill(0);if(operation===settled)operation=null;});operation=settled;return settled;
  }
  async function withAccountState(work,{expectedHome=null,installationLockHeld=false}={}) {
    if(typeof work!=="function"||phase!=="idle"||installationLockHeld!==false)throw nativeError("broker_native_protocol_refused");
    if(expectedHome!==null&&path.resolve(expectedHome).toLowerCase()!==path.resolve(binding.home).toLowerCase())throw nativeError("broker_native_identity_refused");
    phase="verifying";
    try{await verify();if(profileRequest)profileRequest.remainingMs();}catch(error){if(phase==="verifying")phase="idle";throw error;}
    if(phase!=="verifying")throw nativeError("broker_native_exited");
    nonce=randomBytes(32);const capturedNonce=nonce;owned=true;phase="beginning";witnessRejected=false;
    let snapshot;
    try {
      const raw=await send(9,Buffer.alloc(0),nonce);
      try {
        const response=JSON.parse(STRICT_UTF8.decode(raw));
        if(!response||Object.keys(response).sort().join(",")!=="documents,ownership_mode,release_token,witness_schema"||response.witness_schema!==WINDOWS_CREDENTIAL_WITNESS_SCHEMA||response.ownership_mode!=="native"||!/^[a-f0-9]{64}$/.test(response.release_token))failStop();
        const encoded=Buffer.from(JSON.stringify(response.documents));try{snapshot=documents(encoded);}finally{encoded.fill(0);}
        releaseToken=response.release_token;phase="owned";
      }catch{failStop();}finally{raw.fill(0);}
      const capability=Object.freeze({home:binding.home,role:"managed_runtime",credentialWitnessSchema:WINDOWS_CREDENTIAL_WITNESS_SCHEMA,
        refreshSnapshot:()=>rpc(10,Buffer.alloc(0),capturedNonce),exchangeCredential:frame=>rpc(11,frame,capturedNonce),
        captureCredentialWitness:({remainingMs}={})=>rpc(14,Buffer.alloc(0),capturedNonce,remainingMs),
        compareCredentialWitness:(witness,{remainingMs}={})=>rpc(15,witness,capturedNonce,remainingMs)
      });
      try{return await work(snapshot,capability);}
      finally {
        phase="draining";if(operation)await operation.catch(()=>{});phase="releasing";
        const token=Buffer.from(releaseToken,"ascii");try{const reply=await send(12,token,capturedNonce);reply.fill(0);}catch{failStop();}finally{token.fill(0);}
      }
    } finally {if(!owned){nonce?.fill(0);nonce=null;releaseToken=null;snapshot=null;}}
  }
  async function checkedClose() {
    const exit=await withTimeout(closed,timeout,"broker_native_stop_timeout");
    if(exit.error)throw exit.error;
    return exit;
  }
  async function stop() {
    if(stopPromise)return stopPromise;
    stopPromise=(async()=>{
      if(owned||operation||phase==="verifying")failStop();
      if(phase==="new"){phase="closed";return;}
      if(phase==="starting"){try{await startPromise;}catch{}}
      if(phase==="idle"){
        phase="stopping";const reply=await send(13,Buffer.alloc(0),null);reply.fill(0);
        const exit=await checkedClose();if(exit.code!==0||exit.signal!==null)throw nativeError("broker_native_stop_timeout");
      }else if(child){terminateChild(child);await checkedClose();}
      phase="closed";
    })().finally(()=>{discovery?.close();socket?.destroy();key?.fill(0);buffer.fill(0);key=null;});return stopPromise;
  }
  const attachRequest=request=>{
    if(!prepared||profileRequest||phase!=="idle")throw nativeError("profile_account_unavailable");
    profileRequest=request;child.ref();socket.ref();
  };
  const detachRequest=request=>{
    if(!prepared||profileRequest!==request||phase!=="idle"||owned||operation)throw nativeError("profile_cleanup_uncertain");
    profileRequest=null;child.unref();socket.unref();
  };
  const unref=()=>{if(prepared&&phase==="idle"&&!profileRequest){child.unref();socket.unref();}};
  const api=Object.freeze({start,stop,withAccountState,attachRequest,detachRequest,unref,get state(){return phase;},get pid(){return child?.pid??null;}});return api;
}

async function withManagedAccountSession(work,{nativePath,binding,env,timeout,installationLockHeld}) {
  const ownershipMode=installationLockHeld?"external":"native";
  const child=spawnNative(nativePath,[installationLockHeld?"account-session-external":"account-session",String(process.pid)],nativeSpawnOptions(nativePath,env));
  let phase="identity",begun=false,published=false,refused=false,released=false,active=false,closing=false;
  let socket=null,key=null,invocation=null,releaseToken=null,buffer=Buffer.alloc(0),pending=null,sequence=0,operation=null;
  let discoveryBytes=0,resolveReady,rejectReady,witnessRejected=false;
  const ready=new Promise((resolve,reject)=>{resolveReady=resolve;rejectReady=reject;});
  const closed=new Promise(resolve=>child.once("close",(code,signal)=>resolve({code,signal})));
  const failStop=()=>process.exit(74);
  const lost=()=>{if(begun&&!refused&&!released)failStop();if(!released&&!refused)rejectReady(nativeError("broker_native_exited"));};
  const discovery=createInterface({input:child.stdout,crlfDelay:Infinity});
  child.once("error",()=>rejectReady(nativeError("broker_native_spawn_failed")));
  child.once("close",lost);child.stderr.on("data",failStop);
  child.stdout.on("data",chunk=>{discoveryBytes+=chunk.length;if(discoveryBytes>4096||chunk.some(v=>v>127||v===13))failStop();});
  function tag(direction,header,body) {
    return createHmac("sha256",key).update(`KOVYA_ACCOUNT_RPC_V3\n${direction}\n${invocation}\n`,"ascii").update(header).update(body).digest();
  }
  function waitFrame(expectedSequence,kind,limit=timeout) {
    if(pending)failStop();
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(failStop,limit);
      pending={sequence:expectedSequence,kind,resolve,reject,timer};
    });
  }
  function receive(chunk) {
    if(!pending || buffer.length+chunk.length>1024*1024+44)failStop();
    const next=Buffer.concat([buffer,chunk]);buffer.fill(0);chunk.fill(0);buffer=next;
    if(buffer.length<12)return;
    const length=buffer.readUInt32LE(8),total=length+44;
    if(length>1024*1024)failStop();
    if(buffer.length<total)return;
    if(buffer.length!==total || !pending)failStop();
    const header=buffer.subarray(0,12),body=buffer.subarray(12,12+length),mac=tag("helper-to-caller",header,body);
    let valid=false;
    try {valid=timingSafeEqual(mac,buffer.subarray(12+length));}finally{mac.fill(0);}
    const kind=header.readUInt32LE(4),item=pending;
    if(!valid || header.readUInt32LE(0)!==item.sequence
        || (kind!==item.kind && !(item.sequence===0&&kind===2) && !(item.sequence>0&&kind===23)))failStop();
    if((kind===2||kind===22||kind===23)&&length!==0)failStop();
    if(kind===21&&length>24584)failStop();
    const result=Buffer.from(body);buffer.fill(0);buffer=Buffer.alloc(0);pending=null;clearTimeout(item.timer);
    if(kind===2){refused=true;phase="refused";item.reject(nativeError("broker_native_protocol_refused"));}
    else if(kind===23){item.reject(nativeError(item.kind>=25?"account_state_conflict":"broker_native_identity_refused"));}
    else {if(kind===22){released=true;active=false;}item.resolve(result);}
  }
  function send(kind,body,limit=null) {
    if(!Buffer.isBuffer(body)||body.length>(kind===15?262144:24584)||sequence>=0xfffffffe)failStop();
    const current=++sequence,header=Buffer.alloc(12);header.writeUInt32LE(current);header.writeUInt32LE(kind,4);header.writeUInt32LE(body.length,8);
    const mac=tag("caller-to-helper",header,body),frame=Buffer.concat([header,body,mac]);header.fill(0);mac.fill(0);
    const response=waitFrame(current,({10:20,11:21,12:22,14:25,15:26})[kind],limit??(kind===11?30000:timeout));
    socket.write(frame,error=>{frame.fill(0);if(error)failStop();});
    return response;
  }
  function documents(bytes) {
    const value=JSON.parse(STRICT_UTF8.decode(bytes)),keys=["browser_journal","device_journal","device_journal_previous","manifest","manifest_previous"];
    if(!value||Object.keys(value).sort().join(",")!==keys.join(","))throw nativeError("broker_native_protocol_refused");
    for(const encoded of Object.values(value)) {
      if(encoded===null)continue;
      if(typeof encoded!=="string"||encoded.length>174764)throw nativeError("broker_native_protocol_refused");
      const raw=Buffer.from(encoded,"base64");try{if(raw.length>131072||raw.toString("base64")!==encoded)throw nativeError("broker_native_protocol_refused");}finally{raw.fill(0);}
    }
    return Object.freeze(value);
  }
  discovery.on("line",line=>{
    try {
      if(!begun&&line==="KOVYA_ACCOUNT_REFUSED_V1"){refused=true;rejectReady(nativeError("broker_native_protocol_refused"));return;}
      if(phase==="identity") {
        const identity=parseIdentityLine(line,binding.expected_role);
        if(identity.host_process.pid!==child.pid||identity.parent_process.pid!==process.pid)failStop();phase="discovery";return;
      }
      if(phase!=="discovery")failStop();
      const match=/^KOVYA_ACCOUNT_PEER_V3\t([a-f0-9]{64})\t([a-f0-9]{64})$/.exec(line);if(!match)failStop();
      invocation=match[1];key=Buffer.from(match[2],"hex");phase="connecting";
      socket=net.createConnection(`\\\\.\\pipe\\kovya-account-private-v1-${invocation}`);
      socket.on("error",lost);socket.on("end",lost);socket.on("close",lost);socket.on("data",receive);
      socket.once("connect",()=>{
        begun=true;phase="snapshot";
        const initial=waitFrame(0,1);
        initial.then(bytes=>{
          try {
            const response=JSON.parse(STRICT_UTF8.decode(bytes));
            if(!response||Object.keys(response).sort().join(",")!=="documents,ownership_mode,release_token,witness_schema"
                ||response.witness_schema!==(installationLockHeld?null:WINDOWS_CREDENTIAL_WITNESS_SCHEMA)||response.ownership_mode!==ownershipMode||!/^[a-f0-9]{64}$/.test(response.release_token))failStop();
            const encoded=Buffer.from(JSON.stringify(response.documents));let snapshot;
            try{snapshot=documents(encoded);}finally{encoded.fill(0);}
            releaseToken=response.release_token;published=true;active=true;phase="held";resolveReady(snapshot);
          }catch{failStop();}finally{bytes.fill(0);}
        },rejectReady);
        socket.write(`KOVYA_ACCOUNT_BEGIN_V3\t${invocation}\t${ownershipMode}\n`,error=>{if(error)failStop();});
      });
    }catch{failStop();}
  });
  function rpc(kind,input=Buffer.alloc(0),remainingMs=null) {
    if(!active||closing||operation)return Promise.reject(nativeError("broker_native_protocol_refused"));
    if(witnessRejected)return Promise.reject(nativeError("account_state_conflict"));
    if((kind===14||kind===15)&&installationLockHeld){witnessRejected=true;return Promise.reject(nativeError("account_state_conflict"));}
    // Pre-RPC comparison failures must invalidate this admitted lease as well.
    let owned;
    try{owned=kind===15?credentialWitnessBytes(input):Buffer.from(input);}
    catch(error){if(kind===15&&error?.code==="account_state_conflict")witnessRejected=true;return Promise.reject(error);}
    const run=(async()=>{
      const current=await verifyNativeBindingAsync(nativePath,["managed_runtime"]);
      if(JSON.stringify(current)!==JSON.stringify(binding))throw nativeError("broker_native_identity_refused");
      if(!active)throw nativeError("broker_native_protocol_refused");
      let payload=owned,budget=null;
      try {
        if(kind===14||kind===15){budget=witnessBudget(remainingMs);payload=Buffer.from(JSON.stringify({budget_ms:budget,...(kind===15?{witness:JSON.parse(STRICT_UTF8.decode(owned))}:{})}));}
        const bytes=await send(kind,payload,budget);
        if(kind===11)return bytes;
        try {
          if(kind===14||kind===15){witnessBudget(remainingMs);return credentialWitnessResponse(bytes,kind);}
          return documents(bytes);
        }catch(error){if(error?.code==="account_state_conflict"){witnessRejected=true;throw error;}failStop();}finally{bytes.fill(0);}
      }catch(error){if((kind===14||kind===15)&&error?.code==="account_state_conflict")witnessRejected=true;throw error;}
      finally{if(payload!==owned)payload.fill(0);}
    })();
    const settled=run.finally(()=>{owned.fill(0);if(operation===settled)operation=null;});operation=settled;return settled;
  }
  const capability=Object.freeze({home:binding.home,role:binding.expected_role,credentialWitnessSchema:installationLockHeld?null:WINDOWS_CREDENTIAL_WITNESS_SCHEMA,
    refreshSnapshot:()=>rpc(10),exchangeCredential:frame=>rpc(11,frame),
    captureCredentialWitness:({remainingMs}={})=>rpc(14,Buffer.alloc(0),remainingMs),
    compareCredentialWitness:(witness,{remainingMs}={})=>rpc(15,witness,remainingMs)
  });
  try {
    let snapshot;
    try{snapshot=await withTimeout(ready,timeout,"broker_native_handshake_timeout");}
    catch(error){if(begun&&!refused)failStop();if(!refused)terminateChild(child);await withTimeout(closed,timeout,"broker_native_stop_timeout").catch(()=>{});throw error;}
    try{return await work(snapshot,capability);}
    finally {
      closing=true;if(operation)await operation.catch(()=>{});
      const token=Buffer.from(releaseToken,"ascii");
      try{const reply=await send(12,token);reply.fill(0);const exit=await withTimeout(closed,timeout,"broker_native_stop_timeout");if(exit.code!==0||exit.signal)failStop();}
      catch{failStop();}finally{token.fill(0);active=false;}
    }
  } finally {
    if(pending)clearTimeout(pending.timer);
    discovery.close();socket?.destroy();key?.fill(0);buffer.fill(0);key=null;
  }
}

export async function readKovyaWindowsBrokerNativeIdentity({
  timeoutMs = 1000,
  executablePath = resolveKovyaWindowsBrokerNativePath(),
  env = process.env,
  spawnImpl = spawn,
  parentProcessId = process.pid,
  remainingMs = null
} = {}) {
  const timeout = requireTimeout(timeoutMs, MAXIMUM_STARTUP_TIMEOUT_MILLISECONDS);
  const deadline=performance.now()+timeout;
  const profileRequest=profileWorkConfigured()?borrowProfileWorkRequest():null;
  const budget=()=>{
    if(!profileRequest)return timeout;
    const value=Math.floor(Math.min(deadline-performance.now(),profileRequest.remainingMs(),typeof remainingMs==="function"?remainingMs():timeout));
    if(!Number.isFinite(value)||value<1)throw nativeError("broker_deadline_refused");
    return value;
  };
  const parentPid = requireProcessId(parentProcessId);
  const nativePath = requireExecutablePath(executablePath);
  const nativeBinding = profileRequest ? await profileRequest.verifyBinding(nativePath) : verifyNativeBinding(nativePath,["managed_runtime","legacy_layout"]);
  let child;
  try {
    budget();
    child = profileRequest ? await spawnProfileNative(profileRequest.ticket,nativePath,["identity",String(parentPid)],nativeSpawnOptions(nativePath,env))
      : spawnNative(nativePath, ["identity", String(parentPid)], nativeSpawnOptions(nativePath, env), spawnImpl);
  } catch (error) {
    if(profileRequest)throw error;
    throw nativeError("broker_native_spawn_failed");
  }
  if (!isChildProcessShape(child)) throw nativeError("broker_native_spawn_failed");
  const ownedClose=profileRequest?observeNativeHostClose(child):null;
  const lineReader = createBoundedControlLineReader(child.stdout);
  const auxiliary = guardAuxiliaryOutput(child.stderr, () => {
    lineReader.fail(nativeError("broker_native_output_refused"));
    terminateChild(child);
  }, 0);
  try {
    const identity = parseIdentityLine(await lineReader.next(budget()), nativeBinding.expected_role);
    if (identity.host_process.pid !== requireProcessId(child.pid)
        || identity.parent_process.pid !== parentPid) {
      throw nativeError("broker_native_identity_refused");
    }
    const exit = ownedClose ? await withTimeout(ownedClose,budget(),"broker_deadline_refused") : await waitForChildClose(child, timeout);
    if (exit.code !== 0 || exit.signal !== null || auxiliary.bytes !== 0) {
      throw errorForNativeExit(exit.code);
    }
    budget();return identity;
  } catch (error) {
    terminateChild(child);
    if(ownedClose){try{await ownedClose;}catch{}}
    if (["broker_deadline_refused", "profile_work_ended", "account_state_conflict", "profile_cleanup_uncertain"].includes(error?.code)) throw error;
    throw normalizeNativeError(error, "broker_native_identity_refused");
  } finally {
    lineReader.dispose();
    auxiliary.dispose();
  }
}

// Account home owns endpoint identity; codeRoot owns executable identity.
// Legacy installed helpers retain their existing three-up home. A versioned
// runtime must prove its admission rather than silently becoming a legacy root.
export function resolveBrokerInstallationIdentity(executablePath) {
  const nativePath=requireExecutablePath(executablePath);
  return verifyNativeBinding(nativePath,["managed_runtime","legacy_layout"]);
}

export async function launchKovyaWindowsBrokerNativeHost({
  publicPipeName,
  privatePipeName,
  brokerBinding,
  brokerInstance,
  configurationForIdentity = null,
  timeoutMs = 900,
  profileWorkTicket = null,
  residentStartup = null,
  startupTimeoutMs = MAXIMUM_STARTUP_TIMEOUT_MILLISECONDS,
  executablePath = resolveKovyaWindowsBrokerNativePath(),
  env = process.env,
  spawnImpl = spawn,
  connectImpl = net.createConnection,
  parentProcessId = process.pid
} = {}) {
  if(residentStartup!==null&&residentStartup!==residentProfileStartup())throw nativeError("profile_resident_required");
  const operationTimeout = requireTimeout(timeoutMs,residentStartup?3000:MAXIMUM_TIMEOUT_MILLISECONDS);
  const launchDeadline = performance.now() + operationTimeout;
  const profileRequest = profileWorkConfigured() && !residentStartup ? borrowProfileWorkRequest() : null;
  if (profileRequest && profileWorkTicket !== profileRequest.ticket)
    throw nativeError("profile_work_owner_required");
  const budget = limit => {
    if (!profileRequest && !residentStartup) return limit;
    const remaining = Math.floor(Math.min(limit, launchDeadline - performance.now(), (residentStartup?residentStartup.remainingMs():profileRequest.remainingMs())));
    if (remaining < 1) throw nativeError("broker_deadline_refused");
    return remaining;
  };
  // Startup residue cannot become the resident's permanent request policy.
  // Each later profile exchange still clamps to its own original <=1000 ms Work.
  const requestTransportCeiling = profileRequest || residentStartup ? 1000 : operationTimeout;
  const startupTimeout = requireTimeout(startupTimeoutMs, MAXIMUM_STARTUP_TIMEOUT_MILLISECONDS);
  const parentPid = requireProcessId(parentProcessId);
  const nativePath = requireExecutablePath(executablePath);
  const proof = residentStartup ? await residentStartup.verifyBinding(nativePath) : profileRequest ? await profileRequest.verifyBinding(nativePath) : null;
  const nativeBinding = proof ? {...proof, installationRootHash: createHash("sha256").update(proof.home.toLowerCase(), "utf8").digest("hex")}
    : verifyNativeBinding(nativePath,["managed_runtime","legacy_layout"]);
  if (configurationForIdentity !== null && typeof configurationForIdentity !== "function") {
    throw nativeError("broker_native_protocol_refused");
  }

  let child;
  try {
    budget(startupTimeout);
    child = residentStartup ? await residentStartup.spawnHost() : profileRequest
      ? await spawnProfileNative(profileRequest.ticket, nativePath, ["host", String(parentPid)], nativeSpawnOptions(nativePath, env))
      : spawnNative(nativePath, ["host", String(parentPid)], nativeSpawnOptions(nativePath, env), spawnImpl);
  } catch (error) {
    if (profileRequest || residentStartup) throw error;
    throw nativeError("broker_native_spawn_failed");
  }
  if (!isChildProcessShape(child)) {
    throw nativeError("broker_native_spawn_failed");
  }
  const closed = observeNativeHostClose(child);

  const lineReader = createBoundedControlLineReader(child.stdout);
  const auxiliary = guardAuxiliaryOutput(child.stderr, () => {
    lineReader.fail(nativeError("broker_native_output_refused"));
    terminateChild(child);
  }, 0);
  const onChildError = () => lineReader.fail(nativeError("broker_native_spawn_failed"));
  child.once("error", onChildError);

  let privateSocket = null;
  try {
    const childPid = requireProcessId(child.pid);
    const identity = parseIdentityLine(await lineReader.next(budget(startupTimeout)), nativeBinding.expected_role);
    budget(startupTimeout);
    if (identity.host_process.pid !== childPid || identity.parent_process.pid !== parentPid) {
      throw nativeError("broker_native_identity_refused");
    }

    const supplied = configurationForIdentity ? await configurationForIdentity(identity) : {
      publicPipeName, privatePipeName, brokerBinding, brokerInstance
    };
    budget(startupTimeout);
    if (!supplied || typeof supplied !== "object" || Array.isArray(supplied)) {
      throw nativeError("broker_native_protocol_refused");
    }
    const publicPipeLeaf = requirePipeLeaf(supplied.publicPipeName, PUBLIC_PIPE_PREFIX);
    const privatePipeLeaf = requirePipeLeaf(supplied.privatePipeName, PRIVATE_PIPE_PREFIX);
    const binding = requireLowerHex(supplied.brokerBinding, 64);
    const instance = requireLowerHex(supplied.brokerInstance, 32);
    const derivedInstallationRootHash = nativeBinding.installationRootHash;
    const installationRootHash = requireLowerHex(
      supplied.installationRootHash ?? derivedInstallationRootHash,
      64
    );
    if (installationRootHash !== derivedInstallationRootHash) {
      throw nativeError("broker_native_identity_refused");
    }

    const configurationLine = [
      CONFIG_TAG,
      publicPipeLeaf,
      privatePipeLeaf,
      binding,
      instance,
      installationRootHash,
      String(requestTransportCeiling),
      "END"
    ].join("\t");
    await endWithAsciiControlLine(child.stdin, configurationLine, budget(startupTimeout));
    if (profileRequest) await diagnosticCheckpoint({stage:"native_host_policy",outcome:"succeeded",reason:"none",
      transport_ceiling_ms:requestTransportCeiling,startup_remaining_ms:budget(startupTimeout),remaining_work_ms:profileRequest.remainingMs()});

    const privateReady = parsePrivateReadyLine(await lineReader.next(budget(operationTimeout)));
    budget(operationTimeout);
    assertPrivateReadyMatches(privateReady, identity, {
      privatePipeLeaf,
      brokerBinding: binding,
      brokerInstance: instance
    });
    privateSocket = await connectPrivatePipe(
      `\\\\.\\pipe\\${privatePipeLeaf}`,
      binding,
      instance,
      budget(operationTimeout),
      connectImpl
    );

    const ready = parseReadyLine(await lineReader.next(budget(operationTimeout)));
    budget(operationTimeout);
    assertReadyMatches(ready, identity, {
      publicPipeLeaf,
      brokerBinding: binding,
      brokerInstance: instance
    });
    if (auxiliary.bytes !== 0) throw nativeError("broker_native_output_refused");

    lineReader.dispose();
    return Object.freeze({
      child,
      identity,
      privateSocket,
      endpoint: Object.freeze({
        pipe_name: `\\\\.\\pipe\\${publicPipeLeaf}`,
        pid: ready.host_process.pid,
        process_creation_filetime: ready.host_process.process_creation_filetime,
        image_path_sha256: ready.host_process.image_path_sha256,
        owner_sid_hash: ready.owner_sid_hash,
        authentication_id_hash: ready.authentication_id_hash,
        windows_session_id: ready.windows_session_id,
        broker_binding: ready.broker_binding,
        broker_instance: ready.broker_instance,
        installation_root_sha256: installationRootHash,
        parent_pid: identity.parent_process.pid,
        parent_process_creation_filetime: identity.parent_process.process_creation_filetime,
        parent_image_path_sha256: identity.parent_process.image_path_sha256
      })
    });
  } catch (error) {
    try { privateSocket?.destroy(); } catch {}
    lineReader.dispose();
    auxiliary.dispose();
    terminateChild(child);
    if (profileRequest || residentStartup) {
      // No timeout here: the request owner retains actual preparation after the
      // public deadline until native disposal settles or reports uncertainty.
      await closed;
      try { budget(operationTimeout); } catch { throw nativeError("broker_deadline_refused"); }
    }
    throw normalizeNativeError(error, "broker_native_protocol_refused");
  }
}

export async function exchangeKovyaWindowsBrokerNative({
  endpoint,
  canonicalRequestBytes,
  timeoutMs = 900,
  executablePath = resolveKovyaWindowsBrokerNativePath(),
  env = process.env,
  spawnImpl = spawn,
  remainingMs = null,
  monotonicNow = () => performance.now()
} = {}) {
  const operationTimeout = requireTimeout(timeoutMs);
  const deadline = monotonicNow() + operationTimeout;
  const profileRequest = profileWorkConfigured() ? borrowProfileWorkRequest() : null;
  const remaining = () => {
    const value = Math.floor(Math.min(deadline - monotonicNow(),
      typeof remainingMs === "function" ? remainingMs() : operationTimeout,
      profileRequest ? profileRequest.remainingMs() : operationTimeout));
    if (!Number.isFinite(value) || value <= 0) throw nativeError("broker_native_exchange_timeout");
    return value;
  };
  remaining();
  const nativePath = requireExecutablePath(executablePath);
  if (profileRequest) await profileRequest.verifyBinding(nativePath);
  else await verifyNativeBindingAsync(nativePath,["managed_runtime","legacy_layout"]);
  remaining();
  const nativeBudget = remaining();
  if (nativeBudget < 50) throw nativeError("broker_native_exchange_timeout");
  let endpointLine = buildEndpointLine(endpoint, nativeBudget);
  let request;
  try { request = copyAndValidateCanonicalRequest(canonicalRequestBytes); }
  catch(error){await diagnosticCheckpoint({stage:"native_frame_validation",outcome:"failed",reason:"native_request_invalid",frame_failure:"native_request_invalid"});throw error;}
  const {operation:transport_operation,request_id:transport_request_id}=JSON.parse(request.toString("utf8"))??{};
  const transportFields={transport_operation,transport_request_id};
  const remainingObservation=()=>{try{return Math.max(0,remaining());}catch{return 0;}};
  const checkpoint=(stage,fields)=>diagnosticCheckpoint({stage,...transportFields,remaining_work_ms:remainingObservation(),...fields});
  if (profileRequest) {
    try {
      const response = await profileRequest.exchange(nativePath,endpointLine,request,transport_operation,transport_request_id);
      try { remaining(); } catch(error) { response.fill(0); throw error; }
      return response;
    } catch(error) {
      if (["profile_startup_timeout","broker_native_transport_failed"].includes(error?.message)) throw profileRequest.outcomeFailure(error);
      if (["broker_native_protocol_refused","broker_native_identity_refused","broker_native_peer_refused","broker_native_frame_invalid","broker_native_transport_failed"].includes(error?.message)) throw nativeError(error.message);
      throw error;
    } finally { request.fill(0); }
  }
  let frame = null;
  let child;

  try {
    remaining();
    child = profileRequest
      ? await spawnProfileNative(profileRequest.ticket, nativePath, ["client"], nativeSpawnOptions(nativePath, env))
      : spawnNative(nativePath, ["client"], nativeSpawnOptions(nativePath, env), spawnImpl);
  } catch (error) {
    request.fill(0);
    if (profileRequest) throw error;
    if (error?.code === "broker_native_exchange_timeout" || error?.code === "broker_timeout") throw error;
    throw nativeError("broker_native_spawn_failed");
  }
  if (!isChildProcessShape(child)) {
    request.fill(0);
    throw nativeError("broker_native_spawn_failed");
  }
  const ownedClose = profileRequest ? observeNativeHostClose(child) : null;

  // Relative transport waits receive only the original operation's residue.
  let transportBudget;
  try {
    transportBudget = remaining();
    if (profileRequest) endpointLine = buildEndpointLine(endpoint, transportBudget);
  } catch (error) {
    request.fill(0); terminateChild(child);
    if (ownedClose) await ownedClose;
    else await waitForChildClose(child, 1000).catch(() => {});
    throw error;
  }
  const response = collectExactFrame(child.stdout, transportBudget);
  const auxiliary = guardAuxiliaryOutput(child.stderr, () => {
    response.fail(nativeError("broker_native_output_refused"));
    terminateChild(child);
  }, 0);
  const responseOutcome = response.promise.then(
    (value) => ({ ok: true, value }),
    (error) => ({ ok: false, error })
  );
  const closeOutcome = (ownedClose
    ? withTimeout(ownedClose, transportBudget, "broker_native_exchange_timeout")
    : waitForChildClose(child, transportBudget)).then(
    (value) => ({ ok: true, value, remaining_work_ms:remainingObservation() }),
    (error) => ({ ok: false, error, remaining_work_ms:remainingObservation() })
  );
  const onChildError = () => response.fail(nativeError("broker_native_spawn_failed"));
  child.once("error", onChildError);

  try {
    frame = framePayload(request);
    await checkpoint("native_request_write",{outcome:"started",reason:"none",request_bytes:request.length});
    await writeClientInput(child.stdin, endpointLine, frame, remaining);
    await checkpoint("native_request_write",{outcome:"succeeded",reason:"none",request_bytes:request.length});
    await checkpoint("native_response_read",{outcome:"started",reason:"none",response_bytes:response.stats().response_bytes});
    const [responseResult, closeResult] = await Promise.all([responseOutcome, closeOutcome]);
    const stats=response.stats();
    const exit=closeResult.ok?closeResult.value:null;
    await checkpoint("native_response_read",{outcome:responseResult.ok?"succeeded":"failed",reason:stats.frame_failure??"none",...stats});
    await checkpoint("native_close",{outcome:closeResult.ok&&exit.code===0&&exit.signal===null?"succeeded":"failed",
      reason:!closeResult.ok?(remainingObservation()===0?"native_work_expired":"native_transport_timeout"):exit.signal!==null?"native_child_signalled":exit.code!==0?"native_child_exited":"none",
      native_exit_code:exit?.code??null,native_signal:exit?.signal??"none",...stats,remaining_work_ms:closeResult.remaining_work_ms});
    // A missing frame is commonly a consequence of native failure. Preserve
    // that owning failure before evaluating the response, without extending Work.
    if (!closeResult.ok) {if(responseResult.ok)responseResult.value.fill(0);throw closeResult.error;}
    if (exit.code !== 0 || exit.signal !== null) {if(responseResult.ok)responseResult.value.fill(0);throw errorForNativeExit(exit.code);}
    if (!responseResult.ok) throw responseResult.error;
    const rawResponse = responseResult.value;
    if (auxiliary.bytes !== 0) {
      rawResponse.fill(0);
      throw nativeError("broker_native_output_refused");
    }
    try { remaining(); } catch (error) { rawResponse.fill(0); throw error; }
    return rawResponse;
  } catch (error) {
    response.fail(normalizeNativeError(error, "broker_native_transport_failed"));
    terminateChild(child);
    let cleanupFailure;
    if (ownedClose) {
      try { await ownedClose; } catch (cause) { cleanupFailure = cause; }
    } else await waitForChildClose(child, 1000).catch(() => {});
    const discarded = await responseOutcome;
    if (discarded.ok) discarded.value.fill(0);
    if (cleanupFailure) throw cleanupFailure;
    throw normalizeNativeError(error, "broker_native_transport_failed");
  } finally {
    request.fill(0);
    frame?.fill(0);
    auxiliary.dispose();
  }
}

export async function stopKovyaWindowsBrokerNativeHost(
  hostOrChild,
  { timeoutMs = 1000 } = {}
) {
  const timeout = requireTimeout(timeoutMs);
  const child = hostOrChild?.child ?? hostOrChild;
  if (!child || typeof child.once !== "function" || typeof child.kill !== "function") {
    throw nativeError("broker_native_protocol_refused");
  }
  const ownedClose = nativeHostClosures.get(child);
  if (ownedClose) {
    const closed = withTimeout(ownedClose, timeout, "broker_native_stop_timeout");
    if (child.exitCode === null || child.exitCode === undefined) child.kill("SIGTERM");
    return Object.freeze(await closed);
  }
  if (child.exitCode !== null && child.exitCode !== undefined) {
    return Object.freeze({ code: child.exitCode, signal: child.signalCode ?? null });
  }

  const closed = waitForChildClose(child, timeout, "broker_native_stop_timeout");
  try {
    child.kill("SIGTERM");
  } catch {
    throw nativeError("broker_native_stop_timeout");
  }
  return Object.freeze(await closed);
}

export async function terminateKovyaWindowsBrokerNativeExact({
  endpoint,
  timeoutMs = 3000,
  executablePath = resolveKovyaWindowsBrokerNativePath(),
  env = process.env,
  spawnImpl = spawn
} = {}) {
  return invokeTerminationControl({
    endpoint, timeoutMs, executablePath, env, spawnImpl, mode: "terminate",
    expectedTag: TERMINATION_ACK_TAG,
    failureCode: "broker_native_termination_refused"
  });
}

export async function assertKovyaWindowsBrokerNativeTerminated({
  endpoint,
  timeoutMs = 1000,
  executablePath = resolveKovyaWindowsBrokerNativePath(),
  env = process.env,
  spawnImpl = spawn
} = {}) {
  return invokeTerminationControl({
    endpoint, timeoutMs, executablePath, env, spawnImpl, mode: "assert-terminated",
    expectedTag: ABSENT_TAG,
    failureCode: "broker_native_absence_unproven"
  });
}

export async function assertKovyaWindowsBrokerNativeHelperAbsent({
  timeoutMs = 1000,
  executablePath = resolveKovyaWindowsBrokerNativePath(),
  env = process.env,
  spawnImpl = spawn
} = {}) {
  const operationTimeout = requireTimeout(timeoutMs);
  const nativePath = requireExecutablePath(executablePath);
  const nativeBinding = verifyNativeBinding(nativePath,["managed_runtime","legacy_layout"]);
  let child;
  try {
    child = spawnNative(nativePath, ["assert-helper-absent"], nativeSpawnOptions(nativePath, env), spawnImpl);
  } catch {
    throw nativeError("broker_native_spawn_failed");
  }
  if (!isChildProcessShape(child)) throw nativeError("broker_native_spawn_failed");
  const reader = createBoundedControlLineReader(child.stdout);
  const auxiliary = guardAuxiliaryOutput(child.stderr, () => {
    reader.fail(nativeError("broker_native_output_refused"));
    terminateChild(child);
  }, 0);
  try {
    child.stdin.end();
    const line = await reader.next(operationTimeout);
    const exit = await waitForChildClose(child, operationTimeout);
    if (line !== ABSENT_TAG || exit.code !== 0 || exit.signal !== null || auxiliary.bytes !== 0) {
      throw nativeError("broker_native_absence_unproven");
    }
    return true;
  } catch (error) {
    terminateChild(child);
    throw normalizeNativeError(error, "broker_native_absence_unproven");
  } finally {
    reader.dispose();
    auxiliary.dispose();
  }
}

export async function assertKovyaWindowsBrokerFixedRootAbsent({
  installationRoot,
  installedHelperPath,
  timeoutMs = 1000,
  executablePath = resolveKovyaWindowsBrokerNativePath(),
  env = process.env,
  spawnImpl = spawn
} = {}) {
  const operationTimeout = requireTimeout(timeoutMs);
  if (typeof installationRoot !== "string" || !path.isAbsolute(installationRoot)) {
    throw nativeError("broker_native_path_invalid");
  }
  const root = path.normalize(installationRoot);
  const expectedHelper = path.join(root, "connector", "claude-code", "client", "kovya_windows_broker_native.exe");
  const helper = requireExecutablePath(installedHelperPath ?? expectedHelper);
  if (helper.toLowerCase() !== expectedHelper.toLowerCase()) {
    throw nativeError("broker_native_path_invalid");
  }
  const rootHash = createHash("sha256").update(root.toLowerCase(), "utf8").digest("hex");
  const helperHash = createHash("sha256").update(helper.toUpperCase(), "utf8").digest("hex");
  const controlLine = [
    FIXED_ROOT_ABSENCE_TAG, rootHash, helperHash, String(operationTimeout), "END"
  ].join("\t");
  const nativePath = requireExecutablePath(executablePath);
  const nativeBinding = verifyNativeBinding(nativePath,["managed_runtime","legacy_layout"]);
  let child;
  try {
    child = spawnNative(nativePath, ["assert-fixed-root-absent"], nativeSpawnOptions(nativePath, env), spawnImpl);
  } catch {
    throw nativeError("broker_native_spawn_failed");
  }
  if (!isChildProcessShape(child)) throw nativeError("broker_native_spawn_failed");
  const reader = createBoundedControlLineReader(child.stdout);
  const auxiliary = guardAuxiliaryOutput(child.stderr, () => {
    reader.fail(nativeError("broker_native_output_refused"));
    terminateChild(child);
  }, 0);
  try {
    await endWithAsciiControlLine(child.stdin, controlLine, operationTimeout);
    const line = await reader.next(operationTimeout);
    const exit = await waitForChildClose(child, operationTimeout);
    if (line !== `${FIXED_ROOT_ABSENT_TAG}\t${rootHash}`
        || exit.code !== 0 || exit.signal !== null || auxiliary.bytes !== 0) {
      throw nativeError("broker_native_absence_unproven");
    }
    return true;
  } catch (error) {
    terminateChild(child);
    throw normalizeNativeError(error, "broker_native_absence_unproven");
  } finally {
    reader.dispose();
    auxiliary.dispose();
  }
}

async function invokeTerminationControl({
  endpoint, timeoutMs, executablePath, env, spawnImpl, mode, expectedTag, failureCode
}) {
  const operationTimeout = requireTimeout(timeoutMs);
  const nativePath = requireExecutablePath(executablePath);
  const nativeBinding = verifyNativeBinding(nativePath,["managed_runtime","legacy_layout"]);
  const endpointLine = buildTerminationEndpointLine(endpoint, operationTimeout);
  let child;
  try {
    child = spawnNative(nativePath, [mode], nativeSpawnOptions(nativePath, env), spawnImpl);
  } catch {
    throw nativeError("broker_native_spawn_failed");
  }
  if (!isChildProcessShape(child)) throw nativeError("broker_native_spawn_failed");
  const reader = createBoundedControlLineReader(child.stdout);
  const auxiliary = guardAuxiliaryOutput(child.stderr, () => {
    reader.fail(nativeError("broker_native_output_refused"));
    terminateChild(child);
  }, 0);
  const lineOutcome = reader.next(operationTimeout).then(
    (value) => ({ ok: true, value }),
    (error) => ({ ok: false, error })
  );
  const closeOutcome = waitForChildClose(child, operationTimeout).then(
    (value) => ({ ok: true, value }),
    (error) => ({ ok: false, error })
  );
  try {
    await endWithAsciiControlLine(child.stdin, endpointLine, operationTimeout);
    const [lineResult, closeResult] = await Promise.all([lineOutcome, closeOutcome]);
    if (!closeResult.ok) throw closeResult.error;
    const exit = closeResult.value;
    if (exit.code !== 0 || exit.signal !== null) throw errorForNativeExit(exit.code);
    if (!lineResult.ok) throw lineResult.error;
    const line = lineResult.value;
    const expected = `${expectedTag}\t${endpoint.broker_binding}\t${endpoint.broker_instance}`;
    if (line !== expected || auxiliary.bytes !== 0) {
      throw nativeError(failureCode);
    }
    return true;
  } catch (error) {
    terminateChild(child);
    throw normalizeNativeError(error, failureCode);
  } finally {
    reader.dispose();
    auxiliary.dispose();
  }
}

function parseIdentityLine(line, expectedRole) {
  const fields = splitControlLine(line, 11);
  if (fields[10] !== expectedRole) throw nativeError("broker_native_identity_refused");
  if (fields[0] !== IDENTITY_TAG) throw nativeError("broker_native_protocol_refused");
  return Object.freeze({
    role: fields[10],
    host_process: processProof(fields[1], fields[2], fields[3]),
    owner_sid_hash: requireLowerHex(fields[4], 64),
    authentication_id_hash: requireLowerHex(fields[5], 64),
    windows_session_id: requireSessionId(fields[6]),
    parent_process: processProof(fields[7], fields[8], fields[9])
  });
}

function parseReadyLine(line) {
  const fields = splitControlLine(line, 10);
  if (fields[0] !== READY_TAG) throw nativeError("broker_native_protocol_refused");
  return Object.freeze({
    public_pipe_leaf: requirePipeLeaf(fields[1], PUBLIC_PIPE_PREFIX),
    host_process: processProof(fields[2], fields[3], fields[4]),
    owner_sid_hash: requireLowerHex(fields[5], 64),
    authentication_id_hash: requireLowerHex(fields[6], 64),
    windows_session_id: requireSessionId(fields[7]),
    broker_binding: requireLowerHex(fields[8], 64),
    broker_instance: requireLowerHex(fields[9], 32)
  });
}

function parsePrivateReadyLine(line) {
  const fields = splitControlLine(line, 10);
  if (fields[0] !== PRIVATE_READY_TAG) throw nativeError("broker_native_protocol_refused");
  return Object.freeze({
    private_pipe_leaf: requirePipeLeaf(fields[1], PRIVATE_PIPE_PREFIX),
    host_process: processProof(fields[2], fields[3], fields[4]),
    owner_sid_hash: requireLowerHex(fields[5], 64),
    authentication_id_hash: requireLowerHex(fields[6], 64),
    windows_session_id: requireSessionId(fields[7]),
    broker_binding: requireLowerHex(fields[8], 64),
    broker_instance: requireLowerHex(fields[9], 32)
  });
}

function assertReadyMatches(ready, identity, expected) {
  if (ready.public_pipe_leaf !== expected.publicPipeLeaf
      || ready.host_process.pid !== identity.host_process.pid
      || ready.host_process.process_creation_filetime !== identity.host_process.process_creation_filetime
      || ready.host_process.image_path_sha256 !== identity.host_process.image_path_sha256
      || ready.owner_sid_hash !== identity.owner_sid_hash
      || ready.authentication_id_hash !== identity.authentication_id_hash
      || ready.windows_session_id !== identity.windows_session_id
      || ready.broker_binding !== expected.brokerBinding
      || ready.broker_instance !== expected.brokerInstance) {
    throw nativeError("broker_native_identity_refused");
  }
}

function assertPrivateReadyMatches(ready, identity, expected) {
  if (ready.private_pipe_leaf !== expected.privatePipeLeaf
      || ready.host_process.pid !== identity.host_process.pid
      || ready.host_process.process_creation_filetime !== identity.host_process.process_creation_filetime
      || ready.host_process.image_path_sha256 !== identity.host_process.image_path_sha256
      || ready.owner_sid_hash !== identity.owner_sid_hash
      || ready.authentication_id_hash !== identity.authentication_id_hash
      || ready.windows_session_id !== identity.windows_session_id
      || ready.broker_binding !== expected.brokerBinding
      || ready.broker_instance !== expected.brokerInstance) {
    throw nativeError("broker_native_identity_refused");
  }
}

function connectPrivatePipe(pipeName, brokerBinding, brokerInstance, timeoutMs, connectImpl) {
  return new Promise((resolve, reject) => {
    let socket;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        try { socket?.destroy(); } catch {}
        reject(error);
      } else resolve(value);
    };
    const timer = setTimeout(
      () => finish(nativeError("broker_native_handshake_timeout")),
      timeoutMs
    );
    timer.unref?.();
    try { socket = connectImpl(pipeName); }
    catch { return finish(nativeError("broker_native_private_transport_failed")); }
    if (!socket || typeof socket.once !== "function" || typeof socket.write !== "function") {
      return finish(nativeError("broker_native_private_transport_failed"));
    }
    socket.once("error", () => finish(nativeError("broker_native_private_transport_failed")));
    socket.once("connect", async () => {
      const reader = createBoundedControlLineReader(socket);
      const line = `${PRIVATE_PREAMBLE_TAG}\t${brokerBinding}\t${brokerInstance}`;
      const bytes = Buffer.from(`${line}\n`, "ascii");
      try {
        await writeStream(socket, bytes, timeoutMs);
        const acknowledgement = await reader.next(timeoutMs);
        const expected = `${PRIVATE_ACK_TAG}\t${brokerBinding}\t${brokerInstance}`;
        if (acknowledgement !== expected) {
          throw nativeError("broker_native_peer_refused");
        }
        reader.dispose();
        finish(null, socket);
      } catch (error) {
        reader.dispose();
        finish(normalizeNativeError(error, "broker_native_private_transport_failed"));
      } finally {
        bytes.fill(0);
      }
    });
  });
}

function buildEndpointLine(endpoint, timeoutMs) {
  if (!endpoint || typeof endpoint !== "object" || Array.isArray(endpoint)) {
    throw nativeError("broker_native_protocol_refused");
  }
  return [
    ENDPOINT_TAG,
    requirePipeLeaf(endpoint.pipe_name, PUBLIC_PIPE_PREFIX),
    String(requireProcessId(endpoint.pid)),
    requireFileTime(endpoint.process_creation_filetime),
    requireLowerHex(endpoint.image_path_sha256, 64),
    requireLowerHex(endpoint.owner_sid_hash, 64),
    requireLowerHex(endpoint.authentication_id_hash, 64),
    String(requireSessionId(endpoint.windows_session_id)),
    requireLowerHex(endpoint.broker_binding, 64),
    requireLowerHex(endpoint.broker_instance, 32),
    String(timeoutMs),
    "END"
  ].join("\t");
}

function buildTerminationEndpointLine(endpoint, timeoutMs) {
  if (!endpoint || typeof endpoint !== "object" || Array.isArray(endpoint)) {
    throw nativeError("broker_native_protocol_refused");
  }
  const pipeLeaf = requirePipeLeaf(endpoint.pipe_name, PUBLIC_PIPE_PREFIX);
  const brokerBinding = requireLowerHex(endpoint.broker_binding, 64);
  if (pipeLeaf !== `${PUBLIC_PIPE_PREFIX}${brokerBinding.slice(0, 48)}`) {
    throw nativeError("broker_native_protocol_refused");
  }
  return [
    TERMINATION_ENDPOINT_TAG,
    pipeLeaf,
    String(requireProcessId(endpoint.pid)),
    requireFileTime(endpoint.process_creation_filetime),
    requireLowerHex(endpoint.image_path_sha256, 64),
    requireLowerHex(endpoint.owner_sid_hash, 64),
    requireLowerHex(endpoint.authentication_id_hash, 64),
    String(requireSessionId(endpoint.windows_session_id)),
    brokerBinding,
    requireLowerHex(endpoint.broker_instance, 32),
    requireLowerHex(endpoint.installation_root_sha256, 64),
    String(requireProcessId(endpoint.parent_pid)),
    requireFileTime(endpoint.parent_process_creation_filetime),
    requireLowerHex(endpoint.parent_image_path_sha256, 64),
    String(timeoutMs),
    "END"
  ].join("\t");
}

function processProof(pid, creationFileTime, imagePathHash) {
  return Object.freeze({
    pid: requireProcessId(pid),
    process_creation_filetime: requireFileTime(creationFileTime),
    image_path_sha256: requireLowerHex(imagePathHash, 64)
  });
}

function copyAndValidateCanonicalRequest(value) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) {
    throw nativeError("broker_native_frame_invalid");
  }
  const copy = Buffer.from(value);
  if (copy.length < 2 || copy.length > MAXIMUM_FRAME_BYTES) {
    copy.fill(0);
    throw nativeError("broker_native_frame_invalid");
  }
  try {
    let text = STRICT_UTF8.decode(copy);
    let parsed = JSON.parse(text);
    if (text !== stableJson(parsed)) throw nativeError("broker_native_frame_invalid");
    text = "";
    parsed = null;
    return copy;
  } catch (error) {
    copy.fill(0);
    throw normalizeNativeError(error, "broker_native_frame_invalid");
  }
}

function framePayload(payload) {
  const frame = Buffer.allocUnsafe(payload.length + 4);
  frame.writeUInt32LE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

function createBoundedControlLineReader(stream) {
  let buffered = Buffer.alloc(0);
  let failed = null;
  let disposed = false;
  const lines = [];
  const waiters = [];

  const fail = (error) => {
    if (failed || disposed) return;
    failed = normalizeNativeError(error, "broker_native_protocol_refused");
    buffered.fill(0);
    buffered = Buffer.alloc(0);
    while (lines.length) lines.shift().fill(0);
    while (waiters.length) waiters.shift().reject(failed);
  };
  const onData = (chunkValue) => {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue);
    if (buffered.length + chunk.length > MAXIMUM_CONTROL_LINE_BYTES + 1) {
      chunk.fill(0);
      fail(nativeError("broker_native_output_refused"));
      return;
    }
    const prior = buffered;
    buffered = Buffer.concat([prior, chunk]);
    prior.fill(0);
    chunk.fill(0);
    const newline = buffered.indexOf(0x0a);
    if (newline < 0) return;
    if (newline < 1 || newline > MAXIMUM_CONTROL_LINE_BYTES || newline !== buffered.length - 1) {
      fail(nativeError("broker_native_protocol_refused"));
      return;
    }
    const lineBytes = Buffer.from(buffered.subarray(0, newline));
    buffered.fill(0);
    buffered = Buffer.alloc(0);
    if (lineBytes.includes(0x0d) || [...lineBytes].some((value) => value > 0x7f)) {
      lineBytes.fill(0);
      fail(nativeError("broker_native_protocol_refused"));
      return;
    }
    const waiter = waiters.shift();
    if (waiter) waiter.resolve(lineBytes); else lines.push(lineBytes);
  };
  const onEnd = () => fail(nativeError("broker_native_exited"));
  const onError = () => fail(nativeError("broker_native_transport_failed"));
  stream.on("data", onData);
  stream.once("end", onEnd);
  stream.once("error", onError);

  return Object.freeze({
    async next(timeoutMs) {
      let bytes;
      if (failed) throw failed;
      if (lines.length) bytes = lines.shift();
      else {
        bytes = await withTimeout(new Promise((resolve, reject) => waiters.push({ resolve, reject })),
          timeoutMs, "broker_native_handshake_timeout");
      }
      try { return bytes.toString("ascii"); }
      finally { bytes.fill(0); }
    },
    fail,
    dispose() {
      if (disposed) return;
      disposed = true;
      stream.off("data", onData);
      stream.off("end", onEnd);
      stream.off("error", onError);
      buffered.fill(0);
      while (lines.length) lines.shift().fill(0);
      while (waiters.length) waiters.shift().reject(nativeError("broker_native_exited"));
    }
  });
}

function collectExactFrame(stream, timeoutMs) {
  const stats={response_bytes:0,frame_expected_bytes:null,frame_failure:"none"};
  let buffered = Buffer.alloc(0);
  let settled = false;
  let failFrame;
  const promise = withTimeout(new Promise((resolve, reject) => {
    const cleanup = () => {
      stream.off("data", onData);
      stream.off("end", onEnd);
      stream.off("error", onError);
    };
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      buffered.fill(0);
      buffered = Buffer.alloc(0);
      if (error) reject(error); else resolve(value);
    };
    failFrame = error => finish(error);
    const onData = (chunkValue) => {
      const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue);
      stats.response_bytes+=chunk.length;
      if (buffered.length + chunk.length > MAXIMUM_FRAME_BYTES + 4) {
        stats.frame_failure="native_frame_oversized";
        chunk.fill(0);
        finish(nativeError("broker_native_frame_invalid"));
        return;
      }
      const prior = buffered;
      buffered = Buffer.concat([prior, chunk]);
      prior.fill(0);
      chunk.fill(0);
      if (buffered.length >= 4) {
        const expected = buffered.readUInt32LE(0);stats.frame_expected_bytes=expected;
        if (expected < 2 || expected > MAXIMUM_FRAME_BYTES || buffered.length > expected + 4) {
          stats.frame_failure=expected<2?"native_frame_length_invalid":expected>MAXIMUM_FRAME_BYTES?"native_frame_oversized":"native_frame_trailing";
          finish(nativeError("broker_native_frame_invalid"));
        }
      }
    };
    const onEnd = () => {
      if (buffered.length < 4) {stats.frame_failure=buffered.length===0?"native_frame_empty":"native_frame_header_truncated";return finish(nativeError("broker_native_frame_invalid"));}
      const expected = buffered.readUInt32LE(0);stats.frame_expected_bytes=expected;
      if (expected < 2 || expected > MAXIMUM_FRAME_BYTES || buffered.length !== expected + 4) {
        stats.frame_failure=expected<2?"native_frame_length_invalid":expected>MAXIMUM_FRAME_BYTES?"native_frame_oversized":buffered.length<expected+4?"native_frame_truncated":"native_frame_trailing";
        return finish(nativeError("broker_native_frame_invalid"));
      }
      finish(null, Buffer.from(buffered.subarray(4)));
    };
    const onError = () => {stats.frame_failure="native_pipe_closed";finish(nativeError("broker_native_transport_failed"));};
    stream.on("data", onData);
    stream.once("end", onEnd);
    stream.once("error", onError);
  }), timeoutMs, "broker_native_exchange_timeout").catch(error => { failFrame(error); throw error; });
  return Object.freeze({
    promise,
    stats:()=>({...stats}),
    fail(error) {
      failFrame(normalizeNativeError(error, "broker_native_transport_failed"));
    }
  });
}

async function endWithAsciiControlLine(stream, line, timeoutMs) {
  if (Buffer.byteLength(line, "ascii") < 1 || Buffer.byteLength(line, "ascii") > MAXIMUM_CONTROL_LINE_BYTES
      || /[^\x20-\x7e\t]/u.test(line)) {
    throw nativeError("broker_native_protocol_refused");
  }
  const bytes = Buffer.from(`${line}\n`, "ascii");
  try { await endStream(stream, bytes, timeoutMs); }
  finally { bytes.fill(0); }
}

async function writeClientInput(stream, endpointLine, frame, remaining) {
  if (Buffer.byteLength(endpointLine, "ascii") < 1
      || Buffer.byteLength(endpointLine, "ascii") > MAXIMUM_CONTROL_LINE_BYTES
      || /[^\x20-\x7e\t]/u.test(endpointLine)) {
    throw nativeError("broker_native_protocol_refused");
  }
  const control = Buffer.from(`${endpointLine}\n`, "ascii");
  try {
    await writeStream(stream, control, remaining());
    await endStream(stream, frame, remaining());
  } finally {
    control.fill(0);
  }
}

function writeStream(stream, bytes, timeoutMs) {
  return withTimeout(new Promise((resolve, reject) => {
    stream.write(bytes, (error) => error ? reject(nativeError("broker_native_transport_failed")) : resolve());
  }), timeoutMs, "broker_native_exchange_timeout");
}

function endStream(stream, bytes, timeoutMs) {
  return withTimeout(new Promise((resolve, reject) => {
    stream.once("error", () => reject(nativeError("broker_native_transport_failed")));
    stream.end(bytes, () => resolve());
  }), timeoutMs, "broker_native_exchange_timeout");
}

function waitForChildClose(child, timeoutMs, timeoutCode = "broker_native_exchange_timeout") {
  if (child.exitCode !== null && child.exitCode !== undefined) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode ?? null });
  }
  return withTimeout(new Promise((resolve) => {
    child.once("close", (code, signal) => resolve({ code, signal: signal ?? null }));
  }), timeoutMs, timeoutCode);
}

function guardAuxiliaryOutput(stream, onOverflow, maximumBytes = MAXIMUM_AUXILIARY_OUTPUT_BYTES) {
  let bytes = 0;
  const onData = (chunkValue) => {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue);
    bytes += chunk.length;
    chunk.fill(0);
    if (bytes > maximumBytes) onOverflow();
  };
  stream.on("data", onData);
  return {
    get bytes() { return bytes; },
    dispose() { stream.off("data", onData); }
  };
}

function withTimeout(promise, timeoutMs, code) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(nativeError(code)), timeoutMs);
    timer.unref?.();
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); }
    );
  });
}

function splitControlLine(line, exactFields) {
  if (typeof line !== "string" || line.length < 1 || Buffer.byteLength(line, "ascii") > MAXIMUM_CONTROL_LINE_BYTES) {
    throw nativeError("broker_native_protocol_refused");
  }
  const fields = line.split("\t");
  if (fields.length !== exactFields || fields.some((field) => field.length < 1 || field.length > 256)) {
    throw nativeError("broker_native_protocol_refused");
  }
  return fields;
}

function requirePipeLeaf(value, prefix) {
  const text = String(value ?? "");
  const fullPrefix = "\\\\.\\pipe\\";
  const leaf = text.startsWith(fullPrefix) ? text.slice(fullPrefix.length) : text;
  if (leaf !== `${prefix}${leaf.slice(prefix.length)}`
      || !new RegExp(`^${prefix}[a-f0-9]{48}$`, "u").test(leaf)) {
    throw nativeError("broker_native_protocol_refused");
  }
  return leaf;
}

function requireLowerHex(value, exactLength) {
  const text = String(value ?? "");
  if (!new RegExp(`^[a-f0-9]{${exactLength}}$`, "u").test(text)) {
    throw nativeError("broker_native_protocol_refused");
  }
  return text;
}

function requireProcessId(value) {
  const text = String(value ?? "");
  if (!/^[1-9][0-9]{0,9}$/u.test(text)) throw nativeError("broker_native_identity_refused");
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 0xffffffff) {
    throw nativeError("broker_native_identity_refused");
  }
  return parsed;
}

function requireSessionId(value) {
  const text = String(value ?? "");
  if (!/^(0|[1-9][0-9]{0,9})$/u.test(text)) throw nativeError("broker_native_identity_refused");
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 0xffffffff) {
    throw nativeError("broker_native_identity_refused");
  }
  return parsed;
}

function requireFileTime(value) {
  const text = String(value ?? "");
  if (!/^[1-9][0-9]{0,19}$/u.test(text)) throw nativeError("broker_native_identity_refused");
  try {
    if (BigInt(text) > 0xffffffffffffffffn) throw nativeError("broker_native_identity_refused");
  } catch (error) {
    throw normalizeNativeError(error, "broker_native_identity_refused");
  }
  return text;
}

function requireTimeout(value, maximum = MAXIMUM_TIMEOUT_MILLISECONDS) {
  if (!Number.isInteger(value) || value < MINIMUM_TIMEOUT_MILLISECONDS || value > maximum) {
    throw nativeError("broker_native_protocol_refused");
  }
  return value;
}

function requireExecutablePath(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)
      || path.basename(value).toLowerCase() !== "kovya_windows_broker_native.exe") {
    throw nativeError("broker_native_path_invalid");
  }
  return path.normalize(value);
}

function nativeSpawnOptions(executablePath, env) {
  const childEnvironment = {};
  for (const name of ["SystemRoot", "WINDIR"]) {
    if (typeof env?.[name] === "string" && env[name].length > 0) childEnvironment[name] = env[name];
  }
  return Object.freeze({
    cwd: path.dirname(executablePath),
    env: Object.freeze(childEnvironment),
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true
  });
}

function isChildProcessShape(child) {
  return child && typeof child.once === "function" && typeof child.kill === "function"
    && child.stdin && child.stdout && child.stderr;
}

function terminateChild(child) {
  try { child.stdin?.destroy(); } catch {}
  try { child.stdout?.destroy(); } catch {}
  try { child.stderr?.destroy(); } catch {}
  try { child.kill("SIGTERM"); } catch {}
}

function errorForNativeExit(exitCode) {
  if (exitCode === 64) return nativeError("broker_native_protocol_refused");
  if (exitCode === 65) return nativeError("broker_native_identity_refused");
  if (exitCode === 66) return nativeError("broker_native_peer_refused");
  if (exitCode === 67) return nativeError("broker_native_transport_failed");
  if (exitCode === 70) return nativeError("broker_native_private_transport_failed");
  return nativeError("broker_native_exited");
}

function normalizeNativeError(error, fallbackCode) {
  return error instanceof KovyaWindowsBrokerNativeError ? error : nativeError(fallbackCode);
}

function nativeError(code) {
  return new KovyaWindowsBrokerNativeError(code);
}
