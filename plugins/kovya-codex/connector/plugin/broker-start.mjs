import {spawnNativeSync} from "../claude-code/client/kovya-managed-process.mjs";
import {verifyNativeBinding} from "../claude-code/client/kovya-native-binding.mjs";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";
import {profileWorkConfigured,borrowProfileWorkRequest,spawnProfileNative} from "../claude-code/client/kovya-profile-process.mjs";
import {diagnosticFailure,diagnosticCheckpoint,diagnosticObservation} from "./diagnostic-events.mjs";
const fail=code=>Object.assign(new Error(code),{code});
const helper=fileURLToPath(new URL("../claude-code/client/kovya_windows_broker_native.exe",import.meta.url));
async function profileNativeCall(args,env) {
  const request=borrowProfileWorkRequest(),identity=await request.verifyBinding(helper);
  const requestedHome=args[0]==="start-broker"?args[1]:args[2];
  if(typeof requestedHome!=="string" || requestedHome.toLowerCase()!==identity.home.toLowerCase()) throw fail("broker_native_identity_refused");
  request.remainingMs();
  const childEnv=Object.fromEntries(["SystemRoot","WINDIR"].filter(key=>typeof env?.[key]==="string").map(key=>[key,env[key]]));
  await diagnosticCheckpoint({stage:"broker_starter_spawn",outcome:"started",reason:"none",elapsed_ms:0});
  const child=await spawnProfileNative(request.ticket,helper,args,{env:childEnv,shell:false,windowsHide:true,stdio:["pipe","pipe","pipe"],maxBuffer:8192});
  let timer,total=0,failure;const chunks=[];
  const onError=error=>{failure??=error;};
  child.on("error",onError);
  const closed=new Promise(resolve=>child.once("close",(code,signal)=>resolve({code,signal:signal??null})));
  const stop=()=>{try{child.kill();}catch(error){failure??=error;}};
  const data=chunk=>{total+=chunk.length;if(total>8192){failure??=fail("broker_start_unconfirmed");stop();}else chunks.push(Buffer.from(chunk));};
  const stderr=chunk=>{if(chunk.length){failure??=fail("broker_start_unconfirmed");stop();}};
  child.stdout.on("data",data);child.stderr.on("data",stderr);child.stdin.on("error",onError);
  try {
    await diagnosticCheckpoint({stage:"broker_starter_reply",outcome:"started",reason:"none",elapsed_ms:0});
    const budget=Math.floor(request.remainingMs());
    const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail("broker_deadline_refused")),budget);});
    child.stdin.end();
    const exit=await Promise.race([closed,timeout]);
    if(failure)throw failure;
    request.remainingMs();
    if(exit.signal!==null)throw fail("broker_start_unconfirmed");
    let reply;try{reply=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(Buffer.concat(chunks)));}catch{throw fail("broker_start_unconfirmed");}
    if(exit.code!==0)throw fail(["broker_breakaway_refused","broker_scope_unknown"].includes(reply.reason)?reply.reason:"broker_start_refused");
    diagnosticObservation({stage:"broker_starter_verified",outcome:"succeeded",reason:"none"});
    return reply;
  } catch(error) {
    diagnosticObservation({stage:"broker_starter_disposal",outcome:"started",reason:"none"});
    stop();await closed;
    throw failure??error;
  } finally {
    clearTimeout(timer);child.off("error",onError);child.stdin.off("error",onError);
    child.stdout.off("data",data);child.stderr.off("data",stderr);for(const chunk of chunks)chunk.fill(0);
  }
}
function nativeCall(args,env,spawnSyncImpl) {
  const identity=verifyNativeBinding(helper,["managed_runtime"]);
  const requestedHome=args[0]==="start-broker"?args[1]:args[2];
  if(typeof requestedHome!=="string" || requestedHome.toLowerCase()!==identity.home.toLowerCase()) throw fail("broker_native_identity_refused");
  const child=spawnNativeSync(helper,args,{env,shell:false,windowsHide:true,stdio:["ignore","pipe","pipe"],encoding:"utf8",timeout:1500,maxBuffer:8192},spawnSyncImpl);
  if(child.error || child.signal || child.stderr?.length) throw fail("broker_start_unconfirmed");
  let reply;
  try {reply=JSON.parse(child.stdout);} catch {throw fail("broker_start_unconfirmed");}
  if(child.status!==0) throw fail(["broker_breakaway_refused","broker_scope_unknown"].includes(reply.reason)?reply.reason:"broker_start_refused");
  return reply;
}
export function validateBrokerResidency(value,expectedPid) {
  if(!value || value.pid!==expectedPid || !Number.isSafeInteger(value.pid) || value.pid<1
    || !["machine","harness_session"].includes(value.broker_scope)
    || typeof value.process_creation_filetime!=="string" || !/^[1-9][0-9]{5,19}$/.test(value.process_creation_filetime)
    || typeof value.image_path_sha256!=="string" || !/^[a-f0-9]{64}$/.test(value.image_path_sha256))
    throw fail("broker_scope_unknown");
  return Object.freeze({...value});
}
export function createPluginBrokerStarter({spawnSyncImpl=spawnSync}={}) {
  return ({home,env})=>{
    if(profileWorkConfigured())return profileNativeCall(["start-broker",home],env).then(reply=>{
      if(reply?.ok!==true || reply.state!=="broker_started")throw fail("broker_start_unconfirmed");
      return validateBrokerResidency(reply.broker,reply.broker?.pid).pid;
    });
    const reply=nativeCall(["start-broker",home],env,spawnSyncImpl);
    if(reply.ok!==true || reply.state!=="broker_started") throw fail("broker_start_unconfirmed");
    return validateBrokerResidency(reply.broker,reply.broker?.pid).pid;
  };
}
export function observeBrokerResidency({home,env=process.env,spawnSyncImpl=spawnSync,pid=process.pid}) {
  if(profileWorkConfigured())return borrowProfileWorkRequest().observeBroker("residency",helper,home,pid).then(reply=>validateBrokerResidency(reply,pid));
  return validateBrokerResidency(nativeCall(["broker-residency",String(pid),home],env,spawnSyncImpl),pid);
}
export function bindPluginBrokerClient(client,{spawnBroker=createPluginBrokerStarter(),onFailure=null}={}) {
  const result={...client};
  const terminalFailures=new WeakSet();
  result.isTerminalEventFailure=error=>error!==null&&(typeof error==='object'||typeof error==='function')&&terminalFailures.has(error);
  let cold=false,failureCode=null;
  // One binding belongs to one worker event or MCP message, never the host process.
  const brokerEvent=Object.freeze({isCold:()=>cold,markCold:()=>{cold=true;},
    failureCode:()=>failureCode,rememberFailure:code=>{if(code==="profile_cleanup_uncertain")failureCode=code;else failureCode??=code;}});
  const invoke=async operation=>{
    try{return await operation();}catch(error){
      const refusal=typeof client.resolveBrokerEventFailure==="function"
        ? client.resolveBrokerEventFailure(error,brokerEvent) : error;
      if(refusal!==null&&(typeof refusal==='object'||typeof refusal==='function')&&(cold||diagnosticFailure(refusal).deadline?.scope==='request'))terminalFailures.add(refusal);
      onFailure?.(refusal);throw refusal;
    }
  };
  for(const name of ["recallMemory","capturePrivateMemory","retainTurnPrompt","endTurnSession","handleBrokerMcpMessage"])
    if(typeof client[name]==="function") result[name]=(args,options={})=>invoke(()=>client[name](args,{...options,spawnBroker,brokerEvent}));
  for(const name of ["inspectKovyaBroker","inspectKovyaBrokerStatus","shutdownKovyaBroker"])
    if(typeof client[name]==="function") result[name]=(options={})=>invoke(()=>client[name]({...options,spawnBroker,brokerEvent}));
  if(typeof client.brokerRequest==="function")
    result.brokerRequest=(operation,payload,options={})=>invoke(()=>client.brokerRequest(operation,payload,{...options,spawnBroker,brokerEvent}));
  return Object.freeze(result);
}
