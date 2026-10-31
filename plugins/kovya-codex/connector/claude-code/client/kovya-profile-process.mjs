import {WARM_WORK_MS} from "../../plugin/request-budget.mjs";
import {admitServerPhase,projectOutcomeEvidence,attachOutcomeEvidence,createOutcomeOwner} from "./kovya-phase-authority.mjs";
// Explicit work owner API. The public ingress owns begin/end; nested creators
// receive the opaque native ticket and cannot supply or renew its deadline.
import {AsyncLocalStorage} from "node:async_hooks";
import binding from "./kovya-profile-binding.generated.mjs";
import nativeBinding from "./kovya-native-binding.generated.mjs";
import path from "node:path";
import {createRequire} from "node:module";
import {createManagedProcessStreams} from "./kovya-managed-process-streams.mjs";
import {isDiagnosticDeadlineConsumer,noteDiagnosticDeadline,finishStage} from "../../plugin/diagnostic-events.mjs";
let owned,preparedAccount,preparingAccount=false;
function load(){
 if(!binding)throw new Error("profile_binding_required");
 if(!owned){const native=createRequire(import.meta.url)("./kovya_profile_startup.node");native.initialize();owned={native,streams:createManagedProcessStreams(native)};}
 return owned;
}
// The verified preload is the only production caller. Native custody decides
// whether this environment has a sealed Connect/Finish startup purpose.
export async function prepareProfileAccountWorker(){
 if(preparingAccount||preparedAccount)throw failure("profile_account_unavailable");
 preparingAccount=true;
 const {native,streams}=load(),context=native.initialize();
  const startup=residentProfileStartup();
 const child=await streams.prepareAccountWorker();
 const {createKovyaWindowsPreparedAccountWorker}=await import("./kovya-windows-broker-native.mjs");
 const worker=createKovyaWindowsPreparedAccountWorker({child,binding:Object.freeze({home:context.home,codeRoot:context.root,generation:context.generation,payload_digest:context.payload_digest,expected_role:nativeBinding.expected_role,native_sha256:nativeBinding.native_sha256}),executablePath:path.join(context.root,"connector/claude-code/client/kovya_windows_broker_native.exe"),remainingMs:startup?.remainingMs??null});
 try{await worker.start();await native.readyAccountWorker();preparedAccount={worker,child};worker.unref();}
 catch(error){child.kill();throw error;}
}
// A resident capability can only come from the sealed native starter role.
// This facade exposes fixed purposes; no path, argv, Work ticket or deadline.
let residentFacade;
export function residentProfileStartup(){
 if(!profileWorkConfigured())return null;
 if(residentFacade)return residentFacade;
 const {native,streams}=load();
 if(native.residentStatus()===null)return null;
 const remainingMs=()=>native.residentStatus().remaining_ms;
 residentFacade=Object.freeze({
  remainingMs,
  observe:()=>native.observeResident(),
  verifyBinding:async executable=>{
   remainingMs();const proof=await native.observeResident();
   if(proof.native_sha256!==nativeBinding.native_sha256||proof.expected_role!=="managed_runtime"
     ||path.resolve(executable).toLowerCase()!==path.join(proof.codeRoot,"connector/claude-code/client/kovya_windows_broker_native.exe").toLowerCase())
    throw failure("broker_native_identity_refused");
   remainingMs();return Object.freeze(proof);
  },
  spawnHost:()=>streams.spawnResidentHost(),
  checkpoint:stage=>native.residentCheckpoint(stage),
  publish:record=>native.publishResident(JSON.stringify(record)),
  async stop(){
   let error;try{if(preparedAccount)await preparedAccount.worker.stop();}catch(cause){error=cause;}
   try{native.endResident();}catch(cause){error??=cause;}
   if(error)throw error;
  }
 });
 return residentFacade;
}

export function createProfileAccountAdoption(request){
 const owner=requireTicketOwner(request.ticket);
 if(!owner||requests.getStore()!==owner||!preparedAccount)throw failure("profile_account_unavailable");
 const prepared=preparedAccount,{worker}=prepared,native=load().native;
 let started,adopted=false,stopped=false,releaseAdmission;
 const remaining=()=>{try{return request.remainingMs();}catch(error){if(error?.code==="profile_work_ended")throw deadlineFailure(owner);throw error;}};
 const start=()=>started??=(async()=>{
  remaining();
  // Auth lease completion does not detach the native Work grant. Queue at its
  // owning boundary and retain admission until checked request stop below.
  const previous=prepared.admission??Promise.resolve();
  const held=new Promise((resolve,reject)=>{releaseAdmission=error=>error?reject(error):resolve();});
  prepared.admission=previous.then(()=>held);prepared.admission.catch(()=>{});
  await previous;requireCertainCleanup();remaining();
  try{await native.adoptAccountWorker(request.ticket);}catch(error){
   if(error?.message==="profile_account_exited")throw failure("profile_account_unavailable");
   if(!error?.code&&["profile_account_busy","profile_account_unavailable","profile_account_work_reused"].includes(error?.message))throw failure(error.message);
   throw error;
  }adopted=true;
  await admitServerPhase();remaining();
  worker.attachRequest(request);remaining();
 })();
 return Object.freeze({start,withAccountState:async(...args)=>{await start();request.remainingMs();return worker.withAccountState(...args);},
  async stop(){
   if(stopped)return;stopped=true;
   // A refused start owns no JS attachment; its Work still reaches native End.
   if(started)await started.catch(()=>{});
   try{
    if(adopted){await native.releaseAccountWorker(request.ticket);worker.detachRequest(request);adopted=false;}
    releaseAdmission?.();
   }catch(error){releaseAdmission?.(failure("profile_cleanup_uncertain"));throw error;}
  }});
}

const requests=new AsyncLocalStorage();
// Association outlives the public response and is removed only after real End.
const requestOwners=new Map();
// Public expiry cannot release ownership. Fresh admission checks these deadlines
// directly, including while a delayed JS timer has not yet delivered its refusal.
const unsettledFrames=new Set();
// Uncertain request cleanup is retained until host exit; there is no reset.
const failedFrames=new Set();
let cleanupPoison=null;
export const profileCleanupFailed = () => cleanupPoison !== null;
const failure=code=>Object.assign(new Error(code),{code});
function observeExpiry(frame) {
 if(!frame.expiry){const now=performance.now();frame.expiry=Object.freeze({scope:"request",consumer:frame.consumers.at(-1)?.name??"request_dispatch",elapsed_ms:Math.max(0,now-frame.started),budget_ms:frame.budget,
  stage:frame.diagnostic?.cutoffStage?.()??"admission",cleanup:frame.cleanupFailure?"failed":frame.cleanupCompleted?"confirmed":"pending",writer_gap:"expired"});}
 return frame.expiry;
}
function nativeOutcome(frame){
 if(frame.ticket!==null&&!frame.cleanupCompleted)try{
  const native=load().native;
  if(frame.role==='client')frame.outcome=native.exchangeOutcome(frame.ticket);
  else if(frame.role==='server')frame.outcome=native.serverOutcome(frame.ticket);
 }catch{}
 return frame.outcome;
}
function frameEvidence(frame){return frame.evidence.snapshot(nativeOutcome(frame),frame.cleanupCompleted===true);}
function safetyFailure(frame){
 const codes=new Set(['broker_native_identity_refused','broker_native_peer_refused','broker_native_protocol_refused','account_state_conflict','profile_cleanup_uncertain','profile_diagnostic_cleanup_uncertain','profile_poisoned']);
 return frame.cleanupFailure??(frame.conflict?failure('account_state_conflict'):null)??[frame.workError,frame.phaseFailure].find(error=>codes.has(error?.code??error?.message));
}
function deadlineFailure(frame){
 const safety=safetyFailure(frame);
 if(frame.server&&!frame.auditSealed){frame.auditSealed=true;try{load().native.serverPhase(frame.ticket,'terminal',safety?.code??'broker_deadline_refused');}catch{}}
 if(safety){noteDiagnosticDeadline(safety,observeExpiry(frame));return attachOutcomeEvidence(safety,frameEvidence(frame));}
 const observed=frameEvidence(frame);
 // A terminal header is evidence of receipt, not of public body validation.
 // In particular, "none" must never become a failure code or certify success
 // while the original cutoff is unwinding an unsettled JS continuation.
 const terminalReason=observed.terminal_reason??(observed.role==='server'&&observed.terminal_sealed===true?observed.server_reason:null);
 const code=terminalReason&&terminalReason!=='none'?terminalReason:(observed.no_dispatch_proven||frame.role==='unbound_local'?'broker_deadline_refused':'broker_outcome_unknown');
 const error=attachOutcomeEvidence(failure(code),observed);
 if(observed.retry_may_duplicate)error.message='Saving is unconfirmed. A retry may duplicate this capture; do not claim it was saved.';
 noteDiagnosticDeadline(error,observeExpiry(frame));return error;
}
function consumerWork(frame,name,work){
 if(!frame)return work();
 if(!isDiagnosticDeadlineConsumer(name))throw failure("diagnostic_consumer_invalid");
 const consumer={name};frame.consumers.push(consumer);
 const finish=()=>{if(frame.deadlineRefused||(frame.until>0&&performance.now()>=frame.until))observeExpiry(frame);frame.consumers.splice(frame.consumers.indexOf(consumer),1);};
 const failed=error=>{if(error?.message==="profile_startup_timeout"||error?.code==="broker_deadline_refused")noteDiagnosticDeadline(error,observeExpiry(frame));};
 try{const value=work();if(value&&typeof value.then==="function")return Promise.resolve(value).then(result=>{finish();return result;},error=>{failed(error);finish();throw error;});finish();return value;}
 catch(error){failed(error);finish();throw error;}
}
// Observation only. Nested scopes never create tickets or extend their clocks.
export const observeProfileWorkConsumer=(name,work)=>consumerWork(requests.getStore(),name,work);
function requireCertainCleanup(){if(cleanupPoison)throw failure("profile_cleanup_uncertain");}
function requireAdmission(){
 requireCertainCleanup();
 const now=performance.now();
 for(const frame of unsettledFrames)if(frame.deadlineRefused||(frame.until>0&&now>=frame.until))throw failure("profile_cleanup_uncertain");
}
function poisonCleanup(frame,cause){
 const error=cause??failure("profile_cleanup_uncertain");
 frame.cleanupFailure??=error;cleanupPoison??=error;failedFrames.add(frame);
}
function requireTicketOwner(ticket){
 const owner=requestOwners.get(ticket);
 if(owner&&requests.getStore()!==owner)throw failure("profile_work_owner_required");
 return owner;
}
export const profileWorkConfigured=()=>binding!==null;
export const profileIngressRemaining=deadline=>load().native.ingressRemaining(deadline);
export function bindProfileServer(tuple){const frame=requests.getStore();borrowProfileWorkRequest().remainingMs();if(frame.role!=='server')throw failure('profile_work_owner_required');load().native.bindServerWork(frame.ticket,tuple);frame.server=true;return ()=>frameEvidence(frame);}
export function observeProfileServer(stage){const frame=requests.getStore();if(stage==='admitted')borrowProfileWorkRequest().remainingMs();if(!frame?.server)throw failure('profile_work_owner_required');load().native.serverPhase(frame.ticket,stage,'none');}
// Native-minted metadata, never a Work or account capability.
export const newProfileDiagnosticEvent=operation=>load().native.newDiagnosticEvent(operation);
export const prepareProfileBrokerBudget=operation=>{requireAdmission();return Object.freeze(load().native.prepareBrokerBudget(operation));};
export const closeProfileDiagnosticEvent=id=>load().native.closeDiagnosticEvent(id);
export const appendProfileIngressDiagnostic=(id,record)=>load().native.appendIngressDiagnostic(id,record.stage,record.outcome,record.reason);
// Internal fixed-projection sink. Register synchronously before the request
// closes its phase set; timeout is only a public refusal, never ownership End.
export function appendProfileDiagnostic(bytes){
 const frame=requests.getStore();
 borrowProfileWorkRequest().remainingMs();
 if(typeof bytes!=="string"||Buffer.byteLength(bytes)>262144)throw failure("diagnostic_record_invalid");
 const phase=Promise.resolve().then(()=>{
  borrowProfileWorkRequest().remainingMs();
  return load().native.appendDiagnostic(frame.ticket,bytes);
 }).then(()=>({available:true}),error=>{
  if(error?.message==="profile_diagnostic_cleanup_uncertain")poisonCleanup(frame,error);
  return {available:false,reason:"diagnostic_unavailable"};
 });
 frame.phases.add(phase);
 phase.then(()=>frame.phases.delete(phase));
 return phase;
}
export function borrowProfileWorkRequest(){
 const current=requests.getStore();
 const remainingMs=()=>{
  if(!current||requests.getStore()!==current||!current.active||current.ticket===null)throw failure("profile_work_ended");
  if(current.conflict)throw failure("account_state_conflict");
  const remaining=Math.min(current.until-performance.now(),current.remainingMs());
  if(!Number.isFinite(remaining)||remaining<1)throw deadlineFailure(current);
  return remaining;
 };
 const conflict=()=>{if(current&&requests.getStore()===current)current.conflict=true;};
 const checkedBinding=(proof,executable)=>{
  if(!nativeBinding||!Object.isFrozen(nativeBinding)||nativeBinding.expected_role!=="managed_runtime"
    ||proof?.expected_role!==nativeBinding.expected_role||proof.native_sha256!==nativeBinding.native_sha256
    ||typeof proof.home!=="string"||typeof proof.codeRoot!=="string"
    ||path.resolve(executable).toLowerCase()!==path.join(proof.codeRoot,"connector/claude-code/client/kovya_windows_broker_native.exe").toLowerCase())
   throw failure("broker_native_identity_refused");
  return Object.freeze(proof);
 };
 const verifyBinding=async executable=>{
  remainingMs();
  const proof=await load().native.checkWorkBinding(current.ticket,executable);
  remainingMs();return checkedBinding(proof,executable);
 };
 const observeBroker=(purpose,executable,home,pid=process.pid)=>{
  remainingMs();
  if(!['identity','residency'].includes(purpose))throw failure('broker_native_identity_refused');
  const phase=Promise.resolve().then(async()=>{
   remainingMs();
   let proof;
   try{proof=await load().native.observeBroker(current.ticket,purpose,executable,home,pid);}
   catch(error){
    if(error?.message==='profile_startup_timeout')throw deadlineFailure(current);
    throw failure('broker_native_identity_refused');
   }
   remainingMs();checkedBinding(proof,executable);
   if(proof.purpose!==purpose||typeof home!=='string'||proof.home.toLowerCase()!==home.toLowerCase())throw failure('broker_native_identity_refused');
   if(purpose==='identity'&&(!/^[a-f0-9]{64}$/.test(proof.owner_sid_hash)||!/^[a-f0-9]{64}$/.test(proof.authentication_id_hash)
      ||!Number.isSafeInteger(proof.windows_session_id)||proof.windows_session_id<0||proof.windows_session_id>0xffffffff))throw failure('broker_native_identity_refused');
   return proof;
  });
  current.phases.add(phase);
  phase.then(()=>current.phases.delete(phase),error=>{current.phaseFailure??=error;current.phases.delete(phase);});
  return phase;
 };
 const exchange=(executable,endpointLine,request,operation,requestId)=>{
  remainingMs();if(current.role!=='client')throw failure('profile_work_owner_required');current.exchangeOperation=operation;
  const phase=Promise.resolve().then(()=>{remainingMs();current.exchangeStarted=true;return load().native.exchangePhase(current.ticket,executable,endpointLine,request,operation,requestId);});
  current.phases.add(phase);
  phase.then(()=>{nativeOutcome(current);current.phases.delete(phase);},error=>{current.phaseFailure??=error;nativeOutcome(current);current.phases.delete(phase);});
  return phase;
 };
 const accountPhase=(owner,create,work)=>{
  remainingMs();
  if(current.account&&current.account.owner!==owner)throw failure("broker_native_protocol_refused");
  if(!current.account)current.account={owner,worker:create()};
  const phase=Promise.resolve().then(()=>{remainingMs();return consumerWork(current,"account_lease",()=>work(current.account.worker));});
  current.phases.add(phase);
  phase.then(()=>current.phases.delete(phase),error=>{current.phaseFailure??=error;current.phases.delete(phase);});
  return phase;
 };
 remainingMs();return Object.freeze({ticket:current.ticket,remainingMs,conflict,verifyBinding,observeBroker,exchange,accountPhase,outcomeFailure:cause=>{
   const observed=nativeOutcome(current);
   if(observed?.dispatch_submitted||observed?.terminal_reason)return deadlineFailure(current);
   if(cause?.message==='broker_native_transport_failed'&&current.active&&performance.now()<current.until)return failure('broker_native_transport_failed');
   return deadlineFailure(current);
  }});
}
export async function beginProfileWork(remainingMs=()=>1000){
 const current=requests.getStore();
 if(current){if(!current.active)throw failure("profile_work_ended");return current.ticket;}
 requireAdmission();
 return load().native.beginWork(remainingMs);
}
export async function endProfileWork(ticket){
 const current=requests.getStore();
 if(current){if(!current.active||current.ticket!==ticket)throw failure("profile_work_ended");return true;}
 requireCertainCleanup();
 requireTicketOwner(ticket);
 return load().native.endWork(ticket);
}
export const spawnProfileNative=(ticket,executable,argv,configuration)=>{
 requireCertainCleanup();
 const owner=requireTicketOwner(ticket);
 if(owner)borrowProfileWorkRequest();
 requireAdmission();
 const streams=load().streams,creation=streams.spawnAsync(ticket,executable,argv,configuration);
 if(!owner)return creation;
 const observed=creation.then(child=>{
  const cleanup=streams.observeCleanup(child);owner.cleanups.add(cleanup);
  cleanup.completion.then(()=>owner.cleanups.delete(cleanup),cause=>poisonCleanup(owner,cause));
  return child;
 });
 owner.starts.add(observed);
 observed.then(()=>owner.starts.delete(observed),error=>{owner.phaseFailure??=error;owner.starts.delete(observed);});
 return observed;
};

// Only a fresh broker transport request crosses this context boundary. Nested
// creators use beginProfileWork, which borrows this ticket without renewing it.
export const runProfileWorkRequest=(remainingMs,work,diagnostic=null)=>runOwnedProfileWorkRequest(remainingMs,work,diagnostic,'unbound_local',null);
export const runClientProfileWorkRequest=(remainingMs,work,diagnostic=null,operation=null)=>runOwnedProfileWorkRequest(remainingMs,work,diagnostic,'client',operation);
export const runServerProfileWorkRequest=(remainingMs,work,diagnostic=null,operation=null)=>runOwnedProfileWorkRequest(remainingMs,work,diagnostic,'server',operation);
async function runOwnedProfileWorkRequest(remainingMs,work,diagnostic,role,operation){
 if(!profileWorkConfigured())return work(null);
 requireAdmission();
 return requests.exit(async()=>{
  const native=load().native,frame={role,diagnostic,evidence:createOutcomeOwner(role,operation),ticket:null,active:true,remainingMs,until:0,started:performance.now(),budget:0,consumers:[],expiry:null,deadlineRefused:false,conflict:false,account:null,phases:new Set(),phaseFailure:null,starts:new Set(),cleanups:new Set(),cleanupFailure:null};let timer,rejectDeadline;
  unsettledFrames.add(frame);
  const timeout=new Promise((_,reject)=>{rejectDeadline=reject;});
  const budget=()=>{
   const started=performance.now(),remaining=Math.min(remainingMs.budgetAdmission?.budget_ms??WARM_WORK_MS,remainingMs());
   frame.started=started;frame.budget=Number.isFinite(remaining)?Math.max(0,remaining):0;
   if(!Number.isFinite(remaining)||remaining<1)throw deadlineFailure(frame);
   frame.until=started+remaining;
   diagnostic?.deadlineBound?.(frame.until);
   // A delivered refusal fences admission even if the clock still reads early.
   timer=setTimeout(()=>{frame.deadlineRefused=true;frame.active=false;rejectDeadline(deadlineFailure(frame));},Math.max(0,started+remaining-performance.now()));
   return remaining;
  };
  const lifecycle=(async()=>{
   let ticket;
   try{ticket=await consumerWork(frame,"native_work_admission",()=>remainingMs.budgetAdmission?native.beginWork(budget,diagnostic?.eventId??'-',role,operation??'-',remainingMs.budgetAdmission.token):native.beginWork(budget,diagnostic?.eventId??'-',role,operation??'-'));}catch(error){unsettledFrames.delete(frame);throw error;}
   frame.ticket=ticket;frame.evidence.bind(ticket);requestOwners.set(ticket,frame);diagnostic?.terminalWork?.(ticket,frame.until);
   const appendOnly=async bytes=>{
    if(frame.deadlineRefused||performance.now()>=frame.until||remainingMs()<1)return {available:false,reason:"diagnostic_unavailable"};
    try{await native.appendDiagnostic(ticket,bytes);return {available:true};}
    catch(error){if(error?.message==="profile_diagnostic_cleanup_uncertain")poisonCleanup(frame,error);return {available:false,reason:"diagnostic_unavailable"};}
   };
   let result,workError;
   try{
    if(!frame.active||performance.now()>=frame.until)throw deadlineFailure(frame);
    requireAdmission();
    result=await requests.run(frame,()=>Promise.resolve().then(()=>{
     const dispatch=()=>{requireCertainCleanup();borrowProfileWorkRequest().remainingMs();return consumerWork(frame,"request_dispatch",()=>work(ticket));};
     return diagnostic?diagnostic.run(dispatch):dispatch();
    }));
   }catch(error){workError=error;frame.workError=error;}
   if(frame.server&&!frame.auditSealed){
    const reason=workError?.code??(result?.ok===false?result.error_code:'none');frame.auditSealed=true;
    try{native.serverPhase(ticket,'terminal',reason??'broker_failed');}catch{}
   }
   if(workError)attachOutcomeEvidence(workError,frameEvidence(frame));
   diagnostic?.workSettled(result,workError);
   // Persist the cleanup-entry checkpoint while the original ticket can still
   // write. An expired ticket refuses this observation; cleanup still proceeds.
   if(diagnostic?.beforeCleanup)await diagnostic.beforeCleanup(appendOnly);
   frame.active=false;
   // Await actual admitted work, including phases the callback did not await.
   await consumerWork(frame,"request_cleanup",()=>Promise.allSettled([...frame.phases]));
   await consumerWork(frame,"request_cleanup",()=>Promise.allSettled([...frame.starts]));
   try{
    if(frame.account)await consumerWork(frame,"worker_stop",()=>finishStage("worker_cleanup",()=>frame.account.worker.stop()));
    // A live resident child owns its own native R and may outlive this request.
    // Only disposal already started here is request cleanup to await.
    await consumerWork(frame,"request_cleanup",()=>Promise.allSettled([...frame.cleanups].filter(cleanup=>cleanup.started).map(cleanup=>cleanup.completion)));
    if(frame.cleanupFailure)throw frame.cleanupFailure;
    if(diagnostic){
     // Closed to account/spawn/borrow APIs. Only this append capability may use
     // the original ticket before End, and it cannot renew the deadline.
     await consumerWork(frame,"diagnostic_finalize",()=>diagnostic.afterCleanup(appendOnly,workError??frame.phaseFailure??(frame.conflict?failure("account_state_conflict"):null)));
     if(frame.cleanupFailure)throw frame.cleanupFailure;
    }
    if(frame.role==='client')native.closeClientDispatch(ticket);
    nativeOutcome(frame);
    await consumerWork(frame,"native_work_end",()=>finishStage("native_end",()=>native.endWork(ticket)));
    frame.cleanupCompleted=true;diagnostic?.completed();
    requestOwners.delete(ticket);
    unsettledFrames.delete(frame);
   }catch(error){poisonCleanup(frame,error);throw attachOutcomeEvidence(error,frameEvidence(frame));}
   if(frame.cleanupFailure)throw frame.cleanupFailure;
   const safety=safetyFailure(frame);if(safety)throw attachOutcomeEvidence(safety,frameEvidence(frame));
   // Once cleanup is certain, elapsed Work wins over a late application error.
   // The first consumer observation survives unwinding and cannot renew Work.
   if(frame.deadlineRefused||performance.now()>=frame.until||remainingMs()<1)throw deadlineFailure(frame);
   if(workError)throw attachOutcomeEvidence(workError,frameEvidence(frame));
   if(frame.phaseFailure)throw attachOutcomeEvidence(frame.phaseFailure,frameEvidence(frame));
   if(frame.conflict)throw failure("account_state_conflict");
   if(result&&typeof result==="object")attachOutcomeEvidence(result,frameEvidence(frame));
   return result;
  })();
  // The public refusal also covers admission/cleanup queueing. The lifecycle
  // remains observed and retains ownership until native cleanup has settled.
  try{return await Promise.race([lifecycle,timeout]);}
  catch(error){if(error.message==="profile_startup_timeout")throw deadlineFailure(frame);throw error;}
  finally{clearTimeout(timer);}
 });
}

// Opaque native identity and writer stay in this closure, never on product values.
export function createProfileTerminalOperation(operation,eventId="-"){
 if(!profileWorkConfigured())return null;
 const native=load().native;let owner;
 try{owner=native.newTerminalOperation(operation,eventId);}catch{return null;}
 let attempted=false,closed=false;
 return Object.freeze({
  async prepare(ticket,{attempt_id,request_id,phase}={}){
   if(attempted||closed)return false;attempted=true;
   try{return await native.prepareTerminal(owner,ticket,attempt_id??"-",request_id??"-",phase??"unknown");}catch{return false;}
  },
  async commit(decision){
   if(closed)return false;
   try{return await native.commitTerminal(owner,decision.ok,decision.state,decision.reason,decision.phase);}catch{return false;}
  },
  close(){if(closed)return;closed=true;try{native.closeTerminalOperation(owner);}catch{}owner=null;}
 });
}
