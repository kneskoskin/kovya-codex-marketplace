import {COLD_PATH_WORK_MS} from "./request-budget.mjs";
import {terminalWorkContext,runTerminalOperation,bindTerminalDeadline} from "./terminal-operation.mjs";
import {projectOutcomeEvidence,hasOutcomeEvidence} from "../claude-code/client/kovya-phase-authority.mjs";
import {AsyncLocalStorage} from "node:async_hooks";
import {createDiagnosticTrace,diagnosticFailure,phaseObservation,sanitizeDiagnosticRecord,diagnosticLogLevel,diagnosticCheckpoint} from "./diagnostic-events.mjs";
import {persistDiagnosticRecords} from "./diagnostic-sink.mjs";
import {profileWorkConfigured,runProfileWorkRequest,runClientProfileWorkRequest,runServerProfileWorkRequest,observeProfileWorkConsumer} from "../claude-code/client/kovya-profile-process.mjs";
import * as profileDiagnostics from "../claude-code/client/kovya-profile-process.mjs";

const ingress=new AsyncLocalStorage(),receipts=new WeakMap();
const object=v=>v!==null&&(typeof v==="object"||typeof v==="function");
const own=(v,k)=>{try{return Object.getOwnPropertyDescriptor(v,k)?.value;}catch{return undefined;}};
export const diagnosticReceipt=value=>object(value)?receipts.get(value):undefined;
function observation(value,error,metadata){
  const local=["local_preparation","local_acceptance"].includes(metadata?.phase);
  if(local&&["connect","finish"].includes(metadata?.operation)){
    const terminal=own(value,"terminal");if(object(terminal))value=terminal;
    if(!error&&metadata.operation==="connect"&&own(value,"outcome")==="manual_required")
      return sanitizeDiagnosticRecord({event:"stage",stage:"operation_result",outcome:"succeeded",reason:"none",state_after:"approval_required"});
  }
  const failed=error?diagnosticFailure(error):null;
  const rpc=own(value,"jsonrpc")==="2.0";
  const ok=rpc?!own(value,"error"):own(value,"ok");
  return sanitizeDiagnosticRecord({event:"stage",stage:"operation_result",outcome:error||ok===false?"failed":ok===true?"succeeded":"unknown",
    ...failed,reason:failed?.reason??own(value,"reason")??own(value,"error_code")??"none",state_after:error?"failed":own(value,"state"),
    phase:own(value,"phase"),recovery_expires_at:own(value,"recovery_expires_at"),attempt_created_at:own(value,"attempt_created_at")});
}

// Attaches to an existing public work boundary; never nests or renews Work.
export const runObservedProfileWorkRequest=(remainingMs,work,metadata)=>runObservedOwner(remainingMs,work,metadata,runProfileWorkRequest,null);
export const runObservedClientWorkRequest=(remainingMs,work,metadata,operation)=>runObservedOwner(remainingMs,work,metadata,runClientProfileWorkRequest,operation);
export const runObservedServerWorkRequest=(remainingMs,work,metadata,operation)=>runObservedOwner(remainingMs,work,metadata,runServerProfileWorkRequest,operation);
async function runObservedOwner(remainingMs,work,metadata,runOwner,operation){
  if(!profileWorkConfigured())return runOwner(remainingMs,work,null,operation);
  const context=ingress.getStore();if(context)context.owners++;
  const immediate=context&&["worker","mcp"].includes(context.metadata?.operation);
  const persisted=new Set();
  const key=record=>`${record.span_id}:${record.stage}:${record.outcome}`;
  const selected=immediate?{...metadata,...context.metadata,event_id:context.event_id,eventStarted:context.started}:metadata??context?.metadata??{operation:"broker"};
  const incremental=immediate||selected.operation==="broker";
  const trace=createDiagnosticTrace({...selected,checkpoint:incremental?async record=>{
    const saved=await persistDiagnosticRecords([record]);available&&=saved.available;
    if(saved.available)persisted.add(key(record));
  }:undefined});
  let available=true,complete=false,observed,terminalContext,applicationValue,applicationError;
  if(immediate)await diagnosticCheckpoint({stage:"admission",outcome:"started",reason:"none",elapsed_ms:0});
  const observer={
    deadlineBound:bindTerminalDeadline,
    cutoffStage:()=>trace.snapshot().records.at(-1)?.stage??"admission",
    eventId:immediate&&context.event_id!=="unknown"?context.event_id:undefined,
    async run(dispatch){
      const start=await observeProfileWorkConsumer("diagnostic_start_append",()=>persistDiagnosticRecords(trace.snapshot().records));available&&=start.available;
      return trace.run(async()=>{if(immediate)await diagnosticCheckpoint({stage:"admission",outcome:"succeeded",reason:"none",elapsed_ms:0});return dispatch();});
    },
    terminalWork(ticket,until){terminalContext=terminalWorkContext(ticket,until,metadata);},
    workSettled(value,error){applicationValue=value;applicationError=error;observed=observation(value,error,metadata);},
    async beforeCleanup(append){
      if(!incremental)return;
      const record=trace.observe({stage:"cleanup_entry",outcome:"started",reason:"none",elapsed_ms:0});
      if(record){const saved=await persistDiagnosticRecords([record],append);available&&=saved.available;if(saved.available)persisted.add(key(record));}
    },
    async afterCleanup(append,error){
      // This describes observed application work and cleanup, not native End or
      // the diagnostic writer's own future cleanup. Disk never invents End.
      trace.observe({stage:"terminal_pending",outcome:"unknown",reason:"none"});
      trace.observe({stage:"cleanup",outcome:"succeeded",reason:"none"});trace.seal();
      const records=trace.snapshot().records.slice(1).filter(record=>!persisted.has(key(record)));
      const saved=await persistDiagnosticRecords(records,append);available&&=saved.available;
      await terminalContext?.prepare(applicationValue,error??applicationError,{attempt_id:trace.snapshot().records.find(record=>record.attempt_id!=="unknown")?.attempt_id});
    },
    completed(){complete=true;}
  };
  const receipt=value=>Object.freeze({...((hasOutcomeEvidence(value)||value?.code==="broker_outcome_unknown")?{phase_observation:phaseObservation(projectOutcomeEvidence(value))}:observed?.last_verified_phase!==undefined?{phase_observation:phaseObservation(observed)}:{}),diagnostic_id:trace.id,status:diagnosticLogLevel()==="off"?"disabled":available?"recorded":"diagnostic_unavailable",completion:complete?"confirmed":"unconfirmed",operation_outcome:observed?.outcome??"unknown"});
  try{
    const value=await runOwner(remainingMs,work,observer,operation);
    if(object(value))receipts.set(value,receipt(value));
    if(!available&&context)context.unavailable=true;
    return value;
  }catch(error){if(!complete)available=false;if(object(error))receipts.set(error,receipt(error));if(!available&&context)context.unavailable=true;throw error;}
}

// No input content or response payload is retained. Worker/MCP framing and
// admission use a separately typed native diagnostic scope, never Work. Its
// cold-capable initial ceiling only decreases when associated with an original Work
// deadline. Authentication retains its existing fallback observation boundary.
export async function observeDiagnosticIngress(metadata,work,{unavailable=()=>{}}={}){
  if(!profileWorkConfigured())return work();
  const started=performance.now();
  let event_id="unknown";
  const eventLogging=diagnosticLogLevel()!=="off"&&["worker","mcp"].includes(metadata?.operation);
  if(eventLogging){
    try{event_id=profileDiagnostics.newProfileDiagnosticEvent(metadata.operation);}catch{}
  }
  const context={metadata,event_id,started,owners:0,until:started+COLD_PATH_WORK_MS,unavailable:eventLogging&&event_id==="unknown"};
  const prework=eventLogging?createDiagnosticTrace({...metadata,event_id,eventStarted:started,checkpoint:async record=>{
    if(!["framing","admission"].includes(record.stage))return;
    try{await profileDiagnostics.appendProfileIngressDiagnostic(event_id,record);}catch{context.unavailable=true;}
  }}):null;
  const execute=async()=>{
    let value,error;
    try{value=await work();}catch(cause){error=cause;}
    if(!eventLogging&&context.owners===0&&performance.now()<context.until){
      try{await runObservedProfileWorkRequest(()=>context.until-performance.now(),()=>{
        if(error)throw error;return value;
      },metadata);}catch(cause){if(!["recorded","disabled"].includes(diagnosticReceipt(cause)?.status))context.unavailable=true;}
    }else if(!eventLogging&&context.owners===0)context.unavailable=true;
    prework?.seal();
    if(eventLogging&&event_id!=="unknown")try{profileDiagnostics.closeProfileDiagnosticEvent(event_id);}catch{}
    if(context.unavailable)unavailable();
    if(error)throw error;return value;
  };
  return ingress.run(context,()=>runTerminalOperation({...metadata,event_id:event_id==="unknown"?"-":event_id},()=>prework?prework.run(execute):execute()));
}
