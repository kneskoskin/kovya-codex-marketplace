import {AsyncLocalStorage} from 'node:async_hooks';
import {createProfileTerminalOperation} from '../claude-code/client/kovya-profile-process.mjs';
import {diagnosticFailure,diagnosticLogLevel,finishStageSync} from './diagnostic-events.mjs';
import {attachOutcomeEvidence,hasOutcomeEvidence,projectOutcomeEvidence} from '../claude-code/client/kovya-phase-authority.mjs';
const operations=new AsyncLocalStorage(),receipts=new WeakMap();
const own=(v,k)=>{try{return Object.getOwnPropertyDescriptor(v,k)?.value;}catch{return undefined;}};
export const operationTerminalReceipt=value=>value&&typeof value==='object'?receipts.get(value)?.selected:undefined;
// Read-only observation is bound before native admission settles. It never
// grants the recorder a ticket, prepares a writer, or extends a Work deadline.
export function bindTerminalDeadline(until){const context=operations.getStore();if(context&&Number.isFinite(until))context.observedUntil=until;}
export function terminalWorkContext(ticket,until,metadata){
 const context=operations.getStore();if(!context)return null;
 const eligible=metadata?.phase==='local_acceptance'||!['connect','finish'].includes(context.metadata.operation);
 return {async prepare(value,error,details){
  if(metadata?.terminal_candidate?.(value,error)===false)return false;
  const early=metadata?.phase==='local_preparation'&&(error||own(value,'terminal')!==undefined);
  if(!eligible&&!early)return false;
  if(context.work!==null&&context.work!==ticket)return false;
  context.work=ticket;context.until=until;
  return context.recorder?.prepare(ticket,{...details,phase:metadata?.phase??'terminal'})??false;
 }};
}
function semantics(value,error){
 if(error){const failure=diagnosticFailure(error);return {ok:false,state:'failed',reason:failure.reason==='unclassified'?'unexpected_public_projection':failure.reason,phase:failure.stage==='unknown'?'public_projection':failure.stage};}
 let body=value;
 if(own(value,'jsonrpc')==='2.0'){
  const result=own(value,'result');try{body=JSON.parse(own(own(result,'content')?.[0],'text'));}catch{body={ok:!own(value,'error')&&!own(result,'isError')};}
 }
 const ok=own(body,'ok')===true;
 return {ok,state:own(body,'state')??(ok?'unknown':'failed'),reason:ok?'none':own(body,'reason')??own(body,'error_code')??'request_refused',phase:own(body,'stage')??'terminal'};
}
// Construct plain owned wire data without invoking producer getters/toJSON.
// All reflection, recursion, allocation and validation occur before commitment.
function ownedWire(value,seen=new Set()){
 if(value===null||typeof value!=="object"){
  if(typeof value==='bigint'||typeof value==='function'||typeof value==='symbol')throw new Error('unexpected_public_projection');
  return typeof value==='number'&&!Number.isFinite(value)?null:value;
 }
 if(seen.has(value))throw new Error('unexpected_public_projection');seen.add(value);
 const descriptors=Object.getOwnPropertyDescriptors(value),array=Array.isArray(value),copy=array?[]:{};
 for(const [key,descriptor] of Object.entries(descriptors)){
  if(!descriptor.enumerable)continue;
  if(!Object.hasOwn(descriptor,'value'))throw new Error('unexpected_public_projection');
  const child=ownedWire(descriptor.value,seen);
  if(child!==undefined)Object.defineProperty(copy,key,{value:child,enumerable:true,writable:false,configurable:false});
 }
 if(array)copy.length=descriptors.length.value;
 seen.delete(value);return Object.freeze(copy);
}
function preparedReturn(value,error,failed,context){
 const wire=failed?undefined:ownedWire(value),decision=Object.freeze(semantics(wire,failed?error:null)),cell={selected:null};
 const variants={};
 const cutoff=failed?diagnosticFailure(error).deadline:undefined;
 const expired=cutoff?.scope==='request'||(context.observedUntil!==null&&performance.now()>=context.observedUntil);
 for(const status of ['recorded','diagnostic_unavailable','disabled']){
  const receipt=Object.freeze({terminal:decision,operation_outcome:decision.ok?'succeeded':'failed',status,terminal_record:status==='recorded'?'recorded':'unavailable',terminal_record_reason:status==='recorded'?'none':status==='disabled'?'logging_disabled':'terminal_unavailable',writer_gap:status==='recorded'?'none':status==='disabled'?'logging_disabled':expired?'expired':context.work===null?'not_prepared':'unavailable',...(cutoff?{cutoff}:{})});
  let output=wire;
  if(wire&&typeof wire==='object'&&wire.jsonrpc!=='2.0')output=Object.freeze({...wire,ok:decision.ok,...(wire.state!==undefined?{state:decision.state}:{}),diagnostics:Object.freeze({...wire.diagnostics,...receipt})});
  JSON.stringify(output);
  if(output&&typeof output==='object'){
   if(hasOutcomeEvidence(value))finishStageSync('evidence_association',()=>attachOutcomeEvidence(output,projectOutcomeEvidence(value)));
   receipts.set(output,cell);
  }
  variants[status]=Object.freeze({output,receipt});
 }
 if(failed)receipts.set(error,cell);
 return {decision,cell,variants,error,failed};
}
export async function runTerminalOperation(metadata,work){
 if(operations.getStore())return work();
 const context={metadata,work:null,until:null,observedUntil:null,recorder:createProfileTerminalOperation(metadata.operation,metadata.event_id??'-')};
 return operations.run(context,async()=>{
  let value,error,failed=false;
  try{value=await work();}catch(cause){error=cause;failed=true;}
  // The original Work timer bounds settlement; this owner grants no new Work.
  let prepared;
  try{prepared=finishStageSync('public_projection',()=>preparedReturn(value,error,failed,context));}
  catch(cause){
   error=cause;failed=true;
   // No producer data is consulted by the safe failure projection.
   prepared=preparedReturn(undefined,error,true,context);
  }
  const unavailable=prepared.variants.diagnostic_unavailable,disabled=prepared.variants.disabled,recorded=prepared.variants.recorded;
  const off=diagnosticLogLevel()==='off';
  let selected=off?disabled:unavailable;
  // Every public object, receipt and association already exists. The private
  // cell selects an immutable receipt without mutating the producer/error.
  try{if(!off&&context.recorder&&context.until!==null&&performance.now()<context.until&&await context.recorder.commit(prepared.decision))selected=recorded;}
  catch{/* Observation failure selects the prebuilt unavailable receipt. */}
  finally{try{context.recorder?.close();}catch{selected=off?disabled:unavailable;}}
  prepared.cell.selected=selected.receipt;
  if(prepared.failed)throw prepared.error;
  return selected.output;
 });
}
