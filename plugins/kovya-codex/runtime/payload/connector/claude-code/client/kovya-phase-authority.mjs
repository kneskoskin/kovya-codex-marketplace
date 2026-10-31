// Protocol observations are scoped to one authenticated private request. This
// module grants no Work, filesystem, account, or retry authority.
import {AsyncLocalStorage} from 'node:async_hooks';
const phases=new AsyncLocalStorage();
const refuse=()=>Object.assign(new Error('broker_native_protocol_refused'),{code:'broker_native_protocol_refused'});
const decimal=/^[1-9][0-9]{0,19}$/u,hex=/^[a-f0-9]{64}$/u,uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
export function decodePhaseRequest(bytes,instance){
 const end=bytes.indexOf(10);if(end<0||end>1024)throw refuse();
 const line=bytes.subarray(0,end).toString('ascii'),fields=line.split('\t');
 if(fields.length!==8||fields[0]!=='KOVYA_REQUEST_V2'||!hex.test(fields[1])||!uuid.test(fields[2])||!decimal.test(fields[3])||!decimal.test(fields[4])||!['capture','hello','recall','shutdown','status','turn_prompt'].includes(fields[5])||fields[6]!==instance||!decimal.test(fields[7])||!Buffer.from(line,'ascii').equals(bytes.subarray(0,end)))throw refuse();
 return Object.freeze({tuple:fields.slice(1).join('\t'),attempt:fields[1],requestId:fields[2],clientWork:fields[3],generation:fields[4],operation:fields[5],instance:fields[6],deadline:fields[7],body:Buffer.from(bytes.subarray(end+1))});
}
export function createServerPhases(envelope,send,remaining,owner={}){
 let server='-',sequence=0,stage='sent',account=0,memory=0,sealed=false,failed=false,readOwner=null;
 const live=()=>{if(failed||sealed||remaining()<1)throw Object.assign(new Error('broker_deadline_refused'),{code:'broker_deadline_refused'});};
 const frame=(next,reason,terminal,body=Buffer.alloc(0))=>{
  if(++sequence>32)throw refuse();
  const effect=account+memory?'possible':'none';
  return Buffer.concat([Buffer.from(`KOVYA_PHASE_V2\t${envelope.tuple}\t${server}\t${sequence}\t${next}\t${reason}\t${account}\t${memory}\t${effect}\t${terminal?1:0}\n`),body]);
 };
 const emit=async next=>{live();const bytes=frame(next,'none',false);try{await send(bytes);live();stage=next;}catch(error){failed=true;throw error;}};
 const api=Object.freeze({
  envelope,remaining:()=>{live();return remaining();},
  async bind(ticket){if(stage!=='sent'||!decimal.test(ticket))throw refuse();server=ticket;readOwner=owner.bind?.(envelope.tuple);await emit('received');},
  async admit(){if(stage==='received'){owner.observe?.('admitted');await emit('admitted');}else if(!['admitted','started'].includes(stage))throw refuse();},
  async submit(kind,work){
   live();if(!['admitted','started'].includes(stage)||!['account','memory'].includes(kind))throw refuse();
   // Fetch invocation, including an uncertain synchronous failure, is the
   // owning submission observation. Admission alone never increments counts.
   owner.observe?.(kind+'_pending');
   let result;try{result=Promise.resolve(work());}catch(error){result=Promise.reject(error);}result.catch(()=>{});
   owner.observe?.(kind);if(kind==='account')account++;else memory++;
   if(account>8||memory>8){failed=true;throw refuse();}
   await emit('started');return result;
  },
  finish(body){
   if(sealed)throw refuse();
   if(remaining()<1){sealed=true;body.fill(0);return null;}
   const response=JSON.parse(body.toString('utf8'));
   const reason=response.ok===false?response.error_code:'none';if(!/^[a-z][a-z0-9_]{0,79}$/u.test(reason??''))throw refuse();
   const observed=typeof readOwner==='function'?readOwner():null;
   sealed=true;
   if(observed?.role!=='server'||observed?.counts_complete!==true){body.fill(0);return null;}
   account=observed.account_send_count;memory=observed.memory_send_count;
   const next=reason==='broker_deadline_refused'&&stage==='received'?'refused_queue':'terminal';
   return frame(next,reason,true,body);
  },
  snapshot:()=>projectOutcomeEvidence(typeof readOwner==='function'?readOwner():null,'server')
 });return api;
}
export const runServerPhases=(phase,work)=>phases.run(phase,work);
export const admitServerPhase=()=>phases.getStore()?.admit();
export const submitServerEffect=(kind,work)=>phases.getStore()?.submit(kind,work)??work();

// Native owners create evidence. Copy/render boundaries can preserve a validated
// envelope, but neither a role label nor a terminal flag establishes a fact.
const own=(value,key)=>{try{return Object.getOwnPropertyDescriptor(value,key)?.value;}catch{return undefined;}};
const roles=new Set(['client','server','unbound_local']);
const operations=new Set('capture recall hello status shutdown turn_prompt'.split(' '));
const stages=new Set('sent received admitted started terminal refused_arrival refused_queue'.split(' '));
const reason=value=>typeof value==='string'&&/^[a-z][a-z0-9_]{0,79}$/u.test(value)?value:null;
const count=value=>Number.isInteger(value)&&value>=0&&value<=8?value:null;
const workId=value=>typeof value==='string'&&decimal.test(value)?value:null;
const branded=new WeakSet(), associated=new WeakMap();
const object=value=>value!==null&&(typeof value==='object'||typeof value==='function');
export const hasOutcomeEvidence=value=>object(value)&&(associated.has(value)||own(value,'phase_observation')!==undefined);
export function validOutcomeCorrelation(value){
 if(typeof value!=='string')return false;
 const f=value.split('\t');
 return f.length===7&&hex.test(f[0])&&uuid.test(f[1])&&decimal.test(f[2])&&decimal.test(f[3])&&operations.has(f[4])&&/^[a-f0-9]{32}$/u.test(f[5])&&decimal.test(f[6]);
}
function unknown(role='unknown',operation=null){return {
 schema_version:'kovya.outcome.v3',role,operation:operations.has(operation)?operation:null,
 owner_work:null,correlation:null,server_work:null,sequence:null,origin:'unqualified',
 last_verified_phase:'unknown',dispatch_submitted:null,no_dispatch_proven:null,
 terminal_observed:null,terminal_sealed:null,terminal_reason:null,server_reason:null,
 account_send_count:null,memory_send_count:null,counts_complete:false,effect_certainty:'unknown',
 retry_may_duplicate:operation==='capture'?true:null,saved:null,delivered:null,dropped:null,
 cleanup_confirmed:null,logging_status:'unknown',diagnostic_completion:'unconfirmed',peer_server:null,proof:null
};}
function seal(value){if(value.peer_server)Object.freeze(value.peer_server);if(value.proof)Object.freeze(value.proof);Object.freeze(value);branded.add(value);return value;}
// Each closure binds one role and one Work. A snapshot from another native owner
// is ignored even when its tuple, terminal flag, or numeric counts look valid.
export function createOutcomeOwner(role,operation){
 if(!roles.has(role))throw refuse();let ticket=null;
 return Object.freeze({
  bind(value){if(ticket!==null||!workId(value))throw refuse();ticket=value;},
  snapshot(raw,cleanup=false){
   const value=unknown(role,operation);value.owner_work=ticket;
   value.origin=role==='unbound_local'?'local_owner':`native_${role}`;
   value.cleanup_confirmed=cleanup===true&&ticket!==null?true:null;value.diagnostic_completion=value.cleanup_confirmed===true?'confirmed':'unconfirmed';
   const native=own(raw,'role')===role&&own(raw,'owner_work')===ticket&&ticket!==null;
   if(native&&role!=='unbound_local'){
    value.operation=operations.has(own(raw,'operation'))?own(raw,'operation'):value.operation;
    value.logging_status=['recorded','disabled','unavailable'].includes(own(raw,'logging_status'))?own(raw,'logging_status'):'unknown';
    const correlated=validOutcomeCorrelation(own(raw,'correlation'));
    value.correlation=correlated?own(raw,'correlation'):null;
    value.sequence=Number.isSafeInteger(own(raw,'sequence'))&&own(raw,'sequence')>=0?own(raw,'sequence'):null;
    value.server_work=workId(own(raw,'server_work'));
    if(role==='client'){
     const fenced=own(raw,'no_dispatch_proven')===true;
     const terminal=correlated&&own(raw,'terminal_observed')===true&&(value.server_work!==null||own(raw,'last_verified_phase')==='refused_arrival');
     value.dispatch_submitted=fenced?false:own(raw,'dispatch_submitted')===true?true:null;
     value.no_dispatch_proven=fenced?true:null;
     value.last_verified_phase=fenced?'never_sent':stages.has(own(raw,'last_verified_phase'))?own(raw,'last_verified_phase'):'unknown';
     value.terminal_observed=terminal?true:correlated?false:null;
     value.terminal_reason=terminal?reason(own(raw,'terminal_reason')):null;
     value.server_reason=terminal?reason(own(raw,'server_reason')):null;
     const a=terminal?count(own(raw,'account_send_count')):null,m=terminal?count(own(raw,'memory_send_count')):null;
     value.counts_complete=fenced||(terminal&&a!==null&&m!==null);
     value.account_send_count=fenced?0:value.counts_complete?a:null;
     value.memory_send_count=fenced?0:value.counts_complete?m:null;
     if(terminal)value.peer_server={role:'server',origin:'authenticated_terminal',correlation:value.correlation,server_work:value.server_work,sequence:value.sequence,account_send_count:a,memory_send_count:m,counts_complete:value.counts_complete};
     value.effect_certainty=fenced?'none':value.dispatch_submitted===true?'possible':'unknown';
     value.proof={kind:'native_client',dispatch_fenced:fenced,terminal_received:terminal,counts_complete:value.counts_complete};
    }else{
     const closed=correlated&&own(raw,'terminal_sealed')===true;
     const complete=closed&&own(raw,'counts_complete')===true;
     value.last_verified_phase=correlated&&stages.has(own(raw,'last_verified_phase'))?own(raw,'last_verified_phase'):'unknown';
     value.terminal_sealed=closed?true:correlated?false:null;
     value.server_reason=closed?reason(own(raw,'server_reason')):null;
     const a=complete?count(own(raw,'account_send_count')):null,m=complete?count(own(raw,'memory_send_count')):null;
     value.counts_complete=complete&&a!==null&&m!==null;
     value.account_send_count=value.counts_complete?a:null;value.memory_send_count=value.counts_complete?m:null;
     value.effect_certainty=value.counts_complete&&a===0&&m===0?'none':['admitted','started','terminal'].includes(value.last_verified_phase)?'possible':'unknown';
     value.proof={kind:'native_server',admission_closed:closed,counts_complete:value.counts_complete};
    }
   }
   if(value.operation==='capture')value.retry_may_duplicate=value.counts_complete&&value.memory_send_count===0?false:true;
   else value.retry_may_duplicate=value.operation!==null?false:null;
   return seal(value);
  }
 });
}
// A public envelope has fixed fields and must remain in its original namespace.
// Unqualified V2/legacy objects cannot acquire positive facts during rendering.
export function projectOutcomeEvidence(input,expectedRole=null){
 const nested=object(input)?associated.get(input)??own(input,'phase_observation'):undefined;if(nested&&branded.has(nested))input=nested;
 if(!input||!branded.has(input))return seal(unknown(expectedRole??'unknown',own(input,'operation')));
 if(expectedRole&&input.role!==expectedRole)return seal(unknown(expectedRole,input.operation));
 return input;
}
export function deserializeOutcomeEvidence(input,expectedRole=null){
 const role=own(input,'role'),operation=own(input,'operation');
 if(own(input,'schema_version')!=='kovya.outcome.v3'||!roles.has(role)||(expectedRole&&role!==expectedRole))return seal(unknown(expectedRole??'unknown',operation));
 if(branded.has(input))return input;
 const value=unknown(role,operation),ticket=workId(own(input,'owner_work')),proof=own(input,'proof');
 const correlated=validOutcomeCorrelation(own(input,'correlation'));
 value.owner_work=ticket;value.correlation=correlated?own(input,'correlation'):null;
 value.server_work=workId(own(input,'server_work'));
 value.sequence=Number.isSafeInteger(own(input,'sequence'))&&own(input,'sequence')>=0?own(input,'sequence'):null;
 const ingress=role==='server'&&correlated&&own(input,'last_verified_phase')==='refused_arrival'&&own(input,'server_work')===null&&own(proof,'kind')==='native_ingress'&&own(proof,'admission_closed')===true&&own(proof,'counts_complete')===true&&own(input,'terminal_sealed')===true&&own(input,'counts_complete')===true&&own(input,'account_send_count')===0&&own(input,'memory_send_count')===0&&own(input,'server_reason')==='broker_deadline_refused';
 if(ingress)return seal({...value,origin:'native_ingress',last_verified_phase:'refused_arrival',terminal_sealed:true,server_reason:'broker_deadline_refused',counts_complete:true,account_send_count:0,memory_send_count:0,effect_certainty:'none',retry_may_duplicate:false,logging_status:'recorded',proof:{kind:'native_ingress',admission_closed:true,counts_complete:true}});
 if(!ticket)return seal(value);
 if(correlated&&((role==='client'&&value.correlation.split('\t')[2]!==ticket)||(role==='server'&&value.server_work!==ticket)))return seal(unknown(role,operation));
 const client=role==='client'&&own(proof,'kind')==='native_client';
 const server=role==='server'&&own(proof,'kind')==='native_server';
 const fenced=client&&own(proof,'dispatch_fenced')===true&&own(input,'no_dispatch_proven')===true&&own(input,'dispatch_submitted')===false;
 const terminal=client&&correlated&&(value.server_work!==null||own(input,'last_verified_phase')==='refused_arrival')&&own(proof,'terminal_received')===true&&own(input,'terminal_observed')===true;
 const closed=server&&correlated&&own(proof,'admission_closed')===true&&own(input,'terminal_sealed')===true;
 const a=count(own(input,'account_send_count')),m=count(own(input,'memory_send_count'));
 value.counts_complete=(fenced||terminal||closed)&&own(proof,'counts_complete')===true&&own(input,'counts_complete')===true&&a!==null&&m!==null;
 value.account_send_count=value.counts_complete?a:null;value.memory_send_count=value.counts_complete?m:null;
 value.no_dispatch_proven=fenced?true:null;value.dispatch_submitted=client?(fenced?false:own(input,'dispatch_submitted')===true?true:null):null;
 value.last_verified_phase=fenced?'never_sent':correlated&&stages.has(own(input,'last_verified_phase'))?own(input,'last_verified_phase'):'unknown';
 value.terminal_observed=client?(terminal?true:correlated?false:null):null;
 value.terminal_sealed=server?(closed?true:correlated?false:null):null;
 value.terminal_reason=terminal?reason(own(input,'terminal_reason')):null;
 value.server_reason=terminal||closed?reason(own(input,'server_reason')):null;
 value.effect_certainty=value.counts_complete&&a===0&&m===0?'none':value.dispatch_submitted===true||(server&&['admitted','started','terminal'].includes(value.last_verified_phase))?'possible':'unknown';
 value.retry_may_duplicate=value.operation==='capture'?value.counts_complete&&m===0?false:true:value.operation!==null?false:null;
 value.cleanup_confirmed=own(input,'cleanup_confirmed')===true?true:null;value.diagnostic_completion=value.cleanup_confirmed===true?'confirmed':'unconfirmed';
 value.logging_status=['recorded','disabled','unavailable'].includes(own(input,'logging_status'))?own(input,'logging_status'):'unknown';
 value.origin=client?'native_client':server?'native_server':role==='unbound_local'?'local_owner':'unqualified';
 value.proof=client?{kind:'native_client',dispatch_fenced:fenced,terminal_received:terminal,counts_complete:value.counts_complete}:server?{kind:'native_server',admission_closed:closed,counts_complete:value.counts_complete}:null;
 if(terminal)value.peer_server={role:'server',origin:'authenticated_terminal',correlation:value.correlation,server_work:value.server_work,sequence:value.sequence,account_send_count:value.account_send_count,memory_send_count:value.memory_send_count,counts_complete:value.counts_complete};
 return seal(value);
}
export function attachOutcomeEvidence(error,value){
 if(object(error))associated.set(error,projectOutcomeEvidence(value));return error;
}
export function correlateOutcomeReceipt(client,server){
 const c=projectOutcomeEvidence(client,'client'),s=projectOutcomeEvidence(server,'server');
 const matched=c.correlation!==null&&c.correlation===s.correlation&&(!c.server_work||c.server_work===s.server_work);
 return Object.freeze({client:c,server:s,gap:matched?'correlated_separate_owners':'correlation_unavailable_or_mismatch'});
}

