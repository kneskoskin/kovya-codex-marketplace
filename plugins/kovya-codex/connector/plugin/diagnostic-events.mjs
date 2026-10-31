import {COLD_PATH_WORK_MS} from "./request-budget.mjs";
// Safe, bounded observations only. This module performs no filesystem, network,
// credential or recovery action and cannot create or extend native work authority.
import {projectOutcomeEvidence,attachOutcomeEvidence,deserializeOutcomeEvidence,hasOutcomeEvidence} from "../claude-code/client/kovya-phase-authority.mjs";
import {AsyncLocalStorage} from "node:async_hooks";
import {randomUUID,createHash} from "node:crypto";

const networkCaptures=new AsyncLocalStorage();
const traces=new AsyncLocalStorage(), failures=new WeakMap(), deadlines=new WeakMap(),serverFailures=new WeakMap();
const attemptPattern=/^[a-f0-9]{64}(?![\s\S])/u;
const uuidPattern=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}(?![\s\S])/u;
const serverReasons=new Set("none unavailable consumer_query_error consumer_record_invalid consumer_absent consumer_revoked issuer_consumer_lookup issuer_grant_context issuer_namespace_lookup issuer_routing_ambiguous issuer_clock issuer_entropy issuer_recovery_seal issuer_session_store issuer_unknown dependency_failed request_failed request_refused google_admission_refused google_state_refused google_exchange_refused google_account_refused".split(" "));
export const serverDiagnosticReason=value=>typeof value==="string"&&serverReasons.has(value)?value:"unknown";
export const diagnosticLogLevel=()=>["verbose","summary","errors","off"].includes(process.env.KOVYA_AUTH_LOG_LEVEL)?process.env.KOVYA_AUTH_LOG_LEVEL:"verbose";
export const diagnosticRecordEnabled=(record,level=diagnosticLogLevel())=>level!=="off"&&(level==="verbose"||["failed","refused"].includes(record.outcome)||level==="summary"&&["start","end"].includes(record.event));
// Opaque join key derived from an existing private transport ID. Not authority.
export function memoryDiagnosticEventId(requestId){return typeof requestId==="string"&&uuidPattern.test(requestId)?createHash("sha256").update("kovya-memory-event-v1\0"+requestId).digest("hex"):"unknown";}
export const currentMemoryDiagnosticEventId=()=>traces.getStore()?.memory_event_id??"unknown";
export function diagnosticAttemptId(requestId){return typeof requestId==="string"&&requestId.length>=16&&requestId.length<=160&&!/[\0\r\n]/u.test(requestId)?createHash("sha256").update("kovya-auth-attempt-v1\0"+requestId).digest("hex"):"unknown";}
export function bindDiagnosticAttempt(requestId,metadata={}){
 const attempt_id=diagnosticAttemptId(requestId);if(attempt_id==="unknown")return attempt_id;
 const fields={attempt_id,expires_at:diagnosticTime(own(metadata,"expires_at")),attempt_created_at:diagnosticTime(own(metadata,"created_at"))};
 traces.getStore()?.bind(fields);networkCaptures.getStore()?.emit({stage:"request",...fields});return attempt_id;
}
export function noteServerDiagnostic(error,reason,attemptId){if(!object(error))return;const diagnostic_reason=serverDiagnosticReason(reason);if(diagnostic_reason!=="unknown"||attemptPattern.test(attemptId??""))serverFailures.set(error,Object.freeze({...diagnostic_reason!=="unknown"?{diagnostic_reason}:{},...attemptPattern.test(attemptId??"")?{attempt_id:attemptId}:{}}));}
const deadlineConsumers=new Set("native_work_admission request_dispatch diagnostic_start_append account_worker_start account_lease local_preparation authorization_request local_acceptance request_cleanup worker_stop diagnostic_finalize native_work_end".split(" "));
export const isDiagnosticDeadlineConsumer=value=>deadlineConsumers.has(value);
// Only fixed observations are retained; this grants no work/write authority.
export function noteDiagnosticDeadline(error,value) {
  if(!object(error)||deadlines.has(error)||value?.scope!=="request"||!deadlineConsumers.has(value.consumer)
    ||!Number.isFinite(value.elapsed_ms)||value.elapsed_ms<0||!Number.isFinite(value.budget_ms)||value.budget_ms<0||value.budget_ms>COLD_PATH_WORK_MS)return;
  deadlines.set(error,Object.freeze({scope:"request",consumer:value.consumer,elapsed_ms:value.elapsed_ms,budget_ms:value.budget_ms,
    ...(value.stage!==undefined?{stage:stages.has(value.stage)?value.stage:"unknown"}:{}),
    ...(value.cleanup!==undefined?{cleanup:["pending","confirmed","failed"].includes(value.cleanup)?value.cleanup:"pending"}:{}),
    ...(value.writer_gap!==undefined?{writer_gap:["expired","logging_disabled","unavailable"].includes(value.writer_gap)?value.writer_gap:"unavailable"}:{})}));
}
const set=words=>new Set(words.split(" "));
export function noteAuthenticationDeadline(error,value){
 if(!object(error)||deadlines.has(error)||value?.scope!=="authentication"||value.budget_ms!==30000
   ||!Number.isFinite(value.elapsed_ms)||value.elapsed_ms<0||!["authorization_request","token_exchange"].includes(value.consumer))return;
 deadlines.set(error,Object.freeze({scope:"authentication",consumer:value.consumer,elapsed_ms:value.elapsed_ms,budget_ms:30000}));
}
const operations=set("connect finish status repair logout worker mcp broker unknown");
const hosts=set("codex claude_code unknown");
const stages=set("launch native_entrypoint bootstrap_self_pin native_launch startup_selection startup_custody startup_readiness admission identity wait dispatch cleanup_entry broker request journal_publication signing_key_staging signing_key_readback browser_secret_staging browser_secret_readback binding_publication credential_witness response_acceptance protected_input ingress framing operation_result cleanup attempt_binding unknown");
for(const stage of ["broker_starter_spawn","broker_starter_reply","broker_starter_verified","broker_starter_disposal"])stages.add(stage);
for(const stage of "native_request_write native_response_read native_close native_frame_validation profile_exchange_begin profile_pipe_connected profile_peer_verified profile_preamble_done profile_request_written profile_response_first_byte profile_response_complete profile_exchange_terminal native_host_policy broker_request_read broker_dispatch broker_response_encode".split(" "))stages.add(stage);
const transportReasons=set("native_frame_empty native_frame_header_truncated native_frame_length_invalid native_frame_oversized native_frame_truncated native_frame_trailing native_frame_non_json native_frame_noncanonical native_frame_encoding native_request_invalid native_response_request_id_mismatch native_response_binding_mismatch native_pipe_closed native_child_exited native_child_signalled native_work_expired native_transport_timeout");
const phases=set("prepared remote_in_flight remote_ambiguous manual_start_pending manual_required manual_exchange_pending local_write_failed local_commit_cleanup_pending local_committed_cleanup_pending browser_pending unknown");
const states=set("unknown pending ambiguous failed refused unavailable runtime_invalid runtime_missing runtime_configuration_required arguments_invalid sign_in_required session_present connected signed_out approval_required manual_required platform_unavailable release_account_mismatch cancelled skipped saved recalled session_released capture_unconfirmed recall_unavailable recall_unverified timeout");
const reasons=set("unclassified none profile_account_unavailable profile_account_exited profile_account_control_eof mcp_frame_invalid worker_input_invalid broker_unavailable broker_cold_start broker_start_cooldown broker_frame_invalid broker_runtime_incompatible profile_work_owner_required profile_diagnostic_cleanup_uncertain bootstrap_self_pin_refused native_admission_digest account_state_conflict transaction_scope_invalid credential_readback_failed credential_write_failed credential_read_failed credential_delete_failed signing_key_invalid pending_secret_readback_failed result_stage_ambiguous state_write_failed state_changed state_invalid state_path_refused transaction_pending deadline_expired broker_deadline_refused profile_startup_timeout profile_work_ended profile_cleanup_uncertain runtime_startup_timeout runtime_startup_refused runtime_launch_refused runtime_missing runtime_configuration_required runtime_setup_unconfirmed protected_input_required protected_input_invalid protected_input_timeout remote_ambiguous redirect_refused response_invalid start_response_invalid authorization_refused request_refused transport_unavailable release_account_mismatch callback_cancelled refresh_ambiguous");
for(const stage of "memory_account_provider memory_request_build memory_http_dispatch memory_connect memory_response_headers memory_first_body_byte memory_body_read memory_response_body".split(" "))stages.add(stage);
for(const reason of "memory_account_provider_failed memory_request_build_failed memory_http_failed memory_body_read_failed".split(" "))reasons.add(reason);
export const BROWSER_EXCHANGE_REFUSAL_REASONS=Object.freeze(["code_invalid","code_expired","code_consumed","transaction_state","bad_request_shape","store_refused","issuer_failed","cipher_failed","internal_error"]);
for(const reason of BROWSER_EXCHANGE_REFUSAL_REASONS)reasons.add(reason);
export function browserExchangeRefusalReason(payload) {
  if(!payload||typeof payload!=="object"||Array.isArray(payload))return "authorization_refused";
  const value=Object.getOwnPropertyDescriptor(payload,"reason")?.value;
  return typeof value==="string"&&BROWSER_EXCHANGE_REFUSAL_REASONS.includes(value)?value:"authorization_refused";
}
const journals=new Set(["windows-device-auth.json","windows-device-auth.json.previous","state/device-auth/pending.json","state/device-auth/pending.json.previous","state/device-auth/browser-pending.json"]);
reasons.add("authentication_deadline_refused");reasons.add("broker_outcome_unknown");
reasons.add("broker_native_transport_failed");
for(const reason of transportReasons)reasons.add(reason);
for(const reason of ["broker_native_frame_invalid","broker_native_exchange_timeout","broker_native_transport_failed","broker_response_invalid"])reasons.add(reason);
// Fixed classifications for the frozen manual response-acceptance boundary.
for(const reason of "unexpected_acceptance result_invalid access_invalid refresh_invalid start_expiry_invalid journal_invalid authorization_origin_mismatch authorization_url_invalid transaction_missing_or_expired request_id_invalid public_key_invalid device_label_invalid manifest_path_invalid manifest_invalid value_invalid origin_invalid credential_target_refused journal_secret_refused account_interaction_required broker_native_identity_refused broker_native_protocol_refused broker_native_exited authority_mismatch pending_secret_changed pending_code_mismatch".split(" "))reasons.add(reason);
const own=(value,key)=>{try{const d=Object.getOwnPropertyDescriptor(value,key);return d&&Object.hasOwn(d,"value")?d.value:undefined;}catch{return undefined;}};
const pick=(choices,value,fallback="unknown")=>typeof value==="string"&&choices.has(value)?value:fallback;
const object=value=>value!==null&&(typeof value==="object"||typeof value==="function");
stages.add("terminal_pending");
const finishStages=new Set(["protected_input", "state_binding", "credential_witness", "signing_key_read", "signing_key_validate", "exchange_prepare", "exchange_journal", "exchange_http", "exchange_response_validate", "browser_result_accept", "final_signing_write_readback", "final_refresh_write_readback", "manifest_publish", "commit_journal_publish", "retired_key_cleanup", "access_result_construct", "browser_pending_retire", "pending_journal_retire", "lock_lease_release", "worker_cleanup", "request_cleanup", "native_end", "evidence_association", "public_projection", "terminal_observation"]);
for(const stage of finishStages){stages.add(stage);reasons.add("unexpected_"+stage);}
export async function finishStage(stage,work){
 if(!finishStages.has(stage))throw new Error("unexpected_public_projection");
 try{return await work();}catch(error){throw classifyDiagnosticError(error,"unexpected_"+stage,stage);}
}
export function finishStageSync(stage,work){
 if(!finishStages.has(stage))throw new Error("unexpected_public_projection");
 try{return work();}catch(error){throw classifyDiagnosticError(error,"unexpected_"+stage,stage);}
}
export function diagnosticReason(error) {
  for(const key of ["reason","code","message"]) {const value=own(error,key);if(reasons.has(value))return value;}
  return "unclassified";
}
export function classifyDiagnosticError(error,fallback="unexpected_acceptance",stage="response_acceptance") {
  if(!object(error))error=new Error("Kovya operation failed.");
  const prior=diagnosticFailure(error);
  if(prior.reason==="unclassified")failures.set(error,Object.freeze({reason:pick(reasons,fallback,"unexpected_acceptance"),stage:prior.stage==="unknown"?pick(stages,stage):prior.stage}));
  return error;
}
export async function diagnosticAcceptance(work) {
  try{return await work();}catch(error){throw classifyDiagnosticError(error);}
}
// One immutable, sanitized observation crosses the no-Work network interval.
// A late transport continuation cannot change a sealed observation or append.
export async function captureDiagnosticNetwork(route,work) {
  const started=performance.now();let active=true,last={request_outcome:"not_dispatched",http_status:null},value,error;
  const emit=fields=>{if(active&&fields.stage==="request")last=sanitizeDiagnosticRecord({...last,...fields});};
  try{value=await networkCaptures.run({emit},work);}catch(cause){error=classifyDiagnosticError(cause,"response_invalid","request");}
  finally{active=false;}
  const safe=sanitizeDiagnosticRecord({...last,route,stage:"request",elapsed_ms:Math.max(0,performance.now()-started),outcome:error?"failed":"succeeded",reason:error?diagnosticFailure(error).reason:"none"});
  const observation=Object.freeze(Object.fromEntries(["route","stage","http_status","request_outcome","elapsed_ms","outcome","reason","attempt_id","diagnostic_reason","expires_at","attempt_created_at","transaction_age_ms"].map(key=>[key,safe[key]])));
  return Object.freeze({value,error,observation});
}
export function diagnosticFailure(error) {
  const result=object(error)&&failures.has(error)?{...failures.get(error)}:{reason:diagnosticReason(error),stage:"unknown"};
  if(object(error)&&serverFailures.has(error))Object.assign(result,serverFailures.get(error));
  if(object(error)&&(hasOutcomeEvidence(error)||error.code==='broker_outcome_unknown'))Object.assign(result,phaseObservation(projectOutcomeEvidence(error)));
  return object(error)&&deadlines.has(error)?{...result,deadline:deadlines.get(error)}:result;
}
export function propagateDiagnosticFailure(cause,error) {
  if(object(cause)&&object(error)&&(hasOutcomeEvidence(cause)||cause.code==="broker_outcome_unknown"))attachOutcomeEvidence(error,projectOutcomeEvidence(cause));
  if(object(cause)&&object(error)&&failures.has(cause))failures.set(error,failures.get(cause));
  if(object(cause)&&object(error)&&serverFailures.has(cause))serverFailures.set(error,serverFailures.get(cause));
  if(object(cause)&&object(error)&&deadlines.has(cause))deadlines.set(error,deadlines.get(cause));
  return error;
}
function noteFailure(error,stage) {
  if(object(error)&&!failures.has(error))failures.set(error,Object.freeze({reason:diagnosticReason(error),stage:pick(stages,stage)}));
}
export function diagnosticTime(value) {
  if(typeof value!=="string"||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))return null;
  const time=Date.parse(value);return Number.isFinite(time)&&new Date(time).toISOString()===value?value:null;
}
export function diagnosticRecovery(value) {
  return {phase:pick(phases,own(value,"phase")),recovery_expires_at:diagnosticTime(own(value,"recovery_expires_at")),attempt_created_at:diagnosticTime(own(value,"created_at"))};
}
export function phaseObservation(value){
 const evidence=projectOutcomeEvidence(value);
 return {...evidence,phase_observation:evidence,server_reason:pick(reasons,evidence.server_reason),
  observation_gap:evidence.terminal_observed===true?'none':'terminal_not_received'};
}
export function sanitizeDiagnosticRecord(value,options) {
  if(options?.serialized===true&&own(value,'phase_observation')!==undefined)value={...value,phase_observation:deserializeOutcomeEvidence(own(value,'phase_observation'))};
  const number=(key,max)=>{const n=own(value,key);return typeof n==="number"&&Number.isFinite(n)&&n>=0&&n<=max?n:null;};
  const id=own(value,"diagnostic_id"),names=own(value,"journals");
  return {
    ...(own(value,'last_verified_phase')!==undefined?phaseObservation(own(value,'phase_observation')??value):{}),
    schema_version:"kovya.local-diagnostic.v1",utc:diagnosticTime(own(value,"utc")),
    diagnostic_id:typeof id==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(id)?id:null,
    attempt_id:typeof own(value,"attempt_id")==="string"&&attemptPattern.test(own(value,"attempt_id"))?own(value,"attempt_id"):"unknown",
    event_id:typeof own(value,"event_id")==="string"&&attemptPattern.test(own(value,"event_id"))?own(value,"event_id"):"unknown",
    memory_event_id:typeof own(value,"memory_event_id")==="string"&&attemptPattern.test(own(value,"memory_event_id"))?own(value,"memory_event_id"):memoryDiagnosticEventId(own(value,"transport_request_id")),
    ...Object.fromEntries(["connect_ms","headers_ms","first_body_byte_ms","body_read_ms"].filter(k=>own(value,k)!==undefined).map(k=>[k,number(k,86400000)])),
    ...(own(value,"connection_observation")!==undefined?{connection_observation:pick(set("new_connection reused_or_unobserved ambiguous unknown"),own(value,"connection_observation"))}:{}),
    diagnostic_reason:serverDiagnosticReason(own(value,"diagnostic_reason")),
    request_id:typeof own(value,"request_id")==="string"&&uuidPattern.test(own(value,"request_id"))?own(value,"request_id"):null,
    span_id:typeof own(value,"span_id")==="string"&&uuidPattern.test(own(value,"span_id"))?own(value,"span_id"):null,
    expires_at:diagnosticTime(own(value,"expires_at")),transaction_age_ms:number("transaction_age_ms",86400000),
    operation:pick(operations,own(value,"operation")),host:pick(hosts,own(value,"host")),pid:number("pid",0xffffffff),
    host_event:pick(set("SessionStart UserPromptSubmit Stop SessionEnd unknown"),own(value,"host_event")),
    mcp_method:pick(set("initialize notifications/initialized ping tools/list tools/call resources/list prompts/list framing unknown"),own(value,"mcp_method")),
    event:pick(set("start end stage"),own(value,"event")),stage:pick(stages,own(value,"stage")),
    state_before:pick(states,own(value,"state_before")),state_after:pick(states,own(value,"state_after")),
    outcome:pick(set("started succeeded failed refused incomplete unknown"),own(value,"outcome")),
    reason:pick(reasons,own(value,"reason"),"unclassified"),elapsed_ms:number("elapsed_ms",86400000),
    event_elapsed_ms:number("event_elapsed_ms",86400000),
    ...(own(value,"transport_operation")!==undefined?{transport_operation:pick(set("recall capture turn_prompt hello status shutdown unknown"),own(value,"transport_operation"))}:{}),
    ...(own(value,"transport_request_id")!==undefined?{transport_request_id:typeof own(value,"transport_request_id")==="string"&&uuidPattern.test(own(value,"transport_request_id"))?own(value,"transport_request_id"):null}:{}),
    ...Object.fromEntries(["request_bytes","response_bytes","frame_expected_bytes","remaining_work_ms","transport_ceiling_ms","startup_remaining_ms","pipe_bytes_written","pipe_bytes_read","native_win32_error"].filter(k=>own(value,k)!==undefined).map(k=>[k,number(k,k==="remaining_work_ms"?15000:1073741824)])),
    ...(own(value,"native_exit_code")!==undefined?{native_exit_code:(()=>{const n=own(value,"native_exit_code");return Number.isInteger(n)&&n>=-2147483648&&n<=4294967295?n:null;})()}:{}),
    ...(own(value,"native_signal")!==undefined?{native_signal:pick(set("none SIGTERM SIGKILL SIGABRT SIGSEGV SIGBREAK unknown"),own(value,"native_signal"))}:{}),
    ...(own(value,"frame_failure")!==undefined?{frame_failure:pick(transportReasons,own(value,"frame_failure"),"none")}:{}),
    route:pick(set("browser_start browser_exchange device_sign_in device_legacy_exchange device_refresh device_logout memory_recall memory_capture unknown"),own(value,"route")),
    http_status:(()=>{const n=number("http_status",599);return Number.isInteger(n)&&n>=100?n:null;})(),
    request_outcome:pick(set("not_dispatched dispatched_no_response response_observed unknown"),own(value,"request_outcome")),
    ...diagnosticRecovery({phase:own(value,"phase"),recovery_expires_at:own(value,"recovery_expires_at"),created_at:own(value,"created_at")??own(value,"attempt_created_at")}),
    journals:Array.isArray(names)?[...new Set(names.filter(name=>journals.has(name)))].slice(0,5):[]
  };
}
export function createDiagnosticTrace({operation,host,host_event,mcp_method,networkObservation,event_id,memory_event_id,eventStarted,checkpoint}={}) {
  const started=performance.now(),id=randomUUID(),records=[];let ended=false,discarded=0;
  const eventStart=Number.isFinite(eventStarted)&&eventStarted>=0&&eventStarted<=started?eventStarted:started;
  let binding={attempt_id:own(networkObservation,"attempt_id")??"unknown",diagnostic_reason:own(networkObservation,"diagnostic_reason")??"unknown",expires_at:own(networkObservation,"expires_at"),attempt_created_at:own(networkObservation,"attempt_created_at")};
  const emit=fields=>{
    if(ended){discarded++;return;}
    const proposed=own(fields,"attempt_id");
    if(typeof proposed==="string"&&attemptPattern.test(proposed)&&(binding.attempt_id==="unknown"||binding.attempt_id===proposed))binding.attempt_id=proposed;
    const detail=serverDiagnosticReason(own(fields,"diagnostic_reason"));if(detail!=="unknown")binding.diagnostic_reason=detail;
    for(const key of ["expires_at","attempt_created_at"]){const value=diagnosticTime(own(fields,key)??(key==="attempt_created_at"?own(fields,"created_at"):null));if(value)binding[key]=value;}
    const record=sanitizeDiagnosticRecord({...fields,...binding,event_id,memory_event_id:memory_event_id??own(fields,"memory_event_id"),event_elapsed_ms:Math.max(0,performance.now()-eventStart),transaction_age_ms:binding.attempt_created_at?Math.max(0,Date.now()-Date.parse(binding.attempt_created_at)):own(fields,"transaction_age_ms"),request_id:id,span_id:own(fields,"span_id")??randomUUID(),diagnostic_id:id,operation,host,host_event,mcp_method,pid:process.pid,utc:new Date().toISOString()});
    // Reserve the last slot for the terminal record. Never retain raw values.
    if(records.length>=63&&fields.event!=="end"){discarded++;return;}
    records.push(Object.freeze(record));
    return record;
  };
  const saveCheckpoint=async fields=>{
    const record=emit({event:"stage",...fields});
    if(record&&["worker","mcp","broker"].includes(operation)&&typeof checkpoint==="function"&&diagnosticRecordEnabled(record)){
      // The sink owns admission/expiry. Logging cannot replace a product error,
      // renew its ticket, retry a refused append, or dispatch the operation twice.
      try{await checkpoint(record);}catch{}
    }
  };
  emit({stage:"ingress",outcome:"started",reason:"none",request_outcome:"not_dispatched",elapsed_ms:0,...networkObservation,event:"start"});
  return Object.freeze({
    id,observe:fields=>emit({event:"stage",...fields}),seal:()=>{ended=true;},
    run:work=>traces.run({emit,memory_event_id:attemptPattern.test(memory_event_id??"")?memory_event_id:"unknown",checkpoint:saveCheckpoint,bind:fields=>{if(ended)return;if(binding.attempt_id!=="unknown"&&binding.attempt_id!==fields.attempt_id)return;emit({...fields,stage:"attempt_binding",event:"stage",outcome:"succeeded",elapsed_ms:0,reason:"none"});}},work),
    end(result) {
      if(ended)return;
      emit({event:"end",outcome:result?.ok===true?"succeeded":"failed",reason:own(result,"reason")??"none",stage:own(result,"stage"),
        state_after:own(result,"state"),phase:own(result,"phase"),recovery_expires_at:own(result,"recovery_expires_at"),created_at:own(result,"attempt_created_at"),elapsed_ms:performance.now()-started});
      ended=true;
    },
    snapshot:()=>({records:records.map(record=>({...record,journals:[...record.journals]})),discarded,complete:ended})
  });
}
export function diagnosticObservation(fields) {networkCaptures.getStore()?.emit(fields);traces.getStore()?.emit({event:"stage",...fields});}
export async function diagnosticCheckpoint(fields){
 networkCaptures.getStore()?.emit(fields);
 const trace=traces.getStore();
 if(trace?.checkpoint)await trace.checkpoint(fields);else trace?.emit({event:"stage",...fields});
}
export async function diagnosticStage(stage,work) {
  const started=performance.now(),span_id=randomUUID();await diagnosticCheckpoint({stage,span_id,outcome:"started",reason:"none",elapsed_ms:0});
  try {const result=await work();await diagnosticCheckpoint({stage,span_id,outcome:"succeeded",reason:"none",elapsed_ms:performance.now()-started});return result;}
  catch(error){noteFailure(error,stage);await diagnosticCheckpoint({stage,span_id,outcome:"failed",reason:diagnosticFailure(error).reason,elapsed_ms:performance.now()-started});throw error;}
}
export function diagnosticStageSync(stage,work) {
  const started=performance.now(),span_id=randomUUID();diagnosticObservation({stage,span_id,outcome:"started",reason:"none",elapsed_ms:0});
  try {const result=work();diagnosticObservation({stage,span_id,outcome:"succeeded",reason:"none",elapsed_ms:performance.now()-started});return result;}
  catch(error){noteFailure(error,stage);diagnosticObservation({stage,span_id,outcome:"failed",reason:diagnosticFailure(error).reason,elapsed_ms:performance.now()-started});throw error;}
}
