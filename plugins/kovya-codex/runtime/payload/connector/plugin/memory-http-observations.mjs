// Read-only Undici observations. No dispatcher, socket, retry or deadline changes.
import {AsyncLocalStorage} from "node:async_hooks";
import {channel} from "node:diagnostics_channel";
import {diagnosticCheckpoint} from "./diagnostic-events.mjs";

const calls=new AsyncLocalStorage(),requests=new WeakMap(),connections=new WeakMap(),pending=new WeakMap();
const now=()=>performance.now();
function subscribe(name,read){channel(name).subscribe(message=>{try{read(message);}catch{/* observers never affect transport */}});}
subscribe("undici:request:create",({request})=>{const call=calls.getStore();if(call&&!call.closed)requests.set(request,call);});
subscribe("undici:client:beforeConnect",({connector})=>{
  const call=calls.getStore();if(typeof connector!=="function")return;
  // A connector is not request identity. Ambiguous overlapping attempts are discarded.
  const previous=pending.get(connector);
  if(previous){previous.count++;previous.ambiguous=true;}
  else pending.set(connector,{call,started:now(),count:1,ambiguous:false});
});
subscribe("undici:client:connected",({connector,socket})=>{
  const item=pending.get(connector);if(item&&--item.count===0)pending.delete(connector);
  if(item?.call&&socket&&!item.call.closed)connections.set(socket,{...item,elapsed:now()-item.started});
});
subscribe("undici:client:connectError",({connector})=>{const item=pending.get(connector);if(item&&--item.count===0)pending.delete(connector);});
subscribe("undici:client:sendHeaders",({request,socket})=>{
  const call=requests.get(request),connection=connections.get(socket);
  if(!call||call.closed)return;
  if(connection?.call===call){
    call.connection_observation=connection.ambiguous?"ambiguous":"new_connection";
    if(!connection.ambiguous)call.connect_ms=connection.elapsed;
  }
  connections.delete(socket);
});
subscribe("undici:request:headers",({request})=>{const call=requests.get(request);if(call&&!call.closed)call.headers_ms=now()-call.started;});
subscribe("undici:request:bodyChunkReceived",({request,chunk})=>{
  const call=requests.get(request);if(!call||call.closed)return;
  call.first_body_byte_ms??=now()-call.started;
  if(Number.isSafeInteger(chunk?.byteLength))call.response_bytes=(call.response_bytes??0)+chunk.byteLength;
});

async function checkpoint(remaining,fields){
  // Missing completion after expiry is unknown. Never ask the native writer for late authority.
  try{const left=remaining();if(Number.isFinite(left)&&left>0)await diagnosticCheckpoint({...fields,remaining_work_ms:left});}catch{}
}
export async function memoryDiagnosticStage(stage,remaining,work,fields={}){
  const started=now();
  await checkpoint(remaining,{...fields,stage,outcome:"started",reason:"none",elapsed_ms:0});
  try{const result=await work();await checkpoint(remaining,{...fields,stage,outcome:"succeeded",reason:"none",elapsed_ms:now()-started});return result;}
  catch(error){const reason=stage==="memory_account_provider"?"memory_account_provider_failed":stage==="memory_body_read"?"memory_body_read_failed":"memory_request_build_failed";
    await checkpoint(remaining,{...fields,stage,outcome:"failed",reason,elapsed_ms:now()-started});throw error;}
}
export async function observeMemoryFetch(fetch,remaining,fields={}){
  const call={started:now(),closed:false,connection_observation:"reused_or_unobserved"};
  await checkpoint(remaining,{...fields,stage:"memory_http_dispatch",outcome:"started",reason:"none",elapsed_ms:0});
  try{
    if(remaining()<=0)throw new DOMException("Memory request deadline elapsed.","TimeoutError");
    const response=await calls.run(call,fetch);
    await checkpoint(remaining,{...fields,stage:"memory_connect",outcome:call.connect_ms===undefined?"unknown":"succeeded",reason:"none",connect_ms:call.connect_ms??null,elapsed_ms:call.connect_ms??null,connection_observation:call.connection_observation});
    await checkpoint(remaining,{...fields,stage:"memory_response_headers",outcome:"succeeded",reason:"none",http_status:response.status,headers_ms:call.headers_ms??null,elapsed_ms:now()-call.started});
    const bodyStarted=now();
    return {response,async finish(bodyReadOk=true){
      if(call.closed)return;call.closed=true;
      await checkpoint(remaining,{...fields,stage:"memory_first_body_byte",outcome:call.first_body_byte_ms===undefined?"unknown":"succeeded",reason:"none",first_body_byte_ms:call.first_body_byte_ms??null,elapsed_ms:call.first_body_byte_ms??null});
      await checkpoint(remaining,{...fields,stage:"memory_response_body",outcome:bodyReadOk?"succeeded":"failed",reason:bodyReadOk?"none":"memory_body_read_failed",response_bytes:call.response_bytes??null,body_read_ms:now()-bodyStarted,elapsed_ms:now()-call.started});
    }};
  }catch(error){call.closed=true;await checkpoint(remaining,{...fields,stage:"memory_http_dispatch",outcome:"failed",reason:"memory_http_failed",elapsed_ms:now()-call.started});throw error;}
}
