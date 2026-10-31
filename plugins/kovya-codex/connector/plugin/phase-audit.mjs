// Bounded read-only access to the transition-owned fixed slot. Never enumerate
// arbitrary paths or treat an absent file as proof of zero server effects.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {createOutcomeOwner,deserializeOutcomeEvidence,projectOutcomeEvidence,validOutcomeCorrelation} from '../claude-code/client/kovya-phase-authority.mjs';

const decimal=/^[1-9][0-9]{0,19}$/u;
const stages=new Set(['received','admitted','started','terminal','refused_queue','refused_arrival']);
const same=(a,b)=>process.platform==='win32'?a.toLowerCase()===b.toLowerCase():a===b;
const identity=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
export function decodePhaseAudit(bytes,expectedCorrelation){
 if(!Buffer.isBuffer(bytes)||bytes.length!==4096||!validOutcomeCorrelation(expectedCorrelation))throw Error('phase_audit_invalid');
 let end=bytes.indexOf(0);if(end<0)end=bytes.length;
 if(bytes.subarray(end).some(byte=>byte!==0)||bytes[end-1]!==10)throw Error('phase_audit_invalid');
 const record=bytes.subarray(0,end-1);if(record.some(byte=>byte!==9&&(byte<32||byte>126)))throw Error('phase_audit_invalid');
 const f=record.toString('ascii').split('\t');
 if(f[0]==='KOVYA_AUDIT_V2'||f[0]==='KOVYA_PHASE_V2')return {status:'legacy_unqualified',evidence:null};
 if(f.length!==18||f[0]!=='KOVYA_AUDIT_V3'||f[1]!=='server'||f.slice(2,9).join('\t')!==expectedCorrelation
  ||!stages.has(f[11])||!decimal.test(f[10])||Number(f[10])>64||!/^[a-z][a-z0-9_]{0,79}$/u.test(f[12])
  ||!['none','possible'].includes(f[13])||f[14]!=='1'||!['0','1'].includes(f[15]))throw Error('phase_audit_invalid');
 const complete=f[15]==='1',counts=f.slice(16,18);
 if(complete?!counts.every(value=>/^[0-8]$/u.test(value)):!counts.every(value=>value==='null'))throw Error('phase_audit_invalid');
 if(f[13]==='none'&&(!complete||counts.some(value=>value!=='0')))throw Error('phase_audit_invalid');
 const arrival=f[11]==='refused_arrival';
 if(arrival?(f[9]!=='null'||f[12]!=='broker_deadline_refused'||!complete||counts.some(value=>value!=='0')):!decimal.test(f[9]))throw Error('phase_audit_invalid');
 const raw={role:'server',owner_work:arrival?null:f[9],server_work:arrival?null:f[9],operation:expectedCorrelation.split('\t')[4],correlation:expectedCorrelation,sequence:Number(f[10]),last_verified_phase:f[11],server_reason:f[12],terminal_sealed:true,counts_complete:complete,account_send_count:complete?Number(f[16]):null,memory_send_count:complete?Number(f[17]):null,logging_status:'recorded'};
 const evidence=arrival?deserializeOutcomeEvidence({schema_version:'kovya.outcome.v3',...raw,origin:'native_ingress',effect_certainty:'none',proof:{kind:'native_ingress',admission_closed:true,counts_complete:true}},'server'):(()=>{const owner=createOutcomeOwner('server',raw.operation);owner.bind(raw.owner_work);return owner.snapshot(raw);})();
 return {status:'recorded',evidence};
}
export async function readOutcomeReceipt({home,client,clientReason=null}={}){
 const c=projectOutcomeEvidence(client,'client');
 const fixed=Object.freeze({...c,reason_at_return:typeof clientReason==='string'&&/^[a-z][a-z0-9_]{0,79}$/u.test(clientReason)?clientReason:null});
 const result=(server,gap,status)=>Object.freeze({client:fixed,server,gap,server_logging_status:status});
 if(typeof home!=='string'||!path.isAbsolute(home)||!c.correlation)return result(null,'correlation_unavailable','unavailable');
 let handle;
 try{
  const parent=path.join(path.resolve(home),'state','broker'),before=await fs.lstat(parent);
  if(!before.isDirectory()||before.isSymbolicLink()||!same(await fs.realpath(parent),parent))throw Error('phase_audit_unavailable');
  const file=path.join(parent,'phase-'+createHash('sha256').update(c.correlation).digest('hex')+'.bin'),stat=await fs.lstat(file);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.size!==4096)throw Error('phase_audit_unavailable');
  handle=await fs.open(file,'r');const opened=await handle.stat();
  if(!identity(stat,opened)||!opened.isFile()||opened.nlink!==1||opened.size!==4096||!same(await fs.realpath(file),file))throw Error('phase_audit_unavailable');
  const bytes=Buffer.alloc(4097);let used=0;
  while(used<bytes.length){const value=await handle.read(bytes,used,bytes.length-used,null);if(!value.bytesRead)break;used+=value.bytesRead;}
  if(used!==4096)throw Error('phase_audit_unavailable');
  const parsed=decodePhaseAudit(bytes.subarray(0,used),c.correlation),after=await fs.lstat(parent);
  if(!identity(before,after)||after.isSymbolicLink()||!same(await fs.realpath(parent),parent))throw Error('phase_audit_unavailable');
  await handle.close();handle=null;
  if(!parsed.evidence)return result(null,'server_record_unqualified',parsed.status);
  if(c.server_work!==null&&c.server_work!==parsed.evidence.server_work)return result(null,'server_work_mismatch','unavailable');
  return result(parsed.evidence,'correlated_separate_owners','recorded');
 }catch{return result(null,'server_observation_unavailable','unavailable');}
 finally{if(handle)try{await handle.close();}catch{}}
}
