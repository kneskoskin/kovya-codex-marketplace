import {readTerminalRecord,joinTerminalRecords} from "./terminal-record.mjs";
// Runtime/account independent, read-only projection. Never echo raw file bytes.
import fs from "node:fs/promises";
import path from "node:path";
import {readOutcomeReceipt} from "./phase-audit.mjs";
import {sanitizeDiagnosticRecord,diagnosticTime} from "./diagnostic-events.mjs";

const residentStages=new Set(["worker_prepare","worker_ready","account_validate","account_ready","account_end","host_prepare","host_ready","publish","publication_refused"]);
const publicationReasons=new Set(["profile_security","broker_publication_recovery_required","broker_publication_failed","profile_resident_validation_required","profile_resident_work_unsettled","profile_account_busy","profile_account_unavailable","profile_account_exited","broker_native_exited","broker_endpoint_invalid","broker_native_peer_refused","profile_resident_unavailable","broker_startup_ceiling_expired","profile_cleanup_uncertain","native_unclassified"]);
export function readResidentStartupRecord(raw){
 if(!raw||raw.schema_version!=="kovya.resident-startup-diagnostic.v1"||raw.scope!=="resident_startup"||!residentStages.has(raw.stage))return null;
 const refused=raw.stage==="publication_refused";
 const expected=refused?"elapsed_ms,error_code,error_kind,remaining_ms,schema_version,scope,stage":"elapsed_ms,remaining_ms,schema_version,scope,stage";
 if(Object.keys(raw).sort().join(",")!==expected||!Number.isSafeInteger(raw.elapsed_ms)||raw.elapsed_ms<0||!Number.isSafeInteger(raw.remaining_ms)||raw.remaining_ms<0||raw.remaining_ms>3000)return null;
 if(refused&&(raw.error_kind!=="native_exception"||!publicationReasons.has(raw.error_code)))return null;
 return {schema_version:raw.schema_version,scope:raw.scope,stage:raw.stage,elapsed_ms:raw.elapsed_ms,remaining_ms:raw.remaining_ms,...(refused?{error_kind:raw.error_kind,error_code:raw.error_code}:{})};
}
const samePath=(a,b)=>process.platform==="win32"?a.toLowerCase()===b.toLowerCase():a===b;
const identity=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
async function readDiagnosticLogs({home,limit=100}={}){
  const result={schema_version:"kovya.diagnose.v1",available:false,reason:"diagnostic_unavailable",records:[],incomplete:[],invalid_records:0,partial_records:0};
  let directory;
  try {
    if(typeof home!=="string"||!path.isAbsolute(home)||!Number.isInteger(limit)||limit<1||limit>200)return result;
    const root=path.join(path.resolve(home),"logs"),before=await fs.lstat(root);
    if(!before.isDirectory()||before.isSymbolicLink()||!samePath(await fs.realpath(root),root))return result;
    directory=await fs.opendir(root);const names=[];let entries=0;
    for await(const entry of directory){
      if(++entries>64)return result;
      if(entry.isFile()&&!entry.isSymbolicLink()&&/^kovya-\d{8}-[0-3]\.jsonl$/.test(entry.name))names.push(entry.name);
    }
    directory=null;
    // UTC days ascending, older rotated segments before the active segment.
    names.sort((a,b)=>a.slice(6,14).localeCompare(b.slice(6,14))||b[15].localeCompare(a[15]));
    if(names.length>32)return result;
    for(const name of names){
      const file=path.join(root,name),stat=await fs.lstat(file);
      if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.size>1048576)return result;
      let handle;
      try {
        handle=await fs.open(file,"r");const opened=await handle.stat();
        if(!identity(stat,opened)||!opened.isFile()||opened.nlink!==1||opened.size>1048576||!samePath(await fs.realpath(file),file))return result;
        const buffer=Buffer.alloc(1048577);let used=0;
        while(used<buffer.length){const {bytesRead}=await handle.read(buffer,used,buffer.length-used,null);if(bytesRead===0)break;used+=bytesRead;}
        if(used>1048576)return result;
        const bytes=buffer.subarray(0,used);let start=0;
        for(let i=0;i<bytes.length;i++)if(bytes[i]===10){
          const length=i-start+1;
          if(length>4096){result.invalid_records++;start=i+1;continue;}
          try {
            const raw=JSON.parse(bytes.subarray(start,i).toString("utf8"));
            if(raw?.schema_version?.startsWith("kovya.operation-")){const terminal=readTerminalRecord(raw);if(!terminal)throw new Error("invalid");result.records.push(terminal);if(result.records.length>limit)result.records.shift();start=i+1;continue;}
            if(raw?.schema_version==="kovya.resident-startup-diagnostic.v1"){const record=readResidentStartupRecord(raw);if(!record)throw new Error("invalid");result.records.push(record);if(result.records.length>limit)result.records.shift();start=i+1;continue;}
            const safe=sanitizeDiagnosticRecord(raw,{serialized:true});
            if(raw?.schema_version!=="kovya.local-diagnostic.v1"||!safe.diagnostic_id||!diagnosticTime(safe.utc)||!["start","stage","end"].includes(safe.event))throw new Error("invalid");
            result.records.push(safe);if(result.records.length>limit)result.records.shift();
          }catch{result.invalid_records++;}
          start=i+1;
        }
        if(start<bytes.length)result.partial_records++;
      } finally {if(handle)await handle.close();}
    }
    const after=await fs.lstat(root);
    if(!identity(before,after)||after.isSymbolicLink()||!samePath(await fs.realpath(root),root))return {...result,records:[]};
    const unfinished=new Set();for(const record of result.records){if(record.event==="start")unfinished.add(record.diagnostic_id);if(record.event==="end")unfinished.delete(record.diagnostic_id);}
    return {...result,available:true,reason:"none",incomplete:[...unfinished]};
  }catch{return {...result,records:[],incomplete:[]};}
  finally {if(directory)try{await directory.close();}catch{}}
}


const startupReasons=new Set(["version_skew","runtime_missing","admission_binding","runtime_startup_timeout","runtime_launch_refused","runtime_identity","runtime_servicing_recovery_required","marker_mismatch"]);
export function readStartupRefusalRecord(raw){
 if(!raw||Object.keys(raw).sort().join(',')!=="reason,schema_version,stage,utc"||raw.schema_version!=="kovya.startup-refusal.v1"
  ||!startupReasons.has(raw.reason)||!["startup_selection","startup_custody","startup_readiness","native_launch"].includes(raw.stage)
  ||typeof raw.utc!=="string"||raw.utc.length>40||!raw.utc.endsWith('Z')||!Number.isFinite(Date.parse(raw.utc)))return null;
 return {schema_version:raw.schema_version,utc:raw.utc,stage:raw.stage,reason:raw.reason};
}
async function startupRefusal(home){
 let handle;
 try{
  if(typeof home!=="string"||!path.isAbsolute(home))return null;
  for(const dir of [home,path.join(home,'state'),path.join(home,'state/runtime')]){const stat=await fs.lstat(dir);if(!stat.isDirectory()||stat.isSymbolicLink()||!samePath(await fs.realpath(dir),path.resolve(dir)))return null;}
  const file=path.join(home,'state/runtime/startup-refusal.v1.json'),before=await fs.lstat(file);
  if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||before.size>4096)return null;
  handle=await fs.open(file,'r');if(!identity(before,await handle.stat()))return null;
  const buffer=Buffer.alloc(4097);let used=0;
  while(used<buffer.length){const chunk=await handle.read(buffer,used,buffer.length-used,null);if(!chunk.bytesRead)break;used+=chunk.bytesRead;}
  if(used>4096)return null;
  const after=await fs.lstat(file);if(!identity(before,after)||after.isSymbolicLink())return null;
  return readStartupRefusalRecord(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,used))));
 }catch{return null;}finally{await handle?.close();}
}

export async function diagnoseLocal(options={}){
 const log=await readDiagnosticLogs(options),clients=new Map();
 const startup=await startupRefusal(options.home);
 if(startup){log.records.push(startup);log.available=true;log.reason="none";log.startup_refusal=startup;}
 for(const record of log.records){const evidence=record.phase_observation;if(evidence?.role==='client'&&evidence.correlation)clients.set(evidence.correlation,{evidence,reason:record.reason});}
 if(!clients.size)return {...log,terminals:joinTerminalRecords(log.records)};
 const receipts=[];for(const {evidence,reason}of clients.values())receipts.push(await readOutcomeReceipt({home:options.home,client:evidence,clientReason:reason}));
 return {...log,receipts,terminals:joinTerminalRecords(log.records)};
}
