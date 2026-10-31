// The only record-to-native writer boundary. Never stringify caller objects.
import {sanitizeDiagnosticRecord,diagnosticRecordEnabled} from "./diagnostic-events.mjs";
import {appendProfileDiagnostic} from "../claude-code/client/kovya-profile-process.mjs";

export function persistDiagnosticRecords(records,append=appendProfileDiagnostic){
  try {
    if(!Array.isArray(records)||records.length<1||records.length>64)throw new Error("diagnostic_record_invalid");
    const lines=records.map(sanitizeDiagnosticRecord).filter(record=>diagnosticRecordEnabled(record)).map(record=>JSON.stringify(record)+"\n");
    if(lines.length===0)return Promise.resolve({available:true,suppressed:true});
    if(lines.some(line=>Buffer.byteLength(line)>4096))throw new Error("diagnostic_record_invalid");
    return Promise.resolve(append(lines.join(""))).catch(()=>({available:false,reason:"diagnostic_unavailable"}));
  } catch {
    return Promise.resolve({available:false,reason:"diagnostic_unavailable"});
  }
}
