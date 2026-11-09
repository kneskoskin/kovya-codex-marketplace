#!/usr/bin/env node
import {verifyNativeBinding} from "../claude-code/client/kovya-native-binding.mjs";
import {spawn} from "node:child_process";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {loadRuntimeRequirement,runtimeConfigurationRequired} from "./runtime-requirement.mjs";
import {resolvePluginLayout} from "./layout.mjs";
import {createPluginOnboarding,loadRuntimeRelease} from "./onboarding.mjs";
import {operationTerminalReceipt} from "./terminal-operation.mjs";

// The admitted runtime payload owns and pins sign-in configuration. Package
// setup delegates before reading it; no prompt, URL or environment override.
async function main() {
  const [host,operation,...extra] = process.argv.slice(2);
  if (extra.length) throw new Error("arguments_invalid");
  const root=fileURLToPath(new URL("../../",import.meta.url));
  const admittedNode=path.join(root,"runtime","node","node.exe");
  if (path.resolve(process.execPath).toLowerCase()!==path.resolve(admittedNode).toLowerCase()) {
    if (!loadRuntimeRequirement()) return runtimeConfigurationRequired();
    if (process.platform!=="win32") return {ok:false,state:"platform_unavailable",message:"This launcher supports Windows only."};
    const code=await delegatePackageSetup(host,operation);
    process.exitCode=code;
    return null; // The launcher or admitted setup owns stdout.
  }
  const layout=resolvePluginLayout();
  let release;
  try {release=loadRuntimeRelease();} catch {}
  const repairTarget=operation==="repair"?(await readLocalRepairFrame({host})).target:null;
  return createPluginOnboarding({layout,release}).run(operation,host,{repairTarget,inputProvider:remainingMs=>readProfileFinishInput({remainingMs})});
}

// The caller supplies a complete frame through a pipe, never a command argument
// or environment variable. Waiting for bytes spends the same public deadline.
export function readProfileFinishInput({remainingMs,input=process.stdin}={}) {
  return new Promise((resolve,reject)=>{
    let timer,total=0,settled=false;const chunks=[];
    const finish=(error)=>{
      if(settled)return;settled=true;clearTimeout(timer);
      input.pause();input.off("data",data);input.off("end",end);input.off("error",fail);
      let bytes;
      try {
        if(error)throw error;
        remainingMs();bytes=Buffer.concat(chunks);
        const value=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
        if(!value||Object.keys(value).sort().join(",")!=="code,pending_ref"||typeof value.code!=="string"
          ||typeof value.pending_ref!=="string"||!/^authreq_[a-f0-9]{36}$/u.test(value.pending_ref)
          ||! /^[a-fA-F0-9-]{32,64}$/u.test(value.code))throw new Error("protected_input_invalid");
        resolve({pending_ref:value.pending_ref,code:Buffer.from(value.code,"utf8")});value.code=null;
      }catch(cause){reject(cause);}finally{bytes?.fill(0);for(const chunk of chunks)chunk.fill(0);}
    };
    const fail=()=>finish(new Error("protected_input_invalid"));
    const end=()=>finish();
    const data=chunk=>{
      total+=Buffer.byteLength(chunk);
      if(total>512)return fail();
      chunks.push(Buffer.from(chunk));
    };
    try {
      const budget=Math.floor(remainingMs());
      if(input.isTTY||!Number.isFinite(budget)||budget<1)throw new Error("protected_input_required");
      timer=setTimeout(()=>finish(new Error("protected_input_timeout")),budget);
      input.on("data",data);input.once("end",end);input.once("error",fail);input.resume();
      if(input.readableEnded)end();
    }catch(error){finish(error);}
  });
}
export function readLocalRepairFrame({host,input=process.stdin}={}){
  return new Promise((resolve,reject)=>{
    let total=0,settled=false;const chunks=[],until=performance.now()+1000;
    const finish=error=>{
      if(settled)return;settled=true;clearTimeout(timer);input.pause();input.off("data",data);input.off("end",end);input.off("error",fail);
      let bytes;
      try{
        if(error)throw error;if(performance.now()>=until)throw new Error("protected_input_timeout");bytes=Buffer.concat(chunks);const value=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes)),t=value?.target;
        if(!value||Object.keys(value).sort().join(",")!=="schema_version,target"||value.schema_version!=="kovya.consented-local-repair.v1"
          ||!t||Object.keys(t).sort().join(",")!=="host,observation_sha256,request_ref,schema_version"
          ||t.schema_version!=="kovya.automatic-repair-target.v1"||t.host!==host||!["codex","claude_code"].includes(host)
          ||typeof t.request_ref!=="string"||!/^authreq_[a-f0-9]{36}$/.test(t.request_ref)
          ||typeof t.observation_sha256!=="string"||!/^[a-f0-9]{64}$/.test(t.observation_sha256))throw new Error("protected_input_invalid");
        if(performance.now()>=until)throw new Error("protected_input_timeout");resolve(value);
      }catch(error){reject(error);}finally{bytes?.fill(0);for(const b of chunks)b.fill(0);}
    };
    const data=b=>{if(performance.now()>=until)return finish(new Error("protected_input_timeout"));total+=Buffer.byteLength(b);if(total>1024)return fail();chunks.push(Buffer.from(b));};
    const end=()=>finish();const fail=()=>finish(new Error("protected_input_invalid"));
    const timer=setTimeout(()=>finish(new Error("protected_input_timeout")),1000);
    if(input.isTTY){fail();return;}input.on("data",data);input.once("end",end);input.once("error",fail);input.resume();if(input.readableEnded)end();
  });
}
export function delegatePackageSetup(host,operation,{spawnImpl=spawn,inputFrame=null}={}) {
  const launcher=fileURLToPath(new URL("../claude-code/client/kovya_windows_broker_native.exe",import.meta.url));
  return new Promise(resolve=>{
    let bytes=null;
    try{if(inputFrame!==null){bytes=Buffer.from(JSON.stringify(inputFrame),"utf8");if(bytes.length>1024){bytes.fill(0);resolve(1);return;}}}
    catch{bytes?.fill(0);resolve(1);return;}
    verifyNativeBinding(launcher,["bootstrap"]);
    const child=spawnImpl(launcher,["launch","setup",host,operation],{shell:false,windowsHide:true,stdio:inputFrame===null?"inherit":["pipe","inherit","inherit"]});
    let inputState=bytes===null?"confirmed":"pending",terminal=false,exitCode=null,timer=null,settled=false;
    const finish=()=>{if(!settled&&terminal&&inputState!=="pending"){settled=true;clearTimeout(timer);bytes?.fill(0);resolve(bytes===null?(exitCode??1):inputState==="confirmed"&&exitCode===0?0:1);}};
    const inputFailure=()=>{inputState="failed";bytes?.fill(0);child.stdin?.destroy?.();finish();};
    child.once("error",()=>{inputState="failed";terminal=true;exitCode=1;process.stdout.write(JSON.stringify({ok:false,state:"runtime_missing",message:"The Kovya package launcher is missing or could not start. Obtain a complete configured release."})+"\n");finish();});
    child.once("exit",code=>{terminal=true;exitCode=code;finish();});
    if(bytes!==null){
      child.stdin.once("error",inputFailure);
      child.stdin.once("close",()=>{if(inputState==="pending")inputState="failed";finish();});
      timer=setTimeout(inputFailure,1000);
      try{child.stdin.end(bytes,error=>{if(error){inputState="failed";inputFailure();}else if(inputState==="pending")inputState="confirmed";bytes.fill(0);finish();});}
      catch{inputState="failed";inputFailure();}
    }
  });
}

if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
try {
  const result=await main();
  if(result!==null) {
    process.stdout.write(JSON.stringify(result)+"\n");
    process.exitCode=result.ok ? 0 : 1;
  }
} catch (error) {
  const receipt=operationTerminalReceipt(error);
  process.stdout.write(JSON.stringify({ok:false,state:"unavailable",message:"Kovya setup could not start. Use the configured release's setup instructions.",...(receipt?{ok:receipt.terminal.ok,state:receipt.terminal.state,reason:receipt.terminal.reason,error_code:receipt.terminal.reason,stage:receipt.terminal.phase,diagnostics:receipt}:{})})+"\n");
  process.exitCode=1;
}

}
