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
  return createPluginOnboarding({layout,release}).run(operation,host,{inputProvider:remainingMs=>readProfileFinishInput({remainingMs})});
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
export function delegatePackageSetup(host,operation,{spawnImpl=spawn}={}) {
  const launcher=fileURLToPath(new URL("../claude-code/client/kovya_windows_broker_native.exe",import.meta.url));
  return new Promise(resolve=>{
      verifyNativeBinding(launcher,["bootstrap"]);
      const child=spawnImpl(launcher,["launch","setup",host,operation],{shell:false,windowsHide:true,stdio:"inherit"});
      child.once("error",()=>{process.stdout.write(JSON.stringify({ok:false,state:"runtime_missing",message:"The Kovya package launcher is missing or could not start. Obtain a complete configured release."})+"\n");resolve(1);});child.once("exit",code=>resolve(code ?? 1));
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
