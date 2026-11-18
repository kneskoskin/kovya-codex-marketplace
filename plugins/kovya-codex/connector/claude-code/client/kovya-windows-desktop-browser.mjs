import {spawn} from "node:child_process";
import {fileURLToPath} from "node:url";
import {openSync,readSync,fstatSync,closeSync,constants} from "node:fs";
import {createHash} from "node:crypto";
import path from "node:path";

const script=fileURLToPath(new URL("./kovya-windows-desktop-browser.ps1",import.meta.url));
const accepted='{"ok":true,"dispatch":"accepted"}';
const refused='{"ok":false,"dispatch":"refused"}';
const failure=(code,ambiguous)=>Object.assign(new Error("Kovya desktop browser dispatch failed."),{code,ambiguous});
const scriptSha256="364fa7ffa6701217a6c6df282f4b82dfbe3c1b82abb5937832336a7ba6d3c4e7";
function reviewedScript() {
  let descriptor;
  try {
    descriptor=openSync(script,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
    const info=fstatSync(descriptor);
    if(!info.isFile()||info.size<1||info.size>16_384)throw new Error();
    const bytes=Buffer.alloc(info.size+1),count=readSync(descriptor,bytes,0,bytes.length,0);
    if(count!==info.size||createHash("sha256").update(bytes.subarray(0,count)).digest("hex")!==scriptSha256)throw new Error();
    return new TextDecoder("utf-8",{fatal:true}).decode(bytes.subarray(0,count));
  } finally {if(descriptor!==undefined)closeSync(descriptor);}
}

// Only the desktop Explorer receives the URL. The helper never launches a
// browser itself and receives neither the runtime environment nor credentials.
export async function openWindowsDesktopBrowser(url,{
  spawnImpl=spawn,systemRoot=process.env.SystemRoot,timeoutMs=10_000,cleanupMs=1_000
}={}) {
  if(typeof systemRoot!=="string"||! /^[A-Za-z]:\\[^\x00-\x1f";<>|?*:]+$/u.test(systemRoot)
      ||path.win32.normalize(systemRoot)!==systemRoot||systemRoot.endsWith("\\")
      ||!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>10_000
      ||!Number.isInteger(cleanupMs)||cleanupMs<1||cleanupMs>1_000)
    throw failure("desktop_browser_refused",false);
  if(typeof url!=="string"||Buffer.byteLength(url,"utf8")>8192||/[\0\r\n]/u.test(url))
    throw failure("desktop_browser_refused",false);
  let source;
  try {source=reviewedScript();}catch{throw failure("desktop_browser_refused",false);}
  const executable=path.win32.join(systemRoot,"System32","WindowsPowerShell","v1.0","powershell.exe");
  return new Promise((resolve,reject)=>{
    let child,timer,cleanup,settled=false,spawned=false,stopping=false,terminal=null,output="",outputBytes=0;
    const destroy=()=>{for(const stream of [child?.stdin,child?.stdout,child?.stderr])stream?.destroy();};
    const finish=(error)=>{if(settled)return;settled=true;clearTimeout(timer);clearTimeout(cleanup);destroy();if(error)reject(error);else resolve(Object.freeze({dispatch:"accepted",confirmation:"desktop_shell"}));};
    const stop=code=>{
      if(settled||stopping)return;stopping=true;terminal=failure(code,spawned);
      cleanup=setTimeout(()=>finish(failure("desktop_browser_cleanup_unconfirmed",spawned)),cleanupMs);
      try{child?.kill();}catch{}
    };
    try {
      child=spawnImpl(executable,["-NoLogo","-NoProfile","-NonInteractive","-STA","-Command",source],{
        windowsHide:true,shell:false,stdio:["pipe","pipe","pipe"],
        env:{SystemRoot:systemRoot,WINDIR:systemRoot}
      });
      child.once("error",()=>stop("desktop_browser_refused"));
      child.once("spawn",()=>{
        spawned=true;
        if(stopping)return;
        try{child.stdin.end(Buffer.from(url,"utf8"));}catch{stop("desktop_browser_ambiguous");}
      });
      child.stdin.on("error",()=>stop("desktop_browser_ambiguous"));
      child.stdout.on("data",bytes=>{
        outputBytes+=bytes.length;
        if(outputBytes>128){stop("desktop_browser_ambiguous");return;}
        output+=bytes.toString("utf8");
      });
      child.stdout.on("error",()=>stop("desktop_browser_ambiguous"));
      child.stderr.on("data",()=>stop("desktop_browser_ambiguous"));
      child.stderr.on("error",()=>stop("desktop_browser_ambiguous"));
      child.once("close",(code,signal)=>{
        if(terminal)return finish(terminal);
        const record=output.trim();
        if(code===0&&signal===null&&record===accepted)return finish();
        finish(failure(record===refused?"desktop_browser_refused":"desktop_browser_ambiguous",record===refused?false:spawned));
      });
      timer=setTimeout(()=>stop("desktop_browser_timeout"),timeoutMs);
    } catch {finish(failure("desktop_browser_refused",false));}
  });
}
