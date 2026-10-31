import {EventEmitter} from "node:events";
import {PassThrough,Writable} from "node:stream";

const error=code=>Object.assign(new Error(code),{code});
function options(value) {
  if(value.shell!==false || value.detached===true || value.stdio?.join(",")!=="pipe,pipe,pipe") throw error("managed_spawn_options_refused");
  return value;
}

// Shared by the real adapter and direct inert transport tests. The native
// object is injected only here; production obtains it from a fixed pinned load.
export function createManagedProcessStreams(native) {
  // Native disposal completion is distinct from process exit and transport errors.
  const cleanups=new WeakMap();
  function observeCleanup(child){
    const observation=cleanups.get(child);
    if(!observation)throw error("managed_cleanup_required");
    return observation;
  }
  function spawn(executable,argv,configuration) {
    options(configuration);
    const created=native.spawn(executable,argv,configuration.env??{});
    return attach(created,configuration);
  }
  async function spawnAsync(ticket,executable,argv,configuration){
    options(configuration);
    return attach(await native.spawnAsync(ticket,executable,argv,configuration.env??{}),configuration);
  }
  async function prepareAccountWorker(){
    return attach(await native.prepareAccountWorker(),{shell:false,windowsHide:true,stdio:["pipe","pipe","pipe"]});
  }
  async function spawnResidentHost(){return attach(await native.spawnResidentHost(),{shell:false,windowsHide:true,stdio:["pipe","pipe","pipe"]});}
  function attach(created,configuration){
    const child=new EventEmitter();child.pid=created.pid;child.exitCode=null;child.signalCode=null;
    let cleanupDone,cleanupFailed,cleanupStarted=false;
    const completion=new Promise((resolve,reject)=>{cleanupDone=resolve;cleanupFailed=reject;});
    completion.catch(()=>{});cleanups.set(child,Object.freeze({completion,get started(){return cleanupStarted;}}));
    child.stdout=new PassThrough();child.stderr=new PassThrough();
    let timer=null,closed=false,writeCallback=null,ending=null,referenced=true,outputBytes=0;
    const limit=configuration.maxBuffer??8*1024*1024;
    function finish(code,signal) {
      if(closed)return;closed=true;clearTimeout(timer);
      const pending=writeCallback;writeCallback=null;pending?.(error("managed_stdin_closed"));
      ending?.();ending=null;
      cleanupStarted=true;
      try{
        const cleanup=native.dispose(created.id);
        if(cleanup&&typeof cleanup.then==="function"){
          cleanup.then(()=>{cleanupDone();child.emit("close",code,signal);},cause=>{cleanupFailed(cause);child.emit("error",cause);child.emit("close",code,signal);});return;
        }
      }catch(cause){cleanupFailed(cause);child.emit("error",cause);child.emit("close",code,signal);return;}
      cleanupDone();
      child.emit("close",code,signal);
    }
    function fail(cause) {
      if(closed)return;
      try{native.kill(created.id);}catch{}
      child.stdout.destroy();child.stderr.destroy();
      const failure=error(cause?.message??"managed_transport_failed");
      // Match ChildProcess: consumers get one asynchronous error before close.
      child.emit("error",failure);finish(null,null);
    }
    child.stdin=new Writable({write(chunk,_encoding,callback){
      try{if(native.write(created.id,chunk))callback();else writeCallback=callback;}catch(cause){callback(cause);}
    },final(callback){
      try{native.end(created.id);callback();}catch(cause){callback(cause);}
    }});
    child.kill=(signal="SIGTERM")=>{
      if(closed)return false;
      if(!["SIGTERM","SIGKILL"].includes(signal))throw error("managed_signal_refused");
      const result=native.kill(created.id);if(result)child.signalCode=signal;return result;
    };
    child.ref=()=>{referenced=true;timer?.ref();return child;};
    child.unref=()=>{referenced=false;timer?.unref();return child;};
    function poll() {
      if(closed)return;
      try {
        const result=native.poll(created.id);
        for(const name of ["stdout","stderr"]) {
          if(result[name]===false){if(!child[name].writableEnded)child[name].end();}
          else if(result[name]?.length){outputBytes+=result[name].length;if(outputBytes>limit)throw error("managed_output_limit");child[name].write(result[name]);}
        }
        if(result.write_complete && writeCallback){const callback=writeCallback;writeCallback=null;callback();}
        if(result.exit_code!==undefined && child.exitCode===null){child.exitCode=result.exit_code;child.emit("exit",child.exitCode,child.signalCode);}
        if(result.exit_code!==undefined && result.stdout===false && result.stderr===false){finish(child.exitCode,child.signalCode);return;}
        timer=setTimeout(poll,2);if(!referenced)timer.unref();
      }catch(cause){fail(cause);}
    }
    timer=setTimeout(poll,0);
    return child;
  }
  function spawnSync(executable,argv,configuration) {
    const stdio=configuration.stdio;
    if(!Array.isArray(stdio)||!["ignore","pipe"].includes(stdio[0])||stdio[1]!=="pipe"||stdio[2]!=="pipe")throw error("managed_spawn_options_refused");
    const timeout=configuration.timeout;
    if(!Number.isInteger(timeout)||timeout<1||timeout>30000)throw error("managed_timeout_required");
    const c=native.spawn(executable,argv,configuration.env??{}),out=[],err=[],sleep=new Int32Array(new SharedArrayBuffer(4));
    let ended=false,status=null,failure=null,total=0;const deadline=performance.now()+timeout;
    try {
      const input=configuration.input??Buffer.alloc(0);
      if(!Buffer.isBuffer(input)&&typeof input!=="string")throw error("managed_input_invalid");
      let complete=native.write(c.id,Buffer.isBuffer(input)?input:Buffer.from(input));
      for(;;) {
        const p=native.poll(c.id);complete=complete||p.write_complete;
        if(complete&&!ended){native.end(c.id);ended=true;}
        for(const [name,list] of [["stdout",out],["stderr",err]])if(p[name]?.length){total+=p[name].length;if(total>(configuration.maxBuffer??8192))throw error("ENOBUFS");list.push(p[name]);}
        if(p.exit_code!==undefined){status=p.exit_code;if(p.stdout===false&&p.stderr===false)break;}
        if(performance.now()>=deadline)throw error("ETIMEDOUT");
        Atomics.wait(sleep,0,0,2);
      }
    }catch(cause){failure=cause;try{native.kill(c.id);}catch{}}
    finally{native.dispose(c.id);}
    const encode=chunks=>{const b=Buffer.concat(chunks);return configuration.encoding && configuration.encoding!=="buffer"?b.toString(configuration.encoding):b;};
    return {pid:c.pid,status,signal:null,error:failure,stdout:encode(out),stderr:encode(err)};
  }
  return Object.freeze({spawn,spawnSync,spawnAsync,prepareAccountWorker,spawnResidentHost,observeCleanup});
}
