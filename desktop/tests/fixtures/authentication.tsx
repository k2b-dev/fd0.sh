import { render } from "solid-js/web";
import { createSignal, Show } from "solid-js";
import { Unlock } from "../../src/renderer/src/features/Unlock";
import { SSHGrantPanel } from "../../src/renderer/src/features/SSHGrantPanel";
import { createVaultStore, VaultContext } from "../../src/renderer/src/lib/store";
import type { VaultStatus, UnlockInput, SSHGrantInput } from "../../src/shared/contracts";
import "../../src/renderer/src/styles.css";

const status: VaultStatus = { vaultExists:true, agentRunning:true, unlocked:true, yubikey:true,
 authMethods:[{id:"pass",type:"passphrase",label:"Passphrase"}, {id:"key",type:"yubikey",label:"YubiKey",pinMode:"none",default:true}] };
let submitted: UnlockInput | null = null;
let fail = false;
let failList = false;
let opened: unknown = null;
const activeGrants = [{id:"g1",scopeId:"work",name:"build-1",hostname:"build-1.test",user:"admin",port:22,fingerprint:"synthetic",hostFingerprints:["synthetic-server"],active:true},
 {id:"g2",scopeId:"work",name:"backup-1",hostname:"backup-1.test",user:"admin",port:22,fingerprint:"synthetic",hostFingerprints:["synthetic-server"],active:true}];
const preview = {deviceId:"test",digest:"reviewed",grants:[{id:"test",scopeId:"work",name:"host",hostname:"host.test",user:"admin",port:22,fingerprint:"synthetic",hostFingerprints:["synthetic-server"],active:false}]};
Object.defineProperty(window,"fd0",{value:{development:false,status:async()=>status,
 openSSHHost:async(ref:unknown)=>{opened=ref;},
 lock:async()=>{const next={...vault.status()!,sshGrantCount:0};vault.setStatus(next);return next;},
 unlock:async(input:UnlockInput)=>{if(fail) throw new Error("Synthetic failure");submitted=input;return status},
 sshGrant:async(input:SSHGrantInput)=>{
  if(input.action==="prepare") return preview;
  if(input.action==="create") {if(input.digest!=="reviewed") throw new Error("Wrong preview");if(fail) throw new Error("Synthetic failure");submitted=input;}
  if(input.action==="list") {if(failList) throw new Error("Synthetic list failure");return {deviceId:"test",grants:activeGrants};}
  return {deviceId:"test",grants:[]};
 }}});
const vault=createVaultStore();vault.setStatus(status);
const [mode,setMode]=createSignal("unlock");
render(()=><VaultContext.Provider value={vault}>
 <Show when={mode()==="unlock"} fallback={<SSHGrantPanel item={{scopeId:"work",name:"host:host"}}/>}>
  <Unlock status={vault.status()} onUnlock={(next)=>vault.setStatus(next)}/>
 </Show>
</VaultContext.Provider>,document.body);
const authTest={missing:()=>vault.setStatus({...status,authMethods:[]}),
 grants:(count:number,listFails=false)=>{failList=listFails;vault.setStatus({...status,unlocked:false,sshGrantCount:count});},mode:setMode,submitted:()=>submitted,opened:()=>opened,fail:(value:boolean)=>{fail=value},
 pin:(pinMode:"none"|"required"|"optional",supported=true)=>vault.setStatus({...status,yubikey:supported,authMethods:status.authMethods?.map(m=>m.id==="key"?{...m,pinMode}:m)})};
declare global { interface Window { authTest: typeof authTest } }
window.authTest=authTest;
