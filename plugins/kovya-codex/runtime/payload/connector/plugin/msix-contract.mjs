import path from "node:path";

export const MSIX_SELECTION_SCHEMA="kovya.plugin-runtime-selection.v3";
export const MSIX_RELEASE_SCHEMA="kovya.msix-release.v1";
const hex=/^[a-f0-9]{64}$/;
const refuse=reason=>{throw Object.assign(new Error(reason),{code:"runtime_invalid",reason});};
const exact=(value,keys)=>value && typeof value==="object" && !Array.isArray(value)
  && Object.keys(value).sort().join(",")===keys.slice().sort().join(",");
const samePath=(a,b)=>typeof a==="string" && typeof b==="string" && path.win32.isAbsolute(a)
  && path.win32.isAbsolute(b) && path.win32.normalize(a).toLowerCase()===path.win32.normalize(b).toLowerCase();

// Release inputs are generated from selected build artifacts. This validator
// does not turn a user record, environment value or OS path into release trust.
export function validateMsixRelease(value) {
  if(!exact(value,["schema_version","name","publisher","family","full_name","version","architecture","alias","payload_digest"])
    || value.schema_version!==MSIX_RELEASE_SCHEMA || typeof value.name!=="string"
    || !/^[A-Za-z0-9][A-Za-z0-9.-]{2,49}$/.test(value.name)
    || typeof value.publisher!=="string" || !/^CN=/.test(value.publisher) || /[\0\r\n]/.test(value.publisher)
    || value.publisher.length>8192 || value.architecture!=="x64"
    || typeof value.version!=="string" || !/^\d+\.\d+\.\d+\.\d+$/.test(value.version)
    || value.version.split(".").some(v=>String(Number(v))!==v || Number(v)>65535)
    || typeof value.family!=="string" || !new RegExp(`^${value.name.replace(/[.]/g,"\\.")}_[a-z0-9]{13}$`).test(value.family)
    || value.full_name!==`${value.name}_${value.version}_x64__${value.family.slice(value.name.length+1)}`
    || typeof value.alias!=="string" || !/^[a-z][a-z0-9-]{2,63}\.exe$/.test(value.alias)
    || typeof value.payload_digest!=="string" || !hex.test(value.payload_digest)) refuse("msix_release_invalid");
  return Object.freeze({...value});
}

export function validateMsixSelection(value,{release,home,ownerSidHash}) {
  const expected=validateMsixRelease(release);
  if(!exact(value,["schema_version","installation_root","owner_sid_hash","package_full_name","payload_digest","selected_at"])
    || value.schema_version!==MSIX_SELECTION_SCHEMA || !samePath(value.installation_root,home)
    || !hex.test(ownerSidHash) || value.owner_sid_hash!==ownerSidHash
    || value.package_full_name!==expected.full_name || value.payload_digest!==expected.payload_digest
    || typeof value.selected_at!=="string" || !Number.isFinite(Date.parse(value.selected_at))) refuse("msix_selection_disagreement");
  return Object.freeze({...value});
}

// The observation must come from the owning native Windows API boundary, not
// from caller metadata. This is shared comparison logic for resolution/readiness.
export function validateMsixObservation(value,release,{requireProcess=true}={}) {
  const expected=validateMsixRelease(release);
  if(!value || value.registered!==true || value.development_mode!==false || value.main_package!==true
    || value.external_location!==false || value.mutable_location!==false || value.content_integrity!==true
    || value.filesystem!=="NTFS" || value.drive_type!==3 || value.package_full_name!==expected.full_name
    || value.package_family_name!==expected.family || value.publisher!==expected.publisher
    || !samePath(value.install_path,value.effective_path)
    || (requireProcess && value.process_package_full_name!==expected.full_name)) refuse("msix_package_disagreement");
  return Object.freeze({...value});
}

// Deployment return codes alone never establish a selected or ready state.
// The caller must supply a fresh owning-boundary readback for each transition.
export function adjudicateMsixServicing({operation,requestedFullName,observedFullNames,consumersStopped,deferred,operationFailed,ambiguous}) {
  if(!["install","update","repair","remove"].includes(operation) || typeof requestedFullName!=="string"
    || !requestedFullName || !Array.isArray(observedFullNames) || observedFullNames.some(n=>typeof n!=="string" || !n)
    || new Set(observedFullNames).size!==observedFullNames.length) refuse("msix_servicing_observation_invalid");
  if(ambiguous===true || observedFullNames.length>1) return Object.freeze({state:"unconfirmed",ready:false,retry:"readback"});
  if(operation!=="install" && consumersStopped!==true) return Object.freeze({state:"in_use",ready:false,retry:"quiesce"});
  if(deferred===true) return Object.freeze({state:"pending",ready:false,retry:"readback"});
  if(operationFailed===true) return Object.freeze({state:"refused",ready:false,retry:"inspect"});
  if(operation==="remove") return Object.freeze({state:observedFullNames.length===0?"deregistered":"unconfirmed",ready:false,retry:"inspect"});
  return Object.freeze({state:observedFullNames.length===1 && observedFullNames[0]===requestedFullName?"registered_unselected":"unconfirmed",ready:false,retry:"inspect"});
}
