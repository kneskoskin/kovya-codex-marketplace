import {readFileSync} from "node:fs";
const VERSION=/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const HEX=/^[a-f0-9]{64}$/;
export function validateRuntimeRequirement(value) {
  const validVersion=v=>typeof v==="string" && VERSION.test(v) && v.split(".").map(Number).every(Number.isSafeInteger);
  if(!value || Object.keys(value).sort().join(",")!=="digest,minimum,native_helper_sha256,schema_version,version"
      || value.schema_version!=="kovya.plugin-runtime-requirement.v1"
      || !validVersion(value.version) || !validVersion(value.minimum)
      || value.version.split(".")[0]!==value.minimum.split(".")[0]
      || typeof value.digest!=="string" || !HEX.test(value.digest)
      || typeof value.native_helper_sha256!=="string" || !HEX.test(value.native_helper_sha256))
    throw Object.assign(new Error("runtime_configuration_required"),{reason:"runtime_configuration_required"});
  return Object.freeze({...value});
}
export function loadRuntimeRequirement() {
  try {return validateRuntimeRequirement(JSON.parse(readFileSync(new URL("./runtime-requirement.json",import.meta.url),"utf8")));}
  catch {return null;}
}
export const runtimeConfigurationRequired=()=>({ok:false,state:"runtime_configuration_required",
  message:"This Kovya package lacks a valid runtime configuration. Obtain a configured release.",
  systemMessage:"This Kovya package lacks a valid runtime configuration. Obtain a configured release.",
  saving:"unverified",recall:"unverified"});
