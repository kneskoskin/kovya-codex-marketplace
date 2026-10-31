import { createHash } from "node:crypto";

export const KOVYA_RECOVERY_ACTIVATION_ID_DOMAIN = "KOVYA-AUTH-RECOVERY-ACTIVATION-ID-V1\n";
export const KOVYA_RECOVERY_INSTALL_FINGERPRINT_PATTERN = /^[A-Za-z0-9._:-]{32,255}[A-Za-z0-9._:-]?$/u;
export const KOVYA_RECOVERY_NONCE_PATTERN = /^[A-Za-z0-9_-]{16,255}[A-Za-z0-9_-]?$/u;
export const KOVYA_RECOVERY_BEARER_TOKEN_PATTERN = /^kvy_[A-Za-z0-9_-]{16,255}[A-Za-z0-9_-]?$/u;
export const KOVYA_RECOVERY_DEFAULT_SERVER_BINDING = Object.freeze({
  schema_version: "recovery.server_binding.v1",
  origin: "https://kovya-memory-sandbox.fly.dev",
  deployment_id: "deployment:kovya-memory-mvp-sandbox"
});

const RECOVERY_TRANSACTION_ID_PATTERN = /^recoverytxn_[a-z0-9]{32,128}$/u;
const RECOVERY_DEPLOYMENT_ID_PATTERN = /^deployment:[a-z0-9][a-z0-9._-]{2,119}$/u;

export function normalizeKovyaRecoveryServerBinding(value) {
  requireClosedServerBinding(value);
  if (value.schema_version !== "recovery.server_binding.v1"
    || typeof value.deployment_id !== "string"
    || !RECOVERY_DEPLOYMENT_ID_PATTERN.test(value.deployment_id)) {
    throw new TypeError("Recovery server binding is invalid.");
  }
  return Object.freeze({
    schema_version: value.schema_version,
    origin: normalizeRecoveryHttpsUrl(value.origin, "/", false).origin,
    deployment_id: value.deployment_id
  });
}

export function normalizeKovyaRecoveryApiBaseUrl(value) {
  const parsed = normalizeRecoveryHttpsUrl(value, "/memory-api.v1", true);
  return `${parsed.origin}/memory-api.v1`;
}

export function kovyaRecoveryServerBindingHash(value) {
  const binding = normalizeKovyaRecoveryServerBinding(value);
  const canonical = JSON.stringify({
    deployment_id: binding.deployment_id,
    origin: binding.origin,
    schema_version: binding.schema_version
  });
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

export function recoveryActivationId(transactionId) {
  if (typeof transactionId !== "string" || !RECOVERY_TRANSACTION_ID_PATTERN.test(transactionId)) {
    throw new TypeError("Recovery transaction id is invalid.");
  }
  return `act_${createHash("sha256")
    .update(`${KOVYA_RECOVERY_ACTIVATION_ID_DOMAIN}${transactionId}`, "utf8")
    .digest("hex")
    .slice(0, 48)}`;
}

function requireClosedServerBinding(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    || Object.getOwnPropertySymbols(value).length !== 0) {
    throw new TypeError("Recovery server binding is invalid.");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).sort();
  const expected = ["deployment_id", "origin", "schema_version"];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])
    || keys.some((key) => !descriptors[key].enumerable || !("value" in descriptors[key]))) {
    throw new TypeError("Recovery server binding is invalid.");
  }
}

function normalizeRecoveryHttpsUrl(value, requiredPath, allowTrailingSlash) {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim()
    || value.includes("\\")) {
    throw new TypeError("Recovery server binding is invalid.");
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("Recovery server binding is invalid.");
  }
  const authorityStart = value.indexOf("://") + 3;
  const rawPathStart = value.indexOf("/", authorityStart);
  const rawPath = rawPathStart === -1 ? "/" : value.slice(rawPathStart);
  const acceptedPaths = allowTrailingSlash ? new Set([requiredPath, `${requiredPath}/`]) : new Set([requiredPath]);
  if (parsed.protocol !== "https:"
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.search !== ""
    || parsed.hash !== ""
    || parsed.hostname.length === 0
    || parsed.hostname.endsWith(".")
    || (parsed.port !== "" && parsed.port !== "443")
    || !acceptedPaths.has(parsed.pathname)
    || !acceptedPaths.has(rawPath)) {
    throw new TypeError("Recovery server binding is invalid.");
  }
  return parsed;
}
