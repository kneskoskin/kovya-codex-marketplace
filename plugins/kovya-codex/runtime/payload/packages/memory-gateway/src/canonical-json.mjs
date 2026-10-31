import { createHash } from "node:crypto";

export function stableJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
}

export function sha256StableJson(value) {
  return `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`;
}
