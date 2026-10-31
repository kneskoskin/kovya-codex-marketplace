#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import {bindPluginBrokerClient} from "./broker-start.mjs";
import { resolvePluginLayout } from "./layout.mjs";
import {observeDiagnosticIngress} from "./diagnostic-lifecycle.mjs";
import {diagnosticStage} from "./diagnostic-events.mjs";
const layout = resolvePluginLayout();
process.env.KOVYA_HOME = layout.home;
process.env.KOVYA_WINDOWS_AUTH_MANIFEST = layout.authManifest;
const client = await import(pathToFileURL(process.platform === "win32" ? layout.brokerClient : layout.client));
if (process.platform === "win32") {
  const { startKovyaMcpStdio } = await import(pathToFileURL(layout.client));
  const unavailable=()=>process.stderr.write("Kovya diagnostics are unavailable for this request.\n");
  startKovyaMcpStdio({
    onMessage:message=>observeDiagnosticIngress({operation:"mcp",mcp_method:message?.method},async()=>{await diagnosticStage("framing",()=>message);return bindPluginBrokerClient(client).handleBrokerMcpMessage(message);},{unavailable}),
    onInvalidFrame:()=>observeDiagnosticIngress({operation:"mcp",mcp_method:"framing"},()=>diagnosticStage("framing",()=>{throw Object.assign(new Error("mcp_frame_invalid"),{code:"mcp_frame_invalid"});}),{unavailable})
  });
} else client.startKovyaMcpStdio();
