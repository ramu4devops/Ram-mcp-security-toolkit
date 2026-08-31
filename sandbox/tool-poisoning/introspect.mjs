// introspect.mjs — start a *local* MCP server over stdio and dump its
// tools/list response to JSON. No network calls; the server talks to us
// only over stdin/stdout.
//
// Usage: node introspect.mjs "node cli.js" tools.json
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { writeFileSync } from "node:fs";

const [, , cmdline, outFile] = process.argv;
if (!cmdline || !outFile) {
  console.error("usage: node introspect.mjs \"<command to launch server>\" out.json");
  process.exit(2);
}
const [cmd, ...args] = cmdline.split(" ");

const transport = new StdioClientTransport({ command: cmd, args });
const client = new Client({ name: "mcp-poison-introspector", version: "1.0.0" });

await client.connect(transport);
const { tools } = await client.listTools();

// Normalize to the same shape detect_poison.py expects.
const normalized = tools.map(t => ({
  name: t.name,
  description: t.description || "",
  input_schema: t.inputSchema || {},
}));

writeFileSync(outFile, JSON.stringify(normalized, null, 2));
console.error(`Wrote ${normalized.length} tool definitions to ${outFile}`);
await client.close();
process.exit(0);
