import { defineConfig } from "tsup";

export default defineConfig({
  // `paging` is also its own entry (`@agentwares/mcp-kit/paging`), dependency-free, so a Worker
  // or a proxy can read paginated lists without bundling the MCP SDK the root export pulls in.
  entry: ["src/index.ts", "src/example-http.ts", "src/paging.ts"],
  format: ["esm"],
  platform: "node",
  target: "es2022",
  dts: true,
  sourcemap: true,
  clean: true,
});
