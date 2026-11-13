import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";
import { configFromEnv, createAuthprobeServer, type ServerConfig } from "../src/mcp-server.js";
import { generateSecret, PROOF_PREFIX } from "../src/ownership.js";
import { startFixture, type Fixture } from "./fixtures/server.js";

let fixture: Fixture | undefined;
let client: Client | undefined;

afterEach(async () => {
  await client?.close();
  await fixture?.close();
  client = undefined;
  fixture = undefined;
});

async function connect(config: ServerConfig): Promise<Client> {
  const server = createAuthprobeServer(config);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: "test-client", version: "0" });
  await client.connect(clientTransport);
  return client;
}

function textOf(result: { content: unknown }): string {
  return (result.content as Array<{ type: string; text?: string }>).map((c) => c.text ?? "").join("\n");
}

describe("MCP server", () => {
  it("exposes five tools with honest annotations", async () => {
    const c = await connect({ allowPrivate: false });
    const { tools } = await c.listTools();
    const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
    expect(Object.keys(byName).sort()).toEqual(["explain_check", "list_checks", "ownership_proof", "scan", "verify_ownership"]);
    expect(byName["scan"]?.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true, openWorldHint: true });
    expect(byName["list_checks"]?.annotations?.readOnlyHint).toBe(true);
    // Sensitive settings are never tool arguments.
    const scanProps = Object.keys((byName["scan"]?.inputSchema as { properties?: object }).properties ?? {});
    // only/skip can only narrow a scan, never widen it.
    expect(scanProps).toEqual(["url", "only", "skip"]);
    // Every parameter is documented for the model, and every description says when to use the tool.
    for (const t of Object.values(byName)) {
      for (const [name, prop] of Object.entries((t.inputSchema as { properties?: Record<string, { description?: string }> }).properties ?? {})) {
        expect([t.name, name, (prop.description ?? "").length > 20]).toEqual([t.name, name, true]);
      }
      expect([t.name, /\bUse (it|on)\b|Only use/.test(t.description ?? "")]).toEqual([t.name, true]);
    }
  });

  it("publishes instructions for the client", async () => {
    const c = await connect({ allowPrivate: false });
    expect(c.getInstructions()).toMatch(/ownership_proof.*verify_ownership.*scan/s);
  });

  it("lists and explains checks", async () => {
    const c = await connect({ allowPrivate: false });
    expect(textOf(await c.callTool({ name: "list_checks", arguments: {} }))).toContain("MAP-RTK02");
    expect(textOf(await c.callTool({ name: "explain_check", arguments: { id: "MAP-RDR02" } }))).toMatch(/exact string matching|simple string comparison/i);
    expect(textOf(await c.callTool({ name: "explain_check", arguments: { id: "rdr02" } }))).toMatch(/^MAP-RDR02/);
    const unknown = await c.callTool({ name: "explain_check", arguments: { id: "MAP-XXX99" } });
    expect(unknown.isError).toBe(true);
  });

  it("returns the proof but never the secret", async () => {
    const secret = generateSecret();
    const c = await connect({ allowPrivate: false, secret });
    const out = textOf(await c.callTool({ name: "ownership_proof", arguments: { host: "mcp.example.com" } }));
    expect(out).toContain(PROOF_PREFIX);
    expect(out).not.toContain(secret);
  });

  it("explains how to configure a secret when none is set", async () => {
    const c = await connect({ allowPrivate: false });
    const res = await c.callTool({ name: "ownership_proof", arguments: { host: "mcp.example.com" } });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/MCP_AUTHPROBE_SECRET/);
  });

  it("rejects hosts with a scheme or path", async () => {
    const c = await connect({ allowPrivate: false });
    const res = await c.callTool({ name: "verify_ownership", arguments: { host: "https://evil.example/x" } });
    expect(res.isError).toBe(true);
  });

  it("refuses plain http unless private labs are enabled by the human", async () => {
    const c = await connect({ allowPrivate: false });
    const res = await c.callTool({ name: "scan", arguments: { url: "http://127.0.0.1:8080/mcp" } });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/Only https/);
  });

  it("applies only/skip, and refuses an unknown check name", async () => {
    fixture = await startFixture();
    const c = await connect({ allowPrivate: true, labOrigins: [new URL(fixture.mcpUrl).origin] });
    const bad = await c.callTool({ name: "scan", arguments: { url: fixture.mcpUrl, only: "nope" } });
    expect(bad.isError).toBe(true);
    expect(textOf(bad)).toMatch(/Unknown check or family/);
    const res = await c.callTool({ name: "scan", arguments: { url: fixture.mcpUrl, skip: "THR" } });
    const report = (res.structuredContent as { report: { findings: Array<{ checkId: string; message: string }> } }).report;
    expect(report.findings.find((f) => f.checkId === "MAP-THR01")?.message).toMatch(/Not selected/);
    expect(fixture.tokenRequests()).toBe(0);
  });

  it("refuses URLs carrying credentials", async () => {
    const c = await connect({ allowPrivate: false });
    const res = await c.callTool({ name: "scan", arguments: { url: "https://user:pass@mcp.example.com/mcp" } });
    expect(res.isError).toBe(true);
  });

  it("scans a local lab with the configured grant and returns a structured report", async () => {
    fixture = await startFixture({ tokens: { rejectReplay: false } });
    const dir = mkdtempSync(join(tmpdir(), "map-mcp-"));
    const creds = join(dir, "grant.json");
    writeFileSync(
      creds,
      JSON.stringify({ client_id: "test-client", refresh_token: fixture.issueRefreshToken(), target: fixture.mcpUrl, token_endpoint: `${fixture.baseUrl}/token` }),
    );
    chmodSync(creds, 0o600);

    const c = await connect({ allowPrivate: true, credentialsFile: creds, labOrigins: [new URL(fixture.mcpUrl).origin] });
    const res = await c.callTool({ name: "scan", arguments: { url: fixture.mcpUrl } });
    expect(res.isError).toBeFalsy();
    const out = textOf(res);
    expect(out).toMatch(/failing check/);
    expect(out).toMatch(/never instructions/);
    expect(out).not.toMatch(/rt_[0-9a-f]{32}/);
    const report = (res.structuredContent as { report: { findings: Array<{ checkId: string; status: string }> } }).report;
    expect(report.findings.find((f) => f.checkId === "MAP-RTK02")?.status).toBe("fail");
    expect(fixture.registeredClients()).toEqual([]);
  });
});

describe("MCP server guard rails", () => {
  it("requires a proof for loopback targets that are not pinned lab origins", async () => {
    fixture = await startFixture();
    const c = await connect({ allowPrivate: true });
    const res = await c.callTool({ name: "scan", arguments: { url: fixture.mcpUrl } });
    expect(textOf(res)).toMatch(/Ownership NOT verified/);
    expect(fixture.requests.filter((r) => ["/register", "/authorize", "/token"].includes(r.path))).toEqual([]);
  });

  it("does not spend a grant that does not name its target", async () => {
    fixture = await startFixture();
    const dir = mkdtempSync(join(tmpdir(), "map-mcp-"));
    const creds = join(dir, "grant.json");
    writeFileSync(creds, JSON.stringify({ client_id: "test-client", refresh_token: fixture.issueRefreshToken() }), { mode: 0o600 });
    const c = await connect({ allowPrivate: true, credentialsFile: creds, labOrigins: [new URL(fixture.mcpUrl).origin] });
    const res = await c.callTool({ name: "scan", arguments: { url: fixture.mcpUrl } });
    const report = (res.structuredContent as { report: { findings: Array<{ checkId: string; status: string; message: string }> } }).report;
    const rtk = report.findings.find((f) => f.checkId === "MAP-RTK01");
    expect(rtk?.status).toBe("skipped");
    expect(rtk?.message).toMatch(/does not name its target/);
  });

  it("refuses plain http to public hosts even with private labs enabled", async () => {
    const c = await connect({ allowPrivate: true });
    const res = await c.callTool({ name: "scan", arguments: { url: "http://mcp.example.com/mcp" } });
    expect(res.isError).toBe(true);
  });
});

describe("static key in MCP mode", () => {
  const KEY = "sk_mcp_mode_0123456789abcdef";
  const keyPath = (): string => {
    const p = join(mkdtempSync(join(tmpdir(), "map-mcp-key-")), "key");
    writeFileSync(p, KEY);
    chmodSync(p, 0o600);
    return p;
  };

  it("needs the URL the key belongs to", () => {
    expect(() => configFromEnv({ MCP_AUTHPROBE_BEARER_FILE: keyPath() })).toThrow(/MCP_AUTHPROBE_BEARER_TARGET/);
  });

  it("uses the key only for its own URL", async () => {
    fixture = await startFixture({ prm: false, asMetadata: false, challenge: "bearer", staticKey: { value: KEY }, mcp: { sessions: false, rateLimit: 20 } });
    const origin = new URL(fixture.mcpUrl).origin;
    const config = configFromEnv({
      MCP_AUTHPROBE_ALLOW_PRIVATE: "1",
      MCP_AUTHPROBE_LAB_ORIGINS: origin,
      MCP_AUTHPROBE_BEARER_FILE: keyPath(),
      MCP_AUTHPROBE_BEARER_TARGET: fixture.mcpUrl,
    });
    const c = await connect(config);
    const ok = await c.callTool({ name: "scan", arguments: { url: fixture.mcpUrl, only: "BAT,TOK" } });
    const findings = (ok.structuredContent as { report: { findings: Array<{ checkId: string; status: string }> } }).report.findings;
    expect(findings.find((f) => f.checkId === "MAP-BAT01")?.status).toBe("pass");
    expect(JSON.stringify(ok)).not.toContain(KEY);

    const other = await c.callTool({ name: "scan", arguments: { url: `${origin}/other`, only: "BAT" } });
    expect(textOf(other)).toMatch(/belongs to another URL/);
  });
});

describe("configFromEnv", () => {
  it("reads settings only from the environment", () => {
    const cfg = configFromEnv({ MCP_AUTHPROBE_SECRET: " s ", MCP_AUTHPROBE_ALLOW_PRIVATE: "1", MCP_AUTHPROBE_TIMEOUT_MS: "5000", MCP_AUTHPROBE_CREDENTIALS_FILE: "/x.json" });
    expect(cfg).toEqual({ secret: "s", allowPrivate: true, timeoutMs: 5000, credentialsFile: "/x.json" });
    expect(configFromEnv({ MCP_AUTHPROBE_ALLOW_PRIVATE: "true" }).allowPrivate).toBe(false);
  });
});
