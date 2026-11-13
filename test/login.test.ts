import { lstatSync, mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadGrant, writeGrantFile, type TestGrant } from "../src/credentials.js";
import { discover } from "../src/discovery.js";
import { login, LoginError, type LoginResult } from "../src/login.js";
import { runLoginCommand } from "../src/login-command.js";
import { HttpClient } from "../src/net/http.js";
import { scan } from "../src/scan.js";
import { startFixture, type Fixture, type FixtureOptions } from "./fixtures/server.js";

let fixture: Fixture | undefined;
let http: HttpClient | undefined;

afterEach(async () => {
  await fixture?.close();
  await http?.close();
  fixture = undefined;
  http = undefined;
});

/** A scripted "browser": follows the authorization redirect back to the loopback listener. */
function browser(tamper?: (location: URL) => void) {
  return async (url: string): Promise<void> => {
    const res = await fetch(url, { redirect: "manual" });
    const location = res.headers.get("location");
    if (!location) return;
    const back = new URL(location);
    tamper?.(back);
    await fetch(back, { redirect: "manual" });
  };
}

async function runLogin(
  options: FixtureOptions,
  extra: { probe?: boolean; tamper?: (l: URL) => void; timeoutMs?: number } = {},
): Promise<LoginResult> {
  fixture = await startFixture({ authorization: { noSession: "auto-approve" }, ...options });
  http = new HttpClient({ allowPrivate: true });
  const discovery = await discover(fixture.mcpUrl, http);
  return login({
    http,
    mcpUrl: fixture.mcpUrl,
    discovery,
    openUrl: browser(extra.tamper),
    probe: extra.probe ?? true,
    timeoutMs: extra.timeoutMs ?? 5000,
  });
}

describe("login", () => {
  const statuses = (r: LoginResult): Record<string, string> => Object.fromEntries(r.observations.map((o) => [o.checkId, o.status]));

  it("obtains a working test grant and observes the login checks as passing", async () => {
    const result = await runLogin({});
    expect(result.grant).toMatchObject({ authMethod: "none", target: (fixture as Fixture).mcpUrl, tokenEndpoint: `${(fixture as Fixture).baseUrl}/token` });
    expect(statuses(result)).toEqual({ "MAP-PKC01": "pass", "MAP-RDR03": "pass", "MAP-AUD01": "pass", "MAP-ORG01": "pass", "MAP-TOK01": "pass", "MAP-SES01": "pass", "MAP-BAT01": "pass", "MAP-BOD01": "pass", "MAP-INJ01": "pass", "MAP-COD01": "pass" });
    expect(result.observations.find((o) => o.checkId === "MAP-COD01")?.message).toMatch(/revoking them on reuse is recommended/);

    // The grant (refresh token rotated by the probes) and observations feed a full scan.
    const report = await scan((fixture as Fixture).mcpUrl, { allowPrivate: true, grant: result.grant as TestGrant, observations: result.observations });
    const status = (id: string) => report.findings.find((f) => f.checkId === id)?.status;
    for (const id of ["MAP-RTK01", "MAP-RTK02", "MAP-RTK03", "MAP-RDR03", "MAP-PKC01", "MAP-COD01", "MAP-AUD01", "MAP-ORG01", "MAP-TOK01", "MAP-SES01", "MAP-COR01"]) expect([id, status(id)]).toEqual([id, "pass"]);
    expect(report.findings.find((f) => f.checkId === "MAP-RDR03")?.evidence.at(-1)).toMatch(/observed during login/);
    expect(report.findings.filter((f) => /Not implemented/.test(f.message))).toEqual([]);
  });

  it("flags a token endpoint that ignores redirect_uri, and keeps the tokens it issued", async () => {
    const result = await runLogin({ tokens: { bindRedirect: false } });
    expect(statuses(result)).toMatchObject({ "MAP-PKC01": "pass", "MAP-RDR03": "fail" });
    expect(result.grant).not.toBeNull();
  });

  it("explains a strict server that burns the code after a refused attempt, and removes the client", async () => {
    const result = await runLogin({ tokens: { consumeCodeOnFailure: true } });
    // Only the first refusal is meaningful: the other attempts met an invalidated code.
    expect(statuses(result)).toEqual({ "MAP-PKC01": "error", "MAP-RDR03": "error" });
    expect(result.observations[0]?.evidence[0]).toMatch(/without a code_verifier \(PKCE\): HTTP 400/);
    expect(result.grant).toBeNull();
    expect(result.notes.join(" ")).toMatch(/--no-probe/);
    expect((fixture as Fixture).registeredClients()).toEqual([]);
  });

  it.each(["optional", "ignore"] as const)("flags a token endpoint with PKCE %s, and keeps the tokens the probe obtained", async (pkce) => {
    const result = await runLogin({ tokens: { pkce } });
    expect(statuses(result)["MAP-PKC01"]).toBe("fail");
    // The code was spent by the first probe: RDR03 is reported as not observed,
    // and presenting the code normally is itself the second use for COD01.
    expect(statuses(result)["MAP-RDR03"]).toBe("skipped");
    expect(statuses(result)["MAP-COD01"]).toBe("pass");
    expect(result.observations.find((o) => o.checkId === "MAP-PKC01")?.evidence.join(" ")).toMatch(/not run/);
    expect(result.grant).not.toBeNull();
  });

  it("flags an authorization code that can be used twice", async () => {
    const result = await runLogin({ tokens: { codeReuse: "allow" } });
    expect(statuses(result)["MAP-COD01"]).toBe("fail");
    expect(result.grant).not.toBeNull();
  });

  it("reports revocation on code reuse, and asks for a new login", async () => {
    const result = await runLogin({ tokens: { codeReuse: "revoke" } });
    expect(statuses(result)["MAP-COD01"]).toBe("pass");
    expect(result.observations.find((o) => o.checkId === "MAP-COD01")?.message).toMatch(/were revoked/);
    expect(result.grant).toBeNull();
    expect(result.notes.join(" ")).toMatch(/--no-probe/);
  });

  it.each([
    [{ tokens: { resource: "ignore" as const } }, "error"], // the AS's fault, not the MCP server's
    [{ mcp: { checkAudience: false } }, "fail"],
    [{ tokens: { resource: "refuse" as const } }, "pass"],
    [{ tokens: { resource: "refuse" as const }, mcp: { checkAudience: false } }, "pass"],
  ])("judges audience binding (%j)", async (options, expected) => {
    const result = await runLogin(options);
    expect(statuses(result)["MAP-AUD01"]).toBe(expected);
    expect(result.grant).not.toBeNull();
  });

  it.each([429, 500])("never fails AUD01 or ORG01 when the MCP endpoint answers %i to a valid token", async (code) => {
    const result = await runLogin({ mcp: { authenticatedStatus: code, validateOrigin: false, checkAudience: false } });
    expect(statuses(result)).toMatchObject({ "MAP-AUD01": "error", "MAP-ORG01": "error" });
    expect(result.grant).not.toBeNull();
  });

  it("does not pass ORG01 on a 403 caused by a dead token", async () => {
    const result = await runLogin({ tokens: { revokeAccessOnRefresh: true }, mcp: { validateOrigin: false, invalidTokenStatus: 403 } });
    expect(statuses(result)["MAP-ORG01"]).toBe("fail");
  });

  it("keeps the grant and the results when the MCP endpoint drops the connection", async () => {
    const result = await runLogin({ mcp: { hangUpAuthenticated: true } });
    expect(statuses(result)).toMatchObject({ "MAP-PKC01": "pass", "MAP-ORG01": "error", "MAP-AUD01": "error", "MAP-COD01": "pass" });
    expect(result.grant).not.toBeNull();
  });

  it("does not mistake a throttled refresh for revocation after code reuse", async () => {
    const result = await runLogin({ tokens: { throttleRefreshAfter: 1 } });
    const cod = result.observations.find((o) => o.checkId === "MAP-COD01");
    expect(cod?.status).toBe("pass");
    expect(cod?.message).toMatch(/unknown/);
    expect(result.grant).not.toBeNull();
  });

  it("still observes ORG01 and COD01 when no refresh token is issued", async () => {
    const result = await runLogin({ tokens: { issueRefresh: false, codeReuse: "revoke" } });
    expect(statuses(result)).toMatchObject({ "MAP-PKC01": "pass", "MAP-RDR03": "pass", "MAP-ORG01": "pass", "MAP-AUD01": "error", "MAP-COD01": "pass" });
    expect(result.observations.find((o) => o.checkId === "MAP-COD01")?.message).toMatch(/access token issued from it was revoked/);
    expect(result.grant).toBeNull();
    expect(result.notes.join(" ")).toMatch(/no refresh token/);
  });

  it("keeps the probe results when the real exchange then crashes", async () => {
    const result = await runLogin({ tokens: { consumeCodeOnFailure: true, crashOnBadCode: true } });
    expect(statuses(result)).toEqual({ "MAP-PKC01": "error", "MAP-RDR03": "error" });
    expect(result.grant).toBeNull();
    expect(result.notes.join(" ")).toMatch(/code exchange failed after the probes \(HTTP 500/);
  });

  it("explains a token endpoint that crashes on a reused code", async () => {
    const result = await runLogin({ tokens: { crashOnBadCode: true } });
    const cod = result.observations.find((o) => o.checkId === "MAP-COD01");
    expect(cod?.status).toBe("error");
    expect(cod?.message).toMatch(/crashed/);
    expect(result.grant).not.toBeNull();
  });

  it("flags an MCP endpoint that accepts the token in the URL", async () => {
    const result = await runLogin({ mcp: { acceptQueryToken: true } });
    expect(statuses(result)["MAP-TOK01"]).toBe("fail");
    // The token never appears in the evidence.
    expect(JSON.stringify(result.observations)).not.toMatch(/access_token=ey/);
  });

  it("flags a session ID that works without a token, and ends the sessions it opened", async () => {
    const result = await runLogin({ mcp: { sessionWithoutToken: true } });
    expect(statuses(result)["MAP-SES01"]).toBe("fail");
    expect((fixture as Fixture).requests.filter((r) => r.method === "DELETE" && r.path === "/mcp").length).toBeGreaterThan(0);
  });

  it("reports SES01 as not applicable on a stateless server", async () => {
    const result = await runLogin({ mcp: { sessions: false } });
    expect(statuses(result)["MAP-SES01"]).toBe("not_applicable");
  });

  it("does not judge TOK01 or SES01 on an endpoint that also serves anonymous requests", async () => {
    const result = await runLogin({ anonymous: true });
    expect(statuses(result)).toMatchObject({ "MAP-TOK01": "error", "MAP-SES01": "error" });
  });

  it("flags an MCP endpoint that does not validate Origin", async () => {
    const result = await runLogin({ mcp: { validateOrigin: false } });
    expect(statuses(result)["MAP-ORG01"]).toBe("fail");
  });

  it("skips the probe when ownership is not proven", async () => {
    const result = await runLogin({}, { probe: false });
    expect(result.observations).toEqual([]);
    expect(result.grant).not.toBeNull();
    expect(result.notes.join(" ")).toMatch(/not proven/);
  });

  it("aborts on an issuer mismatch (RFC 9207)", async () => {
    await expect(runLogin({}, { tamper: (l) => l.searchParams.set("iss", "https://other.example") })).rejects.toThrow(/iss parameter does not match/);
    expect((fixture as Fixture).registeredClients()).toEqual([]);
  });

  it("aborts when an announced iss is missing", async () => {
    await expect(runLogin({}, { tamper: (l) => l.searchParams.delete("iss") })).rejects.toThrow(/has none/);
  });

  it("ignores callbacks with a wrong state and times out", async () => {
    await expect(runLogin({}, { tamper: (l) => l.searchParams.set("state", "forged"), timeoutMs: 500 })).rejects.toBeInstanceOf(LoginError);
  });

  it("never prints tokens in notes or observations", async () => {
    const result = await runLogin({});
    const text = JSON.stringify({ o: result.observations, n: result.notes });
    expect(text).not.toMatch(/(rt|at|code)_[0-9a-f]{32}/);
  });
});

describe("MAP-COR01 during a scan", () => {
  const cor = async (cors: "none" | "reflect" | "reflect-credentials" | "wildcard") => {
    fixture = await startFixture({ mcp: { cors } });
    const report = await scan(fixture.mcpUrl, { allowPrivate: true });
    return report.findings.find((f) => f.checkId === "MAP-COR01");
  };

  it.each([
    ["none", "pass"],
    ["wildcard", "pass"],
    ["reflect", "pass"],
    ["reflect-credentials", "fail"],
  ] as const)("CORS %s -> %s", async (mode, expected) => {
    const f = await cor(mode);
    expect(f?.status).toBe(expected);
    expect(f?.evidence[0]).toMatch(/preflight/);
  });
});

describe("MAP-ORG01 during a scan", () => {
  const org = async (options: FixtureOptions): Promise<string | undefined> => {
    fixture = await startFixture(options);
    const report = await scan(fixture.mcpUrl, { allowPrivate: true });
    return report.findings.find((f) => f.checkId === "MAP-ORG01")?.status;
  };

  it("passes when a foreign Origin gets 403, even without ownership proof", async () => {
    expect(await org({})).toBe("pass");
  });

  it("fails when an anonymous endpoint processes a foreign Origin", async () => {
    expect(await org({ anonymous: true, mcp: { validateOrigin: false } })).toBe("fail");
  });

  it("is inconclusive when the endpoint asks for a token first", async () => {
    expect(await org({ mcp: { validateOrigin: false } })).toBe("error");
  });
});

describe("login command", () => {
  it("saves the results without a grant, and keeps them when logging in again with --no-probe", async () => {
    fixture = await startFixture({ authorization: { noSession: "auto-approve" }, tokens: { consumeCodeOnFailure: true } });
    const out = join(mkdtempSync(join(tmpdir(), "map-login-")), "lab.json");
    const base = { mcpUrl: fixture.mcpUrl, out, browser: false, allowPrivate: true, secret: undefined, openUrl: browser(), timeoutMs: 5000 };
    expect(await runLoginCommand({ ...base, force: false, probe: true })).toBe(0);
    const first = loadGrant(out);
    expect(first.grant).toBeNull();
    expect(first.observations.map((o) => o.checkId).sort()).toEqual(["MAP-PKC01", "MAP-RDR03"]);

    expect(await runLoginCommand({ ...base, force: true, probe: false })).toBe(0);
    const second = loadGrant(out);
    expect(second.grant).not.toBeNull();
    expect(second.observations.map((o) => o.checkId).sort()).toEqual(["MAP-PKC01", "MAP-RDR03"]);
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, grant: second.grant as TestGrant, observations: second.observations });
    expect(report.findings.find((f) => f.checkId === "MAP-PKC01")?.evidence.at(-1)).toMatch(/observed during login/);
  });
});

describe("grant file", () => {
  const grant: TestGrant = { clientId: "c", refreshToken: "r", authMethod: "none" };

  it("is written with mode 600, round-trips with observations, and is never silently overwritten", () => {
    const dir = mkdtempSync(join(tmpdir(), "map-grant-"));
    const path = join(dir, "grant.json");
    const obs = [{ checkId: "MAP-RDR03", title: "t", severity: "medium" as const, status: "pass" as const, target: "https://x.example/mcp", message: "m", evidence: [], observedAt: "2026-11-01T00:00:00Z" }];
    writeGrantFile(path, grant, obs);
    if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o600);
    const loaded = loadGrant(path);
    expect(loaded.grant).toEqual(grant);
    expect(loaded.observations).toEqual(obs);
    expect(() => writeGrantFile(path, grant, [])).toThrow(/EEXIST/);
    writeGrantFile(path, { ...grant, refreshToken: "r2" }, [], true);
    expect(JSON.parse(readFileSync(path, "utf8")).refresh_token).toBe("r2");
  });

  it("restores mode 600 when overwriting a permissive file", () => {
    const dir = mkdtempSync(join(tmpdir(), "map-grant-"));
    const path = join(dir, "grant.json");
    writeFileSync(path, "{}", { mode: 0o644 });
    writeGrantFile(path, grant, [], true);
    if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it.skipIf(process.platform === "win32")("refuses to write through a symbolic link", () => {
    const dir = mkdtempSync(join(tmpdir(), "map-grant-"));
    const victim = join(dir, "victim.txt");
    writeFileSync(victim, "keep me");
    const link = join(dir, "grant.json");
    symlinkSync(victim, link);
    expect(lstatSync(link).isSymbolicLink()).toBe(true);
    expect(() => writeGrantFile(link, grant, [], true)).toThrow();
    expect(readFileSync(victim, "utf8")).toBe("keep me");
  });

  it("ignores malformed observations", () => {
    const dir = mkdtempSync(join(tmpdir(), "map-grant-"));
    const path = join(dir, "g.json");
    writeFileSync(path, JSON.stringify({ client_id: "c", refresh_token: "r", observations: [{ checkId: "MAP-RDR03", status: "pwned" }, 42] }), { mode: 0o600 });
    expect(loadGrant(path).observations).toEqual([]);
  });
});
