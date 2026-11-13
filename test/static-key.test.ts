import { chmodSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EXIT, main } from "../src/cli.js";
import type { Credential } from "../src/oauth/mcp-call.js";
import { safeText } from "../src/redact.js";
import { toJson } from "../src/report/json.js";
import { scan } from "../src/scan.js";
import { loadBearerFile, StaticKeyError } from "../src/static-key.js";
import { startFixture, type Fixture, type FixtureOptions } from "./fixtures/server.js";

let fixture: Fixture | undefined;
afterEach(async () => {
  await fixture?.close();
  fixture = undefined;
});

const KEY = "sk_test_9f8e7d6c5b4a39281706f5e4d3c2b1a0";
const dir = (): string => mkdtempSync(join(tmpdir(), "map-key-"));
function keyFile(content = `${KEY}\n`, mode = 0o600): string {
  const p = join(dir(), "key");
  writeFileSync(p, content);
  chmodSync(p, mode);
  return p;
}

/** A server without OAuth: a static key, a plain Bearer challenge, no metadata. */
const staticServer = (extra: FixtureOptions = {}, header?: string): FixtureOptions => ({
  prm: false,
  asMetadata: false,
  challenge: "bearer",
  staticKey: header ? { value: KEY, header } : { value: KEY },
  ...extra,
  mcp: { sessions: false, rateLimit: 20, ...extra.mcp },
});

async function scanWith(options: FixtureOptions, header?: string) {
  fixture = await startFixture(options);
  const credential = loadBearerFile(keyFile(), header).credential;
  const report = await scan(fixture.mcpUrl, { allowPrivate: true, credential, rateAttempts: 30 });
  const status = Object.fromEntries(report.findings.map((f) => [f.checkId, f.status]));
  return { report, status };
}

describe("static key file", () => {
  it("reads one key, warns about loose permissions and registers it for redaction", () => {
    const loaded = loadBearerFile(keyFile(`${KEY}\n`, 0o644));
    expect(loaded.credential).toMatchObject({ header: "authorization", value: `Bearer ${KEY}`, kind: "static" } satisfies Partial<Credential>);
    expect(loaded.warnings.join(" ")).toMatch(/readable by other users/);
    expect(safeText(`leaked ${KEY} here`)).toBe("leaked [REDACTED] here");
  });

  it("sends the key as is in a custom header", () => {
    expect(loadBearerFile(keyFile(), "X-API-Key").credential).toMatchObject({ header: "x-api-key", value: KEY });
  });

  it("refuses empty files, several words, symlinks and unsafe headers", () => {
    expect(() => loadBearerFile(keyFile(""))).toThrow(/empty/);
    expect(() => loadBearerFile(keyFile("Bearer abc"))).toThrow(StaticKeyError);
    expect(() => loadBearerFile(keyFile("short\n"))).toThrow(/fewer than 8/);
    const target = keyFile();
    const link = join(dir(), "link");
    symlinkSync(target, link);
    expect(() => loadBearerFile(link)).toThrow(/Cannot read/);
    expect(() => loadBearerFile(keyFile(), "Host")).toThrow(/cannot be sent/);
    expect(() => loadBearerFile(keyFile(), "bad header")).toThrow(/Invalid header/);
  });
});

describe("scan with a static key", () => {
  it("runs the endpoint checks with the key on a compliant server, and marks OAuth checks not applicable", async () => {
    const { report, status } = await scanWith(staticServer());
    expect(status["MAP-DSC01"]).toBe("not_applicable");
    for (const id of ["MAP-ORG01", "MAP-TOK01", "MAP-BAT01", "MAP-BOD01", "MAP-THR02"]) expect([id, status[id]]).toEqual([id, "pass"]);
    expect(status["MAP-SES01"]).toBe("not_applicable"); // stateless
    for (const id of ["MAP-RTK01", "MAP-RDR01", "MAP-PKC01", "MAP-AUD01", "MAP-THR01", "MAP-CSR01"]) expect([id, status[id]]).toEqual([id, "not_applicable"]);
    expect(report.findings.find((f) => f.checkId === "MAP-ORG01")?.evidence.join("\n")).toMatch(/"null".*HTTP 403/s);
    // The key never reaches a report.
    expect(toJson(report)).not.toContain(KEY);
  });

  it("finds every planted flaw on a vulnerable server", async () => {
    const { report, status } = await scanWith(
      staticServer({ maxBodyBytes: 16 * 1024 * 1024, mcp: { validateOrigin: false, acceptQueryToken: true, batch: true, sessions: true, sessionWithoutToken: true, rateLimit: undefined as unknown as number } }),
    );
    for (const id of ["MAP-ORG01", "MAP-TOK01", "MAP-SES01", "MAP-BAT01", "MAP-BOD01", "MAP-THR02"]) expect([id, status[id]]).toEqual([id, "fail"]);
    const msg = (id: string) => report.findings.find((f) => f.checkId === id)?.message ?? "";
    expect(msg("MAP-TOK01")).toMatch(/\?access_token=, \?api_key=, \?key=, \?token=/);
    expect(msg("MAP-BAT01")).toMatch(/5 requests ran from one HTTP request/);
    expect(msg("MAP-ORG01")).toMatch(/foreign Origin.*"null".*malformed/);
    expect(toJson(report)).not.toContain(KEY);
  });

  it("works with a custom header", async () => {
    const { status } = await scanWith(staticServer({}, "X-API-Key"), "X-API-Key");
    expect(status["MAP-TOK01"]).toBe("pass");
    expect(status["MAP-BAT01"]).toBe("pass");
  });

  it("is inconclusive everywhere when the key is refused", async () => {
    fixture = await startFixture(staticServer());
    const credential = loadBearerFile(keyFile("sk_wrong_key_000000000000")).credential;
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, credential });
    for (const id of ["MAP-ORG01", "MAP-TOK01", "MAP-BAT01"]) {
      expect(report.findings.find((f) => f.checkId === id)?.message).toMatch(/did not accept the key/);
    }
  });

  it("never sends the key to an unproven host", async () => {
    // The ownership gate: without proof (no loopback exemption), only passive requests go out.
    fixture = await startFixture(staticServer());
    const credential = loadBearerFile(keyFile()).credential;
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, credential, loopbackExempt: false });
    expect(report.ownership.verified).toBe(false);
    expect(report.findings.find((f) => f.checkId === "MAP-BAT01")?.status).toBe("skipped");
    expect(fixture.requests.filter((r) => r.path === "/mcp" && r.method === "POST").length).toBeLessThanOrEqual(4);
  });

  it("only selected endpoint checks run", async () => {
    fixture = await startFixture(staticServer());
    const credential = loadBearerFile(keyFile()).credential;
    const report = await scan(fixture.mcpUrl, { allowPrivate: true, credential, select: (id) => id === "MAP-BAT01" });
    expect(report.findings.find((f) => f.checkId === "MAP-BAT01")?.status).toBe("pass");
    expect(report.findings.find((f) => f.checkId === "MAP-THR02")?.message).toMatch(/Not selected/);
    expect(fixture.requests.filter((r) => r.path === "/mcp").length).toBeLessThan(10);
  });
});

describe("cli", () => {
  it("validates the key options and honours --fail-on-inconclusive", async () => {
    expect(await main(["scan", "https://x.example/mcp", "--bearer-header", "X-API-Key"])).toBe(EXIT.usage);
    expect(await main(["scan", "https://x.example/mcp", "--bearer-file", "/nonexistent/key"])).toBe(EXIT.usage);
    expect(await main(["scan", "https://x.example/mcp", "--rate-attempts", "5"])).toBe(EXIT.usage);
    expect(await main(["scan", "https://x.example/mcp", "--fail-on-inconclusive", "maybe"])).toBe(EXIT.usage);

    // A server that answers the key with 500: every endpoint check is inconclusive.
    fixture = await startFixture(staticServer({ mcp: { authenticatedStatus: 500 } }));
    const file = keyFile();
    const args = ["scan", fixture.mcpUrl, "--allow-private", "--bearer-file", file, "--fail-on", "critical"];
    expect(await main(args)).toBe(EXIT.error);
    expect(await main([...args, "--fail-on-inconclusive", "false"])).toBe(EXIT.ok);
  });
});
