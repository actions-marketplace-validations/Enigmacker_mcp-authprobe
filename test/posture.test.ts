import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { correlate, parsePostureReport, PostureReportError, type LoadedPosture } from "../src/posture.js";
import { toMarkdown } from "../src/report/markdown.js";
import { toTable } from "../src/report/table.js";
import type { Finding, ScanReport } from "../src/types.js";

// Real output of mcp-posture 1.1.3 against `mcp-authprobe lab` on port 8787.
const real = JSON.parse(readFileSync(new URL("./fixtures/posture/lab-vulnerable.json", import.meta.url), "utf8")) as Record<string, unknown>;
const TARGET = "http://127.0.0.1:8787/mcp";

const finding = (checkId: string, status: Finding["status"]): Finding => ({ checkId, title: "t", severity: "high", status, target: TARGET, message: "m", evidence: [] });
const posture = (findings: Array<[string, Finding["severity"]]>): LoadedPosture => ({
  tool: { name: "mcp-posture", version: "1" },
  generatedAt: null,
  schemaVersion: "1.0",
  notApplicable: [],
  warnings: [],
  findings: findings.map(([checkId, severity]) => ({ checkId, severity, title: "", confidence: "high", location: "", message: "", fingerprint: "f" })),
});

describe("mcp-posture report import", () => {
  it("reads a real report for the matching target", () => {
    const p = parsePostureReport(real, TARGET);
    expect(p.tool.name).toBe("mcp-posture");
    expect(p.schemaVersion).toBe("1.0");
    expect(p.findings.length).toBe(13);
    expect(p.findings.every((f) => f.fingerprint.length > 0)).toBe(true);
    expect(p.findings.map((f) => f.checkId)).toContain("MCPP-ASM08");
    expect(p.notApplicable).toContain("MCPP-TRN08");
  });

  it("refuses another target, an unknown schema version and malformed input", () => {
    expect(() => parsePostureReport(real, "http://127.0.0.1:9999/mcp")).toThrow(/no result for/);
    expect(() => parsePostureReport({ ...real, schema_version: "2.0" }, TARGET)).toThrow(/not supported/);
    expect(() => parsePostureReport([], TARGET)).toThrow(PostureReportError);
    expect(() => parsePostureReport({ schema_version: "1.0", targets: "x" }, TARGET)).toThrow(/targets/);
  });

  it("neutralizes text from the file and drops suppressed findings", () => {
    const hostile = {
      schema_version: "1.0",
      tool: { version: "1" },
      targets: [
        {
          target: TARGET,
          findings: [
            { check_id: "MCPP-X01", title: "t", severity: "high", confidence: "high", target: TARGET, location: "l", message: "evil \u001b[2J‮ access_token=abcdefgh123", fingerprint: "a" },
            { check_id: "MCPP-X02", title: "t", severity: "high", confidence: "high", target: TARGET, location: "l", message: "ok", fingerprint: "b", suppression: { justification: "accepted" } },
            { check_id: 42, severity: "nope" },
          ],
        },
      ],
    };
    const p = parsePostureReport(hostile, TARGET);
    expect(p.findings.map((f) => f.checkId)).toEqual(["MCPP-X01"]);
    expect(p.findings[0]?.message).not.toMatch(/\u001b|‮|abcdefgh123/);
  });

  it("relates active results to passive findings", () => {
    const kinds = (fs: Finding[], p: LoadedPosture) => correlate(fs, p).map((c) => [c.checkId, c.kind]);
    expect(kinds([finding("MAP-PKC01", "fail")], posture([["MCPP-ASM04", "medium"]]))).toEqual([["MAP-PKC01", "confirmed"]]);
    expect(kinds([finding("MAP-PKC01", "fail")], posture([]))).toEqual([["MAP-PKC01", "active-only"]]);
    expect(kinds([finding("MAP-PKC01", "pass")], posture([["MCPP-ASM04", "medium"]]))).toEqual([["MAP-PKC01", "enforced"]]);
    expect(kinds([finding("MAP-AUD01", "pass")], posture([["MCPP-ASM08", "info"]]))).toEqual([["MAP-AUD01", "enforced"]]);
    // Nothing to say: a passing check without related passive findings, or a check that did not run.
    expect(kinds([finding("MAP-PKC01", "pass"), finding("MAP-ORG01", "error")], posture([["MCPP-ASM04", "info"]]))).toEqual([]);
  });

  it("adds a passive section to the table and Markdown reports", () => {
    const p = parsePostureReport(real, TARGET);
    const findings = [finding("MAP-AUD01", "fail"), finding("MAP-PKC01", "pass")];
    const report: ScanReport = {
      tool: { name: "mcp-authprobe", version: "0" },
      startedAt: "",
      finishedAt: "",
      target: TARGET,
      ownership: { verified: true, method: "loopback", detail: "" },
      findings,
      posture: { ...p, correlations: correlate(findings, p) },
    };
    expect(toTable(report)).toMatch(/mcp-posture 1\.1\.3 \(passive\): 13 finding\(s\) \(7 medium, 3 low, 3 info\)/);
    expect(toTable(report)).toMatch(/active only +MAP-AUD01 .*MCPP-ASM08 as not verifiable passively/);
    const md = toMarkdown(report);
    expect(md).toMatch(/## Passive results from mcp-posture 1\.1\.3/);
    expect(md).toMatch(/\| MAP-AUD01 \| active-only \| MCPP-ASM08 \|/);
    expect(md).toMatch(/\| medium \| MCPP-ASM03 \|/);
  });
});
