import { readFileSync, statSync } from "node:fs";
import { safeText } from "./redact.js";
import type { Finding, Severity } from "./types.js";

/**
 * Import of an mcp-posture JSON report (schema_version 1.x), so one report
 * shows what the server announces (passive, mcp-posture) next to what it
 * enforces (active, mcp-authprobe).
 *
 * The file is untrusted input: its size is capped, every field is type
 * checked, and every string is neutralized before it reaches a report.
 * Posture findings never change mcp-authprobe's exit code.
 */

export interface PostureFinding {
  checkId: string;
  title: string;
  severity: Severity;
  confidence: "low" | "medium" | "high";
  location: string;
  message: string;
  /** Stable across mcp-posture runs: the key for matching findings over time. */
  fingerprint: string;
}

export type CorrelationKind =
  /** mcp-posture saw a sign, mcp-authprobe proved the weakness. */
  | "confirmed"
  /** mcp-authprobe proved a weakness that mcp-posture could not see from metadata. */
  | "active-only"
  /** mcp-posture flagged it from metadata, but the active test shows it is enforced. */
  | "enforced";

export interface Correlation {
  checkId: string;
  kind: CorrelationKind;
  postureIds: string[];
  message: string;
}

export interface PostureSection {
  tool: { name: string; version: string };
  generatedAt: string | null;
  schemaVersion: string;
  findings: PostureFinding[];
  notApplicable: string[];
  correlations: Correlation[];
}

export interface LoadedPosture {
  tool: { name: string; version: string };
  generatedAt: string | null;
  schemaVersion: string;
  findings: PostureFinding[];
  notApplicable: string[];
  warnings: string[];
}

export class PostureReportError extends Error {}

const MAX_BYTES = 5 * 1024 * 1024;
const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);
const CONFIDENCES = new Set(["low", "medium", "high"]);

/**
 * mcp-authprobe checks and the mcp-posture checks that look at the same
 * requirement from the metadata side (see mcp-posture's docs/spec-notes.md).
 * `reserved` lists the active mcp-posture IDs it leaves to mcp-authprobe.
 */
export const POSTURE_MAP: Record<string, { passive: string[]; reserved: string[]; subject: string; unverified?: string[] }> = {
  "MAP-DSC01": { passive: ["MCPP-AUTHN01", "MCPP-AUTHN02", "MCPP-AUTHN03", "MCPP-PRM01", "MCPP-ASM01"], reserved: [], subject: "discovery" },
  "MAP-PKC01": { passive: ["MCPP-ASM04", "MCPP-ASM05"], reserved: ["MCPP-ACT08"], subject: "PKCE" },
  "MAP-AUD01": { passive: ["MCPP-ASM08"], reserved: ["MCPP-ACT03", "MCPP-ACT06"], subject: "token audience", unverified: ["MCPP-ASM08"] },
  "MAP-TOK01": { passive: ["MCPP-PRM06"], reserved: ["MCPP-ACT02"], subject: "tokens in the URL" },
  "MAP-SES01": { passive: ["MCPP-TRN08", "MCPP-TRN09"], reserved: ["MCPP-ACT04"], subject: "sessions" },
  "MAP-ORG01": { passive: [], reserved: ["MCPP-ACT01"], subject: "Origin validation" },
  "MAP-RDR01": { passive: [], reserved: ["MCPP-ACT07"], subject: "redirect URI matching" },
  "MAP-RDR02": { passive: [], reserved: ["MCPP-ACT07"], subject: "redirect URI matching" },
  "MAP-RDR04": { passive: ["MCPP-ASM09"], reserved: ["MCPP-ACT09"], subject: "dynamic client registration" },
};

function str(v: unknown, field: string): string {
  if (typeof v !== "string") throw new PostureReportError(`mcp-posture report: "${field}" must be a string.`);
  return v;
}

function normalizeUrl(u: string): string {
  try {
    return new URL(u).toString();
  } catch {
    return u;
  }
}

/** Parse an mcp-posture report and keep the results for `target` only. */
export function parsePostureReport(raw: unknown, target: string): LoadedPosture {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new PostureReportError("mcp-posture report: expected a JSON object.");
  const r = raw as Record<string, unknown>;
  const schemaVersion = str(r["schema_version"] ?? "1.0", "schema_version");
  if (!/^1\.\d+$/.test(schemaVersion)) {
    throw new PostureReportError(`mcp-posture report: schema_version ${safeText(schemaVersion, 20)} is not supported (expected 1.x).`);
  }
  const warnings: string[] = [];
  if (schemaVersion !== "1.0") warnings.push(`mcp-posture report schema_version ${schemaVersion}: read as 1.0; newer fields are ignored.`);
  const toolRaw = (r["tool"] ?? {}) as Record<string, unknown>;
  const tool = { name: safeText(typeof toolRaw["name"] === "string" ? toolRaw["name"] : "mcp-posture", 40), version: safeText(str(toolRaw["version"] ?? "unknown", "tool.version"), 40) };
  const generatedAt = typeof r["generated_at"] === "string" ? safeText(r["generated_at"], 40) : null;
  if (!Array.isArray(r["targets"])) throw new PostureReportError('mcp-posture report: "targets" must be an array.');

  const wanted = normalizeUrl(target);
  const match = (r["targets"] as unknown[]).find(
    (t) => typeof t === "object" && t !== null && typeof (t as Record<string, unknown>)["target"] === "string" && normalizeUrl((t as Record<string, string>)["target"] as string) === wanted,
  ) as Record<string, unknown> | undefined;
  if (!match) throw new PostureReportError(`mcp-posture report has no result for ${safeText(wanted, 200)}; run mcp-posture on the same URL.`);
  if (match["reachable"] === false) warnings.push("mcp-posture could not reach the target; its findings are incomplete.");

  const findings: PostureFinding[] = [];
  for (const f of Array.isArray(match["findings"]) ? (match["findings"] as unknown[]) : []) {
    if (typeof f !== "object" || f === null) continue;
    const o = f as Record<string, unknown>;
    if (typeof o["check_id"] !== "string" || !SEVERITIES.has(o["severity"] as string)) continue;
    if (o["suppression"] && typeof o["suppression"] === "object") continue; // suppressed by the operator in mcp-posture
    findings.push({
      checkId: safeText(o["check_id"], 30),
      title: safeText(typeof o["title"] === "string" ? o["title"] : "", 200),
      severity: o["severity"] as Severity,
      confidence: CONFIDENCES.has(o["confidence"] as string) ? (o["confidence"] as PostureFinding["confidence"]) : "low",
      location: safeText(typeof o["location"] === "string" ? o["location"] : "", 300),
      message: safeText(typeof o["message"] === "string" ? o["message"] : "", 500),
      fingerprint: safeText(typeof o["fingerprint"] === "string" ? o["fingerprint"] : "", 100),
    });
  }
  const notApplicable = Array.isArray(match["not_applicable"])
    ? (match["not_applicable"] as unknown[]).filter((x): x is string => typeof x === "string").map((x) => safeText(x, 30))
    : [];
  return { tool, generatedAt, schemaVersion, findings, notApplicable, warnings };
}

export function loadPostureReport(path: string, target: string): LoadedPosture {
  if (statSync(path).size > MAX_BYTES) throw new PostureReportError(`mcp-posture report ${path} is larger than 5 MiB.`);
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new PostureReportError(`mcp-posture report ${path} is not valid JSON.`);
  }
  return parsePostureReport(raw, target);
}

/** Relate mcp-authprobe results to the mcp-posture findings on the same subject. */
export function correlate(findings: readonly Finding[], posture: LoadedPosture): Correlation[] {
  const out: Correlation[] = [];
  for (const f of findings) {
    const map = POSTURE_MAP[f.checkId];
    if (!map || (f.status !== "pass" && f.status !== "fail")) continue;
    const related = posture.findings.filter((p) => map.passive.includes(p.checkId) && p.severity !== "info");
    // Info findings that say "cannot be verified passively": the active result settles them.
    const info = posture.findings.filter((p) => (map.unverified ?? []).includes(p.checkId));
    const ids = [...new Set(related.map((p) => p.checkId))];
    const infoIds = [...new Set(info.map((p) => p.checkId))];
    if (f.status === "fail" && ids.length > 0) {
      out.push({ checkId: f.checkId, kind: "confirmed", postureIds: ids, message: `Confirmed: mcp-posture saw it in the metadata (${ids.join(", ")}); the active test proves the weakness.` });
    } else if (f.status === "fail") {
      out.push({
        checkId: f.checkId,
        kind: "active-only",
        postureIds: infoIds,
        message: `Only visible actively (${map.subject}): the metadata gives no sign of it${infoIds.length > 0 ? `, and mcp-posture marks ${infoIds.join(", ")} as not verifiable passively` : ""}; the active test proves the weakness.`,
      });
    } else if (ids.length > 0) {
      out.push({ checkId: f.checkId, kind: "enforced", postureIds: ids, message: `mcp-posture flags ${ids.join(", ")} from the metadata, but the active test shows ${map.subject} is enforced in practice.` });
    } else if (infoIds.length > 0) {
      out.push({ checkId: f.checkId, kind: "enforced", postureIds: infoIds, message: `Resolves ${infoIds.join(", ")}, which mcp-posture cannot verify passively: ${map.subject} is enforced.` });
    }
  }
  return out;
}

export function postureSection(findings: readonly Finding[], posture: LoadedPosture): PostureSection {
  return {
    tool: posture.tool,
    generatedAt: posture.generatedAt,
    schemaVersion: posture.schemaVersion,
    findings: posture.findings,
    notApplicable: posture.notApplicable,
    correlations: correlate(findings, posture),
  };
}
