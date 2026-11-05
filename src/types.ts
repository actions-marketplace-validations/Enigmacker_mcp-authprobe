export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

export function severityAtLeast(value: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(value) >= SEVERITY_ORDER.indexOf(threshold);
}

/** Outcome of a single check against a single target. */
export type CheckStatus = "pass" | "fail" | "not_applicable" | "error" | "skipped";

export interface Reference {
  title: string;
  url: string;
}

/** Static description of a check, independent of any target. */
export interface CheckDefinition {
  /** Stable identifier, never reused, e.g. "MAP-RTK01". */
  id: string;
  title: string;
  severity: Severity;
  /** Whether the check sends state-changing requests to the target. */
  active: boolean;
  /** Family the check belongs to, e.g. "RTK" for refresh tokens. */
  family: string;
  /** "available" checks run today; "planned" ones are documented ahead of time. */
  availability: "available" | "planned";
  rationale: string;
  remediation: string;
  references: readonly Reference[];
}

/** Result of running one check against one target. */
export interface Finding {
  checkId: string;
  title: string;
  severity: Severity;
  status: CheckStatus;
  target: string;
  message: string;
  /** Short, already-redacted evidence lines. Never contains tokens. */
  evidence: string[];
}

export interface ScanReport {
  tool: { name: string; version: string };
  startedAt: string;
  finishedAt: string;
  target: string;
  ownership: { verified: boolean; method: string | null; detail: string };
  findings: Finding[];
  /** Imported mcp-posture results and how they relate to these findings (--posture-report). */
  posture?: import("./posture.js").PostureSection;
}
