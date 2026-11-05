import { SEVERITY_ORDER, type Finding, type ScanReport } from "../types.js";

function escapeCell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\r?\n/g, "<br>");
}

const STATUS_LABEL: Record<Finding["status"], string> = {
  fail: "FAIL",
  pass: "pass",
  not_applicable: "n/a",
  error: "error",
  skipped: "skipped",
};

export function toMarkdown(report: ScanReport): string {
  const sorted = [...report.findings].sort(
    (a, b) =>
      Number(b.status === "fail") - Number(a.status === "fail") ||
      SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity) ||
      a.checkId.localeCompare(b.checkId),
  );
  const failures = report.findings.filter((f) => f.status === "fail").length;

  const lines = [
    `# mcp-authprobe report`,
    ``,
    `- **Target:** \`${report.target}\``,
    `- **Ownership:** ${report.ownership.verified ? `verified (${report.ownership.method})` : "not verified"}: ${report.ownership.detail}`,
    `- **Started:** ${report.startedAt}`,
    `- **Tool:** ${report.tool.name} ${report.tool.version}`,
    `- **Failing checks:** ${failures}`,
    ``,
    `| Status | Severity | Check | Message |`,
    `| --- | --- | --- | --- |`,
    ...sorted.map(
      (f) => `| ${STATUS_LABEL[f.status]} | ${f.severity} | ${f.checkId} | ${escapeCell(f.message)} |`,
    ),
    ``,
  ];
  if (report.posture) {
    const p = report.posture;
    lines.push(
      `## Passive results from ${p.tool.name} ${p.tool.version}`,
      ``,
      `What the server announces (${p.tool.name}${p.generatedAt ? `, ${p.generatedAt}` : ""}) next to what it enforces (mcp-authprobe).`,
      ``,
    );
    if (p.correlations.length > 0) {
      lines.push(`| Check | Relation | mcp-posture | Note |`, `| --- | --- | --- | --- |`);
      for (const c of p.correlations) lines.push(`| ${c.checkId} | ${c.kind} | ${c.postureIds.join(", ") || "-"} | ${escapeCell(c.message)} |`);
      lines.push(``);
    }
    if (p.findings.length > 0) {
      lines.push(`| Severity | mcp-posture check | Message |`, `| --- | --- | --- |`);
      for (const f of [...p.findings].sort((a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity))) {
        lines.push(`| ${f.severity} | ${f.checkId} | ${escapeCell(f.message)} |`);
      }
      lines.push(``);
    }
  }
  return lines.join("\n");
}
