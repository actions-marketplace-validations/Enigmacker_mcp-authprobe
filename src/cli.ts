#!/usr/bin/env node
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { CATALOGUE, getCheck } from "./checks/catalogue.js";
import { loadGrant } from "./credentials.js";
import { HttpClient } from "./net/http.js";
import { DNS_LABEL, generateSecret, proofFor, verifyOwnership, WELL_KNOWN_PATH } from "./ownership.js";
import { toJson } from "./report/json.js";
import { toMarkdown } from "./report/markdown.js";
import { toSarif } from "./report/sarif.js";
import { colorWanted, toTable } from "./report/table.js";
import { scan } from "./scan.js";
import { parseSelection } from "./selection.js";
import { loadBearerFile } from "./static-key.js";
import { loadPostureReport, postureSection, type LoadedPosture } from "./posture.js";
import { severityAtLeast, type Severity } from "./types.js";
import { TOOL_NAME, TOOL_VERSION } from "./version.js";

const SECRET_ENV = "MCP_AUTHPROBE_SECRET";

export const EXIT = { ok: 0, findings: 1, usage: 2, error: 3 } as const;
/** Returned by main() when a long-running server was started: do not exit. */
export const KEEP_RUNNING = -1;

const HELP = `${TOOL_NAME} ${TOOL_VERSION}
Active authorization testing for remote MCP servers you own.

Usage:
  ${TOOL_NAME} scan <mcp-url> [options]
  ${TOOL_NAME} ownership init <host>       Create a secret and the proof to publish
  ${TOOL_NAME} ownership proof <host>      Print the proof for <host> from your secret
  ${TOOL_NAME} ownership verify <host>     Check that the proof is published
  ${TOOL_NAME} checks list                 List every check
  ${TOOL_NAME} checks show <id>            Explain one check
  ${TOOL_NAME} login <mcp-url> --out <file> Log in with a test account and save a test grant
  ${TOOL_NAME} consent-check <mcp-url>     MAP-CSR01: consent CSRF, in a real browser
  ${TOOL_NAME} mcp                         Run as an MCP server over stdio
  ${TOOL_NAME} lab [--profile vulnerable|secure] [--port 8787]
                                           Run a local practice server (loopback only)

Scan options:
  --json <file>         Write the JSON report
  --sarif <file>        Write a SARIF 2.1.0 report
  --markdown <file>     Write a Markdown report
  --fail-on <severity>  Exit 1 on a failing check at or above this severity (default: high)
  --allow-private       Allow loopback/private addresses (local labs only)
  --timeout <ms>        Per-request timeout (default: 10000)
  --secret-file <file>  Read the ownership secret from a file instead of ${SECRET_ENV}
  --throttle-attempts <n>
                        Failed token requests sent by MAP-THR01 (5-20, default 10)
  --verbose             Show every evidence line (default: failing checks only)
  --posture-report <file>
                        Merge an mcp-posture JSON report for the same URL: what the
                        server announces next to what it enforces
  --only <list>         Run only these checks: IDs (MAP-RDR01 or RDR01) or families (RDR),
                        comma-separated; the others are reported as skipped
  --skip <list>         Do not run these checks (same syntax; wins over --only)
  --credentials-file <file>
                        Test grant (JSON: client_id, refresh_token, optional
                        client_secret) for the refresh token checks. The grant
                        is consumed: use a dedicated test account.
  --bearer-file <file>  Static API key for a server authenticated without OAuth
                        (one line, mode 600). Never put the key on the command line.
  --bearer-header <name>
                        Header for the key (default: Authorization, sent as Bearer;
                        any other header gets the key as is, e.g. X-API-Key)
  --rate-attempts <n>   Requests sent by MAP-THR02 with the key (10-100, default 30)
  --fail-on-inconclusive <true|false>
                        Exit 3 when a check is inconclusive (default: true)

Consent check options (needs the optional playwright-core package and Chrome or Edge):
  --browser <channel>   chrome (default), msedge or chromium
  --browser-path <exe>  Use this browser executable instead
  --json, --sarif, --markdown, --fail-on, --allow-private, --secret-file  as for scan

Login options:
  --out <file>          Where to write the test grant (mode 600, never overwritten without --force)
  --force               Overwrite an existing grant file
  --no-probe            Do not observe the login checks (PKC01, RDR03, COD01, AUD01, ORG01, TOK01, SES01)
  --no-browser          Print the authorization URL instead of opening a browser
  --allow-private, --secret-file, --timeout  as for scan

Lab options:
  --profile <name>      vulnerable (default): most checks fail; secure: a compliant server;
                        static-bearer / static-bearer-secure: a server with a static API
                        key and no OAuth (the key is printed when the lab starts)
  --port <n>            Port on 127.0.0.1 (default: 8787; 0 picks a free port)
  --host <address>      127.0.0.1 (default) or ::1; nothing else is accepted

Exit codes: 0 no failing check at or above --fail-on; 1 failing checks;
2 usage error; 3 inconclusive checks (unless --fail-on-inconclusive false)
or a scan that could not run.

The ownership secret is read from ${SECRET_ENV} or --secret-file, never from
the command line, so it does not end up in shell history or process lists.

Only scan servers you own or are explicitly authorized to test.
`;

function readSecret(secretFile: string | undefined): string | undefined {
  if (secretFile) return readFileSync(secretFile, "utf8").trim();
  const value = process.env[SECRET_ENV]?.trim();
  return value ? value : undefined;
}

function out(text: string): void {
  process.stdout.write(text);
}

function err(text: string): void {
  process.stderr.write(text);
}

const SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

export async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: {
      json: { type: "string" },
      sarif: { type: "string" },
      markdown: { type: "string" },
      "fail-on": { type: "string", default: "high" },
      "allow-private": { type: "boolean", default: false },
      timeout: { type: "string" },
      "secret-file": { type: "string" },
      "credentials-file": { type: "string" },
      out: { type: "string" },
      "throttle-attempts": { type: "string" },
      only: { type: "string" },
      "bearer-file": { type: "string" },
      "bearer-header": { type: "string" },
      "rate-attempts": { type: "string" },
      "fail-on-inconclusive": { type: "string" },
      "posture-report": { type: "string" },
      skip: { type: "string" },
      browser: { type: "string" },
      "browser-path": { type: "string" },
      force: { type: "boolean", default: false },
      "no-probe": { type: "boolean", default: false },
      "no-browser": { type: "boolean", default: false },
      verbose: { type: "boolean", default: false },
      profile: { type: "string", default: "vulnerable" },
      port: { type: "string", default: "8787" },
      host: { type: "string", default: "127.0.0.1" },
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", short: "v", default: false },
    },
  });

  if (values.version) {
    out(`${TOOL_VERSION}\n`);
    return EXIT.ok;
  }
  const [command, sub, arg] = positionals;
  if (values.help || !command) {
    out(HELP);
    return values.help ? EXIT.ok : EXIT.usage;
  }

  if (command === "mcp") {
    const { startStdioServer } = await import("./mcp-server.js");
    await startStdioServer();
    return KEEP_RUNNING;
  }

  if (command === "lab") {
    const { LabUsageError, startLab } = await import("./lab-command.js");
    try {
      const { lab, banner } = await startLab({ profile: values.profile, port: values.port, host: values.host });
      err(banner);
      const stop = (): void => {
        void lab.close().finally(() => process.exit(EXIT.ok));
      };
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
      return KEEP_RUNNING;
    } catch (e) {
      err(`${(e as Error).message}\n`);
      return e instanceof LabUsageError ? EXIT.usage : EXIT.error;
    }
  }

  if (command === "checks") {
    if (sub === "list") {
      for (const c of CATALOGUE) {
        out(`${c.id.padEnd(10)} ${c.severity.padEnd(8)} ${(c.active ? "active" : "passive").padEnd(7)} ${c.availability.padEnd(9)} ${c.title}\n`);
      }
      return EXIT.ok;
    }
    if (sub === "show" && arg) {
      const c = getCheck(arg);
      if (!c) {
        err(`Unknown check: ${arg}\n`);
        return EXIT.usage;
      }
      out(
        `${c.id}: ${c.title}\nSeverity: ${c.severity}  Mode: ${c.active ? "active" : "passive"}  Status: ${c.availability}\n\nWhy:\n  ${c.rationale}\n\nFix:\n  ${c.remediation}\n\nReferences:\n${c.references.map((r) => `  - ${r.title}: ${r.url}`).join("\n")}\n`,
      );
      return EXIT.ok;
    }
  }

  if (command === "ownership" && arg) {
    if (sub === "init") {
      const secret = generateSecret();
      out(
        [
          `Secret (store it in a password manager or CI secret, then export it as ${SECRET_ENV}):`,
          ``,
          `  ${secret}`,
          ``,
          `Publish ONE of the following for ${arg}:`,
          ``,
          `  File  https://${arg}${WELL_KNOWN_PATH} containing the line:`,
          `        ${proofFor(arg, secret)}`,
          ``,
          `  DNS   TXT record on ${DNS_LABEL}.${arg} with the value:`,
          `        ${proofFor(arg, secret)}`,
          ``,
          `Repeat "ownership proof <host>" for the authorization server host if it differs.`,
          ``,
        ].join("\n"),
      );
      return EXIT.ok;
    }
    const secret = readSecret(values["secret-file"]);
    if (sub === "proof") {
      if (!secret) {
        err(`Set ${SECRET_ENV} or pass --secret-file.\n`);
        return EXIT.usage;
      }
      out(`${proofFor(arg, secret)}\n`);
      return EXIT.ok;
    }
    if (sub === "verify") {
      const http = new HttpClient({ allowPrivate: values["allow-private"] });
      try {
        const result = await verifyOwnership(arg, secret, { http });
        out(`${result.verified ? "verified" : "NOT verified"}: ${result.detail}\n`);
        return result.verified ? EXIT.ok : EXIT.findings;
      } finally {
        await http.close();
      }
    }
  }

  if (command === "consent-check" && sub) {
    let url: URL;
    try {
      url = new URL(sub);
    } catch {
      err(`Not a URL: ${sub}\n`);
      return EXIT.usage;
    }
    const failOn = values["fail-on"] as Severity;
    if (!SEVERITIES.includes(failOn)) {
      err(`--fail-on must be one of ${SEVERITIES.join(", ")}\n`);
      return EXIT.usage;
    }
    const { runConsentCommand } = await import("./consent-command.js");
    const o: Parameters<typeof runConsentCommand>[0] = {
      mcpUrl: url.toString(),
      allowPrivate: values["allow-private"],
      secret: readSecret(values["secret-file"]),
      failOn,
    };
    if (values.browser) o.browser = values.browser;
    if (values["browser-path"]) o.browserPath = values["browser-path"];
    if (values.json) o.json = values.json;
    if (values.sarif) o.sarif = values.sarif;
    if (values.markdown) o.markdown = values.markdown;
    return runConsentCommand(o);
  }

  if (command === "login" && sub) {
    if (!values.out) {
      err("login needs --out <file> for the test grant.\n");
      return EXIT.usage;
    }
    let url: URL;
    try {
      url = new URL(sub);
    } catch {
      err(`Not a URL: ${sub}\n`);
      return EXIT.usage;
    }
    const { runLoginCommand } = await import("./login-command.js");
    return runLoginCommand({
      mcpUrl: url.toString(),
      out: values.out,
      force: values.force,
      probe: !values["no-probe"],
      browser: !values["no-browser"],
      allowPrivate: values["allow-private"],
      secret: readSecret(values["secret-file"]),
    });
  }

  if (command === "scan" && sub) {
    const failOn = values["fail-on"] as Severity;
    if (!SEVERITIES.includes(failOn)) {
      err(`--fail-on must be one of ${SEVERITIES.join(", ")}\n`);
      return EXIT.usage;
    }
    let url: URL;
    try {
      url = new URL(sub);
    } catch {
      err(`Not a URL: ${sub}\n`);
      return EXIT.usage;
    }
    const timeoutMs = values.timeout ? Number(values.timeout) : undefined;
    if (timeoutMs !== undefined && (!Number.isFinite(timeoutMs) || timeoutMs <= 0)) {
      err(`--timeout must be a positive number of milliseconds\n`);
      return EXIT.usage;
    }

    const options: Parameters<typeof scan>[1] = { allowPrivate: values["allow-private"] };
    try {
      const select = parseSelection(values.only, values.skip);
      if (select) options.select = select;
    } catch (e) {
      err(`${(e as Error).message}\n`);
      return EXIT.usage;
    }
    const secret = readSecret(values["secret-file"]);
    if (secret) options.secret = secret;
    if (timeoutMs !== undefined) options.timeoutMs = timeoutMs;
    if (values["throttle-attempts"] !== undefined) {
      const n = Number(values["throttle-attempts"]);
      if (!Number.isInteger(n) || n < 5 || n > 20) {
        err("--throttle-attempts must be an integer between 5 and 20\n");
        return EXIT.usage;
      }
      options.throttleAttempts = n;
    }
    if (values["bearer-header"] !== undefined && !values["bearer-file"]) {
      err("--bearer-header needs --bearer-file\n");
      return EXIT.usage;
    }
    if (values["bearer-file"]) {
      try {
        const loaded = loadBearerFile(values["bearer-file"], values["bearer-header"]);
        for (const w of loaded.warnings) err(`warning: ${w}\n`);
        options.credential = loaded.credential;
      } catch (e) {
        err(`${(e as Error).message}\n`);
        return EXIT.usage;
      }
    }
    if (values["rate-attempts"] !== undefined) {
      const n = Number(values["rate-attempts"]);
      if (!Number.isInteger(n) || n < 10 || n > 100) {
        err("--rate-attempts must be an integer between 10 and 100\n");
        return EXIT.usage;
      }
      options.rateAttempts = n;
    }
    let failOnInconclusive = true;
    if (values["fail-on-inconclusive"] !== undefined) {
      const v = values["fail-on-inconclusive"].toLowerCase();
      if (!["true", "false", "yes", "no", "1", "0"].includes(v)) {
        err("--fail-on-inconclusive must be true or false\n");
        return EXIT.usage;
      }
      failOnInconclusive = ["true", "yes", "1"].includes(v);
    }
    if (values["credentials-file"]) {
      try {
        const loaded = loadGrant(values["credentials-file"]);
        for (const w of loaded.warnings) err(`warning: ${w}\n`);
        if (loaded.grant) options.grant = loaded.grant;
        options.observations = loaded.observations;
      } catch (e) {
        err(`${(e as Error).message}\n`);
        return EXIT.usage;
      }
    }

    let posture: LoadedPosture | null = null;
    if (values["posture-report"]) {
      try {
        posture = loadPostureReport(values["posture-report"], url.toString());
        for (const w of posture.warnings) err(`warning: ${w}\n`);
      } catch (e) {
        err(`${(e as Error).message}\n`);
        return EXIT.usage;
      }
    }

    let report;
    try {
      report = await scan(url.toString(), options);
      if (posture) report.posture = postureSection(report.findings, posture);
    } catch (e) {
      err(`Scan failed: ${(e as Error).message}\n`);
      return EXIT.error;
    }

    out(toTable(report, { color: colorWanted(), verbose: values.verbose }));
    if (values.json) writeFileSync(values.json, toJson(report));
    if (values.sarif) writeFileSync(values.sarif, toSarif(report));
    if (values.markdown) writeFileSync(values.markdown, toMarkdown(report));

    if (report.findings.some((f) => f.status === "fail" && severityAtLeast(f.severity, failOn))) return EXIT.findings;
    if (failOnInconclusive && report.findings.some((f) => f.status === "error")) return EXIT.error;
    return EXIT.ok;
  }

  err(HELP);
  return EXIT.usage;
}

function isEntryPoint(): boolean {
  const script = process.argv[1];
  if (!script) return false;
  try {
    // Resolve npm's bin symlink before comparing with this module's path.
    return realpathSync(script) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  main(process.argv.slice(2)).then(
    (code) => {
      if (code !== KEEP_RUNNING) process.exitCode = code;
    },
    (e: unknown) => {
      err(`${(e as Error).message}\n`);
      process.exitCode = EXIT.usage;
    },
  );
}
