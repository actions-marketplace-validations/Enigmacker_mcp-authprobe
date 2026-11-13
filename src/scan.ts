import { CATALOGUE } from "./checks/catalogue.js";
import { runRedirectUriChecks } from "./checks/redirect-uris.js";
import { runRefreshTokenChecks } from "./checks/refresh-tokens.js";
import { runThrottlingCheck } from "./checks/throttling.js";
import type { Observation, TestGrant } from "./credentials.js";
import { discover, type DiscoveryResult } from "./discovery.js";
import { runEndpointChecks, runMetadataCheck } from "./checks/endpoint.js";
import { FOREIGN_ORIGIN, initializeStatus, type Credential } from "./oauth/mcp-call.js";
import { HttpClient } from "./net/http.js";
import { verifyOwnership, type OwnershipResult, type VerifyOptions } from "./ownership.js";
import { safeText } from "./redact.js";
import type { CheckSelector } from "./selection.js";
import type { CheckDefinition, Finding, ScanReport } from "./types.js";
import { TOOL_NAME, TOOL_VERSION } from "./version.js";

export interface ScanOptions {
  /** Ownership secret; read from MCP_AUTHPROBE_SECRET by the CLI, never from argv. */
  secret?: string;
  allowPrivate?: boolean;
  timeoutMs?: number;
  /** Test grant for the refresh token checks. It is consumed by the scan. */
  grant?: TestGrant;
  /** Checks to run (from --only/--skip). Unselected checks send no request and are reported as skipped. */
  select?: CheckSelector;
  /**
   * Refuse a grant that does not name its target (MCP mode): a hand-written,
   * unbound grant could otherwise be spent on any proven server.
   */
  requireGrantBinding?: boolean;
  /** Exempt loopback labs from the ownership proof (default true; see VerifyOptions). */
  loopbackExempt?: boolean;
  /** Failed token requests sent by MAP-THR01 (clamped to 5-20, default 10). */
  throttleAttempts?: number;
  /** Results observed during `login` (PKC01, RDR03, COD01, AUD01, ORG01, TOK01, SES01), read from the grant file. */
  observations?: Observation[];
  /**
   * Static API key for servers authenticated without OAuth (--bearer-file).
   * Only sent to the target, and only once ownership of it is proven.
   */
  credential?: Credential;
  /** Requests sent by MAP-THR02 with the static key (clamped to 10-100, default 30). */
  rateAttempts?: number;
  /** Test hooks. */
  resolveTxtRecords?: VerifyOptions["resolveTxtRecords"];
  wellKnownBaseUrl?: string;
}

function finding(def: CheckDefinition, target: string, status: Finding["status"], message: string, evidence: string[] = []): Finding {
  return {
    checkId: def.id,
    title: def.title,
    severity: def.severity,
    status,
    target,
    message: safeText(message),
    evidence: evidence.map((e) => safeText(e)),
  };
}

function dsc01(def: CheckDefinition, d: DiscoveryResult, staticKey: boolean): Finding {
  const missing: string[] = [];
  if (!d.prm) missing.push("Protected Resource Metadata");
  if (!d.as) missing.push("Authorization Server Metadata");
  if (d.as && !d.as.metadata.authorization_endpoint) missing.push("authorization_endpoint");
  if (d.as && !d.as.metadata.token_endpoint) missing.push("token_endpoint");
  const evidence = [
    `challenge: HTTP ${d.challenge.status}${d.challenge.resourceMetadataUrl ? `, resource_metadata=${d.challenge.resourceMetadataUrl}` : ""}`,
    ...(d.prm ? [`PRM: ${d.prm.url}`] : []),
    ...(d.as ? [`AS metadata: ${d.as.url}`] : []),
    ...d.notes,
  ];
  if (missing.length === 0) return finding(def, d.mcpUrl, "pass", "Authorization endpoints discovered.", evidence);
  // A server authenticated by a static key publishes no OAuth metadata: that is expected,
  // but only when the operator says so (a plain 401 also looks like a broken OAuth setup).
  if (staticKey && !d.prm && !d.as && !d.challenge.resourceMetadataUrl) {
    return finding(def, d.mcpUrl, "not_applicable", "No OAuth discovery, as expected for a server authenticated by a static key (--bearer-file).", evidence);
  }
  return finding(def, d.mcpUrl, "fail", `Missing: ${missing.join(", ")}. Active checks cannot run.`, evidence);
}

/** Hosts that active checks would contact: the MCP host and the authorization server host. */
export function hostsToVerify(mcpUrl: string, d: DiscoveryResult | null): string[] {
  const hosts = new Set([new URL(mcpUrl).hostname]);
  for (const endpoint of [d?.as?.metadata.authorization_endpoint, d?.as?.metadata.token_endpoint, d?.as?.metadata.registration_endpoint]) {
    if (typeof endpoint === "string") {
      try {
        hosts.add(new URL(endpoint).hostname);
      } catch {
        /* malformed endpoint: reported by discovery */
      }
    }
  }
  return [...hosts];
}

const RTK_IDS = ["MAP-RTK01", "MAP-RTK02", "MAP-RTK03"];
/** Checks of the MCP endpoint that need a working credential. */
const ENDPOINT_IDS = ["MAP-ORG01", "MAP-TOK01", "MAP-SES01", "MAP-BAT01", "MAP-BOD01", "MAP-INJ01", "MAP-THR02"];

async function runRefreshFamily(target: string, d: DiscoveryResult | null, http: HttpClient, options: ScanOptions): Promise<Finding[]> {
  const defs = RTK_IDS.map((id) => CATALOGUE.find((c) => c.id === id)).filter((c): c is CheckDefinition => c !== undefined);
  const all = (status: Finding["status"], message: string): Finding[] => defs.map((def) => finding(def, target, status, message));

  const tokenEndpoint = d?.as?.metadata.token_endpoint;
  if (typeof tokenEndpoint !== "string") return all("skipped", "No token endpoint discovered.");
  const grants = d?.as?.metadata.grant_types_supported;
  if (Array.isArray(grants) && !grants.includes("refresh_token")) {
    return all("not_applicable", "The authorization server does not advertise the refresh_token grant.");
  }
  const { grant, reason } = grantFor(target, tokenEndpoint, options);
  if (!grant) return all("skipped", reason ?? "No usable test grant.");
  return runRefreshTokenChecks({ http, target, tokenEndpoint, grant });
}

/**
 * Report a result observed during `login`. The observation comes from a
 * local file, so its text is neutralized again and it is only used for the
 * exact target it was observed on.
 */
function fromObservation(checkId: string, target: string, observations: Observation[]): Finding {
  const def = CATALOGUE.find((c) => c.id === checkId) as CheckDefinition;
  const obs = observations.filter((o) => o.checkId === checkId && o.target === target).at(-1);
  if (!obs) return finding(def, target, "skipped", "Observed during login: run `mcp-authprobe login` with ownership proven, then scan with the grant file it writes.");
  return finding(def, target, obs.status, obs.message, [...obs.evidence, `observed during login at ${obs.observedAt}`]);
}

/**
 * MAP-INJ01 without a credential: the result observed during `login`, or,
 * for a server that answers anonymous requests, a reading without one.
 */
async function metadataWithoutCredential(target: string, http: HttpClient, observations: Observation[]): Promise<Finding> {
  const def = CATALOGUE.find((c) => c.id === "MAP-INJ01") as CheckDefinition;
  if (observations.some((o) => o.checkId === def.id && o.target === target)) return fromObservation(def.id, target, observations);
  let anonymous: number;
  try {
    anonymous = await initializeStatus(http, target);
  } catch (err) {
    return finding(def, target, "error", `Request failed: ${(err as Error).message}`);
  }
  if (anonymous >= 200 && anonymous < 300) return runMetadataCheck(http, target);
  return finding(def, target, "skipped", "Needs a credential: run `mcp-authprobe login` (ownership proven) and scan with the grant file it writes, or pass a static key with --bearer-file.", [`initialize without any credential: HTTP ${anonymous}`]);
}

/**
 * The grant usable for this target, or the reason it is not. A grant written
 * by `login` names its target and token endpoint; it is never sent elsewhere.
 */
export function grantFor(target: string, tokenEndpoint: string, options: ScanOptions): { grant: TestGrant | null; reason: string | null } {
  const g = options.grant;
  if (!g) return { grant: null, reason: "Needs a test grant: create one with `mcp-authprobe login`, then pass it with --credentials-file." };
  if (g.target === undefined) {
    if (options.requireGrantBinding) return { grant: null, reason: "The test grant does not name its target; create it with `mcp-authprobe login` so it cannot be spent on another server." };
  } else if (new URL(g.target).toString() !== new URL(target).toString()) {
    return { grant: null, reason: "The test grant belongs to another target; it was not used." };
  }
  if (g.tokenEndpoint !== undefined && new URL(g.tokenEndpoint).toString() !== new URL(tokenEndpoint).toString()) {
    return { grant: null, reason: "The test grant belongs to another token endpoint than the one discovered; it was not used." };
  }
  return { grant: g, reason: null };
}

async function runThrottleFamily(target: string, d: DiscoveryResult | null, http: HttpClient, options: ScanOptions): Promise<Finding> {
  const meta = d?.as?.metadata;
  const def = CATALOGUE.find((c) => c.id === "MAP-THR01") as CheckDefinition;
  if (typeof meta?.token_endpoint !== "string") return finding(def, target, "skipped", "No token endpoint discovered.");
  const ctx: Parameters<typeof runThrottlingCheck>[0] = {
    http,
    target,
    tokenEndpoint: meta.token_endpoint,
    registrationEndpoint: typeof meta.registration_endpoint === "string" ? meta.registration_endpoint : null,
  };
  const { grant } = grantFor(target, meta.token_endpoint, options);
  if (grant) ctx.grant = grant; // otherwise a temporary client is used
  if (options.throttleAttempts !== undefined) ctx.attempts = options.throttleAttempts;
  return runThrottlingCheck(ctx);
}

async function runRedirectFamily(target: string, d: DiscoveryResult | null, http: HttpClient, select: CheckSelector): Promise<Finding[]> {
  const meta = d?.as?.metadata;
  if (!meta) {
    const defs = ["MAP-RDR01", "MAP-RDR02", "MAP-RDR04"].map((id) => CATALOGUE.find((c) => c.id === id)).filter((c): c is CheckDefinition => c !== undefined);
    return defs.map((def) => finding(def, target, "skipped", "No authorization server metadata discovered."));
  }
  const scopes = d?.prm?.metadata.scopes_supported;
  const ctx: Parameters<typeof runRedirectUriChecks>[0] = {
    http,
    target,
    authorizationEndpoint: typeof meta.authorization_endpoint === "string" ? meta.authorization_endpoint : null,
    registrationEndpoint: typeof meta.registration_endpoint === "string" ? meta.registration_endpoint : null,
    resource: d?.prm?.metadata.resource ?? target,
    select,
  };
  if (Array.isArray(scopes) && scopes.length > 0) ctx.scope = scopes.join(" ");
  return runRedirectUriChecks(ctx);
}

function notSelected(checkId: string, target: string): Finding {
  const def = CATALOGUE.find((c) => c.id === checkId) as CheckDefinition;
  return finding(def, target, "skipped", "Not selected (--only/--skip): not run.");
}

/**
 * MAP-COR01. Passive: a CORS preflight and an ordinary request, both with a
 * foreign Origin and no credentials; only the CORS response headers are read.
 */
async function runCorsCheck(target: string, http: HttpClient): Promise<Finding> {
  const def = CATALOGUE.find((c) => c.id === "MAP-COR01") as CheckDefinition;
  const evidence: string[] = [];
  let worst: "credentials" | "reflected" | "wildcard" | "none" = "none";
  const judge = (label: string, headers: Record<string, string>, status: number): void => {
    const acao = headers["access-control-allow-origin"];
    const acac = (headers["access-control-allow-credentials"] ?? "").toLowerCase() === "true";
    evidence.push(`${label}: HTTP ${status}, Access-Control-Allow-Origin ${acao === undefined ? "absent" : `"${acao}"`}${acac ? ", Access-Control-Allow-Credentials true" : ""}`);
    const reflected = acao !== undefined && acao.toLowerCase() === FOREIGN_ORIGIN;
    if (reflected && acac) worst = "credentials";
    else if (reflected && worst !== "credentials") worst = "reflected";
    else if (acao === "*" && worst === "none") worst = "wildcard";
  };
  try {
    const pre = await http.request({
      url: target,
      method: "OPTIONS",
      headers: { origin: FOREIGN_ORIGIN, "access-control-request-method": "POST", "access-control-request-headers": "authorization, content-type, mcp-session-id" },
    });
    judge("preflight (OPTIONS) from a foreign Origin", pre.headers, pre.status);
    const res = await http.request({
      url: target,
      method: "POST",
      headers: { origin: FOREIGN_ORIGIN, "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
    });
    judge("request from a foreign Origin", res.headers, res.status);
  } catch (err) {
    return finding(def, target, "error", `Request failed: ${(err as Error).message}`, evidence);
  }
  switch (worst as string) {
    case "credentials":
      return finding(def, target, "fail", "A foreign Origin is reflected in Access-Control-Allow-Origin together with Access-Control-Allow-Credentials: true: any website can call the endpoint with the user's cookies and read the answers.", evidence);
    case "reflected":
      return finding(def, target, "pass", "A foreign Origin is reflected, but without credentials: a website cannot use the user's cookies, and bearer tokens are not sent by browsers on their own. Prefer an explicit allow-list.", evidence);
    case "wildcard":
      return finding(def, target, "pass", "CORS allows any origin (*) without credentials, which browsers never combine with cookies.", evidence);
    default:
      return finding(def, target, "pass", "No CORS access is granted to a foreign origin.", evidence);
  }
}

/**
 * MAP-ORG01. Passive: two ordinary initialize requests, one with a foreign
 * Origin. Without a token most servers answer 401 before looking at Origin;
 * `login` then observes it with a valid token.
 */
async function runOriginCheck(target: string, http: HttpClient, observations: Observation[], staticKey = false): Promise<Finding> {
  const def = CATALOGUE.find((c) => c.id === "MAP-ORG01") as CheckDefinition;
  if (observations.some((o) => o.checkId === def.id && o.target === target)) return fromObservation(def.id, target, observations);
  let baseline: number;
  let foreign: number;
  try {
    baseline = await initializeStatus(http, target);
    foreign = await initializeStatus(http, target, { origin: FOREIGN_ORIGIN });
  } catch (err) {
    return finding(def, target, "error", `Request failed: ${(err as Error).message}`);
  }
  const evidence = [`initialize without Origin: HTTP ${baseline}`, `initialize with Origin: ${FOREIGN_ORIGIN}: HTTP ${foreign}`];
  if (foreign === 403 && baseline !== 403) return finding(def, target, "pass", "A request from a foreign Origin is refused with 403.", evidence);
  if (baseline >= 200 && baseline < 300 && foreign === baseline) {
    return finding(def, target, "fail", "A request from a foreign Origin is processed like any other: the Origin header is not validated.", evidence);
  }
  if (baseline === 401 && foreign === 401) {
    const next = staticKey
      ? "Prove ownership of the target so the declared key can be used, then scan again."
      : "Run `mcp-authprobe login` (ownership proven) to observe it with a valid token, or pass a static key with --bearer-file.";
    return finding(def, target, "error", `Inconclusive: the server asks for authentication before looking at Origin. ${next}`, evidence);
  }
  return finding(def, target, "error", "Unexpected answers; inconclusive.", evidence);
}

export async function scan(mcpUrl: string, options: ScanOptions = {}): Promise<ScanReport> {
  const startedAt = new Date().toISOString();
  const target = new URL(mcpUrl).toString();
  const httpOptions: ConstructorParameters<typeof HttpClient>[0] = { allowPrivate: options.allowPrivate ?? false };
  if (options.timeoutMs !== undefined) httpOptions.timeoutMs = options.timeoutMs;
  const http = new HttpClient(httpOptions);
  const findings: Finding[] = [];

  try {
    let discovery: DiscoveryResult | null = null;
    const dscDef = CATALOGUE.find((c) => c.id === "MAP-DSC01");
    try {
      discovery = await discover(target, http);
      if (dscDef) findings.push(dsc01(dscDef, discovery, options.credential?.kind === "static"));
    } catch (err) {
      if (dscDef) findings.push(finding(dscDef, target, "error", `Discovery failed: ${(err as Error).message}`));
    }

    // Every host an active check would touch must be proven.
    const verifyOpts: VerifyOptions = { http, loopbackExempt: options.loopbackExempt ?? true };
    if (options.resolveTxtRecords) verifyOpts.resolveTxtRecords = options.resolveTxtRecords;
    const results: OwnershipResult[] = [];
    for (const host of hostsToVerify(target, discovery)) {
      const perHost = { ...verifyOpts };
      if (options.wellKnownBaseUrl && host === new URL(target).hostname) perHost.wellKnownBaseUrl = options.wellKnownBaseUrl;
      results.push(await verifyOwnership(host, options.secret, perHost));
    }
    const verified = results.length > 0 && results.every((r) => r.verified);
    const ownership: ScanReport["ownership"] = {
      verified,
      method: verified ? [...new Set(results.map((r) => r.method))].join("+") : null,
      detail: results.map((r) => `${r.host}: ${r.detail}`).join(" "),
    };

    const wanted: CheckSelector = options.select ?? (() => true);
    const anyOf = (ids: string[]): boolean => ids.some(wanted);
    // With a static key and ownership proven, the MCP endpoint checks run with the key.
    const handled = new Set<string>();
    if (options.credential && verified) {
      const ids = (["MAP-ORG01", "MAP-TOK01", "MAP-SES01", "MAP-BAT01", "MAP-BOD01", "MAP-INJ01", "MAP-THR02"] as const).filter(wanted);
      if (ids.length > 0) {
        const ep = await runEndpointChecks(http, target, options.credential, { checks: ids, ...(options.rateAttempts !== undefined ? { rateAttempts: options.rateAttempts } : {}) });
        findings.push(...ep.findings);
        for (const id of ids) handled.add(id);
      }
    }
    if (wanted("MAP-ORG01") && !handled.has("MAP-ORG01")) findings.push(await runOriginCheck(target, http, options.observations ?? [], options.credential?.kind === "static"));
    if (wanted("MAP-COR01")) findings.push(await runCorsCheck(target, http));

    const active = CATALOGUE.filter((c) => c.active);
    if (!verified) {
      for (const def of active) {
        findings.push(finding(def, target, "skipped", "Ownership of every contacted host is not proven; active check not run."));
      }
    } else if (options.credential?.kind === "static" && discovery !== null && !discovery.prm && !discovery.as && !discovery.challenge.resourceMetadataUrl) {
      // No OAuth on this server: the authorization server checks do not apply.
      for (const def of active.filter((c) => !handled.has(c.id) && !ENDPOINT_IDS.includes(c.id))) {
        findings.push(finding(def, target, "not_applicable", "The server does not use OAuth (static key declared, no authorization server discovered)."));
      }
    } else {
      // The refresh token checks are one sequence: they run together, or not at all (the grant is untouched).
      if (anyOf(RTK_IDS)) findings.push(...(await runRefreshFamily(target, discovery, http, options)));
      if (anyOf(["MAP-RDR01", "MAP-RDR02", "MAP-RDR04"])) findings.push(...(await runRedirectFamily(target, discovery, http, wanted)));
      for (const id of ["MAP-RDR03", "MAP-PKC01", "MAP-COD01", "MAP-AUD01", "MAP-TOK01", "MAP-SES01", "MAP-BAT01", "MAP-BOD01"]) {
        if (!handled.has(id)) findings.push(fromObservation(id, target, options.observations ?? []));
      }
      if (wanted("MAP-INJ01") && !handled.has("MAP-INJ01")) findings.push(await metadataWithoutCredential(target, http, options.observations ?? []));
      const csr = CATALOGUE.find((c) => c.id === "MAP-CSR01") as CheckDefinition;
      findings.push(finding(csr, target, "skipped", "Needs a logged-in browser session: run `mcp-authprobe consent-check` separately."));
      // Last on purpose: once throttled, the token endpoint may refuse other checks.
      if (wanted("MAP-THR01")) findings.push(await runThrottleFamily(target, discovery, http, options));
      if (!handled.has("MAP-THR02")) {
        const thr02 = CATALOGUE.find((c) => c.id === "MAP-THR02") as CheckDefinition;
        findings.push(finding(thr02, target, "skipped", "Needs a static key: pass it with --bearer-file."));
      }
      for (const def of active.filter((c) => c.availability === "planned")) {
        findings.push(finding(def, target, "skipped", "Not implemented in this version yet."));
      }
    }

    // Every check appears once: unselected ones as skipped, in catalogue order of first appearance.
    if (options.select) {
      const seen = new Set<string>();
      const kept: Finding[] = [];
      for (const f of findings) {
        if (seen.has(f.checkId)) continue;
        seen.add(f.checkId);
        kept.push(wanted(f.checkId) ? f : notSelected(f.checkId, target));
      }
      for (const def of CATALOGUE) if (!seen.has(def.id)) kept.push(notSelected(def.id, target));
      findings.splice(0, findings.length, ...kept);
    }

    return {
      tool: { name: TOOL_NAME, version: TOOL_VERSION },
      startedAt,
      finishedAt: new Date().toISOString(),
      target,
      ownership,
      findings,
    };
  } finally {
    await http.close();
  }
}
