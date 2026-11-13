import { spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { CATALOGUE } from "./checks/catalogue.js";
import type { Observation, TestGrant } from "./credentials.js";
import type { DiscoveryResult } from "./discovery.js";
import type { HttpClient } from "./net/http.js";
import { runEndpointChecks } from "./checks/endpoint.js";
import { bearerCredential, initializeStatus } from "./oauth/mcp-call.js";
import { describe as describeOutcome, exchangeCode, refresh, type CodeExchangeOutcome } from "./oauth/token-client.js";
import { deleteClient, registerClient, SAFE_DOMAIN, type RegisteredClient } from "./oauth/registration.js";
import { safeText } from "./redact.js";

/**
 * Interactive login to the user's own MCP server, producing a test grant.
 *
 * It behaves like a careful native MCP client (RFC 8252):
 *   - a loopback listener on 127.0.0.1 with a random port, accepting only
 *     GET /callback with the expected state, and echoing nothing back;
 *   - dynamic client registration for that loopback redirect URI;
 *   - authorization code flow with PKCE S256, random state, the RFC 8707
 *     resource, and the RFC 9207 iss check;
 *   - the browser only ever opens the discovered authorization endpoint.
 *
 * When the hosts are proven (ownership gate), it also observes MAP-RDR03:
 * before the real exchange, it presents the code with a different
 * redirect_uri, which a compliant token endpoint must refuse.
 */

export interface LoginOptions {
  http: HttpClient;
  mcpUrl: string;
  discovery: DiscoveryResult;
  /** Opens the authorization URL (a browser in the CLI, a scripted agent in tests). */
  openUrl: (url: string) => Promise<void>;
  /** Run the login checks (PKC01, RDR03, AUD01, ORG01, COD01). Only set when ownership of every contacted host is proven. */
  probe: boolean;
  /** How long to wait for the user to finish in the browser. */
  timeoutMs?: number;
  /** Status lines for the user (stderr in the CLI). Never receives secrets. */
  log?: (line: string) => void;
}

export interface LoginResult {
  grant: TestGrant | null;
  observations: Observation[];
  notes: string[];
}

export class LoginError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LoginError";
  }
}

interface CallbackParams {
  code: string | null;
  error: string | null;
  iss: string | null;
}

function equalStrings(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/** Loopback listener that resolves with the first callback carrying the right state. */
async function startCallbackListener(expectedState: string): Promise<{ redirectUri: string; mismatchUri: string; result: Promise<CallbackParams>; close: () => Promise<void> }> {
  let resolveResult!: (p: CallbackParams) => void;
  const result = new Promise<CallbackParams>((resolve) => {
    resolveResult = resolve;
  });
  let done = false;

  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const state = url.searchParams.get("state") ?? "";
    if (req.method !== "GET" || url.pathname !== "/callback" || done || !equalStrings(state, expectedState)) {
      res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      res.end("Unexpected request.");
      return;
    }
    done = true;
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
    res.end("mcp-authprobe: authorization received. You can close this tab.");
    resolveResult({ code: url.searchParams.get("code"), error: url.searchParams.get("error"), iss: url.searchParams.get("iss") });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    redirectUri: `http://127.0.0.1:${port}/callback`,
    mismatchUri: `http://127.0.0.1:${port}/callback-mismatch`,
    result,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    p,
    new Promise<T>((_, reject) => {
      timer = setTimeout(() => reject(new LoginError(message)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

function observation(checkId: string, target: string, status: Observation["status"], message: string, evidence: string[]): Observation {
  const def = CATALOGUE.find((c) => c.id === checkId);
  if (!def) throw new Error(`Unknown check ${checkId}`);
  return {
    checkId,
    title: def.title,
    severity: def.severity,
    status,
    target,
    message: safeText(message),
    evidence: evidence.map((e) => safeText(e)),
    observedAt: new Date().toISOString(),
  };
}

function scopesFor(d: DiscoveryResult): string | undefined {
  const fromChallenge = /scope="([^"]+)"/i.exec(d.challenge.wwwAuthenticate ?? "")?.[1];
  const scopes = new Set((fromChallenge ?? d.prm?.metadata.scopes_supported?.join(" ") ?? "").split(/\s+/).filter(Boolean));
  // Ask for a refresh token where the server models it as a scope.
  const asScopes = d.as?.metadata["scopes_supported"];
  if (Array.isArray(asScopes) && asScopes.includes("offline_access")) scopes.add("offline_access");
  return scopes.size > 0 ? [...scopes].join(" ") : undefined;
}

export async function login(opts: LoginOptions): Promise<LoginResult> {
  const { http, discovery: d } = opts;
  const log = opts.log ?? (() => undefined);
  const meta = d.as?.metadata;
  const target = opts.mcpUrl;
  const issuer = typeof meta?.issuer === "string" ? meta.issuer : null;
  const authorizationEndpoint = typeof meta?.authorization_endpoint === "string" ? meta.authorization_endpoint : null;
  const tokenEndpoint = typeof meta?.token_endpoint === "string" ? meta.token_endpoint : null;
  const registrationEndpoint = typeof meta?.registration_endpoint === "string" ? meta.registration_endpoint : null;
  if (!authorizationEndpoint || !tokenEndpoint) throw new LoginError("The authorization server does not advertise authorization and token endpoints.");
  if (!registrationEndpoint) throw new LoginError("The authorization server does not offer dynamic client registration; pre-registered clients are not supported yet.");

  const authUrl = new URL(authorizationEndpoint);
  if (authUrl.protocol !== "https:" && !http.allowPrivate) throw new LoginError("Refusing to open a non-https authorization endpoint.");
  const methods = meta?.code_challenge_methods_supported;
  if (Array.isArray(methods) && !methods.includes("S256")) throw new LoginError("The authorization server does not support PKCE S256.");

  const state = randomBytes(24).toString("base64url");
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const listener = await startCallbackListener(state);
  const notes: string[] = [];
  const observations: Observation[] = [];
  let registered: RegisteredClient | null = null;
  let keepClient = false;

  try {
    const reg = await registerClient(http, registrationEndpoint, [listener.redirectUri], {
      clientName: "mcp-authprobe test login",
      grantTypes: ["authorization_code", "refresh_token"],
    });
    if (!reg.client) throw new LoginError(`Dynamic client registration failed (HTTP ${reg.status}${reg.error ? `, error=${safeText(reg.error, 80)}` : ""}).`);
    const client = reg.client;
    registered = client;
    log(`Registered test client ${safeText(client.clientId, 120)}.`);

    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", client.clientId);
    authUrl.searchParams.set("redirect_uri", listener.redirectUri);
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("code_challenge", challenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    const resource = d.prm?.metadata.resource ?? target;
    authUrl.searchParams.set("resource", resource);
    const scope = scopesFor(d);
    if (scope) authUrl.searchParams.set("scope", scope);

    log("Opening the authorization page. Log in with your dedicated TEST account.");
    await opts.openUrl(authUrl.toString());
    const cb = await withTimeout(listener.result, opts.timeoutMs ?? 5 * 60_000, "Timed out waiting for the authorization response.");

    if (cb.error) throw new LoginError(`The authorization server returned error=${safeText(cb.error, 80)}.`);
    if (!cb.code) throw new LoginError("The authorization response carried no code.");
    // RFC 9207: reject a response from another issuer (mix-up attacks).
    if (cb.iss !== null && issuer !== null && cb.iss !== issuer) throw new LoginError("The iss parameter does not match the discovered issuer; aborting.");
    if (cb.iss === null && meta?.["authorization_response_iss_parameter_supported"] === true) {
      throw new LoginError("The server announces the iss parameter but the response has none; aborting.");
    }

    const exchangeParams = { clientId: client.clientId, clientSecret: client.clientSecret, code: cb.code, resource };
    const correct = { ...exchangeParams, codeVerifier: verifier, redirectUri: listener.redirectUri };
    let tokens: CodeExchangeOutcome | null = null;
    let tokensFromProbe = false;

    // --- Before the real exchange: refused attempts with a broken request ---
    type Verdict = "accepted" | "refused" | "inconclusive" | "not_run";
    interface ProbeResult { checkId: string; label: string; verdict: Verdict; line: string }
    const results: ProbeResult[] = [];
    const classify = (o: CodeExchangeOutcome): Verdict =>
      o.accessTokenIssued ? "accepted" : o.status >= 400 && o.status < 500 && !o.throttled ? "refused" : "inconclusive";

    if (opts.probe) {
      const preProbes: Array<{ checkId: string; label: string; params: Parameters<typeof exchangeCode>[2] }> = [
        { checkId: "MAP-PKC01", label: "code presented without a code_verifier (PKCE)", params: { ...exchangeParams, redirectUri: listener.redirectUri } },
        { checkId: "MAP-PKC01", label: "code presented with a wrong code_verifier (PKCE)", params: { ...correct, codeVerifier: randomBytes(32).toString("base64url") } },
        { checkId: "MAP-RDR03", label: "code presented with a different redirect_uri", params: { ...correct, redirectUri: listener.mismatchUri } },
      ];
      for (const p of preProbes) {
        if (tokens) {
          results.push({ checkId: p.checkId, label: p.label, verdict: "not_run", line: `${p.label}: not run, the code was already exchanged` });
          continue;
        }
        const o = await exchangeCode(http, tokenEndpoint, p.params);
        const verdict = classify(o);
        results.push({ checkId: p.checkId, label: p.label, verdict, line: `${p.label}: ${describeOutcome(o)}` });
        if (verdict === "accepted") {
          tokens = o; // the code is spent; keep these tokens as the grant
          tokensFromProbe = true;
        }
      }
    } else {
      notes.push("MAP-PKC01, MAP-RDR03, MAP-COD01, MAP-AUD01, MAP-ORG01, MAP-TOK01, MAP-SES01, MAP-BAT01, MAP-BOD01 and MAP-INJ01 were not observed: ownership of the contacted hosts is not proven, or --no-probe was used.");
    }

    // --- The real exchange ---
    let codeBurnt = false;
    let exchangeFailure: string | null = null;
    if (!tokens) {
      tokens = await exchangeCode(http, tokenEndpoint, correct);
      if (!tokens.accessTokenIssued) {
        if (opts.probe && tokens.error === "invalid_grant") {
          codeBurnt = true;
        } else if (opts.probe && results.some((r) => r.verdict !== "not_run")) {
          // Keep what the probes observed; only the first refusal is trusted.
          codeBurnt = true;
          exchangeFailure = safeText(describeOutcome(tokens), 200);
        } else {
          throw new LoginError(`Code exchange failed: ${safeText(describeOutcome(tokens), 200)}.`);
        }
      }
    }
    if (codeBurnt) {
      // The first refusal invalidated the code: only that first result is meaningful.
      let first = true;
      for (const r of results) {
        if (r.verdict === "refused" && !first) {
          r.verdict = "inconclusive";
          r.line += " (inconclusive: the code had already been invalidated by an earlier refused attempt)";
        }
        if (r.verdict !== "not_run") first = false;
      }
    }

    const PRE_MESSAGES: Record<string, { pass: string; fail: string }> = {
      "MAP-PKC01": {
        pass: "The token endpoint refused the code without a code_verifier and with a wrong one.",
        fail: "The token endpoint exchanged a code without a valid code_verifier, so PKCE is not enforced and an intercepted code can be redeemed.",
      },
      "MAP-RDR03": {
        pass: "The token endpoint refused a code presented with a different redirect_uri.",
        fail: "The token endpoint exchanged a code presented with a redirect_uri different from the one used at authorization.",
      },
    };
    for (const checkId of ["MAP-PKC01", "MAP-RDR03"]) {
      const rs = results.filter((r) => r.checkId === checkId && r.verdict !== "not_run");
      const lines = results.filter((r) => r.checkId === checkId).map((r) => r.line);
      if (rs.length === 0) {
        if (lines.length > 0) observations.push(observation(checkId, target, "skipped", "Not observed: an earlier probe already obtained tokens with this code (see the other login checks).", lines));
        continue;
      }
      const msg = PRE_MESSAGES[checkId] as { pass: string; fail: string };
      if (rs.some((r) => r.verdict === "accepted")) observations.push(observation(checkId, target, "fail", msg.fail, lines));
      else if (rs.some((r) => r.verdict === "inconclusive")) observations.push(observation(checkId, target, "error", "Inconclusive: some attempts got an unexpected answer or could not be told apart from an earlier refusal.", lines));
      else observations.push(observation(checkId, target, "pass", msg.pass, lines));
    }

    if (codeBurnt) {
      notes.push(
        exchangeFailure
          ? `The code exchange failed after the probes (${exchangeFailure}); only the first refusal is trusted. The results are saved; run login again with --no-probe --force --out <same file> to obtain a test grant.`
          : "The server invalidated the code after the first refused attempt (a strict, acceptable behaviour). The results are saved; run login again with --no-probe --force --out <same file> to obtain a test grant.",
      );
      return { grant: null, observations, notes };
    }
    // Without a refresh token there is no grant, but the checks that only need
    // the access token (ORG01, COD01) still run.
    const grant: TestGrant | null = tokens.refreshToken ? {
      clientId: client.clientId,
      refreshToken: tokens.refreshToken,
      authMethod: client.clientSecret ? "client_secret_post" : "none",
      // Bind the grant to where it came from: scans of other targets will not use it.
      target: new URL(target).toString(),
      tokenEndpoint: new URL(tokenEndpoint).toString(),
    } : null;
    if (grant && client.clientSecret) grant.clientSecret = client.clientSecret;

    if (opts.probe) {
      await postExchangeProbes({ http, target, tokenEndpoint, grant, tokens, correct, tokensFromProbe, observations, notes, results });
      if (notes.some((n) => n.startsWith(REVOKED_NOTE))) return { grant: null, observations, notes };
    }
    if (!grant) {
      notes.push("Login succeeded but no refresh token was issued; the refresh token checks cannot run with this server configuration.");
      return { grant: null, observations, notes };
    }
    keepClient = true; // the grant belongs to this client
    return { grant, observations, notes };
  } finally {
    await listener.close();
    // Without a usable grant the client is useless: remove it when possible.
    if (registered && !keepClient) await deleteClient(http, registered, registrationEndpoint);
  }
}

/** Open a URL in the default browser without going through a shell. */
export function openInBrowser(url: string): Promise<void> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return Promise.reject(new Error("Refusing to open a non-HTTP URL."));
  const [cmd, args] =
    process.platform === "darwin"
      ? ["open", [url]]
      : process.platform === "win32"
        ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
        : ["xdg-open", [url]];
  return new Promise((resolve) => {
    try {
      const child = spawn(cmd, args as string[], { stdio: "ignore", detached: true, shell: false });
      child.on("error", () => resolve()); // no browser: the URL is printed anyway
      child.unref();
    } catch {
      /* the URL is printed anyway */
    }
    resolve();
  });
}


const REVOKED_NOTE = "The server revoked the tokens after the code reuse attempt";

interface PostExchange {
  http: HttpClient;
  target: string;
  tokenEndpoint: string;
  /** Null when no refresh token was issued. */
  grant: TestGrant | null;
  tokens: CodeExchangeOutcome;
  correct: Parameters<typeof exchangeCode>[2];
  tokensFromProbe: boolean;
  observations: Observation[];
  notes: string[];
  results: Array<{ checkId: string }>;
}

const is2xx = (s: number | null): s is number => s !== null && s >= 200 && s < 300;

/** Audience of a JWT access token, read without verification (attribution only), or null. */
export function jwtAudience(token: string): string[] | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1] as string, "base64url").toString("utf8")) as { aud?: unknown };
    if (typeof payload.aud === "string") return [payload.aud];
    if (Array.isArray(payload.aud) && payload.aud.every((a) => typeof a === "string")) return payload.aud as string[];
    return null;
  } catch {
    return null;
  }
}

/**
 * Checks that need tokens: MAP-ORG01 and MAP-AUD01 (with the access token,
 * before any refresh), then MAP-COD01 (last: it may revoke the grant). Each
 * one turns a network failure into an inconclusive result, so the grant and
 * the earlier observations are never lost. The grant always keeps the newest
 * refresh token.
 */
async function postExchangeProbes(c: PostExchange): Promise<void> {
  const { http, target, tokenEndpoint, grant, tokens, observations } = c;
  const guard = async (checkId: string, run: () => Promise<void>): Promise<void> => {
    try {
      await run();
    } catch (e) {
      observations.push(observation(checkId, target, "error", `Inconclusive: a request failed (${(e as Error).message}).`, []));
    }
  };

  // Checks of the MCP endpoint with the access token, before any refresh
  // (a refresh may invalidate it): ORG01, TOK01, SES01, BAT01, BOD01, INJ01.
  let control: number | null = null;
  const accessToken = tokens.accessToken;
  if (accessToken) {
    const ep = await runEndpointChecks(http, target, bearerCredential(accessToken));
    control = ep.control;
    for (const f of ep.findings) observations.push({ ...f, observedAt: new Date().toISOString() });
  } else {
    for (const id of ["MAP-ORG01", "MAP-TOK01", "MAP-SES01", "MAP-BAT01", "MAP-BOD01", "MAP-INJ01"]) {
      observations.push(observation(id, target, "error", "Inconclusive: the token endpoint issued no access token.", []));
    }
  }

  await guard("MAP-AUD01", async () => {
    const lines = [`control, token for this server: ${control === null ? "not available" : `HTTP ${control}`}`];
    if (!is2xx(control)) {
      observations.push(observation("MAP-AUD01", target, "error", "Inconclusive: the token issued for this server was not accepted by it, so audience binding cannot be judged.", lines));
      return;
    }
    if (!grant) {
      observations.push(observation("MAP-AUD01", target, "error", "Inconclusive: no refresh token was issued, so a token for another resource cannot be requested.", lines));
      return;
    }
    const foreignResource = `https://other.${SAFE_DOMAIN}/mcp`;
    const o = await refresh(http, tokenEndpoint, grant, grant.refreshToken, foreignResource);
    lines.push(`refresh token used to request a token for ${foreignResource}: ${describeOutcome(o)}`);
    if (o.refreshToken) grant.refreshToken = o.refreshToken; // rotation: keep the newest
    if (!o.accessTokenIssued) {
      // Only invalid_target says why; another refusal (scope, policy, throttling) proves nothing.
      observations.push(
        o.error === "invalid_target"
          ? observation("MAP-AUD01", target, "pass", "The authorization server refused to issue a token for an unrelated resource (invalid_target).", lines)
          : observation("MAP-AUD01", target, "error", "The request for a token for an unrelated resource was refused, but not with invalid_target; inconclusive.", lines),
      );
      return;
    }
    const st = await initializeStatus(http, target, { token: o.accessToken ?? "" });
    lines.push(`that token presented to this MCP server: HTTP ${st}`);
    const aud = o.accessToken ? jwtAudience(o.accessToken) : null;
    if (aud) lines.push(`audience of that token (JWT, unverified): ${aud.join(", ")}`);
    if (st === 401 || st === 403) {
      observations.push(observation("MAP-AUD01", target, "pass", "A token issued for an unrelated resource is rejected by the MCP server.", lines));
    } else if (!is2xx(st)) {
      observations.push(observation("MAP-AUD01", target, "error", "Unexpected answer from the MCP server; inconclusive.", lines));
    } else if (aud && aud.includes(foreignResource) && !aud.includes(target)) {
      observations.push(observation("MAP-AUD01", target, "fail", "The MCP server accepts a token whose audience is another resource: it does not validate the token audience.", lines));
    } else if (aud) {
      observations.push(
        observation("MAP-AUD01", target, "error", "Inconclusive: the authorization server ignored the resource parameter and issued a token for this server (RFC 8707 recommends refusing with invalid_target), so the MCP server's audience validation could not be tested.", lines),
      );
    } else {
      observations.push(
        observation("MAP-AUD01", target, "error", "Inconclusive: a token requested for an unrelated resource works on this server, but the token is opaque, so it cannot be told whether the authorization server ignored the resource parameter or the MCP server does not validate the audience. Check both.", lines),
      );
    }
  });

  // Last: a compliant server may revoke the grant here.
  await guard("MAP-COD01", async () => {
    const reuse = await exchangeCode(http, tokenEndpoint, c.correct);
    const lines = [`code presented a second time: ${describeOutcome(reuse)}`];
    if (c.tokensFromProbe) lines.unshift("the code had already been exchanged by an earlier probe");
    if (reuse.accessTokenIssued) {
      observations.push(observation("MAP-COD01", target, "fail", "The authorization code was exchanged a second time: codes are not single-use.", lines));
      if (reuse.refreshToken && grant) grant.refreshToken = reuse.refreshToken;
      return;
    }
    if (reuse.status < 400 || reuse.status >= 500 || reuse.throttled) {
      observations.push(
        observation(
          "MAP-COD01",
          target,
          "error",
          reuse.status >= 500
            ? "Inconclusive: the token endpoint crashed (server error) on the second use of the code instead of answering invalid_grant. No tokens were issued, but a clean refusal is expected."
            : "Unexpected answer to the second use of the code; inconclusive.",
          lines,
        ),
      );
      return;
    }
    // Were the tokens issued from that code revoked? (recommended)
    if (!grant) {
      // No refresh token: look at the access token instead.
      const st = accessToken ? await initializeStatus(http, target, { token: accessToken }) : null;
      lines.push(`access token after the reuse attempt: ${st === null ? "not available" : `HTTP ${st}`}`);
      const message =
        st !== null && (st === 401 || st === 403) && is2xx(control)
          ? "A second use of the authorization code is refused, and the access token issued from it was revoked."
          : is2xx(st)
            ? "A second use of the authorization code is refused. The access token issued from it stays valid; revoking it on reuse is recommended."
            : "A second use of the authorization code is refused. Whether the tokens issued from it were revoked is unknown.";
      observations.push(observation("MAP-COD01", target, "pass", message, lines));
      return;
    }
    const after = await refresh(http, tokenEndpoint, grant, grant.refreshToken);
    if (after.accessTokenIssued) {
      if (after.refreshToken) grant.refreshToken = after.refreshToken;
      lines.push("newest refresh token after the reuse attempt: still valid");
      observations.push(observation("MAP-COD01", target, "pass", "A second use of the authorization code is refused. The tokens issued from it stay valid; revoking them on reuse is recommended.", lines));
    } else if (after.error === "invalid_grant") {
      lines.push(`newest refresh token after the reuse attempt: ${describeOutcome(after)}`);
      observations.push(observation("MAP-COD01", target, "pass", "A second use of the authorization code is refused, and the tokens issued from it were revoked.", lines));
      c.notes.push(`${REVOKED_NOTE} (recommended behaviour). The results are saved; run login again with --no-probe --force --out <same file> to obtain a test grant.`);
    } else {
      lines.push(`newest refresh token after the reuse attempt: ${describeOutcome(after)} (unknown)`);
      observations.push(observation("MAP-COD01", target, "pass", "A second use of the authorization code is refused. Whether the tokens issued from it were revoked is unknown.", lines));
    }
  });
}
