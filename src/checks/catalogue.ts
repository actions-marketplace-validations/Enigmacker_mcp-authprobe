import type { CheckDefinition, Reference } from "../types.js";

const RFC9700: Reference = {
  title: "RFC 9700 - Best Current Practice for OAuth 2.0 Security",
  url: "https://www.rfc-editor.org/rfc/rfc9700",
};
const OAUTH21: Reference = {
  title: "OAuth 2.1 (draft-ietf-oauth-v2-1)",
  url: "https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/",
};
const MCP_AUTH: Reference = {
  title: "MCP specification - Authorization",
  url: "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
};
const MCP_SEC: Reference = {
  title: "MCP specification - Security Best Practices",
  url: "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices",
};
const RFC9728: Reference = { title: "RFC 9728 - OAuth 2.0 Protected Resource Metadata", url: "https://www.rfc-editor.org/rfc/rfc9728" };
const RFC8414: Reference = { title: "RFC 8414 - OAuth 2.0 Authorization Server Metadata", url: "https://www.rfc-editor.org/rfc/rfc8414" };

/**
 * The check catalogue. IDs are stable and never reused.
 *
 * Prefix "MAP" (mcp-authprobe) avoids clashing with mcp-posture's "MCPP".
 * Families:
 *   DSC  discovery prerequisites (passive)
 *   RTK  refresh token rotation and replay (active)
 *   RDR  redirect_uri strictness (active)
 *   THR  throttling of failed authentication (active, bounded)
 *   CSR  consent page CSRF (active, needs a browser session)
 *   PKC  PKCE enforcement at the token endpoint (active, during login)
 *   COD  authorization code single use (active, during login)
 *   AUD  token audience binding (active, during login)
 *   ORG  Origin validation on the MCP endpoint (passive)
 */
export const CATALOGUE: readonly CheckDefinition[] = [
  {
    id: "MAP-DSC01",
    family: "DSC",
    title: "Authorization endpoints are discoverable",
    severity: "info",
    active: false,
    availability: "available",
    rationale:
      "Active checks need the authorization, token and registration endpoints. They are read from Protected Resource Metadata and Authorization Server Metadata, as a compliant MCP client would.",
    remediation:
      "Return 401 with a WWW-Authenticate resource_metadata parameter, publish Protected Resource Metadata listing the authorization server, and publish Authorization Server Metadata.",
    references: [MCP_AUTH, RFC9728, RFC8414],
  },
  {
    id: "MAP-RTK01",
    family: "RTK",
    title: "Refresh tokens for public clients are rotated",
    severity: "high",
    active: true,
    availability: "available",
    rationale:
      "MCP clients are usually public clients. For them, refresh tokens must be sender-constrained or rotated on each use, so that a leaked refresh token has a short useful life.",
    remediation:
      "Issue a new refresh token on every refresh_token grant and invalidate the previous one.",
    references: [OAUTH21, RFC9700, MCP_AUTH],
  },
  {
    id: "MAP-RTK02",
    family: "RTK",
    title: "A rotated refresh token cannot be replayed",
    severity: "critical",
    active: true,
    availability: "available",
    rationale:
      "Rotation only helps if the previous refresh token is rejected afterwards. Accepting it lets an attacker who copied it keep minting access tokens.",
    remediation: "Reject any refresh token that has already been exchanged.",
    references: [OAUTH21, RFC9700],
  },
  {
    id: "MAP-RTK03",
    family: "RTK",
    title: "Refresh token replay revokes the token family",
    severity: "high",
    active: true,
    availability: "available",
    rationale:
      "When an already-used refresh token is presented, the server cannot tell the legitimate client from an attacker. Revoking every token descended from the same grant contains the compromise.",
    remediation: "On detected reuse, revoke the whole refresh token family and the related access tokens.",
    references: [RFC9700],
  },
  {
    id: "MAP-RDR01",
    family: "RDR",
    title: "Unregistered redirect_uri is refused at the authorization endpoint",
    severity: "critical",
    active: true,
    availability: "available",
    rationale:
      "If the authorization endpoint redirects to a URI the client never registered, authorization codes can be delivered to an attacker.",
    remediation:
      "Compare the requested redirect_uri with the registered ones using exact string matching, and show an error page instead of redirecting when they differ.",
    references: [OAUTH21, RFC9700, MCP_SEC],
  },
  {
    id: "MAP-RDR02",
    family: "RDR",
    title: "redirect_uri matching is exact, not prefix or pattern based",
    severity: "high",
    active: true,
    availability: "available",
    rationale:
      "Prefix, substring or pattern matching lets close variants of a registered URI through (extra path segments, different port, different case, added query). Each variant is a potential open redirect for codes.",
    remediation: "Use simple string comparison as required by OAuth 2.1, with the single loopback port exception for native clients.",
    references: [OAUTH21, RFC9700],
  },
  {
    id: "MAP-RDR03",
    family: "RDR",
    title: "Token endpoint enforces the redirect_uri used at authorization",
    severity: "medium",
    active: true,
    availability: "available",
    rationale:
      "A token request whose redirect_uri differs from the one used in the authorization request should fail; otherwise code injection defenses are weakened.",
    remediation: "Bind the authorization code to its redirect_uri and reject mismatches at the token endpoint.",
    references: [OAUTH21],
  },
  {
    id: "MAP-RDR04",
    family: "RDR",
    title: "Dynamic client registration refuses unsafe redirect URIs",
    severity: "high",
    active: true,
    availability: "available",
    rationale:
      "If anyone can register a client, the registration endpoint is the first line of defense: it should only accept HTTPS or loopback redirect URIs and refuse dangerous schemes.",
    remediation: "Validate redirect_uris at registration: HTTPS, loopback HTTP, or private-use schemes for native apps only.",
    references: [MCP_AUTH, OAUTH21],
  },
  {
    id: "MAP-PKC01",
    family: "PKC",
    title: "Token endpoint enforces PKCE",
    severity: "high",
    active: true,
    availability: "available",
    rationale:
      "PKCE only protects an intercepted authorization code if the token endpoint actually verifies the code_verifier. Observed during login: the code is first presented without a code_verifier, then with a wrong one; both must be refused.",
    remediation: "Require a code_verifier for every code issued with a code_challenge, verify it with S256, and refuse codes issued without PKCE for public clients.",
    references: [OAUTH21, RFC9700, MCP_AUTH, { title: "RFC 7636 - Proof Key for Code Exchange", url: "https://www.rfc-editor.org/rfc/rfc7636" }],
  },
  {
    id: "MAP-COD01",
    family: "COD",
    title: "An authorization code cannot be used twice",
    severity: "high",
    active: true,
    availability: "available",
    rationale:
      "Authorization codes are single-use. Observed during login: after the code has been exchanged, it is presented again and must be refused. Revoking the tokens already issued from it is recommended and reported.",
    remediation: "Reject a second use of any authorization code, and revoke the tokens issued from it when a reuse is detected.",
    references: [OAUTH21, RFC9700],
  },
  {
    id: "MAP-AUD01",
    family: "AUD",
    title: "Tokens are bound to their audience",
    severity: "high",
    active: true,
    availability: "available",
    rationale:
      "A token requested for another resource must not be usable on this MCP server (RFC 8707, and the MCP ban on token passthrough). Observed during login: the refresh token is used to ask for a token for an unrelated resource; the authorization server must refuse, or the MCP server must reject that token. A token for this server is used as a control.",
    remediation: "Honour the resource parameter at the authorization server (refuse unknown resources with invalid_target), and validate the token audience on the MCP server.",
    references: [MCP_AUTH, MCP_SEC, { title: "RFC 8707 - Resource Indicators for OAuth 2.0", url: "https://www.rfc-editor.org/rfc/rfc8707" }],
  },
  {
    id: "MAP-ORG01",
    family: "ORG",
    title: "MCP endpoint rejects requests from a foreign Origin",
    severity: "medium",
    active: false,
    availability: "available",
    rationale:
      "The MCP Streamable HTTP transport requires servers to validate the Origin header and answer 403 to an invalid one, so a web page cannot reach the server through the browser (DNS rebinding). Without a credential, one initialize request is sent with a foreign Origin and compared with the same request without Origin. With a credential (login, or a static key with --bearer-file), a foreign Origin, Origin \"null\" and a malformed Origin are each tried with the credential, then the credential is checked again.",
    remediation: "Validate the Origin header on every request to the MCP endpoint and answer 403 Forbidden when it is not an allowed origin.",
    references: [{ title: "MCP specification - Transports (Streamable HTTP, security warning)", url: "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports" }, MCP_SEC],
  },
  {
    id: "MAP-TOK01",
    family: "TOK",
    title: "MCP endpoint refuses access tokens and keys in the URL",
    severity: "medium",
    active: true,
    availability: "available",
    rationale:
      "The MCP specification forbids access tokens in the URI query string: URLs end up in server and proxy logs, browser history and Referer headers. With the access token from login, or a static key from --bearer-file, an initialize request carries the credential as ?access_token=, ?api_key=, ?key= and ?token= without any header; each must be refused.",
    remediation: "Accept credentials only in a request header (Authorization: Bearer, or your API key header), and refuse requests that carry one in a query parameter.",
    references: [MCP_AUTH, OAUTH21, { title: "RFC 6750 - Bearer Token Usage, section 2.3", url: "https://www.rfc-editor.org/rfc/rfc6750#section-2.3" }],
  },
  {
    id: "MAP-SES01",
    family: "SES",
    title: "An MCP session ID is not accepted instead of a token",
    severity: "high",
    active: true,
    availability: "available",
    rationale:
      "The MCP specification requires the Authorization header on every request, even within the same session, and its security best practices forbid using sessions for authentication. Observed during login: a session is opened with a valid token, then a request that carries only the Mcp-Session-Id must be refused with 401. Not applicable to stateless servers that assign no session ID.",
    remediation: "Authenticate every request with its access token; treat Mcp-Session-Id as a routing identifier only, and bind sessions to the user they were created for.",
    references: [MCP_AUTH, MCP_SEC],
  },
  {
    id: "MAP-COR01",
    family: "COR",
    title: "MCP endpoint does not allow credentialed requests from any origin",
    severity: "medium",
    active: false,
    availability: "available",
    rationale:
      "If the MCP endpoint answers a foreign Origin with Access-Control-Allow-Origin set to that origin and Access-Control-Allow-Credentials: true, any website can make a logged-in user's browser call it with their cookies and read the answers. A CORS preflight and an ordinary request are sent with a foreign Origin and the CORS headers are read.",
    remediation: "Do not reflect arbitrary origins. Allow only the origins you serve, and never combine a broad origin policy with Access-Control-Allow-Credentials: true.",
    references: [MCP_SEC, { title: "Fetch Standard - CORS protocol", url: "https://fetch.spec.whatwg.org/#http-cors-protocol" }],
  },
  {
    id: "MAP-BAT01",
    family: "BAT",
    title: "MCP endpoint refuses JSON-RPC batches",
    severity: "medium",
    active: true,
    availability: "available",
    rationale:
      "Since the 2025-06-18 revision, an MCP POST body must be a single JSON-RPC message. A server that still executes batches runs many requests for one HTTP request, so limits counted per request (rate limits, quotas, logs) see one call: an amplification and a way around them. One POST carries a batch of 5 ping requests (no tool is called), with the credential from login or --bearer-file.",
    remediation: "Reject JSON-RPC arrays on the MCP endpoint (400 Bad Request), or at least count each message against your limits. The TypeScript SDK 1.x still accepts batches of up to 100 messages by default, so servers built on it need their own check.",
    references: [
      { title: "MCP specification - Transports (Sending messages to the server)", url: "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports" },
      { title: "MCP specification 2025-06-18 - Key changes (batching removed)", url: "https://modelcontextprotocol.io/specification/2025-06-18/changelog" },
    ],
  },
  {
    id: "MAP-BOD01",
    family: "BOD",
    title: "MCP endpoint limits the request body size",
    severity: "low",
    active: true,
    availability: "available",
    rationale:
      "Without a body size limit, a few large requests can exhaust the server's memory. Two 6 MiB ping requests are sent with the credential, one with Content-Length and one chunked (no Content-Length, which some limits forget); each should be refused, ideally with 413.",
    remediation: "Set a body size limit on the MCP endpoint (the TypeScript SDK 1.x uses 4 MiB by default), enforced for chunked requests too, and answer 413 Payload Too Large.",
    references: [{ title: "RFC 9110 - 413 Content Too Large", url: "https://www.rfc-editor.org/rfc/rfc9110#section-15.5.14" }, MCP_SEC],
  },
  {
    id: "MAP-INJ01",
    family: "INJ",
    title: "Tool, prompt and resource metadata carry no hidden instructions",
    severity: "high",
    active: true,
    availability: "available",
    rationale:
      "The client's model reads tool, prompt and resource descriptions, input schemas and the initialize instructions as trusted context. Hidden characters (Unicode tags, zero-width and bidi controls, ANSI escapes) or instruction-like text there (\"ignore previous instructions\", <IMPORTANT> blocks, \"do not tell the user\", paths such as ~/.ssh) is a prompt injection every user of the server receives: tool poisoning. Only the list methods are sent (tools/list, prompts/list, resources/list, resources/templates/list); no tool is called and no resource is read. The report names where something matched, never the suspicious text itself. Pattern matching: a pass is not a proof, and a match is something to review.",
    remediation:
      "Keep descriptions plain, visible text about what the tool does. Strip invisible and control characters from anything generated or imported into descriptions (for instance from a third-party API or a package), never put instructions for the model about other tools, files or the user into metadata, and review metadata changes like code. Tool names: 1 to 128 of A-Z a-z 0-9 _ - . (MCP 2025-11-25).",
    references: [
      { title: "MCP specification - Tools, security considerations", url: "https://modelcontextprotocol.io/specification/2025-11-25/server/tools#security-considerations" },
      { title: "OWASP LLM01:2025 Prompt Injection", url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/" },
      MCP_SEC,
    ],
  },
  {
    id: "MAP-THR02",
    family: "THR",
    title: "MCP endpoint rate-limits each credential",
    severity: "low",
    active: true,
    availability: "available",
    rationale:
      "A static API key or a token that can call the endpoint without limit lets one leaked or abused credential run up costs or overload the server. Up to 30 ping requests (--rate-attempts, 10 to 100; no tool is called) are sent with the static key from --bearer-file; a 429 or a Retry-After header counts as a limit. Runs last, since a limited key may be refused for a while.",
    remediation: "Rate-limit the MCP endpoint per credential, answer 429 Too Many Requests with Retry-After, and count each JSON-RPC message, not each HTTP request.",
    references: [{ title: "RFC 6585 - 429 Too Many Requests", url: "https://www.rfc-editor.org/rfc/rfc6585#section-4" }, MCP_SEC],
  },
  {
    id: "MAP-THR01",
    family: "THR",
    title: "Repeated failed token requests are throttled",
    severity: "medium",
    active: true,
    availability: "available",
    rationale:
      "Without throttling, refresh tokens, authorization codes and client secrets can be guessed at line speed. The check sends a small, capped number of token requests carrying random, invalid refresh tokens for the operator's own test client, and looks for rate limiting. It never touches user passwords or login forms.",
    remediation: "Rate-limit failed token requests per client and per source address, and answer with HTTP 429 and a Retry-After header.",
    references: [RFC9700, { title: "RFC 6585 - Additional HTTP Status Codes (429)", url: "https://www.rfc-editor.org/rfc/rfc6585" }],
  },
  {
    id: "MAP-CSR01",
    family: "CSR",
    title: "Consent decision is protected against cross-site request forgery",
    severity: "high",
    active: true,
    availability: "available",
    rationale:
      "If the consent form can be submitted cross-site, a malicious page can grant access on behalf of a logged-in user (confused deputy, as described in the MCP security best practices).",
    remediation: "Protect the consent submission with an anti-CSRF token bound to the session, SameSite cookies and an Origin check.",
    references: [MCP_SEC, RFC9700],
  },
];

export function getCheck(id: string): CheckDefinition | undefined {
  return CATALOGUE.find((c) => c.id.toUpperCase() === id.toUpperCase());
}
