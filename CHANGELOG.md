# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.1] - 2026-11-13

### Changed

- MCP mode: every tool description now says when to use the tool, what it returns and what it never does, every parameter is documented, and the server instructions describe the whole flow (checks, ownership proof, scan) and all check families.
- `explain_check` also accepts IDs without the `MAP-` prefix, case-insensitive (`rtk02`).

## [0.10.0] - 2026-11-13

### Added

- `MAP-INJ01` (tool poisoning, high): tool, prompt and resource metadata and the initialize `instructions` are read with the list methods only (`tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`; nothing is called or read) and must carry no invisible characters (Unicode tags, decoded before matching; zero-width and bidi controls; ANSI escapes) and no instruction-like text ("ignore previous instructions", `<IMPORTANT>`, "do not tell the user", `~/.ssh`…). Tool names with non-ASCII characters fail too. Runs with a static key, during `login`, or anonymously on a server that answers anonymous requests. The report locates matches and never copies the suspicious text.
- The `vulnerable` and `static-bearer` lab profiles announce a poisoned tool, prompt and resource; the secure profiles, clean ones.

### Changed

- The lab answers JSON-RPC notifications with 202 and echoes request IDs.

## [0.9.0] - 2026-11-13

Servers authenticated by a static API key (no OAuth) are now tested, following a field trial against one: 0.8.0 skipped 14 of 19 checks there.

### Added

- `--bearer-file <file>` and `--bearer-header <name>`: a static API key, read from a file (warning if other users can read it), never accepted on the command line, masked in every report, and only sent to the target once its ownership is proven. With it, the MCP endpoint checks run with the key. In MCP mode, `MCP_AUTHPROBE_BEARER_FILE` must come with `MCP_AUTHPROBE_BEARER_TARGET`, the only URL the key may be used for. Also `bearer` and `bearer-header` inputs of the GitHub Action.
- `MAP-BAT01` (JSON-RPC batches): one POST carrying a batch of 5 `ping` requests must be refused; MCP has required one message per request since 2025-06-18, and a server that runs batches counts many calls as one. The TypeScript SDK 1.x accepts batches of up to 100 messages by default.
- `MAP-BOD01` (body size): two 6 MiB `ping` requests, with `Content-Length` and chunked, must be refused.
- `MAP-THR02` (rate limit per credential): up to 30 `ping` requests with the static key (`--rate-attempts`, 10 to 100) must meet a 429 or a `Retry-After`.
- `--fail-on-inconclusive <true|false>` for the CLI (exit code 3 for inconclusive checks stays the default); exit codes documented in the help and the README.
- Lab profiles `static-bearer` and `static-bearer-secure`, with a key generated at each start.

### Changed

- `MAP-ORG01` with a credential now tries a foreign Origin, `Origin: null` and a malformed Origin.
- `MAP-TOK01` tries the credential as `?access_token=`, `?api_key=`, `?key=` and `?token=`.
- The MCP endpoint checks (ORG01, TOK01, SES01, BAT01, BOD01) share one implementation, used by `login` with the OAuth access token and by `scan` with a static key. Only side-effect-free methods are sent: `initialize` and `ping`, never `tools/call`.
- `MAP-DSC01` and the authorization server checks are *not applicable* when a static key is declared and no OAuth metadata is published.

## [0.8.0] - 2026-11-04

### Added

- `--posture-report <file>`: merges an mcp-posture JSON report (schema 1.x) for the same URL into the scan. The table, JSON (`posture` block) and Markdown reports show mcp-posture's findings with their fingerprints, and relate each active result to the passive findings on the same subject: confirmed, only visible actively, or enforced despite what the metadata suggests. The file is size-capped, type-checked and neutralized; suppressed findings are left out; the exit code is unchanged. Also an input of the GitHub Action.

- `Dockerfile` for the stdio MCP server, tested in CI (the image must answer `initialize` and `tools/list`), and `glama.json` for the Glama directory.

## [0.7.0] - 2026-11-01

### Changed

- Easier-to-read terminal output: colours on a terminal (`NO_COLOR` and `FORCE_COLOR` are honoured), at most three evidence lines per failing check, checks that did not run grouped by reason, and a summary line. `--verbose` shows everything, as before. JSON, SARIF and Markdown reports are unchanged.

### Added

- An animated demo in the README, recorded from real output against the lab (`npm run demo` re-records it).

## [0.6.0] - 2026-11-01

### Added

- `MAP-TOK01` (token in the URL): during `login`, an `initialize` request carries the access token as `?access_token=` without an `Authorization` header and must be refused, as the MCP specification requires. The token never appears in evidence or error messages.
- `MAP-SES01` (session ID instead of a token): during `login`, a session is opened with the token, then a `ping` carrying only the `Mcp-Session-Id` must be refused (401 expected). Not applicable to stateless servers; the sessions opened are ended.
- `MAP-COR01` (CORS): in every scan, a preflight and an ordinary request with a foreign `Origin`; fails when the origin is reflected with `Access-Control-Allow-Credentials: true`.
- Both login checks are inconclusive on an endpoint that also serves anonymous requests. The `vulnerable` lab profile plants the three flaws.

## [0.5.0] - 2026-11-01

Fixes from a trial against node-oidc-provider (with an MCP server built on the official SDK) and the MCP SDK's OAuth example server.

### Changed

- `MAP-CSR01` recognises per-flow identifiers issued by the authorization server (hidden fields such as `consent_challenge`, or a random part of the form URL as in node-oidc-provider's `/interaction/<id>`). Without an anti-CSRF field, it first submits the form with the identifier altered and without any cookie: either one accepted is a failure; both refused makes the result inconclusive with an explanation, instead of a failure.
- `login` still observes `MAP-ORG01` and `MAP-COD01` when the server issues no refresh token (COD01 then looks at the access token), and keeps the probe results when the real code exchange fails after the probes.
- `MAP-THR01` switches once to random authorization codes when the refresh grant answers a server error or `unsupported_grant_type`.
- Clearer messages for a token endpoint that crashes on a reused code, and for a rate-limited registration endpoint.

## [0.4.0] - 2026-11-01

### Added

- Official GitHub Action (`uses: Enigmacker/mcp-authprobe@v0.4.0`): runs the scan with the ownership secret from the environment, adds the results table to the job summary, can upload SARIF to code scanning, fails on findings at or above `fail-on`, warns on inconclusive checks (or fails with `fail-on-inconclusive`), and exposes the exit code, the number of failing checks and the report paths. CI tests it against both lab profiles.
- `--only` and `--skip` (and `only` / `skip` in the MCP `scan` tool): choose checks by ID or family. Unselected checks send no request and are reported as skipped; unknown names are refused.

## [0.3.0] - 2026-11-01

### Added

- `MAP-PKC01` (PKCE enforcement): during `login`, the code is first presented without `code_verifier`, then with a wrong one; the token endpoint must refuse both.
- `MAP-COD01` (single-use codes): after the exchange, `login` presents the used code again, then checks whether the tokens issued from it were revoked (recommended, reported in the result).
- `MAP-AUD01` (token audience, RFC 8707): `login` requests a token for an unrelated resource with the refresh token and presents it to the MCP endpoint, after a successful control with its own token. Passes on `invalid_target` from the authorization server or 401/403 from the MCP endpoint. Fails only when the MCP endpoint accepts a token whose JWT audience is the other resource; an opaque token, or an authorization server that ignores `resource`, is reported as inconclusive with the reason.
- `lab` command: a local MCP server with its own OAuth authorization server, in a `vulnerable` profile (most checks fail) or a `secure` one, to try every check in a minute. Loopback only, test account `test` / `test`, in memory.
- `MAP-ORG01` (Origin validation): an `initialize` request with a foreign `Origin` must get 403. Observed during `login` with a valid token, and in every scan without credentials (inconclusive when the server asks for a token first).

### Changed

- `login` runs its probes in a fixed order and handles servers that invalidate a code after the first refused attempt: only that first refusal is trusted. If a probe obtains tokens, the remaining probes are reported as not run and those tokens become the grant. The grant always keeps the newest refresh token.
- Scans report every login observation; no check is listed as "not implemented" any more.
- `login` writes its results even when it keeps no grant (strict servers), and a later `login --no-probe --force` to the same file keeps them. A grant file may therefore hold results only; scans then skip the refresh token checks with a warning.
- The lab server doubles as the test fixture: its consent mode validates authorization requests before asking for a login, and returns the RFC 9207 `iss` parameter.

## [0.2.0] - 2026-11-01

### Added

- `MAP-CSR01` (consent CSRF) with the new `consent-check` command: it opens the installed Chrome or Edge through the optional `playwright-core` peer dependency, lets the user log in with a test account and stop on the consent page, reads the consent form and cookie attributes, then replays at most four submissions with the session cookies (from a foreign Origin: without the anti-CSRF field, with it altered, untouched; plus a control from the page's own Origin). A pass requires a control submission (the untouched form from the page's own Origin) to be accepted, so a badly rebuilt request is reported as inconclusive, never as a pass. It recognises approve controls in several languages and "Don't allow" style labels, honours `formaction`, `<base>`, required checkboxes, selects and textareas, follows one redirect on a proven host to detect resumed grants, alters tokens within their alphabet, reads the raw SameSite attribute, matches cookies like a browser, and stops cleanly on Ctrl-C, browser close or timeout. Requires ownership proof, launches the browser before registering anything, only posts to proven hosts, owns its loopback redirect URI, never reports cookie or token values, and deletes its temporary client.

## [0.1.1] - 2026-11-01

### Added

- Listed in the official MCP Registry as `io.github.Enigmacker/mcp-authprobe` (`server.json`, `mcpName` in `package.json`); releases publish the registry entry from GitHub Actions with OIDC.

### Changed

- Requires Node.js 22.19 or later (Node.js 20 is end-of-life); `undici` 8.
- GitHub Actions updated (`actions/checkout` and `actions/setup-node` v7); the release workflow skips the npm publish when the version already exists.

## [0.1.0] - 2026-11-01

First release.

### Added

- Hardened HTTP client: connect-time refusal of loopback, private, link-local, CGNAT, multicast, reserved and cloud-metadata addresses (after DNS resolution), timeouts, 1 MiB body cap, no automatic redirects, no compression.
- Ownership proof: host-bound SHA-256 proof of a local secret, published as `/.well-known/mcp-authprobe.txt` or a `_mcp-authprobe` DNS TXT record. Required for every host an active check would contact; loopback labs are exempt with `--allow-private`.
- OAuth discovery following the MCP Authorization specification: 401 challenge, Protected Resource Metadata (RFC 9728), Authorization Server Metadata (RFC 8414 and OpenID Connect Discovery).
- Check catalogue with stable `MAP-` identifiers: `MAP-DSC01` available; refresh token, redirect URI, throttling and consent CSRF families documented as planned.
- Reports: terminal table, JSON (`mcp-authprobe/report/v1`), SARIF 2.1.0 and Markdown, with redaction of token-shaped values and neutralization of control, bidi and invisible characters.
- CLI: `scan`, `ownership init|proof|verify`, `checks list|show`, `--fail-on`, exit codes 0/1/2/3.
- Refresh token checks `MAP-RTK01` (rotation), `MAP-RTK02` (replay rejected) and `MAP-RTK03` (family revocation on reuse), in at most three token requests, from a test grant passed with `--credentials-file` (public clients, `client_secret_post`, `client_secret_basic`). Inconclusive outcomes, such as throttling, are reported as errors, never as passes.
- Redirect URI checks `MAP-RDR01` (unregistered URI refused), `MAP-RDR02` (exact matching, 7 near-miss variants) and `MAP-RDR04` (registration refuses unsafe redirect URIs). They register a temporary client, compare each answer with a baseline request, report deferred validation as inconclusive, use only the reserved `.invalid` domain, and delete every client they created (RFC 7592).
- MCP server mode: `mcp-authprobe mcp` serves `list_checks`, `explain_check`, `ownership_proof`, `verify_ownership` and `scan` over stdio. The secret, the test grant and private-address access come only from the environment, never from tool arguments; `scan` is annotated destructive, accepts only `https` targets (unless private labs are enabled), refuses URLs with credentials, runs one scan at a time, and marks server-controlled text as data.
- CLI: `mcp` command.
- Interactive `login`: dynamic registration with a loopback redirect URI, PKCE S256, random state, RFC 8707 resource and RFC 9207 iss check; the browser only opens the discovered authorization endpoint; the grant file is written with mode 600, without following symbolic links or overwriting without `--force`; clients from failed logins are deleted.
- `MAP-RDR03` (token endpoint binds the code to its redirect_uri), observed during `login` when ownership is proven, stored in the grant file and reported by the next scan of the same target.
- `MAP-THR01` (repeated failed token requests are throttled): 5 to 20 sequential requests (default 10, hard-capped, `--throttle-attempts`) carrying random refresh tokens for the operator's test client or a temporary deleted-afterwards client; stops at the first 429, Retry-After, `slow_down` or `temporarily_unavailable`; runs last in a scan.
- Hardening from an independent review before release: HTTPS is required for every request outside loopback/private labs; rate limits and server errors make redirect URI, registration and throttling checks inconclusive instead of passing; test grants record their target and token endpoint and are never used elsewhere (and must name their target in MCP mode); loopback targets need a proof in MCP mode unless listed in `MCP_AUTHPROBE_LAB_ORIGINS`; `login` output is neutralized; more IPv6 transition ranges are refused; a malformed issuer no longer aborts discovery.
- Local fixture server with a stateful token endpoint, dynamic registration and an authorization endpoint and test suite; GitHub Actions CI.

[Unreleased]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Enigmacker/mcp-authprobe/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Enigmacker/mcp-authprobe/releases/tag/v0.1.0
