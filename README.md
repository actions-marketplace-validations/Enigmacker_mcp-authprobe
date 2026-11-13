# mcp-authprobe

[![CI](https://github.com/Enigmacker/mcp-authprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/Enigmacker/mcp-authprobe/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/mcp-authprobe.svg)](https://www.npmjs.com/package/mcp-authprobe)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-mcp--authprobe-blue?logo=github)](https://github.com/marketplace/actions/mcp-authprobe)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Active authorization testing for remote MCP servers you own.**

Passive scanners read what a remote [Model Context Protocol](https://modelcontextprotocol.io) server *announces*: its OAuth metadata, its TLS setup, its tool descriptions. Some properties can only be confirmed by actually exercising the authorization server: does it really rotate refresh tokens, does it really refuse a redirect URI it never registered, does it enforce PKCE, does it accept a token meant for another server, does it slow down repeated failures?

`mcp-authprobe` runs those active checks, against servers whose ownership you have proven, and reports the results as JSON, SARIF and Markdown.

> **19 checks**, field-tested against a certified OpenID provider: OAuth discovery, refresh token rotation and replay, redirect URI strictness, PKCE enforcement, single-use codes, token audience, `Origin` validation, tokens in URLs, session IDs used as credentials, CORS, throttling and consent CSRF (in a real browser). It works as a CLI with an interactive `login`, as an MCP server so an AI assistant can run the audit, and as a GitHub Action. A deliberately vulnerable [lab](#try-it-in-a-minute-the-lab) lets you try everything in a minute.

> **Only test servers you own or are explicitly authorized to test.** Active checks change state on the target. The tool enforces an ownership proof before running them, but responsibility stays with the operator.

![mcp-authprobe against its vulnerable lab: login, then a scan with 10 failing checks](https://raw.githubusercontent.com/Enigmacker/mcp-authprobe/main/docs/demo/demo.gif)

## Contents

- [Field-tested](#field-tested)
- [Why another scanner?](#why-another-scanner)
- [Install](#install)
- [Try it in a minute: the lab](#try-it-in-a-minute-the-lab)
- [Quick start](#quick-start)
- [Ownership proof](#ownership-proof)
- [Refresh token checks](#refresh-token-checks)
- [Interactive login](#interactive-login)
- [Redirect URI checks](#redirect-uri-checks)
- [Throttling check](#throttling-check)
- [Consent CSRF check](#consent-csrf-check)
- [Use it from an MCP client](#use-it-from-an-mcp-client)
- [What it checks](#what-it-checks)
- [Servers with a static API key](#servers-with-a-static-api-key)
- [Tool poisoning check](#tool-poisoning-check)
- [Combine with mcp-posture](#combine-with-mcp-posture)
- [Reports and exit codes](#reports-and-exit-codes)
- [GitHub Action](#github-action)
- [Safety of the scanner](#safety-of-the-scanner)
- [Roadmap](#roadmap)
- [Development](#development)
- [Contributing and security](#contributing-and-security)

## Field-tested

Besides its own test suite and lab, mcp-authprobe was run against real authorization stacks before each release:

- **node-oidc-provider** (an OpenID Certified authorization server) with dynamic registration, resource indicators and JWT access tokens, in front of an MCP server built with the official TypeScript SDK that validates the token audience and the `Origin` header. Every check that can be judged from outside passed; `MAP-THR01` failed, as expected, since that provider leaves rate limiting to the deployment; and its consent page, protected by a per-flow identifier instead of an anti-CSRF field, is reported as inconclusive with the reason.
- **The MCP TypeScript SDK's OAuth example server**, a demonstration that is not meant for production. The results matched its code: `redirect_uri` not bound to the code, no `Origin` validation, unsafe redirect URIs accepted at registration, no refresh tokens, and crashes reported as inconclusive rather than passes. Its sessions correctly require the token on every request (`MAP-SES01` passes).

These runs led to several fixes: results kept when a server issues no refresh token or crashes during login, a throttling check that copes with a broken refresh grant, and the per-flow identifier analysis above.

## Why another scanner?

Good tools already exist, and this one is meant to sit next to them, not replace them:

| Tool | Focus | Overlap with mcp-authprobe |
| --- | --- | --- |
| [mcp-posture](https://github.com/batou9150/mcp-posture) | Passive posture of remote servers: OAuth metadata per RFC, transport, tool poisoning, rug pulls | None by design: it never sends state-changing requests. Run it first. |
| [MCPJam OAuth conformance](https://docs.mcpjam.com/cli/oauth-conformance) | Runs real OAuth flows and checks conformance, with a few negative checks | Basic redirect URI rejection. No refresh token replay, throttling or consent CSRF. |
| [Cisco mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner), [Snyk agent-scan](https://github.com/snyk/agent-scan) | Malicious tools, configs, local servers | None. |

`mcp-authprobe` focuses on what only an **active, authorized** test can confirm, and uses check IDs (`MAP-…`) that do not clash with mcp-posture's (`MCPP-…`). mcp-posture reserves its own active IDs for this and points here; the two reports can be [merged into one](#combine-with-mcp-posture).

## Install

Requires Node.js 22.19 or later.

```sh
# run without installing
npx mcp-authprobe --help

# or install globally
npm install -g mcp-authprobe
```

Releases are published from GitHub Actions with npm trusted publishing; check the provenance on the package page before installing a security tool.

From source:

```sh
git clone https://github.com/Enigmacker/mcp-authprobe.git
cd mcp-authprobe
npm ci
npm run build
node dist/cli.js --help
```

## Try it in a minute: the lab

`mcp-authprobe lab` starts a small MCP server with its own OAuth authorization server on `127.0.0.1`, so you can see every check at work without touching a real server:

```sh
# Terminal 1: a deliberately vulnerable server (or --profile secure)
npx mcp-authprobe lab

# Terminal 2
npx mcp-authprobe scan http://127.0.0.1:8787/mcp --allow-private
npx mcp-authprobe login http://127.0.0.1:8787/mcp --allow-private --out lab-grant.json
npx mcp-authprobe scan http://127.0.0.1:8787/mcp --allow-private --credentials-file lab-grant.json
```

Log in with the account `test` / `test` and click **Allow**.

| Profile | What you should see |
| --- | --- |
| `vulnerable` (default) | Refresh token replay accepted, unsafe redirect URIs registered, PKCE not enforced, token audience ignored, foreign `Origin` accepted, token accepted in the URL, session ID accepted without a token, CORS open to any origin with credentials, no throttling, consent page without CSRF protection. `MAP-RDR02` is reported as **inconclusive**: this server sends unknown visitors to its login page before looking at `redirect_uri`, which cannot be told apart from outside, and the scanner never turns that into a pass. |
| `secure` | Every check passes (or is not applicable); `MAP-CSR01` runs with `consent-check`. |
| `static-bearer` | No OAuth: the MCP endpoint takes a static API key, printed when the lab starts (scan with `--bearer-file`). JSON-RPC batches executed, 6 MiB bodies accepted, key accepted in the URL, any `Origin` accepted, session ID enough without the key, no rate limit. |
| `static-bearer-secure` | The same server done right: every key check passes or is not applicable. |

The lab only listens on `127.0.0.1` or `::1` (`--host`, `--port`, default 8787; names such as `localhost` are refused so that no resolver can move it elsewhere), keeps everything in memory, and stops with Ctrl-C. Its access tokens are unsigned JWTs, so `MAP-AUD01` can read their audience. It is vulnerable on purpose: never expose it.

## Quick start

```sh
# 1. Create a secret and the proof to publish for your MCP host
mcp-authprobe ownership init mcp.example.com

# 2. Publish the proof (well-known file or DNS TXT), then keep the secret in your environment
export MCP_AUTHPROBE_SECRET='…'

# 3. Check the proof is visible
mcp-authprobe ownership verify mcp.example.com

# 4. Scan
mcp-authprobe scan https://mcp.example.com/mcp --sarif results.sarif --markdown summary.md

# 5. Log in once with a dedicated test account to create a test grant
mcp-authprobe login https://mcp.example.com/mcp --out ./test-grant.json

# 6. Full scan, including the refresh token checks
mcp-authprobe scan https://mcp.example.com/mcp --credentials-file ./test-grant.json
```

Without a valid proof the scan still runs discovery (the same read-only requests any MCP client sends before logging in), and every active check is reported as `skipped`.

For a local lab on your own machine:

```sh
mcp-authprobe scan http://127.0.0.1:8080/mcp --allow-private
```

Loopback targets with `--allow-private` do not need a proof.

## Ownership proof

Active checks register clients, rotate tokens and send failing requests. To make sure they only ever hit servers whose operator agreed to it, the scanner requires a proof for **every host it would contact**: the MCP server host and, when it differs, the authorization server host.

The proof is a hash, bound to the host, of a secret that only you hold:

```
mcp-authprobe-verification=sha256:<hex(sha256("<host>:<secret>"))>
```

Publish it in **one** of two places:

| Method | Where | Value |
| --- | --- | --- |
| Well-known file | `https://<host>/.well-known/mcp-authprobe.txt` | one line per proof; other lines are ignored |
| DNS TXT | `_mcp-authprobe.<host>` | the proof string |

Design choices:

- **The secret never leaves your machine.** Only its hash is published, so a proof found in the wild cannot be reused by someone else to scan your server.
- **Proofs are host-bound.** A proof for `mcp.example.com` is useless for any other host.
- **The secret is read from `MCP_AUTHPROBE_SECRET` or `--secret-file`, never from the command line**, so it does not land in shell history or process listings.
- **Hosted authorization servers.** If your authorization server is a third-party service on its own domain, you can only publish a proof if you control that domain (for example a custom domain). Check the provider's penetration testing policy before running active checks against it.

You can remove the proof as soon as you are done testing.

## Refresh token checks

MCP clients are usually public clients, so OAuth 2.1 requires their refresh tokens to be rotated, and RFC 9700 recommends revoking the whole token family when an old one is reused. These properties cannot be read from metadata; they have to be exercised.

The checks need a **test grant**: a client and a refresh token obtained by logging in to your own server with a **dedicated test account**.

The easy way is `mcp-authprobe login` (see [Interactive login](#interactive-login)), which writes the file for you. You can also write it by hand, readable only by you (`chmod 600`):

```json
{
  "client_id": "your-test-client-id",
  "refresh_token": "the-refresh-token",
  "client_secret": "only-for-confidential-clients",
  "token_endpoint_auth_method": "none"
}
```

`token_endpoint_auth_method` is `none` (default for public clients), `client_secret_post` (default when a secret is present) or `client_secret_basic`.

The scan sends **at most three** `refresh_token` requests to the token endpoint found by discovery:

| Step | Request | Expected on a compliant server | Check |
| --- | --- | --- | --- |
| 1 | Refresh with the supplied token | New access token **and a new refresh token** | `MAP-RTK01` |
| 2 | Refresh again with the token from step 1's input (already used) | Rejected, typically `invalid_grant` | `MAP-RTK02` |
| 3 | Refresh with the newest token (from step 1's output) | Rejected: reuse revoked the whole family | `MAP-RTK03` |

Important:

- **The grant is consumed.** On a compliant server, step 3 revokes it. Never use a grant you still need.
- If tokens are not rotated, `MAP-RTK01` fails and the two replay checks are reported as not applicable.
- A throttled or unexpected response is reported as `error` (inconclusive), never as a pass.
- Token values never appear in output or reports; evidence only shows status codes and OAuth error codes.

## Interactive login

```sh
mcp-authprobe login https://mcp.example.com/mcp --out ./test-grant.json
```

`login` behaves like a careful native MCP client ([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252)):

- It registers a client through dynamic client registration, with a loopback redirect URI on `127.0.0.1` and a random port.
- It opens your browser on the **discovered authorization endpoint only** (or prints the URL with `--no-browser`). Log in with your **test account**.
- The loopback listener accepts a single `GET /callback` carrying the expected `state`, and echoes nothing back.
- It uses PKCE S256, a random `state`, the RFC 8707 `resource`, and checks the RFC 9207 `iss` parameter against the discovered issuer.
- It writes the grant with mode 600, never through a symbolic link, and never over an existing file unless you pass `--force`. Tokens are never printed.
- The grant records the **target and token endpoint** it belongs to. A scan of any other target, or a server announcing another token endpoint, will not use it.
- `login` itself does not require an ownership proof: it only does what any MCP client does when you connect it (one registration, your own browser login, one code exchange). Only the extra login checks below require the proof.
- If login fails, the client it registered is deleted when the server allows it.

**Seven checks are observed during login**, because they need a fresh authorization code or a valid access token. They run only when ownership of every contacted host is proven (`--no-probe` skips them), in this order:

| Check | What `login` does | Fails when |
| --- | --- | --- |
| `MAP-PKC01` | Presents the code **without** `code_verifier`, then with a **wrong** one | The token endpoint issues tokens |
| `MAP-RDR03` | Presents the code with a **different** `redirect_uri` | The token endpoint issues tokens |
| *(exchange)* | Exchanges the code normally | |
| `MAP-ORG01` | Sends `initialize` with its access token (control, must succeed), then the same request with `Origin: https://attacker.mcp-authprobe.invalid`, then the control again | The foreign request is processed like any other. Passes when it is refused with a 4xx (403 is what the spec expects) and the token still works afterwards |
| `MAP-TOK01` | Sends `initialize` with the token as `?access_token=` and no `Authorization` header, then the control again | The token in the URL is accepted (the MCP specification forbids it: URLs end up in logs, history and `Referer` headers). The token never appears in the report |
| `MAP-SES01` | Opens an MCP session with its token, sends `ping` with the session ID and the token (control), then with the session ID only, and ends the session | The request without a token is processed. Not applicable to stateless servers that assign no session ID |
| `MAP-AUD01` | Uses the refresh token to request a token for `https://other.mcp-authprobe.invalid/mcp` and presents it to your MCP endpoint (only after a successful control) | The MCP endpoint accepts a token whose audience is the other resource (read from a JWT `aud`). Passes when the authorization server answers `invalid_target`, or the MCP endpoint answers 401/403. When the token is opaque, or the authorization server ignored `resource` and issued a token for your server, the result is inconclusive with an explanation, because the MCP server cannot be blamed |
| `MAP-COD01` | Presents the already used code a second time, then tries the newest refresh token once | The code is exchanged again. Revoking the tokens issued from a reused code (`invalid_grant` on that refresh) is reported as recommended; any other answer leaves revocation unknown |

The results are stored in the grant file and reported by the next scan of the same target. The refresh token kept in the grant is always the newest one, so rotation during these probes does not break the scan. A network failure during a probe makes that check inconclusive; it never loses the grant or the other results.

If a probe obtains tokens (the check fails), the code is spent: the following pre-exchange probes are reported as not observed, the tokens obtained are kept as the grant, and `MAP-COD01` still runs (presenting the code again is its second use).

Some strict servers invalidate a code after any failed attempt. That is acceptable behaviour: only the first refusal is trusted and the following probes are reported as inconclusive. Likewise, a server that revokes the tokens after a code reuse (recommended) passes `MAP-COD01`. In both cases `login` writes the results without a grant; log in again with `--no-probe --force --out <same file>` to add a grant: the earlier results of the same target are kept.

## Redirect URI checks

If an authorization server redirects to a URI the client never registered, authorization codes can end up with an attacker. OAuth 2.1 requires exact string matching. These checks need **dynamic client registration** on your server; no test grant and no login are required.

How they work:

1. The scanner registers a temporary client whose only redirect URI is `https://client.mcp-authprobe.invalid/callback`.
2. It sends a **baseline** authorization request with that registered URI (PKCE S256, random `state`, RFC 8707 `resource`), then one request per variant, and compares the answers. Redirects are never followed.
3. It deletes every client it created (RFC 7592). Clients it could not delete are listed in the report, named `mcp-authprobe test client (safe to delete)`.

| Check | What is sent | Fails when |
| --- | --- | --- |
| `MAP-RDR01` | A completely different host | The server redirects to it |
| `MAP-RDR02` | 7 near misses: extra path segment, trailing slash, added query, different port, subdomain, userinfo trick, `http` downgrade | The server redirects to any of them |
| `MAP-RDR04` | Registrations with plain HTTP on a non-loopback host, `javascript:`, `data:`, and a fragment | The registration endpoint accepts any of them |

Safety by design: every host used lives under the reserved `.invalid` top-level domain ([RFC 2606](https://www.rfc-editor.org/rfc/rfc2606)), which can never resolve. Even a vulnerable server could not deliver a code anywhere.

Reading the results: a variant answered exactly like the baseline (for example both redirected to the login page) is reported as **inconclusive** (`error`), never as a pass, because some servers only check `redirect_uri` after the user logs in. `MAP-RDR03` (token endpoint enforcement) is observed during [interactive login](#interactive-login).

## Throttling check

Without rate limiting, refresh tokens, authorization codes and client secrets can be guessed at line speed. `MAP-THR01` checks that the token endpoint slows down repeated failures, with strict bounds:

- It sends **10** token requests by default (`--throttle-attempts`, between **5 and 20**, hard-capped), **one at a time**.
- Each request carries a **freshly generated random refresh token** that cannot be valid. Nothing is guessed, and **user passwords and login forms are never involved**. If the very first one gets a server error or `unsupported_grant_type` (a server without a working refresh grant), the check switches once to random authorization codes and starts counting again.
- It uses your test client when a grant is supplied (your real refresh token is not sent), otherwise a temporary client that is deleted afterwards.
- It stops at the first sign of throttling: HTTP 429, a `Retry-After` header, or an OAuth `slow_down` / `temporarily_unavailable` error.
- It runs **last** in a scan, so a throttled token endpoint cannot disturb the other checks.

A failure means no throttling was seen within the cap. Your limit may simply be higher than 20; the finding asks you to confirm that one exists.

## Consent CSRF check

If a third-party website can submit your consent page on behalf of a logged-in user, it can make them grant access without noticing (the confused deputy described in the MCP security best practices). `MAP-CSR01` checks that the consent decision is protected, in a **real browser** with your **test account**:

```sh
npx -p mcp-authprobe -p playwright-core mcp-authprobe consent-check https://mcp.example.com/mcp
```

1. The ownership of every contacted host must be proven first.
2. It registers a temporary client and opens **your installed Chrome** (or `--browser msedge`, or `--browser-path <executable>`) on the authorization page. No browser is downloaded; `playwright-core` is an optional dependency used only by this command.
3. You log in with the test account. When the consent page is shown, **do not click anything**: go back to the terminal and press Enter.
4. The tool reads the consent form and the cookie attributes exactly as the server set them, closes the browser, then sends form submissions with the session cookies:
   - without any anti-CSRF field, from a foreign Origin: must be refused;
   - with the anti-CSRF field altered (same length and alphabet), from a foreign Origin: must be refused;
   - the untouched form, from a foreign Origin: informational, shows whether the server also checks Origin;
   - a **control**: the untouched form from the page's own Origin, which must be accepted.
5. It deletes the temporary client. The loopback redirect URI is served by the tool itself, so even an accidental approval delivers the code nowhere else.

Many authorization servers (node-oidc-provider, Ory Hydra, Keycloak) have no anti-CSRF field: the consent form carries a **per-flow identifier** issued by the server, in a hidden field or in the form's URL (`/interaction/<id>`). When there is no anti-CSRF field but such an identifier, two extra submissions come first, before anything can be granted: one with the identifier altered and one without any cookie, both from a foreign Origin. If either is accepted, the check fails. If both are refused and the untouched form is accepted, the result is **inconclusive** with an explanation: this design is safe when the identifier is bound to the user's own session, which cannot be proven from a single session.

The check **fails** when consent is granted without a valid anti-CSRF token. It only **passes** when the control proves that the tool reproduces a real grant; otherwise (labels it cannot recognise, consent sent by JavaScript, multi-step flows, single-use tokens) the result is **inconclusive**, never a pass. The finding also reports whether the session cookies are explicitly `SameSite=Lax/Strict`, which blocks the attack from other sites in modern browsers, but not from same-site subdomains or older clients; a cookie without the attribute is reported as `Unspecified`. Ctrl-C, closing the browser or a 10-minute timeout stop the check cleanly and still delete the temporary client.

It is not available in MCP server mode, because it needs you to log in.

## Use it from an MCP client

`mcp-authprobe mcp` runs the same engine as an MCP server over stdio, so an AI assistant in any MCP client can audit your servers for you.

Add it to your client's MCP configuration (most clients use this `mcpServers` format):

```json
{
  "mcpServers": {
    "mcp-authprobe": {
      "command": "npx",
      "args": ["-y", "mcp-authprobe", "mcp"],
      "env": {
        "MCP_AUTHPROBE_SECRET_FILE": "/home/you/.config/mcp-authprobe/secret",
        "MCP_AUTHPROBE_CREDENTIALS_FILE": "/home/you/.config/mcp-authprobe/test-grant.json"
      }
    }
  }
}
```

The server is also listed in the official MCP Registry as `io.github.Enigmacker/mcp-authprobe`, so registry-aware clients can install it directly.

From a source checkout, use `"command": "node"` with `"args": ["/path/to/mcp-authprobe/dist/cli.js", "mcp"]`.

| Tool | What it does | Annotations |
| --- | --- | --- |
| `list_checks` | Lists the catalogue | read-only |
| `explain_check` | Explains one check | read-only |
| `ownership_proof` | Returns the proof to publish for a host (never the secret) | read-only |
| `verify_ownership` | Checks that the proof is published | read-only, open world |
| `scan` | Runs discovery and the active checks; returns a Markdown summary and the full report as structured content | **destructive**, open world |

The server is built so that the assistant, or a prompt injection reaching it, cannot widen what the scanner may do:

- **Everything sensitive is set by you in the configuration, never by tool arguments:** the ownership secret, the test grant, the static key, and private-address access. The `scan` tool takes a URL, plus `only` and `skip`, which can only narrow a scan.
- **A static key is bound to one URL** (`MCP_AUTHPROBE_BEARER_TARGET`): the assistant cannot send it anywhere else.
- **`scan` is annotated as destructive**, so well-behaved clients ask for your confirmation before each call. It consumes the test grant and registers temporary clients.
- **Only `https` targets** are accepted; plain `http` only for loopback or private-address labs with `MCP_AUTHPROBE_ALLOW_PRIVATE=1`. URLs with embedded credentials are refused, and only one scan runs at a time.
- **Loopback targets still need a proof** in MCP mode, unless you list their origin in `MCP_AUTHPROBE_LAB_ORIGINS`. An assistant cannot point active requests at arbitrary local services.
- **The test grant is only used if it names the scanned target** (grants created by `login` do), so it cannot be spent on another server.
- **Reports are marked as data:** every scan result ends with a notice that server-controlled text in it must not be treated as instructions.

| Environment variable | Purpose |
| --- | --- |
| `MCP_AUTHPROBE_SECRET` or `MCP_AUTHPROBE_SECRET_FILE` | Ownership secret (prefer the file) |
| `MCP_AUTHPROBE_CREDENTIALS_FILE` | Test grant for the refresh token checks |
| `MCP_AUTHPROBE_ALLOW_PRIVATE=1` | Allow loopback and private targets (local labs only) |
| `MCP_AUTHPROBE_LAB_ORIGINS` | Comma-separated lab origins (e.g. `http://127.0.0.1:8080`) exempt from the ownership proof |
| `MCP_AUTHPROBE_TIMEOUT_MS` | Per-request timeout |
| `MCP_AUTHPROBE_BEARER_FILE` and `MCP_AUTHPROBE_BEARER_TARGET` | Static API key, and the exact MCP URL it may be used for (both required) |
| `MCP_AUTHPROBE_BEARER_HEADER` | Header for the key (default `Authorization`, sent as `Bearer`) |


### With Docker

The repository's `Dockerfile` builds the same stdio MCP server:

```sh
docker build -t mcp-authprobe https://github.com/Enigmacker/mcp-authprobe.git
docker run -i --rm -e MCP_AUTHPROBE_SECRET mcp-authprobe
```

In a container, `--allow-private` labs on your machine are not reachable as `127.0.0.1`; use the npm package for the lab.

## What it checks

`mcp-authprobe checks list` prints the catalogue, and `mcp-authprobe checks show <ID>` explains a check: why it matters, how to fix it, and references. IDs are stable and never reused.

| ID | Mode | Status | Check |
| --- | --- | --- | --- |
| `MAP-DSC01` | passive | available | Authorization endpoints are discoverable (401 challenge, RFC 9728, RFC 8414) |
| `MAP-RTK01` | active | available | Refresh tokens for public clients are rotated |
| `MAP-RTK02` | active | available | A rotated refresh token cannot be replayed |
| `MAP-RTK03` | active | available | Refresh token replay revokes the token family |
| `MAP-RDR01` | active | available | Unregistered `redirect_uri` is refused at the authorization endpoint |
| `MAP-RDR02` | active | available | `redirect_uri` matching is exact, not prefix or pattern based |
| `MAP-RDR03` | active | available (via `login`) | Token endpoint enforces the `redirect_uri` used at authorization |
| `MAP-RDR04` | active | available | Dynamic client registration refuses unsafe redirect URIs |
| `MAP-THR01` | active | available | Repeated failed token requests are throttled (5 to 20 sequential requests with random values) |
| `MAP-CSR01` | active | available (via `consent-check`) | Consent decision is protected against CSRF |
| `MAP-PKC01` | active | available (via `login`) | Token endpoint enforces PKCE (no `code_verifier`, wrong `code_verifier`) |
| `MAP-COD01` | active | available (via `login`) | An authorization code cannot be used twice |
| `MAP-AUD01` | active | available (via `login`) | Tokens are bound to their audience (RFC 8707) |
| `MAP-ORG01` | passive | available | MCP endpoint rejects requests from a foreign, `null` or malformed `Origin` |
| `MAP-TOK01` | active | available (via `login` or a static key) | MCP endpoint refuses access tokens and keys in the URL |
| `MAP-SES01` | active | available (via `login` or a static key) | An MCP session ID is not accepted instead of a token |
| `MAP-COR01` | passive | available | MCP endpoint does not allow credentialed requests from any origin (CORS) |
| `MAP-BAT01` | active | available (via `login` or a static key) | MCP endpoint refuses JSON-RPC batches |
| `MAP-BOD01` | active | available (via `login` or a static key) | MCP endpoint limits the request body size (6 MiB, with and without `Content-Length`) |
| `MAP-THR02` | active | available (with a static key) | MCP endpoint rate-limits each credential (10 to 100 `ping` requests) |
| `MAP-INJ01` | active | available (via `login`, a static key, or anonymous servers) | Tool, prompt and resource metadata carry no hidden instructions (tool poisoning) |

Families: **DSC** discovery, **RTK** refresh tokens, **RDR** redirect URIs, **THR** throttling, **CSR** consent CSRF, **PKC** PKCE, **COD** authorization codes, **AUD** token audience, **ORG** Origin validation, **TOK** token transport, **SES** sessions, **COR** CORS, **BAT** batches, **BOD** body size, **INJ** prompt injection.

`MAP-ORG01` runs in every scan without an ownership proof: it sends two ordinary `initialize` requests, one with a foreign `Origin`. Most servers ask for a token before looking at `Origin`; the scan then reports it as inconclusive, and `login` observes it with a valid token. `MAP-COR01` also runs in every scan: a CORS preflight and an ordinary request with a foreign `Origin`; it fails only when that origin is reflected together with `Access-Control-Allow-Credentials: true`.

### Choosing checks

`--only` and `--skip` take comma-separated check IDs (`MAP-RDR01`, or just `RDR01`) or families (`RDR`), case-insensitive. `--skip` wins over `--only`; an unknown name is a usage error, so a typo never silently changes what runs.

```sh
mcp-authprobe scan https://mcp.example.com/mcp --skip THR        # production: no failed token requests
mcp-authprobe scan https://mcp.example.com/mcp --only RDR02      # re-check one fix
```

A check that is not selected sends **no request** and is listed as `skipped (not selected)`, so a report never suggests it passed. The three refresh token checks are one sequence: selecting any of them runs the three (the others are then reported as not selected), and skipping all three leaves the test grant untouched. The MCP server's `scan` tool takes the same `only` and `skip` arguments.

## Servers with a static API key

Many MCP servers, especially in front of SaaS APIs, take a fixed API key instead of OAuth. Give the key to the scanner in a file:

```sh
printf '%s\n' 'your-test-key' > test.key && chmod 600 test.key
mcp-authprobe scan https://mcp.example.com/mcp --bearer-file test.key
# a key sent in another header, as is
mcp-authprobe scan https://mcp.example.com/mcp --bearer-file test.key --bearer-header X-API-Key
```

With the key, and only once ownership of the target is proven, the checks of the MCP endpoint itself run with it:

| Check | With the key |
| --- | --- |
| `MAP-ORG01` | `initialize` with a foreign Origin, `Origin: null` and a malformed Origin: each must be refused with a 4xx (403 is what the spec expects) |
| `MAP-TOK01` | The key as `?access_token=`, `?api_key=`, `?key=` and `?token=`, without any header: each must be refused |
| `MAP-SES01` | When the server uses sessions: a `ping` carrying only the session ID must be refused |
| `MAP-BAT01` | One POST carrying a JSON-RPC batch of 5 `ping` requests must be refused: MCP has allowed one message per request since 2025-06-18, and a server that runs batches counts many calls as one |
| `MAP-BOD01` | Two 6 MiB `ping` requests, one with `Content-Length` and one chunked, must be refused (ideally 413) |
| `MAP-INJ01` | Tool, prompt and resource metadata, read with the key, must carry no hidden instructions (see [Tool poisoning check](#tool-poisoning-check)) |
| `MAP-THR02` | Up to 30 `ping` requests (`--rate-attempts`, 10 to 100) must meet a rate limit (429 or `Retry-After`). Runs last, since a limited key may be refused for a while |

`MAP-DSC01` becomes *not applicable*, and so do the authorization server checks, when no OAuth metadata is published. This only happens when you declare a key: a bare 401 without metadata also looks like a broken OAuth setup, which must stay visible.

Only side-effect-free methods are sent (`initialize`, `ping` and the list methods); no tool is ever called. Every check has a hard request cap, the key is read from a file (a warning is printed if other users can read it), never accepted on the command line, and masked in every report. `MAP-BAT01`, `MAP-BOD01` and `MAP-INJ01` also run during `login` with the OAuth access token.

Use a dedicated test key: `MAP-THR02` may get it rate-limited for a few minutes. The `static-bearer` and `static-bearer-secure` lab profiles show all of this without a real server.

## Tool poisoning check

The client's model reads what a server says about itself (tool, prompt and resource descriptions, input schemas, the `instructions` of the `initialize` result) as trusted context. An instruction hidden there reaches every user of the server: this is *tool poisoning*, a prompt injection that needs no attacker in the conversation. It often arrives by accident, through a description generated from a third-party API or copied from a package.

`MAP-INJ01` reads that metadata with the list methods only (`tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`, at most 10 pages and 1,000 items each; nothing is called or read) and fails on:

- **invisible characters:** Unicode tags (which can spell a whole hidden sentence; the scanner decodes them before matching), zero-width and bidi controls, ANSI escapes and other controls. Emoji sequences are fine;
- **instruction-like text:** "ignore previous instructions", `<IMPORTANT>` and similar pseudo-tags, "do not tell the user", "without asking the user", paths such as `~/.ssh` or `mcp.json`, "you are now…";
- **tool names with non-ASCII characters**, which can imitate another tool. Names outside the recommended format (1 to 128 of `A-Z a-z 0-9 _ - .`) are only noted.

The report names where something matched and which pattern, **never the suspicious text itself**, so the report cannot carry the injection further, for instance into an assistant that runs the scanner through MCP. This is pattern matching, aimed at known idioms: a pass is not a proof, and a match is something to review.

It runs with the key (`--bearer-file`), during `login` with the access token, or, on a server that answers anonymous requests, without any credential once ownership is proven. The `vulnerable` and `static-bearer` lab profiles announce a poisoned tool, prompt and resource; the secure ones, clean ones.

## Combine with mcp-posture

[mcp-posture](https://github.com/batou9150/mcp-posture) reads what a server **announces**; mcp-authprobe tests what it **enforces**. Run mcp-posture first, then hand its JSON report to the scan:

```sh
mcp-posture scan https://mcp.example.com/mcp --json posture.json
mcp-authprobe scan https://mcp.example.com/mcp --posture-report posture.json --markdown report.md
```

The report gains a passive section with mcp-posture's findings (with their stable fingerprints) and one line per subject both tools look at:

| Relation | Meaning |
| --- | --- |
| **confirmed** | mcp-posture saw a sign in the metadata, and the active test proves the weakness |
| **active only** | the metadata gives no sign of it, but the active test proves the weakness (for example PKCE advertised but not enforced) |
| **enforced** | mcp-posture flags it from the metadata, or cannot verify it passively (`MCPP-ASM08`, token audience), but the active test shows it is enforced |

| mcp-authprobe | mcp-posture, passive | mcp-posture IDs reserved for active tests |
| --- | --- | --- |
| `MAP-DSC01` | `MCPP-AUTHN01-03`, `MCPP-PRM01`, `MCPP-ASM01` | |
| `MAP-PKC01` | `MCPP-ASM04`, `MCPP-ASM05` | `MCPP-ACT08` |
| `MAP-AUD01` | `MCPP-ASM08` | `MCPP-ACT03`, `MCPP-ACT06` |
| `MAP-TOK01` | `MCPP-PRM06` | `MCPP-ACT02` |
| `MAP-SES01` | `MCPP-TRN08`, `MCPP-TRN09` | `MCPP-ACT04` |
| `MAP-ORG01` | | `MCPP-ACT01` |
| `MAP-RDR01`, `MAP-RDR02` | | `MCPP-ACT07` |
| `MAP-RDR04` | `MCPP-ASM09` | `MCPP-ACT09` |

The report must be mcp-posture's JSON (`schema_version` 1.x) and contain a result for the same URL. It is treated as untrusted input: size-capped, type-checked and neutralized like everything else. Suppressed mcp-posture findings are left out, and mcp-posture's findings never change mcp-authprobe's exit code. The merged results appear in the table, JSON (a `posture` block) and Markdown reports; SARIF keeps mcp-authprobe's results only, since mcp-posture writes its own.

## Reports and exit codes

| Option | Output |
| --- | --- |
| *(always)* | Human-readable table on stdout |
| `--json <file>` | Full report, schema `mcp-authprobe/report/v1` |
| `--sarif <file>` | SARIF 2.1.0, for GitHub code scanning; only failing checks become results |
| `--markdown <file>` | Table for a pull request comment or a CI job summary |
| `--credentials-file <file>` | Test grant for the refresh token checks (input) |

| Exit code | Meaning |
| --- | --- |
| `0` | No failing check at or above `--fail-on` (default `high`) |
| `1` | At least one failing check at or above `--fail-on` (or `ownership verify` failed) |
| `2` | Usage error |
| `3` | A check was inconclusive, or the target was unreachable. With `--fail-on-inconclusive false`, inconclusive checks no longer change the exit code; a scan that cannot run still exits 3 |

All server-controlled text is neutralized before it reaches a report: terminal escape sequences, bidi overrides and invisible characters are escaped, and token-shaped values are redacted.

## GitHub Action

Run the scan on every deployment, or every night, so a change that reintroduces a flaw is caught before anyone else finds it.

```yaml
name: MCP authorization
on:
  schedule:
    - cron: "17 3 * * *"
  workflow_dispatch:

permissions:
  contents: read
  security-events: write   # only for upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: Enigmacker/mcp-authprobe@v0.10.1
        with:
          url: https://staging.example.com/mcp
          secret: ${{ secrets.MCP_AUTHPROBE_SECRET }}
          skip: THR            # optional: no failed token requests
          upload-sarif: true   # optional: findings in the Security tab
```

The results table is added to the job summary. The step fails when a check fails at or above `fail-on`.

| Input | Default | Meaning |
| --- | --- | --- |
| `url` | (required) | MCP endpoint to scan |
| `secret` | | Ownership secret, from a repository secret. Without it, only discovery, `MAP-ORG01` and `MAP-COR01` run |
| `fail-on` | `high` | Fail on a failing check at or above this severity |
| `fail-on-inconclusive` | `false` | Also fail when a check is inconclusive (otherwise a warning). An unreachable target always fails |
| `only` / `skip` | | Same as `--only` / `--skip` |
| `bearer` | | Static API key, from a repository secret; written to a private temporary file, never on the command line |
| `bearer-header`, `rate-attempts` | | Same as `--bearer-header`, `--rate-attempts` |
| `posture-report` | | An mcp-posture JSON report to merge, see [Combine with mcp-posture](#combine-with-mcp-posture) |
| `throttle-attempts`, `timeout` | | Same as the CLI options |
| `upload-sarif` | `false` | Upload the SARIF report to code scanning (needs `security-events: write`) |
| `allow-private` | `false` | For a lab started in the same job only |
| `node-version` | `22` | Node.js used to run the scanner |
| `package` | this release | npm package spec to run, e.g. `mcp-authprobe@0.10.1` |

Both tools have an Action, so the passive and active views fit in one job:

```yaml
      - uses: batou9150/mcp-posture@v1.2.0
        with:
          targets: https://staging.example.com/mcp
          args: --json posture.json
          fail: false   # let the active scan run too; each tool reports its own findings
      - uses: Enigmacker/mcp-authprobe@v0.10.1
        with:
          url: https://staging.example.com/mcp
          secret: ${{ secrets.MCP_AUTHPROBE_SECRET }}
          posture-report: posture.json
```

Outputs: `exit-code`, `failed` (number of failing checks), `json-file`, `sarif-file`, `markdown-file`.

The secret is passed through the environment, never on a command line. The refresh token checks and the login checks are not run by the action: they need a test grant from an interactive `login`, and a grant is consumed by a scan. Run them by hand after a change to your authorization server.

Run active scans against a staging environment rather than production whenever you can.

Without the action, the same thing in plain steps:

```yaml
- uses: actions/setup-node@v7
  with:
    node-version: 22
- run: npx mcp-authprobe scan "$MCP_URL" --sarif results.sarif --markdown summary.md
  env:
    MCP_URL: https://mcp.example.com/mcp
    MCP_AUTHPROBE_SECRET: ${{ secrets.MCP_AUTHPROBE_SECRET }}
- run: cat summary.md >> "$GITHUB_STEP_SUMMARY"
  if: always()
```

## Safety of the scanner

The scanner talks to servers that may be hostile, and it may be driven by an AI agent. It protects both you and third parties:

- **Ownership gate:** no active request without a valid proof for every contacted host (the only exception is `login`, which behaves like an ordinary MCP client; see above).
- **HTTPS only:** every request, including endpoints announced by a server's metadata, must use HTTPS. Plain HTTP is accepted only for loopback or private-address labs with `--allow-private`, so tokens and secrets never travel in cleartext over the internet.
- **Inconclusive is never a pass:** rate limits (429, `Retry-After`) and server errors (5xx) make a check report `error`, never `pass`.
- **SSRF protection:** loopback, private, link-local, CGNAT, multicast, reserved and cloud-metadata addresses are refused at connect time, after DNS resolution, unless `--allow-private` is passed.
- **No automatic redirects:** every redirect is inspected, never followed blindly.
- **Bounded resources:** per-request timeouts, response bodies capped at 1 MiB, no compression requested.
- **Secrets stay secret:** tokens and the ownership secret are never printed, and are redacted from every report.
- **Server text is data:** everything taken from a server is neutralized (control, bidi and invisible characters escaped) and size-capped; text that looks like an injection is never copied into a report, only located; in MCP mode, the tool result tells the assistant that server content is data, not instructions.
- **No telemetry.**

## Roadmap

**0.1.0**
- ~~Refresh token checks (RTK01-03)~~ done, from a test grant file.
- ~~Interactive login creating the test grant~~ done.
- ~~Redirect URI checks (RDR01, RDR02, RDR04)~~ done.
- ~~`MAP-RDR03`~~ done, observed during login.
- ~~Throttling check (THR01)~~ done.
- ~~MCP server mode (stdio)~~ done.
- ~~npm release~~ done.

**0.2.0**
- ~~Consent CSRF check (CSR01), driven through a browser session~~ done.

**0.3.0**
- ~~PKCE enforcement (PKC01), code reuse (COD01), token audience (AUD01), Origin validation (ORG01)~~ done.
- ~~Local practice server (`lab`)~~ done.

**0.4.0**
- ~~GitHub Action, `--only` / `--skip`~~ done.

**0.5.0**
- ~~Field trial against node-oidc-provider and the MCP SDK's OAuth example, with the fixes it led to~~ done.

**0.6.0**
- ~~Token in the URL (TOK01), session ID without a token (SES01), CORS with credentials (COR01)~~ done.

**0.7.0**
- ~~Readable terminal output and an animated demo~~ done.

**0.8.0**
- ~~Import of mcp-posture reports, merged with the active results~~ done.
- ~~Dockerfile, listed on Glama~~ done.

**0.9.0**
- ~~Servers with a static API key; JSON-RPC batches, body size and per-key rate limit checks~~ done.

**0.10.0**
- ~~Tool poisoning check (INJ01) on tool, prompt and resource metadata, with poisoned lab profiles~~ done.

**Next**
- Ideas welcome in the issues.

## Development

```sh
npm ci
npm run typecheck
npm test          # unit and integration tests against a local fixture server
npm run build
npm run check     # all of the above
npm run demo      # re-record docs/demo/demo.gif (needs Chrome and ffmpeg)
```

Tests never leave the machine: integration tests run against a fixture server bound to `127.0.0.1`.

## Contributing and security

- How to add a check: [CONTRIBUTING.md](CONTRIBUTING.md)
- Reporting a vulnerability in mcp-authprobe itself: [SECURITY.md](SECURITY.md)
- Changes: [CHANGELOG.md](CHANGELOG.md)

## License

[MIT](LICENSE) © 2026 Enigmacker
