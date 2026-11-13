/**
 * Redaction and neutralization helpers.
 *
 * Every string that reaches a report or a log goes through `safeText`, which
 * removes token-shaped values and strips control, bidi and invisible
 * characters that a hostile server could use to spoof terminal output or
 * pull-request comments.
 */

const SECRET_PATTERNS: readonly RegExp[] = [
  // JWTs
  /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g,
  // Bearer values
  /(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi,
  // OAuth parameters carrying secrets
  /((?:access_token|refresh_token|id_token|client_secret|code|code_verifier|password)["']?\s*[=:]\s*["']?)[^"'&\s,}]{4,}/gi,
];

/** Exact values to hide everywhere (a static API key read from --bearer-file). */
const KNOWN_SECRETS = new Set<string>();

/** Registers a secret so that any later report or log line masks it. */
export function registerSecret(value: string): void {
  if (value.length >= 4) KNOWN_SECRETS.add(value);
}

export function redactSecrets(input: string): string {
  let out = input;
  for (const secret of KNOWN_SECRETS) out = out.split(secret).join("[REDACTED]");
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, (match, prefix?: string) =>
      typeof prefix === "string" && match.startsWith(prefix) ? `${prefix}[REDACTED]` : "[REDACTED]",
    );
  }
  return out;
}

// C0/C1 controls (except tab and newline), bidi overrides/isolates,
// zero-width characters, BOM and Unicode tag characters.
const UNSAFE_CHARS =
  /[\u0000-\u0008\u000B-\u001F\u007F-\u009F​-‏‪-‮⁠-⁤⁦-⁩﻿]|[\u{E0000}-\u{E007F}]/gu;

export function neutralize(input: string): string {
  return input.replace(UNSAFE_CHARS, (ch) => `\\u{${ch.codePointAt(0)?.toString(16) ?? "?"}}`);
}

export function safeText(input: string, maxLength = 500): string {
  const cleaned = neutralize(redactSecrets(input));
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}…` : cleaned;
}
