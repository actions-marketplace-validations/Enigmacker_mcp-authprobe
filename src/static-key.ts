import { closeSync, fstatSync, openSync, readSync, constants } from "node:fs";
import { bearerCredential, type Credential } from "./oauth/mcp-call.js";
import { registerSecret } from "./redact.js";

/**
 * Static API key for MCP servers authenticated without OAuth (`--bearer-file`).
 * The key is read from a file, never from the command line, registered for
 * redaction everywhere, and only sent to the target once ownership of it is
 * proven.
 */

const MIN_KEY_LENGTH = 8;
const MAX_KEY_BYTES = 8 * 1024;
/** Headers a key may not be sent in: they would change the request itself. */
const FORBIDDEN_HEADERS = new Set(["host", "content-length", "content-type", "transfer-encoding", "connection", "origin", "mcp-session-id", "mcp-protocol-version", "accept", "user-agent"]);

export class StaticKeyError extends Error {}

export function validateHeaderName(name: string): string {
  const h = name.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(h)) throw new StaticKeyError(`Invalid header name "${name.slice(0, 64)}".`);
  if (FORBIDDEN_HEADERS.has(h)) throw new StaticKeyError(`The key cannot be sent in the ${h} header.`);
  return h;
}

export function loadBearerFile(path: string, header = "authorization"): { credential: Credential; warnings: string[] } {
  const h = validateHeaderName(header);
  const warnings: string[] = [];
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch (e) {
    throw new StaticKeyError(`Cannot read the key file ${path}: ${(e as NodeJS.ErrnoException).code ?? "error"}.`);
  }
  let text: string;
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new StaticKeyError(`${path} is not a regular file.`);
    if (st.size > MAX_KEY_BYTES) throw new StaticKeyError(`${path} is larger than 8 KiB; expected one key.`);
    if (process.platform !== "win32" && (st.mode & 0o077) !== 0) {
      warnings.push(`${path} is readable by other users (mode ${(st.mode & 0o777).toString(8)}); chmod 600 it.`);
    }
    const buf = Buffer.alloc(st.size);
    readSync(fd, buf, 0, st.size, 0);
    text = buf.toString("utf8");
  } finally {
    closeSync(fd);
  }
  const key = text.trim();
  if (!key) throw new StaticKeyError(`${path} is empty.`);
  // Short values could not be redacted reliably and are not real keys.
  if (key.length < MIN_KEY_LENGTH) throw new StaticKeyError(`${path} holds fewer than ${MIN_KEY_LENGTH} characters; expected an API key.`);
  if (/[\s\u0000-\u001f\u007f]/.test(key)) throw new StaticKeyError(`${path} must contain one key on one line, without spaces.`);
  registerSecret(key);
  return { credential: bearerCredential(key, h, "static"), warnings };
}
