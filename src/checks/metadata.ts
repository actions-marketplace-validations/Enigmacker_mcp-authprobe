import type { HttpClient } from "../net/http.js";
import { endSession, jsonRpcMessages, mcpPost, PROTOCOL_VERSION, type Credential } from "../oauth/mcp-call.js";
import { TOOL_NAME, TOOL_VERSION } from "../version.js";

/**
 * MAP-INJ01: what the server tells the model about itself. Tool, prompt and
 * resource descriptions, and the `instructions` of the initialize result,
 * are read by the client's model as trusted context: a hidden instruction
 * there ("tool poisoning") is a prompt injection that every user of the
 * server receives. Only listing methods are sent (tools/list, prompts/list,
 * resources/list, resources/templates/list); nothing is called or read.
 */

export type MetadataIssueKind = "hidden" | "instruction" | "name";

export interface MetadataIssue {
  kind: MetadataIssueKind;
  /** Where, e.g. `tool "search" description`. */
  where: string;
  /** The tool, prompt or resource (or "initialize"). */
  item: string;
  /** What matched, short. */
  detail: string;
}

export interface MetadataResult {
  /** null when initialize itself did not work. */
  initializeStatus: number | null;
  counts: Record<"tools" | "prompts" | "resources" | "templates", number>;
  issues: MetadataIssue[];
  notes: string[];
}

const MAX_PAGES = 10;
const MAX_ITEMS = 1000;
const MAX_STRINGS_PER_ITEM = 200;

/**
 * Characters a reader never sees: C0/C1 controls (tab, CR and LF allowed),
 * zero-width and bidi controls, word joiners, BOM, Unicode tags (which can
 * spell a whole hidden ASCII sentence) and variation selectors outside emoji.
 */
const HIDDEN = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]|[\u{E0000}-\u{E007F}]|[\u{E0100}-\u{E01EF}]/gu;
const PICTO = /\p{Extended_Pictographic}/u;

/**
 * Instruction-like text aimed at the model rather than describing the tool.
 * Deliberately narrow: each pattern is a known tool-poisoning idiom.
 */
const INSTRUCTION_PATTERNS: ReadonlyArray<{ id: string; re: RegExp }> = [
  { id: "ignore previous instructions", re: /\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|preceding|system|other)\s+(?:instructions?|prompts?|rules|messages|directives)/i },
  { id: "pseudo-tag for the model", re: /<\s*\/?\s*(?:important|system|instructions?|hidden|secret|admin|override)\s*>/i },
  { id: "hide something from the user", re: /\b(?:do\s+not|don't|dont|never)\s+(?:tell|inform|mention|reveal|show|notify|alert)\s+(?:this\s+(?:to\s+)?)?(?:the\s+)?user\b/i },
  { id: "act without the user", re: /\bwithout\s+(?:telling|informing|asking|notifying|alerting)\s+(?:the\s+)?user\b/i },
  { id: "sensitive local file", re: /(?:~|\$HOME|%USERPROFILE%)[\\/]+\.(?:ssh|aws|gnupg|kube|docker|netrc)\b|\bid_(?:rsa|ed25519|ecdsa)\b|\bclaude_desktop_config\.json\b|\bmcp\.json\b|\.cursor[\\/]+mcp/i },
  { id: "role reassignment", re: /\byou\s+are\s+now\s+(?:a|an|in)\b|\bnew\s+system\s+prompt\b/i },
];

/** MCP 2025-11-25: tool names SHOULD be 1-128 of A-Z a-z 0-9 _ - . */
const TOOL_NAME_RE = /^[A-Za-z0-9_.-]{1,128}$/;

function visible(ch: string): string {
  return `U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}`;
}

/** Hidden characters in `s`, ignoring a zero-width joiner or variation selector inside an emoji sequence. */
export function hiddenCharacters(s: string): string[] {
  const found = new Set<string>();
  for (const m of s.matchAll(HIDDEN)) {
    const ch = m[0];
    const i = m.index ?? 0;
    if (ch === "‍" || ch === "️") {
      const before = s.slice(Math.max(0, i - 2), i);
      const after = s.slice(i + 1, i + 3);
      if (PICTO.test(before) || PICTO.test(after)) continue;
    }
    found.add(visible(ch));
  }
  return [...found];
}

/** Text spelled with Unicode tag characters (U+E0020-U+E007E map to ASCII). */
function decodeTags(s: string): string {
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCodePoint(cp - 0xe0000);
  }
  return out;
}

export function inspectText(where: string, s: string, item = where): MetadataIssue[] {
  const issues: MetadataIssue[] = [];
  const hidden = hiddenCharacters(s);
  if (hidden.length > 0) {
    const tags = decodeTags(s);
    issues.push({
      kind: "hidden",
      where,
      item,
      detail: `invisible characters ${hidden.slice(0, 6).join(", ")}${hidden.length > 6 ? ", …" : ""}${tags.length >= 4 ? ` (Unicode tags spelling ${tags.length} hidden ASCII characters)` : ""}`,
    });
  }
  // Match on the text a model would read, hidden tag text included.
  const readable = `${s.replace(HIDDEN, "")} ${decodeTags(s)}`;
  for (const p of INSTRUCTION_PATTERNS) {
    if (p.re.test(readable)) issues.push({ kind: "instruction", where, item, detail: p.id });
  }
  return issues;
}

/** Every string inside a JSON value, with a path, capped. */
function strings(v: unknown, path: string, out: Array<[string, string]>, depth = 0): void {
  if (out.length >= MAX_STRINGS_PER_ITEM || depth > 12) return;
  if (typeof v === "string") out.push([path, v]);
  else if (Array.isArray(v)) v.forEach((x, i) => strings(x, `${path}[${i}]`, out, depth + 1));
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) strings(x, path ? `${path}.${k}` : k, out, depth + 1);
}

function label(kind: string, item: Record<string, unknown>, index: number): string {
  const raw = typeof item["name"] === "string" ? item["name"] : typeof item["uri"] === "string" ? item["uri"] : typeof item["uriTemplate"] === "string" ? item["uriTemplate"] : `#${index + 1}`;
  // A name that is itself suspicious is not echoed: the position stands in for it.
  if (inspectText("", raw).length > 0 || raw.length > 60) return `${kind} #${index + 1}`;
  return `${kind} ${JSON.stringify(raw)}`;
}

const LISTS = [
  { method: "tools/list", key: "tools", capability: "tools", count: "tools", kind: "tool" },
  { method: "prompts/list", key: "prompts", capability: "prompts", count: "prompts", kind: "prompt" },
  { method: "resources/list", key: "resources", capability: "resources", count: "resources", kind: "resource" },
  { method: "resources/templates/list", key: "resourceTemplates", capability: "resources", count: "templates", kind: "resource template" },
] as const;

function resultOf(messages: unknown[], id: number): { result?: Record<string, unknown>; error?: { code?: number; message?: string } } | undefined {
  for (const m of messages) {
    if (m && typeof m === "object" && (m as { id?: unknown }).id === id) return m as { result?: Record<string, unknown>; error?: { code?: number } };
  }
  return undefined;
}

export async function inspectMetadata(http: HttpClient, target: string, cred?: Credential): Promise<MetadataResult> {
  const out: MetadataResult = { initializeStatus: null, counts: { tools: 0, prompts: 0, resources: 0, templates: 0 }, issues: [], notes: [] };
  const auth = cred ? { auth: cred } : {};
  const init = await mcpPost(http, target, {
    ...auth,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: TOOL_NAME, version: TOOL_VERSION } } }),
  });
  out.initializeStatus = init.status;
  if (init.status < 200 || init.status >= 300) return out;
  const session = init.sessionId;
  try {
    const initResult = resultOf(jsonRpcMessages(init), 1)?.result;
    if (!initResult) {
      out.notes.push("The initialize answer carries no JSON-RPC result.");
      out.initializeStatus = null;
      return out;
    }
    const capabilities = (initResult["capabilities"] ?? {}) as Record<string, unknown>;
    const fromInit: Array<[string, string]> = [];
    strings(initResult["serverInfo"], "serverInfo", fromInit);
    if (typeof initResult["instructions"] === "string") fromInit.push(["instructions", initResult["instructions"]]);
    for (const [path, s] of fromInit) out.issues.push(...inspectText(`initialize ${path}`, s, "initialize"));

    const withSession = { ...auth, ...(session ? { sessionId: session } : {}) };
    await mcpPost(http, target, { ...withSession, body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) });

    let id = 1;
    for (const list of LISTS) {
      if (!(list.capability in capabilities)) continue;
      let cursor: string | undefined;
      let pages = 0;
      do {
        id += 1;
        const r = await mcpPost(http, target, { ...withSession, body: JSON.stringify({ jsonrpc: "2.0", id, method: list.method, ...(cursor ? { params: { cursor } } : {}) }) });
        const msg = resultOf(jsonRpcMessages(r), id);
        if (!msg?.result) {
          out.notes.push(`${list.method}: ${msg?.error ? `JSON-RPC error ${msg.error.code ?? "?"}` : `HTTP ${r.status}, no result`}`);
          break;
        }
        const items = Array.isArray(msg.result[list.key]) ? (msg.result[list.key] as unknown[]) : [];
        for (const raw of items) {
          if (out.counts[list.count] >= MAX_ITEMS) break;
          if (!raw || typeof raw !== "object") continue;
          const item = raw as Record<string, unknown>;
          const where = label(list.kind, item, out.counts[list.count]);
          out.counts[list.count] += 1;
          if (list.kind === "tool" && typeof item["name"] === "string" && !TOOL_NAME_RE.test(item["name"])) {
            out.issues.push({ kind: "name", where, item: where, detail: /[^\x20-\x7e]/.test(item["name"]) ? "name has non-ASCII characters (can imitate another tool)" : "name outside A-Z a-z 0-9 _ - . (1-128)" });
          }
          const all: Array<[string, string]> = [];
          strings(item, "", all);
          for (const [path, s] of all) out.issues.push(...inspectText(`${where} ${path}`, s, where));
        }
        cursor = typeof msg.result["nextCursor"] === "string" ? msg.result["nextCursor"] : undefined;
        pages += 1;
      } while (cursor && pages < MAX_PAGES && out.counts[list.count] < MAX_ITEMS);
      if (cursor) out.notes.push(`${list.method}: stopped after ${pages} pages / ${out.counts[list.count]} items.`);
    }
  } finally {
    if (session && cred) await endSession(http, target, cred, session);
  }
  return out;
}

/** True when the issues include something that should fail the check. */
export function isPoisoned(issues: readonly MetadataIssue[]): boolean {
  return issues.some((i) => i.kind === "hidden" || i.kind === "instruction" || (i.kind === "name" && i.detail.startsWith("name has non-ASCII")));
}
