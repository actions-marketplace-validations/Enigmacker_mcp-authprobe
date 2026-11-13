import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { runEndpointChecks, type EndpointCheckId } from "../src/checks/endpoint.js";
import { HttpClient } from "../src/net/http.js";
import { bearerCredential, jsonRpcMessages } from "../src/oauth/mcp-call.js";
import { scan } from "../src/scan.js";

const KEY = "sk_edge_0123456789abcdef";
let server: Server | undefined;
afterEach(async () => {
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = undefined;
});

interface Req {
  headers: IncomingMessage["headers"];
  url: string;
  body: string;
  count: number;
}
type Handler = (req: Req, res: ServerResponse) => void;

/** A scripted MCP endpoint: anonymous requests get 401, the rest go to `handler`. */
async function start(handler: Handler): Promise<string> {
  let count = 0;
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (c: Buffer) => {
      if (body.length < 4096) body += c.toString("utf8");
    });
    req.on("end", () => {
      if (req.headers["authorization"] !== `Bearer ${KEY}`) {
        res.writeHead(401, { "www-authenticate": "Bearer" }).end();
        return;
      }
      count += 1;
      handler({ headers: req.headers, url: req.url ?? "/", body, count }, res);
    });
  });
  await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(server!.address() as AddressInfo).port}/mcp`;
}

const ok = (res: ServerResponse, id: unknown = 1): void => {
  res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id, result: {} }));
};
const isPing = (r: Req): boolean => r.body.includes('"ping"');

async function run(url: string, checks: EndpointCheckId[], rateAttempts?: number) {
  const http = new HttpClient({ allowPrivate: true });
  const { findings } = await runEndpointChecks(http, url, bearerCredential(KEY, "authorization", "static"), { checks, ...(rateAttempts ? { rateAttempts } : {}) });
  return Object.fromEntries(findings.map((f) => [f.checkId, f]));
}

describe("endpoint checks, edge cases", () => {
  it("BAT01 is inconclusive when a single ping is refused too", async () => {
    const url = await start((r, res) => (isPing(r) ? res.writeHead(400).end() : ok(res)));
    expect((await run(url, ["MAP-BAT01"]))["MAP-BAT01"]?.status).toBe("error");
  });

  it("BOD01 is inconclusive when even a 1 KiB padded ping is refused", async () => {
    const url = await start((r, res) => (isPing(r) ? res.writeHead(400).end() : ok(res)));
    expect((await run(url, ["MAP-BOD01"]))["MAP-BOD01"]?.status).toBe("error");
  });

  it("THR02 passes on a 403 after accepted requests", async () => {
    const url = await start((r, res) => (isPing(r) && r.count > 6 ? res.writeHead(403).end() : ok(res)));
    const f = (await run(url, ["MAP-THR02"], 10))["MAP-THR02"];
    expect(f?.status).toBe("pass");
    expect(f?.message).toMatch(/probably a limit/);
  });

  it("THR02 does not pass on a 5xx with Retry-After", async () => {
    const url = await start((r, res) => (isPing(r) && r.count > 4 ? res.writeHead(503, { "retry-after": "5" }).end() : ok(res)));
    expect((await run(url, ["MAP-THR02"], 10))["MAP-THR02"]?.status).toBe("error");
  });

  it("THR02 is inconclusive when the first ping is refused", async () => {
    const url = await start((r, res) => (isPing(r) ? res.writeHead(400).end() : ok(res)));
    expect((await run(url, ["MAP-THR02"], 10))["MAP-THR02"]?.status).toBe("error");
  });

  it("sends MCP-Protocol-Version on every request after initialize", async () => {
    const missing: string[] = [];
    const url = await start((r, res) => {
      if (isPing(r) && !r.headers["mcp-protocol-version"]) missing.push(r.body.slice(0, 40));
      ok(res);
    });
    await run(url, ["MAP-BAT01", "MAP-THR02"], 10);
    expect(missing).toEqual([]);
  });
});

describe("jsonRpcMessages", () => {
  it("joins multi-line SSE data and splits events", () => {
    const body = 'event: message\ndata: {"jsonrpc":"2.0",\ndata: "id":1,"result":{}}\n\ndata: {"jsonrpc":"2.0","id":2,"result":{}}\n\n';
    const msgs = jsonRpcMessages({ status: 200, sessionId: null, headers: { "content-type": "text/event-stream" }, body });
    expect(msgs).toHaveLength(2);
  });
});

describe("scan with a static key and partial OAuth metadata", () => {
  it("does not mark the OAuth checks n/a when protected resource metadata exists", async () => {
    let origin = "";
    server = createServer((req, res) => {
      if (req.url?.startsWith("/.well-known/oauth-protected-resource")) {
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ resource: `${origin}/mcp`, authorization_servers: [] }));
        return;
      }
      res.writeHead(401, { "www-authenticate": "Bearer" }).end();
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
    origin = `http://127.0.0.1:${(server!.address() as AddressInfo).port}`;
    const report = await scan(`${origin}/mcp`, {
      allowPrivate: true,
      loopbackExempt: true,
      credential: bearerCredential(KEY, "authorization", "static"),
      select: (id) => id === "MAP-RDR01",
    });
    const rdr = report.findings.find((f) => f.checkId === "MAP-RDR01");
    expect(rdr?.status).not.toBe("not_applicable");
  });
});
