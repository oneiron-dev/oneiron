import { describe, expect, test } from "bun:test";
import { FacadeClient, FACADE_CATALOG, HttpBaseClient } from "../src/index";

describe("engine-table projection", () => {
  test("every generated method makes exactly its named HTTP call", async () => {
    const calls: { url: string; body: unknown }[] = [];
    const client = new HttpBaseClient({ baseUrl: "http://localhost:3000", fetch: (async (url, init) => {
      calls.push({ url: String(url), body: JSON.parse(String(init?.body)) });
      return new Response("{}", { status: 200 });
    }) as typeof fetch });
    expect(Object.keys(client.facade.verbs)).toEqual(FACADE_CATALOG.map(row => row.sdk));
    for (const row of FACADE_CATALOG) {
      await client.facade.verbs[row.sdk]({ probe: row.wire });
    }
    expect(calls).toEqual(FACADE_CATALOG.map(row => ({
      url: `http://localhost:3000/v1/core/facade/${row.wire}`, body: { probe: row.wire },
    })));
  });

  test("connected builder setters do no I/O and each run sends the complete plan once", async () => {
    const requests: unknown[] = [];
    const client = new HttpBaseClient({ baseUrl: "http://localhost:3000", fetch: (async (_url, init) => {
      requests.push(JSON.parse(String(init?.body)));
      return new Response("{\"items\":[]}");
    }) as typeof fetch });
    const query = client.query().text("launch").limit(4).view("full");
    const pack = client.contextPack().text("launch").limit(3).depth({ edge_hop: 1 }).budget({ token_budget: 512 });
    expect(requests).toHaveLength(0);
    await query.run();
    expect(requests).toEqual([{ query: "launch", limit: 4, view: "full" }]);
    await pack.run();
    expect(requests).toHaveLength(2);
    expect(requests[1]).toEqual({ query: "launch", limit: 3, depth: { edge_hop: 1 }, budget: { token_budget: 512 } });
  });

  test("embedded adapter has the identical lazy host-call contract", () => {
    const requests: unknown[] = [];
    // Host spy, not an engine emulator. Engine/connected result parity is the Rust oracle.
    const client = new FacadeClient({ call(verb, body) { requests.push({ verb, body }); return body; } });
    const query = client.query().text("launch").limit(4);
    const pack = client.contextPack().text("launch").budget({ token_budget: 512 });
    expect(requests).toHaveLength(0);
    query.run();
    pack.run();
    expect(requests).toEqual([
      { verb: "query", body: { query: "launch", limit: 4 } },
      { verb: "context_pack", body: { query: "launch", budget: { token_budget: 512 } } },
    ]);
  });
});
