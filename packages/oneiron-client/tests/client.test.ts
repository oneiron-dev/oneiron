import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { HttpBaseClient, mergeHeaders, resolveWithinBase } from "../src/index";

const BASE_URL = "http://127.0.0.1:3000";
/** An obvious non-credential: nothing real belongs in a public repository. */
const PLACEHOLDER_SECRET = "placeholder-secret-not-a-credential";

interface Call {
  readonly input: string;
  readonly init: RequestInit | undefined;
  readonly headers: Headers;
}

function recordingFetch(response: Response | (() => never)): {
  fetch: typeof globalThis.fetch;
  calls: Call[];
} {
  const calls: Call[] = [];
  const fetch = ((input: URL | RequestInfo, init?: RequestInit) => {
    calls.push({
      input: String(input),
      init,
      headers: new Headers(init?.headers ?? {}),
    });
    if (typeof response === "function") {
      return Promise.reject(new TypeError("network unreachable"));
    }
    return Promise.resolve(response);
  }) as typeof globalThis.fetch;

  return { fetch, calls };
}

function makeClient(response: Response): {
  instance: HttpBaseClient;
  calls: Call[];
} {
  const { fetch, calls } = recordingFetch(response);
  return {
    instance: new HttpBaseClient({
      baseUrl: BASE_URL,
      secret: PLACEHOLDER_SECRET,
      fetch,
    }),
    calls,
  };
}

describe("raw response passthrough", () => {
  test("request returns the very Response the runtime produced", async () => {
    const response = new Response('{"ok":true}', {
      status: 200,
      headers: { "x-oneiron-probe": "kept" },
    });
    const { instance } = makeClient(response);

    const received = await instance.request("/api/health");

    expect(received).toBe(response);
    expect(received.bodyUsed).toBe(false);
    expect(received.headers.get("x-oneiron-probe")).toBe("kept");
    expect(await received.text()).toBe('{"ok":true}');
  });

  test("HTTP error statuses resolve untouched; only network failure rejects", async () => {
    const envelope = '{"code":"UNAUTHORIZED","message":"request is not authorized"}';
    const failure = new Response(envelope, {
      status: 401,
      headers: { "content-type": "application/json" },
    });
    const { instance } = makeClient(failure);

    const received = await instance.discover();
    expect(received).toBe(failure);
    expect(received.status).toBe(401);
    expect(received.ok).toBe(false);
    expect(await received.text()).toBe(envelope);

    const { fetch, calls } = recordingFetch(() => {
      throw new TypeError("unused");
    });
    const offline = new HttpBaseClient({ baseUrl: BASE_URL, fetch });
    await expect(offline.discover()).rejects.toBeInstanceOf(TypeError);
    expect(calls).toHaveLength(1);
  });

  test("a failed mutation is never re-sent", async () => {
    const { fetch, calls } = recordingFetch(
      new Response("upstream is unhappy", { status: 500 }),
    );
    const instance = new HttpBaseClient({
      baseUrl: BASE_URL,
      secret: PLACEHOLDER_SECRET,
      fetch,
    });

    const response = await instance.callVerb({
      verb: "board.append",
      body: { text: "placeholder" },
      idempotencyKey: "idem-1",
    });

    expect(response.status).toBe(500);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.headers.get("Idempotency-Key")).toBe("idem-1");
    expect(calls[0]?.init?.method).toBe("POST");
    expect(calls[0]?.init?.body).toBe('{"text":"placeholder"}');
  });
});

describe("url construction stays on the configured origin", () => {
  test("convenience methods build the documented routes", async () => {
    const { instance, calls } = makeClient(new Response("{}"));

    await instance.discover();
    await instance.searchText({ query: "kickoff notes", limit: 5, view: "summary" });
    await instance.getEntity("entity/42");
    await instance.callVerb({ verb: "board.append", body: {} });
    await instance.request("/api/edges/entity-1");

    expect(calls.map((call) => call.input)).toEqual([
      "http://127.0.0.1:3000/api/core/discover",
      "http://127.0.0.1:3000/api/search/text?query=kickoff+notes&limit=5&view=summary",
      "http://127.0.0.1:3000/api/entity/entity%2F42",
      "http://127.0.0.1:3000/v1/core/memory/verbs/board.append",
      "http://127.0.0.1:3000/api/edges/entity-1",
    ]);
  });

  test("a path that leaves the origin is refused before a request exists", () => {
    const baseUrl = new URL(BASE_URL);

    expect(() => resolveWithinBase(baseUrl, "https://evil.example/api/health")).toThrow(
      TypeError,
    );
    expect(() => resolveWithinBase(baseUrl, "//evil.example/api/health")).toThrow(TypeError);
    expect(resolveWithinBase(baseUrl, "/api/health").href).toBe(
      "http://127.0.0.1:3000/api/health",
    );

    const { instance, calls } = makeClient(new Response("{}"));
    expect(() => instance.request("https://evil.example/api/health")).toThrow(TypeError);
    expect(calls).toHaveLength(0);
  });
});

describe("one credential, one authority model", () => {
  test("caller headers add to the configured defaults", async () => {
    const { instance, calls } = makeClient(new Response("{}"));

    await instance.request("/api/health", { headers: { "x-trace": "abc" } });

    const sent = calls[0]?.headers;
    expect(sent?.get("authorization")).toBe(`Bearer ${PLACEHOLDER_SECRET}`);
    expect(sent?.get("x-trace")).toBe("abc");
  });

  test("a caller may not silently substitute the configured credential", () => {
    const defaults = new Headers({ Authorization: `Bearer ${PLACEHOLDER_SECRET}` });

    expect(() => mergeHeaders(defaults, { Authorization: "Bearer other-authority" })).toThrow(
      TypeError,
    );
    // Restating the SAME credential is not a substitution.
    expect(
      mergeHeaders(defaults, { Authorization: `Bearer ${PLACEHOLDER_SECRET}` }).get(
        "authorization",
      ),
    ).toBe(`Bearer ${PLACEHOLDER_SECRET}`);
    // An explicitly configured header wins over the secret shorthand.
    const explicit = new HttpBaseClient({
      baseUrl: BASE_URL,
      secret: PLACEHOLDER_SECRET,
      headers: { Authorization: "Bearer configured-by-caller" },
    });
    expect(explicit.headers.get("authorization")).toBe("Bearer configured-by-caller");
  });

  /**
   * The credential becomes ONE default header and is kept nowhere else: no
   * copy on the instance, nothing printed, and no diagnostic that quotes it.
   * (`client.headers` is the header set the caller configured, so reading the
   * credential back out of it is the caller's own doing.)
   */
  test("the credential is never logged and never echoed into a diagnostic", () => {
    const source = readFileSync(
      join(resolve(dirname(fileURLToPath(import.meta.url)), ".."), "src", "index.ts"),
      "utf8",
    );

    expect(source).not.toContain("console.");
    expect(source).not.toContain("x-oneiron-secret");

    const instance = new HttpBaseClient({
      baseUrl: BASE_URL,
      secret: PLACEHOLDER_SECRET,
    });
    expect(Object.keys(instance)).toEqual(["baseUrl", "fetch", "headers"]);
    expect(String(instance)).not.toContain(PLACEHOLDER_SECRET);
    expect(JSON.stringify({ baseUrl: instance.baseUrl })).not.toContain(PLACEHOLDER_SECRET);

    // Both refusals name the problem without quoting the credential.
    for (const failing of [
      () => instance.request("https://evil.example/api/health"),
      () => mergeHeaders(instance.headers, { Authorization: "Bearer other-authority" }),
    ]) {
      let message = "";
      try {
        failing();
      } catch (error) {
        message = String(error);
      }
      expect(message).not.toBe("");
      expect(message).not.toContain(PLACEHOLDER_SECRET);
    }
  });
});
