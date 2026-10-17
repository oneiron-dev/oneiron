/**
 * `@oneiron/client` — the one thin typed client for the Oneiron API.
 *
 * The verb table (`scripts/sdk/agent-verbs.json`) is the contract; this
 * package is convenience over it and never a second one. Its facade is
 * GENERATED from that table (`./facade.ts`, `./facade-types.ts`): every verb
 * a typed method at its SDK path, its input and result typed from the Rust
 * types its row names, its row metadata in `FACADE_CATALOG`. What is written
 * by hand is this file: the HTTP transport.
 *
 * Every public method hands back the ORIGINAL `Response`: nothing here parses
 * a body, clones a response, throws on an HTTP status, buffers a stream,
 * re-sends a mutation, or caches a result. An HTTP error is therefore
 * something the caller reads off the wire — status, headers, request id, and
 * the server's own error envelope all survive — rather than something this
 * layer has interpreted. `FacadeResult<V>` types what a 2xx body reads as.
 * One answer is read here (OF-580): a facade call a verb hook stopped on an
 * ask, `202 PENDING_ASK`, resolves to a typed `FacadePending` carrying the
 * call's invocation id and the envelope, and `retry` resends that call under
 * the same id only when the caller asks.
 *
 * The one thing it does NOT delegate to the runtime is redirect following.
 * A client carrying a bearer credential cannot let `fetch` chase a `Location`
 * to wherever it points, so each hop is taken by hand and re-checked against
 * the configured origin.
 *
 * One artifact serves three consumers (ARCH-0028): `facadeTree` takes an
 * injected invocation transport, so this HTTP adapter, a native adapter over
 * an in-process binding and the code-mode inject share one typed tree and one
 * catalog. Only the transport differs; `@oneiron/client/facade` is the tree
 * without this fetch client.
 */

import { facadeTree } from "./facade.js";
import type { FacadeErrorEnvelope, FacadeInput, FacadePending, FacadeVerb } from "./facade.js";
export { FACADE_CATALOG, FACADE_VERBS, facadeRetry, facadeTree, newInvocation } from "./facade.js";
export type {
  FacadeErrorEnvelope,
  FacadeHookStop,
  FacadeInput,
  FacadeInputs,
  FacadePending,
  FacadeResult,
  FacadeResults,
  FacadeReturn,
  FacadeReturns,
  FacadeTransport,
  FacadeTree,
  FacadeVerb,
  FacadeVerbMeta,
} from "./facade.js";
export type * as Facade from "./facade-types.js";

export interface HttpBaseClientOptions {
  /** Origin of an existing Oneiron server, e.g. `http://127.0.0.1:9090`. */
  readonly baseUrl: string | URL;
  /** Bearer credential. It becomes one default header and is stored nowhere else. */
  readonly secret?: string;
  /** Injected fetch, for runtimes that supply their own (tests, workers). */
  readonly fetch?: typeof globalThis.fetch;
  /** Additional default headers, merged additively into every request. */
  readonly headers?: HeadersInit;
}

export interface SearchTextRequest {
  readonly query: string;
  readonly limit?: number;
  readonly view?: "summary" | "standard" | "full";
}

export interface CallVerbRequest {
  readonly verb: string;
  readonly body: unknown;
  readonly idempotencyKey?: string;
}

/**
 * Resolve `path` against `baseUrl` and refuse anything that leaves the
 * configured origin. A client is scoped to one server: an absolute URL or a
 * protocol-relative path that points elsewhere is a bug, not a redirect.
 */
export function resolveWithinBase(baseUrl: URL, path: string | URL): URL {
  const resolved = new URL(path instanceof URL ? path.href : path, baseUrl);
  if (resolved.origin !== baseUrl.origin) {
    throw new TypeError(
      `refusing a request that leaves the configured origin: ${resolved.origin} is not ${baseUrl.origin}`,
    );
  }
  return resolved;
}

/**
 * The statuses `fetch` would follow on its own. This client follows them by
 * hand instead, because the runtime's follower would carry the configured
 * `Authorization` header to whatever host a `Location` named — and a client
 * scoped to one server has no business presenting its credential to another.
 */
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

/** Enough hops for a server that canonicalizes; few enough that a loop ends. */
const MAX_REDIRECTS = 5;

/**
 * Names the logical verb call a facade request is (ARCH-0080 §3): 32 lowercase
 * hex digits. Its verb hooks fire once for it, and a retry of a call a hook
 * stopped on an ask names the same one to find that ask.
 */
const INVOCATION_HEADER = "x-oneiron-invocation";

/**
 * What a redirect leaves of the request, per the fetch redirect rules: `303`
 * turns any non-GET/HEAD into a bodyless `GET`, `301`/`302` do the same to a
 * `POST`, and `307`/`308` preserve method and body exactly. The body headers
 * go with the body they described.
 */
function redirectedInit(init: RequestInit, status: number): RequestInit {
  const method = (init.method ?? "GET").toUpperCase();
  const rewritesToGet =
    status === 303
      ? method !== "GET" && method !== "HEAD"
      : (status === 301 || status === 302) && method === "POST";
  if (!rewritesToGet) {
    return init;
  }

  const headers = new Headers(init.headers ?? {});
  headers.delete("content-type");
  headers.delete("content-length");
  // The body is DROPPED by omission, not by an explicit `undefined`: the
  // request that goes on carries no trace of the one that was redirected.
  const { body: _redirected, ...withoutBody } = init;
  return { ...withoutBody, method: "GET", headers };
}

/**
 * The pending policy (OF-580): which facade answer becomes a `FacadePending`.
 * Only a `202` is read, through a clone, and only a body that is the server's
 * `PENDING_ASK` envelope with a pending hook naming its invocation and ask
 * counts; the retry id is the one that hook names. It resolves to `null` for
 * every other answer, a `202` that is no pending ask included, and the
 * caller gets the original `Response`, unread. A pending's original body is
 * cancelled: the clone has been read.
 */
async function facadePending<V extends FacadeVerb>(
  verb: V,
  input: FacadeInput<V>,
  response: Response,
): Promise<FacadePending<V> | null> {
  if (response.status !== 202) {
    return null;
  }
  const envelope = (await response
    .clone()
    .json()
    .catch(() => null)) as FacadeErrorEnvelope | null;
  const hook = envelope?.error?.hook;
  if (
    envelope === null ||
    envelope.error?.code !== "PENDING_ASK" ||
    hook?.status !== "pending" ||
    typeof hook.invocation !== "string" ||
    typeof hook.ask !== "string"
  ) {
    return null;
  }
  await response.body?.cancel().catch(() => undefined);
  return { kind: "pending", verb, input, invocation: hook.invocation, ask: hook.ask, envelope };
}

/**
 * Caller headers ADD to the configured defaults. They may not silently swap
 * the configured credential for a different one: one credential, one
 * authority model, and a substitution is loud rather than quiet.
 */
export function mergeHeaders(defaults: Headers, extra?: HeadersInit): Headers {
  const merged = new Headers(defaults);
  if (extra === undefined) {
    return merged;
  }

  new Headers(extra).forEach((value, name) => {
    if (
      name.toLowerCase() === "authorization" &&
      defaults.has("authorization") &&
      defaults.get("authorization") !== value
    ) {
      throw new TypeError(
        "refusing to replace the configured Authorization header with a second authority model",
      );
    }
    merged.set(name, value);
  });

  return merged;
}

export class HttpBaseClient {
  /**
   * Every facade verb at its SDK path, as `POST /v1/core/facade/<verb>`:
   * `client.facade.vault.recall({ query: "..." }, init)`. Each call goes out
   * under a fresh `x-oneiron-invocation` and returns the original `Response`,
   * or a `FacadePending` when a verb hook stopped it on an ask;
   * `FacadeResult<"vault.recall">` types its 2xx body.
   */
  readonly facade = facadeTree<"response", RequestInit>((verb, input, init, invocation) =>
    this.facadeCall(verb, input, init ?? {}, invocation),
  );

  readonly baseUrl: URL;
  readonly fetch: typeof globalThis.fetch;
  readonly headers: Headers;

  constructor(options: HttpBaseClientOptions) {
    this.baseUrl = new URL(
      options.baseUrl instanceof URL ? options.baseUrl.href : options.baseUrl,
    );
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);

    const headers = new Headers(options.headers ?? {});
    if (options.secret !== undefined && !headers.has("authorization")) {
      headers.set("Authorization", `Bearer ${options.secret}`);
    }
    this.headers = headers;
  }

  /**
   * The one dispatch point. The caller receives the very `Response` the
   * runtime produced — same object, unread body, untouched status and headers.
   * A network failure rejects the way `fetch` rejects; an HTTP error status
   * resolves like any other. The origin check happens before any request
   * exists, so a path that leaves the origin throws synchronously.
   */
  request(path: string | URL, init: RequestInit = {}): Promise<Response> {
    const url = resolveWithinBase(this.baseUrl, path);
    const headers = mergeHeaders(this.headers, init.headers);
    return this.send(url, { ...init, headers, redirect: "manual" });
  }

  /**
   * One hop at a time. `redirect: "manual"` hands the 3xx back instead of
   * chasing it, so its `Location` is resolved against the URL that produced it
   * and then re-checked against the configured origin: a redirect that leaves
   * the origin THROWS, and nothing — least of all the credential — is sent to
   * the foreign host. The terminal response is returned exactly as the runtime
   * produced it, unread and uncloned.
   *
   * The return type is inferred rather than written: it is a promise of that
   * same raw `Response` either way, and leaving it unwritten keeps the written
   * annotation where the passthrough contract actually belongs — once on each
   * PUBLIC method, which is the surface callers hold and the surface the
   * packaging oracle counts. This is a private hop loop, not a sixth entry
   * point, and `request` still declares the contract it returns.
   */
  private async send(url: URL, init: RequestInit) {
    let current = url;
    let request = init;

    for (let hop = 0; ; hop += 1) {
      const response = await this.fetch(current, request);
      const location = REDIRECT_STATUSES.has(response.status)
        ? response.headers.get("location")
        : null;
      if (location === null) {
        return response;
      }
      if (hop >= MAX_REDIRECTS) {
        throw new TypeError(
          `refusing to follow more than ${MAX_REDIRECTS} redirects from ${current.href}`,
        );
      }

      current = resolveWithinBase(this.baseUrl, new URL(location, current));
      request = redirectedInit(request, response.status);
    }
  }

  /**
   * Retries the call `pending` names: `POST`s its verb and input again under
   * its own `x-oneiron-invocation`, so the server finds the ask it stopped on
   * rather than opening a second one. While the ask is open it answers the same
   * pending; once the ask is answered proceed, the saved call runs once. Run
   * one retry of a pending call at a time.
   */
  retry<V extends FacadeVerb>(
    pending: FacadePending<V>,
    init: RequestInit = {},
  ): Promise<Response | FacadePending<V>> {
    return this.facadeCall(pending.verb, pending.input, init, pending.invocation);
  }

  /**
   * One facade call under `invocation`: the original `Response`, or the
   * `FacadePending` that `facadePending` reads off a `202`.
   */
  private async facadeCall<V extends FacadeVerb>(
    verb: V,
    input: FacadeInput<V>,
    init: RequestInit,
    invocation: string,
  ): Promise<Response | FacadePending<V>> {
    const headers = new Headers(init.headers ?? {});
    headers.set("Content-Type", "application/json");
    headers.set(INVOCATION_HEADER, invocation);
    const response = await this.request(`/v1/core/facade/${encodeURIComponent(verb)}`, {
      ...init, method: "POST", headers, body: JSON.stringify(input),
    });
    return (await facadePending(verb, input, response)) ?? response;
  }

  /** `GET /api/core/discover` — vault capability bootstrap. */
  discover(init: RequestInit = {}): Promise<Response> {
    return this.request("/api/core/discover", init);
  }

  /** `GET /api/search/text` — BM25 text search. */
  searchText(request: SearchTextRequest, init: RequestInit = {}): Promise<Response> {
    const url = new URL("/api/search/text", this.baseUrl);
    url.searchParams.set("query", request.query);
    if (request.limit !== undefined) {
      url.searchParams.set("limit", String(request.limit));
    }
    if (request.view !== undefined) {
      url.searchParams.set("view", request.view);
    }
    return this.request(url, init);
  }

  /** `GET /api/entity/{id}` — read one entity. */
  getEntity(entityId: string, init: RequestInit = {}): Promise<Response> {
    return this.request(`/api/entity/${encodeURIComponent(entityId)}`, init);
  }

  /**
   * `POST /v1/core/memory/verbs/{verb}` — one typed verb call. The body is
   * serialized on the way OUT; nothing is deserialized on the way back.
   */
  callVerb(request: CallVerbRequest, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers ?? {});
    if (!headers.has("content-type")) {
      headers.set("Content-Type", "application/json");
    }
    if (request.idempotencyKey !== undefined) {
      headers.set("Idempotency-Key", request.idempotencyKey);
    }

    return this.request(`/v1/core/memory/verbs/${encodeURIComponent(request.verb)}`, {
      ...init,
      method: "POST",
      headers,
      body: JSON.stringify(request.body),
    });
  }
}
