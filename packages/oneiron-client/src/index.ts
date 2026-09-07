/**
 * `@oneiron/client` — one hand-written thin HTTP client for the Oneiron API.
 *
 * The REST API and its OpenAPI document are the contract; this package is
 * convenience over that contract and never a second one. Every public method
 * hands back the ORIGINAL `Response`: nothing here parses a body, clones a
 * response, throws on an HTTP status, buffers a stream, re-sends a mutation,
 * or caches a result. An HTTP error is therefore something the caller reads
 * off the wire — status, headers, request id, and the server's own error
 * envelope all survive — rather than something this layer has interpreted.
 *
 * The one thing it does NOT delegate to the runtime is redirect following.
 * A client carrying a bearer credential cannot let `fetch` chase a `Location`
 * to wherever it points, so each hop is taken by hand and re-checked against
 * the configured origin.
 *
 * There is deliberately no code-mode injector here. The sandbox keeps the
 * host dispatcher it already has, and shares the WIRE with this package
 * rather than the artifact; the importers of this package are the native
 * TypeScript worker and npm-capable external agents.
 */

export interface HttpBaseClientOptions {
  /** Origin of an existing Oneiron server, e.g. `http://127.0.0.1:3000`. */
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
