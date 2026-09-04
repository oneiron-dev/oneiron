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
   * The one dispatch point. It returns the fetch promise itself, so the
   * caller receives the very `Response` the runtime produced — same object,
   * unread body, untouched status and headers. A network failure rejects the
   * way `fetch` rejects; an HTTP error status resolves like any other.
   */
  request(path: string | URL, init: RequestInit = {}): Promise<Response> {
    const url = resolveWithinBase(this.baseUrl, path);
    const headers = mergeHeaders(this.headers, init.headers);
    return this.fetch(url, { ...init, headers });
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
