# @oneiron/client

One hand-written thin HTTP client for the Oneiron API. It is the second lane of
the packaging ladder — the lane for agents and apps that can install one
package — and it exists to save typing, never to become the contract.

The REST API and its OpenAPI document are the contract. This package is a small
fetch wrapper over that contract: it builds URLs and default headers, and it
hands back the raw `Response`.

## Install

```bash
npm install @oneiron/client   # or: bun add @oneiron/client
```

Source-direct and dependency-free: `main`, `types`, and the `exports` map all
resolve to `./src/index.ts`. There is no build step, no generated directory, and
no code generator anywhere in this package.

## Use

```ts
import { HttpBaseClient } from "@oneiron/client";

const client = new HttpBaseClient({
  baseUrl: "http://127.0.0.1:3000",
  secret: process.env.ONEIRON_SECRET, // placeholder credential from the environment
});

const response = await client.discover();
if (!response.ok) {
  // The server's own error envelope, verbatim: status, headers, and body.
  console.error(response.status, await response.text());
}
```

`request`, `discover`, `searchText`, `getEntity`, and `callVerb` all return
`Promise<Response>`. Any route the convenience methods do not cover is one
`client.request(path, init)` away.

## What this client will not do

* It does not parse a response body, clone a response, or throw on an HTTP
  status. `4xx` and `5xx` resolve like any other response; only a network
  failure rejects, exactly as `fetch` rejects.
* It does not re-send a mutation, cache a result, or iterate pages behind your
  back, so wire metadata is never hidden.
* It does not add an endpoint, a second authority model, or a second request
  envelope. Caller headers merge additively, and swapping the configured
  `Authorization` header for a different credential is refused loudly.
* It never logs the credential. The secret becomes one default header and is
  stored nowhere else.

## Consumers

Three consumers share one wire contract; two of them share this artifact.

1. **Code mode** — the sandbox keeps the host dispatcher it already has. It
   speaks the same wire and does **not** import this package; there is no
   injector here to bind an HTTP client into a sandbox.
2. **Native TypeScript worker** — imports `HttpBaseClient` from this package.
3. **npm-capable external agent** — installs the published package and imports
   it through the same public `exports` map.

`tests/consumers.test.ts` proves consumers 2 and 3 resolve the same package root
and the same `HttpBaseClient` implementation: one artifact, not a fork per
consumer.

## Development

```bash
bun install --frozen-lockfile
bun run check   # tsc --noEmit && bun test
```

Examples in this repository use placeholder localhost URLs and placeholder
credentials only.
