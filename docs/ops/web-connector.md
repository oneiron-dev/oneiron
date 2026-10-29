# The built-in web connector

`connector.web.search(query)` and `connector.web.fetch(url)` search the public web and read one
page. Code mode, the MCP gateway and the HTTP facade all reach them as `connector.call` with the
connector name `web`. No pack, MCP server or connector key is needed.

## The deploy's key

By default every vault's web calls run on Tavily basic search and basic extraction, on the
deploy's backend key. Set it in the server's environment:

```sh
TAVILY_API_KEY=...   # ours comes from skate: tavily-api
```

The engine reads it at each call and never logs it. Without it, a web call answers `refused` with
`web_provider_key_missing`. Only Tavily runs on the backend key: its terms allow an embedded
product (research-1120, CONN-1 A).

## The owner's switch

`vault.settings.web_connector.replace` picks the provider and whose key pays:

```json
{ "provider": "exa", "key": { "kind": "secret", "name": "exa-api" } }
```

- `provider`: `tavily`, `exa`, `brave`, `tinyfish`, `context_dev` or `octen`.
- `key.kind`:
  - `backend`: the deploy's key (Tavily only).
  - `secret`: the owner's own key, a custody secret by name. Bind it to the effector
    `connector:web`.
  - `hub`: an installed hub connector that serves the same `search` and `fetch` tools on its
    own key, under its own grant.

`vault.settings.web_connector` reads the switch. Brave has no page reader, so its `fetch` reads
the page through the server's own guarded reader. The connector itself keeps no copy of any
provider's results.

## Results

- `search` takes a string or `{query, max_results}` (default 5, at most 10). It returns
  `{provider, results: [{title, url, snippet}], latency_ms, cost_usd}`, the same shape as
  Afterglow's `search_web`. A snippet is at most 300 characters.
- `fetch` takes a string or `{url}`. It returns `{provider, url, title, content, latency_ms,
  cost_usd}`, with at most 50,000 characters of content.
- A provider failure answers as a tool error (`is_error: true`) with `{provider, error: {status,
  message}}`.

## Usage

Every call writes one usage row: provider, tool, key source (`backend`, `user` or `hub`), latency,
cost, cost basis and outcome. The cost basis is `actual` when the provider reports the cost
(Tavily credits, Exa `costDollars`), `estimated` from the provider's declared price, or
`unpriced`. A row also keeps the provider's request id when the response names one. A row never
holds the query, the URL or the results. `vault.connectors.web.usage {since_ms, limit}` reads the
rows newest first, with their summed cost.
