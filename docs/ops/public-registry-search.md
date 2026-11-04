# Public registry search

`vault.skill_hubs.clawhub.search` queries a ClawHub-compatible public search API.
It uses the configured HTTP hub's origin and the documented `/api/v1/search` path.
The configured endpoint stays unchanged. This verb does not turn a static index
into a ClawHub API, or change the hub's ordinary discovery and package fetching.
The caller selects a compatible origin, such as `https://clawhub.ai`, when
configuring the HTTP hub.

## Owner door and request

The server requires the same authenticated owner proof as the other hub doors.
The native typed door revalidates that owner before making the request. The HTTP
client retains the existing hub transport: no proxy, no redirects, no URL
credentials, a five-second connect timeout and a twenty-second total timeout.
No token is required for the public provider API.

The request names `hub` and `q`. It sends `q` verbatim, with URL query encoding.
Optional `limit`, `highlighted_only` and `non_suspicious_only` are sent only when
provided. Neither filter defaults to true. The client adds no exact-search mode,
result limit, retries, sleeps, local quota or local rate cap.

`response_limit_bytes` controls the local response byte budget. When omitted it
uses the existing HTTP index budget of 2 MiB. The caller can override it; it is
not sent to the provider. Requests do not modify any hub record or installed
skill.

## What the answer means

`outcome: "results"` contains the provider's optional `results` list. A missing
list stays `null`, not an asserted empty list. The hit's optional score, slug,
display name, summary, version, update time and owner metadata stay optional.
There is no synthesized slug, version, content hash, cursor or package row.

`outcome: "provider_error"` contains the HTTP `status`, the raw `retry_after`
header when present and the provider's text `body`. It is not a successful empty
search. Transport, invalid JSON and response-budget failures remain typed engine
errors. No failure schedules a second request.

## Query-only boundary

Search metadata is untrusted provider information. A slug and version are
provider locators, not a pinned `HubRef`, verified bytes, an installed skill or
an admission receipt. Querying does not download, scan, install, trust, activate
or bind a package or hook.

Digest-pinned selected fetch for ClawHub remains open. The download API may
return ZIP bytes or a public-GitHub handoff; this search door does not pretend
the generic static-index importer understands either from a search hit.
Existing pinned Git/HTTP imports and their publisher, hash, scan and admission
gates are unchanged. SkillsMP and Skillselion search remain open. FIX 950 is
therefore PART, not fully built.
