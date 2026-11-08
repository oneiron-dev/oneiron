# Public registry search

`vault.skill_hubs.clawhub.search` queries a ClawHub-compatible public search API.
It uses the configured HTTP hub's origin and the documented `/api/v1/search` path.
The configured endpoint stays unchanged. This verb does not turn a static index
into a ClawHub API, or change the hub's ordinary discovery and package fetching.
The caller selects a compatible origin, such as `https://clawhub.ai`, when
configuring the HTTP hub. HTTP configuration stores the parsed URL's canonical
form, including the trailing slash of a bare origin. The adapter and the stored
source therefore bind the same endpoint; the import's exact source-binding
check is not weakened.

## Owner door and request

The server requires the same authenticated owner proof as the other hub doors.
The native typed door revalidates that owner before making the request. The HTTP
client retains the existing hub transport: no proxy, no redirects, no URL
credentials, a five-second connect timeout and a twenty-second blocking-operation timeout.
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

Search stays query-only. Use the separate explicit import door below to fetch
selected bytes; the generic static-index importer is not given a fabricated
index row from a search hit. Existing pinned Git/HTTP imports and their
publisher, hash, scan and admission gates are unchanged. SkillsMP and Skillselion
search remain open. FIX 950 is therefore PART, not fully built.

## Explicit selected import

`vault.skill_hubs.clawhub.import` takes the configured HTTP `hub`, the selected
`slug`, an explicit `publisher`, and optional provider `version` and `tag`
locators. It calls `/api/v1/download` on that hub's origin. No search result
triggers a download by itself. The owner proof is revalidated before fetching;
the native publisher admission, OSV queries, static scan, chosen fit, permission
ask and import writer remain in force. A successful import can still be a
Candidate or await the existing install permission ask; it is not an approval
from the registry.

The initial HTTP response uses the existing 32 MiB package budget by default;
`response_limit_bytes` can override that response budget. Native expanded-archive,
file, tree and Git process bounds still apply. ZIP parsing uses the existing
HTTP archive path's sixty-second deadline, measured from before the request.
That deadline is checked by the archive parser, not by each HTTP body read.
The no-proxy/no-redirect client and its five-second connect and twenty-second
blocking-operation timeouts are unchanged. Each progressing body read can get a
fresh wait, so this is not a twenty- or sixty-second whole-download guarantee. Provider failures retain status, Retry-After and body and cause no
retry or publisher admission.

Hosted ZIP bytes are parsed by the existing skill archive and frontmatter
readers. A documented `public-github` JSON handoff is read through the native
Git adapter at its full `commit` and exact subtree `path`, without checkout or
execution. Provider repository strings must resolve through the native syntax
to public HTTPS GitHub, never a local host path or another endpoint. Git uses its
existing bounds, not the initial HTTP response budget. The returned
`github_handoff` is untrusted metadata; its `archiveUrl` is not fetched and no
archive/subtree byte-equivalence is asserted. Its opaque `contentHash` is never
relabelled as a native tree hash.

Optional `expected_skill_id`, `expected_skill_version` and
`expected_content_hash` express the caller's actual selection. The last is the
native lowercase SHA-256 canonical-tree hash, not archive SHA-256, per-file
SHA-256 or a provider hash. A supplied expectation is checked on the fetched
bytes before any publisher or skill write. The provider slug/version/tag is
not guessed to be a frontmatter identity.

`outcome: "imported"` returns `entity`, `source` and optional `github_handoff`.
The source names the configured ClawHub hub, its selected slug, and the native
ContentHash of the exact tree committed through a prefetched adapter: there is
no second download between checking and importing. Without an explicit expected
native hash, this is a first-observed content identity, not proof of a prior
review or prior-pin match. Previewing and then supplying a pin is optional, not
a new consent step.

The source records the registry alias and actual tree identity, not a newly
registered Git hub or publisher identity inferred from provider metadata. A
later generic HTTP-index sync still needs a real index entry for that alias;
this explicit import does not manufacture one or change ordinary hub discovery.
