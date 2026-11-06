# Shared end-to-end harness

This is the shared Phase 2 support code for the 29 planned test files. It drives a real, prebuilt
server through public clients. It never imports engine crates, opens LMDB or Loro,
seeds private records, builds a binary, installs a package, or downloads an asset.
Execution is Linux-only. **Do not run Bun, Node, Python, a server, or a test on the
coordinator Mac.** Build/package preparation belongs to the fleet lane.

The public binding snapshot is main `c716fa9921692224fe46114b283993d5d81f6c8c`.
The pinned plan has 29 files, 242 IDs, 443 public registry rows, and three explicit
excluded rows. The generated HTTP SDK's inputs/results are snake_case wire DTOs.
The `oneiron` TypeScript SDK's witness and recall use camelCase DTOs, while
`vault.claims.upsert` and paged `vault.receipts` use the generated snake_case
DTOs. Bind each method's declared type rather than applying a casing rule to
all SDK methods.
Runtime OpenAPI is a binding diagnostic, never an expected-behavior oracle.

## Files and ownership

Under `/Users/olety/.claude/worktrees/solq-e2e-support/tests/e2e/`:

- `support/engine.ts`: real init/bootstrap/pair/serve, fresh roots, peers, restarts.
- `support/clients.ts`: signed HTTP, MCP JSON-RPC, WS app protocol, CLI, SDK processes.
- `support/providers.ts`: scripted external HTTP protocols, streams and barriers.
- `support/fixtures.ts`: fixture fragments, independent facts, checked archives and build pins.
- `support/run.ts`: file declarations, resource ownership, deadlines, four-slot scheduler/report.
- `fixtures/manifest.json`: shared assets and binary requirements only.
- `fixtures/suite-plan.json`: immutable planned IDs, source pins and registry coverage.
- `fixtures/observatory.md` and `fixtures/notes-bundle.zip`: tiny owner-authored corpus.
- `package.json` and `tsconfig.json`: strict Bun TypeScript project, exact dependency versions.

Each area writer owns only their test file, area data, and
`fixtures/<area>/manifest.json`. They do not edit shared helpers, shared pins, or
another area's manifest. Old unit tests are outside this suite and remain untouched. The SDK dependencies are
`file:../../packages/oneiron` and `file:../../packages/oneiron-client`, not registry
copies. The prepared JS package must already contain its built `dist/` and Linux
native addon. No lockfile was generated on the Mac.

## Declare a file and its planned IDs

Use `defineFile` once at module scope. Import Bun's `test` and `afterAll` in the
**test file**, not in a process launcher. Use `suite.test` for every planned ID;
use `suite.todo` for unavailable typed doors. Do not use `.skip`, `.only`,
`.failing`, native unregistered tests, or concurrent tests.

```ts
import { afterAll, expect, test } from "bun:test";
import { defineFile } from "./support/run.ts";
import { EngineFixture } from "./support/engine.ts";
import { loadFixtures } from "./support/fixtures.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush); // Required even when every ID is a TODO.

// Registration form (put only the IDs assigned to this file here):
// suite.test(test, "BOOT-01", "model-free restart", async () => { ... });
// suite.todo(test, "DOCUMENTS-08", "waits on <typed door or verb>");
```

Slots must match `fixtures/suite-plan.json`: one normally, two for heavy,
multi-peer, browser or organ files. All helpers and subprocesses count inside
that file's budget. A flow defaults to 30 seconds. Pass `200_000` as the last
`suite.test` argument for the actual 180-second wake case. Do not change engine
defaults to accelerate it. The optional profile runs only its six pinned IDs;
other IDs are not registered for that run and do not count as default coverage.

**G01 is binding:** if a designed verb has no current typed HTTP and SDK call,
register `suite.todo(test, ID, "waits on <door or verb>")`. Preserve canon's typed
request/result shape in the design notes beside that TODO. Do not cast the name
to `FacadeVerb`, route it through a generic endpoint, execute code instead, or
use internal state as a substitute. For G09's additional hook families, use
`"waits on owner question G09"`. A TODO is a BLOCKED report row and makes a
required run non-green. It is not passing coverage.

## EngineFixture

```ts
const engine = await EngineFixture.start({
  id: "BOOT-01", profile, peers: 0,
  policy: async fixture => {
    // Only explicitly declared owner policy calls through fixture.client/cli.
  },
});
```

`start` returns the fixture with these public members:

| Member | Contract |
| --- | --- |
| `url` | Owned loopback HTTP origin. Never attaches to an existing server. |
| `client` | Owner-paired `PublicHttpClient`; `call(verb, input)` uses the generated typed catalog. |
| `mcp` | Same actor's `McpClient`; operator surface is chosen by `surface`, default tool-first. |
| `cli` | Same actor's real CLI, credential supplied privately in its environment. |
| `pairedActor` | `{principalRef, actorClass, credential, pin, client, mcp, cli}`. Never print it. |
| `sdk` | `SdkProcessDriver` using the prepared Node package or Python venv. |
| `peers` | Additional fresh independent fixtures; no automatic sync or authority. |
| `awaitReceipt(ref, timeoutMs?)` | Public call-receipt lookup or governance receipt observation; no job drain. |
| `restart()` | Stop and re-serve only this fixture's vault, using the same credential. |
| `kill()` | SIGKILL the owned server group. First observe a public receipt/ACK/provider barrier. |
| `close({retainVault?})` | Close peers/server and remove the private root unless explicit local retention. |
| `artifacts` | Redacting JSON writer; never uploads anything. |

The fixture defaults to authenticated, model-free `init --embedder none
--oneironer none`, then documented stopped-vault `token bootstrap`, then serve
and real `Oneiron.pair`. The SDK checks a pairing link's checkpoint pin. The
harness never mints privileged records or chooses an owner principal itself.
`pairActor({principalRef, actorClass, scope?, lifetimeSeconds?})` pairs an
**already-existing** principal through the owner's real `token pair` command.
It creates no person or agent. State, grants, room membership and policy setup
must go through named public calls.

`peers: N` means N **extra** vaults and requires two scheduled slots. All receive
the declared policy callback. Establish actual peer membership through public
operations after startup. Embedded SDK paths must be absolute and separate
from the served `engine.root + "/vault"` path. Process exit releases that SDK's
writer; there is no fake embedded close implementation.

`serverConfig` contains additional **public TOML tables** (start with a table
header). For example, configure `[models.providers.fixture]` with
`kind = "local-openai-compat"`, `base_url` from `providers.urls`, a fixed
`revision`, and `request_compression = false`; bind the required
`[models.roles.<role>]` tables to their declared wire models. This does not
silently authorize inference or egress. Apply required owner policy separately.
The fixture owns host, port, vault path, issuer secret and authentication.

For the public embedding/tagger adapters, use typed options:

- `embedder: {endpoint, modelKey, modelId, dimensions, egress}`. Egress is either
  `{allowAll: true}` or `{entityIds: [...]}` and is an explicit fixture policy.
- `oneironer: {url, checkpointSha16, labelCount, mode?}`; default mode is `save`.
- `initArgs`: additional documented CLI options only, not overrides for the
  fixture-owned config/auth/model-selection fields.
- `capabilities`: required host capabilities from the prepared inventory.
- `ready(client)`: optional predicate of **public reads**, observed within 10s
  after health/pairing. Use it for the requested provider/organ readiness.
- `requireHttpDoor(path, method)`: checks non-facade endpoint bindings against
  the startup OpenAPI snapshot, refreshed only after a fixture restart. OpenAPI
  is a partial facade projection, not the facade contract. Generated facade SDK
  types and actual typed calls establish facade availability.

Readiness observations may repeat. Mutations and failed public calls are never
silently retried. A bind collision is an explicit failure, not a hidden retry.
Fresh ephemeral reservations reduce collisions; pairing proves the answering
server owns this fixture's bootstrap link.

## Request and startup diagnostics

HTTP, CLI and SDK calls persist redacted request-start records before the call,
with a step id, operation, path and start time. Completion/error records carry
that id. SDK batches also write per-operation markers inside the native process.
Fixture startup emits stage-start markers before init, bootstrap, launch, pairing
and schema discovery, including before a second vault has a launch artifact.
An unmatched request-start identifies a call that has no captured completion;
it is not a causal diagnosis. No credential, request body or SDK value is logged.
Unexpected deterministic embedding inputs are recorded with a digest and redacted
text; they still fail the strict vector fixture until explicitly authored.

## Public clients

- `client.raw<T>(method, path, body?, headers?)` returns `{status, headers, body,
  raw, bytes}` even for errors. Binary responses preserve their original bytes.
- `client.request<T>(...)` throws `PublicHttpError` for non-2xx. `.reply` retains
  status, headers and the complete server body. `.error` exposes the raw error.
- `client.call<V>(verb, input): Promise<FacadeResult<V>>` accepts only generated
  `FacadeVerb`/`FacadeInput<V>`. `202 PENDING_ASK` is not success. It throws with
  the original envelope. There is no automatic ask replay or credential renewal.
- Every protected HTTP request signs a new holder nonce over the canonical
  slip bytes. Only the holder proof is signed locally, never an engine record.
- `mcp.initialize()`, `listTools()`, `rpc(method, params)`, `request(...)`, and
  `callTool(name, arguments)` use real JSON-RPC. `rpc` keeps result/error as a
  union; `McpRpcError.response` preserves the full refusal. Tool `isError`
  results remain their actual protocol bodies. No tool-mode auto-switch occurs.
- `await engine.websocket(actor?)` opens the real `/ws`, sends binary hello
  `[3,8]`, and uses MessagePack tags 30/31. `call(verb, input)` is sequential RPC
  and returns both the decoded value and original chunk frames, including
  receipts. For subscription/multiplexing checks use `send(tag, envelope)` and
  `next(timeoutMs)`, assemble chunks before ACK, and retain binary cursors.
  The client does not interpret CRDT storage or negotiate private sync state.
- `cli.run(args, stdin?, timeoutMs?, privateOutput?)` retains stdout, stderr,
  exit code and signal. `cli.json` and typed `cli.call` throw `CliError.result`
  on nonzero exit. Pass secret data through stdin, never argv.
- `sdk.run("typescript" | "napi", target, operations)` runs public `Oneiron` in
  the actual Node host. `sdk.run("python", target, operations)` uses Python's
  installed wheel. Targets are `{mode:"remote",url,credential}` or
  `{mode:"embedded",path,dimensions?}`. Operations are typed `witness`,
  `claimUpsert`, `recall`, `receipts`; Python inputs are native snake_case.
  Per-operation `{ok:false,error}` retains SDK errors; assert them explicitly.
  Broader SDK journeys may use an owned real process and the public package,
  never a private binding or Rust helper. `sdk.pair(link)` redeems through the
  public JS SDK, including checkpoint verification.

## ScriptedProviders

`await ScriptedProviders.start({id, steps, artifacts?})` returns
`{urls, releaseBarrier, seenFixtureCalls, close}` plus `awaitBarrier`.
Each origin gets an ephemeral loopback listener, with its own ordered script.
A step declares `id`, `origin`, `role`, `purpose`, a real protocol `request`, and
an exact `response`. Roles/purposes are scenario metadata: the harness never
pretends the wire carries them. Use separate origins to distinguish roles
when the production adapter does not send such a field.

`request` contains method, path, optional wire model and a subset of public
protocol fields. Never match exact engine-generated prompts. `response` is
`{kind:"json",body,status?,headers?}`, `{kind:"bytes",body,contentType,status?}`,
or `{kind:"stream",contentType,parts,status?}`. Stream parts have fixture-owned
IDs, exact bytes and optional barriers. Scripted HTTP errors use real vendor
error bodies and statuses. The helpers `openaiText`, `openaiStream`,
`anthropicText`, `anthropicStream` and `embeddingReply` require declared usage;
they do not estimate tokens or derive answers from requests.

A step or stream part may name a barrier. `awaitBarrier(name)` waits until the
external adapter reaches it; `releaseBarrier(name)` releases that boundary.
It does **not** claim an internal transaction committed. Early release works.
`seenFixtureCalls` is an in-memory snapshot of sequence, body, fixture ID, role
and purpose. Unexpected, extra or unconsumed calls fail `close` and the flow.
There is no catch-all fallback. Exact JSON/bytes fixtures cover HTTP
Oneironer/media/connectors. Optional `sockets` scripts declare `id`, `origin`,
`path`, `role`, `purpose`, and ordered `exchanges` of `{request,replies}`. Each
request is public JSON or binary audio; replies are exact `StreamPart` frames
with optional barriers. Use a `ws:` URL made from the returned HTTP origin for
an ASR/connector WebSocket adapter. Socket upgrades, messages and unconsumed
exchanges are checked, not emulated as HTTP responses. App WS is supported by
`WsClient`. No browser is started by these helpers.

## Area fixture fragments

`await loadFixtures()` recursively loads **every** area manifest. IDs must be
globally unique. Every non-manifest file under `fixtures/` must be listed and
SHA-256 checked; unpinned/unlisted files, escaping paths and digest mismatches
block preflight. `catalog.fixture<T>(id)` returns metadata,
`expected<T>(id)` returns authored facts, `readJson<T>(id)` loads JSON,
`readArchive(id)` returns verified bytes, and `scenarioFixtures(ID)` lists data
for a public user task. The loader does not extract an archive or seed a vault.

Each fragment has this shape (replace every illustrative value):

```json
{
  "version": 1,
  "area": "calendar",
  "assets": [{
    "id": "calendar-known-occurrences",
    "path": "known-occurrences.json",
    "source": {"uri": "independent-oracle:documented-source", "revision": "immutable-revision"},
    "licence": "SPDX-or-explicit-redistribution-terms",
    "sha256": "64-lowercase-hex-characters-required",
    "expectedFacts": {"explanation": "independent facts, never engine output"},
    "scenarios": ["CALENDAR-01"],
    "requires": []
  }]
}
```

The small shared ZIP is a notes corpus, **not** a fabricated vault export. G02's
one true full-vault export must be obtained from the public engine export door
and checked against independent fixture facts. It is not JSON invented by a
helper. Add a licensed independent Office oracle before claiming Office
fidelity; no Linux stub supplies that proof.

## Prepared build inventory and preflight

The binary bytes do not exist in this source-only writer lane. Do not invent
hashes. The fleet build/asset lane must supply an **absolute**
`E2E_BUILD_MANIFEST` and its independently supplied
`E2E_BUILD_MANIFEST_SHA256`. Preflight verifies that digest, every listed asset,
all fixture fragments, common runtime capabilities, same-build provenance, and
the selected test files. Missing common pins block all selected IDs; optional
client assets block only the cases that need them. There is no build/download
fallback. Fixture `requires` lists document planned public prerequisites; they
are not host capabilities. Tests use typed public calls, explicit capability
gates, or TODOs to report unavailable journeys. The checked-in shared manifest declares binary requirements, not
placeholder executable digests that could accidentally pass.

`BuildManifest` is exported from `support/fixtures.ts`. It requires:

- `version: 1`, `head` (40-hex engine commit), `profile`.
- `assets`: mapping from ID to `{path,sha256,source:{uri,revision},licence,expectedFacts}`.
  Paths are absolute **files**, not directories. Include each loaded SDK/native
  file and organ dependency in the inventory, not just a directory hash.
- Common required IDs: `server`, `cli`, `bun`, `node`, `sdk-js`, `native-addon`.
  `sdk-js` points to the prepared package's public `dist/index.js`; that package
  loads its native addon even for remote pairing. Add `python` (the prepared
  venv interpreter) and `python-wheel` for Python cases. Pin the installed Python extension as an additional
  asset as well as the wheel. Include `sdk-http` if a case consumes it. Add every
  required organ/browser/VM executable and data file with a source, licence and
  digest. Every supplied asset is verified, even when its client is optional.
- `launcher`: argv prefix with an absolute, hash-listed Linux executable that
  execs the appended command without shell interpolation. On the fleet this can
  be `/usr/bin/env`: the fleet job is already the sandbox (Engine, 5 Nov 02:51).
  Do not add `sudo`, `unshare`, user namespaces or a nested cgroup. The fleet
  enforces the booking's resource limits; the scheduler accounts for file slots
  and passes `E2E_FILE_SLOTS`, `E2E_CPU_CREDITS`, and `E2E_MEMORY_MIB`. These are
  accounting values, not additional per-file kernel limits. Ownership-journal
  PIDs remain visible for cleanup. This mode does not claim network isolation.
- `capabilities` includes `linux`, `fleet-job`, `slot-accounting`
  plus runtime prerequisites explicitly checked by a selected scenario.
- `environment`: prepared non-secret runtime paths/settings. HOME, XDG, TMP,
  locale, TZ and thread limits are fixture-owned. Inherited `ONEIRON_*` values
  are not carried into an engine. Generated credentials are private per flow.
- For `real-small-model`: `realModel` includes immutable `revision`, `weights`
  (asset IDs), `tokenizer`/`config` (asset IDs), `quantization`, `threads`,
  `sampling`, and explicit role-to-`real`/`stub` `bindings`. It must have a real
  binding; missing weights/config/tokenizer blocks rather than changing models.

The package pins Bun 1.3.4, Node 22.16.0 and Python 3.12.11 as reference runtime
revisions in the inventory requirements. Other dependency pins are in
`package.json`. Preparation and any typecheck/install happen on Linux, never
implicitly in the runner.

Run on the prepared Linux host only, with `CHECKOUT` set to its actual checkout:

```sh
bun "$CHECKOUT/tests/e2e/support/run.ts" --profile deterministic --workers 4
```

`E2E_REPORT_DIR` optionally selects a protected absolute output directory.
Otherwise the runner allocates one. The scheduler uses longest-estimated-file
first, ties by name, with up to four slots and two CPU credits/4 GiB per slot.
The default reference total is 8 threads and 16 GiB. `--workers` accepts one
through four slots and must fit the heaviest selected file.

For wave 1 on a four-thread fleet booking, select the four files explicitly and
use two slots (four CPU credits):

```sh
bun "$CHECKOUT/tests/e2e/support/run.ts" --profile deterministic --workers 2 \
  --files boot.test.ts,memory.test.ts,retrieval.test.ts,privacy.test.ts
```

The report records the selected files and `scope.completePlan`. A partial run
never claims completion of the 242-ID plan. The prepared manifest must identify
the booked fleet job; never run the suite outside that job or on the Mac.

## Reports, cleanup and redaction

Every selected planned ID gets PASS, FAIL or BLOCKED, duration and a reason
where needed. Coverage includes the pinned row map and explicit exclusions. A
run succeeds only if all selected IDs pass, file declarations/IDs match the
plan, each PASS agrees with Bun's JUnit, and the whole run (including preflight
and cleanup) stays within 600 seconds. A TODO or failing test keeps that run
non-green but does not turn an independently passing sibling into FAIL. Full
plan completion additionally requires all 242 IDs. Partial and optional-profile
results never claim default completeness. The 585-second planning
estimate has not been measured.

Bun 1.3.4 writes JUnit to a real per-file `.junit.xml` outfile under the protected
report directory. The runner reads that file and checks it against registered IDs;
subprocess stdout is not a JUnit outfile. A separate `.junit.json` artifact carries a
redacted XML copy for export. The original XML stays local to the fleet job. Owned file
process artifacts retain bounded, redacted stdout/stderr separately. `fileDiagnostics`
in the aggregate records JUnit presence, case/match/unknown/duplicate counts, file
exit/signal, and registration errors. A harness error remains a FAIL but does not replace an existing
per-file reason; it is recorded separately as `harnessError`. Wrapper cleanup errors are
recorded separately as `cleanupError`, preserving an earlier reason.

Persisted artifacts are redacted first. Credential-bearing private stdout remains withheld.
Private stderr is retained only as decoded JSON with its fields redacted before serialization;
non-JSON private stderr is withheld. This also redacts registered values containing quotes
that were escaped in an SDK error envelope. CLI/SDK errors identify a static setup/operation stage and exit/signal without printing argv,
stdin or credentials. SDK top-level failures also write their error envelope to stderr for
redaction and diagnosis. Stderr diagnostics additionally remove long hexadecimal values. Any truncated stdout/stderr
stream is withheld entirely, with a truncation flag, because a cut secret fragment cannot be
reliably redacted by matching the original full value.
Bun receives a redacted error message rather than raw exception properties, so its JUnit
cannot inspect a failing CLI's private stdout. Process logs are bounded rings; incomplete
lines are not persisted before redaction. Call `redactor.add(secretOrSentinel)` **before** any
operation carrying a generated secret-test value. Never log credentials, raw
SDK process output, pairing links, or recognisable secret sentinels. Use
`artifacts.json(name, value)` rather than direct log files. HTTP automatic logs
contain routing/status metadata only; explicitly save sanitized bodies and
public receipt IDs when they matter to a failure.

Providers, sockets and engines register end-of-flow cleanup automatically.
`ownResource(close)` covers additional fixture services; `ManagedProcess` and
`runProcess` own real subprocess groups and journal group IDs for the scheduler.
On failure/deadline/interruption the runner kills owned groups, including groups
left by an exited file process. Temp vaults are removed unless a test explicitly
calls `engine.close({retainVault:true})`; retained private roots stay local,
are listed in a redacted retention artifact, and are never uploaded.

No engine constants changed. Harness constants are 10s health/readiness and
normal request bounds, 30s normal flow budget, 2s stop grace, 25ms bounded
public-observation cadence, four slots, two CPU credits and 4 GiB per slot,
and 600s whole-suite deadline. They are not new product laws. Zero automatic
mutation retries, zero model downloads, no private clocks or queue ticks.

Builds, typechecking and suite execution run only on fleet Linux hosts. Nothing
in this suite is built or executed on the coordinator Mac. Engine bugs found by
an E2E case are filed as FIX-LIST rows; they do not hold the suite PR.
