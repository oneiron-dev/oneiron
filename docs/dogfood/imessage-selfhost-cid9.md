# ONE-1513 — iMessage self-host bridge dogfood evidence

## Verdict

Partial spike completion. The two tracked deliverables are landed and validated:

- `crates/oneiron/examples/provision_imessage_identity.rs` — the operator
  provisioning door, compiled and exercised end-to-end against a throwaway
  vault on 2026-08-10 (see `## Provisioned ChannelIdentity` and
  `## Evidence index`).
- This notes document, containing the captured ONE-1259 schema digest and the
  declined `BridgeLinePolicy` result.

The live dogfood run is **PARKED**: the Mac mini host, the dedicated Apple ID,
and the dedicated-line owner grant were not available in this environment.
Per the spike contract, sections whose inputs require those prerequisites are
marked `PARKED (<missing input>)` rather than filled with invented
measurements. The `BridgeLinePolicy` lift is the declined block; nothing in
here is a measured Apple limit.

## Run metadata and version pins

Pickup-time pins recorded against the dispatch base:

| pin | value |
|---|---|
| dispatch base commit | `049cde369ca6ed8e905cb3eb044c64cea277667f` |
| dispatch base carries ONE-1259 route | yes — `crates/oneiron-server/src/api/surface_events.rs` present, serving `POST /v1/core/surface-events` |
| pickup-recorded bridge package | `@photon-ai/imessage-kit` **3.0.0** (read-only pickup record from the canonical checkout's `packages/imessage-bridge/node_modules/@photon-ai/imessage-kit/package.json`; matches the blueprint's in-tree statement) |
| notes capture date | 2026-08-10 |
| provisioning-example validation host timezone | JST (UTC+9); validation timestamps below recorded in UTC |
| provisioning-example validation host | macOS 27.0 (build 26A5368g), `rustc 1.96.0 (ac68faa20 2026-05-25)`, `cargo 1.96.0 (30a34c682 2026-05-25)` — this is the example-validation machine, **not** the dogfood host |

PARKED (live-run pins requiring ops prerequisites, recorded here as named
placeholders so the run captures them in one pass):

- Mac mini machine alias, macOS build, Messages build — PARKED (Mac mini
  unavailable).
- Bun version and Node compatibility version — PARKED (host workspace not
  created).
- Exact `imessage-kit` `name@version` import surface at host pickup — the
  pickup record above (3.0.0) must be re-confirmed on the host at workspace
  install; this blueprint deliberately does not guess upstream symbol names.
- Run timezone of the dogfood window — PARKED.

## Engine endpoint and credential configuration

PARKED (engine base URL not yet assigned to a host run).

The live run contract, recorded here so the parked state is unambiguous:

- Engine base URL: to be supplied to the host process through an environment
  variable or a Keychain-backed config entry. Value never enters source,
  command output, screenshots, or this file.
- Core write credential (admission) and core read credential (receipt
  lookup): same custody rule — configuration location named, values omitted.
- No credential value appears in this document; none was generated or used
  during the parked phase.
- Inbound observations enter only through the merged ONE-1259 route
  `POST /v1/core/surface-events`; this spike creates no parallel ingress.

## Provisioned ChannelIdentity

Provisioning command (run contract):

```bash
cargo run --example provision_imessage_identity -- <vault> <handle> <agent-ref>
```

`<agent-ref>` is the 32-hex `EntityId` of an agent that must already exist in
the vault. The example rejects missing/blank arguments, rejects a malformed
agent ref before any vault I/O, refuses a path whose `data.mdb` is not an
existing file rather than allowing `Vault::open` to create a new vault, opens
the existing vault through the public `Vault::open` API, fails closed via
`Vault::get_agent_definition` when the agent is absent (it never invents or
defaults an agent), and constructs the
`imessage_self_host_bridge` identity in `Requested` state with
`dedicated_handle` shape and `Agent { agent_ref }` binding, mints it through
`Vault::create_channel_identity` (which enforces uniqueness on the
`(channel, receiving handle)` assignment key), and walks the checked
lifecycle `Requested → PendingFulfillment (Manual) → Active` through
`Vault::transition_channel_identity`. It prints only the identity ref and a
non-secret channel/shape/binding/handle/state confirmation.

Production provisioning against the operator's real vault: PARKED (no Mac
mini host run; the production agent ref and identity ref are recorded by the
operator at dispatch of the live phase).

Validation evidence (throwaway vault, since deleted, 2026-08-10 UTC): a
temporary out-of-commit seed helper inserted one minimal `AgentDefinition`
through the public `Vault::put_agent_definition` API into a throwaway vault,
after which the example was exercised against it:

| # | invocation | result |
|---|---|---|
| 1 | missing args | usage error, exit 1 |
| 2 | agent ref `nothex` | rejected as malformed 32-hex `EntityId`, exit 1 |
| 3 | blank handle | rejected as blank, exit 1 |
| 4 | fresh vault, absent agent | fail closed: `agent … is absent from this vault; refusing to invent an agent binding`, exit 1 |
| 5 | seeded throwaway vault, handle `+15555550123`, agent `00112233445566778899aabbccddeeff` | minted identity_ref `019feb45b6ed7c5096914b3f61aa6865`, state `active`, exit 0 |
| 6 | identical `(channel, handle)` re-run | assignment-key uniqueness rejection (channel identity already exists), exit 1 |
| 7 | second handle on same channel/agent | second identity minted `019feb45fc5e74c1bd7355d4682aa0f6`, exit 0 |

The seed helper was deleted before staging; it is not part of the claim. The
identity refs above belong to the deleted throwaway vault and bind nothing in
production; the handle values are doc-safe aliases (`555-01xx` range and an
`.invalid` TLD).

## Owner grant

PARKED (no dedicated-line owner grant exists for this line yet).

State of the contract: before **any** direct send, this section must record
the owner grant identifier, grant date, grant scope (dedicated line alias,
controlled recipient set, permitted existing-thread/new-contact measurement
families), and the concrete `run_ceiling`. `hold_to_proposal` is satisfied by
that recorded grant, not by the phrase "owner-dialed." No grant was recorded
in this environment; therefore no direct-send leg ran and none is claimed.

## Out-of-tree workspace and commands

PARKED (host workspace not created).

No workspace directory exists, no `bun install` was run, and no adapter source
was written outside the repository. The normative layout (package.json,
bun.lock, `src/{config,imessage-kit-port,evidence-journal,surface-event-client,adapter,measure-send,main}.ts`,
`test/{adapter-smoke,surface-replay}.test.ts`, `evidence/*.jsonl`) remains as
specified in the blueprint. When the live phase dispatches, the workspace's
absolute path must be outside the Oneiron repository and recorded here before
install or execution; evidence stays out of tree and is cited by run-local id
and digest only.

## Dedicated Apple-ID setup friction

PARKED (dedicated Apple ID not created; Mac mini unavailable).

Nothing was set up, so there is no friction evidence: no elapsed-time figure,
no 2FA/device-approval counts, no activation-delay observation, no
phone-number-vs-email-only determination. These are unknowns, not zeros; the
live phase must record them per the blueprint's friction list without
capturing the Apple ID, credentials, device serials, phone numbers, or
session material.

## Adapter contract and ONE-1259 schema digest

Schema capture (dispatch-time grounding actually performed):

- Source: `crates/oneiron-server/tests/fixtures/v1_core_openapi_contract.snapshot.json`
  on the dispatch base `049cde369ca6ed8e905cb3eb044c64cea277667f`.
- Capture command: `shasum -a 256 crates/oneiron-server/tests/fixtures/v1_core_openapi_contract.snapshot.json`.
- SHA-256: `cdcba38025120f48d11833eb421c8860543f15d40add3f033e25c695b0037f94`.

`SurfaceEventSubmitRequest` (merged ONE-1259 DTO, exact wire keys):

| wire key | required | semantic | notes for the host adapter |
|---|---|---|---|
| `event_id` | yes | provider-native event id | immutable provider message GUID (else line-scoped WAL primary key), never content/timestamp-derived |
| `channel` | yes | raw channel assignment | host constant `imessage_self_host_bridge` |
| `receiving_address_or_handle` | yes | receiving identity routing key | host config: the dedicated handle provisioned in preflight |
| `counterparty` | yes | counterparty stamp | merged known/unknown shape: `{ "state": "known", "counterparty_ref": … }` or `{ "state": "unknown", "counterparty_key": … }` (exact variant keys per the captured schema) |
| `received_at` | yes | provider receive time | **Unix seconds** (`u64`; confirmed read-only in `crates/oneiron-server/src/api/surface_events.rs`: "Provider receive timestamp in Unix seconds"). Host `occurredAtMs` converts via `Math.floor(ms / 1000)` |
| `foreign_inbound` | yes | foreign/provider-authored marker | host constant `true` for admitted provider-authored inbound rows |
| `source` | no | source stamp `{ app, user_ref }` | defaults from `channel` + `counterparty` when omitted; when sent explicitly, `app` uses the exact enum spelling **`imessage`** (the blueprint skeleton's `i_message` was a placeholder, superseded) and `user_ref` carries the normalized remote participant ref |
| `action` | no | typed action | defaults to message; admitted rows are always `{ "kind": "message" }` |
| `workspace_ref` | no | provider workspace stamp | not minted by the iMessage host |
| `correlation_id` | no | public correlation id | defaults to `event_id`; the adapter sets it to the same stable id |
| `payload_ref` | no | adapter-local payload reference | evidence-journal digest ref only; raw text/media is never posted |

`SurfaceSourceAppPayload` enum spellings (verbatim, full set):
`email`, `slack`, `discord`, `web`, `voice`, `imessage`, `line`, `telegram`,
`linkedin`.

202 acceptance shape (`SurfaceEventAckResponse`): `correlation_id`,
`attempt_ref`, `state`, `replayed`, `accepted_at`, `status_path`. Typed
server rejections remain distinguishable from success and are never coerced
into receipts.

Identity-routing rejection reasons (never terminal-advance; each journals a
blocker and stops the inbound leg with the cursor unchanged):
`unknown_receiving_identity`, `non_agent_bound_identity`,
`inactive_receiving_identity`, `tombstoned_receiving_identity`.

Status read: `GET /v1/core/surface-events/{correlation_id}` — readable
through the paired core read route, as required by preflight.

The live inbound leg has an additional precondition: the merged ruled
source-app projection must cover the provisioned `imessage_self_host_bridge`
channel key. The current trace is that `SurfaceSourceApp::from_channel_key`
rules only the closed OF-247 set: assignment lookup resolves
`imessage_self_host_bridge`, but `routed_receipt` refuses it with typed
`InvalidConfig`. Extending the projection to the OF-347 iMessage bridge
channels (or amending the channel model) is a follow-up engine-ticket claim,
not this PR. Until that lands, the live inbound leg stays parked and the
channel constant remains `imessage_self_host_bridge`.

The scratch adapter must map its local skeleton names to these exact keys and
spellings at submit time and hold no second copy of the wire schema.

## Inbound WAL → SurfaceEvent receipt evidence

PARKED (no live inbound run; no adapter exists yet).

No correlation id, attempt ref, replay flag, or route receipt exists to
record. The classification table, correlation-id preference order (provider
message GUID → line-scoped WAL primary key → blocker-and-stop), typed
rejection handling, and receipt-before-cursor-commit ordering all stand as
specified in the blueprint; none of it has produced runtime evidence.

## Resume/backfill handoff

PARKED (no live run).

The restart-with-downtime test and the backfill/watch overlap crash test have
not run; no cursor store or evidence journal exists yet. The startup ordering
(read cursor → attach `startWatching` first, buffering and
correlation-deduping every watcher row → issue `getMessages(after)` and drain
in source order → monotonic source-order cursor commits → drain buffer → live
arrival order) remains the binding contract for the live phase.

## Direct-send measurement method

PARKED (no owner grant recorded; no sends attempted).

Method contract restated for the live phase: two families (existing-thread
reply; new-contact cold send), exact 60-second windows, attempted counts 1, 2,
4, 8, … bounded by the recorded `run_ceiling`, receiver ground truth
(`receiverObserved === true` on every attempt) required for an all-success
window, SDK acceptance / sender-side blue appearance / receiver observation /
final `delivered|ambiguous|not_observed` recorded as separate facts, stop
increasing on first throttle/typed rejection, account challenge, material
delivery-inference divergence, or ceiling; fresh recipients never reused
(`fresh_contact_pool_exhausted` ends the family early).

## Per-window observations

PARKED (no measurement windows ran).

No window rows exist. Nothing was attempted, accepted, observed, delivered,
ambiguous, not-observed, or rejected. No adverse result was encountered and
none is implied.

## BridgeLinePolicy lift

```json
{"policy_row": "declined"}
```

reason: `ops_prerequisites_unavailable` — the live phase's required inputs
(Mac mini host signed into Messages under a dedicated Apple ID, and a
recorded dedicated-line owner grant naming line alias, recipient set,
permitted measurement families, and `run_ceiling`) were unavailable in this
environment, so no all-success new-contact 60-second window exists to lift a
floor from. Emitting a numeric row would fabricate unknown values; emitting
`"max_new_contacts": 0` is forbidden by the spike contract.

next bounded measurement: once the prerequisites above are recorded in `##
Owner grant`, run new-contact family window 1 — 60 seconds, exactly 1
controlled cold send to a zero-prior-contact recipient, record sdk acceptance,
sender-side blue appearance, receiver observation inside the declared
observation horizon, and the final outcome as separate facts — then grow
geometrically (2, 4, 8, …) within the recorded `run_ceiling`; the policy row
lifts only from the first all-success window with count ≥ 1.

## Delivery-inference reliability

PARKED (no sends, no delivery/read indicators observed).

The required separation of facts — imessage-kit call accepted vs typed/error
result; blue-bubble appearance on the dedicated line; receiver observation
within the declared window; final `delivered|ambiguous|not_observed`; optional
delivery/read indicator as an additional, non-substituting observation — has
no evidence rows yet. Absence-of-read-receipt semantics are deliberately not
inferred here.

## Policy-risk posture and limitations

`policy_risk = Apple-ToS-gray, disclosed, owner-dialed`.

- The capability matrix entry `imessage_self_host_bridge`
  (`crates/oneiron/src/data/channel_identity_capability_matrix.v1.json`,
  read-only dependency) declares `mintability: self_hosted_bridge`,
  `policy_risk: hold_to_proposal`, `conservative_floor: true`,
  `disclosure_class: platform_bridge_disclosure`, and hard limits "Apple ToS
  gray area / per-line or Apple ID ban risk / host device availability is part
  of reliability". This spike treats those as empirical product constraints,
  recorded — not as a design-time veto.
- The direct-send exception is bound to the recorded owner grant. No grant is
  recorded, so the exception was never exercised.
- Posture limit: an adverse self-host result in the live phase is recorded;
  it is not converted into an automatic switch to Messages for Business, a
  hosted bridge, another Apple ID, another line, or another provider. Any such
  change is a new identified run with its own grant coverage and a separate
  policy decision.
- Limitation of this parked phase: every operational unknown above remains
  unknown. The declined policy row is the complete, non-fabricated result of
  this phase.

## Repository containment

- Tracked claims (complete): `crates/oneiron/examples/provision_imessage_identity.rs`
  (new) and `docs/dogfood/imessage-selfhost-cid9.md` (this file, new).
- No file under `crates/**/src/` was added, removed, or modified;
  `crates/oneiron/src/channel_identity_manifest.rs`, `outbound.rs`, and
  `attempt_queue.rs` are untouched. `crates/oneiron-server/**` untouched.
- `Cargo.lock` is untouched (byte-identical to the dispatch base; build churn
  observed during validation was restored before staging).
- `crates/oneiron/Cargo.toml` untouched: the example is cargo
  auto-discovered from `examples/`; no manifest registration was needed.
- `packages/imessage-bridge/` does not exist in this worktree and was never
  created; `git status --porcelain --untracked-files=all --
  packages/imessage-bridge/` is empty. In the canonical checkout the package
  directory contains only untracked/ignored operational content — `dist/src`
  and `dist/test` compiled artifacts plus `node_modules` (including the
  pickup-recorded `@photon-ai/imessage-kit@3.0.0`) — recorded here as
  **found, not touched**; ONE-1502-imessage-bridge owns that path.
- No server route was added; the spike consumes the merged ONE-1259
  `POST /v1/core/surface-events` route and its paired status read route only.
- `git status --porcelain` on the final branch shows no tracked change
  outside `docs/dogfood/` and the claimed example file.

## Secrets/private-data review

Review executed over this file before staging. Checklist:

- [x] no Apple IDs, email addresses, or phone numbers (the handles under `##
  Provisioned ChannelIdentity` are doc-safe aliases: `+15555550123` is in the
  reserved 555-01XX fiction range; `dogfood@example.invalid` uses the
  `.invalid` TLD)
- [x] no bearer tokens, API keys, session cookies, or credential material
  (none was generated or used; credential *locations* are named, values never)
- [x] no device identifiers, serials, recipient names, or message bodies
- [x] no raw WAL rows or provider error text
- [x] identity refs recorded are throwaway-vault validation refs, since
  deleted, and bind no production entity
- [x] credentials are omitted entirely rather than masked

## Acceptance checklist

| done-means item | status |
|---|---|
| dispatch base contains ONE-1259 and the example; operator provisioning run recorded | route present on base; example landed and validated on a throwaway vault; **production operator run PARKED** |
| Mac mini + dedicated Apple ID run with version pins/timezone/alias/setup evidence | **PARKED** |
| engine base URL + credential configuration locations named without values | named (env var or Keychain-backed config); assignment **PARKED** |
| owner grant recorded before any direct send; sends within grant | **PARKED** — no grant, no sends |
| host TS adapter behind `ImessageKitPort`; pinned `name@version` recorded; no host source committed; bridge-baseline byte-identity | pickup pin `@photon-ai/imessage-kit 3.0.0` recorded; adapter **PARKED**; no host source committed; bridge path absent in this worktree |
| controlled direct send with separated outcome facts | **PARKED** |
| controlled inbound admitted through `POST /v1/core/surface-events` with 202 receipt fields recorded | **PARKED** |
| skipped classes journaled with fsync-before-cursor advance | **PARKED** |
| replay dedupe (same attempt ref, `replayed=true`) demonstrated | **PARKED** |
| restart-with-downtime backfill gap closure demonstrated | **PARKED** |
| append-only journal fsync semantics; identity-routing blockers stop the leg; transport failures retry | contract recorded in `## Adapter contract and ONE-1259 schema digest`; runtime **PARKED** |
| admitted submission carries merged-schema keys incl. `imessage` source-app token and `payload_ref` | schema mapping captured verbatim; runtime **PARKED** |
| dated 60-second windows for both families with separate ambiguous/not-observed counts | **PARKED** |
| geometric counts ≤ `run_ceiling`; `remaining` semantics | **PARKED** |
| `BridgeLinePolicy` section holds exact five-key row or exact declined block | **satisfied — exact declined block with reason and next measurement** |
| delivery-inference facts distinguished | **PARKED** (no sends) |
| Apple-ID friction evidence complete enough to repeat setup | **PARKED** |
| adapter smoke protocol recorded step by step | **PARKED** (no adapter) |
| post-run bridge-path porcelain byte-identical to dispatch baseline | satisfied for this phase — path absent in worktree; canonical `dist/` content found-not-touched |
| `policy_risk = Apple-ToS-gray, disclosed, owner-dialed` stated; exception bound to grant; no silent provider/line switch | **satisfied** |
| no AI attribution in document/commit/PR; no secret printed; registry outranks guesses | **satisfied** |

## Evidence index

| ref | what | where |
|---|---|---|
| E1 | provisioning example source and contract | `crates/oneiron/examples/provision_imessage_identity.rs` (this branch) |
| E2 | example compile check | `cargo check -p oneiron --example provision_imessage_identity`, clean, 2026-08-10 |
| E3 | example behavioral runs (7 cases incl. happy-path mint, fail-closed absent agent, and assignment-key uniqueness), throwaway vault, since deleted | transcript recorded under `## Provisioned ChannelIdentity`, 2026-08-10 |
| E4 | ONE-1259 OpenAPI fixture digest | sha256 `cdcba38025120f48d11833eb421c8860543f15d40add3f033e25c695b0037f94` over `crates/oneiron-server/tests/fixtures/v1_core_openapi_contract.snapshot.json` on base `049cde369ca6ed8e905cb3eb044c64cea277667f` |
| E5 | `received_at` unit confirmation (Unix seconds) and `imessage` serde spelling | read-only inspection of `crates/oneiron-server/src/api/surface_events.rs` on the dispatch base |
| E6 | pickup-recorded bridge package pin | `@photon-ai/imessage-kit@3.0.0` from the canonical checkout's `packages/imessage-bridge/node_modules/…/package.json`, read-only, 2026-08-10 (re-confirm on host at workspace install) |
| E7 | capability matrix entry for `imessage_self_host_bridge` | `crates/oneiron/src/data/channel_identity_capability_matrix.v1.json` (read-only), quoted under `## Policy-risk posture and limitations` |
