# CUA: S2 runner, S3 checkers and S5 drift protocol

This is harness source, not a collected direction screen. Freeze S1 PUBLIC's
numeric, non-loopback IPv4 bind with `taskgen --fixture-forward` and put the
same value in the runtime pins' `browser.bench_fixture_forward`. The harness
writes `[browser] bench_fixture_forward` into each served vault's config and
sets `ONEIRON_EGRESS_CONFIG` to its private `egress.json` containing
`{"allowed_domains": []}`. Guests open `http://127.0.0.1:8080` plus PRIVATE
reset's relative `entry`; the host forwards only that origin to PUBLIC. Guests
stay network=none; PRIVATE, direct bridge requests and external sites stay
refused. A missing or mismatched plan, pin or written forward names its missing
piece under `fixture_transport_unavailable`.

## CLI

```
oneiron-bench cua taskgen --manifest crates/oneiron-bench/fixtures/cua/manifest.json --seed 20261021 --fixture-forward 172.30.91.1:8765 --out /srv/cua/frozen
oneiron-bench cua run --plan /srv/cua/frozen/plan.json --server /srv/bin/oneiron --pinned-config /srv/cua/pins.json --out /srv/cua/results
oneiron-bench cua run --readiness-only --plan /srv/cua/frozen/plan.json --server /srv/bin/oneiron --pinned-config /srv/cua/pins.json --out /srv/cua/readiness
oneiron-bench cua report --in /srv/cua/results/rows.jsonl --out /srv/cua/report
oneiron-bench cua drift --plan /srv/cua/frozen/s5.json --programs /srv/cua/submissions.json --out /srv/cua/drift
```

`run` refuses non-Linux hosts with `linux_execution_required` in its CLI parser.
`drift` freezes S5 assignments, checks the same forward pins and validates reset
entries against the same virtual origin. Its live adapter still needs access to
the original admitted workflows' vault and attached-run continuity; this is
`s5_original_workflow_vault_unavailable`, not a missing engine forward. See `CUA-S5.md`
for the protocol, input schema, lifecycle/repair state machine and limitations.
No replay or repair is aliased to a fresh solve. Use prebuilt binaries on a booked, isolated Linux host.
No Cargo dependency was added. No tests are part of this change.

`taskgen` freezes 51 fresh cells: B15/C15/C+6/D15. It pairs three evaluation seeds
across arms for each fixture and rotates arm order. C+ is only F2/F4. Two disjoint
additional seeds per fixture are reserved, not executed, for later phases.
The existing interface bench's ordered holdout partition and atomic JSON writer
are shared; its task corpus is not copied into CUA. `StdRng` freezes the generated
seed list, so later runs consume saved seeds rather than regenerate them.

Output must be a new private directory. `plan.json` contains fixture/checker
versions and digests, the optional `fixture_public_bind`, assignments, caps and frozen task text. `public-packets.json`
contains only public work instructions, not expected values or PRIVATE paths.
`holdout-freeze.json` separates evaluation and reserved seeds. The S1 renderer is
never run by taskgen and generated fixture data/pages are never rewritten.
Bench task instructions live outside the fixture tree in
`crates/oneiron-bench/cua-task-packet.txt`.

## Readiness receipt (FIX 8326)

`run --readiness-only` writes one terminal `readiness.json` and private raw
MCP/server/provider/S1 evidence. It does not run the 51 benchmark tasks. On the
frozen F2/C cell it checks PUBLIC GET, a synthetic Company name autosave POST
(including `X-CUA-Run`), PRIVATE refusal, direct bridge refusal, external
`https://example.com/` refusal and a real `library.propose` fresh-guest replay.
It also removes the forward from an in-memory copy of the pins and records all
51 cells as unavailable at harness admission, without starting another guest.
No request is sent to the external site when the empty allowlist works.

Success requires engine bridge answers plus S1 events/state, and negative
navigation requires a blocked egress gate row for that durable run. Candidate
prose is not proof. Missing evidence, setup errors and timeouts never pass; a
timeout is a failed row. Every later skipped case names the cause that stopped
the matrix. Each case uses the existing F2 60-second cap; startup uses the pinned
startup limit. The normal provider identity/cash gate and persistent $5 ledger
also cover readiness; the outer executor is not claimed model-free. The replay
itself is the engine's no-model admission check. No send or submit is authorized.

Use a new private output directory. Terminal or interrupted readiness work is
not retried there. Browser-pack installation and verified connection setup are
still required by the served engine; missing setup fails closed, never by
writing a verification bit. Linux compilation and this live matrix have not
been run on this machine.

## Runtime pin manifest (JSON, schema 1)

Supply real deployment evidence outside the checkout. No guessed model IDs,
keys, tokens, default upstreams or deploy configurations ship in this repo.
Unknown fields are rejected. All digest fields used for file pins are BLAKE3.

| Field | Meaning |
|---|---|
| `allowed`, `background_tier_enabled` | Existing pinned-config wire shape; background tier must be false. Shared parser preserves duplicate and ambiguous-revision refusals. |
| `engine` | Exactly `chromium` or `lightpanda`; one per screen, no fallback. |
| `engine_binary_digest`, `engine_head`, `driver_digest` | Prebuilt binary bytes, engine revision and deployed driver pin. |
| `guest_image_digest`, `prompt_package_digest` | Deployment's guest image and prompt package pins. |
| `browser` | JSON form of the engine's `BrowserConfig`, including an explicit `engine`, absolute `runtime`, pinned `image` and `bench_fixture_forward` matching `plan.fixture_public_bind`; scalar TOML fields only. |
| `navigation_evidence` | Null or `{path,digest}` to a host-private observation described below. |
| `arms` | Exactly B, C, C+, D, each with the arm fields below. |
| `startup_seconds`, `continuation_poll_ms`, `settle_seconds` | Explicit positive startup/readiness, compaction-poll and drain/capture clocks. |
| `clock_tolerance_ms` | Explicit positive endpoint host-UTC vs monotonic consistency tolerance; not an action deadline. |
| `action_policy` | `observe_overshoot` or `require_hard_cap`. The latter is unavailable without a public pre-effect stream. |
| `cash_cap_microusd` | Exactly 5000000 ($5), never per-server or per-task. |
| `cash_ledger`, `campaign_id` | Absolute persistent campaign ledger path and deployment's campaign identity. Changing output directories does not reset this ledger. |

Each arm has `models_body` (absolute path), `models_digest`, `routes`,
`role:"browser_planner"`, `thinking_evidence:{path,digest}`,
`decision_recipe_digest` (null or engine native recipe fingerprint), and
`deployment_evidence` (null or `{path,digest}`). `models_body` is the body of a
`[models]` table, without the outer prefix: use `[roles.browser_planner]`,
`[providers.NAME]`, etc. The shipped engine's `ModelsConfig::from_toml` parses it.
Use absolute file paths throughout this runtime body; deployed prompt text stays
in runtime files/packages. Multiline TOML string literals are refused by the
small table-prefix writer. Dreamer/workflow backgrounds must be disabled.
The browser planner must have one exact pinned rung. E5 now supplies semantic
handoff to the separately configured generative/chat seat; the harness does
not implement that miss counter or hot-swap model configuration.

Thinking evidence is JSON with `attested:true`, exact `requested_model` and
`effort` (D requires `medium`). Deployment evidence binds `models_digest`.
Navigation observations bind `engine`, `engine_binary_digest`, `driver_digest`,
`guest_image_digest`, plus true `public_success`, `private_refused` and
`external_refused`. Evidence files are pinned observations, not a readiness
bypass: the frozen plan/pins and the written served configuration must agree.
A standalone fenced-guest proof is not an S2 run result.

Each route has exact `provider`, `engine_model` (`provider/name@revision`),
`requested_model`, `returned_model`, upstream origin/prefix `upstream`,
`listen_port` on host loopback, `protocol` (`chat`, `messages`, `native`,
`native_chat`, or `system_one`), `cash`, and all these explicit bounds:
`max_context_tokens`, `input_overhead_tokens`, `max_output_tokens`,
`max_request_bytes`, `max_response_bytes`, `max_images`, `timeout_seconds`.
Provider base URLs must equal the route's loopback gate URL. One port/provider per
route; SystemOne's endpoint must point at its own gated `/v1/systemone`. Socket
and compressed transports are unavailable. The gate forwards non-streaming JSON
unchanged; streaming requests stop `unsupported_provider_protocol`. There are no
redirects, model substitutions, prompt generation or harness provider retries.

Owned/native routes also provide `weight_digest`, `tokenizer_digest`,
`deployment_identity`, `attestation:{path,digest}`. That evidence JSON must match
those fields and the exact requested/returned IDs. Native probes are logged but
not counted as inference. Native completion replies without a model rely on
this separate pinned deployment attestation; a chat reply without an exact
model is always `model_id_unattested`. A different returned ID is
`model_id_mismatch` and is withheld before the engine can execute generated code.
B must use exact `-sub` slugs. Noncash routes must be subscription or separately
attested owned models. B/C/C+/D now pin `browser_planner`; configured roles are
recorded per run, separately from observed role receipts. House model aliases
`oneiron-llama/<epoch>/<manifest digest>` map to the attested owned route's pin;
the provider ledger retains the raw alias, epoch and manifest digest.

A cash route supplies `tariff` with `version`,
`input_microusd_per_million`, `output_microusd_per_million`,
`cache_read_microusd_per_million`, `cache_write_microusd_per_million`,
`image_microusd_each`, and `highest_context_tier:true`. Before forwarding, the gate
fsyncs a reservation for the full context at the sum of input/cache rates plus
bounded output and the declared image charge. Text bytes plus declared template
overhead must fit the priced context; output must be wire-bounded. Multiple
samples, streaming, unpriceable requests, cash SystemOne, and cash image requests
are stopped as unavailable rather than admitted on an average-cost estimate.
Image cash bounding awaits a verified decoder/price bound. No reservation is
released using untrusted usage or a lost reply. These conservative retained
commitments are not invoices. The next request that would cross $5 is refused
`cash_cap_reached` before dispatch. Ledger pins must match on reopen.

## Lifecycle and evidence

The plan/pins are checked before any execution; the actual written forward is
checked before `serve`. The orchestration uses a new scratch vault and issuer per trial, shipped `init`
with no embedder, a stopped-vault agent mint, loopback `serve`, and the official
`mcp --surface tool-first` bridge. It discovers schemas from `tools/list` after MCP
initialization. It never signs credentials itself or reads LMDB. The candidate
holds its own agent credential, never the issuer/PRIVATE token, and receives only
public instructions/entry URL. Browser-pack installation and normal verified
connector setup still belong to deployment, not a hand-edited verification bit.

S1 has an owned process/token/event log per trial. It is not mounted into the
guest. PRIVATE health/reset/state use authenticated host-loopback HTTP. No second
listener is started on an occupied port. The engine alone owns the browser pipe.
The Linux deployment must supply the fenced network/firewall setup; S2 does not
create an alternative transport. Candidate continuation uses the same task and
run_ref inside the original whole-item deadline. Only yielded/window-full states
continue; human/send approval, timeout and provider errors terminate the trial.

Owned process groups and gate response delivery stop before bounded drain and
PRIVATE capture. Every failure after reset still attempts final state/events and
the independent checker. Guest-container teardown and complete primitive-effect coverage still need
public evidence, so the trial remains `evidence_incomplete` even after checker
completion. Forward readiness alone is not a direction-screen pass.
A provider may still process a cancelled remote request: its reservation remains
charged conservatively, and no late reply can drive the stopped candidate.

`campaign.json` freezes assignments/config. `started.jsonl` records dispatch;
`rows.jsonl` appends/fsyncs one terminal row per assigned key. Resume skips *all*
terminal rows, including failures/timeouts/blocks. An unfinished started cell
becomes `interrupted`, never an automatic retry. A stale lock requires operator
proof of owned-process/guest cleanup before removal; it is not stolen by timeout.
Report generation includes nonterminal/missing assignments in the denominator.

Raw per-run MCP/server/provider/reset/state/event/checker evidence is private.
Rows separate engine stops, harness stops, checker axes and measurement availability.
Receipts name the browser actually used; any engine mix refuses a screen. API
counts never become browser-action counts. Public effect coverage remains
unproven: receipt lower bounds can detect an overshoot, not prove an exact cap.

Whole-item caps are unchanged: F1 420s/120, F2 60s/20, F3 300s/60, F4 120s/20,
F5 600s/60. F5 inherits S1's research cap assumption. Setup/candidate/drain/total
elapsed times are separate. Reports show observed medians, missing counts and
successful-run medians separately, never p95 or success-only all-assigned latency.

E6 field provenance is `unavailable_e6`. E3 `no_progress_detection` observes
engine batches' `stop_cause.cause == "no_progress"`, with the failed receipt's
step, URL and title. No such stop records false, with the checked receipt count
and batch stop evidence; this says nothing about whether the page made progress.
Host-recorded MCP verb-output JSON is decoded, never candidate prose. E1
`admission_model_free` reads admission replay decision receipts (including an
empty decision list); E2 `execution_model_free` reads library-run receipts,
keeping incomplete `model_free_unproven` evidence null. Available observations
clear their unavailable reason. Whole-TASK freedom stays null without its model
edge ledger, unless a browser receipt positively records model use (false).
E4 TASK-before-planner and E5 browser-planner routing are present. A direct
library call or configured role alone does not prove whole-TASK model freedom
or complete observed role coverage. Physical attempts and raw usage are archived, but incomplete public
rung/stage joins stay unavailable. Engine units are not dollars. GPU kernel
seconds, actual billing, S4 author yield and N=1/5/20 amortisation stay unavailable
without their own evidence. No model-free whole-task claim or direction-screen
score is made. See the checker README for the independent factuality/safety axes.
