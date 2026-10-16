# BEAM evaluation commands

Canon: `/oneiron/eval/oneiron-arch-0042-beam-evaluation-harness-v1/`.

The sibling performance bench has a statistical-validity plan for independent
repeats, per-axis intervals, and run-order effects. It lives in canon at
`/oneiron/eval/oneiron-arch-0042-beam-evaluation-harness-v1/#performance-bench`.
The current `oneiron-bench perf` runner does not implement it.

`cargo run -p oneiron-bench -- beam` lists the commands. There are two lanes:

- `beam run <manifest>` is the deterministic retrieval pre-check. Its legacy
  `vanilla_rag` arm is an in-engine text/vector-only baseline, not Chroma.
  Backbone-solo runs here with an empty pack and no vault call. The other
  model answerers stay explicitly unavailable in this lane.
- `beam measure <plan.json>` runs actual answerers and the three-call judge.
  Deterministic, agentic, backbone-solo and trajectory-only share one exact
  model/parameter pin. Chat is a separate cheap-model point. Optional Chroma
  uses an independent v2 HTTP collection and the same corpus, vectors and
  retrieval limit.

Trajectory-only is the reader's own trace with no vault recall
(ARCH-0042 `scour:G12`). It takes as many steps as the effort's
`retrieval_steps`, under the pinned `trajectory_prompt`. Each step sees the
question and that question's earlier steps only. The steps then go to the
shared answer call as its context.

`beam measure` reports `paired` rows: each arm of the reader against
backbone-solo, question by question, per task family (the gold `ability`
label). Every row carries the paired difference, mean input and output
tokens, context and output truncation rates, and query cost. A
`fixed_answer_cap` row shares the reader's output cap. A
`fixed_total_tokens` row scores zero for any question whose query tokens pass
the effort's `total_token_allowance`. `picks` names the setting per reader and
family: the arm, its optional memory budget and its pack view. Backbone-solo
stays the pick unless an arm beats it strictly.

Each score in `paired`, `picks`, `points`, `frontier` and `agency_lift` has
two columns (ARCH-0042 `beam:D9`). `beam-fixed` is the float nugget score with
half credit, from a judge shown the real question. The picks, the frontier and
the agency lift rest on it. `int-cast-saw-question` takes the same verdicts
and drops each 0.5 to 0. Neither column is `beam-replicate@3e12035`, whose
judge sees the placeholder `<question>`. This harness does not run that
judge pass yet.

`crates/oneiron-bench/fixtures/beam_measure.example.json` is a runnable plan
shape for an OpenAI-compatible local relay. Before using it for real numbers,
set the endpoint, provide the named key environment variable, and replace the
explicitly fake example prices with a verified versioned price table. A provider
must report the pinned model revision and token usage. A response missing either
fails closed. No credential belongs in a plan or command-line argument.

Each `judge` configuration requires `instruction: {"content": "...", "sha256": "..."}`.
The hash pins the exact UTF-8 instruction bytes. Empty content or a mismatched
hash fails before any provider call. The binary supplies no implicit judge prompt.
Retrieval-only reports use a null judge-instruction hash because they invoke no judge.

Reports record the exact answer prompt, its card pin, judge-instruction hash,
fixed call contract, model pins, real provider usage and request hashes. Judge
usage is eval overhead. Offline engine ingest/index time and tokenizer work are
measured separately; no offline LLM call means zero offline provider dollars.

## Data and comparison boundaries

The bundled LongMemEval-S and BEAM tier files are small conformance samples,
not the native 500K/1M/10M datasets. `beam tiers <graduation.json>` requires a
non-regressed previous tier. The 10M cell stays `not-yet-run (10M-gated)`.
Every corpus item must carry `metadata.dataset_timestamp` in Unix seconds;
`occurredAt` must agree with it. Learned time follows corpus order, not ingest
wall-clock time. Measured plans freeze read-time decay with `temporal_now`.

An optional `metadata.stated_claim_predicate` makes the verbatim source text
an observed statement through the existing claim write door. It is not gold.
This lets the access-factor ablation exercise actual OF-095 claim decay. A
TURN-only corpus reports `no_claim_rows` for that leg instead of claiming a
meaningless measurement. The other ablation removes the context-budget cap.
Both ablation triples and their spend stay separate from the main frontier.

`beam infra <measurement.json>` reports carded vector-DB measurements for
cost framing only. They never feed the accuracy scorer. Published citation
rows with missing axes, incompatible scales, oracle context or in-family judges
stay in the appendix or are dropped. Missing evidence is not an invented win.

`beam score-nuggets <replay.json>` writes both scorer columns and all four wedge
buckets under `<output_dir>/<git-commit>/<dataset>/score.json`. It refuses a
dirty checkout. A synthetic replay is a scorer proof, not model accuracy.

`beam rung-fixture` checks identical retrieval through cold attach and remote
handover/fallback. `beam fixture-protocol <fixture.json>` measures known-span
retrieval without a generator. `beam edit-path-pack <directory>` and
`beam edit-path <attempts.json>` run the five edit shapes through independent
functional tests and contract checks. No model judge scores edits.
