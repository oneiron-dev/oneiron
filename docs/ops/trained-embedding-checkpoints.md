# Trained embedding checkpoints

The server can load returned retrieval-embedder checkpoints from vault custody beside its configured embedder. It supports the same Qwen3 body and sentence-transformers chain as the local provider. It does not run repository code or merge an adapter into base weights.

## Supply a real checkpoint

A custom `oneiron::training_pack::TrainingConnector` can return a complete model pack through the existing training-pack doors. Both returned checkpoints must name the run's actual output model. Every file is kept by its immutable custody pin.

The shipped server trainer is still the frozen question-head trainer. Configuring it does not turn it into an embedder trainer. An embedded host supplying a custom connector must also supply its real training and held-out evidence through the existing contract. Logit probe fields are not a license to invent zero-valued vector parity. This runtime adds no training recipe or export schema.

The supported load set includes `config.json`, `modules.json`, `tokenizer.json`, `model.safetensors`, the pooling config, every Dense config and safetensors file the chain uses, and the prompt config when present. Missing or unsupported files fail through the local loader. All files come from a new private temporary directory populated only from custody. The final runtime owner removes it when its last forward ends.

## Evaluate before swapping

A returned or scored embedder run can supply an exact E2 arm. Its model is the exported checkpoint's model; its revision is the direct hex of `PinnedCheckpoint::content_hash()`. It does not borrow a model-registry deployment pin.

For an Embedder-seat `TrainRecipe` offer naming `training_run:<id>`, the card producer checks the actual run's seat and base. It asks the existing E2 measurement job to compare the incumbent with that run's returned checkpoint. The existing cohort, scorer, canary, family estimator and final-card machinery stay in charge. This measures the actual earlier result, not a promised future fine-tune. Missing evidence stays unknown. A `HeldOutResult` is not a sufficiency card.

Each E2 arm owns its runtime through its task and anchor calls. Concurrent work on the same run and checkpoint shares a load. The checkpoint is rechecked against its actual run before each use.

## Fill only after the owner's swap choice

Loading and evaluation do not approve a swap. The existing owner-approved `BindingSource::Training` receipt must still match the run, output binding, checkpoint and current manifest before fill begins.

A backfill pass loads outside the vault writer. In one short writer, `declare_training_embedder_space` compares the full observed run, pending receipt, manifest, kind slots and prior declaration again. A changed observation writes nothing and is retried by the ordinary worker.

The declared space is `<output-model>@training-<checkpoint-content-hash>`. It accepts text and has a text query tower. The existing kind-slot rules still apply: a text-only checkpoint cannot replace a space that must also serve image or audio. Its document and query towers use the same local runtime with their respective checkpoint prompts. The host contributes device, precision, threads, batching and its existing input cap; the candidate supplies its own attention and prompts, with the local chain's existing Int8 output default.

The ordinary move worker fills and checks the candidate. The old manifest and index keep serving until that move swaps. The configured incumbent slot and its `OnceLock` are never replaced. After a swap, declared-space text queries use the same trained runtime that filled it.

The worker also starts without a stock `ai.embed` seat so it can receive an approved checkpoint after startup. Its admission, idle interval, backoff, commit wakes and shutdown ownership are unchanged.

## Runtime ownership and status

The cache belongs to one server. Evaluation entries are weak. Only actual staged or bound sources retain a runtime strongly. A later admitted pass observes cancellation, erasure, undo, expiry or a changed move and removes stale retention; a caller already holding the actual runtime keeps its files only through that work. A space lookup or forward does not authorize a cancelled or erased source.

A trained checkpoint reports `serving` only when its actual bound role receipt, current text-slot selection, matching declared width and live local runtime agree. Loaded bytes alone remain `unavailable`. Other trained roles still have no loader.

The older viewed-swap response and automatic swap-ask exclusion for embedders are unchanged in this slice. The existing explicit training-role swap door can stage one. No model training, benchmark, test or deployment is part of this source change.

## Custody erasure and undo

Every runtime source check also reads each original immutable artifact-version metadata pin and native body-readability state in its transaction. Erased versions cannot keep serving from cached files; the next admitted refresh drops their strong retention.

Training moves recognize the exact checkpoint-hash space, including the already-serving path. Two checkpoints sharing an output model id are not interchangeable. At bind time, `RoleSwapReceipt.previous_swap` records the exact replaced ROLES receipt id. Undo uses that exact receipt, the move's actual incumbent, and the still-live native Bound run/checkpoint; it never selects an unrelated recent history row or invents Bound state.
