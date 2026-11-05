# training_pack: the question-head trainer (FIX 7263, OF-418 L1)

`worker.py` trains one binary head for one exact detector question on a frozen, pinned
Oneironer encoder: the producer the engine's `QuestionHeadTrainer` connector invokes
(`[models.training.connectors.<name>]`, docs/ops/run-with-models.md). The owner prepare/authorize doors exist. A native Candle question-head reader now
reproduces the exported checkpoint's token windows and raw probe logits before the
connector result is recorded. The host now scores returned question heads on their pinned held-out rows. No live detector
consumer exists yet. The worker calls no model service, teacher or network, uploads nothing, runs no remote code and downloads no model.
Its receipt is producer evidence, not a `HeldOutResult`, `TrainingRun`, owner swap or serving
readiness; the released stack is a pinned *candidate* base, not a promise of detector
quality. This code claims no checkpoint, deployment, quality or row closure.

## Environment

One Linux x86_64 CUDA 13 host and no container image. `requirements.txt` pins CPython
3.12.9, torch 2.12.1 (its PyPI wheel pins CUDA 13.0.2, cuDNN 9.20.0.48 and Triton 3.7.1),
safetensors 0.8.0, tokenizers 0.22.2 (the core Candle serving links) and blake3 1.0.11, plus
every pure-Python requirement; its header holds the two `uv` install commands. Any drift,
or no CUDA device, refuses the run. The receipt records every installed distribution, the
device, CUDA, cuDNN and the driver.

## Launch (a future booked GPU run; nothing here launches it)

```sh
fleet run --who L06 --goal "<explicit purpose>" --need cuda,gpu-4090 --mem 16G --est <time> \
  --sync <dir with this checkout, request and consented files> -- <venv>/bin/python -I \
  scripts/training_pack/worker.py --request <abs request.json> --output <abs new dir>
```

Never `--host`; the operator supplies every booking quantity, consented input and the Engine's
standing avoid list explicitly. No default corpus, destination, base download or connector.

## Request: `oneiron.training-pack.job/1` (every object closed; unknown or missing keys refuse)

```json
{"format": "oneiron.training-pack.job/1",
 "run": "<engine run id or dev job id, verbatim>", "spec_blake3": "<64 hex, verbatim>",
 "compute": {"kind": "engine_run | development", "reference": "<authorization/booking ref>"},
 "target": {"kind": "question", "question_id": "<id>", "question_version": 0,
   "definition": "<exact question/policy wording, any JSON>",
   "definition_blake3": "<BLAKE3 of canonical(definition)>", "family": "<failure family>",
   "corpus_revision": "<rev>", "feature_schema": "<id>",
   "label_schema": "oneiron.per-target-binary/1", "renderer": "oneiron.detector-target-text/1",
   "output_model": "<provider/name@revision of the new head, never the base>"},
 "base": {"model": "<base ModelId>", "dir": "<abs bundle dir>",
   "source": {"repository": "<repo>", "revision": "<immutable>"},
   "files": {"manifest": PIN, "config": PIN, "tokenizer": PIN, "trunk": PIN}},
 "training": {"path": "<abs rows.jsonl>", "sha256": "<hex>", "blake3": "<hex>", "bytes": 0},
 "provenance": {"split_receipt": "<L08-B split ref>", "consent_receipt": "<consent ref>"},
 "settings": {"recipe": "oneiron.frozen-encoder-binary-head/1", "seed": 0, "epochs": 20,
   "batch_size": 32, "learning_rate": 0.001, "weight_decay": 0.01,
   "evaluation": {"minimum_accuracy": 0.9}},
 "harness": {"repository": "<this repo>", "revision": "<commit of this worker>"},
 "probes": [{"id": "<id>", "input": {"target": "<JSON>", "context": ["<JSON>"]}}],
 "export_logit_tolerance": 0.0001}
```

`PIN` is `{"file": "<relative name>", "sha256", "blake3", "bytes"}`, all verified before any
parse; `oneironer.json` (format 2) must name exactly the pinned config, tokenizer and trunk.
A `role` target is refused by name. `run`, `spec_blake3` and `compute` are echoed, never
recomputed or certified; a `development` ref is not an engine authorization. The settings
shown are the recommended first training values; the seed is the caller's.
`evaluation` is optional host-only metadata, echoed unchanged by the worker. Its only optional
key is `minimum_accuracy`, a finite number in `[0,1]`. The example chooses 0.9, not a default.
With no criterion, a complete valid measurement passes; that does not certify quality or
approve deployment. With an explicit criterion, `passed` compares held-out binary accuracy
to that value. Neither choice changes the worker's training or export-parity checks. Candidate base: stack
`b8cf6fb2f5d71020`, ModelId `oneironer/local@eeeaf8bea4e8d166`, SHA-256 `oneironer.json`
`b8cf6fb2…6a90` (5,106 B), `config.json` `2ea2cb7d…5768` (1,349 B), `tokenizer.json`
`f59925fc…81af` (17,082,756 B), `trunk.safetensors` `eeeaf8be…3008` (1,226,637,420 B); full
digests in `crates/oneiron-server/src/oneironer/release/catalogue.rs`. The catalogue has no
BLAKE3, so the operator computes it over the same verified bytes.

## Rows: `oneiron.detector-target-row/1` (JSONL)

`{"format", "row", "question_id", "question_version", "corpus_revision", "feature_schema",
"label_schema", "split": "training", "source_family", "consent": {"basis", "receipt"},
"label": {"answer": "no|yes", "unit": "target", "adjudication"}, "input": {"target", "context"}}`

A row of another question, version, corpus or schema refuses the job. So does a window
label (`unit` other than `target`; a positive window is never spread to its runs), a
non-training split side (held-out rows never reach the trainer), a repeated id, empty
training or one class. No row minimum (about 500 is guidance, not a gate); nothing is
sampled, capped or relabeled. Rows come from L08-B's consented ingress and source-family
split, which the worker cannot certify (`split_certified_by_worker: false`).

## Recipe `oneiron.frozen-encoder-binary-head/1` (what PR2's Candle loader must match)

- **Renderer** `oneiron.detector-target-text/1`: the lines `question: <canonical(definition)>`
  and `target: <canonical(target)>`, then `context: <canonical(item)>` per item, joined by
  `\n`. `canonical` is the engine's `canonical_json_bytes` (serde_json, sorted keys, no
  whitespace, ryu floats). Labels, reviewers, consent, families and ids are never rendered.
- **Windows**: tokenizer.json, no padding or truncation. Content is
  `encode(text, add_special_tokens=false)`, cut into consecutive runs of
  `max_position_embeddings - len(prefix) - len(suffix)` ids, where prefix and suffix are what
  `encode(text, true)` adds around it; each window is `prefix + run + suffix`. A text that
  fits is one window. Nothing is truncated or refused for length.
- **Encoder** (`encoder.py`, a port of `oneironer/local/backbone.rs`): the trunk's `encoder.`
  tensors, `Config::validate`'s checks; GTE "new" post-norm, packed `qkv_proj`, non-interleaved
  rotary (`pos / θ^(i/d)`, f32), scores × 1/√d, MLP `up × erf-GELU(gate)`; BERT absolute
  positions. Float32, frozen, eval mode under `no_grad`, one unpadded window per pass.
- **Pooling** `window-mean-of-position-means/1`: the mean over a window's positions (specials
  included), then the unweighted mean over the target's windows.
- **Head**: a new `Linear(hidden, 2)` with label order `[no, yes]`. Unweighted mean
  cross-entropy, AdamW (betas 0.9/0.999, eps 1e-8, the job's lr and weight decay), the job's
  epochs of seeded `randperm` batches, deterministic algorithms and no TF32. Zero steps, an
  unchanged head or a non-finite loss fails. Outputs are raw logits with no calibrator, and
  0.35/0.65 are later serving seeds, not trainer constants.

## Output (a new or empty dir, mode 0700; files 0600 and never overwritten)

`base/{config.json,tokenizer.json,trunk.safetensors}` hold the verified base bytes, shared by
both load sets. The training set adds `training/head.safetensors` (`weight`, `bias`) and
`training/recipe.json`. The exported set adds `export/head.safetensors` (`head.weight`
`[2, hidden]`, `head.bias` `[2]`, f32) and `export/classifier.json`, a classifier manifest
separate from `oneironer.json` (recipe, target pins, base model/source/manifest SHA-256,
`max_positions`, `raw_logits`, each file's name, SHA-256 and size). A load-set row is `name`,
`kind`, `source` (base source, or the harness for produced files), `path`, `bytes`, `sha256`,
`blake3`. `load_set_blake3` is `PinnedCheckpoint::content_hash`: BLAKE3 of canonical `[model,
[[name, kind, source, blake3 bytes, bytes]…] by name]`, never put in the output ModelId.

`compare_export` reloads the exported files by their pins (fresh encoder, tokenizer, head)
and records per probe `input_blake3`, `tokens_blake3`, windows, both logit pairs and argmaxes
and `max_logit_difference`. It passes only with finite logits, identical tokens, no argmax
flip and every difference within tolerance; a failure keeps every file.

`receipt.json` is written for every outcome: `status` `trained` (exit 0),
`export_parity_failed` or `failed` (1), `refused` (2). It holds run/spec verbatim,
authorization (`verified_by_worker: false`), request SHA-256, recipe, settings, harness,
environment, corpus hashes/counts/families/provenance, the encoder record, training (steps,
epoch losses, head SHA-256 before and after), load sets, probes, the export check, elapsed
marks and service units (GPU wall seconds). Cost, serving latency, calibration and held-out
or incumbent comparison are absent, never zero.

Mapping in the adapter (`ai_host/training_pack/wire.rs`, `TrainOutput`): run and spec come back verbatim. The
checkpoints are `load_sets.*`: `model` plus each row's bytes read from `path`.
`probe_*_blake3` is `load_sets.*.load_set_blake3`. `probes[]` maps to `ProbeMeasurement`,
with hex becoming `[u8; 32]`. `settings`, `harness`, `receipt` (the whole file) and
`service_units.quantity` map directly. The engine re-hashes every byte.

## Host held-out evaluation

The host opens the run's sealed held-out exposure through `open_training_held_out`, reads
its pinned exported checkpoint in Candle, and records a `HeldOutResult`. This is separate
from the worker's fixed probe parity. Predictions use raw `[no, yes]` logits, with ties
answering `no`. `binary_accuracy` compares each complete target answer by exact yes/no
identity. The result also reports correct/incorrect counts, confusion counts, class support,
raw and calibrated binary Brier score, and equal-width calibration error.

Calibration fits one positive temperature by mean binary negative log-likelihood on the
**training partition only**, then measures Brier and calibration error on **held-out rows**.
This first adapter does not reserve a separate validation partition for fitting. Its log
names the fitting split rather than claiming validation-fit calibration. The search
normalizes logit margins, brackets the convex inverse-temperature derivative, and uses 96
bisection steps. Temperatures stay in the positive normal `f64` range. Neutral temperature
1 is actually scored and wins an equal objective, including unidentifiable all-zero logits.
Binary Brier is `mean((P(yes) - I(answer=yes))²)`. Calibration error is
`sum_bin(n_bin/N * abs(mean_P_yes - fraction_yes))` in 10 equal-width probability bins;
probability 1 belongs to the last bin. These are reporting algorithms, not serving gates.

One run-bound `oneiron.question-held-out/1` verifier log keeps the exact pins, exposure,
criterion, fitting method/count/objective, metrics and per-case id, input digest, gold
answer, prediction, raw logits and calibrated probability. It contains no raw target or
context text. The existing record door validates the result and moves `Returned` to
`Scored`. Question scoring does not load a role, approve a detector, or deploy anything.
Role recipes still hold with `training.no_evaluator` until their adapters exist.

## Still required elsewhere

- L08-B: consented per-target ingress, the source-family split and the comparison receipt;
  a separate validation partition for temperature fitting remains a follow-up. The host
  explicitly reports this adapter's training-fit calibration, not validation-fit quality.
- Held-out adapters for other seats and incumbent comparisons; native probe parity alone
  is not a held-out quality measurement.
- A live detector consumer and its approve/revoke path. The native reader is independent
  of the extraction slot and does not bind a role or deploy a question head. Swap remains
  owner-only, auto-deploy off.
