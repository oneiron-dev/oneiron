# Retrieval projection training

The host supports `oneiron.reservoir-pair-projection/1` for a training plan
whose target is `retrieval_embedder` and whose seat is `embedder`.
Other role recipes are not advertised by this adapter.

A run starts from a complete, custodied checkpoint the local Qwen/ST loader
supports. Its original tokenizer, prompts, backbone and module chain remain
unchanged. The native runtime computes document-side features before final
provider rounding. Each consented reservoir artifact's chosen and rejected
texts are two views of that artifact. Symmetric contrastive training pulls
these views together against the other artifacts in the batch. These are
paired-view labels, not independently judged query/relevance labels.

Only a new square, bias-free Dense projection trains. It starts at identity.
The checkpoint appends that Dense and Normalize to the original ST chain.
All original files remain, except `modules.json`, which names the added steps.
Training and export use the same float32 projection format. Fixed probe vectors
are measured before and after reloading those actual bytes. The normal core
export-check door verifies the load-set hashes, probe coverage and tolerance.

Configure a separate `[models.training.connectors.<name>]` entry with the
existing paid quote fields and `worker` pointing to
`scripts/training_pack/projection_worker.py`. It uses the same pinned Python
and requirements file as the question worker. There is no default connector.
An actual configured embedder slot supplies the host device/precision settings.
The plan explicitly supplies `epochs`, `batch_size`, `learning_rate`,
`weight_decay`, `temperature`, `seed` and `max_input_tokens`. Contrastive batches
and the training split need at least two pairs. No hyperparameter defaults
are supplied. Native feature computation and GPU-training wall time are
included in the worker's `gpu_wall_second` quantity; the receipt records the environment and
all projection-worker source hashes. The native feature checkpoint hash,
dimensions, runtime/device provenance and requested input window ride on the
request and receipt; the held-out log records its own actual runtime.

The original authorization, budget reservation, one `(run,spec)` job directory,
recovery polling, immutable completion and Used/Kept settlement remain in use.
Only training-side features and authored fixed probes reach the worker. No
held-out text or feature reaches it. The request retains hashes and file pins,
not the feature matrix itself. Owner-requested input cleanup removes the
staged base and training feature file, while preserving output and idempotency.

After custody accepts a returned checkpoint, the evaluator loads those actual
files through the native local runtime. On the sealed held-out pairs, it ranks
each rejected view among all rejected views using its chosen view as the
anchor. Equal-similarity non-pairs rank ahead of the pair. It records MRR,
recall-at-one, candidate count and a run-bound verifier log. A recipe may set
`evaluation.minimum_mrr`; without it the result is a completed measurement,
not a claim that retrieval quality improved. No calibration is fabricated.
The owner still makes the separate swap choice. This adapter never deploys
or binds a role automatically.
