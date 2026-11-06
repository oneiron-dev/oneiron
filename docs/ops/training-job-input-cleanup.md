# Remove a completed trainer job's staged inputs

On the trainer's own host, stop the vault and name the completed training run:

```sh
oneiron maintain --config /absolute/path/to/oneiron.toml --cleanup-training-inputs <32-hex-run-id>
```

Repeat `--cleanup-training-inputs` for more runs. Without this flag, maintenance
keeps every training job file as before. This is an explicit owner action, not
scheduled retention or automatic cleanup.

The run must have its durable result in `Returned`, `Scored` or `Bound`. Its
pinned connector name selects the configured local `jobs_root`. The exact
`<run>-<spec>` job directory and its retained worker receipt must match that
result. A running, failed, unknown or unmatched job is left alone.

The action removes only the four original files under `base/` and the staged
`training.jsonl`. It keeps the job directory, `request.json`, `worker.stderr`,
`output/receipt.json` and every output file. It does not remove unknown files or
follow a symbolic job/base directory. The JSON report lists the actual files
removed; repeating the action skips input files already absent.

The original job directory remains its idempotency key. Same-job rereads and
lost-waiter polls still read the retained output and the vault's pinned base
manifest, not these staging copies. No result, checkpoint, receipt, model pin,
run state or vault custody record is changed. The action never starts a worker.

Output bodies and the duplicate base-file uploads/custody copies remain outside
this cleanup slice. This is not complete job-directory retirement. Deploy the
matching engine/server through the normal authorized rollout; no schema,
configuration or worker update is needed.
