# VoxCPM2 warm worker (ONE-2333)

This is a host-owned inference process. It is not part of the vault or the
cascade session. The host must supply a CUDA machine and an immutable weights
revision. On startup the worker loads `openbmb/VoxCPM2` once on `cuda:0` and
only then opens the loopback listener. `/ready` identifies that loaded process.
No request downloads weights, starts a model, or falls back to CPU. A supervisor
must keep one worker alive across sessions (and restart it if it dies).
`deploy/systemd/oneiron-voxcpm2.service` is a template: adjust its install
paths and provision the CUDA user, wheel environment, and 0600 environment
file before enabling it. It restarts on failure and exposes readiness only
after model load. Do not
expose the listener publicly: the Rust client disables environment proxies so
an operator's HTTP_PROXY cannot redirect credentials or private WAVs; the body carries a private banked WAV. Use a
32+-byte random `VOXCPM_TOKEN` shared with the host adapter; keep the credential
out of logs and repositories. Choose an owner-only runtime directory.

Example on a provisioned CUDA host (install a matching CUDA PyTorch wheel first):

```sh
uv pip install 'voxcpm==2.0.3' 'huggingface_hub' 'numpy'
export VOXCPM_REV=32279effe8c19989596f05d353d1447f51d9e915
export VOXCPM_TOKEN=<host-generated-unguessable-secret>
python3 deploy/voxcpm2/worker.py --runtime-dir /run/user/$(id -u)/voxcpm2 \
  --policy-file deploy/voxcpm2/serving-policy.default.json --port 8769
```

The revision above is an example full commit. The operator must verify and pin
it before deployment. The Rust `VoxCpm2HttpQueue::connect("http://127.0.0.1:8769/", token)`
checks `/ready` outside the session lock. The host supplies `Arc<Vault>` to
`connect` so each queued render rechecks the exact bank revision under a
vault-scoped read guard; withdrawal takes its write guard and deletes that
revision atomically. An old returned PCM fails both `handle_pcm()` and
`filter_pcm()` after withdrawal; repeat `RenderTarget::is_current_in` just before
playback. `VoxCpm2Adapter` reads a fresh owner
ref at Start and submits work through that bounded queue. The host drains
`try_recv()` outside the session lock; for each Audio, call `handle_pcm()` and
then `filter_pcm()` on the active cascade, and recheck its generation at playback.
A Failed event stops/discards that generation. The host dispatches stop to
playback and retries cancellation if queue admission failed. The adapter
rejects stale worker/target replies, wrong render submissions, and malformed
PCM. The worker accepts only one complete utterance at a time (no fabricated
incremental chunks).

The CPU-only harness uses an injected fake model to prove request framing,
ref forwarding, PCM conversion, and target metadata. It is **not** a GPU
latency/quality or owner-ear verdict. Run: `uv run --with numpy python3 -m unittest
discover -s deploy/voxcpm2 -p test_worker.py -v`. On a real CUDA host, run a
separate authenticated render smoke with a consented ref before claiming a
live GPU acceptance pass. The E1/E2/E3 and register-escape ear picks remain
with the owner; this worker does not make them.

Upstream: <https://voxcpm.readthedocs.io/en/latest/reference/api.html> and
<https://voxcpm.readthedocs.io/en/latest/usage_guide.html>.

Serving policy: the seeded trusted Gate manifest has a `voice_serving` row with
`precedence: nested_narrowing`, required vault limits, and optional per-holder
limits. The Rust adapter resolves it from the live vault. Each holder row must
fit below the resolved vault ceiling; multiple trusted packs compose by minima.
The worker must receive the same deployment vault ceiling in a private policy
file (copy `serving-policy.default.json`, then apply the vault's resolved row).
It refuses any request that tries to widen that ceiling. Changed rows require
worker restart/reconnection to make `/ready` advertise matching limits; a
worker with narrower limits rejects a host whose manifest was widened. This
file is deployment data, not an invitation to publish raw references.
Upload admission is shared across all sessions and occurs before reading body
bytes. A monotonic elapsed deadline begins at socket accept, covering slow
headers and continuous as well as idle partial bodies; `/ready` remains
available when all render slots are occupied. The only compiled limit checks
are PCM16 alignment, 4-byte metadata framing, integer/host-width
representability, and the relation between read and HTTP deadlines. All
operational ceiling values are manifest data, not hidden second defaults.
