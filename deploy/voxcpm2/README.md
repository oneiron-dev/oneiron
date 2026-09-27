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
expose the listener publicly: the body carries a private banked WAV. Use a
32+-byte random `VOXCPM_TOKEN` shared with the host adapter; keep the credential
out of logs and repositories. Choose an owner-only runtime directory.

Example on a provisioned CUDA host (install a matching CUDA PyTorch wheel first):

```sh
uv pip install 'voxcpm==2.0.3' 'huggingface_hub' 'numpy'
export VOXCPM_REV=32279effe8c19989596f05d353d1447f51d9e915
export VOXCPM_TOKEN=<host-generated-unguessable-secret>
python3 deploy/voxcpm2/worker.py --runtime-dir /run/user/$(id -u)/voxcpm2 --port 8769
```

The revision above is an example full commit. The operator must verify and pin
it before deployment. The Rust `VoxCpm2HttpQueue::connect("http://127.0.0.1:8769/", token)`
checks `/ready` outside the session lock. `VoxCpm2Adapter` reads a fresh owner
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
