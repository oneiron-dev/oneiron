# Oneironer workers on a Mac: the MLX and Core ML workers

The Oneironer tagger serves through one dispatcher per slot. Every slot has
the Candle baseline: the engine its rows chose, or the device the section
names. On an Apple silicon Mac, a server can also run two platform workers
beside Candle: the bundle's managed MLX worker (FIX 6755 slice 3) and its
native Core ML worker (slice 2c). This page covers where each comes from,
when it starts, how it loads and falls back, how it restarts or stays down,
how it stops, who owns it, and what each call's receipt says. The MLX worker
comes first; [The Core ML worker](#the-core-ml-worker) covers what differs
for Core ML. The dispatcher itself is described in
[run-with-models.md](run-with-models.md), "Workers, live and bulk calls, and
receipts".

## Placement

The worker ships in the bundle as the `mlx-worker` platform row: the archive
`oneironer-mlx-worker-0.2.0-macos-arm64.tar` (about 350 MB). The archive
holds a relocatable CPython 3.12, the hash-locked wheels (MLX 0.32.3 among
them) and the worker package. `oneiron oneironer fetch` places it on a Mac by
default (`--platforms host`), or anywhere with `--platforms all`. The fetch
extracts the archive beside itself:

```text
<models root>/oneironer/b8cf6fb2f5d71020/
  oneironer.json  trunk.safetensors  tokenizer.json  ...
  oneironer-mlx-worker-0.2.0-macos-arm64.tar
  oneironer-mlx-worker-0.2.0-macos-arm64/      # with .extracted
```

The engine never downloads, installs or repairs the worker. It installs no
Python environment and looks up no interpreter on a path. A bundle fetched
with `--platforms none`, or on Linux, holds no worker, and that slot serves
Candle alone.

## Activation

The worker joins a slot only when all of these hold:

- the section is `provider = "local"` with `runtime = "auto"` (the default)
  and `device = "auto"` (the default). `runtime = "candle"` or a named
  device pins the slot to Candle, and no MLX worker starts;
- the bundle ships `parity.json`, so the worker can be held to its
  reference cases here;
- the server is a macOS build on aarch64. Linux checks the same code and
  never starts a process;
- the Mac's `ProductVersion` is at least the row's `min_os`: `26.0` for the
  shipped worker;
- the row's archive and its extraction are both placed, and the extraction
  matches the archive entry by entry: type, size, mode and bytes, with
  nothing else in the tree but `.extracted`;
- the row names the protocol `oneironer-worker-v2`.

`serve` and a managed vault check these after the slot is built, on a
background thread, so none of it holds back the listener. `oneiron init`
builds the slot only to check the section and starts no worker.

When a check fails, the log names the reason once, and Candle serves:

Each line carries `row = "mlx-worker"` (or `"coreml-ane"` for the Core ML
worker) and its `reason`:

| Reason | Level | Meaning |
|---|---|---|
| `unsupported_host` | debug | not a macOS aarch64 build |
| `not_installed` | info | no `mlx-worker` row, or neither its archive nor its extraction is placed |
| `install_invalid` | warn | the archive or the extraction is placed without the other, the extraction does not match the archive, or the row's program is missing. The engine does not repair it: remove the bundle and fetch it again |
| `os_too_old` | warn | the Mac's release is older than the row's `min_os`, or unreadable |
| `identity_mismatch:protocol` | warn | the row names a wire this engine does not speak |

## Loading and fallback

The engine starts the row's own program inside the verified extraction:

```text
<extraction>/python/bin/python3.12 -I -m oneironer_worker \
  --bundle <bundle dir> --max-input-tokens <oneironer.max_input_tokens>
```

The program and its first arguments come from the row's `launch`. The engine
appends `--bundle` and `--max-input-tokens`. `--bundle` is the bundle
directory that holds `oneironer.json`, not the extraction. The cap is the
section's `max_input_tokens` (default 2,048), not the worker's 512-token
window. The process starts with a cleared environment: only
`PYTHONDONTWRITEBYTECODE=1`, plus `HOME` and `TMPDIR` when the server has
them. Its working directory is `/`, and it gets the standard three
descriptors and no other. Its stderr goes to the server log as
`oneironer worker stderr` lines; stdout carries frames only.

The worker loads, hashes every file it reads, warms up, then sends its
handshake. It has 120 s to do so. The handshake must name the pinned worker
exactly: the protocol, the worker's name, version and lock hash, the
bundle's checkpoint, stack, label count and tokenizer SHA-256, the decode
(revision, character head, refinement K and tau, DATE snap), the runtime
(`mlx/metal`, float16), the window (`--max-input-tokens` as passed, a
qualified window of the row's 512 tokens), and the capabilities. The model
card it implies, contract version 2, spans and no links or mood, must be
the slot's own card.

Next, the worker is measured on this machine. Each reference case whose live
window fits 512 tokens (36 of the shipped 42) runs on the worker directly,
never through the dispatcher. Every one must give the reference spans
within the bundle's bar. Candle is timed on the same 36 cases, on a Candle
engine loaded for the measurement and dropped after it. The worker ranks
first only when it is preferred over Candle by the usual rule: a median at
least 3% faster and a 95th percentile at most 5% slower. Otherwise it ranks
after Candle. Both rows go into `engines.json`, keyed by the worker
archive's hash, the executable, the OS build and the 512-token cohort, so a
later start skips the measurement. It never skips the verification, the
handshake or the worker's warm-up. Candle's full-window row stays as the
survey keeps it.

Until the worker is ready, Candle takes every call. Once it is ready, the
two share the dispatcher. A window longer than 512 tokens, special tokens
included, always goes to Candle: it is never cut to fit and never refused.
A bulk unit of up to 8 calls goes to the worker as one request. A request
is split only where the worker's batch limit or the 16 MiB frame needs it;
nothing is dropped. A live call goes alone.

## Restart and down reasons

A crash takes the worker out of the pool at once, idle or busy. A crash is
the process exiting or closing stdout, a broken pipe, a malformed frame, a
call past `timeout_ms`, a reply that does not answer its request, a refused
load (`load`), or a handshake past 120 s. Calls routed to the worker go back
to routing. The call in flight fails with the worker's own receipt, and the
tagging markers retry through their usual schedule; the engine never
replays a request on Candle by itself. The process is stopped and reaped,
and a new one starts after a backoff. The backoff starts at
`retry_backoff_secs` (default 5 s) and doubles up to
`max_retry_backoff_secs` (default 300 s). The first good request of a
freshly admitted session resets it. A restarted worker is handshaken again,
then rejoins on its measured row.

The worker stays down, with no restart until the next server start, when
it is not the pinned worker or its answers do not clear here. Its state
moves to `unavailable`, logged at WARN once, with one of these reasons:

- `identity_mismatch:<field>`: the handshake differs in `protocol`,
  `worker_name`, `worker_version`, `worker_lock`, `checkpoint`, `stack`,
  `label_count`, `tokenizer`, `decode`, `runtime`, `window`,
  `capabilities` or `card`. `identity_mismatch:bundle` means the worker
  refused the bundle itself on its first frame;
- `parity_failed`: a held case gave other spans or scores past the bar, or
  no reference case fits the worker's window.

A crash moves the state to `failed` with its reason (`worker_exited`,
`broken_pipe`, `malformed_frame`, `call_timeout`, `handshake_timeout`,
`bad_reply`, `load_failed`, `spawn_failed`, `calibration_failed`,
`worker_panicked`, `wrong_result_count`), and back through `loading`,
`calibrating` and `ready` on its restart. To bring a down worker back, fix
the cause (a new bundle or a new server build), then restart the server.

## Shutdown

When the slot closes, the dispatcher stops taking work, and every call still
queued is answered. Each worker's wait is cut short. The engine then closes
the worker's stdin. The worker exits at that EOF and has 2 s to do so. A
worker still running at 5 s is killed. Either way the engine reaps it and
joins the threads that drained its pipes. A backoff wait ends at once. The
slot's drop waits for all of this, so no worker outlives a server shutdown.
If the server process dies without one, the worker reads EOF on stdin and
exits by itself.

## Per-process ownership

Each server process owns its workers. Within one process, a bundle's
canonical directory and stack hold one session of each platform worker; a
second slot of the same bundle in that process serves Candle alone. Several
server processes on one Mac, a managed host with several vault processes
say, each run their own workers: the MLX worker at about 1.3 GB of memory
each, the Core ML worker as below. This rewrites contract A1's "one process
per bundle per Mac" (Engine call 5).

## What a call's receipt says

Every call's `execution` receipt names the worker that ran it, from the
host's own facts, never from anything the worker reported:

- `runtime = "mlx"`, `compute = "metal"`, `engine = "mlx/metal"` for a
  call the MLX worker ran, failed calls included;
- `runtime = "coreml"`, `compute = "cpu_and_ne"`,
  `engine = "coreml/cpu_and_ne"` for a call the Core ML worker ran, failed
  calls included;
- `candle/cpu` or `candle/metal` for a call Candle ran: every window over
  512 tokens, and every call while a platform worker loads, restarts or is
  down, a marker's retry after a failed MLX or Core ML call among them;
- `pick` is `calibrated`, `free` or `shorter_queue` by the usual rules, and
  `fallback` when Candle runs a call because the better-ranked worker is
  not ready;
- `queue_ms` is the call's wait until its unit started, and `infer_ms` the
  whole unit's run. A bulk call shares its unit's run time with the others
  in it; the time is not divided among them.

The receipt never enters the answer: parity and digests compare the spans
alone.

## The Core ML worker

The Core ML worker runs the bundle's compiled model inside the server
process, on the CPU and the Neural Engine. It is admitted beside Candle and
the MLX worker by the same rules, on its own worker of the dispatcher.

### Placement and activation

The model ships in the bundle as the `coreml-ane` platform row: the archive
`coreml-ane-port-v1.mlmodelc.tar` (about 240 MB), one multifunction model
with one function per window length (`s32` through `s512`) and the weights
stored once. The fetch extracts it beside itself, as it does the MLX
archive:

```text
<models root>/oneironer/b8cf6fb2f5d71020/
  coreml-ane-port-v1.mlmodelc.tar
  coreml-ane-port-v1.mlmodelc/                 # with .extracted
```

The worker loads that extraction in place. The OS keys its Neural Engine
compile cache on the path, so the path stays the same for the bundle's
life; the engine never copies or moves it.

It joins under the same conditions as the MLX worker (`runtime = "auto"`,
`device = "auto"`, a shipped `parity.json`, a macOS aarch64 build, both the
archive and a matching extraction placed), with these differences:

- the Mac's release must be at least the row's `min_os`, `15.0`:
  multifunction models need macOS 15. An Intel Mac or Linux never selects
  it;
- there is no program and no protocol to check: the extraction is the
  model.

The not-started reasons and their levels are the table above, with
`row = "coreml-ane"`.

### Loading, the cold compile and fallback

The worker loads on its own background thread, with no deadline, while
Candle takes every call:

1. the bundle's manifest, which must still hash to the slot's stack;
2. the row, which must be the port this engine runs (`ane-port-v1`):
   `x` float32 `[1, 768, 1, L]` and `attention_mask` int32 `[1, L]` in;
   `logits` float16 `[1, 53, 1, L]` and `proj` float16 `[1, 128, 1, L]`
   among the outputs. The bundle may have no mention, coreference or affect
   head, and must have the character head;
3. from the verified trunk, only `encoder.embeddings.word_embeddings.weight`,
   kept as float16 (about 384 MB), and the character head's weights and
   vocabulary, in F32 on the CPU. No encoder is built and nothing is run;
4. each turn function, loaded with compute units CPU and Neural Engine and
   its function name, its model description checked against the row: the
   same feature names, types and shapes;
5. one warm-up prediction per function.

The first load on a path compiles every function for the Neural Engine. The
publisher measured 230 to 265 s for all eight on its Mac, about 38 to 41 s
each. A later start on the same path reuses the OS cache, while the disk
has room for it. The cache costs about 240 MB per loaded function, about
1.9 GB for all eight. If the OS evicts it, the next start compiles again,
and Candle serves meanwhile.

Then the worker is measured as the MLX worker is: the 36 reference cases
whose window fits 512 tokens run on it directly, every one must clear the
bar, and it is ranked against Candle timed on the same cases. Its row in
`engines.json` is keyed by the model archive's hash. When both platform
workers are ready, Candle ranks after them once either is preferred over
it; the two platform workers are not contested against each other.

Each call runs alone (a bulk unit holds one call). The worker picks the
smallest function whose tokens hold the call's window, special tokens
included, fills `x` with the window's word embeddings (float16 values in
float32), pads with the row's pad id under a zero mask, and reads `logits`
and `proj` back as float16 by their strides. `proj` is the character
head's projection, already applied; the engine runs the rest of the head
and its own decode on the CPU, the same code Candle runs. A call with no
current message is answered with no prediction. A window longer than 512
tokens always goes to Candle.

### Down reasons and restart

A load that fails is down, never a crash and never a failed server start:
the worker moves to `unavailable` with one of these reasons, logged at
WARN once, and Candle keeps serving:

- `coreml_unsupported_port`: the row's port, embedding table or tensors
  are not the ones this engine reads, or `proj` is not the character
  head's width;
- `coreml_unsupported_heads`: the bundle has a mention, coreference or
  affect head, or no character head;
- `coreml_load_failed:<what>`: `manifest`, `row`, `trunk`, `embedding`,
  `char_head`, `model`, or a function name (`s32` ... `s512`) did not load
  or warm;
- `coreml_io_mismatch:<feature>`: a function's model description differs
  from the row's tensor of that name, or names a feature the row does not;
- `identity_mismatch:stack`: the manifest no longer hashes to the slot's
  stack;
- `parity_failed`: as for the MLX worker.

There is no process to crash. A failed prediction fails that call alone,
with the worker's own receipt, as a failed Candle call does; markers retry
through their usual schedule. A reference case that fails during the
measurement is `calibration_failed`: the worker is reloaded after the
usual backoff. To bring a down worker back, fix the cause and restart the
server.

### Shutdown

The load observes the dispatcher's close between functions. A function
already compiling finishes first, so a shutdown during a cold compile can
wait for that one function, tens of seconds. Nothing outlives the server:
the models are the server process's own memory.

### What `cpu_and_ne` means

`compute = "cpu_and_ne"` names the compute units the engine allowed Core ML
to use, the CPU and the Neural Engine. It is not proof that any operation
ran on the Neural Engine: Core ML places each operation itself. The receipt
also covers the CPU work the engine does around the model: the embedding
lookup, the character head's tail and the decode.
