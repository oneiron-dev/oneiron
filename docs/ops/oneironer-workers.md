# Oneironer workers on a Mac: the managed MLX worker

The Oneironer tagger serves through one dispatcher per slot. Every slot has
the Candle baseline: the engine its rows chose, or the device the section
names. On an Apple silicon Mac, a server can also run the bundle's MLX worker
beside Candle (FIX 6755 slice 3). This page covers where that worker comes
from, when it starts, how it loads and falls back, how it restarts or stays
down, how it stops, who owns it, and what each call's receipt says. The
dispatcher itself is described in [run-with-models.md](run-with-models.md),
"Workers, live and bulk calls, and receipts".

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
canonical directory and stack hold one worker session; a second slot of the
same bundle in that process serves Candle alone. Several server processes
on one Mac, a managed host with several vault processes say, each run their
own worker, at about 1.3 GB of memory each. This rewrites contract A1's
"one process per bundle per Mac" (Engine call 5).

## What a call's receipt says

Every call's `execution` receipt names the worker that ran it, from the
host's own facts, never from anything the worker reported:

- `runtime = "mlx"`, `compute = "metal"`, `engine = "mlx/metal"` for a
  call the MLX worker ran, failed calls included;
- `candle/cpu` or `candle/metal` for a call Candle ran: every window over
  512 tokens, and every call while the worker loads, restarts or is down,
  a marker's retry after a failed MLX call among them;
- `pick` is `calibrated`, `free` or `shorter_queue` by the usual rules, and
  `fallback` when Candle runs a call because the better-ranked worker is
  not ready;
- `queue_ms` is the call's wait until its unit started, and `infer_ms` the
  whole unit's run. A bulk call shares its unit's run time with the others
  in it; the time is not divided among them.

The receipt never enters the answer: parity and digests compare the spans
alone.
