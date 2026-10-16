# Load bench: the shipped server under synthetic load

`oneiron-bench load` measures what an agent living in Oneiron feels, on the
real `oneiron-server` binary. It is one command with fixed seeds and one JSON
result, so two commits can be compared on the same host. `load run` and
`load startup` read the server's `/proc` files, so they run on Linux only.

## What one run does

For each corpus size (`--records`) and vector setting (`--vectors`), on a fresh
vault:

1. `oneiron-server init` (no embedder, or an endpoint embedder pointed at the
   bench's loopback stub), then `token agent --tier full-access` for each agent
   on the stopped vault. Agents are real signed slips; every request carries a
   fresh holder proof, as production agents do.
2. `serve` on loopback. **startup_empty**: time to `/api/health` and peak
   memory (VmHWM, RssAnon, RssFile from `/proc`). Then the clock probe: the
   server checks a holder proof's timestamp against the vault's authority
   clock, within 60 s, and that clock does not run while the vault is closed.
   `init` and one `token agent` process per agent leave it behind the wall
   clock; past 60 s, every proof stamped with the wall clock is refused. The
   bench finds the offset with a few light recalls, signs every proof with it,
   and records it as `clock_skew_secs`.
3. **ingest_single_empty**: one caller writes the first `--single-writes`
   records. **ingest_parallel**: `--ingest-callers` agents write the rest; each
   conversation stays with one caller. **ingest_single_full**: one caller
   writes `--single-writes` more records on the full vault. A record is either a
   witnessed turn (`POST /v1/core/facade/vault.witness`, one or two messages) or a
   claim (`POST /v1/core/facade/vault.claims.upsert`, about the turn's conversation,
   or about the vault owner with probability `--hot-subject`).
4. With vectors: wait until the stub has answered a text carrying every
   record's tag, the server has since logged the embedding pass that stored
   the last of them (the stub reads the pass count as each new tag arrives;
   the worker runs one pass at a time, so the next pass line is that pass's;
   `serve` runs with `RUST_LOG=<level or your RUST_LOG>,oneiron_server::server::embedding=info`
   for these lines), and `--drain-settle-seconds` (35, beyond the worker's 15 s idle sleep and
   its publication of what it staged) pass with no further pass
   (`drain_seconds`). The run fails instead when the server exits, logs a
   failed embedding pass, or an hour passes. **steady** memory and
   **disk_mib** follow.
5. **golden**: each golden query once per grade by one agent; the result keeps
   every query's ranking (as record indexes, read from a tag word every record
   carries) and the hit@10 of the record each targeted query was drawn from. A
   failed query counts as a miss. Deep recall (`high`) needs a lease the
   facade does not mint, so the bench does not ask for it.
6. **memory_per_agent**: anonymous memory before and after the agents not yet
   heard from each make two light recalls.
7. **recall_<grade>_x<agents>**: each grade at each agent count, closed loop.
   Every agent first makes one untimed warm-up recall; then the cell's timer
   starts.
   **mixed_x<agents>**: half the agents at call grade, half at medium.
   **fairness**: 8 call-grade agents alone, then beside one agent recalling at
   medium from 8 threads at once.
8. Stop, then **startup_full**: restart on the full vault and measure again.

Grades: `call` (the call mode, light effort under its hard deadline; the
server default unless `--call-deadline-ms`), `light`, `medium` (the facade's
default, the normal grade). A server without call mode answers `call` with an
error, which the cell counts as failures.

Latencies are the client's, on loopback: a little above server-side time.

## The corpus

Invented words (three syllables from a fixed set of twenty) drawn with Zipf
frequencies from `--seed`. Turn `t` is record `2t`; the claim paired with it is
record `2t + 1`. Twenty turns make a conversation, and each conversation is a
claim subject. Each claim has its own predicate, so no claim supersedes another.
Golden queries are mostly the three rarest words of one record, plus
common-word and tag queries.

Times are fixed too: record `i` happened, and was learned, `i` seconds after a
fixed instant, and every recall sends `as_of` one minute after the last
record, so recency scores and rankings repeat on any day.

The stub embedder answers the plain OpenAI `/v1/embeddings` wire with
bag-of-words vectors (`--dimensions`, default 1024), so similar texts land near
each other. It is a load device, not a model.

## Run it

Build the server and the bench in two cargo invocations, so the server binary
keeps its production features (the bench enables `oneiron`'s `test-support`):

```sh
cargo build --release -p oneiron-server --bins
cargo build --release -p oneiron-bench
B=target/release
$B/oneiron-bench load run --server $B/oneiron-server --work /tmp/load --out before.json \
  --label "$(git rev-parse --short HEAD)" --records 1000,10000 --vectors both
```

Useful flags: `--agents 1,8,32,128`, `--ingest-callers 32`, `--single-writes
200`, `--grades call,light,medium`, `--cell-requests 200` (timed requests per cell,
spread evenly over its agents, but at least two each, so `x128` makes 256),
`--cell-seconds 60` (a cell's time cap once each agent has two samples),
`--skip mixed,fairness,agent-memory,restart`.

On a shared host, book the whole box and repeat each run; the result records
the load average before and after every cell, the host's CPU and the job's
cgroup CPU quota.

The server runs in the bench's process group. Stop a run with Ctrl-C or a
signal to the whole group (`kill -TERM -<pgid>`); a signal to the bench alone
skips its cleanup and leaves the server running.

## Compare two commits

Run the same command on the same host for each commit's binaries, then:

```sh
oneiron-bench load compare before.json after.json
```

It prints a markdown table of every cell both runs share, plus, per grade, how
many golden rankings are identical, how many differ and how many failed in
either run. A change meant to keep results identical must keep every golden
ranking equal, with no new failures.

## Profiling one cell

`--server-env KEY=VALUE` passes environment to `serve`, and
`--signal-cell CELL:SIGNAL` sends a signal to the server just before and just
after the named cell. With gperftools' CPU profiler, which needs no
`perf_event` permission:

```sh
--server-env LD_PRELOAD=/path/libprofiler.so.0 \
--server-env CPUPROFILE=/tmp/serve.prof --server-env CPUPROFILESIGNAL=12 \
--signal-cell recall_medium_x1:USR2
google-pprof --text $B/oneiron-server /tmp/serve.prof.0
```
