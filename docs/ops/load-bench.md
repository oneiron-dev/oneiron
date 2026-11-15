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

ARCH-0042's latency curve (#lives-bench: p50 and p95 at 10k, 100k and 1M
records, and at 1, 8 and 32 agents; the 100k call cell is the unmeasured
p95 ≤ 150 ms bar) is one `load run` on a whole booked box. It runs before a
release (PRE-RELEASE-CHECKLIST, "Full benches"), and the 1M vault needs
several GiB of work directory:

```sh
$B/oneiron-bench load run --server $B/oneiron-server --work /tmp/curve --out curve.json \
  --label "$(git rev-parse --short HEAD)" --records 10000,100000,1000000 --vectors off \
  --agents 1,8,32 --grades call,light,medium --skip mixed,fairness,agent-memory
```

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

## Lives screen

`load lives` is ARCH-0042's synthetic-lives bench (#lives-bench): every system
ingests the same synthetic lives and answers the same questions, and each row
carries its accuracy and its latency. The lives stay outside the repository;
pass the generation run's `lives-*.jsonl` files or their directories:

```sh
$B/oneiron-bench load lives --server $B/oneiron-server --embedder none \
  --lives /data/lives-snapshot/seats --lives /data/lives-snapshot/kimi \
  --sample 5 --seed 7 --work /tmp/lives --out screen-oneiron.json --label "$(git rev-parse --short HEAD)"
```

- **The pick.** `--sample N --seed S` sorts the lives by key, shuffles them
  with the bench's fixed generator and takes them in that order until it holds
  N lives and at least `--min-turns` turns (default 1,000, canon's corpus floor
  for latency), or the files end. `--life ID` (repeatable) takes exactly those
  lives; with neither flag every life is taken (the full run). The report lists
  the picked keys and each file's sha256, so another system's run takes the
  same set with `--life`. A life's key is its `life_id`; when the files read
  hold two lives under one id (the 2026-10-14 run has 12), the later copies
  are keyed `id~2`, `id~3` in read order.
- **One store.** All the picked lives go into one store per system (one vault
  for Oneiron). Questions name their person, and every system faces the same
  mixed store.
- **Ingest.** One conversation per session, its id fixed by the life key and
  the session id. One `vault.witness` per turn with one message: `user` for
  the user, `companion` for the assistant, `companion` with message type
  `tool_result` for a tool turn (its tool name, then its lines). A turn
  happens at its day's date, 09:00 UTC, plus 2 h per session of the day, plus
  20 s per turn. The ledger, persona, plan and meta are never ingested. Then
  the bench waits for the server's CPU to go quiet (`--settle-max-seconds`)
  and, with an embedder, for its embedding passes to stop
  (`--drain-settle-seconds` after the last pass).
- **Asking.** Every question (`questions`, then `questions_ja`) goes to
  `vault.recall` at every grade of `--grades` (default `call,light,medium`)
  with `--limit` items (default 10), one at a time, at `as_of` = the end of
  the asked life's last day. `as_of` filters nothing: it anchors the
  question's time words ("last week") and recency, so they read on that
  person's own timeline. Each grade starts with one untimed recall.
- **Context accuracy** (no model). A question is scored when its answer span
  was checked (`support: string`, with a span) and it is not `unanswerable`;
  the others stay in the report with `unscored_reason` (`unanswerable`,
  `unchecked_support`, `no_answer_span`). `answer_in_context`: the span,
  lower-cased with whitespace collapsed, is inside one of the top-k returned
  texts (an Oneiron item's text and the texts of the messages it cites).
  `evidence_rank`: the rank of the first item holding a gold evidence turn's
  whole text (`d2s1t04:L02` names turn `d2s1t04`); a text the system cut short
  holds the turn when its 32 or more characters lie inside it.
- **Latency.** `ms` is the client round trip on loopback. Each grade's summary
  applies canon's floor: below 1,000 documents its latency reads
  `not_measured` (`corpus_below_1000_documents`) instead of a number.
- **Embedders.** `--embedder` is required with `--server`, so a run names what
  it measured: `none`, `local`, or
  `endpoint=<url>,<model-key>,<model-id@revision>,<dimensions>` for the shared
  GPU model every system uses (`--embedder-api-key-env NAME` when the endpoint
  wants a key; the bench passes the name, never the key). The URL is
  loopback: reach a GPU host through a tunnel (`ssh -L`). `oneiron-server init`
  takes a network endpoint only with an on-device fallback serving the same
  model and an egress grant, which the screen does not set; the lives are
  synthetic, so nothing private crosses the tunnel.
- **Other systems** (`--system <name>=<adapter-url>`, repeatable) run after
  the Oneiron store, each through a thin adapter over the system's own SDK
  that speaks one JSON protocol:
  - `POST /v1/lives/reset {store}`;
  - `POST /v1/lives/ingest {store, conversation, at, turn: {id, role, text}}`
    → `{system_ms?}`, with every turn's conversation id, time and text as
    the Oneiron store gets them (`role` is `user`, `assistant` or `tool`);
  - `POST /v1/lives/settle {store}` → `{ready}`, polled every second for up
    to `--settle-max-seconds`;
  - `POST /v1/lives/search {store, query, k, as_of}` →
    `{items: [{text}], system_ms?}`, once per question per grade.

  `ms` is the bench's round trip and `system_ms` the adapter's own timing of
  the system's call, so network time sits apart from server time; each grade
  summarises both. An adapter URL is https, or plain http on loopback, with
  no credentials, query or fragment; an adapter takes any key from an
  environment variable it names, never from the bench. A system that fails
  to reset, takes no turn or never settles is reported `not_ready` with its
  reason and no rows, and the other systems still run. The store name is
  `lives-v1-` plus 16 hex of the picked keys, the same at every adapter.
- **`--in-process`** serves the engine linked into the bench (with its
  `test-support` features) on loopback and calls it as the vault owner, on any
  platform. Its timings are for checking the harness only and are never a
  published number; the report records `server.mode` and `server.principal`.
  `--server` mode calls the shipped binary as a minted full-access agent and
  runs on Linux.
