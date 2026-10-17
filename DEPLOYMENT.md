# Oneiron Local Deployment

This release is a single-vault local daemon setup. Shared multi-vault sync is
not enabled.

## Install

From crates.io after publication:

```sh
cargo install oneiron-server
```

From a checkout:

```sh
cargo install --path crates/oneiron-server
```

From GitHub:

```sh
curl -fsSL https://raw.githubusercontent.com/oneiron-dev/oneiron/main/deploy/install-oneiron-server.sh | sh
```

Set `ONEIRON_GIT_BRANCH`, `ONEIRON_GIT_TAG`, or `ONEIRON_GIT_REV` to install
a specific branch, tag, or revision.

The local daemon convention is:

```text
~/.local/share/oneiron/default/
```

Create the vault and inspect its compatibility metadata:

```sh
oneiron-server init ~/.local/share/oneiron/default
oneiron-server doctor ~/.local/share/oneiron/default
```

Run the daemon:

```sh
oneiron-server serve --vault-path ~/.local/share/oneiron/default
```

Legacy serve flags still work at the top level:

```sh
oneiron-server --vault-path ~/.local/share/oneiron/default --port 9090
```

## Config

`oneiron-server serve` reads `~/.config/oneiron/oneiron.toml` when it exists.
Values are layered in this order: file, environment, then CLI flags.

Example:

```toml
vault_path = "~/.local/share/oneiron/default"
host = "127.0.0.1"
port = 9090
log_level = "info"
allow_unauthenticated = true
allowed_origins = ["http://localhost:3000"]

dimensions = 4096
map_size = 8589934592
max_frame_size = 4194304
max_update_payload = 2097152
max_messages_per_sec = 200
dict_search_paths = ["~/.local/share/oneiron/dicts"]
assistant_display_names = ["mira"]
```

Environment overrides use `ONEIRON_` names, for example
`ONEIRON_PORT`, `ONEIRON_AUTH_SECRET`, `ONEIRON_ALLOWED_ORIGINS`,
`ONEIRON_DICT_SEARCH_PATHS`, and `ONEIRON_ASSISTANT_DISPLAY_NAMES`.

`assistant_display_names` (flag `--assistant-display-names`, comma-separated)
lists the host's assistant voice names. Stored turns spoken under one of those
names count as assistant turns during consolidation, beside the generic
`assistant`, `agent`, `ai`, and `model` speakers. The default is empty.

`trusted_proxies` (flag `--trusted-proxies`, env `ONEIRON_TRUSTED_PROXIES`,
comma-separated `ip` or `ip/prefix`) names the reverse proxies whose
`X-Forwarded-For` the server believes when it keys per-address booking quotas.
Behind such a proxy each client is charged as itself; from any other peer the
header is ignored. Every address in a listed block is believed when it names a
client, so list proxy hosts only, never a client network. An entry that does
not parse, a `/0` block, or an address with bits set past its prefix stops
startup. The default is empty: every caller is keyed by its own connection.

`artifact_port` (flag `--artifact-port`, env `ONEIRON_ARTIFACT_PORT`) is the
port of a second listener, on the same host, that serves hosted artifacts
(`/a/...`) and nothing else. A code bundle runs its own scripts, so it gets
that origin rather than the API's: there it keeps its module scripts and
fonts, and no route it can reach holds API data. The API still answers `/a/`,
but sandboxes a code bundle into an opaque origin there, where module scripts
and fonts do not load. The default `0` takes any free port, which
`/api/health` reports as `artifact_port`; clients open artifacts at the API's
scheme and host with that port. Set a fixed port for links that outlive a
restart. Behind a reverse proxy, publish that port on its own origin as well,
and never list it in `allowed_origins`. Both listeners share the `[limits]`
connection floor and each address's unauthenticated share. Managed serve
(`--managed-by-hypnos`) refuses the port flag. Its artifact listener is the unix
socket the supervisor names with `--artifact-http-socket` (an absolute path);
without one, its `/a/` answers on the API socket alone.

`artifact_domains` (flag `--artifact-domains`, env `ONEIRON_ARTIFACT_DOMAINS`,
comma-separated) and `artifact_vault_name` (flag `--artifact-vault-name`, env
`ONEIRON_ARTIFACT_VAULT_NAME`, a DNS label) put this vault on a subdomain of
its own on the artifact listener: `<vault>.<domain>/<artifact>/...` serves what
`/a/<artifact>/...` serves, with the same tiers, pointers and cache headers, on
an origin per vault. The edge, DNS and certificates stay static config: route
each domain's subdomains to the artifact port. A subdomain that names no vault
here answers exactly as a forbidden artifact does (the artifact 404), and so
does every refusal from this vault there. Other hosts keep plain `/a/`. A
device publishes to this server by syncing: a pinned pointer reaches it once
window sync has delivered the bytes and rows it names. Managed serve takes
`--artifact-domains` beside `--artifact-http-socket` and refuses
`--artifact-vault-name`: its subdomain is always its own vault name.

`[limits]` bounds the work a caller can start. Every bound is finite. A zero is
a config error on every row except `disk_reserve_bytes`, where zero puts the
floor at the disk's last byte. The count rows sit far above fleet scale (each
is at least ten times the 200 agents a fleet plans for, many of them on one
credential and one address). Past a row, work waits its turn in a fair queue,
round-robin across credentials and in arrival order within one, and the row
asks whether everything is okay: a typed `inspect_limit_crossing` question
(OF-520), logged as `limit_crossed` and kept on the vault. It never refuses
authenticated work for count. A wait ends at `queue_wait_timeout_ms`, a
request timeout, with a 503 and `retry-after` and nothing started.

```toml
[limits]
max_connections = 32768           # sockets open at once: the descriptor floor (default: half the open-file limit)
max_unauthenticated_connections_per_peer = 256  # sockets an off-device address holds before they authenticate
header_read_timeout_ms = 30000    # headers must arrive within it; also idle keep-alive
body_idle_timeout_ms = 60000      # a request body may pause this long between pieces
git_exchanges = 2048              # git smart-HTTP exchanges at once (one child each); past it they queue
lfs_transfers = 2048              # LFS uploads, downloads and verifies at once; past it they queue
lfs_memory_bytes = 2147483648     # bytes LFS transfers hold in memory: half reads, half installs (default: an eighth of memory)
embedder_requests = 2048          # requests `embedder serve` holds at once; past it they queue
embedder_answer_bytes = 268435456 # bytes `embedder serve`'s answers hold until delivered; past it they queue
decision_reads = 2048             # owner decision-read probes held at once; past it they queue
task_work = 2048                  # can, ask, wait and tasks.answer calls the vault runs at once; past it each caller waits a fair turn, then runs
lfs_quota_bytes = 68719476736     # LFS bytes stored plus uploads in flight; past it the row asks
transfer_idle_timeout_ms = 300000 # a git or LFS transfer moving no byte this long ends
retrieval_query_bytes = 1048576   # one retrieval query, as sent (413 past it)
projection_body_bytes = 4194304   # body bytes one multi-row read decodes
git_scan_blob_bytes = 1073741824  # one pushed blob the push door scans (default: RAM / 64)
git_scan_disk_floor_bytes = 1073741824 # free disk the door's hook leaves while it frames a push
queue_wait_timeout_ms = 300000    # how long queued work waits for its turn
disk_reserve_bytes = 2147483648   # free bytes the vault's disk keeps; uploads and held pushes stop at it (507)
keyed_filter_json_bytes = 67108864 # one keyed-memory search filter; past it the search runs whole and the row asks
code_result_inline_bytes = 1048576 # one code-mode result kept inline in LMDB; a bigger one is a file in the vault's bodies/
code_result_disk_floor_bytes = 1073741824 # free disk the result body store keeps; below it the row asks and the result is stored whole
code_result_scan_bytes = 268435456 # bytes one result search or query scans before it answers with a cursor
code_result_memory_bytes = 8589934592 # result bodies every run holds in memory at once (default: memory / 8, the least of RAM and the container limit)
code_result_session_memory_bytes = 1073741824 # result bodies one run holds in memory (default: memory / 64); past either, a body is read from its file by range
import_folder_text_bytes = 268435456 # text one notes import or folder rescan holds; past it the folder is imported whole and the row asks
import_folder_notes = 100000      # notes one notes import or folder rescan reads; past it the folder is imported whole and the row asks
import_decoded_messages = 1000000 # messages one history import holds decoded; past it the import lands whole and the row asks
import_decoded_bytes = 1073741824 # bytes those decoded messages hold; past it the import lands whole and the row asks
```

The push door scans a push one blob at a time, so `git_scan_blob_bytes` is
its memory floor per blob, never a cap on the push: a push of any size lands
while each blob fits and the disk keeps `git_scan_disk_floor_bytes` free. A
push past either is refused whole, with a reason that names the key.

Only the machine's own floors and the anonymous surface hold work back. Past
`max_connections` the server stops accepting, so new sockets wait in the
kernel's backlog; raising the open-file limit (`LimitNOFILE=`) raises the
default. Serving raises its soft open-file limit to the hard one, at most
65,536 (a refused raise keeps the limit there was, and logs it). The
descriptors the sockets leave hold the transfer rows too: half of what is
left past the server's own (256) bounds git exchanges at sixteen
descriptors each (its backend's pipes, a push's lock, and a git child it
reads through while the next one starts), and the other half LFS transfers
at one each, so a 1,024-descriptor limit runs 8 git exchanges at once, and
65,536 with half for sockets runs 1,016; past them they queue. A log line
(`transfer_descriptor_room`) gives the limit held and the bounds at start.
LFS transfers hold memory within `lfs_memory_bytes`. Reads take room on one
half before they take a transfer permit (and so does a git exchange's
check that its published refs' LFS objects are readable, for each manifest
it reads): a chunk exchange 128 MiB, and 256 bytes for each byte its
request declares, which it decodes; a download or a verify four times its
manifest's stored row, and 1 MiB, for as long as it streams. An upload takes
room on the other half once its body is spooled: 256 bytes for each byte of
an object of up to 8 MiB, which the install's credential scan decodes whole (a
larger object's chunks are decoded one at a time), and 256 bytes for each
32 KiB for its manifest. Past either half work queues, and work larger than
its half waits to run alone; nothing is refused for its size. A smaller row
than one chunk exchange in each half (256 MiB) is a config error. A connection from off this device that has not yet authenticated
counts toward its address's `max_unauthenticated_connections_per_peer` (never
more than half of `max_connections`, so one address cannot fill the floor), and
one past that share is shed with a 503; it leaves the share as soon as a
request on it presents a credential the server accepts. A loopback peer meets
`max_connections` only: it is this device, or a TLS proxy whose callers all
arrive from its one address. A push to a repository another push holds waits
its turn behind it. An LFS upload over `--max-lfs-object-bytes` (2 GiB unless
set) lands and the row asks; an upload that would take the vault's disk below
`disk_reserve_bytes` is refused with 507, by its declared size before any byte
is read. A push holds its command section and status report on that disk past
memory, and is answered 507 when a write of them would take it below the
reserve. Each such write asks first and claims nothing, so writes at the same
moment can each pass the reserve by their own bytes.

The two retrieval rows bound one request's shape, not how much a caller may
read. A query past `retrieval_query_bytes` is refused with a 413 that names
the field and the bound, and the first such query from a caller at a door
leaves a check for the operator. A list, search or query whose decoded bodies
would pass `projection_body_bytes` serves every row, and the rows past it
carry `bodyOmitted` in place of their body; reading that row on its own
returns its body whole. An over-large `limit` is served at 1,000 rows, and
the response says it was clamped.

## CJK Dictionaries

Oneiron can run without CJK dictionaries, but Japanese, Chinese, and Korean
text then uses portable n-gram tokenization. On daemon startup the server emits
a WARN if no CJK dictionary root is found.

Dictionary roots are expected to contain any of:

```text
ja/system.dic
zh/jieba.dict.utf8
ko/metadata.json
```

Auto-discovery checks the XDG oneiron data/config dictionary roots and common
system install roots. The recommended local path is:

```text
~/.local/share/oneiron/dicts/
```

Use `--dict-search-paths` or `ONEIRON_DICT_SEARCH_PATHS` for custom roots.

## Slide Review Renders

A held slide review whose slides change before Keep withdraws only the changed
slides' answers. After the quiet interval the server asks those slides again
over fresh renders of the head. It renders them itself with LibreOffice Impress
headless (`soffice`, exported to PDF) and poppler's `pdftoppm` (one PNG per
slide at 96 dpi). Both must be on the server's `PATH`. Each conversion uses its
own temporary profile and a timeout. Install the review fonts beside them:
Liberation for Arial, Times New Roman and Courier New; Carlito and Caladea for
Calibri and Cambria.

Without both tools the slides stay withdrawn, and their wake is held and tried
again every five minutes. The rest of the review still lands on Keep.

## Service Templates

Linux user service:

```sh
mkdir -p ~/.config/systemd/user
cp deploy/systemd/oneiron.service ~/.config/systemd/user/oneiron.service
systemctl --user daemon-reload
systemctl --user enable --now oneiron.service
```

macOS launchd:

```sh
mkdir -p ~/Library/LaunchAgents
sed "s#__HOME__#$HOME#g" deploy/launchd/com.oneiron.server.plist > ~/Library/LaunchAgents/com.oneiron.server.plist
launchctl load ~/Library/LaunchAgents/com.oneiron.server.plist
```

The templates assume `oneiron-server` was installed by Cargo into
`~/.cargo/bin` and use `~/.local/share/oneiron/default` as the vault path.

The Linux unit sets `MALLOC_ARENA_MAX=2`: glibc otherwise keeps a malloc arena
per busy thread, and two arenas measured 75 to 93 MiB less resident per vault
running the local embedder, at the same embedding speed. Keep it in any unit
you write yourself. macOS's allocator does not read it.

## Shared Embedder

A vault on the `local` embedder loads its own copy of the model, about 1 GiB
resident. Several vaults on one host, or a host with a GPU, can share one copy
instead: run `oneiron-server embedder serve`, which serves the local model over
an OpenAI-compatible `/v1/embeddings`, and put the vaults on the `endpoint`
provider.

```sh
# The host that holds the model. Loopback 127.0.0.1:7399 by default; it prints
# the model id, which is also the first row of GET /v1/models.
oneiron-server embedder serve

# Each vault.
MODEL=perplexity-ai/pplx-embed-v1-0.6b@2c4d510dd4a732063c31a0f70193e35067b51fd8
oneiron-server init ~/vaults/notes --embedder endpoint \
  --embedder-endpoint http://127.0.0.1:7399/v1 \
  --embedder-model-key "$MODEL" --embedder-model-id "$MODEL" --dimensions 1024
```

On the same backend as the local vault, and with the same settings (weight
precision and input cap among them), the vectors are the ones a `local` vault
makes, to the bit: the server runs the same verified files, tokenizer, pooling
and module chain, returns the chain's output, and the vault normalises and
rounds it exactly as the local provider does. On another backend they are
close but not equal: a CUDA server's vectors differ slightly from a CPU vault's
(cosine 0.998 or more), and CPU builds that sum in another order (aarch64,
x86_64 with AVX2) can differ in the last bits. Neither the transform nor the
run settings name the device, so the vault admits such a server; whether a
device change should need `reembed` is open (ARCH-0036 #space-identity-open).
The vault's client recognises this server from its `/v1/models` listing
and then sends whole texts marked query or document, so the server's tokenizer
cuts long inputs and its prompts apply where a local vault's would. The server
names the model it loaded, its transform and the settings it runs with on
every listing row (an alias's too, from `--model-alias`) and in every answer.
The vault admits the server only when that model is the vault's own
`model_id`, and holds every answer to the model and transform it admitted: a
server started, or restarted, with another model behind the same name, or with
say another output quantization, fills and answers nothing until it is
restored or `oneiron-server reembed`, run with the endpoint configuration,
moves the vault to it. A vault can move between `local` and this endpoint
without `reembed`.

A vault on the shipped model judges vector evidence by that model's measured
floors only when the server runs it as it was measured (Q8_0 weights, the
checkpoint's attention and output quantization, the shipped input cap or more,
its own files) and the vault's queries carry no prompt of their own; any other
profile, and any other endpoint, keeps the engine's default floors, as a
`local` vault on the same settings does. A remote rung pointed at
`embedder serve` is held the same way: its answers must name the vault's model
and transform and, when the vault judges by measured floors, the measured
profile, or the vault's own provider fills the row instead.
`deploy/systemd/oneiron-embedder.service` runs it as a user service.

`--config` or the `--embedder-*` flags pick another local model, as `serve`
reads them. Off loopback the server needs `--api-key-env NAME` (vaults send the
key with `--embedder-api-key-env`), and vaults refuse a network endpoint that is
not HTTPS, so reach a remote embedder through a TLS proxy such as
`tailscale serve`, or an SSH tunnel to a loopback port. The server checks the
key before it reads any of a request's body, and reads bodies only within a
budget (16 MiB for bodies up to 256 KiB, 64 MiB for larger ones, each body at
most 32 MiB), so neither strangers nor key holders can make it hold more. A
body must declare its `Content-Length` (411 otherwise). It reads `[limits]`
from the same config: an answer takes room for its vectors and their encoding
in `embedder_answer_bytes` before the model makes it, and keeps it until it is
delivered. The endpoint does not start when that row cannot hold its model's
largest answer (2,048 inputs at its dimensions: about 193 MiB at 4,096). Past
`embedder_requests`, past a full budget or `embedder_answer_bytes`, and past
the few requests the model works on at once, a request with the key waits its
turn in order and is never refused for how many wait. Each wait ends at
`queue_wait_timeout_ms` (503, to retry, nothing started), and crossing a row
or a budget logs a `limit_crossed` question. A body has 120 s to arrive once
its budget is reserved (408 after).

On a GPU host, build with candle's CUDA kernels (the CUDA toolkit's `nvcc` on
`PATH`) and ask for the device:

```sh
cargo build --release -p oneiron-server --features candle-core/cuda,candle-nn/cuda
oneiron-server embedder serve --embedder-device cuda
```

Without those features the build needs no GPU and `cuda` is refused as
unavailable. Apple silicon builds use Metal by default.
