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
header is ignored. An entry that does not parse stops startup. The default is
empty: every caller is keyed by its own connection.

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
body must declare its `Content-Length` (411 otherwise); at most 32 requests
wait for each budget (503 past that, to retry), and a body has 120 s to arrive
once its budget is reserved (408 after).

On a GPU host, build with candle's CUDA kernels (the CUDA toolkit's `nvcc` on
`PATH`) and ask for the device:

```sh
cargo build --release -p oneiron-server --features candle-core/cuda,candle-nn/cuda
oneiron-server embedder serve --embedder-device cuda
```

Without those features the build needs no GPU and `cuda` is refused as
unavailable. Apple silicon builds use Metal by default.
