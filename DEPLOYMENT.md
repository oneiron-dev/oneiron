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

The vectors are the ones a `local` vault makes, to the bit: the server runs the
same verified files, tokenizer, pooling and module chain, returns the chain's
output, and the vault normalises and rounds it exactly as the local provider
does. The vault's client recognises this server from its `/v1/models` listing
and then sends whole texts marked query or document, so the server's tokenizer
cuts long inputs and its prompts apply where a local vault's would. The vault
also holds the server's transform to the one it pinned: a server started with,
say, another output quantization fills nothing until `reembed`. A vault can
move between `local` and this endpoint without `reembed`.
`deploy/systemd/oneiron-embedder.service` runs it as a user service.

`--config` or the `--embedder-*` flags pick another local model, as `serve`
reads them. Off loopback the server needs `--api-key-env NAME` (vaults send the
key with `--embedder-api-key-env`), and vaults refuse a network endpoint that is
not HTTPS, so reach a remote embedder through a TLS proxy such as
`tailscale serve`, or an SSH tunnel to a loopback port.

On a GPU host, build with candle's CUDA kernels (the CUDA toolkit's `nvcc` on
`PATH`) and ask for the device:

```sh
cargo build --release -p oneiron-server --features candle-core/cuda,candle-nn/cuda
oneiron-server embedder serve --embedder-device cuda
```

Without those features the build needs no GPU and `cuda` is refused as
unavailable. Apple silicon builds use Metal by default.
