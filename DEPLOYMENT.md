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
```

Environment overrides use `ONEIRON_` names, for example
`ONEIRON_PORT`, `ONEIRON_AUTH_SECRET`, `ONEIRON_ALLOWED_ORIGINS`, and
`ONEIRON_DICT_SEARCH_PATHS`.

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
