# oneiron-server

Local sync daemon for a single Oneiron vault.

```sh
cargo install oneiron-server
oneiron-server init ~/.local/share/oneiron/default
oneiron-server serve --vault-path ~/.local/share/oneiron/default
```

See the workspace [`README.md`](../../README.md) and
[`DEPLOYMENT.md`](../../DEPLOYMENT.md) for local daemon configuration,
service templates, and dictionary layout.
