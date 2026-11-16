# Off-record rooms and core dumps

An off-record room keeps its bytes in memory only. The overlay scrubs its rows when they drop.
While a room is open, the process that holds it turns its own core dumps off, so a crash file or a
debugger attached by the same user cannot read the room (ARCH-0052 threat-model note).

- Linux and Android: `prctl(PR_SET_DUMPABLE, 0)` and `RLIMIT_CORE` set to zero. Attaching a debugger
  then needs `CAP_SYS_PTRACE`.
- macOS and other unix: `RLIMIT_CORE` set to zero.
- Windows: nothing yet.

The change starts with the first off-record room the process opens and lasts until the process
exits. Freed memory may still hold a closed room's bytes, so it does not end when the room closes.
It never stops a room from opening: if the call fails, the server logs a warning.

## Turning it off

The engine runs on your own machine. To attach a debugger or keep a core file, turn suppression off
and restart `oneiron serve`:

```toml
# oneiron.toml, before the first [section]
off_record_dump_suppression = false
```

Or set `ONEIRON_OFF_RECORD_DUMP_SUPPRESSION=false` for one run. The environment stands over the
file. `true` turns suppression back on. A server with suppression off logs a warning when it opens
the vault. The setting is read when `serve` or the app's embedded engine opens the vault. A
managed vault keeps suppression on: its process is the host's, and its settings file may not name
the key.

## Checking it

`oneiron doctor <vault> --config <file>` reports what a serve started with that config file and
your current environment applies:

```json
"off_record_dump_suppression": { "enabled": true, "mechanisms": ["prctl PR_SET_DUMPABLE 0", "RLIMIT_CORE 0"] }
```

`enabled` is `null` when the settings do not resolve; `config_errors` then says why. Doctor reads
the settings, not a running server.
