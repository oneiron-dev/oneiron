# Key custody beside your backups

A backup never holds the vault's exterior key custody: the keys that seal claim-bound Gate
rows, which an erase destroys on the spot. They travel separately, as a sealed custody head and
a keyless log, so an erase cannot come back from an old backup, and a restore on a new host can
still open what the backup holds.

## What is published, and where

Each publication pass writes this vault's custody lineage to every member of its required
target set, then advances the anchor:

- **The folder beside the backups**: `<backups>/oneiron-custody/<namespace>.<vault>/head` (the
  latest sealed head) and `.../log/f<seq>` (the keyless log, one frame per key minted or
  retired). The head is wrapped to the vault's recovery root and, while the vault data key is
  held, to the data key as well. Every folder a pass ever published to stays a member and is
  retried at its own path, so moving `[backup] dir` never drops the old copy silently.
- **The residence home**: a machine that syncs to a home ships the same head and log to it
  (`residence:<home machine id>`); the home keeps them in `.<vault>.custody-residence/` beside
  its own vault, never inside it or its backups.
- **Declared hosted holders**: `backup.custody_targets` (`ONEIRON_CUSTODY_TARGETS`,
  comma-separated) names hosted members such as `wasabi:offsite`, `s3:<name>`, `r2:<name>`,
  `shelf:<name>` or `outbox:<name>`. This build has no adapter for them yet: each stays
  `custody_target_pending` with reason `no_adapter`, never green.

A member holds a head only once it shows that every older head, stage and temporary copy it
kept is gone, and stores an acknowledgement saying so before it answers. The vault keeps each
acknowledgement in its custody journal. A member that is unmounted, offline, locked or refuses
stays pending by name, with its reason and since when, and the next pass retries; nothing is
dropped from the set, and nothing turns green on a timer.

Passes run right after every backup (`oneiron backup`, the `[backup]` schedule and
`POST /v1/owner/backups`), when `serve` starts, and every minute while anything is pending, on a
managed host too. A save or a backup never waits on a pass and never fails because of one.

## The anchor

The anchor is the one optional step. It records the newest custody position somewhere that does
not roll back with this host, so a restore can tell a stale head from the current one. Set one of:

```toml
[backup]
custody_anchor_root = "/mnt/usb/oneiron-anchor"  # ONEIRON_CUSTODY_ANCHOR_ROOT: a directory outside the vault
# or
custody_anchor_url = "https://other-host:8443"   # ONEIRON_CUSTODY_ANCHOR_URL: another install's anchor door
```

With `custody_anchor_url`, the owner credential that door admits is handed to each command that
calls it on a pipe of its own, never in the config, the environment or a file:
`--custody-anchor-credentials-fd <fd>` on `oneiron serve` (managed or plain), `oneiron backup`
and `oneiron restore` where no vault is yet. The pipe carries one JSON object, then ends:
`{"bearer": "<token>", "binding_seed": null}`, or for a capability slip its 32-byte binding seed
as an array of 32 numbers in place of `null`. A descriptor that is not a pipe's read end, or a
pipe that carries anything else, is refused before the vault opens; on Linux a named FIFO is
refused too, because it has a pipe's type but stands on the filesystem that holds it, not on the
kernel's own pipe (FIX 11068). Without the flag the door is never called: the anchor step stays
`custody_anchor_pending`, and a restore checked against that door is refused. An app's embedded
engine has no pipe: it reads the same object once at start from the app's keychain, under
`custody_anchor_credentials`, and keeps it for every wake. A keychain that keeps none leaves the
door uncalled, as above; one whose object does not decode is logged and the door is not called
either. A server with `custody_anchor_root` set serves that root
to other installs: `GET /v1/owner/custody-anchor?vault=<64 hex>&namespace=<32 hex>` answers
`{"record": "<hex>" | null}`, and `POST /v1/owner/custody-anchor` with
`{"expected": "<BLAKE3 hex of the record read>" | null, "record": "<hex>"}` answers
`{"advanced": true | false}`. A record carries a position and a tag, never a key. The anchor
advances only once every member acknowledged the head at that position, and never backwards.

With no anchor set, heads still publish, the anchor step stays `custody_anchor_pending`, and a
restore on a new host uses the head it finds and says rollback is not proven. A retirement still
completes: `custody_retirement_complete` once every required target acknowledged it, with the note
`rollback not proven: no custody anchor configured`.

## Status

`oneiron doctor` (`location.backups.custody`), `GET /v1/owner/status` (`backups.custody`) and
`oneiron backup` (`custody`) show:

- `state`: `custody_none`, `custody_published`, `custody_target_pending`,
  `custody_anchor_pending` or `custody_fenced` (another install took the custody over in a
  disaster recovery), with `log_seq`, `published_seq`, `anchored_seq` and `detail`.
- `data_key_wrapped`: `false` while a member holds a head sealed when the data key was not
  held; the next pass with the key unlocked seals it again.
- `retirement`, once any key was retired: `state` is `custody_retirement_pending` or
  `custody_retirement_complete`; `names` lists each step still owed, in order:
  `custody_retirement_pending` (a retirement not handed off yet), every
  `custody_target_pending(<target id>)`, then `custody_anchor_pending` (only while an anchor is
  set; with none, `note` says rollback is not proven). `targets` lists every
  member with its `acked_seq` and, while pending, `pending` (`offline`, `locked`, `denied`,
  `no_adapter`, `moved` or `failed`), `pending_since` and `detail`.

An erase's receipt read (`vault.records.erase_sweep`) carries the same for the erased records'
keys, claim keys and body instance keys alike: `custody: {"state": ..., "pending": [...],
"recall": ..., "note": ...}`. `body_shared_owner_retained` names a body another record still
holds: its key retires with that holder's release. `recall` says bytes already read before the
erase cannot be recalled. The erase itself is done and stays done on this host from the moment it
returns; `custody` says where the old copies stand.

## Body instances

Every body a vault keeps, a code-run result's or an ASSET's, as a file or inline in its row, is
one instance whose 32-byte key custody holds (kind `0x02`). A sealed vault's file is sealed under
it; a plain vault's file is plain and read with no key. A checkpoint or backup carries every body
sealed under its instance's key alone, and an inline body leaves its row to travel that way, so no
image holds a key or a wrap that recovers one. A delete keeps the key, so the restore window stays;
an erase retires it, and the old copies become unreadable once every required target acknowledged
the retirement. A restore needs each instance live (landed and read back) or retired (its rows
pruned as the erase pruned them); one custody holds neither refuses as
`body_key_custody_unavailable`.

Row-held responses are body instances too: a turn program's kept send body, an LLM step's saved
payload, a terminal `dreamer.step` claim's inline response and a code run's replay outcomes. Each
takes its instance the first time a checkpoint carries its row, and again whenever its bytes
change; no live read or write touches custody. The image row holds a stub, never the response.
Each instance is kept against every owner the row was stamped with (its actor, subject and source
rows), past the row's own life: an erase of any owner retires every instance an image of the row
was carried under. A restore under a live instance lands the exact bytes (a signed claim exactly
as it was signed); under a retired one the row keeps its erased form: a step its evidence, a saved
payload an erased state that is never asked or paid for again, a replay its terminal evidence with
each outcome failed, and a claim the erase's shell. Activating an archived vault prunes the same
way and reads every body it keeps back under its own custody before the archive lifts; its report
carries `custody_note` and `training_note` as a restore's does.

The server's own row-held responses are instances the same way: each HTTP idempotency entry
(request, headers, target and response) and each kept media job with each of its clips. An entry
is stamped with its caller beside the rows it served and re-admits; a job with the actor that
asked and its request's subject, never its payer. An erase of an owner leaves an entry its erased
form, which answers `idempotent_response_erased` until the entry expires (never a miss, never a
second run), and a job its skeleton with the request scrubbed and the end terminal, which is never
taken up, resumed or resubmitted, its clips gone. Expiry, cancel and removal are deletes, which
keep every key. A media job is the live vault's in a restore that keeps current authority, with
its binding; the image's copy is passed over.

## Restore

A restore on a host without the image's custody reads the head beside the backup. With an
anchor set, a head the anchor does not vouch for, or a bad seal, chain or coverage, refuses the
restore. With none, it restores and `custody_note` says rollback is not proven. An image for
which no head is found (none beside the backup, a wake, a migration, an engine restore, or a
vault that carries only the old untyped custody marker) restores without the claim-bound Gate
rows whose keys stayed on the old host, and names them in `dropped_gate_decisions`.
