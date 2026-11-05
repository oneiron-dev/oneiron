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
  `shelf:<name>` or `outbox:<name>`. `wasabi:`/`s3:`/`r2:`/`shelf:` have no adapter yet:
  each stays `custody_target_pending` with reason `no_adapter`, never green. An `outbox:`
  member ships through the Hypnos outbox below on a managed host whose supervisor names
  one; without it, it stays `no_adapter` too.

A member holds a head only once it shows that every older head, stage and temporary copy it
kept is gone, and stores an acknowledgement saying so before it answers. The vault keeps each
acknowledgement in its custody journal. A member that is unmounted, offline, locked or refuses
stays pending by name, with its reason and since when, and the next pass retries; nothing is
dropped from the set, and nothing turns green on a timer.

Passes run right after every backup (`oneiron backup`, the `[backup]` schedule and
`POST /v1/owner/backups`), when `serve` starts, and every minute while anything is pending, on a
managed host too. A save or a backup never waits on a pass and never fails because of one.

An Owners' vault deletion keeps the automatic folder beside the configured backups until
`backup_retain_until` on the vault's clock. A standing legal hold defers the drop. After that
deadline without a hold, the folder's copy of this lineage goes: its sealed head, keyless log,
stages and temporary files. Its automatic publisher does not recreate it. The shared parent,
other lineages, local keys and independent targets stay untouched. The target stays registered,
but its current acknowledgement is cleared and its status says pending; this is not a member
drain, a deletion acknowledgement or completion of outstanding custody obligations.

## The Hypnos outbox

On a managed host, the engine stages a declared `outbox:<name>` member's exact batch
under `custody/` in the supervisor-named escrow outbox (made when missing), for Hypnos
to ship to the control plane. The file contract returns the control plane's acknowledgement
to the engine. `meta.json` names the kind `hypnos_outbox`; staging alone is not an ack.

Layout (directories owner-only, files `0600`, links never followed):

- `<outbox>/custody/<namespace hex>.<vault hex>/<target id hex>/` is the member's slot:
  the host-owned directory plus the slot locator key, the hex of the full `outbox:<name>`
  id. A slot holds at most one outstanding batch.
- `b.<operation id hex>.r<set revision>/` is the batch: `meta.json` (version, the
  supervisor-given vault name, target id/kind/scope, set revision, position, head object
  id, operation id, whether the head is data-key wrapped — ids, positions and digests
  only), the exact sealed `head` (none for a log-only member), `log/f<seq hex16>` frames
  the member lacks with their `frames.jsonl` inventory (`{"seq":N,"length":M}` per frame),
  and the empty `READY` marker, written last. The shipper must wait for `READY`.
- The control plane answers inside the batch directory: `ack.json` is its acknowledgement
  (target id, set revision, position, head object id and operation id covered, deletion
  evidence, attester), which must name this member and this batch exactly — anything else
  stays pending as failed; `pending.json` is an optional note Hypnos writes while no ack
  is there.

The engine records the outstanding batch (position, head object id, set revision, data-key
wrap — no key) in the lineage journal before staging a byte, so a restart takes the
original batch's ack in without sealing it again, and never takes an ack against another
batch. A pass takes an ack in before it reads the acks: the ack is checked against the
record, kept, every local copy of the batch is removed and synced, and only then does the
journal accept it. Anything that does not go through stays pending by name — `offline`
(steady-state reads "awaiting CP custody acknowledgement"), `locked`, or `failed` with
the reason in words — and the next pass retries; nothing here refuses a save, backup,
restore or start. Removal deletes `READY` first, then the key-bearing head, then the
rest, syncing after; directories and stages the journal does not record are swept.

An acked outbox position records the control plane's acknowledgement and deletion evidence;
it is not independent delivery proof, and the outbox is no restore source — a restore
still reads the head beside the backup.

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

## Credential values in an image

A checkpoint or backup copies credential rows in their stored, sealed form. It never opens a
credential value or carries its custody key. New captures use image format 4 and may record
that a credential's exact generation had no live source key during capture. The observation
is taken under the existing custody read guard and the same row snapshot. It binds the
credential id, generation and digest of the captured row. A present entry is not proof that
the value was readable, and a custody fault records no observation.

A restore or side copy using required custody still leaves an unreadable credential sealed
or withheld, pending. If the exact row has this capture-time observation, its pending note
also says the source key was already unavailable. It does not claim when a key was lost.
Without matching evidence the existing pending note is unchanged. These observations never
decide whether a restore is allowed or authorize an erase. Re-entry, reissue and the existing
pending-batch retry and confirmation remain available.

Observations for rows moved into an owner-only payload compartment are omitted from the
image-wide metadata, so it exposes neither their identities nor their key state. Their
capture-time diagnostics remain incomplete. New-host/head routes and archived-vault
activation keep their existing diagnostics.

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
