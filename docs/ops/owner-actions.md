# Your vault: where it lives, backups, restore, export, and one-act approvals

Everything here works with no model configured. Each action has a CLI command and, for a
running server, a route under `/v1/owner`. The CLI commands read the same config as
`oneiron serve` (`--config FILE`, `--vault-path DIR`, `ONEIRON_*`). Commands that open the
vault need the server stopped, because one process holds a vault at a time. Two commands
also work while `serve` runs: `restore --rehearse`, which never opens the vault, and
`backup --list`. A command that finds the vault in use tells you which route to call
instead.

## Where your data lives

```sh
oneiron doctor /path/to/vault            # add --config FILE if it is not the XDG default
```

`doctor` prints the engine report plus a `location` section:

| Field | Meaning |
|---|---|
| `location.vault` | The vault directory, absolute. |
| `location.disk_bytes`, `location.disk` | Space the vault directory takes on disk. |
| `location.backups` | Backup directory, how many backups, the newest one, the schedule (`every_hours`, `keep`). |
| `location.last_export` | The latest recorded export receipt: when, format, size, who. Writing the receipt is best effort, so an export can succeed without a new one. |
| `location.secret_scan` | `on` or `off`. |

While `serve` holds the vault, `doctor` still prints the path, size and backups, and says to ask
the server for the rest: `GET /v1/owner/status` returns the same `location` object. A serve
setting that does not resolve never hides where the vault is: `doctor` reports the vault and
lists the problem under `config_errors`.

## Back up

```sh
oneiron backup                 # take one now; prints the file, its checkpoint id, and what was pruned
oneiron backup --list          # this vault's backups, oldest first
oneiron backup --dir DIR --keep 14
```

A backup is the engine's checkpoint image: the vault's own records, without indexes. A
restore rebuilds the indexes, and vectors are re-embedded by the next `serve` that has an
embedder. Files are named `<vault-name>-<path hash>-<sequence>-<UTC time>-<id>.oneiron-backup`.
The path hash keeps two vaults that share one backup directory from listing or pruning each
other's files. Each backup takes the next sequence number, and retention keeps the highest
numbers, so a clock that steps back never makes a new backup look oldest, and the backup just
taken is never the one pruned. A backup named before sequences (no `<sequence>` field) lists as
older than every numbered one. The file is owner-only (`0600`) and sits in an owner-only directory (`0700`). A backup
is written under a hidden partial name and renamed into place only once complete. Backups are
not encrypted yet and include device key material, so keep `--dir` on a local disk, not a synced
or cloud folder (see *Limits*).

`oneiron serve` can take backups on its own. The schedule is opt-in; turn it on in the config
file or environment:

```toml
[backup]
enabled = true        # ONEIRON_BACKUP_ENABLED — default false; `oneiron backup` works either way
dir = "~/oneiron-backups"   # ONEIRON_BACKUP_DIR — default: <vault>.backups beside the vault
every_hours = 24      # ONEIRON_BACKUP_EVERY_HOURS
keep = 7              # ONEIRON_BACKUP_KEEP — newest kept; older ones are deleted after each new backup
```

The schedule is off by default because erasing a record does not yet reach backup files (see
*Limits*). With it on, the server checks every minute whether the newest backup is older than
`every_hours`. The newest file on disk is its only state, so a restart or a manual backup is
counted. Only a self-hosted local vault backs up this way; hosted and relay deployments back up
through their host. The server also takes a backup on demand: `POST /v1/owner/backups`. `GET
/v1/owner/backups` lists the backups.

## Rehearse a restore

```sh
oneiron restore FILE --rehearse
oneiron restore FILE --rehearse --scratch /tmp/look-here   # keep the copy, at /tmp/look-here/vault
```

A rehearsal restores the backup into a scratch directory, opens it through every open check,
verifies its gate receipts against the vault's current key custody, and reports:
`checkpoint_id`, `kinds` (live entities by kind), `entities`, `text_documents`,
`pending_embeddings`, `verified`. The live vault is never opened, so a rehearsal is safe while
`serve` runs; on the server, retention waits until the rehearsal has read its backup. `--scratch DIR` names a new directory the rehearsal creates and keeps, with the
copy in `DIR/vault`; without it the copy goes in a new temp directory that is deleted
afterwards. A failed rehearsal removes what it created. On a running server:
`POST /v1/owner/backups/rehearse` with `{}` (the newest backup) or `{"file": "<name>"}`.

## Restore

```sh
# stop `oneiron serve` first
oneiron restore FILE
```

A restore brings back your **content** as it stood at the backup: notes, claims,
conversations, tasks, files and receipts. It keeps the vault's **current authority, consent and
policy** (ARCH-0038, RD-20). Every kind of stored row has one restore class in the engine, and
a row nobody classed is never restored silently. What stays as it is now:

- the authority log (root, devices and keys, paired slips, revocations), device identity and
  leases, freshness pins and clocks, gate-decision key custody, and one-shot approvals;
- policy switches and their receipts: the secret scan, manifest trust and quarantine, the
  policy change ledger and notification rules, model and routing settings, and your `settings`
  dials;
- consent: voice consent and its withdrawals, consent-graduation rulings and thresholds, and
  widening requests. Material erased by a withdrawal (voice prints, samples, reference packs)
  stays erased;
- erasure fences, legal holds and key-retirement intents;
- the record of acts that already left the vault: sends and their dedupe ledgers, exports,
  secret materializations and usage events. A send is never made twice.

A slip revoked after the backup stays revoked. A device added after the backup keeps working.
An approval spent after the backup stays spent. A secret scan switched on after the backup stays
on.

The restored copy is built beside the vault, then swapped into place in one atomic step while
the restore holds both vaults, so a server starting meanwhile can open neither half-way. Your
previous vault is kept whole as `<vault>.pre-restore-<UTC time>`; nothing is deleted. To undo,
stop the server and swap the directories back. If the directory cannot be synced after the swap,
the restore still reports success, with a `durability_warning` that names the previous vault:
the swap is done, but a crash before the disk flushes may undo it.

A restore refuses, and changes nothing, when:

- the vault is in use (stop `serve`);
- the backup belongs to another vault (each vault has its own store id, minted at its first
  open);
- something that holds authority together with content changed since the backup, since
  restoring it would roll a permission back: grants, policy manifests, standing consent grants,
  secret custody, connector keys, channel identities, outbound grants (using one is not a
  change), machine identities, published artifacts; for a room, skill, agent, contact, claim or
  task the backup holds: room roles and membership (who is in a room, their role, how far back
  they read), a skill quarantine, an agent switched off or narrowed, a contact revoked, opted
  out or rebound to another party, a relationship membership retracted, a task cancelled, reassigned or its ask class
  narrowed; or an e-sign ceremony the backup holds (a signature, rejection or void since). The
  refusal names what moved. Content edits do not block the
  restore, and a room, document or claim created after the backup is simply not in the restored
  vault. Rehearse with `--scratch` to read the old content beside the vault instead;
- the restored vault would make someone an owner or member who is not one now: a person
  deleted, merged away or removed from a shared vault since the backup does not get their
  authority back;
- a claim was erased after the backup. Its receipt key is gone, and a restore never brings a
  destroyed key back. Take a new backup after an erase.

The restore runs from the CLI only, because the server cannot swap out the vault it is serving.

## Export

```sh
oneiron export --format md --out vault.md      # toon (default), md, json, yaml or txt
oneiron export --format json > vault.json      # stdout when --out is omitted
```

On a running server, `POST /v1/core/facade/export` with `{"format": "md"}` and an owner
credential. Each export tries to write a receipt (time, format, bytes, digest, who), and
`doctor` shows the latest one recorded. The receipt is best effort: if it cannot be written the
export still succeeds, a warning is logged, and `last_export` stays as it was. An export is a
readable archive of your knowledge. It is not a backup: restore from a backup file.

## Secret scan switch

```sh
oneiron secret-scan            # current setting and every change to it
oneiron secret-scan off        # owner only; writes a receipt
oneiron secret-scan on
```

Routes: `GET /v1/owner/secret-scan` and `POST /v1/owner/secret-scan` with `{"mode": "off"}`.
`off` skips the write-door scan on ingest. Serve and export still redact credentials either
way. Each change is receipted with its revision, the owner who made it and the previous
setting. Only a live owner of the vault can switch it.

## Approve an import in one act

An import batch is a JSON file:

```json
{
  "source_id": "chatgpt",
  "claims": [
    { "subject": "<32-hex entity id>", "source_record_id": "conv-17#3",
      "predicate": "profile.name", "value": "Ada",
      "occurred": { "start": 1759900000, "end": 1759900000 }, "learned_at": 1759900000 }
  ]
}
```

`source_id` is a registered import source (`chatgpt`, `claude`, `gemini`, `markdown`, `okf`,
`mem0`, …).

```sh
oneiron import preview batch.json > preview.json   # the exact batch, ids filled in, and its digest
oneiron import approve preview.json --digest <digest from preview>
oneiron import decline preview.json --digest <digest from preview>
```

`approve` admits every claim of the previewed batch as approved, in one transaction, with one
approval receipt. A batch that changed after preview is refused whole. `decline` writes one
refusal receipt and admits nothing. A batch takes one decision: once any owner approves or
declines it, a second approve or decline, by any owner, is refused (409, `already_decided`)
and the first decision stands. Routes: `POST /v1/owner/imports/preview` with the batch, then
`/v1/owner/imports/approve` or `/decline` with `{"batch": <preview.batch>, "digest": "<digest>"}`.

## Approve or decline an agent run in one act

When an agent run's proposals wait for your consent, the whole run is one unit:

```sh
oneiron runs pending                       # runs with proposals waiting, and how many
oneiron runs show RUN_ID                   # what it proposes, and its bundle id
oneiron runs approve RUN_ID --bundle <bundle id from show>
oneiron runs decline RUN_ID --bundle <bundle id from show>
```

The bundle id binds exactly the proposals you reviewed: `show` and the route read the proposals
and compute the id in one read. Values, predicates, run ids and labels are shown through the same
credential redaction as serve and export, even with the secret scan off; the stored proposal is
unchanged. Each run also has a `run_ref`, which `show`, `approve` and `decline` (and the routes'
`run_id`) accept in place of the run id. If the run changed
since, the action is refused (409) and you review again. Approve lands every proposal as approved; decline closes
every one as rejected. Either way one receipt represents the run. Routes: `GET
/v1/owner/runs`, `GET /v1/owner/runs/review?run_id=…`, `POST /v1/owner/runs/approve` or
`/decline` with `{"run_id": "…", "bundle_id": "…"}`.

## Calling the owner routes

Every `/v1/owner` route needs a verified, unattenuated owner slip held by a live human owner of
the vault. That is the slip the first-owner link from `oneiron token bootstrap` redeems to.
Other credentials get the same 403: another person, an agent-class slip, a slip narrowed to
some verbs, or the host root. Managed vaults are owned through their supervisor, and these
routes refuse there. Each act rechecks the slip and your ownership in the transaction that
commits it, so a request still queued when its slip is revoked changes nothing. From a shell, with the slip in `ONEIRON_SECRET` and its binding seed in
`ONEIRON_BINDING_KEY`:

```sh
oneiron api raw GET /v1/owner/status
oneiron api raw POST /v1/owner/backups
oneiron api raw POST /v1/owner/secret-scan --data '{"mode":"off"}'
```

## Limits today

- Erase does not reach local backups yet. A backup keeps the plaintext of anything erased after
  it. Restoring that backup is refused when the erased record had receipts bound to a key the
  erase destroyed. ARCH-0038 orders an exterior erasure ledger before snapshot storage ships,
  and that ledger is not built, which is why the schedule is opt-in. After an erase, delete the
  backups taken before it if they must not keep the data.
- Device replicas that synced after the backup can send newer data back to a restored vault.
- To cut someone's access, revoke their slip; a revocation is authority and survives a restore.
  Deleting a person who is not a vault owner or member is content, and an older backup brings
  that person back.
- Backups are not encrypted yet, and they include device key material. Keep `--dir` (and
  `[backup] dir`) on a local disk, not a synced or cloud folder. Encryption comes with the vault
  cipher work.
