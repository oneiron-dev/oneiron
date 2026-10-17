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
| `location.backups` | Backup directory, how many backups, the newest one, the schedule (`every_hours`, `keep`), and `restores`: every restore this vault came from, oldest first (`checkpoint_id`, `restored_at`, `reason`). |
| `location.last_export` | The latest recorded export receipt: when, format, size, who. Writing the receipt is best effort, so an export can succeed without a new one. |
| `location.secret_scan` | `on` or `off`. |

While `serve` holds the vault, `doctor` still prints the path, size and backups, and says to ask
the server for the rest: `GET /v1/owner/status` returns the same `location` object. A serve
setting that does not resolve never hides where the vault is: `doctor` reports the vault and
lists the problem under `config_errors`.

Both also print an `embedder` section, which keeps three things apart:

| Field | Meaning |
|---|---|
| `embedder.configured` | What `[embedder]` asks for: provider, `model_id`, `dimensions`, and a local model's `device` as written (`auto` resolves at load) and `quant`. Absent when no provider is configured. |
| `embedder.persisted` | What the vault pins: the `model_id` its vectors came from and their `dimensions`. |
| `embedder.loaded` | The model a running server loaded on this machine, checked and admitted by the vault: `repo`, `revision`, `dimensions` (the width its module chain was checked to give), `device` (`cpu`, `metal` or `cuda`, never `auto`), `quant`, and `artifacts`: `pinned_digests` (each file's size and sha256 at the pinned revision), `unpinned` or `model_dir` (an operator's directory, read as found). Absent for an endpoint provider, whose model runs elsewhere. |
| `embedder.dense`, `embedder.reason` | Whether dense recall runs: `ready`; `loading` (it runs on its sparse signals until the model is admitted); `refused`, with the reason the last load or admission failed (the server tries again); `not_configured`; or, from `doctor`, `not_observed`. |

`doctor` loads no model, so it never reports one as loaded: its `dense` is `not_observed`. The
running server's `GET /v1/owner/status` is what says which model serves, and `serve` logs the same
facts once the vault admits the model (`embedder model loaded and admitted`).

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
is written under a hidden partial name and renamed into place only once complete. Each backup
is sealed: the records and the result bodies they name are one file of encrypted chunks under a
key derived from the vault's data key, and a restore checks the whole file before it makes
anything. The first backup mints that data key, wrapped to this device's keystore, when the vault
has none; a rehearsal or a restore on this device unlocks it from that wrap, and one on another
host from a password, passkey or escrow wrap the backup carries (*The vault key on a new host*).
The install that takes a backup signs it, and a restore checks that signature first. While any
legal hold stands, no backup is pruned, whatever `keep` says.

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
previous vault is kept whole as `<vault>.pre-restore-<UTC time>`; nothing is deleted. It still
binds the gate-decision key custody the restored vault keeps, so it is archived: it opens and
reads, but refuses every write, erase and key retirement, which would otherwise reach the
restored vault's keys. A restore that stops part-way through the swap (a crash, a power cut)
leaves the same rule: whichever vault sits at the vault's path is the live one, and the other
opens archived. To use the archived vault again, activate it:

```sh
oneiron restore --activate /path/to/vault.pre-restore-<UTC time>
```

Activation gives it key custody of its own beside it, holding only the keys still live in the
restored vault's custody, the way a rehearsal's copy gets its own; from then on it is a side
vault you can serve from its own path (`--vault-path`), and an erase in either vault never
reaches the other's keys. If the directory cannot be synced after the swap,
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
  out, rebound to another party or marked as first met in public (a contact first met in public
  since the backup also refuses), a recipient's observed jurisdiction that moved, a
  relationship membership retracted, a task cancelled, reassigned or its ask class narrowed; or
  an e-sign ceremony the backup holds (a signature, rejection or void since). The refusal names
  what moved. Content edits do not block the restore, and a room, document or claim created
  after the backup is simply not in the restored vault. Rehearse with `--scratch` to read the old content beside the vault instead;
- the restored vault would make someone an owner or member who is not one now: a person
  deleted, merged away or removed from a shared vault since the backup does not get their
  authority back;
- a claim was erased after the backup. Its receipt key is gone, and a restore never brings a
  destroyed key back. Take a new backup after an erase.

The restore runs from the CLI only, because the server cannot swap out the vault it is serving.

## Agents refused after the host clock ran ahead

Each agent request carries a holder proof signed with the agent's clock time, and the vault
takes it only within 60 seconds of its proof clock. That clock follows this host's clock but
never runs back, so a replayed proof cannot get in. If the host clock jumps ahead while an
agent calls (a bad NTP answer, a VM restored with the wrong time) and is then set back, the
proof clock stays ahead. Every agent then gets 401 until the host clock catches up, and a
restart does not help. You can tell this 401 from a bad credential: its message says
`proof_clock_ahead` and names the command below, and the server log gives both clocks.

```sh
# stop `oneiron serve` first
oneiron recover-clock
```

It moves the proof clock back to this host's clock and prints where it stood, where it stands
now, and the gap in seconds:

```json
{
  "old_floor": "2027-10-11T07:02:11.000Z",
  "new_floor": "2026-10-11T07:05:40.000Z",
  "gap_secs": 31535791,
  "not_before": "2026-10-11T07:05:40.000Z"
}
```

No proof signed before `not_before` gets in again. The vault also keeps the nonce of every
proof it admitted while the clock was ahead, so none of those can be replayed either. Start
`oneiron serve` again, and agents get in with their next request. Only the proof clock moves.
The clock that stamps what the vault records stays where the jump left it until the host clock
catches up, so anything recorded meanwhile carries that later time.

It refuses, and changes nothing, when:

- the vault is in use (stop `serve`);
- the proof clock is not ahead of this host's clock: there is nothing to recover;
- the host clock stayed ahead for more than a day while agents connected, or agents connected
  while it was ahead under a version without `recover-clock` (it kept a nonce for a minute).
  The vault keeps a proof's nonce for a day, so it no longer remembers every proof from that
  time. It must keep refusing every proof signed up to the time the refusal names, which is
  still ahead of the host clock, so lowering its clock would not let agents in. They get in
  again once the host clock reaches the proof clock.

## Housekeeping

A running `oneiron serve` retires, on its own, what the vault already said would retire. Each
minute it checks which sweeps are due and runs them off the request path, each within its own
bound; a pass stops starting sweeps after 20 seconds and the rest run on the next one.

| sweep | every | what it retires |
|---|---|---|
| `secret_lease_expiry` | at each expiry; hourly | secret leases past their expiry, and their registered files |
| `critical_confirm_expiry` | at each window's end; hourly | critical-write confirms still open 300 s after the write: the claim goes back to Proposed |
| `symbol_lease_expiry` | 5 min | symbol-lease holds past their expiry |
| `voice_print_retention` | at each deadline; hourly | voice prints past their retention deadline (a print past it already matches no one) |
| `esign_expiry`, `esign_seal_backstop` | 15 min | signing windows that ran out; seals whose trigger was missed |
| `commitment_lapse` | 15 min | open commitments past their due time |
| `gate_decision_retention` | hour, and at start | gate decisions past the horizon you set |
| `hard_erase_sweep` | day; hour while an erasure waits | the history an erase left in sync carriers (the 30-day erasure deadline) |
| `ppr_cache_eviction` | day | cached graph walks older than the longest serve window (168 h) |

The signing sweeps and the cache eviction walk their records a page at a time and go on from
where they stopped on the next pass. A sweep that fails, or that could not finish some of its
records, is logged by kind and retried within the hour; it never stops the others. The vault
keeps each sweep's schedule, so a restart neither repeats a sweep early nor drops one. Before an
erasure runs, the server writes down and closes the sync windows no client is using, so their
history can be compacted; a window in use waits for the next run. Compaction drops history, which is
itself an erase, so it runs only for a due erasure obligation: a run with none leaves every window as
it was. Quarantine retention and the dropped-obligation audit still run daily.

Every hour the server also runs `git gc --auto` on each repository it serves, one at a time, under
a git exchange permit it waits for and the repository's lock. Maintenance never turns a push away:
a repository a push holds waits for the next hour, and a push that comes while maintenance runs
asks for the repository, the maintenance ends its git at once, and the push goes ahead. Git is
terminated rather than killed, so it removes its own lock files first. A push itself starts no
maintenance. Git reads no system or global configuration here and runs no hook; a repository whose
own configuration sets `gc.recentObjectsHook` (a command gc would run) is left unmaintained and
counted as refused.

A managed vault that is stopped between uses tells its supervisor when to wake it: a
`housekeeping` entry in its wake ledger carries the next secret-lease expiry, voice-print
retention deadline, critical-confirm window or waiting erasure. Cache and retention hygiene never
wake a vault.
Signing reminders, consult digests, moderation-hold pruning, the TASK attribution pump, attempt
lease reclaim and self-heal detector runs need authority only the host holds; the report lists
them as `host_only` with the reason.

To run every sweep now, on a stopped vault, and print the report:

```sh
oneiron maintain
```

It exits nonzero when a sweep failed or could not finish some of its records. It also runs repairs you name: `--rebuild-vector-graph`
(with `--heal-invalid-vectors` to leave out stored vectors that do not validate),
`--recompute-short-ids`, `--backfill-gate-claim-index`, `--migrate-conversation-dags`, and
`--reindex-text`, which rebuilds the text index from the text each record was indexed with; it is
the repair for a vault refused after an analyzer or dictionary change. A running server answers
`POST /v1/owner/maintain` with the same report, without the repairs.

## Export

```sh
oneiron export --out vault.zip                 # the whole-vault archive (format `archive`)
oneiron export > vault.zip                     # stdout when --out is omitted
```

The export is one ZIP archive (OF-222): `manifest.json`, one JSONL file per record kind under
`records/` (`records/entity/<kind>.jsonl` per entity type, then `edge`, `pack`, `agent_pack`,
`derivation_envelope`, `run` and `result_body`), and each attached file once under
`files/<blake3>` (skill and pack source files, code-run result bodies). The manifest lists every
record file and attached file with its length and BLAKE3, and an import refuses an archive whose
members disagree with it. It is plaintext and re-imports into a fresh vault
(`Vault::import_whole_vault_archive`, or `oneiron import archive vault.zip` with `serve` stopped).
Credentials inside records are nulled by the serializer. Result bodies go through the release
scan: a text or binary body that passes is a file under `files/<blake3>`; tainted, secret-marked
and credential-bearing bodies are withheld and named in `result_body.jsonl`.

Your own archive also carries your keys, by default: each active secret-custody record's value,
in `records/secret_custody.jsonl` (the custody codec, base64), so a re-import keeps them. Keep
the archive as safe as the keys in it. To leave the values out, export with
`--include-secrets false` (`{"include_secrets": false}` on `vault.export`): each custody record
then goes as its handle and value-less metadata, the manifest says `secrets_included: false`, and
a re-import lists those as `missing_secrets` to re-enter. A caller off this device gets values
only for portable records (device-bound ones go as handles); suspended records always go as
handles; an export-first removal's archive, like any export to a contact or share, carries no
custody record.

`oneiron export --format okf --out vault-okf.zip` is "Export to OKF": the vault as an Open
Knowledge Format v0.1 bundle (Google's markdown-plus-YAML-frontmatter format) for importing into
other tools. Each entity is one concept at `<kind>/<id>.md` with `type`, `title`, `description`
and `timestamp` frontmatter; graph edges are markdown links; claim evidence is a `# Citations`
list; `index.md` files list each folder. It is lossy by design and says so in its root
`index.md` and in every file's `oneiron_copy: "lossy"`: it drops bi-temporal validity,
confidence, approval and lifecycle, typed edge values, run results, source packages and every
custody secret, and it does not re-import as a vault. The archive is the full copy.

A diary is exported as a read of it (OF-490), through the diary door with the reason `export`:
only the entries the exporter's `diary.read` Grant covers (`POST /v1/owner/diary/grants`) are
read. Each agent's read is logged in its own read log, where it sees it, and on the export
receipt. An agent that reviews each read first (on for Eiri) gets a pending review and its
entries stay out until it says yes; one yes admits one export. Every held entry is named in the
manifest's `diary_holds` (`not_covered_by_grant`, `agent_review_pending`, `declined`, or
`read_log_unavailable` when the read log could not be written). An export-first removal reads as
the removed owner, under their own Grants.

On a running server, `POST /v1/core/facade/vault.export` with `{}` (or `{"format": "archive"}`)
and an owner credential; the reply's `archive` is the ZIP in standard base64. Each export tries to
write a receipt (time, format, bytes, digest, who, diary reads), and `doctor` shows the latest one
recorded. The receipt is best effort: if it cannot be written the export still succeeds, a warning
is logged, and `last_export` stays as it was. An export is your exit path, not a backup: restore
from a backup file, the vault's encrypted snapshot.

## Secret scan switch

```sh
oneiron secret-scan            # current setting and every change to it
oneiron secret-scan off        # owner only; writes a receipt
oneiron secret-scan on
```

Routes: `GET /v1/owner/secret-scan` and `POST /v1/owner/secret-scan` with `{"mode": "off"}`.
With the scan `on`, a secret the write door can place in text or in a field goes to secret
custody, and the record keeps its handle in its place: `[secret sc12]` inside text, or `sc12` as a
field's whole value. The rest of the write lands. A recovery phrase, a key inside a binary file
and anything else the door finds but cannot place still refuse the whole write.
`off` skips the write-door scan on ingest. Serve and export still redact credentials either
way. Each change is receipted with its revision, the owner who made it and the previous
setting. Only a live owner of the vault can switch it.

## Reveal a secret by its handle

An agent never reads a secret as its value, only as its handle. When it needs the value for its
model it calls `reveal({handle, why})`. If a standing grant covers this agent's connection, this
class of secret and this project, the value is delivered with a quiet receipt. Otherwise you are
asked once: approve once, approve and stop asking (a standing grant on exactly that connection,
class and project), or deny. A doored or cross-vault credential is never revealed to a model.

```sh
oneiron api raw GET '/v1/owner/secrets/reveals?pending=true'    # asks, each with its card and expected_digest
oneiron api raw POST /v1/owner/secrets/reveals/answer \
  --data '{"reveal": "<32 hex>", "expected_digest": "<64 hex>", "outcome": "once"}'
oneiron secrets reveal --handle sc12 --reason "rotate the deploy token"   # value to stdout, receipt to stderr
```

`POST /v1/owner/secrets/reveal` with `{"handle"}` or `{"name"}` and `"reason"` returns the value as
`value_base64`, in that reply only. Each reveal's receipt names the handle, the class, the why or
reason, the connection and who answered, never the value. An agent's granted reveal is a 15-minute
lease to its model connection, and an unanswered ask lapses after an hour. A standing grant is
revoked in the consent registry like any other.

## Bind a secret so an agent can use it

An agent can hand a secret to a trusted operation, such as Slack's `auth.test`, with
`self.use({handle, operation})`. The value goes to that operation's door and never to the agent's
model. The only grant is the secret's binding for the operation's effector. A secret the mask on
write found has no binding, so the agent's use is refused, and the refusal names this door:

```sh
oneiron api raw POST /v1/owner/secrets/bind \
  --data '{"handle": "sc12", "effector": "connector:slack"}'
```

Name the secret by `handle` or `name`. `tier_ceiling` is the binding's rung, 0 (doored) by default
and never above the class's live floor, and `scopes` defaults to `["read"]`. A binding for the same
effector is replaced. The reply lists the record's bindings and the Gate record that keeps the
binding. A portable secret's new binding reaches your other machines as a signed custody transition.

## Hand a served repository's origin to another host

A repository this vault serves at `/git/<repo>` has no origin authority until you set one. With
none, this vault takes its pushes. Setting one names the epoch, the residence (`local-vault` or
`cloud-vault`), the writer host and whether this copy is a read-only mirror:

```sh
oneiron api raw GET '/v1/owner/origin-authority?repo=demo'   # the row, and this host's machine id
oneiron api raw POST /v1/owner/origin-authority \
  --data '{"repo": "demo", "expected_epoch": null, "residence": "local-vault"}'
```

`writer` defaults to this host's machine id; name another host's to hand it the repository.
`expected_epoch` is the epoch you read (`null` before the first cutover), and a cutover whose epoch
moved since is refused. One is also refused while the repository has a push or publication
in flight; retry once it drains. After the cutover, a push here runs under this host's lease when
it is the writer. Otherwise the push gets 403 naming the epoch: at a mirror (`"mirror": true`),
or when another host writes the repository. Reads still serve. Only a live owner can cut over.

## Mirror a served repository outward

The repository's origin pushes its published refs to one https mirror (GitHub, GitLab, a Gitea)
on a cadence you set. **That cadence is the repository's real RPO**: a promoted replica or the
mirror holds what the last push carried, and nothing newer. Put the mirror's push token into
custody first, bound to `origin:mirror-push`, then name the mirror:

```sh
oneiron api raw POST /v1/owner/secrets/register --data '{"name": "demo-mirror-token",
  "class": "custody-portable", "rung": 0,
  "bindings": [{"effector": "origin:mirror-push", "scopes": ["read"]}],
  "value_base64": "<base64 of the token>"}'
oneiron api raw POST /v1/owner/origin-mirror --data '{"repo": "demo",
  "url": "https://github.com/you/demo.git", "secret_ref": "demo-mirror-token",
  "every_secs": 900}'
oneiron api raw GET '/v1/owner/origin-mirror?repo=demo'    # the target and its last push
oneiron api raw POST /v1/owner/origin-mirror/push --data '{"repo": "demo"}'   # push now
oneiron api raw DELETE '/v1/owner/origin-mirror?repo=demo' # stop; the mirror keeps what it has
```

The token goes to git as a basic-auth header with the user `x-access-token` (GitHub's; pass
`"user": "oauth2"` for GitLab). It is handed to the one push inside the custody door, never
written to git config or disk. Every push is forced and carries only refs this vault published,
never keep-refs or anything a push has not landed; a ref you delete here is deleted at the mirror
on the next push. `every_secs` is at least 60. Only the host that is the repository's origin
pushes: a host holding a mirror copy, or another host's epoch, does not. A failed push is
recorded on the target (`last.failure`) and tried again next cadence. Git LFS objects are not
pushed.

The mirror's `main` is read-only. Work done on the mirror side comes back in through this
vault's door: push it here as `refs/imported/<source>/<branch>` (for example
`git push origin HEAD:refs/imported/github/fix-typo`), where the change index stamps it as a
mirror import. Merge it here; the next mirror push carries the merge out. Imported refs are never
pushed back to the mirror.

## Approve an import in one act

To bring your ChatGPT, Claude, Claude Code or Codex history itself in, use
`oneiron import <source> <path>`: see [Import your history](import-history.md). The batch
below is for claims that already exist as a batch.

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
unchanged. Each run also has a `run_ref`, which `show`, `approve` and `decline` take as
`--ref RUN_REF` (and the routes as `run_ref`) in place of the run id. A run id is any text, so the
two are separate fields and one is never read as the other. If the run changed
since, the action is refused (409) and you review again. Approve lands every proposal as approved; decline closes
every one as rejected. Either way one receipt represents the run. Routes: `GET
/v1/owner/runs`, `GET /v1/owner/runs/review?run_id=…` (or `?run_ref=…`), `POST /v1/owner/runs/approve` or
`/decline` with `{"run_id": "…", "bundle_id": "…"}` (or `"run_ref"` in place of `"run_id"`).

## Settle an open contradiction

When two claims disagree and nothing settled them, the vault keeps a `conflict.open` marker
beside both, and both stay active. An observed want next to a stated one is held this way:
the observed one never outranks what you said. The marker stays open until you answer it.

- `GET /v1/owner/conflicts` (optionally `?subject=<32 hex>&limit=<n>`): every unanswered
  marker, oldest first, with its contested predicates and each member's value, source,
  approval and lifecycle.
- `POST /v1/owner/conflicts/settle` with `{"marker": "…", "settlement": "keep", "keep": "…"}`
  keeps that member and supersedes every other live member with it. `"hold_both"` leaves every
  member active, and `"dismiss"` says the marker named no real contradiction; neither takes a
  `keep`. A generated claim still never supersedes what you stated.

Each answer writes a `conflict.resolved` claim naming the marker, plus one receipt. The marker
itself stays as the record. A person or agent you delegate `memory.conflict_review` on a subject
may settle that subject's conflicts too, but an agent never closes a claim you stated. The
Dreamer asks its decision ladder only about conflicts its own delegation covers. Anything it
can't settle stays here for you.

## Review cleanup

The cleanup job files away husks: a person an extraction minted and never learned anything
about, a summary with nothing left in it. Its only verb is archive, and an archived record comes
back whole. While its integrity checks are open (ARCH-0066), the job only proposes: nothing is
archived until you accept, and the engine refuses the automatic posture.

- `GET /v1/owner/cleanup`: the posture, the done-task retention in days (`0` turns that arm
  off), the open proposals with what accepting would archive, the digests of what was
  archived, and everything still archived: records (`"kind": "record"`) and finished queue
  attempts (`"kind": "completed_attempt"`), in one list.
- `POST /v1/owner/cleanup/accept` or `/reject` with `{"proposal": "<id>"}`. Accept archives the
  candidates that are still empty and records one digest; a proposal already answered is a 409.
- `POST /v1/owner/cleanup/restore` with `{"entity": "<id>", "kind": "<kind>"}`, both copied
  from that list, brings back the item: a record (`kind` may be left out for one), or an
  attempt, which returns to the queue listing. An item that is not archived is a 409.
- `POST /v1/owner/cleanup` with `{"task_retention_days": 30}` or `{"posture": "propose_first"}`.
  `auto_with_digest` is refused (409) while the integrity checks are open.

## Export a persona card

A persona card (OF-325, mode A) is a shareable summary of one person: an identity line, key
relationships, and the strongest claims, each with its sources. `GET
/v1/owner/persona?subject=<person id>` compiles it and returns its rows and a `stamp`. Claims
about other people start struck. `POST /v1/owner/persona/export` with `{"subject": "…",
"stamp": "…", "strike": ["<row id>"], "unstrike": ["<row id>"]}` returns the card as
MemoryPack-lite JSON and markdown and records the export. If the card changed after your
preview, the export is refused (409) and you preview again. A handed copy is a copy: to stop
sharing, do not issue another.

## Off-record sessions

An off-record session (ARCH-0052) keeps its turns in memory, out of the vault, its indexes, sync
and exports, until you save a turn or close the session. Close drops every turn you did not
save. An anonymous session keeps nothing at all and cannot be saved or put on record.

- `POST /v1/owner/off-record` with `{"session_ref": "…", "mode": "off_record" | "anonymous",
  "backend": "local" | "remote_provider"}` starts one. `GET /v1/owner/off-record?session_ref=…`
  reads it.
- `POST /v1/owner/off-record/witness` with `{"session_ref": "…", "turn": {…}}` writes a turn
  into it; the turn has the shape `POST /v1/core/facade/vault.witness` takes.
- `POST /v1/owner/off-record/promote` with `{"session_ref": "…", "turn": "<turn id>"}` saves one
  turn through the ordinary write door.
- `POST /v1/owner/off-record/save` with `{"session_ref": "…"}` saves every turn nobody saved yet,
  in one transaction.
- `POST /v1/owner/off-record/mode` with `"on_record"` saves later turns as ordinary memory;
  `"off_record"` goes back.
- `POST /v1/owner/off-record/close` ends it.

The session lives in the server process: a restart ends it, and only saved turns remain. These
routes keep no wire receipt (the per-route and per-caller call counts other routes keep), so
nothing records that a session ran.

### Everyone in a room (ARCH-0052 D5, the notice model)

A stretch can also run in a room, a conversation whose members are everyone in it. Each person
or agent acts with their own slip (`principal_ref` and `actor_class`), under the scopes they
already hold.

- `POST /v1/core/off-record/start` with `{"room": "<conversation id>", "session_ref": "…",
  "backend": "local" | "remote_provider"}`: any person on the room's roster starts one.
- `POST /v1/core/off-record/witness` with `{"room": "…", "session_ref": "…", "turn": {…}}`: a
  member speaks into it. Leave each message's `id` out: the stretch gives every message its own,
  and a turn that names one is refused (400) while the stretch is off record.
- `POST /v1/core/off-record/save` with `{"room": "…", "session_ref": "…"}`: a holder of this
  vault's write grant keeps the whole talk in it. The grant is held by a live owner of this vault,
  a member of a shared vault whose grant writes its content, or one of this vault's own agents, on
  their own slip with `core:write` over the whole vault. Anyone else is refused, and nothing is
  written: a person gets 403 with advice to export, an agent gets 403 with `requiredScope`
  `core:write` and advice to ask a holder through `suggest-save`. If an ordinary write has since
  put a message at the order of one said into a turn this stretch saved, the save keeps nothing
  and answers 409 (`conflict`, naming the turn); the talk stays in the room until it closes, and
  an export still takes it.
- `POST /v1/core/off-record/save-from-here` with `{"room": "…", "session_ref": "…"}`: a holder
  puts the stretch on record, as your own `mode` route does. Later turns are saved as they land,
  while the holder still holds the grant and stays in the room.
- `POST /v1/core/off-record/export` with `{"room": "…", "session_ref": "…"}` (`core:read`): any
  person in the room takes an export file of the turns their membership lets them see. It writes
  no vault.
- `POST /v1/core/off-record/suggest-save` with `{"room": "…", "session_ref": "…"}`
  (`core:propose` or `core:write`): an agent suggests a save. It saves nothing, and it waits,
  shown under `waiting_suggestions` in the room, until a holder answers it.
- `POST /v1/core/off-record/confirm-save` and `POST /v1/core/off-record/decline-save`, with the
  same body: a holder answers the waiting suggestions. A confirm is the holder's own save of the
  whole talk; a decline keeps nothing. Either answers 409 (`no_suggestion`) when nothing waits.
  Any save answers the suggestions waiting when it ran.
- `GET /v1/core/off-record?room=…&session_ref=…` reads the stretch and the notices from the
  times your membership shows you.

Each room names its own stretches, so the same `session_ref` may run in two rooms. Your own
routes above address a room's stretch as `room:<conversation id>:<session_ref>`, and only while
you are on that room's roster; a name you pick for `POST /v1/owner/off-record` may not start
with `room:`.

Every save, export, suggestion and decline posts a notice to the room (`saved_talk`, `saved_turn`,
`saving_from_here`, `exported`, `save_suggested`, `save_declined`), with who and when, never the
content. A save that finds nothing new to keep posts one too. Your own `promote` and `mode`
above post one too when the stretch runs in a room. A 1:1 with your own companion posts none: a stretch you start
with `POST /v1/owner/off-record` has no room, and a room that holds only you and this vault's own
agents has nobody else to tell. Someone outside the room gets the same 404 as for a stretch that
does not exist.

A save keeps what the room showed you, as an export does: the visible messages of the turns your
membership shows you. An agent's hidden messages (its own reasoning) and turn summaries stay out.

Putting a room on record saves into your vault only while you are in the room and own the vault
on a live credential (for a holder's `save-from-here`, while they hold the grant on a live slip).
Each later turn checks that again. Once you leave, or lose the vault or the credential, saving
stops: the stretch goes back off record and the room hears
`saving_stopped`. A turn caught in that moment is refused with `409`, and nothing of it is kept;
say it again to keep it off record.

## Read the vault as files

`GET /v1/owner/graph-fs?path=/entities` reads the vault as a read-only tree (OF-355): `/worlds`,
`/entities`, `/claims` (by time and by id) and `/backlinks`. `op` is `ls` (default), `cat`,
`head` (`lines`), `wc`, `find` (`newer_than`), `grep` (`pattern`, `recursive`) or `readlink`.
Listings and searches are bounded; pass `next_cursor` back as `cursor` for the next page. Every
page that a limit cut hands out a cursor, so only the last page has none: `find` walks depth first
through every page of every directory, `grep` and `head` resume inside a file, and a line longer
than a page continues on the next one, cut on a character boundary. A listing's or search's cursor
is sealed: it names no row, and it works only for you, on that path with those parameters, until
the server restarts (then list again). Reads go through your own scoped read, so scopes excluded
from you are absent. Sealed secret custody is never part of the tree: walks pass over it, and a
direct read of it is refused. `output` comes with its `encoding`: `utf8` for text, or `base64`
for bytes that are not text, such as a MessagePack body. `cat` pages a text body on character
boundaries, so decoding each page by its own `encoding` and joining them gives the stored bytes.

## Send feedback

Configure where feedback goes:

```toml
[feedback]
destination = "collector"     # ONEIRON_FEEDBACK_DESTINATION: cloud, collector or github_issue
endpoint = "https://…"        # ONEIRON_FEEDBACK_ENDPOINT; HTTPS, or HTTP on loopback
```

The destination's token, if any, comes from `ONEIRON_FEEDBACK_TOKEN`. `POST
/v1/owner/feedback/preview` with `{"category": "bug"}` (or `papercut`, `confusion`,
`feature-wish`) returns the bundle exactly as it would leave, its `digest`, the `approval` that
names this bundle going to this destination on your approval, and `previewed_at`.

To send a suggested fix with the report, add `"proposal": {"problem": "…", "fix": "…"}` to
the body. Both are non-blank text up to 4096 bytes, shown in the preview exactly as they
leave. A proposal goes out under the encoding token `oneiron.feedback.bundle.v2` (the six v1
keys, then `proposal`); the preview returns that token as `encoding`, and every destination
receives it in the `X-Oneiron-Bundle-Encoding` header (GitHub issues also carry it on the
body's first line). A bundle without a proposal stays `oneiron.feedback.bundle.v1`, byte for
byte. Changing either string after the preview is a different bundle and is refused (409).

`POST /v1/owner/feedback/send` with the same body plus those three fields sends that bundle once to
that destination: repeating the request is the same send, a changed destination or bundle, or
another owner's preview, is refused (409), and a preview older than an hour is refused. Two
owners sending the same bundle are two sends. The send is an ordinary outbound effect: until the vault's policy grants
`external:send` on the feedback channel to you, it is held (`"outcome": "held"`) and nothing
leaves. A bundle carries no vault text the engine attached; proposal text is yours, and it leaves only
on your send of exactly that preview. A written note is refused until the engine redacts notes
in the vault (OF-420).

A vault our cloud hosts (managed serve) sends to `collector` at `https://oneiron.dev/feedback`
unless told otherwise; self-hosted serve sends nowhere until you set both keys. `GET
/v1/owner/status` shows the effective `feedback` setting. Every send still asks you first.

## Keep an open feedback inbox

A server can take feedback from anyone, with no key and no moderation (ARCH-0056 #open-inbox).
It is off unless you turn it on:

```toml
[feedback.inbox]
enabled = true            # ONEIRON_FEEDBACK_INBOX
notes_per_sender = 20     # notes one sender may leave in an hour
notes_per_hour = 2000     # notes the inbox takes in an hour, from everyone

[limits]
feedback_inbox_bytes = 131072   # the most one note may carry
```

Then `GET /v1/feedback?text=…` (optionally `&category=bug`, `papercut`, `confusion` or
`feature-wish`) lands one note, and so does `POST /v1/feedback` with a plain-text, form or JSON
(`{"text": …}`) body, or the MessagePack bundle another vault's `collector` send delivers. The
reply is `202 {"received": true}` and nothing else. Every attempt the cap lets through counts, an empty or unreadable one too.
Past either count a sender gets `429` with
`retry-after` and `details.state = "feedback_inbox_flood"`; an IPv6 sender is counted by its
/64. Behind a reverse proxy, list it in `trusted_proxies` so the proxy's `X-Forwarded-For` names
the sender; otherwise every caller is counted by its own connection. A longer note gets `413`,
and a disk at its `disk_reserve_bytes` floor gets `507`.

The notes stay out of recall, views and the Dreamer. `GET /v1/owner/feedback/inbox?after=<seq>
&limit=<n>` returns them oldest first (100 unless `limit` says fewer, at most 1,000). Each
carries its arrival number `seq`; a sweep keeps the last one it read and passes it as `after`.

## Share failure signals

A participating deployment sends its publisher two things, and nothing else: the content-free
tier-1 failure counts, and the Coach's sealed code-fix records (an invented example verified in
the vault, and a candidate fix's fixed or not-fixed result). No world text leaves, and a failure
that touched a private world sends its counts only. A vault our cloud hosts participates by its
terms; a self-hosted server participates only once you set `failure_signal_export = true`
(`ONEIRON_FAILURE_SIGNAL_EXPORT`). Training on what leaves is a separate yes,
`failure_signal_training` (`ONEIRON_FAILURE_SIGNAL_TRAINING`). Where it goes:

```toml
[failure_signals]
endpoint = "https://…"     # ONEIRON_FAILURE_SIGNALS_ENDPOINT; HTTPS, or HTTP on loopback
every_secs = 3600          # ONEIRON_FAILURE_SIGNALS_EVERY_SECS
batch = 64                 # ONEIRON_FAILURE_SIGNALS_BATCH: code-fix records per send

[failure_signals.candidates.tone-fix]    # a publisher candidate; file layers only
instructions_file = "/etc/oneiron/candidates/tone-fix.txt"
sha256 = "…"               # the file's SHA-256, lowercase hex
```

A candidate is an instruction your publisher ships and you install and pin. The Coach replays
each failure in the vault with the candidate added to the failing agent's instructions, and only
the fixed or not-fixed result leaves, as `publisher.<id>@<first 16 hex of the pin>`. Nothing
fetches or installs it. A file that no longer matches its pin stops the server at start. At most
8 candidates, 16 KiB each. A newly pinned candidate is also tried once on each past failure that
still stands: after the server starts, the Coach works through its earlier code-fix work a few
failures at a time.
`GET /v1/owner/coach/code-fixes?limit=<n>` lists the Coach's code-fix work, newest first: each
failure case's heal route (`case`), or a blocked report's when the agent's run has no failed case
(`blocked_report`), its class, the invented example's verdict and each candidate's fixed or
not-fixed result. It holds no text of the failure.

The endpoint's token, if any, comes from `ONEIRON_FAILURE_SIGNALS_TOKEN`. A hosted vault sends to
`https://oneiron.dev/failure-signals` unless told otherwise; a self-hosted server with no endpoint
sends nothing, and sealed records wait in the vault. Each send is one JSON batch, `POST`ed as an
ordinary outbound effect on `failure_signals/send` with its recorded receipt. While the deployment
participates, the vault keeps a standing grant on that channel for the sender, so no send asks
you; turning participation off revokes it. A record leaves the vault only once the publisher took
it: a failed send keeps it for the next one.

The counts come from the Coach's detectors. Each diagnostic they raise counts once, ever: a missed
recall is `memory_miss`, a consolidation error `task_failure`, a consent storm or predicate drift
`other` with its detector named. Your own refusal of a single consent ask is never counted. A
diagnostic does not say which agent failed, so these counts carry the agent `unattributed`.
Counts wait in the vault, across restarts, until the publisher takes them.

## Model-graded self-heal detectors

Canon ships no detector wording, so no model-graded detector runs until you write one. Each
`[self_heal.detectors.<family>]` table is one detector over the retrieval telemetry:

```toml
[self_heal.detectors.recall_gaps]
class = "retrieval_miss"   # the diagnostic class a finding carries (not agent_health)
tier = "t3"                # t3 (default), t2 or session
prompt = "…"               # what it looks for
rubric = "…"               # how a positive is told from a negative
consecutive = 3            # runs a window needs; for t2, positives in a row that raise
window_secs = 3600         # one window of time; for session, how long a conversation is quiet
```

Every five minutes the server reads the newest 1,024 runs and asks each detector's question of
each window it has not graded yet, up to 8 windows a pass, on the decision ladder's local and big
rungs (never a person). `t3` judges each completed window of time at once. `t2` asks once per
run. `session` judges one conversation's runs once it has been quiet for `window_secs`. A raised
window becomes a proposed diagnostic: nothing is repaired. Changing a prompt or rubric grades
windows again.

`GET /v1/owner/self-heal/findings?family=<family>` lists one detector's raised `t3` findings,
newest first, each with your label. `POST /v1/owner/self-heal/findings/label` with
`{"family", "event", "positive"}` labels one finding; a label never changes. Once a family has
`consecutive` positive labels and one negative, a `t2` detector of that family asks with the
labeled findings. For a `t3` detector, the next pass registers a T2 of the family: it grades each
window's runs one by one, shown the labeled findings' run facts, beside the `t3`, which keeps
running. A new label or a reworded detector registers a new revision, which grades windows again.
When a shipped closed-form T1 detector reproduces every label (today `retrieval.miss.v1` for
`retrieval_miss`: a confirmed window holds a miss, a rejected one holds none), the revision is
graduated and its T2 stops running; the T1 already runs in the Coach's nightly tier-1 sweep.
`GET /v1/owner/self-heal/minted` lists each family's registration and what graduated it.

## Answer the decision ladder's asks

When a typed decision climbs past every model rung (the dial reaches the
owner, the read says "ask up?", or the clock cut an irreversible step), the
server's decision ladder queues it for you (run-with-models.md, section 13).
The ask waits in the vault, through restarts, until you answer.

`GET /v1/owner/decisions/asks?after=<seq>&limit=<n>&open=true` lists them
oldest first (50 unless `limit` says fewer, at most 500). Each ask carries:
- its arrival number `seq`;
- the question (its text and the answers its contract takes);
- the principal it is for, and the evidence ids;
- why it was asked;
- the answer the ladder held, if any, and the model that read it;
- your answer, once given.
`open=true` keeps only the unanswered asks.

Answer one with `POST /v1/owner/decisions/asks/answer`:

```json
{"seq": 3, "answer": {"kind": "choice", "value": "allow"}}
```

`kind` is `noul` (`value` true or false), `choice` (one of the question's
options) or `score` (a number in its range). An abstention is not an answer.
The decision waiting on the ask gets your answer. When your answer differs
from the ladder's, the case is kept for the Coach, which tunes when the
ladder asks you. Sending the same answer again changes nothing. A different
answer to an answered ask is refused.

## The vault key on a new host

A vault's data key unlocks from any of its wraps: this device's keystore, the vault password, a
passkey's PRF output, or an escrow recipient whose seed a recovery box keeps. Every backup carries
the wraps (never the key), so a host with none of the vault's keystore slots restores from one of
the others. Secrets are read from stdin, or an owner-only `--secret-file`, exactly as given but
for one trailing line break; a PRF output or a seed is 32 bytes, raw, hex or base64url.

```sh
oneiron vault-key status                       # the key and its wraps; a passkey's lists its PRF input
printf %s "$PASSWORD" | oneiron vault-key set-password
oneiron vault-key prf-input my-yubikey         # the input to evaluate the passkey's PRF at
oneiron vault-key add-passkey my-yubikey --secret-file prf.bin
oneiron vault-key add-escrow usb --box-dir /Volumes/KEY/oneiron-box
oneiron vault-key signer > signer.json         # the pin another host trusts this vault's backups by
oneiron vault-key remove passkey:my-yubikey    # the last wrap stays
```

A passkey's PRF input is `BLAKE3-derive_key("oneiron/vault-key-passkey-prf-input/v1", vault id ‖
credential name)`: the vault and the name fix it, so the same authenticator gives the same output
on any host. A running server takes the same steps at `/v1/owner/vault-key` (`GET` for the wraps,
`GET /prf-input?credential=NAME`, `POST /passkeys`, `POST /password`, `POST /device`,
`POST /remove`, `POST /unlock`, `GET /signer`).

An escrow wrap seals to a hybrid key grown from a 32-byte seed; the recovery box keeps the seed.
`--box-dir DIR` keeps it at `DIR/<vault id>/<label>.seed`, owner-only (removable media, your own
box). `--box-command PROGRAM` hands it to a program: `PROGRAM store <vault id> <label>` reads the
seed as 64 hex digits on stdin, and `PROGRAM release <vault id> <label>` prints it after its own
sign-in. A hosted recovery box plugs in that way.

On the new host:

```sh
oneiron restore BACKUP --inspect               # what unlocks it, with each passkey's PRF input
printf %s "$PASSWORD" | oneiron restore BACKUP --unlock password --trust signer.json
oneiron restore BACKUP --unlock passkey --credential my-yubikey --secret-file prf.bin --trust signer.json
oneiron restore BACKUP --unlock escrow --label usb --box-dir /Volumes/KEY/oneiron-box --trust signer.json
```

Every unlock but this device's needs `--trust`: a host holding no signer seed has no other ground
to trust a backup on, and a backup's own head is never trusted. Where no vault is at the
configured path, the restore makes it there, unlocks its key the same way and wraps it to this
install's keystore. Where one is, it restores over it as above, or rehearses with `--rehearse`.

A managed vault's escrow capsules live in the registry, one report per recipient (`managed` or
`break-glass`). One of them opens a backup even when the backup is older than its wrap:

```sh
oneiron restore BACKUP --unlock escrow --capsule vault-key-escrow-managed.<fp>.json \
  --secret-file recipient.secret --trust signer.json
```

The report is the registry's JSON row as the node spooled it. Unknown fields, another
`schema_version` or `report_type`, and a `vault_id` or `key_commitment` other than the backup's
(`--inspect` prints both) are refused before the secret is read. The recipient's secret comes from
stdin, an owner-only `--secret-file` or the recovery box, never the command line: a 32-byte seed,
or the key's 96 bytes of seeds (ML-KEM-1024's 64, then X25519's 32), raw, hex or base64url. A
released recipient is never reused, and the restore says so on stderr. Retire it yourself: seal the
vault key to a new recipient (`oneiron vault-key add-escrow`, or the managed node's fresh one at its
next start), `oneiron vault-key remove escrow:<label>` if the restored vault still carries it, and
have the registry delete its capsules.

### Maximum tier

`oneiron init --maximum-tier` creates a vault whose every LMDB page is sealed under a key derived
from its data key (OF-570), and writes `maximum_tier = true` to the config. It is slower: point
reads about 20x, scans about 12x. The tier is chosen when the vault is created; a plain vault is
never converted. The new key is wrapped to this device's keystore, and with `--secret-file FILE` to
a vault password too, which a host with no keystore needs. The wraps are mirrored beside the vault
in `.<vault dir>.page-seal`, owner-only and never in a backup, so the pages unlock before the vault
opens. With no keystore, serve unlocks them with the password the service manager's credential store
holds as `vault_password`. `oneiron vault-key status` shows `"pages": "sealed"` and the warning. On
another device, unlock the pages first: `printf %s "$PASSWORD" | oneiron vault-key add-device
--unlock password` (or `passkey`, `escrow`, or `kit` with the world kit's pieces); `oneiron
vault-key prf-input NAME` gives a passkey's input before the vault opens. A credential whose wrap was removed or replaced opens nothing, even if an interrupted change
left it in the mirror; the next open with a current one repairs the mirror. Where the mirror is but
the vault's data is not, init, serve and restore refuse: move the mirror away to create a new vault,
since it may be the only copy of that vault's wraps. A restore makes a plain vault, so it is refused
over a sealed one; restore to another `--vault-path`. Body files, `.lines`, LFS staging and lock
files stay outside the tier.

A managed vault is plain unless its supervisor passes `--maximum-tier` when the vault is created.
Its pages then seal under the data key the supervisor delivers at every start, with a fresh vault
id and incarnation, and the mirror beside the data directory is written at the first open, before
any wrap: the next start reopens from its id and incarnation with the delivered key, which must be
the one the mirror's commitment names. A sealed managed vault reopens that way with or without the
flag; a plain one stays plain. The managed and break-glass escrow wraps join the mirror as they are
sealed, so a restore elsewhere unlocks the pages with either.

## The world recovery kit

The world kit carries your recovery root: the key every private world's key is also wrapped to.
It is a fixed 2 of 3: any two pieces open it, and one piece alone, or the passphrase alone, opens
nothing. No piece ever lives on the host. Run these on a stopped vault:

```sh
oneiron recovery-kit issue --home paper --home password-manager --home passphrase --out /Volumes/KEY/kit
oneiron recovery-kit confirm --piece /Volumes/KEY/kit/piece-1.txt --piece /Volumes/KEY/kit/piece-2.txt
oneiron recovery-kit status
oneiron recovery-kit restore --piece piece-1.txt --piece piece-2.txt
```

`issue` takes one `--home` per piece, in order: `paper`, `password-manager`, `own-email`,
`file-elsewhere`, `file-here`, `file-on:<machine>`, `other-machine:<machine>`, `trusted-person`,
`security-key` or `passphrase`. Each stored piece is written to `--out` as `piece-<x>.txt`, its
recovery code, readable by you alone; a passphrase is read from stdin or `--secret-file`.
`file-on:<machine>` with this machine's own id counts as `file-here`, and `other-machine:<machine>`
with it is refused. Nothing is published yet: the kit is pending. Put each piece where its home
says, then `confirm` with two of them, or with one and the passphrase. That re-entry is the proof
you saved them. Confirm makes the kit's root live on this machine and marks every earlier kit
replaced. When the vault has a key, confirm also seals it to the root as the escrow wrap
`world-kit`, replacing the earlier kit's. It opens the key with this machine's keystore, and a key
that stays locked refuses the confirm before anything changes. A replaced kit's pieces still open
their own old root; replacing a kit does not revoke it. `this-machine` is refused until a keystore
slot can hold a piece.

`status` lists every kit, pending ones too, with its homes, coverage and confirmation, and each
private world's state. `covered` means only that the world's current key has a wrap to the pinned
root. A running server shows the same at `GET /v1/owner/recovery-kit`; issue, confirm and restore
run only from the CLI, so no piece crosses HTTP.

`restore` opens the world keys wrapped to the kit's root on this machine. It never changes a
world's settings. A kit opened with one piece and the passphrase is not verified on its own:
pass `--fingerprint <root>`, read on one of your machines that pins it, or `--confirm-unverified`.
A kit this vault still lists as pending is refused: `confirm` it instead.

On a new host, the kit also opens a backup through the `world-kit` wrap, and a sealed vault's
pages through the same wrap in its mirror. `--vault-id` is the id `status` prints, the id the kit
is bound to; it is never read from the vault or its mirror:

```sh
oneiron restore BACKUP --unlock kit --vault-id <hex> --piece piece-1.txt --piece piece-2.txt --trust signer.json
oneiron vault-key add-device --unlock kit --vault-id <hex> --piece piece-1.txt --piece piece-2.txt
```

With `--unlock kit`, add-device refuses `--credential`, `--label`, `--box-dir` and `--box-command`;
with any other unlock, it refuses `--piece` and `--vault-id`.

## Contact disclosure

A contact sees only what you cleared it for. An agent or the companion can only offer you a
clearance (the `vault.disclosure.offer` verb, under an agent credential that carries
`propose_disclosure_widen`). Only you settle it, here. The generic widen accept refuses a
contact offer.

- `GET /v1/owner/disclosure/offer?proposal_ref=<64 hex>` shows one frozen offer: the contact,
  the Scope, the purpose, the channel, the one party it reaches, and its `canonical_delta`.
- `POST /v1/owner/disclosure/confirm` with
  `{"proposal_ref": "...", "expected_delta": "<canonical_delta>", "outcome": "once"}` answers it.
  `once` discloses this once and keeps nothing. `standing` clears the contact for that Scope
  until you narrow or revoke it. `deny` refuses. An offer settles once. It is refused when it
  expired, when the delta differs from what you were shown, when the contact's clearance changed
  since it was filed, or when the credential line that filed it tries to settle it.
- `POST /v1/owner/disclosure/narrow` with `{"contact": "<hex>", "scope": {...}}` narrows a
  standing clearance to a Scope inside the current one.
- `POST /v1/owner/disclosure/revoke` with `{"contact": "<hex>"}` is
  `consent.revoke_contact_disclosure`. The row stays, revoked, and admits nothing.
- `POST /v1/owner/disclosure/preclear` with `{"set_name": "...", "contacts": [...], "scope": {...}}`
  clears a named trusted set in advance, 1 to 256 contacts, one receipt each.
- `GET` and `PUT /v1/owner/disclosure/mode` read and set the mode: `always_ask` (the companion
  never offers), `auto` (the default) or `always_yes` (pre-clear trusted sets; offers stay
  allowed). No mode clears anyone by itself.
- `POST /v1/owner/disclosure/attendee` with
  `{"ask_ref": "<hex>", "roster_revision": 4, "choice": "<contact hex>" | "unknown"}` answers a
  "who is this?" ask once. It names the speaker for that roster revision only. It clears nothing
  and enrolls no voice, so an unknown speaker stays public-only.

Each clearance answer returns its Gate receipt: `receipt_ref`, the act, the contact, the
registry row `contact_clearance:<contact hex>`, its revoke command, and the clearance digests
before and after. A `once` answer also returns the one-time digest the disclosure spends. There
is no dedicated CLI command; use `oneiron api raw`, as in the last section.

## Saved queries after a pack update

When a new source of an installed pack is activated, the saved queries that read a predicate it
dropped or remapped go through the repair ladder in the same transaction (ARCH-0059 §4). A
rename in the pack's migration map migrates the query; an equivalent rewrite migrates it with a
notice; a rewrite that changes meaning waits as a proposal; a predicate with no rewrite pauses
the query with its error. A map names a move between two versions, so a source changed under the
same version applies none, and no rewrite lands on a predicate the update drops.
`GET /v1/owner/pack-drift` lists what the ladder did, query by query;
a paused query shows its error on the query itself.

## A forked root handoff

When a key a held root handoff retired signs another row, the vault refuses the row and saves a
fork alarm: the retired key (`suite:hex`), the refused row's hash, the handoffs the key signed,
and when it was raised. The alarm stays until you acknowledge it. Acknowledging keeps it saved
with that refused row marked seen, and only a refused row you have not seen raises it again.

```sh
oneiron handoff-alarms list                     # every saved alarm, open or acknowledged
oneiron handoff-alarms acknowledge SUITE:HEX    # you have seen this key's alarm
```

Routes: `GET /v1/owner/authority/handoff-alarms` (open alarms first) and
`POST /v1/owner/authority/handoff-alarms/acknowledge` with `{"signer": "suite:hex"}`. An unknown
signer is 404, and acknowledging an acknowledged alarm changes nothing.

## Learned settings

A learned setting is a knob the vault fits from its own runs, such as the audit rate
(`audit_rate`), a planner floor or a health dial (`health.loop.repeats`). You can lay two kinds of
row on a knob. A **seed** is a prior the fit starts from, weighted in runs. A **pin** is the value,
whatever the fit says.

A row applies to the vault, to one project, or to one task type (a type row matches its node at
any tree version). A read takes the narrowest pin (project, then type, then vault). Without a
pin, it takes the vault's fit once the fit has runs of its own. Failing that, it takes the
narrowest seed, then the catalog seed. The catalog keeps each knob's bounds; a value outside
them is refused.

```sh
oneiron learning-settings list                                  # catalog, values now, your rows
oneiron learning-settings list --key health.loop.repeats
oneiron learning-settings put health.loop.repeats pin 5 --why "noisy tools" --project HEX32
oneiron learning-settings put audit_rate seed 0.1 --weight-runs 20 --why "start low"
oneiron learning-settings put health.silent.minutes pin 60 --why "slow jobs" --task-type research
oneiron learning-settings clear health.loop.repeats pin --project HEX32
```

The commands open a stopped vault. A running server answers the same at
`GET /v1/owner/settings/learning[?key=…]`, `POST /v1/owner/settings/learning` with
`{"key", "mode": "seed"|"pin", "value", "weight_runs"?, "why", "project"?, "task_type"?}`, and
`POST /v1/owner/settings/learning/clear` with `{"key", "mode", "project"?, "task_type"?}`.
Each answers with the key's catalog entry and rows. The host verbs `vault.settings.learning`,
`.put` and `.clear` take the same input over the facade and MCP. All of them are the owner's
alone, and clearing an absent row succeeds.

The app's policy actions have host verbs too. Each runs the same action as
`POST /v1/core/actions/{verb}`:
- `vault.settings.wake_policy.set` with `{"policy", "idempotency_key"}` runs
  `dreamer.wake_policy.set`, which needs the owner's own credential.
- `vault.settings.inference_defaults` with `{}` runs `inference.defaults.read`.
- `vault.settings.inference_defaults.replace` with `{"defaults", "idempotency_key"}` runs
  `inference.defaults.replace`.

The two inference verbs need the caller's Auto ceiling. Each answers with the action's
`outcome`. A retry with the same idempotency key gets the first call's answer.

Two app writes are verbs as well, so a button and an agent make them the same way:
- `vault.messages.react` with `{"message", "by", "glyph", "occurred_at"?, "remove"?}` puts or
  removes your own reaction. `POST /v1/core/messages/{message}/reactions` runs it as an action
  of your credential, and the request's `Idempotency-Key` becomes the action's key. A connector
  host's `external` provider reaction needs an owner-grade credential.
- `vault.artifacts.create` with `{"name", "media_type", "content_base64", "run_ref"?,
  "made_by"?}` creates an artifact with its first version. `POST /v1/core/artifacts` runs the
  same door.

The core conversation writes and the atomic batch are verbs too:
- `vault.conversations.create` creates a conversation. A body that names members also writes
  its membership, creator and roles, as you.
- `vault.conversations.turns.create` with `{"conversation", "body", ...}` puts one TURN under a
  conversation, with its ChildOf edge.
- `vault.conversations.records.append` appends one TURN to a conversation's DAG, under your
  name. It takes the same fields as `POST /v1/core/conversations/{id}/records`, plus
  `conversation` and less `actor`.
- `vault.batch` with `{"entities": [...]}` commits up to 256 puts at once. An owner-grade
  credential commits them at owner grade. Any other credential, and an embedded handle, commits
  them below it, which refuses a put that turns an agent definition back on.

Each REST route (`POST /v1/core/conversations`, `.../{id}/turns`, `.../{id}/records`,
`/v1/core/batch`) runs its verb as an action of your credential. It runs the verb's own door
instead when the request is larger than one action argument (16 KiB of JSON), names a room
turn, or comes from a credential that binds no person or agent. The route picks the path before
it writes. A TURN write wakes the Dreamer once on either path.

## Widen proposals

When an agent asks to spawn a child with more context than its own slice holds, the gate does not
grant it. The ask is parked as a **widen proposal** for the board above (the attempt that
dispatched the asking agent). Its id is the digest of the stored request, so the proposal you
answer is the one you listed. Approving it widens the parent's slice and enqueues the child,
under a one-time consent. Declining it is final: the decline stays on record, a retry of the same
ask is refused, and the Coach counts it as a widen denial in its agent health review.

```sh
oneiron widen-proposals list                      # newest first
oneiron widen-proposals list --state pending
oneiron widen-proposals approve HEX64
oneiron widen-proposals decline HEX64
```

The commands open a stopped vault. A running server answers the same at
`GET /v1/owner/widen-proposals[?state=pending|approved|declined]`,
`POST /v1/owner/widen-proposals/approve` and `POST /v1/owner/widen-proposals/decline`, each with
`{"proposal_id"}`. The host verbs `vault.widen_proposals`, `.approve` and `.decline` take the same
input over the facade and MCP. Each answer shows the parent and board attempts, the target, the
three context descriptors (never their content), when it was raised, and how it settled. Only the
owner of the board's TASK may answer one.

## Legal holds

A legal hold keeps records from being deleted. While a hold names a record, its delete fails for
agents, timers, members and you alike, and every other verb keeps working. A hold names records,
or a claim's gate-decision key partition, and can carry an opaque matter reference (1 to 128 of
`A-Z a-z 0-9 . _ : - /`, never free text). You can widen a hold. You lift it only through one
confirm, "Lift the hold and erase?", which lifts your holds on the records it names and erases
them. The hold log keeps ids, times and reason codes only, for the hold's life and 24 months
after.

```sh
oneiron legal-holds place --record HEX [--record HEX] [--gate-partition HEX|none] [--matter-ref REF]
oneiron legal-holds widen HOLD --record HEX
oneiron legal-holds list
oneiron legal-holds log
oneiron legal-holds lift-and-erase RECORD [RECORD] --yes   # prints the prompt; acts only with --yes
```

Routes take targets as `{"record": "<hex>"}`, `{"gate_partition": "<hex>"}` or
`{"gate_partition": null}` (the claim-free partition):

- `POST /v1/owner/legal-holds` with `{"targets": [...], "matter_ref": "..."}` places a hold, and
  `GET /v1/owner/legal-holds` lists the holds you may see.
- `POST /v1/owner/legal-holds/widen` with `{"hold_id": "<hex>", "targets": [...]}`.
- `GET /v1/owner/legal-holds/log` reads the log, oldest first.
- `GET /v1/owner/legal-holds/lift-and-erase` returns the confirm's title and prompt, to show
  before you `POST` it with `{"records": ["<hex>", ...]}`. Each record answers `erased` with its
  receipt, `completion_pending` where Oneiron hosts the bytes until the deletion receipt
  completes, `kept_by_legal_order`, or `failed` (the hold is lifted; a plain delete retries).

The SDK verbs `vault.legal_holds.place`, `.widen`, `.list`, `.log` and `.lift_and_erase` do the
same under the owner's credential. Where Oneiron hosts the bytes, a legal order Oneiron must obey
can also hold records. You cannot lift it, and an erase you confirm waits until it ends.

## Erase a text's history

`POST /v1/owner/history/erase` with `{"entity": "<hex>"}` (and optionally `"through"`, a base64
frontier) drops a text's edit history below its oldest pin. In a personal vault, or a shared one
with one live Owner, it erases at once and answers `"outcome": "erased"` with the receipt. In a
shared vault with two or more live Owners it erases nothing yet: it answers `"outcome":
"waiting"` with the vault's started `erase` act, and every other Owner is told. Once the window
passes with no objection, `POST /v1/owner/history/erase/execute` with `{"act_id": "..."}` runs
it, and a retry returns the same receipt. `GET /v1/owner/history?entity=<hex>` lists the erases
filed for a text. A legal hold on the text refuses the erase.

## The model catalog

The model catalog comes from the first-party hub as the knowledge pack `oneiron.models`
(`packs/model-catalog` in oneiron-hub). Installing it puts its models in the vault's model
registry. From then on `/v1/llm/generate` and `/v1/llm/stream` admit a call that names one of
them. A model in `[models]` needs no catalog row.

- `GET /v1/owner/model-catalog` shows the catalog ref's sync policy and pin, the last revision
  fetched (`latest_seen`), the last one installed (`latest_trusted`), and the installed pack's
  receipt.
- `PUT /v1/owner/model-catalog` with `{"sync_policy": "...", "pin": "..."}` moves the policy.
  `pinned-commit` takes a full commit id. `pinned-ref` takes a tag, and each sync follows the
  tag to the commit it names then. `content-hash-frozen` takes one content hash. A sync whose
  bytes hash otherwise fails, and an installed catalog with another hash stops counting.
  Nothing is fetched until the next sync. Until you set a policy, the ref is pinned to the
  engine's released hub commit.
- `POST /v1/owner/model-catalog/sync` fetches the pack at that policy, scans the bytes, and
  installs them as a knowledge-only pack: nothing runs and nothing is granted. The reply's
  `outcome` is `installed`, `candidate` or `blocked` (with its `reason`). On install, a model
  the previous pack shipped and nobody edited takes the new row and keeps its scores. A row the
  host edited stays as it is.

A catalog's authority is its content hash and that hash's scan evidence. The commit only says
where the bytes come from.

## Embedding spaces and model moves

Text, image and audio each search through a kind slot. An unbound text slot reads the vault's
own text index. A bound slot reads a declared embedding space, whose id is an `ai.embed` rung id
(as `GET /v1/ai/options` lists it), then `@where`: the `[models]` provider key that binds that
rung, so one model at two clouds is two spaces. Where the space's model runs is that provider's
locality. A space whose `@where` names no provider serving its rung embeds nothing.

- `GET /v1/owner/embedding-spaces` lists the declared spaces, the text index, which space each
  slot reads, every move with its last check, and how many probes each kind holds.
- `PUT /v1/owner/embedding-spaces` with `{"id", "dimensions", "accepts", "query_towers"}` (and
  optional `"evidence": {"floor", "strong"}`) declares a space. `POST .../bind` with
  `{"kind", "space"}` binds one slot; leave out `space` to return the slot to its default.
  `POST .../one-space` with `{"space"}` binds every slot that space accepts, text included. Both
  refuse a slot an open move carries until the move ends.
  With the text slot bound, a text query embeds through that space's text tower in the context
  pack (HTTP and the native MCP pack), the Context Board, `/v1/core/query`, recall (HTTP,
  WebSocket and MCP) and `/api/search/semantic`, and its list holds every kind of item the space
  holds. `/api/search/vector` reads the text index unless it names `space`.
  A `media` query (`{"space", "mime", "bytes_b64", "kinds"}`) seeds a search on its own: the
  server embeds the bytes into that space through the `ai.embed` rung its id names and searches
  that space's list. The context pack and the Context Board over HTTP, `/v1/core/query`, the
  native MCP context pack, and `vault.recall` on every SDK take it. Recall refuses it at light
  effort and in call mode, and refuses `kinds`. A client with no server (an embedded handle)
  answers `MODEL_UNAVAILABLE` (`EMBEDDER_UNAVAILABLE` on the native context pack) and never
  searches without the media.
  `POST .../retire` with `{"space"}` drops a space that no slot binds and no open move names.
- **From the config file.** `[[embedding.spaces]]` rows (the same fields as the `PUT` body) and
  `[embedding.slots]` (`text`, `image`, `audio` = a space id), or `[embedding] one_space = "<id>"`
  for the preset, apply at each `serve` start. A start declares only spaces the vault does not
  hold and binds only slots the vault leaves unbound and no open move carries, so a door edit
  or a model move stays. A listed space the vault holds at another width stops `serve`: a new
  width needs a new id.
- **Moving to a new model version.** `POST .../move` with `{"candidate", "incumbent", "margin"}`
  starts moving every slot the incumbent serves to the candidate. Leave out `incumbent` for the
  text index. The media backfill fills the candidate while the incumbent keeps serving, and
  writes probes meanwhile: short queries the chat seat writes from text documents, the
  captioner or Local-vision seat from images, and the chat seat from audio once the
  `[models.media]` transcribe seat has transcribed it. Audio and image bytes never go to a
  third-party seat for a probe. Once the candidate holds every document, the
  probes run on both spaces, and on the incumbent twice for its retest noise. The candidate swaps
  in by itself only when every kind is not worse: the low end of the kind's family-grouped
  paired interval stays at or above minus that noise, or minus your stricter `margin`. A kind
  whose whole interval is below that closes the move, and the incumbent keeps serving. Fewer
  than 10 probe families, or an interval across the margin, reads unknown. Unknown never swaps
  by itself: the move stays open and is checked again every 6 hours. Each swap, keep and undo
  leaves a short note in the inbox.
- The media backfill skips any document a space's model refuses by its content (a format it
  cannot read, a content filter) until the document changes, so one bad file never stalls a
  space or a move. A model that refuses everything it is sent before it has embedded anything
  is treated as down, and the backfill retries it. `GET .../embedding-spaces` counts each
  space's refused documents under `refused`; `GET .../refused?space=<id>` lists them with the
  reason and time, and `POST .../refused/clear` with `{"space", "id"}` forgets one, so the
  backfill sends the same bytes again (after a provider's policy or model changed).
- A move that goes 14 days from its start without one check (its model never filled the
  candidate, or the probes never ran) closes as kept, with a note: the incumbent keeps serving
  and the candidate's rows go. Begin the move again once that model answers.
- `POST .../move/check` with `{"candidate"}` runs the probes now. It answers within 20 seconds:
  past that it answers `running`, and the check finishes on its own and records its reading on
  the move. `.../move/approve` swaps a full candidate in on your yes. `.../move/undo` binds the
  incumbent again after a swap, and `.../move/abandon` ends an open move without one. An undo
  works for 30 days after the swap. Then the incumbent retires (its rows and declaration go)
  unless a slot binds it again.
- `GET .../probes` lists the probes. `POST .../probes` with `{"kind", "query", "family",
  "targets", "author"}` stores one you wrote. `POST .../probes/delete` with `{"id"}` removes
  one.

On a stopped vault the same acts run from the command line, and each prints what the route
answers:

```sh
oneiron embedding-spaces list
oneiron embedding-spaces declare ID --width N --accepts text,image [--query-towers text] [--floor F --strong S]
oneiron embedding-spaces bind text|image|audio [SPACE]   # no SPACE: back to the default
oneiron embedding-spaces one-space SPACE
oneiron embedding-spaces retire SPACE
oneiron embedding-spaces move CANDIDATE [--incumbent SPACE] [--margin F]
oneiron embedding-spaces move-approve|move-undo|move-abandon CANDIDATE
oneiron embedding-spaces probes list
oneiron embedding-spaces probes put --kind text --query Q --family HEX [--target HEX] --author A
oneiron embedding-spaces probes delete ID
```

A check runs the server's own `ai.embed` towers, so only a running server checks a move. It can
take minutes, and `oneiron api raw` waits for it:

```sh
oneiron api raw POST /v1/owner/embedding-spaces/move/check --data '{"candidate": "SPACE"}'
```

The SDK verbs `vault.embedding_spaces.list`, `.declare`, `.bind`, `.one_space`, `.retire`,
`.move`, `.move_check`, `.move_approve`, `.move_undo`, `.move_abandon`, `.probes.list`,
`.probes.put` and `.probes.delete` do the same under the owner's credential, with the same
bodies and answers. An embedded vault has no `ai.embed` towers, so it refuses `.move_check`. The
SDK client waits up to 30 minutes for a check, as for an export.

## Sign a secret's custody with your owner anchor

A portable secret's custody moves between your machines under a signed transition. An install
that cannot sign as one of your machines can have its current transition signed with the owner
anchor of your recovery kit instead. The record keeps its generation, status and value, and the
value is sealed to every machine of yours. The kit is read on this machine only: stop `serve`,
then pipe the kit's recovery codes in, one per line (with `--with-passphrase`, the kit
passphrase on the first line, and then one code is enough):

```sh
oneiron secrets anchor-sign --name NAME < kit.txt
```

It prints `{"name", "signed"}`. `signed` is false for a record that stays on its device
(device-bound, cross-vault or "this device only") or a value no machine of yours here can open.
No route or SDK verb takes the kit.

## Calling the owner routes

Every `/v1/owner` route needs a verified, unattenuated owner slip held by a live human owner of
the vault. That is the slip the first-owner link from `oneiron token bootstrap` redeems to.
Other credentials get the same 403: another person, an agent-class slip, a slip narrowed to
some verbs, or the host root. Managed vaults are owned through their supervisor, and these
routes refuse there. Each act rechecks the slip and your ownership in the transaction that
commits it, so a request still queued when its slip is revoked changes nothing; an off-record
witness and promote recheck it where the turn lands. A feedback send rechecks it
where the send is admitted, so a send whose slip is revoked while it waits admits nothing and
never reaches the destination. Entering, flipping and closing a room keep no row of their own
to recheck in, so they recheck the slip when they start. From a shell, with the slip in `ONEIRON_SECRET` and its binding seed in
`ONEIRON_BINDING_KEY`:

```sh
oneiron api raw GET /v1/owner/status
oneiron api raw POST /v1/owner/backups
oneiron api raw POST /v1/owner/maintain
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
- A server with `[keystore] backend = "off"` cannot take a backup.
- A backup is signed (Ed25519 and SLH-DSA) by the install that took it, and chained to the one
  before it. A restore refuses a signer it does not trust: the CLI trusts the signers this
  device's keystore holds, or exactly the ones `--trust` pins.
- A restore onto a new host brings no exterior key custody with it: gate receipts sealed under
  claim keys the old host kept do not come back.
- Host-order legal holds cross a restore over a vault, a rehearsal and `--activate` from the live
  vault. A restore where no vault is cannot read them; the hosting side carries them
  (`Vault::carried_host_order_holds`, `Vault::install_carried_host_order_holds`).
