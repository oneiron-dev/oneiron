# Code round trip (FIX 6869, G4 PR3)

One user-run round trip of a real Git repository through Oneiron: admit a chosen
commit, import and seal it, preview and export it, clone it with stock Git, run
the repository's own native command once, make one real signed edit, push it,
take it through review and the merge queue, then preview, export and re-clone
the result and prove that every path, mode and raw blob byte matches the push.

**Connected in source, not executed.** Every call in `roundtrip.ts` names a
built verb and its generated `FacadeInput` / `FacadeResult` type. Nothing here
has been run end to end, and nothing here is a test, fixture or CI job.

## What you provide first

The script provisions none of these. Until each exists, the step that needs it
answers `roundtrip_pending`, and an accepted push stays exactly as it is.

- A host with an already-built `oneiron` binary, Bun, stock Git, GPG set up for
  `git commit -S`, and the repository's own native tools.
- Two credentials, each named by environment variable (`secret_env`,
  `binding_key_env`): a live Owner's, and the agent run's own. The run also needs
  its real attached live run (the opaque string, in `live_run_file`), an assigned
  TASK, a checkout lease it may claim, and a Grant on the served anchor and ref.
- **A configured checker.** The merge queue's default checker is an isolated
  Linux session backend with its pinned image and toolchain; the explicit host
  opt-in setting is the only other way. Without one, queue init and every later
  check answer `needs_configuration` and name the setting.
- **No review policy is needed** (FIX 8268). A pushed change becomes ONE
  `received_files` proposal that names no catalog. With no vault review policy
  set (`vault.code.merge_queue.review_policy.get` answers `land_on_green`), the
  queue's intake enqueues it once into the same checks; nothing approves it and
  no check is skipped. The import manifest's catalog is not a review policy.
- Real reviewers, only if an owner opted the vault into a review policy
  (`vault.code.merge_queue.review_policy.set`). Then matching only proposes:
  reviews go through `vault.code.proposal_review`, approval through
  `vault.code.proposal_settle`, and the owner enqueues. The script reads
  `vault.code.proposal_settlement` and never votes. A policy row that does not
  read holds the candidate until an owner sets or clears it.

## Running it

```sh
bun run /absolute/path/examples/code-roundtrip/roundtrip.ts --plan /absolute/path/plan.json
```

Each invocation advances to the next boundary it can, reads each asynchronous
status once, and then exits with one JSON value:

- `roundtrip_pending` (exit 3): rerun it later, after the named prerequisite or
  hold clears. Nothing polls, waits or retries.
- `roundtrip_stopped` (exit 1): a human decides. This includes any effect the
  state file shows as started but never reported (a push, an export, the native
  or edit command). Read `vault.code.origin.publications` and resolve it by hand.
  The script never reruns an effect on its own.
- `roundtrip_complete` (exit 0): printed once, after every proof below passed.

The private `state_file` (mode 0600, outside the source and both clones) keeps
the plan digest, every returned pin and receipt, and the custody of each effect.
It holds no secret and no attachment contents. A changed plan needs a new state
file.

## The plan

`schema_version` must be `1` (`ROUNDTRIP_PLAN_VERSION`). Nothing has a default:
no implied HEAD, branch, command, TTL or timeout.

| Field | Meaning |
|---|---|
| `binary`, `base_url`, `endpoint` | The built `oneiron`, the API origin, and the explicit `/git` door base on that same origin. |
| `owner`, `run` | `{secret_env, binding_key_env}`: the variable NAMES of each credential. |
| `live_run_file` | Absolute private file holding the run's attached live run. |
| `project`, `owner_task`, `run_task` | Existing PROJECT and TASK ids (32 hex). |
| `source_repo`, `source_commit`, `source_ref` | The ordinary Git repository, the full chosen commit, and its full ref. |
| `served_repo`, `default_branch`, `ref_name` | A NEW served name, its branch, and that branch's full ref (it must equal `source_ref`). |
| `owner_checkout`, `run_checkout` | `{checkout, ttl_seconds}` for each lease claim. |
| `clone_dir`, `reclone_dir` | Absolute NEW directories, never overwritten. |
| `state_file` | Absolute private file outside the source and both clones. |
| `manifest_catalog` | The owner-selected review catalog the import's acceptance records. |
| `manifest_review` | `vault.critic.review` input minus `target_ref`, or `null` exactly when the catalog names no lenses. |
| `native_command`, `edit_command` | `{argv, env}`: each runs exactly once in `clone_dir`, with exactly the declared env (declare `PATH`), never a shell. `native_command` is the repository's own build or validation, not its tests. |
| `commit_message` | The message of the one signed edit commit. |
| `git_env` | The non-secret env stock Git runs with (`PATH`, `HOME`, `GNUPGHOME` and so on). |

## The sequence

S is the source commit, B the accepted Baseline revision, P the served branch
and Q the queue's own source. These are labels in this text, not wire fields.

1. The owner registers an empty served origin and pushes exactly `S:source_ref`
   through the direct door (no push certificate). The unique Published
   publication gives the admission receipt and its distinct receive provenance.
2. The owner imports with `accept: null` and keeps the manifest. The owner's
   checkout claims `anchor.snapshot` (never `anchor.repo`) and binds to the door.
3. `vault.code.merge_queue.init` on `anchor.repo` at S. The engine prepares Q,
   one detached worktree of the same store at `<vault env>/merge-queue/<store>/source`.
   Neither the plan nor any response names that root. The sealed Baseline is
   the queue's current green once its checks pass.
4. The manifest review (if the catalog names lenses), then the same import with
   `accept`. Only `promoted` with the same B and a promotion receipt continues.
5. The run claims its own checkout of the snapshot and binds it with
   `vault.repo.checkout.bind`. It receives its lease remote.
6. The owner previews B against S with `vault.code.export.preview` and reads
   every changed side with `vault.code.export.preview.read`. Then the owner runs
   `vault.code.export` with the same pins. P becomes E0 while Q stays at S.
7. A fresh stock clone of E0 through the run's lease door. Its root tree, every
   path and each changed side's raw bytes must equal the preview. Then
   `native_command` runs once and must leave tracked sources unchanged.
8. `edit_command` runs once. Its tracked change is committed with
   `git commit -S` and pushed as one exact commit U through the run's lease door.
9. The push's ingress (by its receive provenance, not its publication receipt),
   its ONE all-files candidate proposal, its fork and the run's TASK are read.
10. With no vault review policy, the queue's intake has enqueued the candidate
    (its `batch_refs`); with one set, once reviewed and approved, one owner
    enqueue. The queue checks, lands and seals in Q. Its check receipts are
    kept: every retained generation, in saved order. The candidate's
    `revision_refs` is the seal bound to this push.
11. The owner previews that seal against U. Its target tree must be U's tree.
    Then `vault.code.merge_queue.export_green`, whose request has no revision pin:
    a revision that differs from the previewed seal stops the run and is shown,
    never relabelled. A fresh re-clone must hold U's exact tree, with S and U as
    ancestors. Engine commit ids may differ from U. The trees may not.

## Signed Git transport

Stock Git makes several HTTP requests, and one static header would replay one
nonce. `with_signed_git_relay` listens on 127.0.0.1 at an OS-assigned port,
under one random in-memory prefix per relay, with `idleTimeout: 0`. It forwards
only the pinned door's `info/refs` and pack routes, each through `oneiron api
raw`, which signs every request afresh. A failed upstream call is never answered
as success. No bearer reaches argv or `.git/config`. The owner's relay serves the
source push alone and is closed before any native or edit command runs. Clones
and the edit push use the run's credential only.

## What this proves, and what it does not

It proves the exported bytes: complete paths, Git modes and raw blob bytes,
compared as objects, never as checkout-filtered text or followed symlinks. It
does not prove checker isolation (the checker's own concern), binary edit, LFS,
submodule or signature parity, a public release, or any UI. A preview is exact
for its pins even when the ref has moved since. It is never a reservation: the
export keeps its own compare-and-swap.
