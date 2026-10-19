# The deck export gate run (OF-510, `pptx-live-v1`)

The live deck body exports through the projector, but its exports stay
proposals, and blob versions stay authoritative, until the export gate opens
(ARCH-0077, "The eight-step import-then-export check"). The gate
(`Gate::is_open`, `crates/oneiron-docedit/src/live/deck_export.rs`) opens only
on an `OracleReceipt` for `pptx-live-v1` with `clean: true` and all eight steps
`passed`. The vault records the receipt through `vault.artifacts.body.deck.oracle`
and stamps it with the server's projector version. A receipt from another
projector does not count, so rerun the whole set after every projector bump.

Nothing in the run names a projector version by hand. `deck-gate-cases` reads
`PROJECTOR_VERSION` from the live crate it was built from, so a run binds
whatever projector main carries at the run's `$sha`. The run manifest records
it (`projector` in `manifest.json`), and `plan`, the `## DECK-GATE` line and
`gate-evidence.json` repeat it.

The run has two halves, because the Mac mini (`vel`, the only host with
PowerPoint) cannot build the workspace:

| Half | Where | What |
|---|---|---|
| Engine | a Linux fleet host (`nelly` or `mel`) | `deck-gate-cases` (`crates/oneiron-docedit/src/bin/`) exports every candidate through the current projector and runs the engine side of all eight steps. |
| Office | `vel`, through the fleet, one booking, serial | `office/deck_gate.py` opens each candidate in the pinned PowerPoint, checks PowerPoint's save-back for the intended change and writes the receipt. |

The case set is `scripts/office/pptx-live-v1.json`:

| Step | Engine half | Office half |
|---|---|---|
| 1 Baseline preservation | no-op export returns the archive's own bytes; typed reads match the fixture's pins | (the no-op candidates open in step 6) |
| 2 Edit preservation | 14 mutations over a baseline with unknown-XML probes in the shape and slide extension lists: unexplained part changes and displaced or rewritten probes fail | |
| 3 Semantic fixed point | each edited export re-imported and compared by binding (values, structure, identity bindings); its own export must be a byte-identical no-op | |
| 4 Concurrency | the seven ARCH-0077 cases, landed in both orders through fork, preflight and land: conflicts surfaced in both orders, or convergence with no dangling reference and an exportable head | |
| 5 Corruption | every candidate: package closure, content types, relationship targets and ids, slide and master id scopes, shape-id ambiguity, animation, connector and comment cross-references | |
| 6 Office oracle | every candidate written and pinned | every candidate opens clean (no repair), saves PDF, rasterizes with PDFKit and saves reference XML; the save-back shows the intended change; a timeout is inconclusive |
| 7 Non-PDF checks | a modern comment survives text and geometry edits of its slide; a paragraph build is kept, remapped or refused when its text changes | PowerPoint's save-back still holds the comment and the build |
| 8 Regression | the 100 pinned PPTArena originals through steps 1, 2, 3 and 5; the adversarial fixtures refused or imported as pinned | the corpus candidates open clean (isolated account only); `failed-open`, `damaged-candidate`, `repair-prompt` and `timeout` classify as expected; font versions recorded |

Each step's outcome is the worse of its two halves. An unrun, timed-out or
unsupported case is inconclusive, and the gate stays closed.

## Before you start

- The Mac mini's PowerPoint, macOS, PDFKit, observer and locale must match
  `scripts/office/environment.json`, and so must the running account's font
  inventory. The Office half refuses before opening anything when they differ.
  Update the pin only after checking a deliberate upgrade
  (`scripts/office/README.md`).
- The font inventory is per account: the SHA-256 of sorted JSON rows
  `{root_label, relative_path, bytes, sha256}` over the font files in
  `/System/Library/Fonts`, `/Library/Fonts`, the account's `~/Library/Fonts`
  and the PowerPoint bundle's `Contents/Resources/DFonts` and `Fonts`. A
  missing root or an unreadable file is a row of its own; mtime is never
  identity. `environment.json` holds one approved digest per account in
  `approved_font_inventories`, and each receipt records its `font_account` and
  `font_inventory_sha256`, judged against that account's approval. The digest
  is measured once per Office pass; the pass also writes the rows to
  `office-results/font-inventory.json`.
- Approve each account once, and again after a deliberate font or Office
  change, on vel in a source checkout of the commit you will run, as that
  account. The refusal prints the observed digest and this command:

  ```sh
  python3 -I scripts/office/deck_oracle.py fonts
  python3 -I scripts/office/deck_oracle.py fonts --approve scripts/office/environment.json
  ```

  The first command prints the rows and the digest; check them. The second
  records only this account's digest. Do it for `olety` (over ssh) and for
  `decktest` (in its own logged-in Terminal), then commit `environment.json`
  and start a new run: a run directory pins its copy of the script, so
  approving inside a run invalidates it.
- `scripts/office/README.md` "Safe Mac setup" applies: Automation and
  Accessibility granted once, no Grant File Access, no other open presentation.
  The Office half takes the shared lock `~/w7-oracle/lock` and releases it on
  every exit it can catch (SIGTERM and SIGHUP included; only SIGKILL leaves it,
  to remove by hand). When PowerPoint custody is uncertain it says so: check
  the Mac mini; the next pass refuses while PowerPoint holds a presentation.
  Three custody queries in a row that PowerPoint leaves unanswered stop the
  pass with an environment verdict: inconclusive, never a pass.
- PPTArena decks are untrusted. Their candidates open only in the isolated macOS
  test account (network and active content off, logged in, PowerPoint signed in).
  The owner account (`office.owner_accounts`) refuses `--isolated-account`.
- Never run the Office half on the owner's MacBook.

Throughout, `$sha` is the full origin/main commit under test and `$run` names the
run:

```sh
sha=$(git -C /Users/olety/Desktop/code/oneiron ls-remote origin refs/heads/main | cut -f1)
run=deck-gate-$(date +%Y%m%d)-${sha:0:12}
mkdir -p /Users/olety/Desktop/temp/deck-gate/job
git -C /Users/olety/Desktop/code/oneiron fetch -q origin
git -C /Users/olety/Desktop/code/oneiron show "$sha:scripts/office/deck_gate_linux.sh" > /Users/olety/Desktop/temp/deck-gate/job/deck_gate_linux.sh
```

## 1. Engine half (Linux fleet host)

```sh
cd /Users/olety/Desktop/temp/deck-gate && fleet run --who deck-gate --goal "OF-510 deck gate engine half $run" --need rust-1.96 --host nelly --mem 12G --no-mem-floor --threads 8 --disk 30 --timeout 2h --sync /Users/olety/Desktop/temp/deck-gate/job -- bash deck_gate_linux.sh "$sha" "$run" > /Users/olety/Desktop/temp/deck-gate/$run-engine.log 2>&1
```

The job clones oneiron at `$sha`, runs `deck_gate.py acquire` for the PPTArena
originals (kept beside the synced tree in `deck-gate-corpus/`; the download
never opens a deck), builds `deck-gate-cases` and runs it. Its first line names
the run directory:

```
## DECK-GATE-ENGINE start host=<host> sha=<sha> out=<run directory on the host>
```

The runner journals each case as it finishes to `results.jsonl` in that
directory: a header line with the run's pins, then one synced line per case
(its step outcomes, candidates, calibration fixtures, notes and `elapsed_ms`),
written after the files it names. Stderr gets one progress line per case
(`deck-gate-cases: <case> <outcome> <ms> ms`). At the end the runner folds the
journal into `manifest.json`, written whole, and journals a run-complete line.
The job's last line is

```
## DECK-GATE-ENGINE rc=<rc> acquire=<rc> host=<host> out=<run directory on the host> journal_lines=<n> bytes=<size>
```

`rc=0`: every engine half passed. `rc=1`: the run directory is complete, but an
engine half failed or stayed open, so the receipt will say so. Carry it on so the
recorded receipt names the failure. `clone-failed` and `out-exists` wrote no
run. `rc=2` (the runner stopped on an error) and `rc=stopped` (the job was
killed or timed out) leave an incomplete run: `results.jsonl` holds every case
that finished and no `manifest.json`.

An incomplete run is evidence, not a gate run. Pull it as in step 2 and run
`plan` on it: `deck_gate.py` reports the finished cases from the journal's
complete lines (a line cut by the stop is the case in progress, never counted)
with their outcomes per step, then refuses with exit 2. `office` and
`assemble` refuse it the same way, so no Office pass and no receipt come from
an incomplete run. Fix what stopped it and run the engine half again under a
new `$run`.

## 2. Bring the run to the Mac and check it

```sh
rsync -az nelly:<out path from the DECK-GATE-ENGINE line>/ /Users/olety/Desktop/temp/deck-gate/$run/
python3 -B /Users/olety/Desktop/temp/deck-gate/$run/office/deck_gate.py plan /Users/olety/Desktop/temp/deck-gate/$run
```

`plan` checks every pinned file and prints the engine outcome of each step. It
opens nothing. It must print no `PROBLEM` line. On an incomplete run it prints
the journal's finished cases and refuses (exit 2).

## 3. Office half on the Mac mini (owner account, through the fleet)

```sh
cd /Users/olety/Desktop/temp/deck-gate && fleet run --who deck-gate --goal "OF-510 deck gate Office half $run" --need macos --host vel --mem 4G --threads 1 --no-mem-floor --timeout 6h --sync /Users/olety/Desktop/temp/deck-gate/$run -- python3 -B office/deck_gate.py office . > /Users/olety/Desktop/temp/deck-gate/$run-office.log 2>&1
```

The fleet syncs the run to `/Users/olety/fleet-work/sync/deck-gate/$run` on vel and
runs inside it. The pass opens every fixture candidate, then the calibration
fixtures, one PowerPoint session at a time. Results go to
`office-results/<candidate>/` there. A pass that stops early (unsupported
environment, cleanup warning) prints `STOPPED`. Fix the cause and rerun the same
command: candidates that already have a receipt are kept.

## 4. Corpus pass (isolated test account on the Mac mini)

Copy the run where the test account can read and write it, then run the same
script there:

```sh
ssh vel "mkdir -p /Users/Shared/deck-gate && cp -R /Users/olety/fleet-work/sync/deck-gate/$run /Users/Shared/deck-gate/ && chmod -R a+rwX /Users/Shared/deck-gate/$run"
```

In the test account's own logged-in Terminal on the Mac mini:

```sh
cd /Users/Shared/deck-gate/<run> && python3 -B office/deck_gate.py office . --isolated-account
```

This adds the untrusted corpus candidates to the results the first pass wrote.
Skipping it leaves step 8 inconclusive and the gate closed. The run directory
carries every corpus candidate, so steps 3 and 4 move as much data as the corpus
holds; budget the sync to vel accordingly.

## 5. Record the receipt

Each pass ends by assembling the receipt and printing
`## DECK-GATE open=<true|false> ... request=<path>` and a
`## DECK-GATE-REQUEST {...}` line. `office-results/oracle-request.json` is exactly
the body the door takes (`{"receipt": OracleReceipt}`). Fetch it from the last
pass (`/Users/olety/fleet-work/sync/deck-gate/$run/office-results/` when step 4
did not run) and record it against the vault, with the owner's `ONEIRON_SECRET` and
`ONEIRON_BINDING_KEY` (Write scope) in the environment:

```sh
scp vel:/Users/Shared/deck-gate/$run/office-results/oracle-request.json /Users/olety/Desktop/temp/deck-gate/$run-request.json
oneiron api call vault.artifacts.body.deck.oracle --data @/Users/olety/Desktop/temp/deck-gate/$run-request.json
```

Use `--base-url` (or `ONEIRON_URL`) for a server that is not the local
default. The reply is the gate view: `open`, `projector` and the stored
receipt. Its `projector` must equal the run's (`projector` in
`/Users/olety/Desktop/temp/deck-gate/$run/manifest.json`). If they differ, the
server moved past the evidence: record a fresh run. Recording replaces the
profile's earlier receipt, so a failing receipt closes a gate a pass opened. Read
the gate back with:

```sh
oneiron api call vault.artifacts.body.deck.gate --data '{}'
```

`office-results/gate-evidence.json` holds every case's verdict and detail.
`assemble` rebuilds the receipt from the results without opening Office:
`python3 -B office/deck_gate.py assemble <run>`.
