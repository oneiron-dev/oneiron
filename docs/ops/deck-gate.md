# The deck export gate run (OF-510, `pptx-live-v1`)

The live deck body exports through the projector, but its exports stay
proposals, and blob versions stay authoritative, until the export gate opens
(ARCH-0077, "The eight-step import-then-export check"). The gate
(`Gate::is_open`, `crates/oneiron-docedit/src/live/deck_export.rs`) opens only
on an `OracleReceipt` for `pptx-live-v1` with `clean: true`, all eight steps
`passed`, and a `projector` equal to the server's. The receipt names the run it
came from, as the run manifest pins it: `projector`, `source_sha` (the full
commit the engine half was built from) and `case_manifest_sha256`. The vault
records it through `vault.artifacts.body.deck.oracle`, checks those pins for
form, and keeps them as given; it never stamps a receipt with its own projector.
A receipt that names no run is refused. A receipt from another projector's run
records as that run's evidence and opens nothing, so rerun the whole set after
every projector bump.

Nothing in the run names a projector version by hand. `deck-gate-engine` reads
`PROJECTOR_VERSION` from the live crate it was built from, so a run binds
whatever projector main carries at the run's `$sha`. The run manifest records
it (`projector` in `manifest.json`), and `plan`, the `## DECK-GATE` line,
`gate-evidence.json` and the receipt repeat it.

The run has two halves, because the Mac mini (`vel`, the only host with
PowerPoint) cannot build the workspace:

| Half | Where | What |
|---|---|---|
| Engine | a Linux fleet host (`nelly` or `mel`) | `deck-gate-engine` (`crates/oneiron/src/bin/`: docedit's `deck-gate-cases` runner given the engine's Loro body) exports every candidate through the current projector and runs the engine side of all eight steps. |
| Office | `vel`, through the fleet, one booking, serial | `office/deck_gate.py` opens each candidate in the pinned PowerPoint, checks PowerPoint's save-back for the intended change and writes the receipt. |

The case set is `scripts/office/pptx-live-v1.json`:

| Step | Engine half | Office half |
|---|---|---|
| 1 Baseline preservation | no-op export returns the archive's own bytes; typed reads match the fixture's pins | (the no-op candidates open in step 6) |
| 2 Edit preservation | 14 mutations over a baseline with unknown-XML probes in the shape and slide extension lists: unexplained part changes and displaced or rewritten probes fail | |
| 3 Semantic fixed point | each edited export re-imported and compared by binding (values, structure, identity bindings); its own export must be a byte-identical no-op | |
| 4 Concurrency | the seven ARCH-0077 cases, landed in both orders through fork, preflight and land: conflicts surfaced in both orders, or both landed with no dangling reference and an exportable head (each order's export kept as a candidate; how the two orders' heads compare is landing-order evidence in the case's notes, not convergence); convergence is `loro_peers`: two Loro peers of one body merged in both import orders by the engine must read back as one deck, children in one order, with one export (`deck-gate-cases` alone cannot run it: inconclusive) | |
| 5 Corruption | every candidate: package closure, content types, relationship targets and ids, slide and master id scopes, shape-id ambiguity, animation, connector and comment cross-references; and schema validation (xmllint over the pinned ECMA-376 transitional XML Schemas, `scripts/office/deck_schema.py`), bound to the candidate's SHA-256, charged only with diagnostics the deck it came from lacked. No schema report: inconclusive | |
| 6 Office oracle | every candidate written and pinned; the run names its source commit (no `--source`, or not a full commit: inconclusive) | every candidate opens clean (no repair), saves PDF, rasterizes with PDFKit and saves reference XML; the save-back shows the intended change; a timeout is inconclusive; a candidate PowerPoint never opens, or refuses, is a failed row and the pass goes on |
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
- The account running the Office half needs a console (Aqua) session on vel:
  it owns `/dev/console`, or `who` lists its `console` login. Without one the
  pass refuses before opening anything with "log olety into vel's desktop (use
  fast user switching for decktest)", not with osascript's -10810.
- `scripts/office/README.md` "Safe Mac setup" applies: Automation and
  Accessibility granted once, no Grant File Access, no other open presentation.
  The Office half takes the shared lock `~/w7-oracle/lock` and releases it on
  every exit it can catch (SIGTERM and SIGHUP included; only SIGKILL leaves it).
  A lock left by a pass whose recorded process (`pid=` on its owner line) no
  longer exists is moved aside before the next pass takes the lock, as
  `~/w7-oracle/lock.stale-<that run's directory name>`, with a log line and
  `lock_moved` in `office-run.json`. It is never deleted. A lock whose holder
  is alive, or whose owner line names no pid (another oracle's, or an older
  pass's), stays and the pass refuses: check it and move it by hand. When PowerPoint custody is uncertain it says so: check
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
cd /Users/olety/Desktop/temp/deck-gate && fleet run --who deck-gate --goal "OF-510 deck gate engine half $run" --need rust-1.96 --host nelly --mem 32G --no-mem-floor --threads 6 --disk 30 --timeout 3h --sync /Users/olety/Desktop/temp/deck-gate/job -- bash deck_gate_linux.sh "$sha" "$run" > /Users/olety/Desktop/temp/deck-gate/$run-engine.log 2>&1
```

The job clones oneiron at `$sha`, runs `deck_gate.py acquire` for the PPTArena
originals (kept beside the synced tree in `deck-gate-corpus/`; the download
never opens a deck), fetches the pinned ECMA-376 Part 4 transitional XML
Schemas with `deck_schema.py fetch` (kept in `deck-gate-schemas/`; when the
fetch fails the run goes on and step 5 stays inconclusive), then builds
`deck-gate-engine` in release (the whole engine crate: hence the 20G, 3h
booking) and runs it with `--source $sha`. Its first line names the run
directory:

```
## DECK-GATE-ENGINE start host=<host> sha=<sha> out=<run directory on the host>
```

The runner journals each case as it finishes to `results.jsonl` in that
directory: a header line with the run's pins, then one synced line per case
(its step outcomes, candidates, calibration fixtures, notes and `elapsed_ms`),
written after the files it names. Stderr gets one progress line per case
(`deck-gate-cases: <case> <outcome> <ms> ms`, from either binary). At the end the runner folds the
journal into `manifest.json`, written whole, and journals a run-complete line.
The job's last line is

```
## DECK-GATE-ENGINE rc=<rc> acquire=<rc> schemas=<rc> host=<host> out=<run directory on the host> journal_lines=<n> bytes=<size>
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

The test account (`decktest`) drives PowerPoint from its own Terminal, so that
terminal app, the one the pass actually runs in, needs both grants in System
Settings > Privacy & Security, signed in as `decktest`:

- Accessibility (the observer reads PowerPoint's windows through System
  Events; without it the pass refuses before opening anything);
- Full Disk Access, so it can stage and clear decks in PowerPoint's container,
  `/Users/decktest/Library/Containers/com.microsoft.Powerpoint/Data/tmp`.

With iTerm, start the pass from a `.command` file in the run directory:
`open -a iTerm /Users/Shared/deck-gate/<run>/<script>.command`. Granting
Terminal.app does not cover iTerm, nor the other way round.

PowerPoint 16.113 shows first-run notices to a new account. The pass dismisses
only the named ones in `scripts/office/deck_session.py` (`KNOWN_DIALOGS`: the
"Introducing Copilot" notice, and "What's New"), each at most once per pass,
with a decline or close button, never one that accepts or signs in; it does so
when a candidate's session meets one (its setup, while it is watched, or at
cleanup). Every dismissal is a line in the log and a row in `office-run.json`
`dialog_dismissals` and in the candidate's `receipt.json`. Any other dialog is
handled as before: the candidate is unsupported, and one left after cleanup
stops the pass.

The observer reads PowerPoint's windows one by one; a window that closes while
it is read (an export progress sheet, a slow open) is read again until the
candidate's deadline. A deadline that passes is that candidate's timed-out row
(inconclusive). A candidate PowerPoint never opens, or refuses as input, is a
failed row (`failure`: `never_opened` or `unsupported_input` in its receipt,
with the osascript error), and the pass goes on to the next candidate: one
candidate never stops a pass. Only the environment does (custody, a foreign
presentation, missing access, an unknown dialog left after cleanup).

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
default. The reply is the gate view: `open`, the server's `projector` and the
stored receipt, which carries its run's `projector`, `source_sha` and
`case_manifest_sha256`. The gate opens only when the receipt's `projector` is the
server's; nobody compares them by hand. When `open` is false on an all-pass clean
receipt, the server moved past the run's projector: record a fresh run. A
receipt from a run made before receipts named their run (no pins) is refused;
run the set again. Recording replaces the profile's earlier receipt, so a failing
receipt, or one from another projector's run, closes a gate a pass opened. Read
the gate back with:

```sh
oneiron api call vault.artifacts.body.deck.gate --data '{}'
```

`office-results/gate-evidence.json` holds every case's verdict and detail.
`assemble` rebuilds the receipt from the results without opening Office:
`python3 -B office/deck_gate.py assemble <run>`.
