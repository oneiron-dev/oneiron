# Deck preservation oracle (ONE-2531)

This is a repository test mechanism, not the document writer. It asks the pinned
PowerPoint for Mac to open a **copy**, export PDF, uses PDFKit to rasterize every
page, then saves a reference `.pptx`. It records SHA-256 of the candidate and
all outputs with PowerPoint/macOS/PDFKit/font-inventory settings. A PowerPoint
save-back is diagnostic, never the writer's canonical output. `clean` requires
all four steps and checked, nonempty PDF/PNGs/ZIP. Repair, failures, timeouts,
and unsupported environments are distinct, never passes.

## Safe Mac setup and live run

Run untrusted PPTArena decks only in an isolated macOS test account with
network and active content disabled. The Mac mini needs Microsoft PowerPoint
installed and signed in, and the calling process (Terminal or its runner) needs
one macOS Automation permission to control PowerPoint. System Events needs
Accessibility permission to inspect dialogs and hide the app. Do not grant
PowerPoint access to a repo workspace: a **Grant File Access** prompt means
staging is wrong and the run is `unsupported`.

The oracle copies each input into a fresh private directory under
`~/Library/Containers/com.microsoft.Powerpoint/Data/tmp/w8-oracle/<name>-<pid>/`.
PowerPoint reads that copy and writes PDF and save-back there; PDFKit also writes
PNGs there. The harness moves outputs to the result directory and removes the
staging directory in `finally`. It launches PowerPoint in the background, never
activates it, hides it after each call, and closes only the staged presentation.
It refuses any pre-existing open presentation, including a saved but hidden one.
The serial fixture runner quits PowerPoint once at the end only when it
started the app and no presentations remain. It leaves an existing app running. A standalone `run` leaves the app running without its deck. A known repair
alert naming our staged deck is dismissed using **Cancel**, not Repair. The
harness never clicks a Grant File Access prompt.
Use a new result directory each time.

From the repository root on the Mac mini, run the live matrix exactly as follows:

```sh
python3 scripts/office/run_fixture_matrix.py scripts/office/fixtures/.runs/mac-mini-001
```

To run one case, or the opt-in Mac test:

```sh
python3 scripts/office/deck_oracle.py run \
  scripts/office/fixtures/clean.pptx scripts/office/fixtures/.runs/clean-001 \
  --observer system-events --timeout 90
ONEIRON_DECK_ORACLE=1 python3 -m unittest scripts/office/test_deck_oracle.py -v
```

On Linux or without PowerPoint the matrix and opt-in test skip with a clear
reason. Offline classification, fixture, custody and review-seed tests run on
all hosts:

```sh
python3 -m unittest scripts/office/test_deck_oracle.py -v
python3 scripts/office/review_seed_check.py scripts/office/review_example.json
python3 scripts/office/deck_oracle.py classify scripts/office/fixtures.json \
  scripts/office/fixtures/.runs/mac-mini-001
```

`fixtures.json` names a safe local clean deck, a missing-slide repair candidate,
a non-ZIP failed-open file, an invalid-presentation damaged candidate, and an
injected one-second timeout run (use `--timeout 1` with the clean fixture).
The repair candidate runs last and is expected to trigger a repair prompt; if a PowerPoint
build refuses it outright, the matrix must report a failure, not silently
change the expectation. `test_deck_oracle.py` pins timeout handling without
requiring a flaky real hang. The local clean source was generated with
`python-pptx` from one textbox; no external document content is shipped.

## Environment approval and receipt gates

`environment.json` is the versioned approved Mac/renderer pin. It fixes the
PowerPoint and macOS builds, PDFKit version, font-inventory SHA-256, observer,
locale, raster scale and harness version. The oracle records the observed pin
but refuses to open a candidate when any approved field differs. Update the
configuration explicitly after checking a deliberate Mac or Office upgrade;
never change it just to turn an unsupported result green. The committed Mac
mini receipts show the reference values.

`classify` requires each receipt's input SHA-256 to match the fixture hash or
one of that PPTArena case's pinned original/ground-truth hashes. Missing or
wrong-case evidence fails. Missing cases and unexpected timeouts stay
inconclusive, and both fail the CLI exit status.

## Recorded Mac mini result

The post-review passing live fixture run and hashed outputs are committed
under [`results/mac-mini-008/`](results/mac-mini-008/). Its summary and host pin are
in [`results/README.md`](results/README.md). Use a **new** result directory for
each later run; the command above shows the invocation shape, not a reusable
output path.

## PPTArena preservation matrix

`pptarena.json` pins all 100 case names, source/ground-truth paths, SHA-256
binary hashes, corpus revision and index hash. Profiles mark clearly excluded
v1 authoring (SmartArt, themes/masters, animations, video, transitions) as
read-only; other cases require **case-level** verb and dependency checks. A
case profile is scope classification, not proof that an edit passed. Oracle
`expected_oracle: clean` is the opening expectation for each source/target,
not a claim that the reference output preserves unknown XML. A candidate edit
still needs the independent per-part diff, semantic fixed point and render
checks in ARCH-0077 before it passes preservation.

```sh
python3 scripts/office/deck_oracle.py acquire pptarena-064 /private/tmp/pptarena-064
```

`acquire` downloads one pair at the pinned Hugging Face commit and checks both
SHA-256 values. It never opens either file. The dataset card says MIT, but the
underlying slides have mixed sources and no per-deck license proof. Do not
redistribute binaries or run downloaded decks outside the isolated account.
Run one case at a time, then place its receipts under `<results>/pptarena-064`
and classify against `pptarena.json`. Missing cases are `inconclusive`, not a
pass. A damaged candidate is a failure even if some renderer can make a PNG.

`review_seed.json` is the v1 editable claim-strength and audience-glossary
question seed from ARCH-0077. It is data, not a hard-coded prompt in Rust.
An agent can write the v1 answer packet and run its strict checker now:

```sh
python3 scripts/office/review_seed_check.py scripts/office/review_example.json
```

The checker rejects stale glossary versions, unknown/duplicate questions,
missing evidence, and out-of-range probabilities. SLD-03's chat activation,
model execution and comment-writing proposal remain a separate follow-on;
this packet checker does not pretend to be that agent runtime.
