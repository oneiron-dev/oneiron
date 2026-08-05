# WORKLOG — ONE-1810 [VOX-00] Producer adapter-skill: productize the transcribe tool

lane: VOX (head) · seat: standard · size: L · stack: VOX-pipe layer 1

## Custody / paths
- Engine worktree (ON claims): `/Volumes/Cinema/w5-lt/vox` (branch `ONE-1810`, base `w5/vox/main`)
- Satellite repo (TR claims): transcribe — canonical checkout `/Users/olety/Desktop/code/transcribe` (main @ 79e2718)
  - **decision seg0**: work TR in a dedicated worktree `/Volumes/Cinema/w5-lt/vox-transcribe`
    on branch `ONE-1810`, so the owner's live `~/Desktop/code/transcribe` checkout (which is
    a symlink-installed working tool at `~/.local/bin/transcribe`) is never mutated by the lane.
    Orchestrator must push BOTH branches (engine + transcribe) at verdict close.
- CLAIMS read END-TO-END: `/Users/olety/.claude-wave5/blueprints/VOX/CLAIMS.md` ✅
- Blueprint read END-TO-END: `/Users/olety/.claude-wave5/blueprints/VOX/ONE-1810.md` ✅

## Claim set (from CLAIMS.md §ONE-1810 + blueprint §Claims)
TR: `transcribe` (edit) · `README.md` (edit) · `transcribe_pipeline/{__init__,contracts,audio,pipeline}.py` (new) ·
    `tests/test_producer_pipeline.py` (new)
ON: `crates/oneiron/src/ingest.rs` (edit) · `src/ingest/tests.rs` (edit) · `src/lib.rs` (edit — seam: before 1800) ·
    `crates/oneiron/tests/fixtures/ingest/meeting_transcript_v1.json` (new)

Seam law: ON `lib.rs` is shared 1810 → 1800 → 1806 (re-export additions only, rebase-trivial).
ON `ingest.rs` is 1810-ONLY. Must NOT touch: `session_lifecycle.rs`, `facade.rs`, `registry.rs`,
`skill.rs`, `skill_hub.rs`, NOTE registration, CAL files.

## Segment log

### seg0 (this segment)
- [x] Read CLAIMS.md + blueprint end-to-end
- [x] Recon: worktree state, transcribe repo state, engine ingest.rs/tests.rs sizes
- [x] Recon: read `transcribe` script — audio path (VAD `_build_vad_windows`, LocalBackend/
      RemoteBackend, `structure_with_llm`, `render_markdown`, `process_one`, `main` argparse)
- [x] Recon: engine `ingest.rs` (608 ln) + `ingest/tests.rs` (346 ln) + lib.rs re-export block
- [x] Impl: `transcribe_pipeline/` package — contracts.py (wire shapes + encoder),
      audio.py (packing/remap/aligner chunking), pipeline.py (orchestration + backends)
- [x] Impl: transcribe script — `sys.path.insert(0, resolved parent)` bootstrap before the
      package import; `--emit-ingest-json PATH` single-file audio mode; `GroqCleanupBackend`;
      markdown rendered FROM the artifact; docstring EXAMPLES/OUTPUT updated
- [x] Impl: README.md — package section, symlink note, structural guarantees
- [x] Impl: `tests/test_producer_pipeline.py` — 37 tests, all green (homebrew python3 + pytest)
- [x] Impl: engine — `MeetingTranscriptSource`, `IngestAdapterSkillRef`,
      `IngestSourceConfig.adapter_skill`, `NormalizedIngestNote`,
      `NormalizedIngestBatch.note_fallback`, 6 new document-shaped error variants,
      2-entry registry, lib.rs re-exports, fixture, 13 new tests
- [x] Gate: `cargo test -p oneiron --lib ingest` → 38 passed, 0 failed
- [x] Gate: `cargo check -p oneiron --all-features --all-targets` → clean
- [x] Gate: `cargo clippy -p oneiron --all-features --all-targets` → zero warnings
- [x] Gate: `cargo test -p oneiron --all-features --lib` → **3164 passed, 0 failed**
      (split into two runs to fit the harness timeout: 2774 with sync/hnsw skipped,
      then 390 sync+hnsw. A first single-shot run was SIGTERM'd by the harness
      timeout at 600s while other lanes held the cargo lock — zero test failures in
      its output, external kill, not a red.)
- [x] Gate: `cargo test -p oneiron --all-features --tests` → **3450 passed, 0 failed**
- [x] Gate: `cargo fmt -p oneiron --check` → clean (rustfmt applied to 2 files, retested)

## Design decisions worth flagging at screen

1. **Two cutting policies, deliberately separate.** `plan_boundary_packs` (ASR packing, cuts
   only at VAD boundaries) and `plan_alignment_chunks` (aligner input, cuts with overlap) never
   interact. The blueprint's rule "alignment has its own sub-chunking rule and never changes
   ASR pack or transcript boundaries" is enforced by them living in different functions with
   no shared state, and asserted by
   `test_over_five_minute_span_aligns_in_sub_chunks_but_keeps_text_and_provenance`.

2. **Trailing pack may sit below `PACK_MIN_MS`.** First test run caught this: a recording's
   final pack is the remainder — there is no later boundary to cut at, so requiring ≥90s of
   it would mean either dropping real speech or cutting the previous pack short. The band
   describes where to CUT; the tail is what's left. Packs below the 2-second floor are still
   dropped entirely. Test asserts the band on `packs[:-1]` and total speech conservation.

3. **Pack-fill tie-break.** Same test run surfaced that `>=` on the drift comparison closed
   packs at exactly 90s when 120s was equally distant from the 105s target. Changed to strict
   `>`: ties keep the span, so packs fill rather than fragment.

4. **`crossed_join` rather than a silent shift.** A word straddling a removed silence gets its
   true source extent (left half from the earlier span, right half from the later) plus a flag.
   The blueprint says "split or flagged, never silently shifted" — flagging is the honest read,
   since the word's audio genuinely spans the gap.

5. **`decode_cleanup_response` takes ONLY text from the model.** Turn ids, times, word grounding,
   and speaker fields are re-read from the input turn of the same id, so a model that rewrote a
   timestamp cannot land one even before the validator runs. Validator then catches
   dropped/reordered/invented turns.

6. **`AsrPackResult.words = None` vs `()`.** `None` means "provider gave no timings, run the
   aligner"; an empty tuple would mean "provider says there are no words". Conflating them
   would silently skip alignment on a genuinely wordless pack.

7. **Engine errors are document-shaped, not line-shaped.** The existing `IngestError` variants
   all carry `line: usize`, which is meaningless for a single-document artifact. Added 6
   variants that name a JSON path or an id instead. Existing JSONL variants untouched.

8. **`speaker_ref` outranks `speaker_cluster`.** Resolved identity wins; with neither the record
   is speaker-less rather than attributed to a guess. At this layer `speaker_ref` is always
   null (ONE-1800 fills it), so the fixture exercises both arms.

9. **Missing `capture_started_at` is not a batch failure.** Turns stay ordered and
   offset-bearing; they normalize with `occurred_at: None`. Failing the whole batch over an
   absent wall-clock anchor would discard good turns.

10. **Satellite worktree.** TR claims are worked in `/Volumes/Cinema/w5-lt/vox-transcribe`
    (branch ONE-1810) rather than the owner's live `~/Desktop/code/transcribe` checkout, which
    is symlink-installed at `~/.local/bin/transcribe` and in daily use. **The orchestrator must
    push BOTH branches** — engine `ONE-1810` in `/Volumes/Cinema/w5-lt/vox` and transcribe
    `ONE-1810` in `/Volumes/Cinema/w5-lt/vox-transcribe` (remote
    `https://github.com/olety/transcribe.git`).

## Not done by this ticket (blueprint-explicit)
- No SESSION/TURN/NOTE/follow-up/Dreamer entity minted; no `session_lifecycle.rs`, `facade.rs`,
  `registry.rs`, `skill.rs`, `skill_hub.rs`, or CAL file touched.
- No entity type byte allocated.
- No Meet bot / Drive connector / recorder / platform capture.
- `diarization` (ONE-1799) and `identity` (ONE-1800) are reserved and emitted `null`.

## Segment log — fix leg (K3, w5-belt-vox)

Fix list applied as per-fix commits. Satellite commits live in
`/Volumes/Cinema/w5-lt/vox-transcribe` (branch ONE-1810); the engine commit in
`/Volumes/Cinema/w5-lt/vox` (branch ONE-1810).

- [x] FIX1 `.gitignore` packet violation — reverted commit `b096b14` (revert
      chosen over PACKET_AMEND: pycache-on-disk untracked is the constraint).
- [x] FIX2 forced-aligner unwired — new `transcribe_pipeline/forced_aligner_qwen3.py`
      (`Qwen3ForcedAligner` over the local mlx-audio hub, lazy load) +
      `ProducerConfig.forge_default()` auto-wiring it when the hub is
      importable; CLI's ingest path forges through it. Missing provider words
      now land through the aligner, never ProducerError.
- [x] FIX3 asr text loss — `_merge_timed_with_text`: provider timed words
      interleave with the full text stream; skipped tokens are emitted in ORDER
      position with `timed=False` and BOTH endpoints null (interpolation stays
      forbidden). Test at :739 inverted: "hello there" is the output.
- [x] FIX4 alignment chunking — reconcile is now a pure same-word dedup over
      the overlap; a 700s pack / six-word transcript yields exactly 6 ordered
      words (pin test).
- [x] FIX5 pack-band overrun — overrun rule fires on the OPEN pack whenever
      the next span would carry it past PACK_MAX_MS; `[0,80s]+[90,140s]` mints
      an 80s pack plus a 50s under-band tail.
- [x] FIX6 vad-speech accounting — Silero detector runs UNPADDED; pad is
      applied as explicit arithmetic (edges out by speech_pad_ms, clamped at
      neighbours). `speech_ms` = detected speech, extent = what gets sliced.
- [x] FIX7 join provenance — `TimedWord.crossed_join` carried through and
      emitted on the wire only when true.
- [x] FIX8 satellite bridge — all-silence/all-blank input mints body "empty
      audio recording (no detected speech), <duration>"; engine's non-empty
      note requirement passes.
- [x] FIX9 cleanup status sealing — `status=done` requires decisions,
      action_items, open_questions AND garbled_spans as present keys; a
      done-flagged subset response rejects at decode and at validate.
- [x] FIX10 cleanup grounding — invented `owner`/`due` values (absent from
      every input turn's text) reject; garbled-span timestamps must sit inside
      the input time bounds.
- [x] FIX11 adapter dispatch — `--emit-ingest-json` short-circuits the
      stale-md skip guard before any md existence check; source-order pin test
      + README documents the behaviour change.
- [x] FIX12 timestamp remap — directional span ownership (start inclusive,
      end exclusive); a word whose endpoints land in the same span is not
      flagged `crossed_join`.
- [x] FIX13 capture-time — `_capture_started_at` mtime fallback deleted;
      `capture_started_at: None` flows to engine `occurred_at: None`.
- [x] FIX14 timestamp overflow — engine `occurred_at` uses checked_add;
      u64::MAX-adjacent capture_started_at rejects with
      `IngestError::TimestampOverflow`.
- [x] FIX15 hygiene — ruff F401 unused imports removed; `ruff check` clean.
- [x] Gates: `pytest tests/test_producer_pipeline.py` 54 green;
      `pytest --collect-only` on forced_aligner_qwen3 OK;
      engine `cargo test -p oneiron --all-features --lib` 3165 green, fmt
      clean, clippy clean.
