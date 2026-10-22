//! What a run writes: candidates with their hashes and owed Office checks,
//! each step's engine cases, and the run manifest the Office half reads.

use super::checks;
use super::journal::{self, CaseLine, Header, JOURNAL_SCHEMA, Journal, Line, write_atomic};
use super::schema::{SchemaEvidence, Validator};
use super::spec::CaseManifest;
use crate::live::deck_export::{PROJECTOR_VERSION, StepOutcome};
use crate::retained_opc::{Limits, XmlLimits};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub(super) type Res<T> = Result<T, String>;

/// The run manifest's schema; `deck_gate.py` refuses any other.
pub(super) const RUN_SCHEMA: &str = "oneiron.deck-gate-run/1";
/// The run manifest's name inside the run directory.
pub(super) const MANIFEST: &str = "manifest.json";

pub(super) const BASELINE: u8 = 1;
pub(super) const EDIT: u8 = 2;
pub(super) const FIXED_POINT: u8 = 3;
pub(super) const CONCURRENCY: u8 = 4;
pub(super) const CORRUPTION: u8 = 5;
pub(super) const ORACLE: u8 = 6;
pub(super) const NON_PDF: u8 = 7;
pub(super) const REGRESSION: u8 = 8;

/// The eight steps in canon order (ARCH-0077).
const STEP_NAMES: [&str; 8] = [
    "baseline preservation",
    "edit preservation",
    "semantic fixed point",
    "concurrency",
    "corruption",
    "office oracle",
    "non-PDF checks",
    "regression",
];

/// Steps whose outcome also needs the Office half.
const OFFICE_STEPS: [u8; 3] = [ORACLE, NON_PDF, REGRESSION];

/// How many failing cases a step's outcome names before it counts the rest.
const NAMED_CASES: usize = 4;

/// The document name every projection runs under: part of the export key
/// and of every creation-id seed, so candidates are reproducible.
pub(super) const DOCUMENT: &str = "deck-oracle";

pub(super) fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub(super) fn failed(why: impl Into<String>) -> StepOutcome {
    StepOutcome::Failed(why.into())
}

pub(super) fn verdict(result: Res<()>) -> StepOutcome {
    match result {
        Ok(()) => StepOutcome::Passed,
        Err(why) => StepOutcome::Failed(why),
    }
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = sha2::Sha256::digest(bytes).into();
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The engine's shipped docedit resource row (`gate::default_manifest`):
/// the runner opens a deck under the same codec bounds a vault's live body
/// does, so a deck the engine would refuse is refused here too.
pub(super) fn engine_limits() -> Limits {
    Limits {
        archive_bytes: 512 * 1024 * 1024,
        entries: 10_000,
        part_bytes: 64 * 1024 * 1024,
        expanded_bytes: 512 * 1024 * 1024,
        xml: XmlLimits {
            max_depth: 256,
            max_nodes: 1_000_000,
        },
    }
}

/// Where a case's engine results land: the core set feeds its own step; the
/// corpus feeds regression, which runs the same path (step 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Lane {
    Core,
    Corpus,
}

impl Lane {
    pub(super) fn step(self, step: u8) -> u8 {
        match self {
            Self::Core => step,
            Self::Corpus => REGRESSION,
        }
    }

    pub(super) fn trust(self) -> Trust {
        match self {
            Self::Core => Trust::Fixture,
            Self::Corpus => Trust::Untrusted,
        }
    }
}

/// Whether PowerPoint may open a candidate in the owner's account. Corpus
/// decks are untrusted: only an isolated account opens them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Trust {
    Fixture,
    Untrusted,
}

/// What the Office half checks in PowerPoint's save-back of a candidate
/// (slides count from 1 in presentation order; ids are `p:cNvPr/@id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "check", rename_all = "snake_case")]
pub(super) enum OfficeCheck {
    /// PDFKit rasterized this many pages.
    Pages {
        count: usize,
    },
    Slides {
        count: usize,
    },
    Text {
        slide: usize,
        contains: String,
    },
    NoText {
        slide: usize,
        absent: String,
    },
    Shape {
        slide: usize,
        id: u32,
        offset: Option<(i64, i64)>,
    },
    NoShape {
        slide: usize,
        id: u32,
    },
    /// The slide part's markup holds this text.
    Markup {
        slide: usize,
        contains: String,
    },
    /// A modern comment on the slide with this text.
    Comment {
        slide: usize,
        text: String,
    },
    /// An animation target on the shape, and its paragraph range when given.
    Timing {
        slide: usize,
        spid: u32,
        paragraphs: Option<(u32, u32)>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Candidate {
    pub(super) id: String,
    pub(super) file: String,
    pub(super) sha256: String,
    pub(super) bytes: usize,
    /// The steps the Office result of this candidate feeds.
    pub(super) steps: Vec<u8>,
    pub(super) trust: Trust,
    pub(super) checks: Vec<OfficeCheck>,
    /// The schema validator's report on these bytes, or why there is none
    /// (step 5, FIX 8590).
    pub(super) schema: SchemaEvidence,
}

/// An adversarial fixture the Office half classifies against its expected
/// oracle status (failed, repaired, timed out).
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Calibration {
    pub(super) id: String,
    pub(super) file: String,
    pub(super) sha256: String,
    pub(super) bytes: usize,
    pub(super) expected_oracle: String,
    pub(super) timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CaseRecord {
    pub(super) id: String,
    pub(super) outcome: StepOutcome,
}

/// One engine result of a case, under the step it feeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StepCase {
    pub(super) step: u8,
    pub(super) id: String,
    pub(super) outcome: StepOutcome,
}

#[derive(Debug, Serialize)]
pub(super) struct StepRecord {
    pub(super) step: u8,
    pub(super) name: &'static str,
    /// The engine half's outcome over its cases.
    pub(super) engine: StepOutcome,
    /// Whether the Office half also decides this step.
    pub(super) office: bool,
    pub(super) cases: Vec<CaseRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct FileRef {
    pub(super) path: String,
    pub(super) sha256: String,
    pub(super) bytes: usize,
}

/// A passed case's note: what it could not exercise on its deck.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Note {
    pub(super) id: String,
    pub(super) note: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Excluded {
    pub(super) id: String,
    pub(super) reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct OfficeRef {
    pub(super) scripts: Vec<FileRef>,
    pub(super) timeout_seconds: u64,
    pub(super) observer: String,
    pub(super) owner_accounts: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct RunManifest {
    schema: &'static str,
    profile: String,
    projector: String,
    source: String,
    case_manifest: FileRef,
    office: OfficeRef,
    pub(super) steps: Vec<StepRecord>,
    pub(super) candidates: Vec<Candidate>,
    pub(super) calibration: Vec<Calibration>,
    excluded: Vec<Excluded>,
    notes: Vec<Note>,
}

impl RunManifest {
    /// The manifest of a run, folded from its journal: the header's pins
    /// and every finished case's records, in the order they finished.
    fn folded(header: Header, lines: Vec<CaseLine>) -> Self {
        let mut results = Vec::new();
        let mut manifest = Self {
            schema: RUN_SCHEMA,
            profile: header.profile,
            projector: header.projector,
            source: header.source,
            case_manifest: header.case_manifest,
            office: header.office,
            steps: Vec::new(),
            candidates: Vec::new(),
            calibration: Vec::new(),
            excluded: Vec::new(),
            notes: Vec::new(),
        };
        for line in lines {
            results.extend(line.results);
            manifest.candidates.extend(line.candidates);
            manifest.calibration.extend(line.calibration);
            manifest.excluded.extend(line.excluded);
            manifest.notes.extend(line.notes);
        }
        manifest.steps = steps(&results);
        manifest
    }
}

/// One exported candidate to write and hand to the Office half.
pub(super) struct Emit<'a> {
    pub(super) id: &'a str,
    pub(super) bytes: &'a [u8],
    pub(super) steps: &'a [u8],
    pub(super) lane: Lane,
    pub(super) checks: Vec<OfficeCheck>,
    /// The defects its baseline already had: step 5 judges only new ones.
    pub(super) baseline: &'a [String],
    /// The bytes of the deck it came from: the schema diagnostics those
    /// already have are not charged to it either.
    pub(super) origin: &'a [u8],
}

/// A case in progress: what it recorded since it began, journaled whole
/// when it finishes.
struct Open {
    id: String,
    started: Instant,
    results: Vec<StepCase>,
    candidates: Vec<Candidate>,
    calibration: Vec<Calibration>,
    excluded: Vec<Excluded>,
    notes: Vec<Note>,
}

impl Open {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            started: Instant::now(),
            results: Vec::new(),
            candidates: Vec::new(),
            calibration: Vec::new(),
            excluded: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.results.is_empty()
            && self.candidates.is_empty()
            && self.calibration.is_empty()
            && self.excluded.is_empty()
            && self.notes.is_empty()
    }
}

/// What the case a record lands in is called when no case is open: a
/// record outside every case is still journaled, when the run completes.
const UNCASED: &str = "run";

/// The run in progress.
pub(super) struct Run {
    out: PathBuf,
    pub(super) limits: Limits,
    journal: Option<Journal>,
    /// The cases open now, innermost last; a record lands in the innermost.
    open: Vec<Open>,
    /// The schema validator step 5 asks; `None` when the run was given no
    /// schema set.
    pub(super) schema: Option<Validator>,
    /// The engine's two-peer Loro merge of one body, for step 4's
    /// `loro_peers` case; `None` in a runner built without the engine.
    pub(super) peers: Option<super::PeerMerge>,
}

impl Run {
    /// A new output directory; an existing one is refused, never reused.
    pub(super) fn create(out: &Path) -> Res<Self> {
        if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        std::fs::create_dir(out).map_err(|error| {
            format!(
                "{}: {error} (the output directory must be new)",
                out.display()
            )
        })?;
        for dir in ["candidates", "calibration", "office"] {
            std::fs::create_dir(out.join(dir))
                .map_err(|error| format!("{}: {error}", out.join(dir).display()))?;
        }
        Ok(Self {
            out: out.to_path_buf(),
            limits: engine_limits(),
            journal: None,
            open: Vec::new(),
            schema: None,
            peers: None,
        })
    }

    /// Start the journal with the run's pins, before any case.
    pub(super) fn begin(
        &mut self,
        cases: &CaseManifest,
        source: String,
        case_manifest: FileRef,
        scripts: Vec<FileRef>,
    ) -> Res<()> {
        let header = Header {
            schema: JOURNAL_SCHEMA.to_owned(),
            source,
            projector: PROJECTOR_VERSION.to_owned(),
            profile: cases.profile.clone(),
            case_manifest,
            office: OfficeRef {
                scripts,
                timeout_seconds: cases.office.timeout_seconds,
                observer: cases.office.observer.clone(),
                owner_accounts: cases.office.owner_accounts.clone(),
            },
        };
        self.journal = Some(Journal::create(&self.out, header)?);
        Ok(())
    }

    /// Write `bytes` at `relative` inside the run, whole and synced, before
    /// anything names it; its reference.
    pub(super) fn write_file(&self, relative: &str, bytes: &[u8]) -> Res<FileRef> {
        write_atomic(&self.out.join(relative), bytes)?;
        Ok(FileRef {
            path: relative.to_owned(),
            sha256: sha256_hex(bytes),
            bytes: bytes.len(),
        })
    }

    /// Copy the Office half's scripts from `scripts/office/`, so the run
    /// directory is all the Mac mini needs.
    pub(super) fn copy_scripts(&self, repo: &Path, names: &[String]) -> Res<Vec<FileRef>> {
        names
            .iter()
            .map(|name| {
                let source = repo.join("scripts/office").join(name);
                let bytes = std::fs::read(&source)
                    .map_err(|error| format!("{}: {error}", source.display()))?;
                self.write_file(&format!("office/{name}"), &bytes)
            })
            .collect()
    }

    /// Run one case: everything `body` records lands in it (or in a case it
    /// opens), and it finishes as one journal line whatever `body` returns,
    /// a refusal, an early return or an error that stops the run.
    pub(super) fn case<T>(&mut self, id: &str, body: impl FnOnce(&mut Self) -> Res<T>) -> Res<T> {
        self.open.push(Open::new(id));
        let result = body(self);
        let open = self.open.pop().ok_or("the case stack is empty")?;
        let finished = self.finish(open, result.as_ref().err());
        match (result, finished) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(why), Ok(())) => Err(why),
            (Ok(_), Err(journal)) => Err(journal),
            (Err(why), Err(journal)) => Err(format!("{why}; and {journal}")),
        }
    }

    /// Journal a finished case and print its progress line. A case that
    /// recorded nothing (one that only held others) writes no line.
    fn finish(&mut self, open: Open, error: Option<&String>) -> Res<()> {
        if open.is_empty() && error.is_none() {
            return Ok(());
        }
        let elapsed_ms = u64::try_from(open.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let outcome = match error {
            Some(why) => StepOutcome::Inconclusive(format!("the run stopped here: {why}")),
            None => aggregate(
                &open
                    .results
                    .iter()
                    .map(|result| CaseRecord {
                        id: result.id.clone(),
                        outcome: result.outcome.clone(),
                    })
                    .collect::<Vec<_>>(),
            ),
        };
        let progress = format!(
            "deck-gate-cases: {} {} {elapsed_ms} ms",
            open.id,
            word(&outcome)
        );
        let line = CaseLine {
            id: open.id,
            outcome,
            elapsed_ms,
            error: error.cloned(),
            results: open.results,
            candidates: open.candidates,
            calibration: open.calibration,
            excluded: open.excluded,
            notes: open.notes,
        };
        self.journal
            .as_mut()
            .ok_or("a case finished before the journal began")?
            .append(&Line::Case(line))?;
        let _ = writeln!(std::io::stderr(), "{progress}");
        Ok(())
    }

    /// The case a record lands in: the innermost open one.
    fn top(&mut self) -> &mut Open {
        if self.open.is_empty() {
            self.open.push(Open::new(UNCASED));
        }
        self.open.last_mut().expect("a case is open")
    }

    pub(super) fn record(&mut self, step: u8, id: &str, outcome: StepOutcome) {
        self.top().results.push(StepCase {
            step,
            id: id.to_owned(),
            outcome,
        });
    }

    pub(super) fn note(&mut self, id: &str, note: String) {
        self.top().notes.push(Note {
            id: id.to_owned(),
            note,
        });
    }

    pub(super) fn exclude(&mut self, excluded: Excluded) {
        self.top().excluded.push(excluded);
    }

    pub(super) fn calibrate(&mut self, calibration: Calibration) {
        self.top().calibration.push(calibration);
    }

    /// Write one candidate, run the corruption checks on it, and owe the
    /// Office half its checks.
    pub(super) fn candidate(&mut self, emit: Emit<'_>) -> Res<()> {
        let file = format!("candidates/{}.pptx", emit.id);
        let written = self.write_file(&file, emit.bytes)?;
        let schema = match self.schema.as_mut() {
            Some(validator) => validator.evidence(emit.bytes, &written.sha256, emit.origin),
            None => SchemaEvidence::absent("the run was given no schema set (--schemas)"),
        };
        let outcome = checks::corruption(
            emit.bytes,
            self.limits,
            emit.baseline,
            &schema,
            &written.sha256,
        );
        self.record(emit.lane.step(CORRUPTION), emit.id, outcome);
        self.top().candidates.push(Candidate {
            id: emit.id.to_owned(),
            file,
            sha256: written.sha256,
            bytes: written.bytes,
            steps: emit.steps.to_vec(),
            trust: emit.lane.trust(),
            checks: emit.checks,
            schema,
        });
        Ok(())
    }

    /// Every finished case so far, read back from the journal.
    pub(super) fn journaled(&self) -> Res<Vec<CaseLine>> {
        journal::fold(&self.out).map(|(_, lines)| lines)
    }

    /// End the run: journal any record left outside a case, fold the
    /// journal into the manifest, write it whole, and journal the run's
    /// completion. The manifest.
    pub(super) fn complete(&mut self) -> Res<RunManifest> {
        while let Some(open) = self.open.pop() {
            self.finish(open, None)?;
        }
        let (header, lines) = journal::fold(&self.out)?;
        let cases = lines.len();
        let manifest = RunManifest::folded(header, lines);
        let bytes = serde_json::to_vec_pretty(&manifest).map_err(text)?;
        let written = self.write_file(MANIFEST, &bytes)?;
        self.journal
            .as_mut()
            .ok_or("the run completed before the journal began")?
            .append(&Line::Complete {
                manifest: written,
                cases,
            })?;
        Ok(manifest)
    }
}

/// An outcome in one word, for a progress line.
fn word(outcome: &StepOutcome) -> &'static str {
    match outcome {
        StepOutcome::Passed => "passed",
        StepOutcome::Failed(_) => "FAILED",
        StepOutcome::Inconclusive(_) => "inconclusive",
        StepOutcome::NotRun => "not-run",
    }
}

/// The eight steps over every result, each with its cases and engine
/// outcome.
fn steps(results: &[StepCase]) -> Vec<StepRecord> {
    (1..=8u8)
        .zip(STEP_NAMES)
        .map(|(step, name)| {
            let cases: Vec<CaseRecord> = results
                .iter()
                .filter(|result| result.step == step)
                .map(|result| CaseRecord {
                    id: result.id.clone(),
                    outcome: result.outcome.clone(),
                })
                .collect();
            StepRecord {
                step,
                name,
                engine: aggregate(&cases),
                office: OFFICE_STEPS.contains(&step),
                cases,
            }
        })
        .collect()
}

/// A step passes only when it ran cases and every one passed; a failure
/// outranks an open case, and an unrun step is never a pass.
fn aggregate(cases: &[CaseRecord]) -> StepOutcome {
    if cases.is_empty() {
        return StepOutcome::Inconclusive("no case ran".to_owned());
    }
    let mut failures = Vec::new();
    let mut open = Vec::new();
    for case in cases {
        match &case.outcome {
            StepOutcome::Passed => {}
            StepOutcome::Failed(why) => failures.push(format!("{}: {why}", case.id)),
            StepOutcome::Inconclusive(why) => open.push(format!("{}: {why}", case.id)),
            StepOutcome::NotRun => open.push(format!("{}: not run", case.id)),
        }
    }
    if !failures.is_empty() {
        return StepOutcome::Failed(summary(&failures));
    }
    if !open.is_empty() {
        return StepOutcome::Inconclusive(summary(&open));
    }
    StepOutcome::Passed
}

fn summary(lines: &[String]) -> String {
    let mut out = lines
        .iter()
        .take(NAMED_CASES)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    if lines.len() > NAMED_CASES {
        let _ = write!(out, " (+{} more)", lines.len() - NAMED_CASES);
    }
    out
}
