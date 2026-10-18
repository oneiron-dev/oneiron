//! What a run writes: candidates with their hashes and owed Office checks,
//! each step's engine cases, and the run manifest the Office half reads.

use super::checks;
use super::spec::CaseManifest;
use crate::live::deck_export::{PROJECTOR_VERSION, StepOutcome};
use crate::retained_opc::{Limits, XmlLimits};
use serde::Serialize;
use sha2::Digest as _;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub(super) type Res<T> = Result<T, String>;

/// The run manifest's schema; `deck_gate.py` refuses any other.
pub(super) const RUN_SCHEMA: &str = "oneiron.deck-gate-run/1";

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Trust {
    Fixture,
    Untrusted,
}

/// What the Office half checks in PowerPoint's save-back of a candidate
/// (slides count from 1 in presentation order; ids are `p:cNvPr/@id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Serialize)]
pub(super) struct Candidate {
    pub(super) id: String,
    pub(super) file: String,
    pub(super) sha256: String,
    pub(super) bytes: usize,
    /// The steps the Office result of this candidate feeds.
    pub(super) steps: Vec<u8>,
    pub(super) trust: Trust,
    pub(super) checks: Vec<OfficeCheck>,
}

/// An adversarial fixture the Office half classifies against its expected
/// oracle status (failed, repaired, timed out).
#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub(super) struct FileRef {
    pub(super) path: String,
    pub(super) sha256: String,
    pub(super) bytes: usize,
}

/// A passed case's note: what it could not exercise on its deck.
#[derive(Debug, Serialize)]
pub(super) struct Note {
    pub(super) id: String,
    pub(super) note: String,
}

#[derive(Debug, Serialize)]
pub(super) struct Excluded {
    pub(super) id: String,
    pub(super) reason: String,
}

#[derive(Debug, Serialize)]
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
    projector: &'static str,
    source: String,
    case_manifest: FileRef,
    office: OfficeRef,
    steps: Vec<StepRecord>,
    candidates: Vec<Candidate>,
    calibration: Vec<Calibration>,
    excluded: Vec<Excluded>,
    notes: Vec<Note>,
}

impl RunManifest {
    pub(super) fn new(
        cases: &CaseManifest,
        source: String,
        case_manifest: FileRef,
        scripts: Vec<FileRef>,
        steps: Vec<StepRecord>,
        run: &mut Run,
    ) -> Self {
        Self {
            schema: RUN_SCHEMA,
            profile: cases.profile.clone(),
            projector: PROJECTOR_VERSION,
            source,
            case_manifest,
            office: OfficeRef {
                scripts,
                timeout_seconds: cases.office.timeout_seconds,
                observer: cases.office.observer.clone(),
                owner_accounts: cases.office.owner_accounts.clone(),
            },
            steps,
            candidates: std::mem::take(&mut run.candidates),
            calibration: std::mem::take(&mut run.calibration),
            excluded: std::mem::take(&mut run.excluded),
            notes: std::mem::take(&mut run.notes),
        }
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
}

/// The run in progress.
pub(super) struct Run {
    out: PathBuf,
    pub(super) limits: Limits,
    cases: Vec<(u8, CaseRecord)>,
    pub(super) candidates: Vec<Candidate>,
    pub(super) calibration: Vec<Calibration>,
    pub(super) excluded: Vec<Excluded>,
    notes: Vec<Note>,
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
            cases: Vec::new(),
            candidates: Vec::new(),
            calibration: Vec::new(),
            excluded: Vec::new(),
            notes: Vec::new(),
        })
    }

    /// Write `bytes` at `relative` inside the run; its reference.
    pub(super) fn write_file(&self, relative: &str, bytes: &[u8]) -> Res<FileRef> {
        let path = self.out.join(relative);
        std::fs::write(&path, bytes).map_err(|error| format!("{}: {error}", path.display()))?;
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

    pub(super) fn record(&mut self, step: u8, id: &str, outcome: StepOutcome) {
        self.cases.push((
            step,
            CaseRecord {
                id: id.to_owned(),
                outcome,
            },
        ));
    }

    pub(super) fn note(&mut self, id: &str, note: String) {
        self.notes.push(Note {
            id: id.to_owned(),
            note,
        });
    }

    /// Write one candidate, run the corruption checks on it, and owe the
    /// Office half its checks.
    pub(super) fn candidate(&mut self, emit: Emit<'_>) -> Res<()> {
        let file = format!("candidates/{}.pptx", emit.id);
        let written = self.write_file(&file, emit.bytes)?;
        let outcome = checks::corruption(emit.bytes, self.limits, emit.baseline);
        self.record(emit.lane.step(CORRUPTION), emit.id, outcome);
        self.candidates.push(Candidate {
            id: emit.id.to_owned(),
            file,
            sha256: written.sha256,
            bytes: written.bytes,
            steps: emit.steps.to_vec(),
            trust: emit.lane.trust(),
            checks: emit.checks,
        });
        Ok(())
    }

    /// The eight steps, each with its cases and engine outcome.
    pub(super) fn steps(&self) -> Vec<StepRecord> {
        (1..=8u8)
            .zip(STEP_NAMES)
            .map(|(step, name)| {
                let cases: Vec<CaseRecord> = self
                    .cases
                    .iter()
                    .filter(|(at, _)| *at == step)
                    .map(|(_, case)| case.clone())
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
