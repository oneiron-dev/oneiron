//! The OF-510 deck gate runner, engine half: the `pptx-live-v1` case set
//! through the current projector (ARCH-0077, "The eight-step
//! import-then-export check").
//!
//! [`run`] reads the case manifest (`scripts/office/pptx-live-v1.json`),
//! imports each pinned baseline and derives the fixture variants the steps
//! need: unknown-XML probes beside the mutated shape, a modern comment and a
//! paragraph animation. It applies every live mutation, merges the
//! concurrent cases in both landing orders, and runs the regression corpus
//! and the adversarial fixtures through the same path. Every exported
//! candidate is written to a new directory with its SHA-256 and the checks
//! PowerPoint owes it, beside the engine outcome of each step. Each case is
//! journaled as it finishes (`results.jsonl`), so a run cut short keeps
//! every case it finished; the run manifest is folded from that journal.
//!
//! The Office half (`scripts/office/deck_gate.py`, on the Mac mini) opens
//! those candidates under the pinned environment, joins its outcomes to the
//! engine's and writes the [`super::OracleReceipt`] the gate takes through
//! `vault.artifacts.body.deck.oracle`. Evidence tooling, not a test:
//! nothing here runs under `cargo test`.
//!
//! [`main_with`] is the command line: docedit's `deck-gate-cases` runs it
//! without the engine, the engine's `deck-gate-engine` (crates/oneiron)
//! with its two-peer Loro merge ([`PeerMerge`]), which step 4's convergence
//! case needs; the gate's engine half runs the latter.

mod assets;
mod checks;
mod cli;
mod edits;
mod journal;
mod merge;
mod nonpdf;
mod recipes;
mod record;
mod regression;
mod schema;
mod spec;
mod suite;
mod text_check;
mod variants;

use super::deck_export::{ExportProfile, PROJECTOR_VERSION, StepOutcome};
use super::{DeckOp, LiveDeck};
pub use cli::main_with;
use record::{ORACLE, Run};
use std::path::{Path, PathBuf};

/// The engine's merge of two Loro peers of one deck body (FIX 3773): each
/// side's operations applied in its own peer forked at `base`'s frontier,
/// the two merged in both import orders (a then b, b then a), each read
/// back as a deck, or the engine's reason it refused that order.
pub type PeerMerge =
    fn(&LiveDeck, &[DeckOp], &[DeckOp]) -> Result<[Result<LiveDeck, String>; 2], String>;

/// What one run reads and where it writes.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// The repository root: the case manifest, the fixtures and the Office
    /// scripts are read from it.
    pub repo: PathBuf,
    /// A new directory for the candidates and the run manifest.
    pub out: PathBuf,
    /// Pinned PPTArena pairs as `deck_gate.py acquire` lays them out
    /// (`<corpus>/<case>/original.pptx`); `None` leaves the corpus unrun.
    pub corpus: Option<PathBuf>,
    /// The source revision the runner was built from, recorded as given;
    /// `None` records the run's provenance as missing (FIX 8573).
    pub source: Option<String>,
    /// The pinned schema set `scripts/office/deck_schema.py fetch` wrote;
    /// `None` leaves step 5 without schema evidence, inconclusive.
    pub schemas: Option<PathBuf>,
    /// The engine's two-peer Loro merge; `None` leaves step 4's
    /// convergence case inconclusive.
    pub peers: Option<PeerMerge>,
}

/// The engine outcome of a run, one line per step.
#[derive(Debug, Clone)]
pub struct RunSummary {
    pub lines: Vec<String>,
    /// Every engine half passed; the Office half still decides the gate.
    pub engine_passed: bool,
    pub manifest: PathBuf,
}

/// Generate the `pptx-live-v1` candidates and run every engine step.
pub fn run(options: &RunOptions) -> Result<RunSummary, String> {
    let manifest_path = options.repo.join(spec::CASE_MANIFEST);
    let (cases, manifest_bytes): (spec::CaseManifest, Vec<u8>) = spec::read_json(&manifest_path)?;
    if cases.version != 1 {
        return Err(format!(
            "{}: case manifest version {} is not 1",
            manifest_path.display(),
            cases.version
        ));
    }
    if cases.profile != ExportProfile::default().name {
        return Err(format!(
            "{}: the case manifest is for profile {}, the projector exports {}",
            manifest_path.display(),
            cases.profile,
            ExportProfile::default().name
        ));
    }
    let mut run = Run::create(&options.out)?;
    run.schema = options
        .schemas
        .as_deref()
        .map(|schemas| schema::Validator::new(&options.repo, schemas));
    run.peers = options.peers;
    let scripts = run.copy_scripts(&options.repo, &cases.office.scripts)?;
    let case_manifest = run.write_file("case-manifest.json", &manifest_bytes)?;
    let source = options.source.clone().unwrap_or_default();
    run.begin(&cases, source, case_manifest, scripts)?;
    run.case("provenance", |run| {
        provenance(run, options.source.as_deref(), &options.repo);
        Ok(())
    })?;
    for baseline in &cases.baselines {
        run.case(&baseline.id, |run| {
            suite::baseline(run, &options.repo, baseline, &cases)
        })?;
    }
    run.case("adversarial", |run| {
        regression::adversarial(
            run,
            &options.repo,
            &cases.regression.adversarial,
            cases.office.timeout_seconds,
        )
    })?;
    run.case("pptarena", |run| {
        regression::corpus(
            run,
            &options.repo,
            options.corpus.as_deref(),
            &cases.regression.pptarena,
        )
    })?;
    let office = run
        .journaled()?
        .iter()
        .flat_map(|line| &line.candidates)
        .filter(|c| c.steps.contains(&ORACLE))
        .count();
    if office > 0 {
        run.case("candidates", |run| {
            run.record(ORACLE, "candidates", StepOutcome::Passed);
            Ok(())
        })?;
    }
    let manifest = run.complete()?;
    let engine_passed = manifest
        .steps
        .iter()
        .all(|step| step.engine == StepOutcome::Passed);
    let lines = manifest
        .steps
        .iter()
        .map(|step| {
            format!(
                "step {} {}: {}",
                step.step,
                step.name,
                outcome_line(&step.engine)
            )
        })
        .chain(std::iter::once(format!(
            "{} candidates, {} calibration fixtures, profile {}, projector {PROJECTOR_VERSION}",
            manifest.candidates.len(),
            manifest.calibration.len(),
            cases.profile
        )))
        .collect();
    Ok(RunSummary {
        lines,
        engine_passed,
        manifest: options.out.join(record::MANIFEST),
    })
}

/// Whether `source` names a full commit, as a receipt's `source_sha` must.
fn full_commit(source: &str) -> bool {
    source.len() == 40 && source.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The run's provenance (FIX 8573): a given full commit is kept as given; a
/// malformed one, or none, is named in a note and leaves step 6
/// inconclusive, since the receipt could not name the commit its run came
/// from. Nothing is refused, guessed or invented: the repository's HEAD at
/// run time, when git answers, is an unverified note only, never the
/// binary's source.
fn provenance(run: &mut Run, source: Option<&str>, repo: &Path) {
    const ID: &str = "provenance";
    match source {
        Some(given) if full_commit(given) => run.note(
            ID,
            format!("provenance given: {given}, as the caller asserts it built this runner"),
        ),
        Some(given) => {
            run.note(
                ID,
                format!("provenance malformed: --source {given:?} is not a full commit"),
            );
            run.record(
                ORACLE,
                ID,
                StepOutcome::Inconclusive(format!(
                    "the given source {given:?} is not a full 40-character commit: the receipt cannot name its run"
                )),
            );
        }
        None => {
            let head = git_head(repo).map_or_else(String::new, |head| {
                format!("; git HEAD of {} at run time is {head} (unverified, not proof of the binary's source)", repo.display())
            });
            run.note(
                ID,
                format!("provenance missing: no --source was given{head}"),
            );
            run.record(
                ORACLE,
                ID,
                StepOutcome::Inconclusive(
                    "the run names no source revision (no --source): the receipt cannot name its run"
                        .to_owned(),
                ),
            );
        }
    }
}

/// `git rev-parse HEAD` in `repo`, when git answers with a full commit.
fn git_head(repo: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    let head = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (output.status.success() && full_commit(&head)).then_some(head)
}

fn outcome_line(outcome: &StepOutcome) -> String {
    match outcome {
        StepOutcome::Passed => "passed".to_owned(),
        StepOutcome::Failed(why) => format!("FAILED {why}"),
        StepOutcome::Inconclusive(why) => format!("inconclusive {why}"),
        StepOutcome::NotRun => "not run".to_owned(),
    }
}
