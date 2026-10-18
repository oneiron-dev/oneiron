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
//! PowerPoint owes it, beside the engine outcome of each step.
//!
//! The Office half (`scripts/office/deck_gate.py`, on the Mac mini) opens
//! those candidates under the pinned environment, joins its outcomes to the
//! engine's and writes the [`super::OracleReceipt`] the gate takes through
//! `vault.artifacts.body.deck.oracle`. Evidence tooling, not a test:
//! nothing here runs under `cargo test`.

mod assets;
mod checks;
mod edits;
mod merge;
mod nonpdf;
mod recipes;
mod record;
mod regression;
mod spec;
mod suite;
mod variants;

use super::deck_export::{ExportProfile, PROJECTOR_VERSION, StepOutcome};
use record::{ORACLE, Run, RunManifest};
use std::path::PathBuf;

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
    /// The source revision the runner was built from, recorded as given.
    pub source: String,
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
    let scripts = run.copy_scripts(&options.repo, &cases.office.scripts)?;
    let case_manifest = run.write_file("case-manifest.json", &manifest_bytes)?;
    for baseline in &cases.baselines {
        suite::baseline(&mut run, &options.repo, baseline, &cases)?;
    }
    regression::adversarial(
        &mut run,
        &options.repo,
        &cases.regression.adversarial,
        cases.office.timeout_seconds,
    )?;
    regression::corpus(
        &mut run,
        &options.repo,
        options.corpus.as_deref(),
        &cases.regression.pptarena,
    )?;
    let office = run
        .candidates
        .iter()
        .filter(|c| c.steps.contains(&ORACLE))
        .count();
    if office > 0 {
        run.record(ORACLE, "candidates", StepOutcome::Passed);
    }
    let steps = run.steps();
    let engine_passed = steps.iter().all(|step| step.engine == StepOutcome::Passed);
    let lines = steps
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
            run.candidates.len(),
            run.calibration.len(),
            cases.profile
        )))
        .collect();
    let manifest = RunManifest::new(
        &cases,
        options.source.clone(),
        case_manifest,
        scripts,
        steps,
        &mut run,
    );
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(record::text)?;
    run.write_file("manifest.json", &bytes)?;
    Ok(RunSummary {
        lines,
        engine_passed,
        manifest: options.out.join("manifest.json"),
    })
}

fn outcome_line(outcome: &StepOutcome) -> String {
    match outcome {
        StepOutcome::Passed => "passed".to_owned(),
        StepOutcome::Failed(why) => format!("FAILED {why}"),
        StepOutcome::Inconclusive(why) => format!("inconclusive {why}"),
        StepOutcome::NotRun => "not run".to_owned(),
    }
}
