//! `eval route-calibration` (Engine row 22229, PR 2): the known-answer bench
//! that gives route-conditioned calibration its first per-route numbers.
//!
//! One run is one fresh vault, its embedded owner the one principal, and one
//! standing yes/no graph question at one id and version. Every case's body is
//! seeded as its own unit before the question is stored over those units. Each
//! case is then prepared through the public standing-answer door, answered by
//! the real [`DecisionLadder`](oneiron::llm::decision::DecisionLadder) whose
//! escalation rung is the configured house read (the production label read:
//! P(yes) is the model's, never the bench's) and whose Big rung is the
//! configured big model when the models file binds one, and admitted with its
//! full decision, so its receipt keeps its clock and so its route. Only after
//! that answer lands is the case's gold written on its unit, through the
//! public gated claim writer, as the fact the question's outcome binding
//! labels. The gold never enters a state the model reads.
//!
//! The report is `route_calibration_report` over the ordinary calibration
//! pairs, beside a run header and a per-case table. A case that abstains,
//! fails or leaves no pair is counted under its own status; nothing fills a
//! group with a substituted label or probability. The vault stays where
//! `--vault` names it, so the existing pair reader reads the same pairs later.

mod cases;
mod house_read;
mod report;
mod vault_flow;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::EntityId;

use super::{EvalError, EvalResult, help_requested, required_value, write_json_line};
use cases::TRUTH_PREDICATE;
use house_read::HouseReadRung;
use report::{
    CaseCounts, CasePins, CaseRow, QuestionPins, ROUTE_CALIBRATION_CONTRACT_VERSION,
    RouteCalibrationRun, RunHeader,
};
use vault_flow::{BenchVault, CaseRun};

/// The five paths one run reads and writes, each named by its own flag.
struct RouteCalibrationArgs {
    models_toml: PathBuf,
    vault: PathBuf,
    definition: PathBuf,
    cases: PathBuf,
    out: PathBuf,
}

impl RouteCalibrationArgs {
    /// Cases, definition, vault and report stay outside the source tree, as
    /// the inference bench keeps its packets and rows.
    fn refuse_in_tree(&self) -> EvalResult<()> {
        for (flag, path) in [
            ("--definition", &self.definition),
            ("--cases", &self.cases),
            ("--vault", &self.vault),
            ("--out", &self.out),
        ] {
            crate::infer::cases::refuse_in_tree(flag, path).map_err(EvalError::RouteCalibration)?;
        }
        Ok(())
    }
}

pub(super) fn run_route_calibration(args: &[String]) -> EvalResult<()> {
    let args = parse_args(args)?;
    args.refuse_in_tree()?;
    if args.out.exists() {
        return Err(failure(format!(
            "--out {} already exists; each run writes a new report",
            args.out.display()
        )));
    }
    let started_at = unix_now();
    let definition = cases::load_definition(&args.definition)?;
    let case_file = cases::load_cases(&args.cases)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let mut rung = HouseReadRung::load(&args.models_toml, &runtime)?;
    let bench = BenchVault::create(&args.vault)?;
    rung.bind_big(bench.vault(), runtime.handle().clone())?;
    let units = bench.seed_units(&case_file.cases)?;
    let question = bench.store_question(definition.input, units.clone())?;
    let budget = question.definition.deadline(bench.vault())?;
    let id = question.definition.question.id;
    let case_run = CaseRun::new(&bench, &rung, &question, budget);
    let mut rows: Vec<CaseRow> = case_file
        .cases
        .iter()
        .zip(&units)
        .map(|(case, unit)| case_run.answer(case, *unit))
        .collect();
    let projected = bench.project(id)?;
    let pairs = bench.pairs(id)?;
    report::join_pairs(&mut rows, &pairs);
    let counts = CaseCounts::of(&rows, pairs.len(), bench.label_count(id)?, projected);
    let header = RunHeader {
        contract_version: ROUTE_CALIBRATION_CONTRACT_VERSION,
        run_id: EntityId::now().to_hex(),
        started_at,
        finished_at: unix_now(),
        vault: bench.path().display().to_string(),
        owner: bench.owner().to_hex(),
        models: rung.pins().clone(),
        question: QuestionPins {
            id: id.to_hex(),
            version: question.definition.question.version,
            definition: args.definition.display().to_string(),
            definition_blake3: definition.blake3,
            dial: question.definition.dial,
            deadline_ms: u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
            outcome_predicate: TRUTH_PREDICATE,
            horizon_seconds: question
                .definition
                .binding
                .as_ref()
                .map(|binding| binding.horizon),
        },
        cases: CasePins {
            path: args.cases.display().to_string(),
            blake3: case_file.blake3,
            count: case_file.cases.len(),
        },
    };
    let run = RouteCalibrationRun {
        header,
        counts,
        cases: rows,
        report: bench.report(id)?,
    };
    report::write(&args.out, &run)?;
    let summary = serde_json::json!({
        "out": args.out.display().to_string(),
        "counts": &run.counts,
    });
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    write_json_line(&summary, &mut lock)
}

fn parse_args(args: &[String]) -> EvalResult<RouteCalibrationArgs> {
    if help_requested(args) {
        return Err(EvalError::HelpRequested);
    }
    let mut models_toml = None;
    let mut vault = None;
    let mut definition = None;
    let mut cases = None;
    let mut out = None;
    let mut index = 0;
    while index < args.len() {
        let (slot, flag): (&mut Option<PathBuf>, &'static str) = match args[index].as_str() {
            "--models-toml" => (&mut models_toml, "--models-toml"),
            "--vault" => (&mut vault, "--vault"),
            "--definition" => (&mut definition, "--definition"),
            "--cases" => (&mut cases, "--cases"),
            "--out" => (&mut out, "--out"),
            other => return Err(EvalError::InvalidArgument(other.to_owned())),
        };
        if slot.is_some() {
            return Err(EvalError::InvalidArgument(format!("{flag} given twice")));
        }
        *slot = Some(PathBuf::from(required_value(args, index, flag)?));
        index += 2;
    }
    Ok(RouteCalibrationArgs {
        models_toml: models_toml.ok_or(EvalError::MissingArgument("--models-toml"))?,
        vault: vault.ok_or(EvalError::MissingArgument("--vault"))?,
        definition: definition.ok_or(EvalError::MissingArgument("--definition"))?,
        cases: cases.ok_or(EvalError::MissingArgument("--cases"))?,
        out: out.ok_or(EvalError::MissingArgument("--out"))?,
    })
}

/// A refusal or failure of this bench, in words.
fn failure(reason: String) -> EvalError {
    EvalError::RouteCalibration(reason)
}

/// A failure an engine door reported in its own words.
fn failure_from(error: impl std::fmt::Display) -> EvalError {
    failure(error.to_string())
}

/// Wall-clock Unix seconds: the clock a standing answer's `answered_at` and its
/// gold fact's `occurred_at` are read on.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
