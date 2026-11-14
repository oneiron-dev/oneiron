//! `eval phonetic` (CROSS-ARCH-0013 §11): the cross-script name bench that
//! decides whether a learned phonetic model is served.
//!
//! One run is one fresh vault holding each case's entity under its names. The
//! learned model (an endpoint on the `[phonetic_embedder]` wire, or vectors
//! computed offline) embeds them through the engine's reconcile door. Each
//! case's query is then asked three ways through the owner's hybrid search:
//! the code rung alone (the query as a heard mention), the learned rung alone
//! (the model's vector of the query), and both. With no model, only the code
//! rung is asked.
//!
//! The report gives R@1, R@5, MRR and the false-positive rate (another entity
//! ranked first) per script pair, for short queries (at most three
//! characters), for hard negatives, and over all cases. Entities are held out
//! whole: a case whose entity the model trained on is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use oneiron::embed::EmbedderLocality;
use oneiron::memory::{HybridPhoneticVectorQuery, HybridSearchRequest};
use oneiron::phonetic_learned::PhoneticEmbedder;
use oneiron::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde::{Deserialize, Serialize};

use super::{EvalError, EvalResult, help_requested, required_value, write_json_line};

const PHONETIC_EVAL_CONTRACT_VERSION: &str = "oneiron.eval_phonetic.v1";
/// Hits each query lists: enough for R@5, and MRR over the top ten.
const QUERY_LIMIT: usize = 10;
/// A query of at most this many characters is in the short slice.
const SHORT_QUERY_CHARS: usize = 3;

/// One line of `--cases`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhoneticCase {
    id: String,
    /// The entity the query must find.
    entity: CaseEntity,
    query: String,
    /// The slice the case reports in, e.g. `Latn-Hani`.
    script_pair: String,
    /// The key of the entity this case's entity is a hard negative of: one
    /// that sounds alike and is another entity.
    #[serde(default)]
    hard_negative_of: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseEntity {
    key: String,
    #[serde(default)]
    kind: EntityKind,
    /// The name first, then the aliases.
    names: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum EntityKind {
    #[default]
    Person,
    Org,
    Place,
}

impl EntityKind {
    const fn entity_type(self) -> u8 {
        match self {
            Self::Person => ENTITY_TYPE_PERSON,
            Self::Org => ENTITY_TYPE_ORG,
            Self::Place => ENTITY_TYPE_PLACE,
        }
    }
}

/// Where the learned model's vectors come from.
enum NameVectors {
    /// A process on the `[phonetic_embedder]` wire: `{"names": [..]}` in,
    /// `{"vectors": [[..], ..]}` out.
    Endpoint {
        client: reqwest::blocking::Client,
        url: String,
    },
    /// Vectors computed offline, one JSONL line `{"name", "vector"}` each.
    Table(BTreeMap<String, Vec<f32>>),
}

/// The learned model under test. The bench's vault is its own, so the model
/// is read as on this device.
struct BenchModel {
    model_id: String,
    dimensions: usize,
    vectors: NameVectors,
}

#[derive(Serialize)]
struct NamesRequest<'a> {
    names: &'a [&'a str],
}

#[derive(Deserialize)]
struct NamesAnswer {
    vectors: Vec<Vec<f32>>,
}

#[derive(Deserialize)]
struct TableRow {
    name: String,
    vector: Vec<f32>,
}

impl PhoneticEmbedder for BenchModel {
    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed_names(&self, names: &[&str]) -> oneiron::Result<Vec<Vec<f32>>> {
        let refused = |code: String| oneiron::Error::UpstreamToolFailure {
            tool: "phonetic-eval-model",
            code,
        };
        match &self.vectors {
            NameVectors::Endpoint { client, url } => client
                .post(url)
                .json(&NamesRequest { names })
                .send()
                .and_then(reqwest::blocking::Response::error_for_status)
                .and_then(reqwest::blocking::Response::json::<NamesAnswer>)
                .map(|answer| answer.vectors)
                .map_err(|error| refused(format!("phonetic model endpoint: {error}"))),
            NameVectors::Table(table) => names
                .iter()
                .map(|name| {
                    table
                        .get(*name)
                        .cloned()
                        .ok_or_else(|| refused(format!("the vectors file has no row for {name}")))
                })
                .collect(),
        }
    }
}

/// One case's result under one arm: the gold entity's 1-based rank, if it
/// was listed, and how many entities were listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Outcome {
    rank: Option<usize>,
    listed: usize,
}

/// One slice's numbers under one arm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
struct SliceMetrics {
    cases: usize,
    r_at_1: f64,
    r_at_5: f64,
    mrr: f64,
    false_positive_rate: f64,
}

impl SliceMetrics {
    fn of(outcomes: &[Outcome]) -> Self {
        if outcomes.is_empty() {
            return Self::default();
        }
        let cases = outcomes.len() as f64;
        Self {
            cases: outcomes.len(),
            r_at_1: share(outcomes, |outcome| outcome.rank == Some(1)),
            r_at_5: share(outcomes, |outcome| {
                outcome.rank.is_some_and(|rank| rank <= 5)
            }),
            mrr: outcomes
                .iter()
                .map(|outcome| outcome.rank.map_or(0.0, |rank| 1.0 / rank as f64))
                .sum::<f64>()
                / cases,
            // Another entity ranked first: a phonetic match to the wrong one.
            false_positive_rate: share(outcomes, |outcome| {
                outcome.listed > 0 && outcome.rank != Some(1)
            }),
        }
    }
}

/// The share of `outcomes` that `keep` keeps; `outcomes` is not empty.
fn share(outcomes: &[Outcome], keep: impl Fn(&Outcome) -> bool) -> f64 {
    outcomes.iter().filter(|outcome| keep(outcome)).count() as f64 / outcomes.len() as f64
}

/// The slices `case` reports in: all cases, its script pair, short queries
/// and hard negatives.
fn slices_of(case: &PhoneticCase) -> Vec<String> {
    let mut slices = vec!["all".to_owned(), case.script_pair.clone()];
    if case.query.chars().count() <= SHORT_QUERY_CHARS {
        slices.push("short".to_owned());
    }
    if case.hard_negative_of.is_some() {
        slices.push("hard_negative".to_owned());
    }
    slices
}

/// Each slice's numbers over `outcomes`, one per case of `cases` in order.
fn slice_report(cases: &[PhoneticCase], outcomes: &[Outcome]) -> BTreeMap<String, SliceMetrics> {
    let mut grouped: BTreeMap<String, Vec<Outcome>> = BTreeMap::new();
    for (case, outcome) in cases.iter().zip(outcomes) {
        for slice in slices_of(case) {
            grouped.entry(slice).or_default().push(*outcome);
        }
    }
    grouped
        .into_iter()
        .map(|(slice, outcomes)| (slice, SliceMetrics::of(&outcomes)))
        .collect()
}

/// Refuses a case whose entity the model trained on: entities are held out
/// whole, never alias by alias (canon `#test-accuracy`).
fn refuse_trained_entities(cases: &[PhoneticCase], trained: &BTreeSet<String>) -> EvalResult<()> {
    match cases.iter().find(|case| trained.contains(&case.entity.key)) {
        Some(case) => Err(failure(format!(
            "case {} asks for entity {}, which the model trained on: hold out whole entities",
            case.id, case.entity.key
        ))),
        None => Ok(()),
    }
}

/// The distinct entities of `cases`, by key; one key named two ways is refused.
fn entities_of(cases: &[PhoneticCase]) -> EvalResult<BTreeMap<String, CaseEntity>> {
    let mut entities: BTreeMap<String, CaseEntity> = BTreeMap::new();
    for case in cases {
        if case.entity.names.is_empty() {
            return Err(failure(format!(
                "case {} names no name of its entity",
                case.id
            )));
        }
        match entities.get(&case.entity.key) {
            Some(known) if *known != case.entity => {
                return Err(failure(format!(
                    "entity {} is stated two ways",
                    case.entity.key
                )));
            }
            Some(_) => {}
            None => {
                entities.insert(case.entity.key.clone(), case.entity.clone());
            }
        }
    }
    Ok(entities)
}

/// The arms one case is asked through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
enum Arm {
    Code,
    Learned,
    Both,
}

/// One fresh vault with the cases' entities, their names embedded.
struct BenchVault {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    ids: BTreeMap<String, String>,
}

impl BenchVault {
    fn create(
        entities: &BTreeMap<String, CaseEntity>,
        model: Option<&BenchModel>,
    ) -> EvalResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::default())?;
        let owner = vault.ensure_embedded_owner_actor().map_err(failure_from)?;
        let mut ids = BTreeMap::new();
        for (key, entity) in entities {
            let (name, aliases) = entity
                .names
                .split_first()
                .ok_or_else(|| failure(format!("entity {key} names no name")))?;
            let body = serde_json::json!({ "name": name, "aliases": aliases });
            let id = EntityId::now();
            vault.put_entity(
                &id,
                entity.kind.entity_type(),
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&body).map_err(failure_from)?,
            )?;
            ids.insert(key.clone(), id.to_hex());
        }
        if let Some(model) = model {
            while vault.reconcile_phonetic_embeddings(model, 1000)?.embedded > 0 {}
        }
        Ok(Self {
            _dir: dir,
            vault,
            owner,
            ids,
        })
    }

    /// `case` asked through `arm`: where its entity ranked.
    fn ask(
        &self,
        case: &PhoneticCase,
        arm: Arm,
        model: Option<&BenchModel>,
    ) -> EvalResult<Outcome> {
        let phonetic_vector = match (arm, model) {
            (Arm::Code, _) => None,
            (Arm::Learned | Arm::Both, Some(model)) => {
                let vector = model
                    .embed_names(&[case.query.as_str()])?
                    .pop()
                    .ok_or_else(|| {
                        failure(format!("no vector for the query of case {}", case.id))
                    })?;
                Some(HybridPhoneticVectorQuery {
                    model_id: model.model_id.clone(),
                    vector,
                    limit: None,
                })
            }
            (Arm::Learned | Arm::Both, None) => {
                return Err(failure("the learned arms need a model".to_owned()));
            }
        };
        let phonetic_mentions = match arm {
            Arm::Learned => Vec::new(),
            Arm::Code | Arm::Both => vec![case.query.clone()],
        };
        let request = HybridSearchRequest {
            query: None,
            query_vector: None,
            phonetic_codes: Vec::new(),
            phonetic_mentions,
            phonetic_vector,
            ppr: None,
            temporal: None,
            replay: None,
            limit: QUERY_LIMIT,
            filter: None,
        };
        let hits = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .query_hybrid(&request)
            .map_err(failure_from)?
            .value;
        let gold = self.ids.get(&case.entity.key).map(String::as_str);
        Ok(Outcome {
            rank: hits
                .iter()
                .position(|hit| Some(hit.entity_ref.as_str()) == gold)
                .map(|index| index + 1),
            listed: hits.len(),
        })
    }
}

/// The flags of one run.
struct PhoneticEvalArgs {
    cases: PathBuf,
    out: PathBuf,
    model_id: Option<String>,
    dimensions: Option<usize>,
    endpoint: Option<String>,
    vectors: Option<PathBuf>,
    trained_entities: Option<PathBuf>,
}

#[derive(Serialize)]
struct CaseRow<'a> {
    id: &'a str,
    script_pair: &'a str,
    ranks: BTreeMap<Arm, Option<usize>>,
}

#[derive(Serialize)]
struct PhoneticEvalReport<'a> {
    contract_version: &'static str,
    model_id: Option<&'a str>,
    cases: usize,
    entities: usize,
    arms: BTreeMap<Arm, BTreeMap<String, SliceMetrics>>,
    rows: Vec<CaseRow<'a>>,
}

pub(super) fn run_phonetic_eval(args: &[String]) -> EvalResult<()> {
    let args = parse_args(args)?;
    if args.out.exists() {
        return Err(failure(format!(
            "--out {} already exists; each run writes a new report",
            args.out.display()
        )));
    }
    let cases: Vec<PhoneticCase> = read_jsonl(&args.cases)?;
    if let Some(path) = &args.trained_entities {
        refuse_trained_entities(&cases, &read_keys(path)?)?;
    }
    let model = bench_model(&args)?;
    let entities = entities_of(&cases)?;
    let bench = BenchVault::create(&entities, model.as_ref())?;
    let arms: &[Arm] = if model.is_some() {
        &[Arm::Code, Arm::Learned, Arm::Both]
    } else {
        &[Arm::Code]
    };
    let mut outcomes: BTreeMap<Arm, Vec<Outcome>> = BTreeMap::new();
    for arm in arms {
        for case in &cases {
            let outcome = bench.ask(case, *arm, model.as_ref())?;
            outcomes.entry(*arm).or_default().push(outcome);
        }
    }
    let rows = cases
        .iter()
        .enumerate()
        .map(|(index, case)| CaseRow {
            id: &case.id,
            script_pair: &case.script_pair,
            ranks: outcomes
                .iter()
                .map(|(arm, outcomes)| (*arm, outcomes[index].rank))
                .collect(),
        })
        .collect();
    let report = PhoneticEvalReport {
        contract_version: PHONETIC_EVAL_CONTRACT_VERSION,
        model_id: model.as_ref().map(|model| model.model_id.as_str()),
        cases: cases.len(),
        entities: entities.len(),
        arms: outcomes
            .iter()
            .map(|(arm, outcomes)| (*arm, slice_report(&cases, outcomes)))
            .collect(),
        rows,
    };
    let mut out = std::fs::File::create_new(&args.out)?;
    serde_json::to_writer_pretty(&mut out, &report)?;
    out.write_all(b"\n")?;
    let summary = serde_json::json!({
        "out": args.out.display().to_string(),
        "all": report
            .arms
            .iter()
            .map(|(arm, slices)| (arm, slices.get("all")))
            .collect::<BTreeMap<_, _>>(),
    });
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    write_json_line(&summary, &mut lock)
}

/// The model the flags name: an endpoint or a vectors file with its id and
/// width, or none for the code rung alone.
fn bench_model(args: &PhoneticEvalArgs) -> EvalResult<Option<BenchModel>> {
    let vectors = match (&args.endpoint, &args.vectors) {
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => {
            return Err(EvalError::InvalidArgument(
                "--endpoint and --vectors name two models".to_owned(),
            ));
        }
        (Some(url), None) => NameVectors::Endpoint {
            client: reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(failure_from)?,
            url: url.clone(),
        },
        (None, Some(path)) => NameVectors::Table(
            read_jsonl::<TableRow>(path)?
                .into_iter()
                .map(|row| (row.name, row.vector))
                .collect(),
        ),
    };
    Ok(Some(BenchModel {
        model_id: args
            .model_id
            .clone()
            .ok_or(EvalError::MissingArgument("--model-id"))?,
        dimensions: args
            .dimensions
            .ok_or(EvalError::MissingArgument("--dimensions"))?,
        vectors,
    }))
}

fn parse_args(args: &[String]) -> EvalResult<PhoneticEvalArgs> {
    if help_requested(args) {
        return Err(EvalError::HelpRequested);
    }
    let mut values: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let flag = match args[index].as_str() {
            "--cases" => "--cases",
            "--out" => "--out",
            "--model-id" => "--model-id",
            "--dimensions" => "--dimensions",
            "--endpoint" => "--endpoint",
            "--vectors" => "--vectors",
            "--trained-entities" => "--trained-entities",
            other => return Err(EvalError::InvalidArgument(other.to_owned())),
        };
        let value = required_value(args, index, flag)?.to_owned();
        if values.insert(flag, value).is_some() {
            return Err(EvalError::InvalidArgument(format!("{flag} given twice")));
        }
        index += 2;
    }
    let dimensions = values
        .get("--dimensions")
        .map(|value| {
            value
                .parse()
                .map_err(|_| EvalError::InvalidArgument(format!("--dimensions {value}")))
        })
        .transpose()?;
    Ok(PhoneticEvalArgs {
        cases: values
            .remove("--cases")
            .map(PathBuf::from)
            .ok_or(EvalError::MissingArgument("--cases"))?,
        out: values
            .remove("--out")
            .map(PathBuf::from)
            .ok_or(EvalError::MissingArgument("--out"))?,
        model_id: values.remove("--model-id"),
        dimensions,
        endpoint: values.remove("--endpoint"),
        vectors: values.remove("--vectors").map(PathBuf::from),
        trained_entities: values.remove("--trained-entities").map(PathBuf::from),
    })
}

/// Every non-blank line of `path` as one `T`.
fn read_jsonl<T: serde::de::DeserializeOwned>(path: &Path) -> EvalResult<Vec<T>> {
    let mut rows = Vec::new();
    for line in BufReader::new(std::fs::File::open(path)?).lines() {
        let line = line?;
        if !line.trim().is_empty() {
            rows.push(serde_json::from_str(&line)?);
        }
    }
    Ok(rows)
}

/// The entity keys of `path`, one a line; blank lines and `#` lines skipped.
fn read_keys(path: &Path) -> EvalResult<BTreeSet<String>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

fn failure(reason: String) -> EvalError {
    EvalError::Phonetic(reason)
}

fn failure_from(error: impl std::fmt::Display) -> EvalError {
    failure(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(id: &str, key: &str, names: &[&str], query: &str, script_pair: &str) -> PhoneticCase {
        PhoneticCase {
            id: id.to_owned(),
            entity: CaseEntity {
                key: key.to_owned(),
                kind: EntityKind::Person,
                names: names.iter().map(|name| (*name).to_owned()).collect(),
            },
            query: query.to_owned(),
            script_pair: script_pair.to_owned(),
            hard_negative_of: None,
        }
    }

    fn outcome(rank: Option<usize>, listed: usize) -> Outcome {
        Outcome { rank, listed }
    }

    #[test]
    fn metrics_on_a_known_ranking() {
        let metrics = SliceMetrics::of(&[
            outcome(Some(1), 3),
            outcome(Some(3), 4),
            outcome(None, 2),
            outcome(Some(5), 5),
            outcome(None, 0),
        ]);
        assert_eq!(metrics.cases, 5);
        assert!((metrics.r_at_1 - 0.2).abs() < 1e-9, "{metrics:?}");
        assert!((metrics.r_at_5 - 0.6).abs() < 1e-9, "{metrics:?}");
        let mrr = (1.0 + 1.0 / 3.0 + 1.0 / 5.0) / 5.0;
        assert!((metrics.mrr - mrr).abs() < 1e-9, "{metrics:?}");
        // Ranks 3 and 5 and the unlisted gold beside two others: another
        // entity first. An empty list matches nothing, wrong or right.
        assert!(
            (metrics.false_positive_rate - 0.6).abs() < 1e-9,
            "{metrics:?}"
        );
        assert_eq!(SliceMetrics::of(&[]), SliceMetrics::default());
    }

    #[test]
    fn a_holdout_sharing_an_entity_with_training_is_refused() {
        let cases = [
            case("c1", "xiao-ming", &["小明"], "Showming", "Latn-Hani"),
            case("c2", "siobhan", &["Siobhan"], "Shivon", "Latn-Latn"),
        ];
        let trained: BTreeSet<String> = ["bjork".to_owned()].into();
        assert!(refuse_trained_entities(&cases, &trained).is_ok());
        let trained: BTreeSet<String> = ["bjork".to_owned(), "siobhan".to_owned()].into();
        let refused = refuse_trained_entities(&cases, &trained).expect_err("a trained entity");
        assert!(refused.to_string().contains("siobhan"), "{refused}");
    }

    #[test]
    fn slices_report_per_script_pair_and_short_names() {
        let mut hard = case("c3", "zhang-wei-b", &["章玮"], "章玮", "Hani-Hani");
        hard.hard_negative_of = Some("zhang-wei-a".to_owned());
        let cases = [
            case("c1", "xiao-ming", &["小明"], "Showming", "Latn-Hani"),
            case("c2", "li", &["李"], "Lee", "Latn-Hani"),
            hard,
        ];
        let report = slice_report(
            &cases,
            &[outcome(Some(1), 2), outcome(None, 1), outcome(Some(2), 2)],
        );
        let slices: Vec<&str> = report.keys().map(String::as_str).collect();
        assert_eq!(
            slices,
            ["Hani-Hani", "Latn-Hani", "all", "hard_negative", "short"]
        );
        assert_eq!(report["all"].cases, 3);
        assert_eq!(report["Latn-Hani"].cases, 2);
        assert!((report["Latn-Hani"].r_at_1 - 0.5).abs() < 1e-9);
        // Lee and 章玮: at most three characters.
        assert_eq!(report["short"].cases, 2);
        assert!((report["short"].false_positive_rate - 1.0).abs() < 1e-9);
        assert_eq!(report["hard_negative"].cases, 1);
        assert!((report["hard_negative"].mrr - 0.5).abs() < 1e-9);
    }

    #[test]
    fn an_entity_stated_two_ways_is_refused() {
        let cases = [
            case("c1", "xiao-ming", &["小明"], "Showming", "Latn-Hani"),
            case("c2", "xiao-ming", &["晓明"], "Xiaoming", "Latn-Hani"),
        ];
        assert!(entities_of(&cases).is_err());
        assert_eq!(entities_of(&cases[..1]).expect("one entity").len(), 1);
    }

    /// The learned arm, end to end through a vault: Showming finds 小明 by
    /// the model's vectors alone.
    #[test]
    fn the_learned_arm_finds_the_cross_script_entity() {
        let model = BenchModel {
            model_id: "fixture-phonetic-v1".to_owned(),
            dimensions: 4,
            vectors: NameVectors::Table(
                [
                    ("小明", [1.0, 0.1, 0.0, 0.0]),
                    ("Showming", [1.0, 0.05, 0.05, 0.0]),
                    ("Siobhan", [0.0, 0.0, 1.0, 0.0]),
                    ("Shivon", [0.0, 0.0, 0.9, 0.43]),
                ]
                .into_iter()
                .map(|(name, vector)| (name.to_owned(), vector.to_vec()))
                .collect(),
            ),
        };
        let cases = [
            case("c1", "xiao-ming", &["小明"], "Showming", "Latn-Hani"),
            case("c2", "siobhan", &["Siobhan"], "Shivon", "Latn-Latn"),
        ];
        let bench = BenchVault::create(&entities_of(&cases).expect("entities"), Some(&model))
            .expect("bench vault");
        let learned = bench
            .ask(&cases[0], Arm::Learned, Some(&model))
            .expect("learned arm");
        assert_eq!(learned.rank, Some(1), "{learned:?}");
        let both = bench
            .ask(&cases[0], Arm::Both, Some(&model))
            .expect("both arms");
        assert_eq!(both.rank, Some(1), "{both:?}");
    }
}
