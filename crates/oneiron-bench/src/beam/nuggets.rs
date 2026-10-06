//! D9 dual-column scorer. Model verdicts and replayed verdicts share this door.
use super::{BeamError, BeamResult, report_model::ScoreReport, scorer::FixedBeamScorer};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// Upstream BEAM commit every published number was scored at (owner ruling
/// 1a, 2026-10-06). Vendored in oneiron-eval `vendor/official/beam`.
pub(super) const BEAM_REPLICATE_COMMIT: &str = "3e12035532eb85768f1a7cd779832b650c4b2ef9";
/// At 3e12035 the judge prompt's question slot was never substituted: the
/// judge saw this literal text where the probing question belongs.
pub(super) const BEAM_REPLICATE_QUESTION: &str = "<question>";
/// Replicate column: judged with the placeholder question, `int(score)` per
/// rubric item (event ordering kept `float`), mean per probe, mean over probes.
pub(super) const REPLICATE_COLUMN: &str = "beam_replicate_3e12035";
/// Fixed column: judged with the real probing question, `float(score)`
/// clamped to [0, 1] so half credit survives, mean per probe, mean over probes.
pub(super) const FIXED_COLUMN: &str = "beam_fixed_float_question";
/// The nugget scorer's own version. Changing the convention is a new version;
/// results scored under an older one are never rescored.
pub(super) const BEAM_NUGGET_SCORER_VERSION: &str = "beam-nugget-scorer-v2";
pub(super) const CONVENTION: &str = "beam_replicate_3e12035: judge sees the literal <question>, int(score) per rubric item except event_ordering float(score), probe mean of items, mean of probes; beam_fixed_float_question: judge sees the real probing question, float(score).clamp(0,1), probe mean of items, mean of probes";
/// The one ability whose evaluator at 3e12035 summed `float(score)`.
const FLOAT_AT_REPLICATE_ABILITY: &str = "event_ordering";
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum WedgeBucket {
    Temporal,
    Contradiction,
    EventOrdering,
    KnowledgeUpdate,
}
const BUCKETS: [WedgeBucket; 4] = [
    WedgeBucket::Temporal,
    WedgeBucket::Contradiction,
    WedgeBucket::EventOrdering,
    WedgeBucket::KnowledgeUpdate,
];
/// One rubric item judged twice: once as upstream 3e12035 judged it, once
/// with the probing question in the prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NuggetJudgment {
    pub ability: String,
    pub wedge_bucket: WedgeBucket,
    /// Groups rubric items into one probe. Absent: the item is its own probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub question_id: Option<String>,
    /// Verdict of the replicate pass (judge saw [`BEAM_REPLICATE_QUESTION`]).
    pub replicate_value: f64,
    /// Verdict of the fixed pass (judge saw the real probing question).
    pub fixed_value: f64,
}
impl NuggetJudgment {
    fn replicate_credit(&self) -> f64 {
        if self.ability == FLOAT_AT_REPLICATE_ABILITY {
            self.replicate_value
        } else {
            self.replicate_value.trunc()
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NuggetMean {
    /// Rubric items.
    pub count: usize,
    /// Probes the items belong to; each probe weighs the same.
    pub probes: usize,
    pub replicate: f64,
    pub fixed: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NuggetColumns {
    pub convention: &'static str,
    pub replicate_column: &'static str,
    pub replicate_commit: &'static str,
    pub fixed_column: &'static str,
    pub aggregate: NuggetMean,
    pub abilities: BTreeMap<String, NuggetMean>,
    pub wedge_buckets: BTreeMap<WedgeBucket, Option<NuggetMean>>,
}
/// Upstream's per-probe `llm_judge_score` is the mean over its rubric items;
/// the column is the mean over probes.
fn mean(rows: &[&NuggetJudgment]) -> NuggetMean {
    let mut probes: BTreeMap<String, Vec<&NuggetJudgment>> = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        let key = row
            .question_id
            .clone()
            .unwrap_or_else(|| format!("item:{index}"));
        probes.entry(key).or_default().push(row);
    }
    let probe_mean = |items: &Vec<&NuggetJudgment>, credit: fn(&NuggetJudgment) -> f64| {
        items.iter().map(|item| credit(item)).sum::<f64>() / items.len() as f64
    };
    let n = probes.len() as f64;
    NuggetMean {
        count: rows.len(),
        probes: probes.len(),
        replicate: probes
            .values()
            .map(|items| probe_mean(items, NuggetJudgment::replicate_credit))
            .sum::<f64>()
            / n,
        fixed: probes
            .values()
            .map(|items| probe_mean(items, |item| item.fixed_value.clamp(0.0, 1.0)))
            .sum::<f64>()
            / n,
    }
}
impl FixedBeamScorer {
    pub(super) fn score_nuggets(&self, judgments: &[NuggetJudgment]) -> BeamResult<ScoreReport> {
        if judgments.is_empty()
            || judgments.iter().any(|j| {
                [j.replicate_value, j.fixed_value]
                    .iter()
                    .any(|v| !v.is_finite() || !(0.0..=1.0).contains(v))
                    || j.ability.trim().is_empty()
            })
        {
            return Err(BeamError::Comparability {
                reason: "nuggets must be nonempty, finite, and ability-tagged".into(),
            });
        }
        let mut abilities: BTreeMap<String, Vec<&NuggetJudgment>> = BTreeMap::new();
        for judgment in judgments {
            abilities
                .entry(judgment.ability.clone())
                .or_default()
                .push(judgment);
        }
        let aggregate = mean(&judgments.iter().collect::<Vec<_>>());
        let columns = NuggetColumns {
            convention: CONVENTION,
            replicate_column: REPLICATE_COLUMN,
            replicate_commit: BEAM_REPLICATE_COMMIT,
            fixed_column: FIXED_COLUMN,
            aggregate,
            abilities: abilities.into_iter().map(|(k, v)| (k, mean(&v))).collect(),
            wedge_buckets: BUCKETS
                .into_iter()
                .map(|bucket| {
                    let rows: Vec<_> = judgments
                        .iter()
                        .filter(|j| j.wedge_bucket == bucket)
                        .collect();
                    (bucket, (!rows.is_empty()).then(|| mean(&rows)))
                })
                .collect(),
        };
        Ok(ScoreReport {
            scorer_version: BEAM_NUGGET_SCORER_VERSION.into(),
            // The headline stays the replicate column (canon D9).
            overall_score: Some(columns.aggregate.replicate as f32),
            abilities: Vec::new(),
            beam: Some(columns),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replay {
    dataset: String,
    judgments: Vec<NuggetJudgment>,
    output_dir: PathBuf,
}
#[derive(Serialize)]
pub(super) struct ProofResult {
    commit: String,
    dataset: String,
    score: ScoreReport,
    result_path: PathBuf,
}
pub(super) fn run(path: &Path) -> BeamResult<ProofResult> {
    let replay: Replay = serde_json::from_slice(&std::fs::read(path)?)?;
    if replay.dataset.is_empty()
        || !replay
            .dataset
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(BeamError::Comparability {
            reason: "invalid result dataset name".into(),
        });
    }
    let score = FixedBeamScorer.score_nuggets(&replay.judgments)?;
    if score
        .beam
        .as_ref()
        .expect("FixedBeamScorer produces BEAM columns")
        .wedge_buckets
        .values()
        .any(Option::is_none)
    {
        return Err(BeamError::Comparability {
            reason: "proof number must cover all four wedge buckets".into(),
        });
    }
    let status = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err(BeamError::Comparability {
            reason: "proof publication requires a clean source checkout".into(),
        });
    }
    let head = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()?;
    let commit = String::from_utf8_lossy(&head.stdout).trim().to_owned();
    if !head.status.success()
        || commit.len() != 40
        || !commit.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(BeamError::Comparability {
            reason: "proof requires a source commit".into(),
        });
    }
    let result_dir = replay.output_dir.join(&commit).join(&replay.dataset);
    let result_path = result_dir.join("score.json");
    let report = ProofResult {
        commit,
        dataset: replay.dataset,
        score,
        result_path,
    };
    std::fs::create_dir_all(result_dir)?;
    std::fs::write(&report.result_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nugget_half_is_dropped_only_in_the_replicate_column_and_all_buckets_report() {
        let rows: Vec<_> = BUCKETS
            .into_iter()
            .map(|bucket| NuggetJudgment {
                ability: format!("{bucket:?}"),
                wedge_bucket: bucket,
                question_id: None,
                replicate_value: 0.5,
                fixed_value: 0.5,
            })
            .collect();
        let report = FixedBeamScorer.score_nuggets(&rows).unwrap();
        let columns = report.beam.as_ref().unwrap();
        assert_eq!(
            columns.aggregate,
            NuggetMean {
                count: 4,
                probes: 4,
                replicate: 0.0,
                fixed: 0.5
            }
        );
        assert_eq!(columns.wedge_buckets.len(), 4);
        assert_eq!(columns.abilities.len(), 4);
        let snapshot: serde_json::Value =
            serde_json::from_str(include_str!("../../fixtures/beam_nuggets.snapshot.json"))
                .unwrap();
        assert_eq!(serde_json::to_value(report).unwrap(), snapshot);
    }

    /// The crafted half-credit case of ruling 1a. One probe, two rubric
    /// items. Without the question the judge gives half credit on both;
    /// with it, full credit on one and half on the other.
    #[test]
    fn replicate_and_fixed_columns_differ_on_a_crafted_half_credit_probe() {
        let item = |replicate_value, fixed_value| NuggetJudgment {
            ability: "temporal_reasoning".into(),
            wedge_bucket: WedgeBucket::Temporal,
            question_id: Some("beam-100k/1/temporal_reasoning/0".into()),
            replicate_value,
            fixed_value,
        };
        let report = FixedBeamScorer
            .score_nuggets(&[item(0.5, 1.0), item(0.5, 0.5)])
            .unwrap();
        let columns = report.beam.unwrap();
        assert_eq!(columns.replicate_column, "beam_replicate_3e12035");
        assert_eq!(columns.fixed_column, "beam_fixed_float_question");
        assert_eq!(columns.replicate_commit, BEAM_REPLICATE_COMMIT);
        assert_eq!(columns.aggregate.probes, 1);
        assert_eq!(columns.aggregate.count, 2);
        assert_eq!(columns.aggregate.replicate, 0.0, "int(0.5) drops both");
        assert_eq!(columns.aggregate.fixed, 0.75, "half credit survives");
        assert_eq!(report.overall_score, Some(0.0), "headline is replicate");
    }

    #[test]
    fn event_ordering_kept_float_credit_at_the_replicate_commit() {
        let judgment = |ability: &str, question: &str| NuggetJudgment {
            ability: ability.into(),
            wedge_bucket: WedgeBucket::EventOrdering,
            question_id: Some(question.into()),
            replicate_value: 0.5,
            fixed_value: 0.5,
        };
        let report = FixedBeamScorer
            .score_nuggets(&[
                judgment("event_ordering", "p1"),
                judgment("knowledge_update", "p2"),
            ])
            .unwrap();
        let columns = report.beam.unwrap();
        assert_eq!(columns.abilities["event_ordering"].replicate, 0.5);
        assert_eq!(columns.abilities["knowledge_update"].replicate, 0.0);
        assert_eq!(columns.aggregate.replicate, 0.25, "mean over probes");
    }

    #[test]
    fn probes_weigh_the_same_whatever_their_rubric_size() {
        let item = |question: &str, value: f64| NuggetJudgment {
            ability: "information_extraction".into(),
            wedge_bucket: WedgeBucket::Temporal,
            question_id: Some(question.into()),
            replicate_value: value,
            fixed_value: value,
        };
        // Probe a: 3 items all 1. Probe b: 1 item 0. Item mean 0.75, probe mean 0.5.
        let report = FixedBeamScorer
            .score_nuggets(&[
                item("a", 1.0),
                item("a", 1.0),
                item("a", 1.0),
                item("b", 0.0),
            ])
            .unwrap();
        let aggregate = report.beam.unwrap().aggregate;
        assert_eq!(aggregate.fixed, 0.5);
        assert_eq!(aggregate.replicate, 0.5);
    }

    #[test]
    fn a_single_verdict_replay_is_refused_not_guessed() {
        let old =
            serde_json::json!({"ability": "temporal", "wedge_bucket": "temporal", "value": 0.5});
        assert!(serde_json::from_value::<NuggetJudgment>(old).is_err());
    }
}
