//! D9 dual-column scorer. Model verdicts and replayed verdicts share this door.
use super::{
    BEAM_SCORER_VERSION, BeamError, BeamResult, report_model::ScoreReport, scorer::FixedBeamScorer,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub(super) const CONVENTION: &str =
    "official:int(score); side:float(score).clamp(0,1); nugget mean";
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NuggetJudgment {
    pub ability: String,
    pub wedge_bucket: WedgeBucket,
    pub value: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NuggetMean {
    pub count: usize,
    pub official_int_cast: f64,
    pub fixed_float_clamped: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NuggetColumns {
    pub convention: &'static str,
    pub aggregate: NuggetMean,
    pub abilities: BTreeMap<String, NuggetMean>,
    pub wedge_buckets: BTreeMap<WedgeBucket, Option<NuggetMean>>,
}
fn mean(rows: &[&NuggetJudgment]) -> NuggetMean {
    NuggetMean {
        count: rows.len(),
        official_int_cast: rows.iter().map(|r| r.value.trunc()).sum::<f64>() / rows.len() as f64,
        fixed_float_clamped: rows.iter().map(|r| r.value.clamp(0.0, 1.0)).sum::<f64>()
            / rows.len() as f64,
    }
}
impl FixedBeamScorer {
    pub(super) fn score_nuggets(&self, judgments: &[NuggetJudgment]) -> BeamResult<ScoreReport> {
        if judgments.is_empty()
            || judgments.iter().any(|j| {
                !j.value.is_finite()
                    || !(0.0..=1.0).contains(&j.value)
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
            scorer_version: BEAM_SCORER_VERSION.into(),
            overall_score: Some(columns.aggregate.official_int_cast as f32),
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
        .unwrap()
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
    let result_path = replay
        .output_dir
        .join(&commit)
        .join(&replay.dataset)
        .join("score.json");
    let report = ProofResult {
        commit,
        dataset: replay.dataset,
        score,
        result_path,
    };
    std::fs::create_dir_all(report.result_path.parent().unwrap())?;
    std::fs::write(&report.result_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nugget_half_is_dropped_only_in_official_column_and_all_buckets_report() {
        let rows: Vec<_> = BUCKETS
            .into_iter()
            .map(|bucket| NuggetJudgment {
                ability: format!("{bucket:?}"),
                wedge_bucket: bucket,
                value: 0.5,
            })
            .collect();
        let report = FixedBeamScorer.score_nuggets(&rows).unwrap();
        let columns = report.beam.as_ref().unwrap();
        assert_eq!(
            columns.aggregate,
            NuggetMean {
                count: 4,
                official_int_cast: 0.0,
                fixed_float_clamped: 0.5
            }
        );
        assert_eq!(columns.wedge_buckets.len(), 4);
        assert_eq!(columns.abilities.len(), 4);
        let snapshot: serde_json::Value =
            serde_json::from_str(include_str!("../../fixtures/beam_nuggets.snapshot.json"))
                .unwrap();
        assert_eq!(serde_json::to_value(report).unwrap(), snapshot);
    }
}
