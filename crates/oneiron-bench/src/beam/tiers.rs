//! Dataset graduation: no-regression at the previous rung, explicit gated cells.
use super::{BeamError, BeamResult};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum DatasetTier {
    LongMemEvalS,
    Beam128k,
    Beam500k,
    Beam1m,
    Beam10m,
}
const LADDER: [DatasetTier; 5] = [
    DatasetTier::LongMemEvalS,
    DatasetTier::Beam128k,
    DatasetTier::Beam500k,
    DatasetTier::Beam1m,
    DatasetTier::Beam10m,
];
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TierMeasurement {
    pub baseline: f64,
    pub measured: f64,
    pub source_commit: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Graduation {
    pub scale_work_ready: bool,
    pub measurements: BTreeMap<DatasetTier, TierMeasurement>,
}
#[derive(Debug, Serialize)]
pub(super) struct TierCell {
    pub tier: DatasetTier,
    pub status: String,
    pub measurement: Option<TierMeasurement>,
}
impl Graduation {
    pub(super) fn cells(&self) -> BeamResult<Vec<TierCell>> {
        let mut cells = Vec::new();
        let mut previous_cleared = true;
        for tier in LADDER {
            let measurement = self.measurements.get(&tier);
            let gated = tier == DatasetTier::Beam10m && !self.scale_work_ready;
            if let Some(value) = measurement
                && (gated
                    || !previous_cleared
                    || !value.baseline.is_finite()
                    || !value.measured.is_finite()
                    || !(0.0..=1.0).contains(&value.baseline)
                    || !(0.0..=1.0).contains(&value.measured)
                    || value.source_commit.len() != 40
                    || !value.source_commit.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(BeamError::Comparability {
                    reason: "tier measurement bypassed graduation or has invalid provenance".into(),
                });
            }
            let status = if gated {
                "not-yet-run (10M-gated)"
            } else if measurement.is_some_and(|m| m.measured < m.baseline) {
                "regressed"
            } else if measurement.is_some() {
                "measured"
            } else {
                "not-yet-run"
            };
            previous_cleared = measurement.is_some_and(|m| m.measured >= m.baseline);
            cells.push(TierCell {
                tier,
                status: status.into(),
                measurement: measurement.cloned(),
            });
        }
        Ok(cells)
    }
}
pub(super) fn run(path: &Path) -> BeamResult<Vec<TierCell>> {
    let graduation: Graduation = serde_json::from_slice(&std::fs::read(path)?)?;
    graduation.cells()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::beam::{
        load::resolve_manifest_paths,
        runner::{parse_manifest_json, run_manifest},
    };
    #[test]
    fn tier_graduation_never_hides_the_gated_10m_cell() {
        let mut graduation = Graduation {
            scale_work_ready: false,
            measurements: BTreeMap::new(),
        };
        assert_eq!(
            graduation.cells().unwrap().last().unwrap().status,
            "not-yet-run (10M-gated)"
        );
        let good = TierMeasurement {
            baseline: 0.4,
            measured: 0.5,
            source_commit: "a".repeat(40),
        };
        graduation
            .measurements
            .insert(DatasetTier::LongMemEvalS, good.clone());
        graduation.measurements.insert(
            DatasetTier::Beam128k,
            TierMeasurement {
                measured: 0.3,
                ..good.clone()
            },
        );
        graduation.measurements.insert(DatasetTier::Beam500k, good);
        assert!(graduation.cells().is_err());
    }
    #[test]
    fn tier_manifests_load_and_wrong_occurred_at_aborts_the_run() {
        for name in ["longmemeval-s", "beam-500k", "beam-1m", "beam-10m"] {
            let path =
                Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("fixtures/{name}.run.json"));
            let mut manifest =
                parse_manifest_json(&std::fs::read_to_string(&path).unwrap()).unwrap();
            resolve_manifest_paths(&mut manifest, &path);
            manifest.outputs = None;
            let report = run_manifest(&manifest, None).unwrap();
            assert_eq!(report.dataset.records_loaded, 2);
        }
        let mut record: serde_json::Value =
            serde_json::from_str(include_str!("../../fixtures/beam-500k.run.jsonl")).unwrap();
        record["corpus"][0]["metadata"]["occurredAt"] = serde_json::json!(1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        std::fs::write(&path, record.to_string()).unwrap();
        let mut manifest =
            parse_manifest_json(include_str!("../../fixtures/beam-500k.run.json")).unwrap();
        manifest.outputs = None;
        if let super::super::model::DatasetSource::Jsonl { path: p, .. } = &mut manifest.dataset {
            *p = path;
        }
        assert!(run_manifest(&manifest, None).is_err());
    }
}
