//! Strict run/request identity and actual output files for the projection worker.
use std::path::{Component, Path};

use super::super::wire::{blake3_hex, invalid, sha256_hex};
use crate::config::models::TRAINING_SERVICE_UNIT;
use oneiron::training_pack::{
    CheckpointFileKind, CheckpointFileUpload, CheckpointUpload, ProbeMeasurement, SourcePin,
    TrainOutput, TrainRequest,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Receipt {
    format: String,
    status: String,
    run: String,
    spec_blake3: String,
    authorization: Value,
    request_sha256: String,
    settings: Value,
    harness: SourcePin,
    training_blake3: String,
    load_sets: LoadSets,
    probes: Vec<Probe>,
    service_units: ServiceUnits,
}
#[derive(Deserialize)]
struct LoadSets {
    training: LoadSet,
    export: LoadSet,
}
#[derive(Deserialize)]
struct LoadSet {
    model: String,
    load_set_blake3: String,
    files: Vec<File>,
}
#[derive(Deserialize)]
struct File {
    name: String,
    kind: CheckpointFileKind,
    source: SourcePin,
    path: String,
    blake3: String,
}
#[derive(Deserialize)]
struct Probe {
    probe_id: String,
    input_blake3: String,
    training: Vec<f64>,
    export: Vec<f64>,
}
#[derive(Deserialize)]
struct ServiceUnits {
    unit: String,
    quantity: u64,
}

fn hash(value: &str) -> oneiron::Result<[u8; 32]> {
    blake3::Hash::from_hex(value)
        .ok()
        .filter(|h| h.to_hex().as_str() == value)
        .map(|h| *h.as_bytes())
        .ok_or_else(|| invalid("invalid projection receipt hash"))
}

pub(super) fn decode(
    request: &TrainRequest,
    reference: &str,
    body: &[u8],
    output: &Path,
) -> oneiron::Result<TrainOutput> {
    let bytes = std::fs::read(output.join("receipt.json"))?;
    let whole: Value =
        serde_json::from_slice(&bytes).map_err(|_| invalid("projection receipt is not JSON"))?;
    let receipt: Receipt = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("projection worker returned no complete result"))?;
    if receipt.format != "oneiron.embedding-projection.receipt/1"
        || receipt.status != "trained"
        || receipt.run != request.run.to_hex()
        || receipt.spec_blake3 != blake3_hex(&request.spec_blake3)
        || receipt.authorization
            != serde_json::json!({"kind": "engine_run", "reference": reference})
        || receipt.request_sha256 != sha256_hex(body)
        || receipt.settings != request.plan.settings
        || receipt.harness != request.plan.harness
        || receipt.training_blake3 != blake3_hex(&request.training_blake3)
        || receipt.service_units.unit != TRAINING_SERVICE_UNIT
    {
        return Err(invalid(
            "projection receipt differs from its dispatched request",
        ));
    }
    let model = request.plan.target.output_model();
    let upload = |set: LoadSet| -> oneiron::Result<(CheckpointUpload, [u8; 32])> {
        if set.model != model.as_str() {
            return Err(invalid("projection output model differs"));
        }
        let declared = hash(&set.load_set_blake3)?;
        let files = set
            .files
            .into_iter()
            .map(|file| {
                if file.path.is_empty()
                    || !Path::new(&file.path)
                        .components()
                        .all(|c| matches!(c, Component::Normal(_)))
                {
                    return Err(invalid("projection file sits outside the output directory"));
                }
                Ok(CheckpointFileUpload {
                    name: file.name,
                    kind: file.kind,
                    source: file.source,
                    blake3: hash(&file.blake3)?,
                    bytes: std::fs::read(output.join(&file.path))?,
                })
            })
            .collect::<oneiron::Result<Vec<_>>>()?;
        Ok((
            CheckpointUpload {
                model: model.clone(),
                files,
            },
            declared,
        ))
    };
    let (training_checkpoint, probe_training_blake3) = upload(receipt.load_sets.training)?;
    let (exported_checkpoint, probe_export_blake3) = upload(receipt.load_sets.export)?;
    let probes = receipt
        .probes
        .into_iter()
        .map(|probe| {
            if probe.training.is_empty()
                || probe.training.len() != probe.export.len()
                || !probe
                    .training
                    .iter()
                    .chain(&probe.export)
                    .all(|x| x.is_finite())
            {
                return Err(invalid("projection probe has missing or nonfinite vectors"));
            }
            let argmax = |vector: &[f64]| -> u64 {
                let mut best = 0;
                for index in 1..vector.len() {
                    if vector[index] > vector[best] {
                        best = index;
                    }
                }
                best as u64
            };
            Ok(ProbeMeasurement {
                probe_id: probe.probe_id,
                input_blake3: hash(&probe.input_blake3)?,
                tokens_blake3: None,
                training_argmax: argmax(&probe.training),
                export_argmax: argmax(&probe.export),
                max_logit_difference: probe
                    .training
                    .iter()
                    .zip(&probe.export)
                    .map(|(a, b)| (a - b).abs())
                    .fold(0.0, f64::max),
            })
        })
        .collect::<oneiron::Result<Vec<_>>>()?;
    Ok(TrainOutput {
        run: request.run,
        spec_blake3: request.spec_blake3,
        training_checkpoint,
        exported_checkpoint,
        probe_training_blake3,
        probe_export_blake3,
        probes,
        settings: receipt.settings,
        harness: receipt.harness,
        receipt: whole,
        service_units: receipt.service_units.quantity,
        question_check: None,
        candle_parity: None,
    })
}
