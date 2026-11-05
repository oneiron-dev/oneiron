//! What an EXL3 worker's answers must echo to keep a verified-artifacts
//! claim (FIX 9195, FIX 9296): the launch manifest's digest beside the
//! epoch. [`Tie`] is the check itself, shared by the native channel and the
//! HTTP routes; [`external_tie`] builds one for a bound external worker
//! from its captured worker and operator pin.

use oneiron::llm::{INFERENCE_CALLS_KEY, WorkerBuildEvidence, WorkerKind, WorkerReadiness};
use serde::Deserialize;
use serde_json::Value as JsonValue;

use super::worker_host::ExternalWorker;

/// The usage key a worker's answer echoes its launch manifest's digest
/// under, as the worker probe reads it.
const LAUNCH_MANIFEST_KEY: &str = "launch_manifest";

/// What a sent call answers to: its manifest and epoch check (FIX 9195, FIX 9296).
#[derive(Clone)]
pub(super) struct Tie {
    manifest_sha256: Option<String>,
    epoch: Option<String>,
}

impl Tie {
    /// Keeps each receipt's verified-artifacts claim only when the answer
    /// echoes this launch's manifest and the receipt names this epoch;
    /// otherwise the receipt's build is unknown. Both expected facts must be
    /// known: a missing fact never matches, so it downgrades a claimed
    /// verification to unknown instead of keeping it.
    pub(super) fn apply(&self, body: &mut JsonValue) {
        let Some(usage) = body.get_mut("usage").and_then(JsonValue::as_object_mut) else {
            return;
        };
        let echoed = match (
            self.manifest_sha256.as_deref(),
            usage.get(LAUNCH_MANIFEST_KEY).and_then(JsonValue::as_str),
        ) {
            (Some(expected), Some(echoed)) => echoed == expected,
            _ => false,
        };
        let Some(JsonValue::Array(calls)) = usage.get_mut(INFERENCE_CALLS_KEY) else {
            return;
        };
        for call in calls {
            let Some(worker) = call.get_mut("worker").and_then(JsonValue::as_object_mut) else {
                continue;
            };
            let claimed = worker
                .get("build_evidence")
                .and_then(|evidence| WorkerBuildEvidence::deserialize(evidence).ok())
                == Some(WorkerBuildEvidence::VerifiedArtifacts);
            let epoch = worker
                .get("identity")
                .and_then(|identity| identity.get("backend_epoch"))
                .and_then(JsonValue::as_str);
            let epoch_matches = match (self.epoch.as_deref(), epoch) {
                (Some(expected), Some(actual)) => actual == expected,
                _ => false,
            };
            if claimed
                && !(echoed && epoch_matches)
                && let Ok(unknown) = serde_json::to_value(WorkerBuildEvidence::Unknown)
            {
                worker.insert("build_evidence".to_owned(), unknown);
            }
        }
    }
}

impl Tie {
    /// The tie for these expected facts: a missing fact never matches, so
    /// it downgrades a claimed verification to unknown instead of keeping
    /// it.
    pub(super) fn new(manifest_sha256: Option<String>, epoch: Option<String>) -> Self {
        Self {
            manifest_sha256,
            epoch,
        }
    }

    /// The epoch this tie's answers must name, when it names one.
    pub(super) fn epoch(&self) -> Option<&str> {
        self.epoch.as_deref()
    }
}

/// The tie for a bound external worker's HTTP answers (FIX 9296): `Some`
/// for an EXL3 row, even when its pin or its ready epoch is absent, so an
/// unpinned answer's self-claimed verification downgrades to unknown
/// instead of passing. `None` for any other kind. The epoch is the SAME
/// captured worker's readiness now; the caller takes it before the send.
pub(super) fn external_tie(bound: &ExternalWorker) -> Option<Tie> {
    if bound.worker.spec().kind != WorkerKind::Exl3 {
        return None;
    }
    let manifest_sha256 = bound
        .launch_manifest_sha256
        .as_ref()
        .map(|digest| digest.as_str().to_owned());
    let epoch = match bound.worker.status().readiness {
        WorkerReadiness::Ready { observed } => observed
            .identity
            .backend_epoch
            .as_ref()
            .map(|epoch| epoch.as_str().to_owned()),
        _ => None,
    };
    Some(Tie::new(manifest_sha256, epoch))
}
