use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::edge::EdgeActorClass;
use crate::gate::constants::{
    DREAMER_PROVENANCE_RUN_ID_KEY, DREAMER_PROVENANCE_RUN_KEY, DREAMER_PROVENANCE_RUNNER_KEY,
    DREAMER_PROVENANCE_SURFACE_KEY,
};
use crate::write_envelope::WriteEnvelope;

pub(super) fn pending_consent_dreamer_run_id(
    envelope: Option<&WriteEnvelope>,
    body: &ClaimBody,
) -> Option<String> {
    if body.approval != ClaimApprovalStatus::Proposed || body.source != Some(ClaimSource::Generated)
    {
        return None;
    }

    let envelope = envelope?;
    dreamer_run_id_from_write_envelope(envelope)
}

/// The Dreamer run this write is authored by, if any.
///
/// Authorship is a property of the WRITE, read off provenance and
/// SOURCE-AGNOSTIC: `Agent` actor class, the Dreamer run surface/runner
/// marker, and a non-empty run id. `envelope.source()` is the computed
/// evidence meet — epistemic taint derived FROM the candidate's evidence —
/// so a truthful `ToolOutput` or `Observed` meet says how well the claim is
/// known, never who wrote it, and must not disable the deny-first GATE-12
/// floor. Source narrowing answers the other question, owner-review
/// grouping, and lives solely in `pending_consent_dreamer_run_id`.
pub(in crate::gate) fn dreamer_run_id_from_write_envelope(
    envelope: &WriteEnvelope,
) -> Option<String> {
    if envelope.actor().actor_class() != EdgeActorClass::Agent {
        return None;
    }
    dreamer_run_id_from_provenance(envelope.provenance().value())
}

fn dreamer_run_id_from_provenance(value: &Value) -> Option<String> {
    let Value::Map(entries) = value else {
        return None;
    };
    if !entries.iter().any(|(key, value)| {
        key.as_str().is_some_and(|key| {
            key == DREAMER_PROVENANCE_RUNNER_KEY || key == DREAMER_PROVENANCE_SURFACE_KEY
        }) && value.as_str() == Some(DREAMER_RUNNER_ATTEMPT_KIND)
    }) {
        return None;
    }

    [DREAMER_PROVENANCE_RUN_ID_KEY, DREAMER_PROVENANCE_RUN_KEY]
        .into_iter()
        .find_map(|run_key| {
            entries.iter().find_map(|(key, value)| {
                if key.as_str() != Some(run_key) {
                    return None;
                }
                let run_id = value.as_str()?.trim();
                (!run_id.is_empty()).then(|| run_id.to_owned())
            })
        })
}
