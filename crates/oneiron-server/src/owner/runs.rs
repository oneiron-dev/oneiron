//! Agent-run batch consent: see what a run is waiting on, then approve or
//! decline the whole run in one act (OF-211).
//!
//! A run's pending proposals are one content-bound bundle. Review returns its
//! id; resolve must present that id, and the engine re-hashes the live bundle
//! inside the resolving transaction, so an approval never lands on proposals
//! the owner did not see.

use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::run_tree::{GateConsentBundle, GateConsentBundleAction};
use oneiron::write_envelope::WriteActor;
use oneiron::{ClaimSubject, EntityId, Vault};
use serde::Serialize;

use super::{OwnerError, OwnerResult};

/// Pending rows read when listing runs; a run past this is still resolvable.
const PENDING_SCAN_LIMIT: usize = 10_000;

/// A run with proposals waiting for the owner.
#[derive(Debug, Serialize)]
pub(crate) struct PendingRun {
    pub(crate) run_id: String,
    pub(crate) pending: usize,
}

/// One run's waiting proposals as the owner reviews them.
#[derive(Debug, Serialize)]
pub(crate) struct RunReview {
    /// Send this back to approve or decline exactly what was reviewed.
    pub(crate) bundle_id: String,
    pub(crate) name: String,
    pub(crate) run_id: String,
    pub(crate) agent_label: Option<String>,
    pub(crate) proposals: Vec<RunProposal>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RunProposal {
    pub(crate) claim_id: String,
    pub(crate) predicate: Option<String>,
    pub(crate) subject: Option<String>,
    pub(crate) value: Option<serde_json::Value>,
    pub(crate) reason_codes: Vec<String>,
    pub(crate) created_at: u64,
}

/// The run's one receipt.
#[derive(Debug, Serialize)]
pub(crate) struct RunResolved {
    pub(crate) run_id: String,
    pub(crate) bundle_id: String,
    pub(crate) action: &'static str,
    pub(crate) receipt_id: String,
    pub(crate) claim_ids: Vec<String>,
}

/// Runs with proposals waiting, most proposals first.
pub(crate) fn pending(vault: &Vault) -> OwnerResult<Vec<PendingRun>> {
    let mut runs: Vec<PendingRun> = vault
        .pending_gate_consent_groups(PENDING_SCAN_LIMIT)?
        .into_iter()
        .filter_map(|group| {
            group.dreamer_run_id.map(|run_id| PendingRun {
                run_id,
                pending: group.records.len(),
            })
        })
        .collect();
    runs.sort_by(|a, b| b.pending.cmp(&a.pending).then(a.run_id.cmp(&b.run_id)));
    Ok(runs)
}

/// What one run is waiting on.
pub(crate) fn review(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    run_id: &str,
) -> OwnerResult<RunReview> {
    let actor = WriteActor::new(owner.actor(), EdgeActorClass::Human);
    let bundle = vault.review_gate_consent_bundle(&actor, run_id)?;
    review_of(vault, bundle)
}

fn review_of(vault: &Vault, bundle: GateConsentBundle) -> OwnerResult<RunReview> {
    let proposals = bundle
        .members
        .into_iter()
        .map(|member| -> OwnerResult<RunProposal> {
            let claim = vault.get_claim(&member.claim_id)?;
            Ok(RunProposal {
                claim_id: member.claim_id.to_hex(),
                predicate: claim.as_ref().map(|body| body.predicate.clone()),
                subject: claim.as_ref().map(|body| match &body.subject {
                    ClaimSubject::Entity(id) => id.to_hex(),
                    ClaimSubject::Edge { source, target, .. } => {
                        format!("{}->{}", source.to_hex(), target.to_hex())
                    }
                }),
                value: claim
                    .as_ref()
                    .map(|body| crate::commands::msgpack_value_json(&body.value)),
                reason_codes: member.reason_codes,
                created_at: member.created_at,
            })
        })
        .collect::<OwnerResult<Vec<_>>>()?;
    Ok(RunReview {
        bundle_id: hex(&bundle.bundle_id),
        name: bundle.name,
        run_id: bundle.dreamer_run_id,
        agent_label: bundle.agent_label,
        proposals,
    })
}

/// Approves or declines the whole reviewed run in one engine transaction.
pub(crate) fn resolve(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    run_id: &str,
    bundle_id: &str,
    action: GateConsentBundleAction,
) -> OwnerResult<RunResolved> {
    let expected = parse_bundle_id(bundle_id)?;
    let receipt = vault
        .resolve_gate_consent_bundle(owner, expected, run_id, action, vault.now_recorded_at())
        .map_err(|error| match error.kind() {
            oneiron::ErrorKind::GateConsentStale => OwnerError::Changed(
                "this run's proposals changed since they were reviewed; review it again".into(),
            ),
            _ => OwnerError::from(error),
        })?;
    Ok(RunResolved {
        run_id: receipt.dreamer_run_id,
        bundle_id: hex(&receipt.bundle_id),
        action: receipt.action.as_str(),
        receipt_id: receipt.receipt_id.to_hex(),
        claim_ids: receipt
            .member_claim_ids
            .iter()
            .map(EntityId::to_hex)
            .collect(),
    })
}

fn parse_bundle_id(value: &str) -> OwnerResult<[u8; 32]> {
    let invalid = || OwnerError::Invalid("bundle_id must be 64 lowercase hex characters".into());
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let mut id = [0_u8; 32];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(id)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
