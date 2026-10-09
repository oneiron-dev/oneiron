//! The owner reads the self-healing loop (ARCH-0066): the three signed
//! oversight receipts the vault emits, and the custom-agent dispatches the
//! failure ladder ended, grouped by failure class, with a drill into one.

use oneiron::attempt_queue::{AttemptId, AttemptState};
use oneiron::consent::AuthenticatedOwner;
use oneiron::entity_id::bytes_to_hex_lower;
use oneiron::failure_ladder::FailureSignalClass;
use oneiron::failure_ladder::oversight::OversightCounts;
use serde::{Deserialize, Serialize};

use super::{OwnerResult, entity_id};

/// One stored oversight receipt and whether it verifies against this vault
/// device's own key.
#[derive(Debug, Serialize)]
pub(crate) struct OversightRead {
    #[serde(flatten)]
    pub(crate) counts: OversightCounts,
    pub(crate) signer: String,
    pub(crate) verified: bool,
}

pub(crate) fn oversight(vault: &oneiron::Vault) -> OwnerResult<Vec<OversightRead>> {
    Ok(vault
        .healer_oversight_receipts()?
        .into_iter()
        .map(|(receipt, verified)| OversightRead {
            counts: receipt.counts,
            signer: bytes_to_hex_lower(&receipt.signer),
            verified,
        })
        .collect())
}

/// Ended custom-agent dispatches of one failure class.
#[derive(Debug, Serialize)]
pub(crate) struct FailureGroup {
    pub(crate) class: FailureSignalClass,
    pub(crate) count: u64,
    pub(crate) attempts: Vec<String>,
}

pub(crate) fn failure_groups(vault: &oneiron::Vault) -> OwnerResult<Vec<FailureGroup>> {
    Ok(vault
        .custom_agent_failure_groups()?
        .into_iter()
        .map(|group| FailureGroup {
            class: group.class,
            count: group.count,
            attempts: group
                .member_refs
                .iter()
                .map(|id| bytes_to_hex_lower(id.as_bytes()))
                .collect(),
        })
        .collect())
}

/// One member of a group, named by the class it was listed under.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DrillQuery {
    pub(crate) class: FailureSignalClass,
    pub(crate) attempt: String,
}

/// The ended attempt and the receipts its run left.
#[derive(Debug, Serialize)]
pub(crate) struct FailureDrill {
    pub(crate) attempt: String,
    pub(crate) kind: String,
    pub(crate) state: AttemptState,
    pub(crate) tries: u32,
    pub(crate) last_error: Option<String>,
    pub(crate) task_ref: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) retry_of: Option<String>,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
    pub(crate) receipt_refs: Vec<String>,
}

pub(crate) fn drill(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    query: DrillQuery,
) -> OwnerResult<FailureDrill> {
    let attempt = AttemptId::from_bytes(entity_id("attempt", &query.attempt)?.as_bytes())?;
    let drill = vault.drill_custom_agent_failure(owner, query.class, attempt)?;
    let trace = drill.trace;
    Ok(FailureDrill {
        attempt: bytes_to_hex_lower(trace.id.as_bytes()),
        kind: trace.kind,
        state: trace.state,
        tries: trace.attempt_count,
        last_error: trace.last_error,
        task_ref: trace.task_ref,
        run_id: trace.run_id,
        retry_of: trace.retry_of.map(|id| bytes_to_hex_lower(id.as_bytes())),
        created_at: trace.created_at,
        updated_at: trace.updated_at,
        receipt_refs: drill.receipt_refs,
    })
}
