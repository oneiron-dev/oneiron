//! Door to the local claim-value redaction core (gate census G2). The
//! courtesy-delete answer door (`Vault::answer_cooperative_deletion_as`)
//! reaches it only behind a federation pact and a delivered peer request,
//! which no integration fixture builds; this door runs the same writer step
//! with the inputs that answer passes: one stored CLAIM, the value fields
//! named in the answer, and the owner as the acting actor.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;
use crate::vault::entity_revision::{LocalClaimValueRedaction, redact_claim_value_fields_in_txn};

/// Redacts `keys` from the stored value of CLAIM `id` in one write, as the
/// courtesy answer's redact arm does (`coop_delivery/redact.rs`).
///
/// # Errors
///
/// The redaction's own refusals: no field named, a record-headed row, a
/// claim family that keeps its value whole, or a legal hold.
pub fn redact_claim_value_fields(
    vault: &Vault,
    id: EntityId,
    keys: &[String],
    actor: EntityId,
) -> Result<LocalClaimValueRedaction> {
    vault
        .with_write_txn_grouped(|txn| redact_claim_value_fields_in_txn(vault, txn, id, keys, actor))
}
