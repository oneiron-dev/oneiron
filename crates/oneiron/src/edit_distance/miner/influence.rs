//! Principal and decay checks at the miner/optimizer's actual read boundary.

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::claim::{
    ClaimBody, claim_principal_id, preference_evidence_in_force, preference_in_force,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

pub(crate) fn is_mined_preference(predicate: &str) -> bool {
    predicate == super::PREDICATE_PREFERENCE_PHRASING
        || super::target::is_compiled_preference(predicate)
}

/// Active learned preferences for exactly one principal. Missing legacy
/// identity is audit-only. Raw `Vault::get_claim` remains an administrative read.
pub fn mined_preferences_for_principal(
    vault: &Vault,
    principal: &EntityId,
    now: u64,
) -> Result<Vec<(EntityId, ClaimBody)>> {
    let txn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for predicate in [
        super::PREDICATE_PREFERENCE_PHRASING,
        "preference.affirmed",
        "preference.ban",
        "preference.style_rule",
        "charter.line",
        "brief.preference",
    ] {
        for (id, body) in vault.claims_with_predicate_in_txn(&txn, predicate)? {
            let learned_at = vault
                .store
                .entities
                .get(&txn, id.as_bytes())?
                .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.learned_at))
                .ok_or(Error::CorruptedIndex("mined preference header"))?;
            if claim_principal_id(&body)? == Some(*principal)
                && preference_in_force(&body, learned_at, now)?
            {
                out.push((id, body));
            }
        }
    }
    Ok(out)
}

/// Every teaching receipt must bind the requested audience and still carry
/// current evidence. An absent principal is not an implicit global grant.
pub(crate) fn preference_receipts_in_force(
    vault: &Vault,
    receipts: &[String],
    principal: Option<EntityId>,
    now: u64,
) -> Result<bool> {
    let Some(principal) = principal else {
        return Ok(false);
    };
    if receipts.is_empty() {
        return Ok(false);
    }
    let txn = vault.store.env.read_txn()?;
    for receipt in receipts {
        let Some(row) = super::feedback::principal_decision(vault, &txn, receipt)? else {
            return Ok(false);
        };
        if row.principal != principal || !preference_evidence_in_force(row.at, now) {
            return Ok(false);
        }
    }
    Ok(true)
}
