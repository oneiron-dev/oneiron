//! Claim write-window admission and read-time quarantine share one causal predicate.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimBody;
use crate::error::{ClaimError, Error, Result};
use crate::store::Store;
use crate::{EntityId, HostingPrivacyPosture, Vault};
use rmpv::Value;

/// A typed quarantine result for a stored claim. Raw bytes remain available to
/// trusted local audit code; ordinary scoped reads and exports suppress them.
impl Vault {
    pub fn claim_write_disposition(&self, id: &EntityId) -> Result<Option<CausalWriteDisposition>> {
        let txn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&txn, id.as_bytes())? else {
            return Ok(None);
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_CLAIM)
        {
            return Ok(None);
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        Ok(Some(if claim_causal_admitted(&fold, &body) {
            CausalWriteDisposition::Admitted
        } else {
            CausalWriteDisposition::Quarantined
        }))
    }
}

pub(crate) fn claim_causal_admitted(fold: &AuthorityFold, body: &ClaimBody) -> bool {
    if fold.vault_root_is_conflicted() {
        return false;
    }
    if fold.revoked_actor_keys.is_empty() {
        return true;
    }
    let Some(Value::Map(entries)) = &body.evidence else {
        return false;
    };
    let field = |name: &str| {
        let mut found = entries.iter().filter(|(k, _)| k.as_str() == Some(name));
        let value = found.next().map(|(_, v)| v)?;
        found.next().is_none().then_some(value)
    };
    let Some(actor) = field("actor_entity_ref").and_then(|value| match value {
        Value::Binary(bytes) => EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok(),
        _ => None,
    }) else {
        return false;
    };
    let Some(class) = field("actor_class")
        .and_then(Value::as_u64)
        .and_then(|v| u8::try_from(v).ok())
        .and_then(crate::edge::EdgeActorClass::try_from_u8)
    else {
        return false;
    };
    let class = class.gate_actor_class();
    // This door withdraws authority in a revoke window; unrelated actors still
    // pass their ordinary policy/credential admission, not a newly invented bind.
    if !fold
        .actor_revocation_affected_writers
        .contains(&(actor, class.to_owned()))
    {
        return true;
    }
    let frontier = field("authority_frontier").and_then(|value| match value {
        Value::Binary(bytes) => bytes.as_slice().try_into().ok(),
        _ => None,
    });
    fold.actor_write_disposition(&actor, class, frontier) == CausalWriteDisposition::Admitted
}

pub(crate) fn check_materialized_claim_causality(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
    ids: &std::collections::BTreeSet<EntityId>,
) -> Result<()> {
    let mut claims = Vec::new();
    for id in ids {
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        if EntityMetadataHeader::parse(&raw)
            .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
        {
            claims.push(crate::claim::decode_claim_body(
                &raw[ENTITY_METADATA_HEADER_LEN..],
                true,
            )?);
        }
    }
    if claims.is_empty() {
        return Ok(());
    }
    let fold = authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    if claims
        .iter()
        .any(|body| !claim_causal_admitted(&fold, body))
    {
        return Err(Error::Claim(ClaimError::WriteConcurrentWithRevocation));
    }
    Ok(())
}

pub(crate) fn row_causal_admitted(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    raw: &[u8],
) -> Result<bool> {
    let header =
        EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("causal row header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(true);
    }
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    Ok(claim_causal_admitted(
        &vault.authority_fold_readonly_in_txn(txn)?,
        &body,
    ))
}
