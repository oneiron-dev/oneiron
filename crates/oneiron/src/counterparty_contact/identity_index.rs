//! The identity-value index over live `counterparty_contact.identity_ref`
//! heads (FIX 1855): the disclosure readers used to walk the predicate's
//! whole posting list once per member. This derived index maps an identity
//! to the contacts whose live head names it, pointing at that head claim.
//! It is a prefilter only: every hit is revalidated against its head claim
//! and the contact's deletion state, and any doubt (flag unset, head
//! changed, read error) falls back to the posting walk in `storage.rs`.

use super::storage::{claim_body_in_txn, contact_deleted_in_txn};
use super::types::PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF;
use crate::Vault;
use crate::claim::{ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// Key `(identity, contact)`, value the live `identity_ref` head claim.
const IDENTITY_INDEX: SideTable<(EntityId, EntityId), EntityId, Raw> =
    SideTable::new(&side_table::COUNTERPARTY_CONTACT_IDENTITY_INDEX);

/// `Some(1)` once a whole rebuild of the index has committed.
const IDENTITY_INDEX_STATE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::COUNTERPARTY_CONTACT_IDENTITY_INDEX_STATE);

const INDEX_VERSION: u64 = 1;

fn index_complete_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> bool {
    matches!(
        IDENTITY_INDEX_STATE.get(store, txn, &()),
        Ok(Some(INDEX_VERSION))
    )
}

/// Rebuilds the identity index from the `identity_ref` postings when it is
/// missing or stale, in one write transaction (a crash leaves nothing or
/// everything). Runs at writable open and after a checkpoint restore
/// (`force`); a complete index is left alone. The collect applies the
/// posting walk's live-head rules; a value that is not an id's hex indexes
/// nothing (the identity reader only ever asks a real id's hex). Store and
/// codec errors behave per the wrapper below.
pub(crate) fn backfill_counterparty_identity_index(vault: &Vault, force: bool) -> Result<()> {
    // At open (`force` false) a failed rebuild of this Derived index must
    // never refuse the open (L01 13:15): the flag stays unset and readers
    // keep the posting walk. The restore rebuild (`force`) propagates its
    // errors like its sibling backfills.
    match rebuild_counterparty_identity_index(vault, force) {
        Err(error) if !force => {
            tracing::warn!(
                %error,
                "counterparty identity index rebuild failed; identity reads keep the posting walk"
            );
            Ok(())
        }
        other => other,
    }
}

fn rebuild_counterparty_identity_index(vault: &Vault, force: bool) -> Result<()> {
    let store = &vault.store;
    let mut wtxn = store.env.write_txn()?;
    if !force && index_complete_in_txn(store, &wtxn) {
        return Ok(());
    }
    const PAGE: usize = 256;
    let mut rows: Vec<((EntityId, EntityId), EntityId)> = Vec::new();
    let mut after = None;
    loop {
        let page = crate::claim::claim_ids_for_predicate_page_in_txn(
            store,
            &wtxn,
            PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF,
            after,
            PAGE,
        )?;
        for claim_id in &page {
            let Some(body) = claim_body_in_txn(store, &wtxn, claim_id)? else {
                continue;
            };
            if body.predicate != PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.stale
            {
                continue;
            }
            let ClaimSubject::Entity(contact) = body.subject else {
                continue;
            };
            let Some(hex) = body.value.as_str() else {
                continue;
            };
            let Ok(identity) = EntityId::from_hex(hex) else {
                continue;
            };
            if identity.to_hex() != hex {
                continue;
            }
            rows.push(((identity, contact), *claim_id));
        }
        if page.len() < PAGE {
            break;
        }
        after = page.last().copied();
    }
    IDENTITY_INDEX.delete_from(store, &mut wtxn, &[])?;
    for (key, claim_id) in &rows {
        IDENTITY_INDEX.put(store, &mut wtxn, key, claim_id)?;
    }
    IDENTITY_INDEX_STATE.put(store, &mut wtxn, &(), &INDEX_VERSION)?;
    wtxn.commit()?;
    Ok(())
}

/// The contacts whose live `identity_ref` head names `identity`, from the
/// index when it is complete, in id order. `None` means any doubt at all:
/// the caller runs the posting walk, which answers (or errors) exactly as
/// it does today. A deleted contact is skipped, as the walk skips it; a
/// head that no longer stands (missing, retracted, stale, renamed) means
/// the index is stale, never a partial answer.
pub(super) fn contact_ids_for_identity_via_index_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity: &EntityId,
) -> Option<Vec<EntityId>> {
    if !index_complete_in_txn(store, txn) {
        return None;
    }
    let rows = IDENTITY_INDEX
        .scan_from(store, txn, identity.as_bytes())
        .ok()?;
    let hex = identity.to_hex();
    let mut ids = Vec::with_capacity(rows.len());
    for ((key_identity, contact), claim_id) in rows {
        if key_identity != *identity {
            return None;
        }
        match contact_deleted_in_txn(store, txn, &contact) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(_) => return None,
        }
        let body = match claim_body_in_txn(store, txn, &claim_id) {
            Ok(Some(body)) => body,
            _ => return None,
        };
        if body.predicate != PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF
            || body.value.as_str() != Some(hex.as_str())
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.stale
            || !matches!(&body.subject, ClaimSubject::Entity(of) if *of == contact)
        {
            return None;
        }
        ids.push(contact);
    }
    Some(ids)
}

/// Maintains the index on one claim put, on every put and replay door
/// (`stage_claim_projection_indexes`): a live `identity_ref` head points
/// its `(identity, contact)` row at itself; every other put leaves the
/// index alone. Put-only by design: any claim door may mint, supersede or
/// retract these heads (no reserved wall fences the family), so a delete
/// here could drop the row of a second live head this put never saw. A row
/// left pointing at a closed head costs its identity one fallback to the
/// posting walk (the reader revalidates), and the open/restore whole
/// rebuild clears it.
pub(crate) fn maintain_counterparty_identity_index_for_put(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    body: &crate::claim::ClaimBody,
) -> Result<()> {
    if body.predicate != PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
    {
        return Ok(());
    }
    let ClaimSubject::Entity(contact) = body.subject else {
        return Ok(());
    };
    let Some(hex) = body.value.as_str() else {
        return Ok(());
    };
    let Ok(identity) = EntityId::from_hex(hex) else {
        return Ok(());
    };
    if identity.to_hex() != hex {
        return Ok(());
    }
    IDENTITY_INDEX.put(store, wtxn, &(identity, contact), claim_id)
}
