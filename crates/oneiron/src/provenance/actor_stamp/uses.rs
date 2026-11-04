//! Which records' documents name each stamp token (FIX 11965).
//!
//! An actor's erase forgets the actor's stamp tokens, so a document whose
//! commit messages, birth or authorship entries name one names no one from
//! then on. A legal hold keeps a held record's history as it stands, so a
//! token a held record's document names keeps its claim until the hold
//! lifts. This index finds those documents without a history walk of every
//! document: each write of a document records the tokens its new changes and
//! entries name, in the write's own transaction, and the erase's hold check
//! reads the rows of each held record.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use loro::{ID, LoroDoc, VersionVector};

use crate::deletion::LegalHoldTarget;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// Each record whose document names a token. Key: id16 (the document's
/// record) + id16 (token); value: empty. Keyed by record first, so a
/// record's erase drops its rows by prefix and a hold check reads a held
/// record's tokens by prefix.
const ACTOR_STAMP_TOKEN_USE: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::PROVENANCE_ACTOR_STAMP_TOKEN_USE);

/// Records that `record`'s document names each of `tokens`, in the writer's
/// transaction (FIX 11965). A row already stored stays as it is.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn record_actor_stamp_uses_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    record: &EntityId,
    tokens: impl IntoIterator<Item = EntityId>,
) -> Result<()> {
    for token in tokens {
        let key = (*record, token);
        if !ACTOR_STAMP_TOKEN_USE.contains(store, &*wtxn, &key)? {
            ACTOR_STAMP_TOKEN_USE.put(store, wtxn, &key, &())?;
        }
    }
    Ok(())
}

/// The tokens the changes `doc` holds past `since` name, each change's
/// message read by `token_of` (FIX 11965): every change it retains when
/// `since` is `None`, names a version it does not hold, or falls before its
/// shallow floor. A shallow document's trimmed history names nothing here.
pub(crate) fn tokens_named_since(
    doc: &LoroDoc,
    since: Option<&VersionVector>,
    token_of: impl Fn(&str) -> Option<EntityId>,
) -> BTreeSet<EntityId> {
    let floor = doc.shallow_since_vv().to_vv();
    let retained = |version: &&VersionVector| {
        doc.oplog_vv().includes_vv(version) && version.includes_vv(&floor)
    };
    let from = match since.filter(retained) {
        Some(version) => doc.vv_to_frontiers(version),
        None => doc.shallow_since_frontiers(),
    };
    let mut tokens = BTreeSet::new();
    for (peer, span) in &doc.find_id_spans_between(&from, &doc.oplog_frontiers()).forward {
        let mut counter = span.start.max(floor.get(peer).copied().unwrap_or(0));
        while counter < span.end {
            let Some(change) = doc.get_change(ID::new(*peer, counter)) else {
                break;
            };
            tokens.extend(change.message.as_deref().and_then(&token_of));
            let next = i32::try_from(change.len)
                .ok()
                .and_then(|len| change.id.counter.checked_add(len));
            match next {
                Some(next) if next > counter => counter = next,
                _ => break,
            }
        }
    }
    tokens
}

/// Drops `record`'s rows: one of the erasers its delete and erase run (FIX
/// 11965), so a token the record's gone document named is no longer held
/// through it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_actor_stamp_uses_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    record: &EntityId,
) -> Result<()> {
    ACTOR_STAMP_TOKEN_USE.delete_from(store, wtxn, record.as_bytes())?;
    Ok(())
}

/// The tokens a held record's document names (FIX 11965): the rows of each
/// record a standing legal hold names. A vault that keeps no hold row holds
/// none.
///
/// # Errors
///
/// Storage errors, or a hold or index row that does not decode.
pub(super) fn tokens_of_held_documents_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    let records: BTreeSet<EntityId> = crate::store::legal_hold::holds_in_txn(store, txn)?
        .iter()
        .flat_map(|hold| hold.targets.iter().filter_map(LegalHoldTarget::id))
        .collect();
    let mut tokens = BTreeSet::new();
    for record in records {
        if !crate::store::legal_hold::held_in_txn(store, txn, record.as_bytes())? {
            continue;
        }
        let uses = ACTOR_STAMP_TOKEN_USE.scan_keys(store, txn, record.as_bytes())?;
        tokens.extend(uses.into_iter().map(|(_, token)| token));
    }
    Ok(tokens)
}
