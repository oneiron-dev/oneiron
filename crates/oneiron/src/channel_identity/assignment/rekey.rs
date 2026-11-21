//! A write unit's assignment re-key (OF-272): the identities a CLAIM write
//! moved a `channel_identity.*` head of, re-keyed from their final heads
//! right before the write commits.
//! Entry: `AssignmentRekeys`. Defines its own items; the slot index stays in `assignment`.

use std::sync::{Mutex, PoisonError};

use super::*;

/// Re-keys one identity's slot from its final channel and address heads
/// (OF-272), once a write unit has staged all its claim rows, edges and
/// closures. Whether it occupies is its row's custody answer; the pair is
/// its heads'. Nothing moves, and the slot keeps holding its pair, for
/// anything but a live identity (absent, a deleted shell, another kind) or
/// for heads that settle on no single pair: none, withdrawn, or a
/// correction still in flight across transactions. No pair is ever taken
/// from the row. A slot conflict is returned so the whole write rolls back.
fn reconcile_assignment_from_claim_heads_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(row) = store.port_entity_record(txn, id)? else {
        return Ok(());
    };
    if row.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY || ERASED.get(store, txn, id)?.is_some() {
        return Ok(());
    }
    let identity = decode_channel_identity_body(&row.body)?;
    let HeadsKey::Settled(key) = heads_key(store, txn, id)? else {
        return Ok(());
    };
    move_assignment_slot(
        store,
        txn,
        id,
        &key,
        identity.occupies_assignment_key(),
        true,
    )
}

/// Identities a CLAIM put, delete or `claim_of` removal moved a
/// `channel_identity.*` head of, per store environment: one write
/// transaction's set, since LMDB runs one write transaction per environment
/// at a time. Only a write unit that opened [`AssignmentRekeys`] has an entry.
type PendingRekeys = BTreeMap<usize, BTreeSet<EntityId>>;

static PENDING_REKEYS: Mutex<PendingRekeys> = Mutex::new(BTreeMap::new());

fn pending_rekeys<T>(f: impl FnOnce(&mut PendingRekeys) -> T) -> T {
    f(&mut PENDING_REKEYS
        .lock()
        .unwrap_or_else(PoisonError::into_inner))
}

fn pending_key(store: &Store) -> usize {
    // Identity only: never dereferenced or kept past the write unit.
    std::ptr::from_ref(&store.env) as usize
}

/// A write unit's assignment re-key (OF-272). The owner of a raw write
/// transaction that may write `channel_identity.*` claims opens it with the
/// transaction and finishes it once, right before commit, after the whole
/// logical write. One opened inside an open one joins it, so only the
/// outermost owner re-keys. Dropping an unfinished owner (an abort, an
/// error, an unwind) discards what it noted, so nothing reaches the next
/// transaction.
#[must_use]
pub(crate) struct AssignmentRekeys {
    key: usize,
    owner: bool,
}

impl AssignmentRekeys {
    pub(crate) fn begin(store: &Store) -> Self {
        let key = pending_key(store);
        let owner = pending_rekeys(|pending| {
            if pending.contains_key(&key) {
                return false;
            }
            pending.insert(key, BTreeSet::new());
            true
        });
        Self { key, owner }
    }

    /// Re-keys every identity noted since [`Self::begin`] from its final
    /// heads in `txn`. An error (a slot conflict is
    /// [`RecordError::ChannelIdentityAlreadyExists`]) must roll the write back.
    pub(crate) fn finish(mut self, store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        if !self.owner {
            return Ok(());
        }
        self.owner = false;
        let noted = pending_rekeys(|pending| pending.remove(&self.key)).unwrap_or_default();
        for id in &noted {
            reconcile_assignment_from_claim_heads_in_txn(store, txn, id)?;
        }
        Ok(())
    }
}

impl Drop for AssignmentRekeys {
    fn drop(&mut self) {
        if self.owner {
            pending_rekeys(|pending| {
                pending.remove(&self.key);
            });
        }
    }
}

/// Notes, for the open [`AssignmentRekeys`], the identity a CLAIM put writes
/// a `channel_identity.*` head for and the one the claim it overwrites was
/// about. The put chokepoint calls it before the new body lands; with no
/// re-key open it reads and records nothing.
pub(crate) fn note_claim_put_for_rekey(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: Option<&ClaimBody>,
) -> Result<()> {
    let Some(body) = body else {
        return Ok(());
    };
    let key = pending_key(store);
    if !pending_rekeys(|pending| pending.contains_key(&key)) {
        return Ok(());
    }
    let mut noted = Vec::new();
    noted.extend(rekey_subject(body));
    if let Some(old) = stored_claim_body(store, txn, id)? {
        noted.extend(rekey_subject(&old));
    }
    note_rekeys(key, noted);
    Ok(())
}

/// Notes, for the open [`AssignmentRekeys`], the identity that loses a
/// `channel_identity.*` head when the stored claim `id` is deleted
/// (`edge_subject` `None`, its own subject) or only its `claim_of` edge to
/// `edge_subject` is removed. The caller runs it in the write transaction of
/// the delete or the edge removal, while the claim row still reads; any other
/// entity type, and any other predicate, notes nothing. With no re-key open it
/// reads and records nothing, as [`note_claim_put_for_rekey`].
pub(crate) fn note_claim_delete_for_rekey(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    edge_subject: Option<EntityId>,
) -> Result<()> {
    let key = pending_key(store);
    if !pending_rekeys(|pending| pending.contains_key(&key)) {
        return Ok(());
    }
    let Some(old) = stored_claim_body(store, txn, id)? else {
        return Ok(());
    };
    let noted = match edge_subject {
        Some(subject) if is_channel_identity_claim_predicate(&old.predicate) => Some(subject),
        Some(_) => None,
        None => rekey_subject(&old),
    };
    note_rekeys(key, noted);
    Ok(())
}

fn note_rekeys(key: usize, noted: impl IntoIterator<Item = EntityId>) {
    pending_rekeys(|pending| {
        if let Some(set) = pending.get_mut(&key) {
            set.extend(noted);
        }
    });
}

fn rekey_subject(body: &ClaimBody) -> Option<EntityId> {
    match body.subject {
        ClaimSubject::Entity(subject) if is_channel_identity_claim_predicate(&body.predicate) => {
            Some(subject)
        }
        _ => None,
    }
}
