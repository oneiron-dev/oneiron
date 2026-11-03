//! The rows a fold of the stored log holds, past the continuation it resumes
//! from (FIX 12331). The type index keys an authority row by its content
//! hash, not by when it was stored, so no key range holds only the rows
//! stored past the continuation and the scan reads every id. It counts the
//! continuation's rows it meets instead of inserting them: a resume inserts
//! only the tail's rows, and compares one count for the rest.

use super::*;

/// The rows a fold of the stored log holds: each stored row, and each
/// arriving row it inserts.
pub(super) struct HeldRows<'a> {
    baseline: Option<&'a AuthorityContinuation>,
    /// Whether the store holds every row `baseline` folded: then each of
    /// them is held without an insert.
    whole: bool,
    /// Each other held row. Where the store lacks a row `baseline` folded,
    /// every held row ([`baseline_rows_held_in_txn`]).
    rest: BTreeSet<AuthorityEntryHash>,
}

impl<'a> HeldRows<'a> {
    /// The stored rows, each one `baseline` did not fold decoded into
    /// `tail` in id order.
    pub(super) fn scan_in_txn(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        baseline: Option<&'a AuthorityContinuation>,
        tail: &mut Vec<(AuthorityEntryHash, AuthorityLogEntry)>,
    ) -> Result<Self> {
        let mut rest = BTreeSet::new();
        let mut folded = 0;
        for id in store.port_entity_ids_by_type(txn, ENTITY_TYPE_AUTHORITY_LOG, None)? {
            let id = id?;
            // The store id is the row's content hash, and a stored authority
            // row's body never changes: the baseline already read this one.
            if baseline.is_some_and(|baseline| baseline.ids.contains_key(&id)) {
                folded += 1;
                continue;
            }
            let entry =
                decode_authority_log_entry_body(&authority_log_body_in_txn(store, txn, &id)?)?;
            let hash = authority_entry_hash(&entry)?;
            rest.insert(hash);
            tail.push((hash, entry));
        }
        // The type index holds each id once, so the count is of distinct
        // rows of the baseline.
        let whole = baseline.is_none_or(|baseline| folded == baseline.ids.len());
        if let Some(baseline) = baseline.filter(|_| !whole) {
            rest.extend(baseline_rows_held_in_txn(store, txn, baseline)?);
        }
        Ok(Self {
            baseline,
            whole,
            rest,
        })
    }

    /// Whether `hash` is a row the baseline folded and the store holds,
    /// where the store holds them all.
    fn folded(&self, hash: &AuthorityEntryHash) -> bool {
        self.whole
            && self.baseline.is_some_and(|baseline| {
                authority_log_entity_id_from_hash(hash)
                    .is_ok_and(|id| baseline.ids.get(&id) == Some(hash))
            })
    }

    pub(super) fn contains(&self, hash: &AuthorityEntryHash) -> bool {
        self.rest.contains(hash) || self.folded(hash)
    }

    /// Holds `hash`; whether it was not held yet.
    pub(super) fn insert(&mut self, hash: AuthorityEntryHash) -> bool {
        !self.folded(&hash) && self.rest.insert(hash)
    }

    /// Whether every row the baseline folded is held.
    pub(super) fn holds_baseline(&self) -> bool {
        self.whole
            || self
                .baseline
                .is_none_or(|baseline| baseline.ids.values().all(|hash| self.rest.contains(hash)))
    }
}

/// Each row `baseline` folded that the store holds, by hash, as a fold that
/// inserts every stored row holds it: read only where the store lacks one
/// of them, so the fold needs history and names what it lacks.
fn baseline_rows_held_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    baseline: &AuthorityContinuation,
) -> Result<Vec<AuthorityEntryHash>> {
    let mut held = Vec::new();
    for id in store.port_entity_ids_by_type(txn, ENTITY_TYPE_AUTHORITY_LOG, None)? {
        if let Some(hash) = baseline.ids.get(&id?) {
            held.push(*hash);
        }
    }
    Ok(held)
}
