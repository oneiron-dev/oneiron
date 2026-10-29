//! Signed late evidence a local append could not store (FIX 2989, CALLS
//! "FIX 2989 pending history evidence").
//!
//! On a vault that adopted a checkpoint image, a batch of new rows whose fold
//! the image cannot answer for (a fork on a covered row it keeps no state
//! for, an op past it only the whole history folds) would leave every
//! authority read of the vault refusing for history. At the transaction
//! owner's door, a batch of granting rows ([`grants_only`]), each of whose
//! fold needs that history, is not stored then, once the store door admits
//! it: the act refuses with the typed history request, and the owner keeps
//! the rows' signed bytes here, as evidence that admits nothing, so only
//! what depends on them waits for the history (identity.md, "A late
//! pre-cutoff fork stops the affected grants"). Any other batch keeps
//! today's path: it is stored, and the vault's reads refuse until the
//! history arrives, so no withdrawal, erase or narrowing is ever held back,
//! and a composing door stores as before.
//!
//! The history the rows need joins the vault's own request
//! ([`pending_history_request_in_txn`]); once any commit stores an authority
//! row, whichever door stored it (a local append, a signed page or repair
//! page, the selector door or the replicated commit), the rows are put
//! again ([`Vault::retry_pending_authority_history`]), each with the pending
//! rows it stands on, parents first. A row leaves once the fold with it
//! answers: stored where the door admits it, dropped with every pending row
//! standing on it where the door still refuses it for something other than
//! history (CALLS AUTHORITY_HISTORY_PENDING_END). The evidence survives a
//! restore (LIVE).

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use super::super::readonly_fold::{ArrivingFold, authority_view_with_rows_for_store_in_txn};
use super::*;
use crate::side_table::{self, Raw, SideTable};
use crate::{TimeRange, Vault};

/// Key: the row's entry hash. Value: its canonical signed bytes.
const AUTHORITY_HISTORY_PENDING: SideTable<AuthorityEntryHash, Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHORITY_HISTORY_PENDING);

/// When pending evidence leaves (CALLS AUTHORITY_HISTORY_PENDING_END): once
/// the fold with it answers, never by age or count.
pub(crate) const AUTHORITY_HISTORY_PENDING_END: PendingEnd = PendingEnd::ResolvedByReferenceFold;

/// The policy hook behind [`AUTHORITY_HISTORY_PENDING_END`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingEnd {
    /// A row leaves when the fold with it answers: a put of it lands, or the
    /// door refuses it for something other than history, which no later
    /// history changes. A row whose fold still needs history stays.
    ResolvedByReferenceFold,
}

thread_local! {
    /// Set while this thread puts pending rows again, so the commit of a row
    /// it lands starts no second retry inside the first.
    static RETRYING: Cell<bool> = const { Cell::new(false) };
}

/// What one put of a pending row, with the pending rows it stands on, did.
enum PendingLanding {
    /// Stored: the rows left the evidence in the same commit.
    Landed,
    /// The fold with them still needs history: they stay.
    Waiting,
    /// The fold with them answers and the door refuses them for something
    /// other than history.
    Refused(crate::error::Error),
}

/// A batch a local append keeps as evidence instead of storing it: the
/// history its fold needs, and each row's canonical signed bytes.
pub(crate) struct PendingAuthorityHistory {
    pub(crate) request: AuthorityHistoryRequest,
    rows: Vec<(AuthorityEntryHash, Vec<u8>)>,
}

/// What the owner's local append of `staged` on `txn`'s snapshot does under
/// the rule above: `Some` where the vault adopted a checkpoint image, every
/// row not stored yet grants only, and each one's fold needs history; None
/// to store them as before. A fault of a fold with them in keeps today's
/// path (CALLS AUTHORITY_ADMISSION_UNKNOWN). The caller keeps the evidence
/// only once the store door admitted the batch.
pub(crate) fn pending_history_of_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    staged: &[(AuthorityEntryHash, &AuthorityLogEntry)],
) -> Result<Option<PendingAuthorityHistory>> {
    Ok(pending_history_of(store, posture, txn, staged).unwrap_or(None))
}

/// [`pending_history_of_in_txn`], with its own faults returned.
fn pending_history_of(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    staged: &[(AuthorityEntryHash, &AuthorityLogEntry)],
) -> Result<Option<PendingAuthorityHistory>> {
    if super::super::checkpoint_adopt::adopted_authority_checkpoint_in_txn(store, txn)?.is_none() {
        return Ok(None);
    }
    let mut arriving = BTreeMap::new();
    for (hash, entry) in staged {
        if !super::super::retired_signers::authority_row_resident(store, txn, entry)? {
            arriving.insert(*hash, (*entry).clone());
        }
    }
    if arriving.is_empty() || !arriving.values().all(|entry| grants_only(&entry.op)) {
        return Ok(None);
    }
    // Each row needs the history itself: its fold, with the batch rows it
    // rests on, needs it. A row that does not keeps the batch on today's
    // path.
    for (hash, entry) in &arriving {
        let mut own = BTreeMap::from([(*hash, entry.clone())]);
        let mut stack = entry.parent_hashes.clone();
        while let Some(parent) = stack.pop() {
            if let Some(row) = arriving.get(&parent)
                && own.insert(parent, row.clone()).is_none()
            {
                stack.extend(row.parent_hashes.iter().copied());
            }
        }
        if !matches!(
            authority_view_with_rows_for_store_in_txn(store, posture, txn, &own),
            Ok(ArrivingFold::NeedHistory(_))
        ) {
            return Ok(None);
        }
    }
    let Ok(ArrivingFold::NeedHistory(request)) =
        authority_view_with_rows_for_store_in_txn(store, posture, txn, &arriving)
    else {
        return Ok(None);
    };
    let rows = arriving
        .iter()
        .map(|(hash, entry)| Ok((*hash, encode_authority_log_entry_body(entry)?)))
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(PendingAuthorityHistory { request, rows }))
}

/// Whether `op` only adds or widens authority (lead ruling a, 10-29): a
/// device enrollment, an actor binding, an owner root, a slip mint, a
/// federation confirm that is no revocation, a critical-write confirm that
/// clears, a federation connect. Every withdrawal, erase, narrowing or
/// terminal act, and every act whose effect turns on state (a rescope, a
/// rebind, a machine revision), keeps today's path. The fold's own
/// permissive class (`ancestry_evaluator::skippable_permissive`) is not this
/// door's.
fn grants_only(op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::EnrollDevice { .. }
        | AuthorityOp::BindActor { .. }
        | AuthorityOp::OwnerRoot(_)
        | AuthorityOp::SlipMint(_) => true,
        AuthorityOp::FederationConfirm(action) => action.kind != AuthorityConfirmKind::Revoke,
        AuthorityOp::CriticalWriteConfirm(action) => {
            action.disposition == CriticalWriteConfirmDisposition::Clear
        }
        AuthorityOp::FederationLifecycle(action) => action.kind == FederationLifecycleKind::Connect,
        _ => false,
    }
}

/// Keeps `pending`'s rows as evidence in the owner's writer, after the act
/// that signed them rolled back. The authority generation moves on, so no
/// view cached before it answers for the evidence.
pub(crate) fn keep_pending_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    pending: &PendingAuthorityHistory,
) -> Result<()> {
    for (hash, bytes) in &pending.rows {
        AUTHORITY_HISTORY_PENDING.put(store, txn, hash, bytes)?;
    }
    super::super::readonly_fold::advance_authority_cache_generation(store, txn)
}

/// The pending rows, decoded, by hash. A row whose bytes do not decode to
/// its key is corruption.
fn pending_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<AuthorityEntryHash, AuthorityLogEntry>> {
    AUTHORITY_HISTORY_PENDING
        .scan(store, txn)?
        .into_iter()
        .map(|(hash, bytes)| {
            let entry = decode_authority_log_entry_body(&bytes)?;
            if authority_entry_hash(&entry)? != hash {
                return Err(crate::error::Error::CorruptedIndex(
                    "authority history pending key",
                ));
            }
            Ok((hash, entry))
        })
        .collect()
}

/// The history the pending rows still need: the request of the fold with
/// them in, in `txn`'s snapshot. None with no pending row, where that fold
/// answers (the next retry stores them), or where it or the evidence read
/// fails: the vault's own request stands then, as before.
pub(crate) fn pending_history_request_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<AuthorityHistoryRequest>> {
    let Ok(pending) = pending_rows_in_txn(store, txn) else {
        return Ok(None);
    };
    if pending.is_empty() {
        return Ok(None);
    }
    Ok(
        match authority_view_with_rows_for_store_in_txn(store, posture, txn, &pending) {
            Ok(ArrivingFold::NeedHistory(request)) => Some(request),
            Ok(ArrivingFold::Complete(_)) | Err(_) => None,
        },
    )
}

impl Vault {
    /// After a commit that stored an authority row (`noted`), whichever door
    /// stored it, puts the pending rows again (FIX 2989 rest): history that
    /// lands by window sync or a plain page import ends their wait as a
    /// repair page does. A failure is logged and leaves them waiting for the
    /// next authority commit; it never fails the commit that called it.
    pub(crate) fn retry_pending_authority_history_after_authority_ingest(&self, noted: bool) {
        if !noted || RETRYING.with(Cell::get) {
            return;
        }
        if let Err(error) = self.retry_pending_authority_history() {
            tracing::warn!(
                target: "oneiron::authority::history",
                %error,
                "pending authority evidence retry failed; the next authority commit retries it"
            );
        }
    }

    /// Puts every pending row again through the local append door (FIX
    /// 2989), parents first, each with the pending rows it stands on, so a
    /// row the door refuses or one still waiting holds back only the rows
    /// standing on it (CALLS AUTHORITY_HISTORY_PENDING_END).
    pub(crate) fn retry_pending_authority_history(&self) -> Result<()> {
        match AUTHORITY_HISTORY_PENDING_END {
            PendingEnd::ResolvedByReferenceFold => {}
        }
        let pending = {
            let txn = self.store.env.read_txn()?;
            pending_rows_in_txn(&self.store, &txn)?
        };
        if pending.is_empty() {
            return Ok(());
        }
        let outer = RETRYING.with(|retrying| retrying.replace(true));
        let result = self.retry_pending_rows(&pending);
        RETRYING.with(|retrying| retrying.set(outer));
        result
    }

    /// [`Self::retry_pending_authority_history`] over `pending`, read before.
    fn retry_pending_rows(
        &self,
        pending: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ) -> Result<()> {
        let closures: BTreeMap<_, _> = pending
            .keys()
            .map(|hash| (*hash, pending_closure(pending, hash)))
            .collect();
        // An ancestor's closure is a strict subset of its descendant's.
        let mut order: Vec<_> = closures.keys().copied().collect();
        order.sort_by_key(|hash| (closures[hash].len(), *hash));
        let mut resolved = BTreeSet::new();
        for hash in order {
            if resolved.contains(&hash) {
                continue;
            }
            let rows: BTreeMap<_, _> = closures[&hash]
                .iter()
                .filter(|row| !resolved.contains(*row))
                .map(|row| (*row, pending[row].clone()))
                .collect();
            match self.land_pending_rows(&rows)? {
                PendingLanding::Landed => resolved.extend(rows.into_keys()),
                PendingLanding::Waiting => {}
                PendingLanding::Refused(error) => {
                    resolved.extend(self.drop_refused_pending(hash, &closures, &error)?);
                }
            }
        }
        Ok(())
    }

    /// One put of `rows` through the local append door, in a writer of its
    /// own that deletes them from the evidence as it stores them. The fold
    /// with them in is read first: while it needs history, no writer opens.
    fn land_pending_rows(
        &self,
        rows: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ) -> Result<PendingLanding> {
        let now = {
            let txn = self.store.env.read_txn()?;
            if !matches!(
                authority_view_with_rows_for_store_in_txn(
                    &self.store,
                    self.privacy_posture(),
                    &txn,
                    rows
                ),
                Ok(ArrivingFold::Complete(_))
            ) {
                return Ok(PendingLanding::Waiting);
            }
            self.instant_in_txn(&txn)?.secs()
        };
        let entries: Vec<_> = rows
            .values()
            .map(|entry| {
                (
                    entry.clone(),
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )
            })
            .collect();
        let watch = crate::federation::StaleSweepWatch::begin(self);
        let mut wtxn = self.store.env.write_txn()?;
        match self.put_authority_log_rows_in_txn(&mut wtxn, &entries, true) {
            Ok(AuthorityPut::Stored(_)) => {}
            Ok(AuthorityPut::Pending(_)) => return Ok(PendingLanding::Waiting),
            Err(error) if super::super::readonly_fold::is_history_incomplete(&error) => {
                return Ok(PendingLanding::Waiting);
            }
            Err(error @ crate::error::Error::Record(_)) => {
                return Ok(PendingLanding::Refused(error));
            }
            Err(error) => return Err(error),
        }
        for hash in rows.keys() {
            AUTHORITY_HISTORY_PENDING.delete(&self.store, &mut wtxn, hash)?;
        }
        wtxn.commit()?;
        watch.finish()?;
        self.store.notify_proactivity_changes();
        Ok(PendingLanding::Landed)
    }

    /// Drops `refused` and every pending row standing on it from the
    /// evidence, once the fold with it answered and the door still refused
    /// it (`error`), and answers them all.
    fn drop_refused_pending(
        &self,
        refused: AuthorityEntryHash,
        closures: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
        error: &crate::error::Error,
    ) -> Result<BTreeSet<AuthorityEntryHash>> {
        let dropped: BTreeSet<_> = closures
            .iter()
            .filter(|(_, closure)| closure.contains(&refused))
            .map(|(hash, _)| *hash)
            .collect();
        let mut txn = self.store.env.write_txn()?;
        for hash in &dropped {
            AUTHORITY_HISTORY_PENDING.delete(&self.store, &mut txn, hash)?;
        }
        txn.commit()?;
        tracing::warn!(
            target: "oneiron::authority::history",
            %error,
            rows = dropped.len(),
            "pending authority evidence left: its history is here and the door refused it"
        );
        Ok(dropped)
    }
}

/// `hash` and every pending row it stands on, through pending rows only.
fn pending_closure(
    pending: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    hash: &AuthorityEntryHash,
) -> BTreeSet<AuthorityEntryHash> {
    let mut closure = BTreeSet::from([*hash]);
    let mut stack = pending[hash].parent_hashes.clone();
    while let Some(parent) = stack.pop() {
        if let Some(row) = pending.get(&parent)
            && closure.insert(parent)
        {
            stack.extend(row.parent_hashes.iter().copied());
        }
    }
    closure
}
