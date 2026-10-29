//! The preflight an authority door runs before it admits arriving rows
//! (FIX 2535, 2989; CALLS "FIX 2535 2989 admission unknown").
//!
//! A door judges an arriving row against this vault's fold in its own
//! snapshot. Where that fold answers, the door reads it as before. Where it
//! refuses for history this vault does not hold, the arriving rows may be
//! that history: the door then folds the snapshot with them in, as stored
//! rows first seen now, and judges them on that fold where it answers, so a
//! repair row lands at every door, not only through a signed page import.
//! Neither fold enters the authorization cache. Where the fold with them
//! still needs history, or fails, the snapshot's own refusal stands, as
//! before: an unknown never admits.
//!
//! A local append on a vault that adopted a checkpoint image runs the same
//! fold with its batch in before it stores the batch ([`pending`], FIX
//! 2989).

use std::collections::BTreeMap;

use super::readonly_fold::{
    ArrivingFold, AuthorityView, authority_view_with_rows_for_store_in_txn, is_history_incomplete,
};
use super::*;
use crate::HostingPrivacyPosture;
use crate::error::Result;
use crate::store::Store;

mod pending;

pub(crate) use pending::{
    PendingAuthorityHistory, keep_pending_in_txn, pending_history_of_in_txn,
    pending_history_request_in_txn,
};

/// What a local append does with a batch (FIX 2989): stores it, or returns
/// it to the transaction owner as evidence to keep, with the history its
/// fold needs.
pub(crate) enum AuthorityPut {
    Stored(Vec<crate::EntityId>),
    Pending(PendingAuthorityHistory),
}

/// What a door does where the fold with the arriving rows folded in does
/// not answer (CALLS AUTHORITY_ADMISSION_UNKNOWN): the snapshot's own answer
/// stands. It reaches only the new fold with the rows in; a signature, root
/// or clock failure of the snapshot's fold is never an unknown.
pub(crate) const AUTHORITY_ADMISSION_UNKNOWN: AdmissionUnknown = AdmissionUnknown::KeepCurrent;

/// The policy hook behind [`AUTHORITY_ADMISSION_UNKNOWN`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionUnknown {
    /// The snapshot's answer stands: its fold, or its refusal.
    KeepCurrent,
}

/// The fold a door judges arriving rows against: the snapshot's own, or,
/// where that one needs history the rows supply, the snapshot's with them
/// folded in.
pub(crate) struct AuthorityAdmissionView {
    view: AuthorityView,
}

impl std::ops::Deref for AuthorityAdmissionView {
    type Target = AuthorityFold;

    fn deref(&self) -> &Self::Target {
        &self.view
    }
}

/// The fold `rows` are judged against in `txn` under `posture` (see the
/// module doc). The snapshot's fold is read first and returned whenever it
/// answers; its history refusal stands wherever the fold with `rows` in does
/// not answer. Any other failure of the snapshot's fold is returned as it is.
pub(crate) fn preflight_authority_rows_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    rows: &[(AuthorityEntryHash, &AuthorityLogEntry)],
) -> Result<AuthorityAdmissionView> {
    let refusal = match authority_view_readonly_for_store_in_txn(store, posture, txn) {
        Ok(view) => {
            return Ok(AuthorityAdmissionView { view });
        }
        Err(error) if is_history_incomplete(&error) && !rows.is_empty() => error,
        Err(error) => return Err(error),
    };
    match AUTHORITY_ADMISSION_UNKNOWN {
        AdmissionUnknown::KeepCurrent => {}
    }
    let arriving: BTreeMap<_, _> = rows
        .iter()
        .map(|(hash, entry)| (*hash, (*entry).clone()))
        .collect();
    match authority_view_with_rows_for_store_in_txn(store, posture, txn, &arriving) {
        Ok(ArrivingFold::Complete(view)) => Ok(AuthorityAdmissionView { view }),
        Ok(ArrivingFold::NeedHistory(_)) | Err(_) => Err(refusal),
    }
}
