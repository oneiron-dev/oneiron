//! The owner's kit push as a custody request in the fold (FIX 6053, CALLS
//! `KS-6 kit request authority`): the one push an install with no machine
//! profile makes (CALLS CUSTODY_KIT_PUSH) records the same custody request
//! every other change does, under a typed authority of its own.
//!
//! A kit request is a rewrap with no input and no holder, signed by the
//! anchor of the recovery root this install pins, which it names. No
//! machine carries or executes it: no install key signs it and no pickup
//! answers it; the transition the kit signs in the same commit is its
//! enactment. It has effect when the pin here names its root and that
//! root's anchor signed it, its owner is live at its parents and its `seen`
//! is its secret's revision there; it counts without a carrier's removal
//! race, which no machine runs. It joins no secret's live custody heads, so
//! the requests a later rotate, rebind or retry reads stay as they were.

use super::*;

/// Whose say-so a kit push stands on (CALLS `KS-6 kit request authority`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyKitRequestAuthority {
    /// The pinned recovery root's anchor, for an unprofiled install's
    /// rewrap alone: no fake machine carrier or executor, no root signature
    /// for any other change, and never an install's profile demanded.
    PinnedRecoveryRootForUnprofiledCustodyRewrapOnly,
}

const CUSTODY_KIT_REQUEST_AUTHORITY: CustodyKitRequestAuthority =
    CustodyKitRequestAuthority::PinnedRecoveryRootForUnprofiledCustodyRewrapOnly;

/// A kit request for `root` lands: valid with effect on the rule above,
/// valid without effect otherwise. Its signer is an Ed25519 key whose
/// sequence moves on, or the entry is invalid.
pub(super) fn apply_kit_request(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    request: &OwnerWorkRequest,
    hash: AuthorityEntryHash,
    root: RecoveryRootId,
    pin: Option<&PinnedRoot>,
) -> std::result::Result<(), AuthorityFoldIssue> {
    match CUSTODY_KIT_REQUEST_AUTHORITY {
        CustodyKitRequestAuthority::PinnedRecoveryRootForUnprofiledCustodyRewrapOnly => {}
    }
    let AuthorityKey::Ed25519(key) = entry.signer_key() else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    if state
        .seqs
        .get(entry.signer_key())
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    // Its permits in pieces join from its own signer's pieces at its parents
    // (FIX 11866); pieces that do not join leave it without effect.
    let Some(request) = permit_pieces::joined_request(&state.owner_work, key, request) else {
        state.owner_work.refused.insert(hash);
        return Ok(());
    };
    let pinned = pin.is_some_and(|pin| pin.id == root && pin.anchor_key == *key);
    let live = pinned
        && crate::authority::owner_act::owner_live_at(state, request.act.owner)
        && custody::custody_request_lands(&state.owner_work, &request);
    let work = &mut state.owner_work;
    if !live {
        work.refused.insert(hash);
        return Ok(());
    }
    work.requests.insert(
        hash,
        Arc::new(WorkRequest {
            request: request.into_owned(),
            key: *key,
            marks: BTreeMap::new(),
            narrow_only: false,
        }),
    );
    Ok(())
}
