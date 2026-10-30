//! The owner's kit push records the custody request it enacts (FIX 6053,
//! ARCH-0069 #custody-seal-planned; CALLS `KS-6 kit request authority`).
//!
//! An install with no live machine profile carries no owner act, so the kit
//! is its authority (CALLS CUSTODY_KIT_PUSH). Its push now records the same
//! custody request every change does, in the same commit as the transition:
//! a rewrap of the record at its generation, no input and no holder, to the
//! permits the owner named, signed by the anchor of the root this vault
//! pins, under the typed `PinnedKit` authority. No machine carries or
//! executes it (its carrier and executor fields name the secret itself),
//! no profile is asked for, and no other change takes the kit's signature.
//! The transition then names that request, and a receiver admits it only on
//! it ([`kit_request_admits`]). A fault recording it leaves the push as it
//! was, its request zero, warned: never a refusal, never a demand for a
//! profile. The request is recorded in a savepoint, so a fault takes its
//! staged pieces and frontier join with it, never orphaned (FIX 12016).
//! Its permits are measured as an install's request's are, and past
//! one row ride in pieces the anchor signs ahead of the request (FIX 11866).

use ed25519_dalek::SigningKey;

use super::super::types::SecretCustodyStatus;
use super::CustodyTransition;
use crate::Vault;
use crate::authority::{
    ActSurface, AuthorityEntryHash, AuthorityFold, AuthorityKey, AuthorityOp, CustodyChange,
    CustodyRecipientPermit, CustodyRequestAuthority, FrontierSigner, MAX_PARENTS, OwnerAct,
    OwnerActKind, OwnerWorkBody, OwnerWorkRequest, RecoveryRootId, authority_entry_hash,
    next_sequence, sign_side_entry,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;

/// What the kit push records (CALLS `KS-6 kit request authority`): one
/// custody request for the owner `actor`'s push of record `id` at
/// `generation` to `permits`, signed with `anchor`, the anchor of `root`,
/// in `wtxn`. Returns its entry hash once the fold here counts it; zero,
/// warned, when it cannot be recorded or has no effect here, so the push
/// goes on as it did (CUSTODY_NEW_CHECK_FAULT = WarnAndKeepCurrentPath).
/// The request is written in a savepoint of `wtxn`: a fault drops every row
/// it staged (its permit pieces and frontier join) with it (FIX 12016).
#[allow(clippy::too_many_arguments)]
pub(super) fn record_kit_request_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fold: &AuthorityFold,
    actor: EntityId,
    id: EntityId,
    generation: u32,
    permits: &[CustodyRecipientPermit],
    (anchor, root): (&SigningKey, RecoveryRootId),
) -> AuthorityEntryHash {
    let recorded = vault
        .store
        .env
        .nested_write_txn(wtxn)
        .map_err(Error::from)
        .and_then(|mut savepoint| {
            let hash = record_in_txn(
                vault,
                &mut savepoint,
                fold,
                actor,
                id,
                generation,
                permits,
                (anchor, root),
            )?;
            savepoint.commit()?;
            Ok(hash)
        });
    match recorded {
        Ok(hash) => hash,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "the kit push's custody request was not recorded; the push carries no request, \
                 as before (FIX 6053 pending here)"
            );
            [0; 32]
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fold: &AuthorityFold,
    actor: EntityId,
    id: EntityId,
    generation: u32,
    permits: &[CustodyRecipientPermit],
    (anchor, root): (&SigningKey, RecoveryRootId),
) -> Result<AuthorityEntryHash> {
    let seen = fold.custody_work_revision(id);
    let act = OwnerAct::by_owner(
        actor,
        OwnerActKind::CustodyTransition,
        id,
        ActSurface::ThisInstall,
        seen,
    );
    let mut work = OwnerWorkBody::Custody {
        change: CustodyChange::Rewrap,
        generation,
        input: None,
        holder: None,
        recipients: permits.to_vec(),
        pieces: None,
        authority: CustodyRequestAuthority::PinnedKit { root },
    };
    // FIX 8498 (Engine 09:31; L04 09:40 (c)): the anchor joins a frontier
    // wider than the request names, ahead of its own row, else today's path.
    let joiner = FrontierSigner::Anchor(anchor);
    let joined = vault.prepare_authority_frontier_in_txn(wtxn, fold, joiner, MAX_PARENTS)?;
    let fold = joined.as_deref().unwrap_or(fold);
    // FIX 11866: the anchor writes permits past one row in pieces ahead of
    // its own row too, measured as an install's request measures them, else
    // today's path.
    let staged = vault.stage_custody_permit_pieces_in_txn(wtxn, fold, (None, anchor), &mut work)?;
    let fold = staged.as_deref().unwrap_or(fold);
    let request = OwnerWorkRequest {
        carrier: id,
        act,
        executor: id,
        work,
        privacy_basis: None,
    };
    let signer = AuthorityKey::Ed25519(anchor.verifying_key().to_bytes());
    let seq = next_sequence(fold, &signer)?;
    let now = vault.instant_in_txn(wtxn)?.secs();
    let entry = sign_side_entry(
        fold,
        anchor,
        seq,
        fold.owner_work_parents(),
        AuthorityOp::OwnerWorkRequest(request),
        now,
    )?;
    let hash = authority_entry_hash(&entry)?;
    let at = TimeRange {
        start: now,
        end: now,
    };
    vault.put_authority_log_entries_in_txn(wtxn, &[(entry, at, now)])?;
    if vault
        .authority_view_readonly_in_txn(wtxn)?
        .counted_owner_work_request(&hash)
        .is_none()
    {
        return Err(Error::InvalidConfig(
            "the kit push's custody request has no effect here".into(),
        ));
    }
    Ok(hash)
}

/// Whether `transition` stands on `request`, a kit request counted in
/// `fold` (FIX 6053): a rewrap of the transition's record at its
/// generation, live, with no input, its piece of exactly its permits, and
/// signed by the anchor of the root the request names, which this vault
/// pins.
pub(super) fn kit_request_admits(
    fold: &AuthorityFold,
    request: &OwnerWorkRequest,
    transition: &CustodyTransition,
) -> bool {
    let OwnerWorkBody::Custody {
        change: CustodyChange::Rewrap,
        generation,
        input: None,
        recipients,
        ..
    } = &request.work
    else {
        return false;
    };
    request.act.target == transition.id
        && *generation == transition.generation
        && transition.input.is_none()
        && transition.status != SecretCustodyStatus::Revoked
        && transition.piece_of(recipients)
        && fold.pinned_root.as_ref().is_some_and(|pin| {
            Some(pin.id) == request.kit_root() && pin.anchor_key == transition.signer
        })
}
