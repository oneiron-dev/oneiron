//! Generic claim-door writes of the projector-only `comm.*` classes, routed
//! through the projector.
//!
//! The projector alone authors `comm.last_touch` and `comm.thread_member`: it
//! mints each head at an id derived from its source event, behind its
//! compare-and-set write and its slot rules (the newest touch supersedes the
//! rest; one live membership per thread). A generic write of either class is
//! not refused. It is recorded as the source event the projector reads, and
//! the projector's next pass authors the head. The projector's own writes,
//! the typed doors and replication land through `apply_ops` and never come
//! here.

use super::claims::{
    CommClaim, CommClaimValue, CommError, PREDICATE_COMM_LAST_TOUCH, PREDICATE_COMM_THREAD_MEMBER,
};
use super::descriptor::claim_class_descriptor_in_txn;
use super::projector::put_source_event_in_txn;
use super::records::CommEventKind;
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, encode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};

/// Routes one generic claim-door write of a projector-only `comm.*` class
/// through the projector, in the caller's write. Returns `true` when the
/// write was routed, so the door writes nothing more, and `false` when the
/// door writes it as before.
///
/// A class routes while its descriptor (the synced row, else the compiled
/// one) says `projector_only`. The body is validated as the door validates
/// it, so a body the door refuses is refused alike. A body byte-identical to
/// the claim already at `id` is a replay and records nothing. Otherwise the
/// fact the body states becomes a source event on the party it names: a live
/// touch an asserted touch, a live membership a join, and a closed membership
/// a leave at its close. The projector mints the head at its derived id, so
/// `id` stays free. A body that states no fact the projector authors (a
/// proposed, rejected or stale head, a closed touch) and a subject that is
/// not a PERSON party are left to the door.
///
/// # Errors
/// A body the door refuses, a subject that is not there, or a storage
/// failure.
pub fn route_projector_only_comm_put_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<bool> {
    if body.predicate != PREDICATE_COMM_LAST_TOUCH && body.predicate != PREDICATE_COMM_THREAD_MEMBER
    {
        return Ok(false);
    }
    if !claim_class_descriptor_in_txn(&vault.store, wtxn, &body.predicate)?
        .is_some_and(|descriptor| descriptor.projector_only)
    {
        return Ok(false);
    }
    let data = encode_claim_body(body)?;
    let body =
        crate::claim::validate_claim_body_and_decode_in_txn(&vault.store, wtxn, &data, false)?;
    if let Some(resident) = vault.store.port_entity_record(&*wtxn, id)?
        && resident.entity_type == ENTITY_TYPE_CLAIM
        && resident.body == data[..]
    {
        return Ok(true);
    }
    let claim = CommClaim::from_claim_body(&body)?;
    let stated = matches!(
        claim.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) && !claim.stale;
    let live = stated && claim.lifecycle == ClaimLifecycleStatus::Active;
    let (party_ref, kind, channel_class, thread_ref, occurred_at) = match claim.value {
        CommClaimValue::LastTouch {
            party_ref,
            channel_class,
            occurred_at,
        } if live => (
            party_ref,
            CommEventKind::TouchAsserted,
            Some(channel_class),
            None,
            occurred_at,
        ),
        CommClaimValue::ThreadMember {
            party_ref,
            thread_ref,
            occurred_at,
        } if live => (
            party_ref,
            CommEventKind::ThreadJoined,
            None,
            Some(thread_ref),
            occurred_at,
        ),
        CommClaimValue::ThreadMember {
            party_ref,
            thread_ref,
            occurred_at,
        } if stated => (
            party_ref,
            CommEventKind::ThreadLeft,
            None,
            Some(thread_ref),
            claim.valid_to.unwrap_or(occurred_at),
        ),
        _ => return Ok(false),
    };
    match vault.store.port_entity_record(&*wtxn, &party_ref)? {
        None => return Err(Error::EntityNotFound),
        // The projector writes a comm head only on a PERSON party.
        Some(party) if party.entity_type != ENTITY_TYPE_PERSON => return Ok(false),
        Some(_) => {}
    }
    put_source_event_in_txn(
        vault,
        wtxn,
        party_ref,
        kind,
        channel_class.as_deref(),
        thread_ref.as_deref(),
        occurred_at,
    )
    .map_err(|error| match error {
        CommError::Engine(error) => error,
        _ => Error::InvalidClaimBody("comm source event refused"),
    })?;
    Ok(true)
}
