//! The push authority on a receive-pack intent (FIX 6867, G1-PUSH): the
//! final writer takes the stamp's authority only when the locally observed
//! admission evidence names that same authority, and recovery rebuilds the
//! stamp with the authority the intent was accepted under, never a bare
//! principal standing in for it (CALLS "FIX 6867 git_push acceptance").

use super::super::door::DoorAdmissionStamp;
use super::super::evidence::{receive_pack_field, receive_pack_provenance_refused};
use super::ReceivePackIntent;
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::git_push::GitPushStamp;

/// The push authority `stamp` was admitted under, once `admission` (its
/// producer-bound evidence) records that same authority.
///
/// # Errors
/// The evidence names another authority, or the stamp carries none.
pub(super) fn admitted_push<'a>(
    admission: &ClaimBody,
    stamp: &'a DoorAdmissionStamp,
) -> Result<&'a GitPushStamp> {
    let push = stamp
        .push
        .as_ref()
        .ok_or_else(|| receive_pack_provenance_refused("intent was not admitted to push"))?;
    if receive_pack_field(admission, "git_push")? != &GitPushStamp::evidence_value(Some(push)) {
        return Err(receive_pack_provenance_refused(
            "intent's push authority differs from its admission",
        ));
    }
    Ok(push)
}

/// The stamp recovery completes `intent` under: the accepted operation's own
/// principal, host authority and push authority. An intent from before
/// G1-PUSH carries no push authority and completes as it was accepted.
///
/// # Errors
/// The intent's operation id does not parse.
pub(super) fn recovered_stamp(intent: &ReceivePackIntent) -> Result<DoorAdmissionStamp> {
    Ok(DoorAdmissionStamp {
        principal_ref: intent.actor_id.clone(),
        credential_fingerprint: None,
        method: "bearer+registered-principal",
        admitted_at: intent.admitted_at,
        origin_authority: intent.origin_authority.clone(),
        operation_id: EntityId::from_hex(&intent.operation_id)
            .map_err(|_| Error::CorruptedIndex("receive-pack operation id"))?,
        push: intent.push.clone(),
        ingress_proof: intent
            .ingress_proof
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()
            .map_err(|_| Error::CorruptedIndex("receive-pack ingress proof id"))?,
    })
}
