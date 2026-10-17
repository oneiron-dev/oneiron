//! Member-mailbox send predicates (OF-374).
//!
//! A delegated `email` row whose grant carries `mail.send` is an engine mail
//! sender beside native mail. It rides the SAME canonical mail operation:
//! recipient binding at dispatch, the approve-once digest the owner presses,
//! and the replay proof the intent ledger checks are native mail's own
//! ([`super::native_mail::CanonicalMailSend`]). These predicates only say which
//! rows qualify, read on the caller's transaction so the Gate decides on its
//! own writer snapshot.
//!
//! What a member row does NOT share is native mail's cold-recipient policy and
//! reputation ramp: those describe an address the product minted. A member
//! send with no covering grant is simply an ungranted irreversible effect, so
//! the Gate holds it for the owner's press (ARCH-0063 "posture starts at
//! draft→approve"; ARCH-0046 "depends on the grant").

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityFacts, channel_identity_facts_in_txn,
    decode_channel_identity_body,
};
use crate::gate::ExternalEffectGateInput;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::store::Store;
use crate::{EntityId, Error, Result};

/// A delegated `email` identity: its facts from its `channel_identity.*`
/// heads, its custody from the local row (OF-272).
pub(crate) struct MemberMailIdentity {
    pub(crate) facts: ChannelIdentityFacts,
    pub(crate) custody: ChannelIdentity,
}

/// The identity at `identity_ref`, when it is a delegated `email` one.
///
/// The channel is the identity's `channel_identity.channel` head; whether it
/// is DELEGATED is custody — the grant lives only on the local row, as does
/// every send capability. Structural only: a released row still answers, so
/// terminal replay can recognize its own sender. Every effect path asks
/// [`ChannelIdentity::may_send`] on top.
pub(crate) fn member_mail_identity_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
) -> Result<Option<MemberMailIdentity>> {
    let Some(facts) = channel_identity_facts_in_txn(store, txn, &identity_ref)? else {
        return Ok(None);
    };
    if facts.channel != "email" {
        return Ok(None);
    }
    let Some(raw) = store
        .port_entity_record(txn, &identity_ref)?
        .map(|row| row.encode())
    else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("member-mail identity entity header"))?;
    if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Ok(None);
    }
    let custody = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if custody.grant().is_none() {
        return Ok(None);
    }
    Ok(Some(MemberMailIdentity { facts, custody }))
}

/// Whether `identity_ref` names a delegated `email` row at all.
pub(crate) fn is_member_mail_identity_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
) -> Result<bool> {
    Ok(member_mail_identity_in_txn(store, txn, identity_ref)?.is_some())
}

/// A live member row whose grant carries send.
pub(crate) fn is_member_mail_sender_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
) -> Result<bool> {
    Ok(member_mail_identity_in_txn(store, txn, identity_ref)?
        .is_some_and(|identity| identity.custody.may_send()))
}

/// The Gate requires the live send-capable row to belong to its
/// authenticated actor, not just a mailbox named in the sender slot. Whose it
/// is comes from the binding head; whether it may send, from custody.
pub(crate) fn member_mail_actor_may_send_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
    actor: Option<EntityId>,
) -> Result<bool> {
    Ok(
        member_mail_identity_in_txn(store, txn, identity_ref)?.is_some_and(|identity| {
            identity.custody.may_send() && identity.facts.binding.actor_ref() == actor
        }),
    )
}

/// Whether this effect is one canonical member-mailbox send: `email/send` to
/// one counterparty, from a live send-capable member row bound to the
/// effect's own actor. Only then does the Gate look up the canonical mail
/// approve-once digest for it.
pub(crate) fn member_mail_send_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
) -> Result<bool> {
    if effect.channel != "email"
        || effect.verb != "send"
        || effect.counterparty.as_deref().is_none_or(str::is_empty)
        || effect.send_ref.as_deref().is_none_or(str::is_empty)
    {
        return Ok(false);
    }
    let (Some(identity_ref), Some(actor)) = (
        effect.channel_identity_ref,
        effect.provenance.actor_entity_ref,
    ) else {
        return Ok(false);
    };
    if effect.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str()) {
        return Ok(false);
    }
    member_mail_actor_may_send_in_txn(store, txn, identity_ref, Some(actor))
}
