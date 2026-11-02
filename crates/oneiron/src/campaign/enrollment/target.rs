//! The pinned send target of one campaign enrollment's outward leg (FIX 11513).
//!
//! A program step names its channel and its sticky sender; the leg resolves
//! the enrolled member to a live counterparty contact on exactly that
//! (channel, sender) pair. Anything else — a member that is not a PERSON, a
//! PERSON with no comm address, a sender that is not Active on this channel
//! or may not send, a contact that is not Active — resolves to nothing, and
//! the leg sends nothing (K12). The gate still applies its restrictions past
//! this point; the resolver only refuses to invent a target.

use rmpv::Value;

use super::program::CampaignProgramStep;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::campaign::claims::normalize_campaign_pack_token;
use crate::channel_identity::{ChannelIdentityState, channel_identity_facts_in_txn};
use crate::counterparty_contact::CounterpartyContactStatus;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_PERSON;

/// The comm-owned PERSON body's address field. Spelled literally: the
/// constant (`KEY_PARTY_KEY` in `human_task::storage`) is `pub(super)` to
/// `human_task` and unreachable here, so this cite carries the reference.
const PARTY_KEY_FIELD: &str = "party_key";

/// Where one campaign send goes: the live contact's address plus the member
/// key that binds the frozen payload to the person (erasing them stops it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CampaignMemberTarget {
    /// The live contact's counterparty string: the envelope's `target`.
    pub(super) target: String,
    /// The member's replicated comm `party_key`: the envelope's
    /// `counterparty_ref`, in the string form
    /// `OutboundExecutionRequest::counterparty_ref` carries (`Option<&str>`).
    pub(super) party_key: String,
}

/// Resolves `member` to a sendable target on the step's pinned channel and
/// sender. `None` answers every unresolvable shape (FIX 11513 K12): a member
/// that is not a PERSON, a PERSON with no replicated `party_key`, a sender
/// row that does not read, is not Active, names another channel, or may not
/// send, and a counterparty contact that does not read or is not Active. No
/// veto is applied here: the route resolves through opt-outs and the gate
/// restricts, as the follow-up resolver does.
///
/// # Errors
///
/// Storage errors propagate; every unresolvable shape is `None`, never an
/// error.
pub(super) fn resolve_campaign_member_target(
    vault: &Vault,
    member: EntityId,
    step: &CampaignProgramStep,
) -> Result<Option<CampaignMemberTarget>> {
    let txn = vault.store.env.read_txn()?;
    if vault.get_entity_type_in_txn(&txn, &member)? != Some(ENTITY_TYPE_PERSON) {
        return Ok(None);
    }
    let Some(party_key) = comm_party_key(vault, &txn, member)? else {
        return Ok(None);
    };
    let (Some(row), Some(facts)) = (
        vault.get_channel_identity_in_txn(&txn, &step.sender_ref)?,
        channel_identity_facts_in_txn(&vault.store, &txn, &step.sender_ref)?,
    ) else {
        return Ok(None);
    };
    if facts.state != ChannelIdentityState::Active
        || normalize_campaign_pack_token(&facts.channel)
            != normalize_campaign_pack_token(&step.channel)
        || !row.may_send()
    {
        return Ok(None);
    }
    let Some((_, contact)) =
        vault.find_counterparty_contact_in_txn(&txn, &step.sender_ref, &party_key)?
    else {
        return Ok(None);
    };
    if contact.status != CounterpartyContactStatus::Active {
        return Ok(None);
    }
    Ok(Some(CampaignMemberTarget {
        target: contact.counterparty,
        party_key,
    }))
}

/// The comm-owned PERSON's `party_key` — the address the identity plane
/// already knows this person by. Absent means the PERSON was minted by some
/// other surface and carries no communication address.
///
/// A replica of `human_task::followup::comm_party_key`, which is
/// `human_task`-only (`pub(super)` there): the raw read, the header parse,
/// the PERSON check, and the msgpack `party_key` lookup, step for step.
fn comm_party_key(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person_ref: EntityId,
) -> Result<Option<String>> {
    let Some(raw) = vault.get_raw_in(txn, &person_ref)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Ok(None);
    }
    let Ok(value) = rmpv::decode::read_value(&mut std::io::Cursor::new(
        &raw[ENTITY_METADATA_HEADER_LEN..],
    )) else {
        return Ok(None);
    };
    let Value::Map(entries) = value else {
        return Ok(None);
    };
    Ok(entries.into_iter().find_map(|(key, value)| {
        (key.as_str() == Some(PARTY_KEY_FIELD))
            .then(|| value.as_str().map(str::to_owned))
            .flatten()
    }))
}
