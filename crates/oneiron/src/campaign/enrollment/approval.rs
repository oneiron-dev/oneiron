//! FIX 6424 part 2a (Engine 10-20 21:0x rulings 6 and 7): the owner's
//! approve-once ask on one campaign enrollment's outbound leg.
//!
//! The leg's press pins the consequence, never the event row that carried
//! it (CALLS `FIX 6424 campaign event row versus logical event`): the logical
//! event (query, campaign, recipient entity, epoch), the program step, the
//! consequence id and its durable call sequence (the nonce), and the digest
//! of the frozen outbound body. Duplicate event rows for one consequence name
//! one digest; another step, epoch, call sequence or body is another send and
//! a new ask.
//!
//! Each prepared request of a consequence's call is retained before the
//! chokepoint first asks for it (CALLS `FIX 6424 pre-ask prepared snapshot
//! retention`), keyed by (consequence, call sequence, request digest): its
//! target, the body by its digest, its sender, and the event row it was first
//! asked under; its channel, verb and idempotency are named by the request
//! digest. A retry reads it before it builds its gate input: live rows that
//! prepare that same request reuse the retained one, so the same digest and
//! the first event row; a changed target or body is a new ask, retained under
//! its own key and never over another's. No body, address or payload byte is
//! copied, only ids and digests. A row that does not read, decode or match
//! leaves the call on its live rows, as before this table; one that does not
//! write is logged and the call goes on.

use super::detection::CampaignEnrollmentEvent;
use super::program::{CampaignProgramOutbound, CampaignProgramStep};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::gate::CampaignLegFacts;
use crate::side_table::{self, Raw, SideTable};

/// The retained request's row layout version.
const RETAINED_VERSION: u8 = 1;
/// Version; the query, campaign and recipient entity; the epoch; the program
/// and step; the body digest; the sender; the event row first asked under.
const RETAINED_LEN: usize = 1 + 16 * 3 + 8 + 16 * 2 + 32 + 16 + 16;
/// The domain of the retained request's digest.
const REQUEST_DOMAIN: &[u8] = b"oneiron.campaign.enrollment.retained_request.v1";
/// The additional domain separation for an email body's frozen subject.
const EMAIL_PAYLOAD_DOMAIN: &[u8] = b"oneiron.campaign.enrollment.email_payload.v1";

/// (consequence id, call sequence, request digest) → the retained request.
const RETAINED: SideTable<([u8; 16], u64, [u8; 32]), [u8; RETAINED_LEN], Raw> =
    SideTable::new(&side_table::CAMPAIGN_ENROLLMENT_ASK);

/// What the leg's ask on one consequence's call names (Engine ruling 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LegAsk {
    /// The target the press pins: the retained request's when the live rows
    /// prepare that same request, else the live rows' own (a new ask).
    pub(super) target: CampaignLegFacts,
    /// The event row the retained request was first asked under; `None` when
    /// none was read or kept.
    // Read by the leg, ONE-1778 staging (see `outbound_leg.rs`).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) first_event_ref: Option<EntityId>,
}

/// The frozen body digest, with the optional email subject framed explicitly.
/// Non-email payloads keep their existing digest byte-for-byte.
fn outbound_payload_digest(outbound: &CampaignProgramOutbound) -> [u8; 32] {
    let body = crate::outbound_intent_ledger::hash_frozen_payload(&outbound.payload);
    let Some(subject) = outbound.subject.as_deref() else {
        return body;
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(EMAIL_PAYLOAD_DOMAIN);
    hasher.update(&body);
    hasher.update(&(subject.len() as u64).to_be_bytes());
    hasher.update(subject.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The ask on the request `event`, `step` and `outbound` prepare for
/// `consequence_id`'s call, read against the request retained for it. With
/// `retain`, a request none retained yet is retained now, before the
/// chokepoint asks for it; without, it reads and records nothing.
/// A request the erase retired is not retained again: the fence in `keep`
/// skips it, and the call goes on from its live rows.
pub(super) fn leg_ask(
    vault: &Vault,
    event: &CampaignEnrollmentEvent,
    step: &CampaignProgramStep,
    outbound: &CampaignProgramOutbound,
    consequence_id: AttemptId,
    retain: bool,
) -> LegAsk {
    let live = CampaignLegFacts {
        query_ref: event.query_ref,
        campaign_ref: event.campaign_ref,
        entity_ref: event.entity_ref,
        epoch: event.epoch,
        program_ref: step.program_ref,
        step_ref: step.step_ref,
        consequence_id: *consequence_id.as_bytes(),
        call_seq: outbound.call_seq,
        payload_digest: outbound_payload_digest(outbound),
    };
    let key = (
        live.consequence_id,
        live.call_seq,
        request_digest(&live, step, outbound),
    );
    match retained(vault, &key) {
        Retained::Same(target, first_event_ref) if target == live => LegAsk {
            target,
            first_event_ref: Some(first_event_ref),
        },
        // A row that does not read or decode, or names another request under
        // this key: the live rows, as before, and the row stays as it is.
        Retained::Same(..) | Retained::Unusable => LegAsk {
            target: live,
            first_event_ref: None,
        },
        Retained::Absent => {
            let kept = retain && keep(vault, &key, &live, step.sender_ref, event.event_ref);
            LegAsk {
                target: live,
                first_event_ref: kept.then_some(event.event_ref),
            }
        }
    }
}

/// One prepared request's identity: its target, its sender, its channel,
/// verb and idempotency.
fn request_digest(
    facts: &CampaignLegFacts,
    step: &CampaignProgramStep,
    outbound: &CampaignProgramOutbound,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUEST_DOMAIN);
    for id in [
        facts.query_ref,
        facts.campaign_ref,
        facts.entity_ref,
        facts.program_ref,
        facts.step_ref,
        step.sender_ref,
    ] {
        hasher.update(id.as_bytes());
    }
    hasher.update(&facts.epoch.to_be_bytes());
    hasher.update(&facts.consequence_id);
    hasher.update(&facts.call_seq.to_be_bytes());
    hasher.update(&facts.payload_digest);
    for text in [step.channel.as_str(), outbound.verb.as_str()] {
        hasher.update(&(text.len() as u64).to_be_bytes());
        hasher.update(text.as_bytes());
    }
    hasher.update(&[u8::from(outbound.idempotency_supported)]);
    *hasher.finalize().as_bytes()
}

/// What the retained table holds under one key.
enum Retained {
    /// No request retained under it.
    Absent,
    /// The retained target and the event row it was first asked under.
    Same(CampaignLegFacts, EntityId),
    /// A row that does not read or decode.
    Unusable,
}

fn retained(vault: &Vault, key: &([u8; 16], u64, [u8; 32])) -> Retained {
    let Ok(txn) = vault.store.env.read_txn() else {
        return Retained::Unusable;
    };
    match RETAINED.get(&vault.store, &txn, key) {
        Ok(None) => Retained::Absent,
        Ok(Some(value)) => decode(key, &value).map_or(Retained::Unusable, |(facts, event_ref)| {
            Retained::Same(facts, event_ref)
        }),
        Err(_) => Retained::Unusable,
    }
}

fn decode(
    key: &([u8; 16], u64, [u8; 32]),
    value: &[u8; RETAINED_LEN],
) -> Option<(CampaignLegFacts, EntityId)> {
    if value[0] != RETAINED_VERSION {
        return None;
    }
    let id = |at: usize| -> Option<EntityId> {
        EntityId::from_bytes(value.get(at..at + 16)?.try_into().ok()?).ok()
    };
    let facts = CampaignLegFacts {
        query_ref: id(1)?,
        campaign_ref: id(17)?,
        entity_ref: id(33)?,
        epoch: u64::from_be_bytes(value.get(49..57)?.try_into().ok()?),
        program_ref: id(57)?,
        step_ref: id(73)?,
        consequence_id: key.0,
        call_seq: key.1,
        payload_digest: value.get(89..121)?.try_into().ok()?,
    };
    // The sender at 121 is named by the key's request digest too.
    Some((facts, id(137)?))
}

/// Retains `facts` (with its sender and the event row it is asked under)
/// under `key`, in a writer of its own. `false` when it did not write (the
/// erase fence skipped it, or the write failed): that is logged and the call
/// goes on.
fn keep(
    vault: &Vault,
    key: &([u8; 16], u64, [u8; 32]),
    facts: &CampaignLegFacts,
    sender_ref: EntityId,
    event_ref: EntityId,
) -> bool {
    let epoch = facts.epoch.to_be_bytes();
    let mut value = [0_u8; RETAINED_LEN];
    value[0] = RETAINED_VERSION;
    let mut at = 1;
    let parts: [&[u8]; 9] = [
        facts.query_ref.as_bytes(),
        facts.campaign_ref.as_bytes(),
        facts.entity_ref.as_bytes(),
        &epoch,
        facts.program_ref.as_bytes(),
        facts.step_ref.as_bytes(),
        &facts.payload_digest,
        sender_ref.as_bytes(),
        event_ref.as_bytes(),
    ];
    for part in parts {
        value[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    let kept = vault.try_with_write_txn(|wtxn| -> crate::error::Result<bool> {
        // FIX 6835 P1: this writer opens after the leg prepared its rows, so
        // an erase of the call or of any id the retained request names may
        // have committed in between and already dropped it. Fence the put:
        // an erased ledger call leaves its erased row behind the attempt
        // index, and an erased id leaves a hard-delete marker. Skip the
        // retention when either shows; the call goes on from its live rows.
        let attempt_id = AttemptId::from_bytes(&key.0)?;
        if crate::outbound_intent_ledger::call_row_erased_in_txn(vault, wtxn, attempt_id, key.1)? {
            return Ok(false);
        }
        for id in [
            &facts.query_ref,
            &facts.campaign_ref,
            &facts.entity_ref,
            &facts.program_ref,
            &facts.step_ref,
            &sender_ref,
            &event_ref,
        ] {
            if vault.local_hard_delete_marker_exists_in_txn(wtxn, id)? {
                return Ok(false);
            }
        }
        RETAINED.put(&vault.store, wtxn, key, &value)?;
        Ok(true)
    });
    match kept {
        Ok(true) => true,
        Ok(false) => false,
        Err(error) => {
            tracing::warn!(
                reason = "campaign_enrollment_request_not_retained",
                consequence = %crate::entity_id::bytes_to_hex_lower(&key.0),
                call_seq = key.1,
                %error,
                "a campaign enrollment's prepared outbound request was not retained; \
                 the call goes on from its live rows"
            );
            false
        }
    }
}

/// The typed key one raw retained row names, for the erases that scan the
/// table raw so a row that does not decode is passed over, never an error.
fn retained_key(bytes: &[u8]) -> Option<([u8; 16], u64, [u8; 32])> {
    if bytes.len() != 16 + 8 + 32 {
        return None;
    }
    Some((
        bytes.get(..16)?.try_into().ok()?,
        u64::from_be_bytes(bytes.get(16..24)?.try_into().ok()?),
        bytes.get(24..)?.try_into().ok()?,
    ))
}

/// FIX 6835: drops every retained request `drop` names, in `wtxn`, after the
/// scan: a retained press authorizes nothing once the Gate's own rows for
/// what it names are erased, and a missing one only re-asks. A row that does
/// not decode is passed over: nothing reads it back as a live request, and
/// the damage report owns it, as in the ledger scrub.
fn drop_retained_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    drop: impl Fn(&([u8; 16], u64, [u8; 32]), &CampaignLegFacts, &EntityId, &EntityId) -> bool,
) -> crate::error::Result<()> {
    let mut dropped = Vec::new();
    for row in RETAINED.iter_raw_from(&vault.store, wtxn, &[])? {
        let (key, value) = row?;
        let Some(key) = retained_key(&key) else {
            continue;
        };
        let Ok(value) = <[u8; RETAINED_LEN]>::try_from(value.as_slice()) else {
            continue;
        };
        let Some((facts, event_ref)) = decode(&key, &value) else {
            continue;
        };
        let Some(sender_ref) = value
            .get(121..137)
            .and_then(|bytes| bytes.try_into().ok())
            .and_then(|bytes| EntityId::from_bytes(bytes).ok())
        else {
            continue;
        };
        if drop(&key, &facts, &sender_ref, &event_ref) {
            dropped.push(key);
        }
    }
    for key in dropped {
        RETAINED.delete(&vault.store, wtxn, &key)?;
    }
    Ok(())
}

/// FIX 6835: this table's actor scrub (FIX 3520): an erase of `actor` drops
/// every retained request naming it — as sender, recipient, query,
/// campaign, program, step, event row, or the consequence in its key — in
/// the erase's writer.
///
/// # Errors
/// A storage failure.
pub(crate) fn erase_enrollment_ask_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::error::Result<()> {
    drop_retained_in_txn(vault, wtxn, |key, facts, sender_ref, event_ref| {
        key.0 == *actor.as_bytes()
            || *sender_ref == *actor
            || facts.query_ref == *actor
            || facts.campaign_ref == *actor
            || facts.entity_ref == *actor
            || facts.program_ref == *actor
            || facts.step_ref == *actor
            || *event_ref == *actor
    })
}

/// FIX 6835: drops every retained request of one consequence's call, in the
/// per-call erase's writer: that erase owns the whole call, so the drop is
/// by key prefix and does not decode.
///
/// # Errors
/// A storage failure.
pub(crate) fn drop_enrollment_asks_of_call_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt_id: AttemptId,
    call_seq: u64,
) -> crate::error::Result<()> {
    let mut prefix = attempt_id.as_bytes().to_vec();
    prefix.extend_from_slice(&call_seq.to_be_bytes());
    RETAINED.delete_from(&vault.store, wtxn, &prefix)?;
    Ok(())
}
