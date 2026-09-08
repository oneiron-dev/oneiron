//! Deterministic claim ids, idempotent claim writes and standing-state matching.

use rmpv::Value;

use super::claims::{
    COMM_SCHEMA_VERSION, CommClaim, CommClaimValue, CommError, CommResult, KEY_CHANNEL_CLASS,
    KEY_OCCURRED_AT, KEY_OPTED_OUT, KEY_PARTY_REF, KEY_SCHEMA_VERSION,
    PREDICATE_COMM_THREAD_MEMBER, is_comm_claim_predicate,
};
use super::parties::resolve_party;
use super::records::encode_value;
use super::thread_membership::{active_thread_refs_in_txn, matching_thread_memberships_in_txn};
use crate::Vault;
use crate::affect::Vad;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::encode_claim_body;
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::Error;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::vault::CLAIM_OF_DEFAULT_WEIGHT;

/// Domain separator for projector-derived `comm.*` CLAIM ids. A deterministic
/// projector derives its row ids from its inputs, so replaying one source event
/// — or projecting it independently on two devices — converges on ONE physical
/// row instead of racing two random ids into the same conflict key.
const PROJECTED_COMM_CLAIM_ID_DOMAIN: &[u8] = b"oneiron.comm.projected_claim.v1\0";

/// Canonical conflict key for one projected `comm.*` value: the tuple that
/// makes two claims the SAME standing-state slot. Length-prefixed so
/// `("ab", "c")` and `("a", "bc")` can never hash alike.
pub(super) fn projected_comm_conflict_key(value: &CommClaimValue) -> Vec<u8> {
    let mut key = Vec::new();
    let mut push = |bytes: &[u8]| {
        key.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        key.extend_from_slice(bytes);
    };
    match value {
        // An elided channel is its OWN slot, not a wildcard over the others:
        // the party-wide head and a channel-scoped head are different standing
        // facts and must never collide. No channel class can be empty
        // (`validate_channel_class` refuses blanks), so the empty component is
        // unambiguously "every channel".
        CommClaimValue::OptOut {
            party_ref,
            channel_class,
            ..
        } => {
            push(party_ref.as_bytes());
            push(channel_class.as_deref().unwrap_or_default().as_bytes());
        }
        CommClaimValue::LastTouch {
            party_ref,
            channel_class,
            ..
        }
        | CommClaimValue::ReachableVia {
            party_ref,
            channel_class,
            ..
        } => {
            push(party_ref.as_bytes());
            push(channel_class.as_bytes());
        }
        CommClaimValue::ThreadMember {
            party_ref,
            thread_ref,
            ..
        } => {
            push(party_ref.as_bytes());
            push(thread_ref.as_bytes());
        }
        // No projector rule mints an override — it is a human-ruled verb — so
        // this arm exists for totality. The key still names the whole binding,
        // so it could never merge two distinct owner decisions.
        CommClaimValue::SendOverride {
            party_ref,
            channel_class,
            scope,
            send_ref,
            ..
        } => {
            push(party_ref.as_bytes());
            push(channel_class.as_deref().unwrap_or_default().as_bytes());
            push(scope.as_str().as_bytes());
            push(send_ref.as_deref().unwrap_or_default().as_bytes());
        }
    }
    key
}

/// Derives the deterministic CLAIM id for one projector-created `comm.*` claim
/// from `(source event, predicate, conflict key)`. Version/variant nibbles are
/// stamped exactly as [`crate::outbound::connector_actor_id`] so the result is
/// a well-formed v7-shaped id.
pub(super) fn projected_comm_claim_id(
    source_event_id: EntityId,
    value: &CommClaimValue,
) -> CommResult<EntityId> {
    let predicate = value.claim_body().predicate;
    let conflict_key = projected_comm_conflict_key(value);
    let mut hash = blake3::Hasher::new();
    hash.update(PROJECTED_COMM_CLAIM_ID_DOMAIN);
    hash.update(source_event_id.as_bytes());
    hash.update(&(predicate.len() as u64).to_le_bytes());
    hash.update(predicate.as_bytes());
    hash.update(&(conflict_key.len() as u64).to_le_bytes());
    hash.update(&conflict_key);
    let mut bytes = [0_u8; ENTITY_ID_LEN];
    bytes.copy_from_slice(&hash.finalize().as_bytes()[..ENTITY_ID_LEN]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId::from_bytes(bytes).map_err(CommError::from)
}

// `CommClaimValue::party_ref` sits beside its only callers, the projected
// claim writes below; the rest of the impl stays in `claims`.
impl CommClaimValue {
    fn party_ref(&self) -> EntityId {
        match self {
            Self::OptOut { party_ref, .. }
            | Self::SendOverride { party_ref, .. }
            | Self::LastTouch { party_ref, .. }
            | Self::ThreadMember { party_ref, .. }
            | Self::ReachableVia { party_ref, .. } => *party_ref,
        }
    }
}

/// Writes one projector-created `comm.*` claim at its derived id.
///
/// Returns `(id, minted)`. A resident row at the derived id is recognized as a
/// replay — skip the write, `minted = false` — only when it is BYTE-IDENTICAL
/// to the body this projection authors AND is still reachable from the party
/// through a live `claim_of` edge. Anything else is a deterministic-id
/// collision and fails closed rather than overwriting the resident row.
///
/// Both halves are load-bearing, because `minted = false` is exactly what tells
/// [`project_event`] to stamp the source COMM_RECORD `projected`:
///
/// * Byte identity, not typed `CommClaimValue` equality. The encoded body
///   carries the whole governance envelope — `appr`, `life`, and the
///   elided-when-false `stale` marker all live in those bytes, and
///   [`CommClaimValue::claim_body`] pins them to `auto` / `active` / absent. A
///   rejected, supplanted, retracted, or staleness-marked row therefore cannot
///   pass as "already projected" the way decoded-value equality let it, which
///   would have retired the source event against a row that no longer says what
///   the projector meant — silently dropping standing state a `STOP` depends on.
/// * The live edge. The body names its subject, but only the `claim_of` edge
///   makes the claim reachable from the party, and every comm reader walks that
///   edge. A row carrying the right bytes with no live edge is standing state
///   nothing can see.
pub(super) fn put_projected_comm_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    source_event_id: EntityId,
    value: &CommClaimValue,
    occurred_at: u64,
) -> CommResult<(EntityId, bool)> {
    let id = projected_comm_claim_id(source_event_id, value)?;
    if let Some(raw) = vault.store.entities.get(&*wtxn, id.as_bytes())? {
        let header = EntityMetadataHeader::parse(&raw).ok_or(CommError::InvalidRecord)?;
        let projected_body = encode_claim_body(&value.claim_body())?;
        if header.entity_type != ENTITY_TYPE_CLAIM
            || raw[ENTITY_METADATA_HEADER_LEN..] != projected_body[..]
            || !vault
                .claims_for_subject_in_txn(&*wtxn, &value.party_ref())?
                .contains(&id)
        {
            return Err(CommError::InvalidRecord);
        }
        return Ok((id, false));
    }
    put_comm_claim_with_id_in_txn(vault, wtxn, id, value, occurred_at)?;
    Ok((id, true))
}

pub(super) fn put_comm_claim_with_id_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    value: &CommClaimValue,
    occurred_at: u64,
) -> CommResult<EntityId> {
    put_comm_claim_with_id_in_txn_inner(vault, wtxn, id, value, occurred_at, false)
}

/// [`put_comm_claim_with_id_in_txn`] on the ENGINE-OWNED setting, for the
/// projection a contact writer authors on the party's behalf (ONE-1752).
///
/// The contact door already validated and authorized that write; re-asking the
/// public criticality ladder here would turn one recorded counterparty fact
/// into an owner review inside somebody else's transaction, and a refusal would
/// roll back the contact write that the ladder never meant to question. Body
/// validation and the source-trust check are unchanged.
pub(super) fn put_engine_owned_comm_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    value: &CommClaimValue,
    occurred_at: u64,
) -> CommResult<EntityId> {
    put_comm_claim_with_id_in_txn_inner(vault, wtxn, id, value, occurred_at, true)
}

fn put_comm_claim_with_id_in_txn_inner(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    value: &CommClaimValue,
    occurred_at: u64,
    engine_owned: bool,
) -> CommResult<EntityId> {
    let body = value.claim_body();
    let data = encode_claim_body(&body)?;
    let subject = value.party_ref();
    // A comm.* claim's subject must be a PERSON party. A replicated event can
    // name any existing entity as party_ref; a subject that is absent or not a
    // PERSON is rejected so the projector fail-soft skips it (see
    // run_comm_projector) rather than attaching communication state to an
    // arbitrary TASK/CLAIM/etc. entity outside the party-indexed contact APIs.
    let subject_is_person = vault
        .store
        .entities
        .get(&*wtxn, subject.as_bytes())?
        .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
        == Some(ENTITY_TYPE_PERSON);
    if !subject_is_person {
        return Err(CommError::Engine(Error::EntityNotFound));
    }
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![
            BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: occurred_at,
                    end: occurred_at,
                },
                learned_at: crate::unix_seconds_now(),
                data,
                allow_maintenance: false,
                allow_reserved_predicate: engine_owned,
                hub_sync_imported: false,
            },
            BatchOp::Edge {
                src: id,
                kind: EdgeKind::ClaimOf,
                tgt: subject,
                weight: CLAIM_OF_DEFAULT_WEIGHT,
                vad: Vad::NEUTRAL,
            },
        ],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    Ok(id)
}

pub(super) fn count_comm_claims(
    vault: &Vault,
    predicate: &str,
    party: &str,
    channel_class: Option<&str>,
    thread_ref: Option<&str>,
    active_only: bool,
) -> CommResult<usize> {
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Ok(0);
    };
    let rtxn = vault.store.env.read_txn()?;
    Ok(matching_claims_in_txn(
        vault,
        &rtxn,
        party_ref,
        predicate,
        channel_class,
        thread_ref,
        active_only,
    )?
    .len())
}

pub(super) fn matching_claims_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: EntityId,
    predicate: &str,
    channel_class: Option<&str>,
    thread_ref: Option<&str>,
    active_only: bool,
) -> CommResult<Vec<(EntityId, CommClaim)>> {
    if predicate == PREDICATE_COMM_THREAD_MEMBER {
        return matching_thread_memberships_in_txn(vault, rtxn, party_ref, thread_ref, active_only);
    }
    let mut matches = Vec::new();
    for claim_id in vault.claims_for_subject_in_txn(rtxn, &party_ref)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        if body.predicate != predicate || !is_comm_claim_predicate(&body.predicate) {
            continue;
        }
        let claim = CommClaim::from_claim_body(&body)?;
        if active_only && !claim.is_standing() {
            continue;
        }
        let key_matches = match &claim.value {
            // SLOT lookup, not fold matching: a party-wide head answers a
            // `None` query and never a channel-scoped one, so the two heads
            // stay separately addressable for supersession. Whether a
            // party-wide head APPLIES to a channel is the fold's question, and
            // `StandingOptOutHead::matches_channel` answers it.
            CommClaimValue::OptOut {
                channel_class: candidate,
                ..
            }
            | CommClaimValue::SendOverride {
                channel_class: candidate,
                ..
            } => channel_class == candidate.as_deref(),
            CommClaimValue::LastTouch {
                channel_class: candidate,
                ..
            }
            | CommClaimValue::ReachableVia {
                channel_class: candidate,
                ..
            } => channel_class == Some(candidate.as_str()),
            CommClaimValue::ThreadMember {
                thread_ref: candidate,
                ..
            } => thread_ref == Some(candidate.as_str()),
        };
        if key_matches {
            matches.push((claim_id, claim));
        }
    }
    Ok(matches)
}

pub(super) fn require_at_most_one(matches: &[(EntityId, CommClaim)]) -> CommResult<()> {
    if matches.len() > 1 {
        Err(CommError::InvalidRecord)
    } else {
        Ok(())
    }
}

pub(super) fn latest_claim_transition_boundary(matches: &[(EntityId, CommClaim)]) -> Option<u64> {
    matches
        .iter()
        .filter_map(|(_, claim)| {
            if claim.is_standing() {
                claim.valid_from
            } else {
                claim.valid_to
            }
        })
        .max()
}

pub(super) fn build_contact_view_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: EntityId,
) -> CommResult<(Vec<u8>, u64)> {
    let mut last_touch = Vec::new();
    let mut opt_out = Vec::new();
    let threads = active_thread_refs_in_txn(vault, rtxn, party_ref)?;
    for claim_id in vault.claims_for_subject_in_txn(rtxn, &party_ref)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        if !is_comm_claim_predicate(&body.predicate) {
            continue;
        }
        let claim = CommClaim::from_claim_body(&body)?;
        if !claim.is_standing() {
            continue;
        }
        match claim.value {
            CommClaimValue::LastTouch {
                channel_class,
                occurred_at,
                ..
            } => last_touch.push((channel_class, occurred_at)),
            CommClaimValue::OptOut {
                channel_class,
                occurred_at,
                ..
            } => opt_out.push((channel_class, occurred_at)),
            CommClaimValue::ThreadMember { .. } => {}
            // Reachability carries no view entry, and an override is an owner
            // DECISION about sending rather than contact state — the lens
            // reports what the counterparty said, not what the owner ruled.
            CommClaimValue::ReachableVia { .. } | CommClaimValue::SendOverride { .. } => {}
        }
    }
    last_touch.sort();
    opt_out.sort();
    let entry_count = u64::try_from(last_touch.len() + opt_out.len() + threads.len())
        .map_err(|_| CommError::InvalidRecord)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMM_SCHEMA_VERSION),
        ),
        (Value::from(KEY_PARTY_REF), Value::from(party_ref.to_hex())),
        (Value::from("first_touch"), Value::Nil),
        (
            Value::from("last_touch"),
            Value::Array(
                last_touch
                    .iter()
                    .map(|(channel, occurred_at)| {
                        Value::Map(vec![
                            (
                                Value::from(KEY_CHANNEL_CLASS),
                                Value::from(channel.as_str()),
                            ),
                            (Value::from(KEY_OCCURRED_AT), Value::from(*occurred_at)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            Value::from("opt_out"),
            Value::Array(
                opt_out
                    .iter()
                    .map(|(channel, occurred_at)| {
                        // The lens mirrors the head: a party-wide head has no
                        // channel, so the entry carries none either rather than
                        // inventing a class the head never named.
                        let mut entry = Vec::new();
                        if let Some(channel) = channel {
                            entry.push((
                                Value::from(KEY_CHANNEL_CLASS),
                                Value::from(channel.as_str()),
                            ));
                        }
                        entry.push((Value::from(KEY_OPTED_OUT), Value::Boolean(true)));
                        entry.push((Value::from(KEY_OCCURRED_AT), Value::from(*occurred_at)));
                        Value::Map(entry)
                    })
                    .collect(),
            ),
        ),
        (
            Value::from("threads"),
            Value::Array(
                threads
                    .iter()
                    .map(|thread| Value::from(thread.as_str()))
                    .collect(),
            ),
        ),
    ]);
    Ok((encode_value(&value)?, entry_count))
}
