//! UID-first passport index and feed diff (CAL-02, ONE-1784).
//!
//! One live `calendar.passport` claim per `(system × UID)`, attached to an
//! EVENT, with a UID-first `vault_meta` index as the cross-calendar lookup
//! accelerator. The claim value is the synced truth; the index is node-local
//! cache — exactly the [`crate::comm`] `PARTY_INDEX_PREFIX` / `resolve_party`
//! discipline, including repair-on-miss from synced truth.
//!
//! The passport *value* type ([`CalendarPassportValue`]) and its wire codec
//! live in CAL-00's [`super::claims`]; this module imports them and owns only
//! the index and the diff machinery. Value maps are written through the same
//! key set [`super::claims::decode_passport_value`] reads — the write-door
//! validator chain rejects any drift fail-closed, so a misspelled key can
//! never land silently.
//!
//! Multi-source law (verbatim from the ratified seam): feed-absence
//! cancellation applies ONLY when every live inbound passport for the EVENT
//! reports absence; a single-source absence supersedes only that passport,
//! never the EVENT status.

use sha2::{Digest, Sha256};

use super::CalendarError;
use super::claims::{
    CalendarPassportPresence, CalendarPassportValue, PREDICATE_CALENDAR_PASSPORT,
    decode_passport_value,
};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::vault::Vault;

/// `vault_meta` key prefix for the UID → EVENT index. Node-local cache; the
/// live passport claims are the synced truth.
pub const CALENDAR_PASSPORT_INDEX_PREFIX: &[u8] = b"calendar.passport.v1:";

/// The per-`(system × UID)` diff verdict for one feed row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassportDecision {
    /// No live passport anywhere carries this UID: mint a new EVENT.
    CreateEvent,
    /// The UID already names an EVENT through another source's passport;
    /// attach this source's passport to it.
    AttachToExisting {
        /// The EVENT the UID index resolved.
        event_ref: EntityId,
    },
    /// Same SEQUENCE and same content hash (or an older SEQUENCE replay):
    /// nothing moves.
    SkipUnchanged {
        /// The EVENT the UID index resolved.
        event_ref: EntityId,
    },
    /// Higher SEQUENCE, same-SEQUENCE content drift, or re-appearance of a
    /// source whose passport was marked absent: supersede the passport.
    UpdateExisting {
        /// The EVENT the UID index resolved.
        event_ref: EntityId,
    },
    /// A complete feed omitted a UID this source previously reported:
    /// supersede only that source's passport with `presence: absent`.
    MarkSourceAbsent {
        /// The EVENT the UID index resolved.
        event_ref: EntityId,
    },
}

/// Resolves one VEVENT UID to its EVENT through the index, repairing the
/// node-local shortcut from synced truth on a stale or missing hit.
///
/// Like [`crate::comm`]'s party resolution, an index miss means "look again",
/// never "absent": the scan walks live passport claims so an EVENT that
/// synced in on another node is still found rather than twinned.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures.
pub fn resolve_event_by_uid(vault: &Vault, uid: &str) -> Result<Option<EntityId>, CalendarError> {
    let key = passport_index_key(uid);
    let indexed = {
        let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        vault
            .store
            .vault_meta
            .get(&rtxn, &key)?
            .map(|raw| raw.to_vec())
    };
    if let Some(raw) = indexed {
        let bytes: [u8; 16] = raw
            .as_slice()
            .try_into()
            .map_err(|_| ingest("passport index row is not an entity id"))?;
        let id = EntityId::from_bytes(bytes)
            .map_err(|_| ingest("passport index row is not an entity id"))?;
        if vault.get_entity_type(&id)? == Some(ENTITY_TYPE_EVENT)
            && live_passport_for_uid(vault, &id, uid)?.is_some()
        {
            return Ok(Some(id));
        }
    }

    // Miss or stale shortcut: synced truth is the set of live passport claims.
    let event_ids = {
        let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let mut ids = Vec::new();
        for entry in vault
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_EVENT])?
        {
            let (key, _) = entry?;
            ids.push(crate::vault::entity_id_from_type_index_key(&key)?);
        }
        ids
    };
    let mut found: Option<EntityId> = None;
    for event_ref in event_ids {
        if live_passport_for_uid(vault, &event_ref, uid)?.is_some()
            && found.is_none_or(|current| event_ref.as_bytes() < current.as_bytes())
        {
            // Lexicographically smallest id, so every node converges on the
            // same EVENT when twins exist — the comm.rs convergence rule.
            found = Some(event_ref);
        }
    }
    if let Some(event_ref) = found {
        index_passport_uid(vault, uid, &event_ref)?;
    }
    Ok(found)
}

/// Classifies one feed row against the current passport state.
///
/// The diff is SEQUENCE-first: a higher SEQUENCE updates; the same SEQUENCE
/// with a drifted content hash updates; the same SEQUENCE with the same hash
/// skips; an *older* SEQUENCE is a stale replay and also skips — a lagging
/// source never regresses passport state. A live passport whose source marked
/// it absent updates back to live on any re-appearance.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures.
pub fn classify_passport(
    vault: &Vault,
    system: &str,
    uid: &str,
    sequence: u32,
    content_hash: [u8; 32],
) -> Result<PassportDecision, CalendarError> {
    let Some(event_ref) = resolve_event_by_uid(vault, uid)? else {
        return Ok(PassportDecision::CreateEvent);
    };
    let Some((_, current)) = live_passport_for(vault, &event_ref, system, uid)? else {
        return Ok(PassportDecision::AttachToExisting { event_ref });
    };
    if current.presence == CalendarPassportPresence::Absent
        || sequence > current.last_sequence
        || (sequence == current.last_sequence && content_hash != current.content_hash)
    {
        return Ok(PassportDecision::UpdateExisting { event_ref });
    }
    Ok(PassportDecision::SkipUnchanged { event_ref })
}

/// Keeps one live `calendar.passport` claim per `(system × UID)`: admits
/// `next` through the imported-evidence Gate door, then supersedes exactly
/// the live claim whose decoded key is `(next.system, next.uid)` — never a
/// sibling source's passport on the same EVENT.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] when no live passport carries
/// `(next.system, next.uid)`, or on store/gate failures.
pub fn supersede_calendar_passport(
    vault: &Vault,
    event_ref: EntityId,
    next: &CalendarPassportValue,
    recorded_at: u64,
) -> Result<(), CalendarError> {
    let Some((old_id, _)) = live_passport_for(vault, &event_ref, &next.system, &next.uid)? else {
        return Err(ingest("no live passport carries this (system, uid) pair"));
    };
    let new_id = super::ingest::admit_calendar_import_claim(
        vault,
        &event_ref,
        PREDICATE_CALENDAR_PASSPORT,
        encode_passport_value(next),
        &next.uid,
        recorded_at,
    )?;
    vault.supersede_claim(&new_id, &old_id, recorded_at)?;
    Ok(())
}

/// Points the UID index at `event_ref`. Called when a passport is minted;
/// resolution repairs it on every other path.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store failure.
pub fn index_passport_uid(
    vault: &Vault,
    uid: &str,
    event_ref: &EntityId,
) -> Result<(), CalendarError> {
    let key = passport_index_key(uid);
    vault.try_with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, &key, event_ref.as_bytes())?;
        Ok::<_, crate::Error>(())
    })?;
    Ok(())
}

/// Every live passport claim on one EVENT, as `(claim id, decoded value)`.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures.
pub fn live_passports_for_event(
    vault: &Vault,
    event_ref: &EntityId,
) -> Result<Vec<(EntityId, CalendarPassportValue)>, CalendarError> {
    let mut out = Vec::new();
    for claim_id in vault.claims_for_subject(event_ref)? {
        let Some(body) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CALENDAR_PASSPORT
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let value = decode_passport_value(&body.value)
            .map_err(|_| ingest("stored passport claim did not decode"))?;
        out.push((claim_id, value));
    }
    Ok(out)
}

/// The live passport claim on `event_ref` for exactly `(system, uid)`.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures.
pub fn live_passport_for(
    vault: &Vault,
    event_ref: &EntityId,
    system: &str,
    uid: &str,
) -> Result<Option<(EntityId, CalendarPassportValue)>, CalendarError> {
    for (claim_id, value) in live_passports_for_event(vault, event_ref)? {
        if value.system == system && value.uid == uid {
            return Ok(Some((claim_id, value)));
        }
    }
    Ok(None)
}

/// The multi-source law's premise: at least one live inbound-bearing passport
/// exists for the EVENT, and every one of them reports absence. Outbound-only
/// passports never vote ([`CalendarPassportDirection::is_inbound_bearing`]),
/// and an EVENT with no inbound passport at all is never absence-cancelled —
/// zero votes is no evidence, not unanimity.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures.
pub fn all_live_inbound_passports_absent(
    vault: &Vault,
    event_ref: &EntityId,
) -> Result<bool, CalendarError> {
    let mut inbound = 0_usize;
    let mut absent = 0_usize;
    for (_, value) in live_passports_for_event(vault, event_ref)? {
        if value.direction.is_inbound_bearing() {
            inbound += 1;
            if value.presence == CalendarPassportPresence::Absent {
                absent += 1;
            }
        }
    }
    Ok(inbound > 0 && inbound == absent)
}

/// The live passport claim on `event_ref` carrying `uid` from any system.
fn live_passport_for_uid(
    vault: &Vault,
    event_ref: &EntityId,
    uid: &str,
) -> Result<Option<(EntityId, CalendarPassportValue)>, CalendarError> {
    for (claim_id, value) in live_passports_for_event(vault, event_ref)? {
        if value.uid == uid {
            return Ok(Some((claim_id, value)));
        }
    }
    Ok(None)
}

/// Index key: prefix + SHA-256 of the UID, mirroring `comm.rs::party_index_key`.
fn passport_index_key(uid: &str) -> Vec<u8> {
    let digest = Sha256::digest(uid.as_bytes());
    let mut key = Vec::with_capacity(CALENDAR_PASSPORT_INDEX_PREFIX.len() + digest.len());
    key.extend_from_slice(CALENDAR_PASSPORT_INDEX_PREFIX);
    key.extend_from_slice(&digest);
    key
}

/// The `calendar.passport` wire map, keyed exactly as
/// [`super::claims::decode_passport_value`] reads. CAL-00 owns the codec; the
/// write-door validator chain rejects any drift fail-closed.
pub(crate) fn encode_passport_value(value: &CalendarPassportValue) -> rmpv::Value {
    rmpv::Value::Map(vec![
        (
            rmpv::Value::from("system"),
            rmpv::Value::from(value.system.as_str()),
        ),
        (
            rmpv::Value::from("uid"),
            rmpv::Value::from(value.uid.as_str()),
        ),
        (
            rmpv::Value::from("last_sequence"),
            rmpv::Value::from(value.last_sequence),
        ),
        (
            rmpv::Value::from("content_hash"),
            rmpv::Value::Binary(value.content_hash.to_vec()),
        ),
        (
            rmpv::Value::from("direction"),
            rmpv::Value::from(value.direction.as_str()),
        ),
        (
            rmpv::Value::from("last_seen_at"),
            rmpv::Value::from(value.last_seen_at),
        ),
        (
            rmpv::Value::from("presence"),
            rmpv::Value::from(value.presence.as_str()),
        ),
    ])
}

fn ingest(reason: &'static str) -> CalendarError {
    CalendarError::IcsIngest {
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::claims::CalendarPassportDirection;
    use super::*;
    use crate::calendar::test_support::open_calendar_vault;

    fn passport(system: &str, uid: &str, sequence: u32) -> CalendarPassportValue {
        CalendarPassportValue {
            system: system.to_owned(),
            uid: uid.to_owned(),
            last_sequence: sequence,
            content_hash: [7_u8; 32],
            direction: CalendarPassportDirection::Inbound,
            last_seen_at: 1_754_400_000,
            presence: CalendarPassportPresence::Live,
        }
    }

    #[test]
    fn index_key_is_prefixed_sha256_of_the_uid() {
        let key = passport_index_key("uid-1@example.com");
        assert!(key.starts_with(CALENDAR_PASSPORT_INDEX_PREFIX));
        assert_eq!(key.len(), CALENDAR_PASSPORT_INDEX_PREFIX.len() + 32);
        assert_ne!(key, passport_index_key("uid-2@example.com"));
        assert_eq!(key, passport_index_key("uid-1@example.com"));
    }

    #[test]
    fn encode_passport_value_matches_the_cal00_codec() {
        let value = passport("google", "uid-1@example.com", 3);
        let decoded = decode_passport_value(&encode_passport_value(&value)).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn resolve_event_by_uid_scans_synced_truth_on_index_miss() {
        let (_dir, vault) = open_calendar_vault();
        let event = crate::test_util::entity(0x61);
        vault
            .put_entity(
                &event,
                ENTITY_TYPE_EVENT,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                b"event",
            )
            .expect("put event");
        let claim_id = crate::test_util::entity(0x62);
        vault
            .put_claim(
                &claim_id,
                &crate::claim::ClaimBody::new(
                    PREDICATE_CALENDAR_PASSPORT,
                    crate::claim::ClaimSubject::Entity(event),
                    encode_passport_value(&passport("google", "uid-1@example.com", 3)),
                    1.0,
                    crate::claim::ClaimApprovalStatus::Approved,
                    ClaimLifecycleStatus::Active,
                ),
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
            )
            .expect("put passport claim");

        // No index row at all: resolution scans the live claims, finds the
        // EVENT, and repairs the shortcut.
        let resolved = resolve_event_by_uid(&vault, "uid-1@example.com").expect("resolve");
        assert_eq!(resolved, Some(event));
        let with_index = resolve_event_by_uid(&vault, "uid-1@example.com").expect("resolve");
        assert_eq!(with_index, Some(event));
        assert_eq!(
            resolve_event_by_uid(&vault, "uid-absent@example.com").expect("resolve"),
            None
        );
    }
}
