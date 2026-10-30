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
//! key set `super::claims::decode_passport_value` reads — the write-door
//! validator chain rejects any drift fail-closed, so a misspelled key can
//! never land silently.
//!
//! Multi-source law (verbatim from the ratified seam): feed-absence
//! cancellation applies ONLY when every live inbound passport for the EVENT
//! reports absence; a single-source absence supersedes only that passport,
//! never the EVENT status.

use crate::ports::EntityStoreRead;
use sha2::Digest;
use sha2::Sha256;

use super::CalendarError;
use super::claims::{
    CalendarPassportPresence, CalendarPassportValue, PREDICATE_CALENDAR_PASSPORT,
    decode_passport_value,
};
use crate::claim::{ClaimLifecycleStatus, ClaimSubject, claim_surfaceable};
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::side_table::{self, Raw, SideTable};
use crate::vault::Vault;

/// UID-to-EVENT lookup cache. Key: `sha256(uid)`. Node-local cache; the live
/// passport claims are the synced truth.
const PASSPORT_INDEX: SideTable<[u8; 32], EntityId, Raw> =
    SideTable::new(&side_table::CALENDAR_PASSPORT_UID_INDEX);

/// The admitted passports on `event`: surfaceable heads about the EVENT itself.
///
/// This is the revision-authority read. A writer derives a passport's next UID
/// and SEQUENCE from these and supersedes only these, so a pending, rejected
/// or stale proposal can neither block a revision nor steer it. The ingest
/// diff keeps the approval-blind [`live_passports_for_event`], because the
/// import gate files its own passports pending review.
pub(crate) fn admitted_passports_for_event_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
) -> Result<Vec<(EntityId, CalendarPassportValue)>, CalendarError> {
    let mut values = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, event)? {
        if let Some(body) = vault.get_claim_in_txn(txn, &id)?
            && body.predicate == PREDICATE_CALENDAR_PASSPORT
            && body.subject == ClaimSubject::Entity(*event)
            && claim_surfaceable(&body)
            && crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, &id)?
        {
            values.push((id, decode_passport_value(&body.value)?));
        }
    }
    Ok(values)
}

/// The one admitted passport on `event` for exactly `(system, uid)`. Two
/// admitted heads for one key are refused, never picked by scan order.
pub(crate) fn admitted_passport_for_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
    system: &str,
    uid: &str,
) -> Result<Option<(EntityId, CalendarPassportValue)>, CalendarError> {
    let mut matching = admitted_passports_for_event_in_txn(vault, txn, event)?
        .into_iter()
        .filter(|(_, value)| value.system == system && value.uid == uid);
    let found = matching.next();
    if matching.next().is_some() {
        return Err(ingest("competing live calendar passports"));
    }
    Ok(found)
}

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
/// This is the ingest diff's resolver, so a pending passport vouches for its
/// EVENT: the import gate files its own passports pending review. Only an
/// admitted passport repairs the index, though, because the first outbound
/// invite falls back to that shortcut (`event_ref_for_indexed_uid`).
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures.
pub fn resolve_event_by_uid(vault: &Vault, uid: &str) -> Result<Option<EntityId>, CalendarError> {
    resolve_uid(vault, uid, carries_live_uid, is_live_series_exception)
}

/// Resolves one UID to its EVENT through admitted passports only.
///
/// The authority form of [`resolve_event_by_uid`]: an index hit counts only
/// when an admitted passport on that EVENT carries the UID, and the scan reads
/// only admitted passports. So a pending, rejected or stale proposal never
/// picks the EVENT an outbound invite binds to.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures.
pub(crate) fn resolve_admitted_event_by_uid(
    vault: &Vault,
    uid: &str,
) -> Result<Option<EntityId>, CalendarError> {
    resolve_uid(
        vault,
        uid,
        carries_admitted_uid,
        is_admitted_series_exception,
    )
}

/// The shared resolver. `vouches` and `detached` read the same authority: a
/// passport that vouches for the UID and an exception claim that excludes a
/// detached instance are judged by one reader, so the two never disagree on
/// which claims count.
fn resolve_uid(
    vault: &Vault,
    uid: &str,
    vouches: fn(&Vault, &EntityId, &str) -> Result<bool, CalendarError>,
    detached: fn(&Vault, &EntityId) -> Result<bool, CalendarError>,
) -> Result<Option<EntityId>, CalendarError> {
    let digest = passport_digest(uid);
    let indexed = {
        let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        PASSPORT_INDEX.get(&vault.store, &rtxn, &digest)?
    };
    if let Some(id) = indexed
        && vault.get_entity_type(&id)? == Some(ENTITY_TYPE_EVENT)
        && !detached(vault, &id)?
        && vouches(vault, &id, uid)?
    {
        return Ok(Some(id));
    }

    // Miss or stale shortcut: synced truth is the set of live passport claims.
    let event_ids = {
        let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let mut ids = Vec::new();
        for entry in vault
            .store
            .port_entity_ids_by_type(&rtxn, ENTITY_TYPE_EVENT, None)?
        {
            ids.push(entry?);
        }
        ids
    };
    let mut found: Option<EntityId> = None;
    for event_ref in event_ids {
        if !detached(vault, &event_ref)?
            && vouches(vault, &event_ref, uid)?
            && found.is_none_or(|current| event_ref.as_bytes() < current.as_bytes())
        {
            // Lexicographically smallest id, so every node converges on the
            // same EVENT when twins exist — the comm.rs convergence rule.
            found = Some(event_ref);
        }
    }
    if let Some(event_ref) = found
        && carries_admitted_uid(vault, &event_ref, uid)?
    {
        index_passport_uid(vault, uid, &event_ref)?;
    }
    Ok(found)
}

/// Resolves an invite inside its publication snapshot, without repairing an
/// index through a second writer. Admitted synced truth wins; a first confirm
/// may fall back to the UID index written by the EVENT minter.
pub(crate) fn resolve_invite_event_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    uid: &str,
) -> Result<Option<EntityId>, CalendarError> {
    let indexed = PASSPORT_INDEX.get(&vault.store, txn, &passport_digest(uid))?;
    let mut found = None;
    for entry in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_EVENT, None)?
    {
        let event = entry?;
        let mut exception = false;
        for id in vault.claims_for_subject_in_txn(txn, &event)? {
            if vault.get_claim_in_txn(txn, &id)?.is_some_and(|body| {
                body.predicate == super::claims::PREDICATE_CALENDAR_SERIES_EXCEPTION
            }) {
                exception = true;
                break;
            }
        }
        if exception {
            continue;
        }
        if admitted_passports_for_event_in_txn(vault, txn, &event)?
            .iter()
            .any(|(_, passport)| passport.uid == uid)
        {
            if indexed == Some(event) {
                return Ok(Some(event));
            }
            if found.is_none_or(|current: EntityId| event.as_bytes() < current.as_bytes()) {
                found = Some(event);
            }
        }
    }
    if found.is_some() {
        return Ok(found);
    }
    if let Some(event) = indexed
        && vault.get_entity_type_in_txn(txn, &event)? == Some(ENTITY_TYPE_EVENT)
    {
        return Ok(Some(event));
    }
    Ok(None)
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
    classify_event_passport(vault, event_ref, system, uid, sequence, content_hash)
}

pub(in crate::calendar) fn classify_event_passport(
    vault: &Vault,
    event_ref: EntityId,
    system: &str,
    uid: &str,
    sequence: u32,
    content_hash: [u8; 32],
) -> Result<PassportDecision, CalendarError> {
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

/// Keeps one live `calendar.passport` claim per `(system × UID)`: supersedes
/// exactly the live claim whose decoded key is `(system, uid)` with the
/// already-admitted `new_id` — never a sibling source's passport on the same
/// EVENT.
///
/// Admission is the caller's half and runs FIRST, through CAL-09's
/// `screen_then_claim` hook and the imported-evidence Gate door
/// ([`super::ingest`] owns both); this helper owns only the scoped
/// replacement. There is deliberately no admission inside this module, so no
/// unscreened passport-movement path can exist.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] when no live passport carries `(system, uid)`,
/// or on store failures.
pub fn supersede_calendar_passport(
    vault: &Vault,
    event_ref: EntityId,
    system: &str,
    uid: &str,
    new_id: &EntityId,
    recorded_at: u64,
) -> Result<(), CalendarError> {
    let Some((old_id, _)) = live_passport_for(vault, &event_ref, system, uid)? else {
        return Err(ingest("no live passport carries this (system, uid) pair"));
    };
    vault.supersede_claim(new_id, &old_id, recorded_at)?;
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
    let digest = passport_digest(uid);
    vault.try_with_write_txn_grouped(|wtxn| {
        PASSPORT_INDEX.put(&vault.store, wtxn, &digest, event_ref)?;
        Ok::<_, crate::Error>(())
    })?;
    Ok(())
}

/// The EVENT the UID index currently points at, without requiring a live
/// passport to vouch for it.
///
/// [`resolve_event_by_uid`] deliberately treats an index row with no live
/// passport as stale — for the INGEST diff, a shortcut nothing confirms must
/// not resolve. The first outbound invite (CAL-04) is the one case where that
/// is inverted: the UID was minted with the EVENT and indexed there, and the
/// passport being about to exist is exactly what the caller is asking for. So
/// this reader answers the narrower question — "what does the index say, and is
/// it still an EVENT?" — and adds no second index. Its answer stays the
/// minter's, because no resolver repairs the index from a pending passport.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store failures or a corrupt index row.
pub(super) fn event_ref_for_indexed_uid(
    vault: &Vault,
    uid: &str,
) -> Result<Option<EntityId>, CalendarError> {
    let digest = passport_digest(uid);
    let Some(id) = ({
        let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        PASSPORT_INDEX.get(&vault.store, &rtxn, &digest)?
    }) else {
        return Ok(None);
    };
    if vault.get_entity_type(&id)? == Some(ENTITY_TYPE_EVENT) {
        return Ok(Some(id));
    }
    Ok(None)
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
/// passports never vote
/// ([`CalendarPassportDirection::is_inbound_bearing`](crate::calendar::claims::CalendarPassportDirection::is_inbound_bearing)),
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

/// Whether a live passport on `event_ref`, pending or not, carries `uid` from
/// any system.
fn carries_live_uid(vault: &Vault, event_ref: &EntityId, uid: &str) -> Result<bool, CalendarError> {
    Ok(live_passports_for_event(vault, event_ref)?
        .iter()
        .any(|(_, value)| value.uid == uid))
}

/// Whether an admitted passport on `event_ref` carries `uid` from any system.
pub(super) fn carries_admitted_uid(
    vault: &Vault,
    event_ref: &EntityId,
    uid: &str,
) -> Result<bool, CalendarError> {
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    Ok(
        admitted_passports_for_event_in_txn(vault, &rtxn, event_ref)?
            .iter()
            .any(|(_, value)| value.uid == uid),
    )
}

/// Index key digest: SHA-256 of the UID, mirroring `comm.rs::party_index_key`.
fn passport_digest(uid: &str) -> [u8; 32] {
    Sha256::digest(uid.as_bytes()).into()
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

/// Whether the ingest diff reads `event` as a detached series instance.
///
/// The importer's comparison form: an admitted exception head counts, and so
/// does the importer's own pending one, since the import gate files its
/// exception claims pending review exactly as it files its passports.
fn is_live_series_exception(vault: &Vault, event: &EntityId) -> Result<bool, CalendarError> {
    series_exception_with(vault, event, |body| {
        claim_surfaceable(body)
            || (body.approval == crate::claim::ClaimApprovalStatus::Proposed
                && body.source == Some(crate::claim::ClaimSource::Imported))
    })
}

/// Whether an admitted exception head makes `event` a detached instance.
fn is_admitted_series_exception(vault: &Vault, event: &EntityId) -> Result<bool, CalendarError> {
    series_exception_with(vault, event, claim_surfaceable)
}

/// Folds the current exception state: only a lifecycle-active
/// `calendar.series_exception` head that `counts` admits excludes `event`.
/// Superseded, retracted and rejected history is inert and never steers
/// identity.
fn series_exception_with(
    vault: &Vault,
    event: &EntityId,
    counts: impl Fn(&crate::claim::ClaimBody) -> bool,
) -> Result<bool, CalendarError> {
    for id in vault.claims_for_subject(event)? {
        if vault.get_claim(&id)?.is_some_and(|body| {
            body.predicate == super::claims::PREDICATE_CALENDAR_SERIES_EXCEPTION
                && body.lifecycle == ClaimLifecycleStatus::Active
                && body.approval != crate::claim::ClaimApprovalStatus::Rejected
                && counts(&body)
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::claims::CalendarPassportDirection;
    use crate::calendar::test_support::{CalendarEventFixture, open_calendar_vault};

    #[test]
    fn passport_uid_index_pins_literal_key_and_survives_vault_reopen() {
        let uid = "uid-1@example.com";
        let digest: [u8; 32] = [
            0x66, 0x56, 0xa0, 0x0b, 0xd3, 0x3b, 0x8a, 0xd1, 0x86, 0xc8, 0x2a, 0x6a, 0xbe, 0xc0,
            0xc2, 0x74, 0x2d, 0xc4, 0x8b, 0xf5, 0x8c, 0x34, 0xab, 0x07, 0x54, 0x7f, 0x2d, 0x16,
            0x62, 0x9a, 0x13, 0xbe,
        ];
        let key = [b"calendar.passport.v1:".as_slice(), digest.as_slice()].concat();
        let (dir, vault) = open_calendar_vault();
        let event = CalendarEventFixture::new(0x52, "UID index fixture", 100, 200).store(&vault);
        let passport = CalendarPassportValue {
            system: "fixture".to_owned(),
            uid: uid.to_owned(),
            last_sequence: 3,
            content_hash: [7; 32],
            direction: CalendarPassportDirection::Outbound,
            last_seen_at: 100,
            presence: CalendarPassportPresence::Live,
        };
        let claim = crate::ClaimBody::new(
            PREDICATE_CALENDAR_PASSPORT,
            crate::ClaimSubject::Entity(event),
            encode_passport_value(&passport),
            1.0,
            crate::ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .unwrap();
        let claim_id = EntityId::now();
        vault
            .put_claim(
                &claim_id,
                &claim,
                crate::TimeRange {
                    start: 100,
                    end: 100,
                },
                100,
            )
            .unwrap();
        index_passport_uid(&vault, uid, &event).unwrap();
        {
            let txn = vault.store.env.read_txn().unwrap();
            let stored = vault.store.vault_meta.get(&txn, &key).unwrap().unwrap();
            assert_eq!(stored.as_ref(), event.as_bytes());
        }
        drop(vault);
        let reopened = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
        {
            let txn = reopened.store.env.read_txn().unwrap();
            let stored = reopened.store.vault_meta.get(&txn, &key).unwrap().unwrap();
            assert_eq!(stored.as_ref(), event.as_bytes());
        }
        assert_eq!(resolve_event_by_uid(&reopened, uid).unwrap(), Some(event));
    }
}
