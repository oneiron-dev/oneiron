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

mod feed_diff;
pub use feed_diff::{
    PassportDecision, PassportRevision, classify_passport, index_passport_uid, resolve_event_by_uid,
};
pub(crate) use feed_diff::{
    admitted_passport_for_in_txn, importer_pending_passports_in_txn, resolve_admitted_event_by_uid,
};
pub(in crate::calendar) use feed_diff::{
    admitted_passport_keyed, classify_event_passport, index_passport_uid_in_txn,
    revise_passport_in_txn,
};

use crate::ports::EntityStoreRead;
use sha2::Digest;
use sha2::Sha256;

use super::CalendarError;
use super::claims::{
    CalendarPassportPresence, CalendarPassportValue, PREDICATE_CALENDAR_PASSPORT,
    PREDICATE_CALENDAR_SERIES_EXCEPTION, decode_passport_value,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSubject, claim_surfaceable};
use crate::code_run::CompareKnown;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::side_table::{self, Raw, SideTable};
use crate::store::known_value_index::KnownValues;
use crate::vault::Vault;

mod masked_key;

use masked_key::MaskedKey;
pub(in crate::calendar) use masked_key::{
    derived_uid_among, passport_system_is, passport_uid_among,
};

/// The reason code on the tray resolution of a waiting passport revision
/// that a later revision replaced.
/// The gate decision ledger takes only `gate.` reason codes.
const REVISION_REPLACED_REASON: &str = "gate.calendar.passport.revision_replaced";

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
            && passport_admitted_in_txn(vault, txn, &id, &body)?
        {
            values.push((id, decode_passport_value(&body.value)?));
        }
    }
    Ok(values)
}

/// Whether the passport claim `id` is admitted: a surfaceable head whose
/// critical confirm, if any, is settled. Only an admitted passport carries
/// revision authority.
fn passport_admitted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &crate::claim::ClaimBody,
) -> Result<bool, CalendarError> {
    Ok(claim_surfaceable(body)
        && crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, id)?)
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
        if crate::source_audience::binding_in(vault, txn, &event)?.is_some() {
            continue;
        }
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
        && crate::source_audience::binding_in(vault, txn, &event)?.is_none()
    {
        return Ok(Some(event));
    }
    Ok(None)
}

/// Files `new_id`, which its caller already admitted through the Gate door,
/// as the next revision of exactly `(system × UID)` on `event_ref`, never
/// touching a sibling source's passport on the same EVENT
/// ([`revise_passport_in_txn`]): the admitted head stays the head until
/// `new_id` is approved. Answers what the filing did to that head.
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
) -> Result<PassportRevision, CalendarError> {
    vault.try_with_write_txn_grouped(|txn| {
        revise_passport_in_txn(vault, txn, &event_ref, system, uid, new_id, recorded_at)?
            .ok_or_else(|| ingest("no live passport carries this (system, uid) pair"))
    })
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

/// The live passport claims on one EVENT, one per `(system × UID)`, as
/// `(claim id, decoded value)`: the revision the ingest diff compares a feed
/// row with.
///
/// The admitted head stays live beside a revision that waits for review or
/// that the owner rejected ([`revise_passport_in_txn`]), so one key can hold
/// several live claims. This view takes the latest filed of them, admitted or
/// not: the diff files neither a waiting revision nor a rejected one again,
/// and once a later revision is admitted, an older rejected one no longer
/// steers the diff. The larger claim id is the later filing: ids are ULIDs in
/// minting order, so a claim filed under an id minted earlier (a synced claim,
/// or a raw [`Vault::put_claim`] with a reserved id) counts at its minting
/// time. Authority reads the admitted head
/// ([`admitted_passports_for_event_in_txn`]).
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures.
pub fn live_passports_for_event(
    vault: &Vault,
    event_ref: &EntityId,
) -> Result<Vec<(EntityId, CalendarPassportValue)>, CalendarError> {
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    live_passports_for_event_in_txn(vault, &txn, event_ref)
}

pub(crate) fn live_passports_for_event_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<Vec<(EntityId, CalendarPassportValue)>, CalendarError> {
    let mut out: Vec<(EntityId, CalendarPassportValue)> = Vec::new();
    for claim_id in vault.claims_for_subject_in_txn(txn, event_ref)? {
        let Some(body) = vault.get_claim_in_txn(txn, &claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CALENDAR_PASSPORT
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let value = decode_passport_value(&body.value)
            .map_err(|_| ingest("stored passport claim did not decode"))?;
        match out
            .iter_mut()
            .find(|(_, kept)| kept.system == value.system && kept.uid == value.uid)
        {
            Some(kept) => {
                if claim_id.as_bytes() > kept.0.as_bytes() {
                    *kept = (claim_id, value);
                }
            }
            None => out.push((claim_id, value)),
        }
    }
    Ok(out)
}

/// The live passport claim on `event_ref` for exactly `(system, uid)`: its
/// system and UID as written, else as custody reads each where it is pinned
/// ([`passport_keyed`]).
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures,
/// and the custody read's.
pub fn live_passport_for(
    vault: &Vault,
    event_ref: &EntityId,
    system: &str,
    uid: &str,
) -> Result<Option<(EntityId, CalendarPassportValue)>, CalendarError> {
    let passports = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        live_passports_for_event_in_txn(vault, &txn, event_ref)?
    };
    let base_known = || vault.known_values_now();
    let known = CompareKnown::new(Some(&base_known));
    passport_keyed(
        passports,
        system,
        uid,
        || {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            MaskedKey::read_in_txn(vault, &txn, event_ref, system, uid)
        },
        &known,
    )
}

/// The passport of `passports`, the live ones of `event_ref`, keyed exactly
/// `(system, uid)` as the vault reads it now ([`passport_keyed`]), for a
/// scan over many EVENTs that read their passports and the values custody
/// holds (`known`) once.
///
/// # Errors
///
/// As [`live_passport_for`].
pub(in crate::calendar) fn live_passport_keyed(
    vault: &Vault,
    event_ref: &EntityId,
    passports: Vec<(EntityId, CalendarPassportValue)>,
    system: &str,
    uid: &str,
    known: &CompareKnown<'_>,
) -> Result<Option<(EntityId, CalendarPassportValue)>, CalendarError> {
    passport_keyed(
        passports,
        system,
        uid,
        || {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            MaskedKey::read_in_txn(vault, &txn, event_ref, system, uid)
        },
        known,
    )
}

/// [`live_passport_for`] as the writer `txn` reads it, the values custody
/// holds included.
///
/// # Errors
///
/// As [`live_passport_for`].
pub(in crate::calendar) fn live_passport_for_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    event_ref: &EntityId,
    system: &str,
    uid: &str,
) -> Result<Option<(EntityId, CalendarPassportValue)>, CalendarError> {
    let passports = live_passports_for_event_in_txn(vault, txn, event_ref)?;
    let base_known = || KnownValues::shared_in_writer(&vault.store, txn);
    let known = CompareKnown::new(Some(&base_known));
    passport_keyed(
        passports,
        system,
        uid,
        || MaskedKey::read_in_txn(vault, txn, event_ref, system, uid),
        &known,
    )
}

/// The passport of `passports`, one EVENT's live ones, keyed exactly
/// `(system, uid)`: the one whose system and UID are `system` and `uid` as
/// written, else the first that carries the key as custody reads its system
/// and UID, each where `masked` pins it ([`MaskedKey`]). A passport the claim
/// door stored with a system name or a UID custody holds is the one the
/// seat's or the feed's key names, so the diff reads its SEQUENCE before an
/// older version lands as new, or a second passport of one source lands
/// beside it (blind review round 2 of #10090,
/// CAL-PASSPORT-SYSTEM-UID-LOOKUP-MISSES-MASKED-PASSPORT).
fn passport_keyed<'k>(
    mut passports: Vec<(EntityId, CalendarPassportValue)>,
    system: &'k str,
    uid: &'k str,
    masked: impl FnOnce() -> Result<MaskedKey<'k>, CalendarError>,
    known: &CompareKnown<'_>,
) -> Result<Option<(EntityId, CalendarPassportValue)>, CalendarError> {
    if let Some(at) = passports
        .iter()
        .position(|(_, value)| value.system == system && value.uid == uid)
    {
        return Ok(Some(passports.swap_remove(at)));
    }
    if passports.is_empty() {
        return Ok(None);
    }
    let masked = masked()?;
    for (claim_id, value) in passports {
        if masked.carried_by(&value, known)? {
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
/// any system, as written or as custody reads it ([`passport_uid_is`]).
fn carries_live_uid(
    vault: &Vault,
    event_ref: &EntityId,
    uid: &str,
    known: &CompareKnown<'_>,
) -> Result<bool, CalendarError> {
    let passports = live_passports_for_event(vault, event_ref)?;
    any_passport_carries(vault, event_ref, &passports, uid, known)
}

/// Whether an admitted passport on `event_ref` carries `uid` from any system,
/// as written or as custody reads it ([`passport_uid_is`]).
fn carries_admitted_uid(
    vault: &Vault,
    event_ref: &EntityId,
    uid: &str,
    known: &CompareKnown<'_>,
) -> Result<bool, CalendarError> {
    let passports = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        admitted_passports_for_event_in_txn(vault, &txn, event_ref)?
    };
    any_passport_carries(vault, event_ref, &passports, uid, known)
}

/// Whether one of `passports`, live on `event_ref`, carries `uid`: as
/// written, or as custody reads it where `uid` is pinned to `event_ref`
/// ([`passport_uid_pinned_is`]).
fn any_passport_carries(
    vault: &Vault,
    event_ref: &EntityId,
    passports: &[(EntityId, CalendarPassportValue)],
    uid: &str,
    known: &CompareKnown<'_>,
) -> Result<bool, CalendarError> {
    if passports.iter().any(|(_, value)| value.uid == uid) {
        return Ok(true);
    }
    if passports.is_empty() || !uid_pinned_to(vault, event_ref, uid)? {
        return Ok(false);
    }
    for (_, value) in passports {
        if passport_uid_is(&value.uid, uid, known)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `held`, a UID a passport on an EVENT stored, is `uid`: as
/// written, or, when `pinned` says `uid` is pinned to that EVENT
/// ([`uid_pinned_to`]), as custody reads it ([`passport_uid_is`]).
fn passport_uid_pinned_is(
    held: &str,
    uid: &str,
    pinned: bool,
    known: &CompareKnown<'_>,
) -> Result<bool, CalendarError> {
    if held == uid {
        return Ok(true);
    }
    if !pinned {
        return Ok(false);
    }
    passport_uid_is(held, uid, known)
}

/// Whether `uid` is pinned to `event_ref`: it is the UID a first write of
/// `event_ref` mints, or this node's UID index points it at `event_ref`,
/// which an entry does only once a passport of exactly that UID was filed
/// there or vouched for it. A custody record keeps every value it held, so
/// a passport UID read through its handle meets each of them: only a pinned
/// UID is read so, and a VEVENT whose UID a rotation gave the record since
/// never lands on the EVENT of the UID it held before (blind review round
/// 2 of #10090).
///
/// # Errors
///
/// Store failures.
fn uid_pinned_to(vault: &Vault, event_ref: &EntityId, uid: &str) -> Result<bool, CalendarError> {
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    uid_pinned_to_in_txn(vault, &txn, event_ref, uid)
}

fn uid_pinned_to_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
    uid: &str,
) -> Result<bool, CalendarError> {
    if super::connectors::local_uid(event_ref) == uid {
        return Ok(true);
    }
    Ok(PASSPORT_INDEX.get(&vault.store, txn, &passport_digest(uid))? == Some(*event_ref))
}

/// Whether `held`, a UID the vault stored, is `uid`: as written, or with a
/// custody handle in place of a value custody holds. The claim door stores a
/// `calendar.passport`, and the side-row wall an outbox row, with such a
/// value's handle, so a passport the settled write of a UID custody holds
/// filed vouches for that UID's index entry only when its UID is read as a
/// template: each handle meets only a value of its own record, and every
/// other byte only itself ([`CompareKnown::admits`]). `known` reads the
/// values custody holds once the compare as written misses (blind review
/// round 1 of #10090, CAL-OUTBOX-SCAN-MASKED-SYSTEM-MISSES-ROW). A handle
/// meets every value its record ever held, so a caller reads a UID so only
/// where something else pins it to the stored one ([`uid_pinned_to`]; a
/// first write's row of the EVENT whose minted UID `uid` is).
///
/// # Errors
///
/// The custody read's, or a value the wall cannot read.
pub(in crate::calendar) fn passport_uid_is(
    held: &str,
    uid: &str,
    known: &CompareKnown<'_>,
) -> Result<bool, CalendarError> {
    if held == uid {
        return Ok(true);
    }
    known
        .admits(&rmpv::Value::from(held), &rmpv::Value::from(uid))
        .map_err(CalendarError::from)
}

pub(in crate::calendar) fn carries_admitted_uid_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
    uid: &str,
) -> Result<bool, CalendarError> {
    Ok(admitted_passports_for_event_in_txn(vault, txn, event_ref)?
        .iter()
        .any(|(_, value)| value.uid == uid))
}

/// Index key digest: SHA-256 of the UID, mirroring `comm.rs::party_index_key`.
fn passport_digest(uid: &str) -> [u8; 32] {
    Sha256::digest(uid.as_bytes()).into()
}

/// The `calendar.passport` wire map, keyed exactly as
/// [`super::claims::decode_passport_value`] reads. CAL-00 owns the codec; the
/// write-door validator chain rejects any drift fail-closed.
pub(crate) fn encode_passport_value(value: &CalendarPassportValue) -> rmpv::Value {
    let mut entries = vec![
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
    ];
    if let Some(source) = value.source {
        entries.push((
            rmpv::Value::from("source"),
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("artifact"),
                    rmpv::Value::from(source.artifact.to_hex()),
                ),
                (
                    rmpv::Value::from("version"),
                    rmpv::Value::from(source.version),
                ),
            ]),
        ));
    }
    if let Some(since) = value.cancelled_since {
        entries.push((
            rmpv::Value::from("cancelled_since"),
            rmpv::Value::from(since),
        ));
    }
    if value.written_cancelled {
        entries.push((
            rmpv::Value::from("written_cancelled"),
            rmpv::Value::Boolean(true),
        ));
    }
    if let Some(seen_at) = value.deferred_cancel_seen_at {
        entries.push((
            rmpv::Value::from("deferred_cancel_seen_at"),
            rmpv::Value::from(seen_at),
        ));
    }
    rmpv::Value::Map(entries)
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
    series_exception_with(vault, event, counts_for_ingest)
}

/// Whether the ingest diff counts `body` as a surfaceable head or as the
/// importer's own pending one ([`is_live_series_exception`]).
fn counts_for_ingest(body: &crate::claim::ClaimBody) -> bool {
    claim_surfaceable(body)
        || (body.approval == crate::claim::ClaimApprovalStatus::Proposed
            && body.source == Some(crate::claim::ClaimSource::Imported))
}

/// Whether `body`, an exception claim, is a head the ingest diff counts: as
/// [`series_exception_with`] folds it for [`is_live_series_exception`].
fn exception_head_counts_for_ingest(body: &crate::claim::ClaimBody) -> bool {
    body.lifecycle == ClaimLifecycleStatus::Active
        && body.approval != crate::claim::ClaimApprovalStatus::Rejected
        && counts_for_ingest(body)
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
            body.predicate == PREDICATE_CALENDAR_SERIES_EXCEPTION
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
            source: None,
            direction: CalendarPassportDirection::Outbound,
            last_seen_at: 100,
            presence: CalendarPassportPresence::Live,
            cancelled_since: None,
            written_cancelled: false,
            deferred_cancel_seen_at: None,
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
