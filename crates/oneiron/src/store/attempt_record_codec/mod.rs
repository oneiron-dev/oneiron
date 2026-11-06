//! The attempt record's strict codec (`job_records` rows): the version byte
//! and named MessagePack body, the side-row-admitted encoding of a row's
//! authored members, and the strict reader with every persisted-row check it
//! runs, in order. The attempt queue (`attempt_queue::encoding`) keeps the
//! dedupe and ready index keys and the checkpoint index rebuild; the store's
//! open gates and the secret-scan lift history read rows through here.
use rmpv::Value;

use crate::batch::secret_scan::{SidePart, admit_side_parts, from_named_tree, named_tree};
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::SideTableDbs;
use crate::store::attempt_id::AttemptId;
use crate::store::attempt_lease::validate_lease_owner;
use crate::store::attempt_record::{ATTEMPT_RECORD_VERSION, AttemptRecord, RequeuedFailure};
use crate::store::attempt_state::AttemptState;

pub(crate) mod cancel_validators;
pub(crate) mod field_validators;
pub(crate) mod signal_validators;

use cancel_validators::validate_cancel_state;
use field_validators::{
    ERR_ABANDONED_WITHOUT_REASON, ERR_ABANDONED_WITHOUT_RESULT, ERR_CANCELLATION_MISPLACED,
    ERR_DEDUPE_ACTOR_WITHOUT_KEY, ERR_LANDING_RECORD_MISPLACED, ERR_LANDING_WITH_BACKOFF,
    ERR_LANDING_WITHOUT_LEASE, ERR_LANDING_WITHOUT_RECORD, validate_attempt_events,
    validate_attempt_manifest, validate_failure_reason, validate_kind, validate_optional_dedupe,
    validate_optional_dedupe_actor_ref, validate_optional_failure_reason,
    validate_optional_result_ref, validate_optional_run_id, validate_planned_binding,
};

const ERR_RECORD_UNENCODABLE: &str = "failed to encode attempt record";

/// The most bytes one LMDB value holds (`MAXDATASIZE` in the pinned
/// `lmdb-master3-sys`): a storage capacity, the one size bound a row meets.
const LMDB_MAX_VALUE_BYTES: u64 = 4_294_967_295;

const ERR_RECORD_PAST_VALUE_CAPACITY: &str =
    "attempt record exceeds LMDB's 4294967295-byte value capacity";

/// The members of a row a caller authored, which the side-row wall reads beside
/// the payload (OF-067): the failure text, the intervention, signal, ask and
/// cancel notes, the requeued failures (FIX 5240) and the outputs and
/// checkpoint a settled try left behind (FIX 9578). The queue's own ids,
/// keys, states and times index the row and are never rewritten.
const AUTHORED_MEMBERS: [&str; 7] = [
    "last_error",
    "events",
    "signals",
    "asks",
    "cancel_state",
    "history",
    "terminal_exhaust",
];

/// Longest actor scope the dedupe index admits. It bounds the length prefix
/// the v2 hash writes, so the segment can never be truncated into ambiguity.
pub(crate) const MAX_DEDUPE_ACTOR_REF_LEN: usize = 128;

/// True when a pending row is waiting on a retry backoff, in either the new
/// `scheduled_at` spelling or the legacy `backoff_until` one.
pub(crate) fn waiting_on_backoff(record: &AttemptRecord) -> bool {
    record.scheduled_at.is_some() || record.backoff_until.is_some()
}

/// Encodes one row under the pinned header version.
///
/// The body is a named MessagePack map, so a field ADDED with `serde(default)`
/// is invisible to a reader that predates it and decodes as its default on a
/// row that predates the writer. Unit-enum values are encoded by DECLARATION
/// INDEX, so a state variant may only be appended after every existing one —
/// the rule stated on [`AttemptState`] — and the header version stays at
/// [`ATTEMPT_RECORD_VERSION`] because neither addition rewrites an existing
/// byte.
///
/// A row past `LMDB_MAX_VALUE_BYTES` is refused whole, naming that capacity;
/// nothing is cut to fit.
pub(crate) fn encode_record(record: &AttemptRecord) -> Result<Vec<u8>> {
    let mut encoded = vec![ATTEMPT_RECORD_VERSION];
    let mut body = rmp_serde::to_vec_named(record).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RECORD_UNENCODABLE,
        ))
    })?;
    encoded.append(&mut body);
    if encoded.len() as u64 > LMDB_MAX_VALUE_BYTES {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RECORD_PAST_VALUE_CAPACITY,
        )));
    }
    Ok(encoded)
}

/// [`encode_record`] once the side-row wall has read the row, in the writer's
/// transaction (OF-067; ARCH-0069 #mask-on-write): each secret the payload or
/// an authored member holds goes to custody, and `record` keeps the handles
/// the stored row keeps. A hit the mask cannot place, or a masked row that no
/// longer reads back as a row, refuses the write.
pub(crate) fn encode_admitted_record(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    record: &mut AttemptRecord,
) -> Result<Vec<u8>> {
    let Value::Map(members) = named_tree(record)? else {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RECORD_UNENCODABLE,
        )));
    };
    let authored = members
        .iter()
        .filter(|(name, _)| {
            name.as_str()
                .is_some_and(|name| AUTHORED_MEMBERS.contains(&name))
        })
        .cloned()
        .collect();
    let rebuilt = |parts: &[SidePart]| -> Option<AttemptRecord> {
        let [
            SidePart::Body(payload),
            SidePart::Value(Value::Map(authored)),
        ] = parts
        else {
            return None;
        };
        let mut members = members.clone();
        for (name, value) in authored {
            if let Some((_, member)) = members.iter_mut().find(|(held, _)| held == name) {
                member.clone_from(value);
            }
        }
        let mut rebuilt: AttemptRecord = from_named_tree(&Value::Map(members))?;
        rebuilt.payload.clone_from(payload);
        Some(rebuilt)
    };
    let reads_back = |parts: &[SidePart]| {
        rebuilt(parts).is_some_and(|row| {
            encode_record(&row)
                .and_then(|raw| decode_record(&raw, row.id))
                .is_ok()
        })
    };
    let mut parts = [
        SidePart::Body(record.payload.clone()),
        SidePart::Value(Value::Map(authored)),
    ];
    if admit_side_parts(
        dbs,
        wtxn,
        ("attempt", record.id.as_bytes().as_slice()),
        &mut parts,
        reads_back,
    )? {
        *record = rebuilt(&parts).ok_or(Error::InvariantViolation(
            "a masked attempt record no longer decodes",
        ))?;
    }
    encode_record(record)
}

/// A signal row's bytes, read once by the side-row wall in the writer's
/// transaction ([`encode_admitted_record`]). An erased dispatch
/// target's text leaves the row first, as on every queue write (FIX 7076).
pub(crate) fn encode_admitted_signal_record(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &mut AttemptRecord,
) -> Result<Vec<u8>> {
    vault
        .store
        .attempt_operations
        .scrub_hard_erased_payload_in_txn(&vault.store, wtxn, record);
    encode_admitted_record(vault, wtxn, record)
}

pub(crate) fn decode_record(raw: &[u8], expected_id: AttemptId) -> Result<AttemptRecord> {
    // The erased marker of a retired dispatch row that never decoded reads
    // as the typed unavailable, before any version or map (FIX 9390).
    let family = crate::store::ResponseFamily::AttemptPayload;
    let raw = crate::store::ResponseRead::of(family, expected_id.as_bytes(), raw).present()?;
    let Some((&version, body)) = raw.split_first() else {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            "missing attempt record version",
        )));
    };
    if version != ATTEMPT_RECORD_VERSION {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            "unsupported attempt record version",
        )));
    }
    let record: AttemptRecord = rmp_serde::from_slice(body).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            "failed to decode attempt record",
        ))
    })?;
    if record.id != expected_id {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            "job_records key/id mismatch",
        )));
    }
    validate_kind(&record.kind)?;
    if let Some(worker) = record.placement.as_ref().and_then(|p| p.worker.as_deref()) {
        validate_lease_owner(worker)?;
    }
    validate_optional_dedupe(record.dedupe_key.as_deref())?;
    validate_optional_dedupe_actor_ref(record.dedupe_actor_ref.as_deref())?;
    // An actor scope with nothing to scope is a corrupted row, not a quirk:
    // it would name an index entry that cannot exist, so no-key rows are
    // always actorless on both the write and the read side.
    if record.dedupe_actor_ref.is_some() && record.dedupe_key.is_none() {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_DEDUPE_ACTOR_WITHOUT_KEY,
        )));
    }
    validate_optional_run_id(record.run_id.as_deref())?;
    validate_optional_failure_reason(record.last_error.as_deref())?;
    validate_requeued_history(&record.history)?;
    validate_attempt_events(&record.events)?;
    validate_attempt_manifest(&record.manifest)?;
    validate_cancel_state(&record.cancel_state)?;
    signal_validators::validate_signal_rows(&record)?;
    validate_optional_result_ref(record.result_ref.as_ref())?;
    validate_planned_binding(&record)?;
    if let Some(lease_owner) = record.lease_owner.as_deref() {
        validate_lease_owner(lease_owner)?;
    }
    // ONE-1896 placement rules, independent of the state-shape match below: a
    // landing record outside a landing/landed row, or a cancellation receipt on
    // a row that is not cancelled, would let a read surface report a landing
    // that never happened.
    if record.cancel_state.landing.is_some()
        && !matches!(
            record.state,
            AttemptState::Landing | AttemptState::Cancelled
        )
    {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_LANDING_RECORD_MISPLACED,
        )));
    }
    if record.cancel_state.cancellation.is_some() && record.state != AttemptState::Cancelled {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_CANCELLATION_MISPLACED,
        )));
    }
    match record.state {
        AttemptState::Queued if record.lease_owner.is_some() => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "queued attempt must not have a lease owner",
            )));
        }
        AttemptState::Leased if record.lease_owner.is_none() => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "leased attempt must have a lease owner",
            )));
        }
        AttemptState::Leased if waiting_on_backoff(&record) => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "leased attempt must not have backoff state",
            )));
        }
        AttemptState::Paused if record.lease_owner.is_some() => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "paused attempt must not have a lease owner",
            )));
        }
        AttemptState::Scheduled if record.lease_owner.is_some() => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "scheduled attempt must not have a lease owner",
            )));
        }
        AttemptState::Scheduled if record.scheduled_at.is_none() => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "scheduled attempt must have a scheduled instant",
            )));
        }
        // A landing row still OWNS its lease — that is what buys it the bounded
        // time to finish — so it is shaped like a leased row plus its landing
        // record, never like a queued or terminal one.
        AttemptState::Landing if record.lease_owner.is_none() => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_LANDING_WITHOUT_LEASE,
            )));
        }
        AttemptState::Landing if waiting_on_backoff(&record) => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_LANDING_WITH_BACKOFF,
            )));
        }
        AttemptState::Landing if record.cancel_state.landing.is_none() => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_LANDING_WITHOUT_RECORD,
            )));
        }
        AttemptState::Completed
        | AttemptState::Failed
        | AttemptState::Cancelled
        | AttemptState::Abandoned
            if record.lease_owner.is_some() =>
        {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "terminal attempt must not have a lease owner",
            )));
        }
        AttemptState::Completed
        | AttemptState::Failed
        | AttemptState::Cancelled
        | AttemptState::Abandoned
            if waiting_on_backoff(&record) =>
        {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "terminal attempt must not have backoff state",
            )));
        }
        AttemptState::Completed | AttemptState::Cancelled if record.last_error.is_some() => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "non-failed terminal attempt must not have a failure reason",
            )));
        }
        AttemptState::Failed if record.last_error.is_none() => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "failed attempt must have a failure reason",
            )));
        }
        // An abandonment is only auditable if the row still says what it left
        // behind and why it stopped. Both are required at the door, so a row
        // that lost either can never be read back as a well-formed abandonment.
        AttemptState::Abandoned if record.result_ref.is_none() => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_ABANDONED_WITHOUT_RESULT,
            )));
        }
        AttemptState::Abandoned if record.last_error.is_none() => {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_ABANDONED_WITHOUT_REASON,
            )));
        }
        _ => {}
    }
    Ok(record)
}

/// Refuses a stored history entry no requeue could have written.
pub(crate) fn validate_requeued_history(history: &[RequeuedFailure]) -> Result<()> {
    for failure in history {
        validate_lease_owner(&failure.lease_owner)?;
        validate_failure_reason(&failure.reason)?;
        if failure.count == 0 || failure.last_at < failure.at {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "invalid requeued failure span",
            )));
        }
    }
    Ok(())
}
