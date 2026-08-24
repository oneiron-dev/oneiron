//! Input validators and in-place record mutators guarding the attempt-queue
//! doors.
//!
//! Every refusal message is a stable `&'static str` const declared here, so a
//! caller can assert on the exact reason. Storage-shape validation that reads
//! or writes index keys lives in [`super::encoding`] instead.

use crate::error::{Error, Result};

use super::telemetry::invalid_transition;
use super::types::{
    AttemptEvent, AttemptInterventionKind, AttemptRecord, AttemptState, CleanupAttemptLeases,
    MAX_ATTEMPT_EVENTS_PER_RECORD, MAX_ATTEMPT_MANIFEST_ENTRIES, ManifestEntry,
};

const MAX_KIND_LEN: usize = 128;
const MAX_DEDUPE_KEY_LEN: usize = 512;
pub(super) const MAX_FAILURE_REASON_LEN: usize = 2048;
const MAX_LEASE_OWNER_LEN: usize = 128;
const MAX_RUN_ID_LEN: usize = 128;
const MAX_INTERVENTION_ACTOR_LEN: usize = 128;
const MAX_INTERVENTION_NOTE_LEN: usize = 2048;
pub(super) const MAX_MANIFEST_REFERENCE_LEN: usize = 512;
pub(super) const MAX_MANIFEST_VERSION_LEN: usize = 128;
const ERR_EMPTY_KIND: &str = "kind must not be empty";
const ERR_KIND_TOO_LONG: &str = "kind exceeds 128 bytes";
const ERR_DEDUPE_KEY_EMPTY: &str = "dedupe key must not be empty";
const ERR_DEDUPE_KEY_TOO_LONG: &str = "dedupe key exceeds 512 bytes";
pub(super) const ERR_FAILURE_REASON_EMPTY: &str = "failure reason must not be empty";
const ERR_FAILURE_REASON_TOO_LONG: &str = "failure reason exceeds 2048 bytes";
const ERR_LEASE_OWNER_EMPTY: &str = "lease owner must not be empty";
const ERR_LEASE_OWNER_TOO_LONG: &str = "lease owner exceeds 128 bytes";
const ERR_RUN_ID_EMPTY: &str = "run id must not be empty";
const ERR_RUN_ID_TOO_LONG: &str = "run id exceeds 128 bytes";
const ERR_INTERVENTION_ACTOR_EMPTY: &str = "intervention actor must not be empty";
const ERR_INTERVENTION_ACTOR_TOO_LONG: &str = "intervention actor exceeds 128 bytes";
const ERR_INTERVENTION_NOTE_EMPTY: &str = "intervention note must not be empty";
const ERR_INTERVENTION_NOTE_TOO_LONG: &str = "intervention note exceeds 2048 bytes";
pub(super) const ERR_MANIFEST_REFERENCE_EMPTY: &str = "manifest reference must not be empty";
pub(super) const ERR_MANIFEST_REFERENCE_TOO_LONG: &str = "manifest reference exceeds 512 bytes";
pub(super) const ERR_MANIFEST_REFERENCE_HAS_AT: &str = "manifest reference must not contain '@'";
pub(super) const ERR_MANIFEST_VERSION_EMPTY: &str = "manifest version must not be empty";
pub(super) const ERR_MANIFEST_VERSION_TOO_LONG: &str = "manifest version exceeds 128 bytes";
pub(super) const ERR_MANIFEST_FULL: &str = "attempt manifest is full; entries are never dropped";
pub(super) const ERR_LEASE_TIMEOUT_ZERO: &str = "lease timeout must be > 0";

pub(super) fn validate_kind(kind: &str) -> Result<()> {
    if kind.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(ERR_EMPTY_KIND));
    }
    if kind.len() > MAX_KIND_LEN {
        return Err(Error::InvalidAttemptQueueRecord(ERR_KIND_TOO_LONG));
    }
    Ok(())
}

pub(super) fn validate_optional_dedupe(dedupe_key: Option<&str>) -> Result<()> {
    if let Some(dedupe_key) = dedupe_key {
        if dedupe_key.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(ERR_DEDUPE_KEY_EMPTY));
        }
        if dedupe_key.len() > MAX_DEDUPE_KEY_LEN {
            return Err(Error::InvalidAttemptQueueRecord(ERR_DEDUPE_KEY_TOO_LONG));
        }
    }
    Ok(())
}

pub(super) fn validate_failure_reason(reason: &str) -> Result<()> {
    validate_optional_failure_reason(Some(reason))
}

pub(super) fn validate_optional_failure_reason(reason: Option<&str>) -> Result<()> {
    if let Some(reason) = reason {
        if reason.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(ERR_FAILURE_REASON_EMPTY));
        }
        if reason.len() > MAX_FAILURE_REASON_LEN {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_FAILURE_REASON_TOO_LONG,
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_optional_run_id(run_id: Option<&str>) -> Result<()> {
    if let Some(run_id) = run_id {
        if run_id.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(ERR_RUN_ID_EMPTY));
        }
        if run_id.len() > MAX_RUN_ID_LEN {
            return Err(Error::InvalidAttemptQueueRecord(ERR_RUN_ID_TOO_LONG));
        }
    }
    Ok(())
}

pub(super) fn validate_intervention_actor(actor: &str) -> Result<()> {
    if actor.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_INTERVENTION_ACTOR_EMPTY,
        ));
    }
    if actor.len() > MAX_INTERVENTION_ACTOR_LEN {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_INTERVENTION_ACTOR_TOO_LONG,
        ));
    }
    Ok(())
}

pub(super) fn validate_optional_intervention_note(note: Option<&str>) -> Result<()> {
    if let Some(note) = note {
        if note.is_empty() {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_INTERVENTION_NOTE_EMPTY,
            ));
        }
        if note.len() > MAX_INTERVENTION_NOTE_LEN {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_INTERVENTION_NOTE_TOO_LONG,
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_lease_owner(lease_owner: &str) -> Result<()> {
    if lease_owner.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(ERR_LEASE_OWNER_EMPTY));
    }
    if lease_owner.len() > MAX_LEASE_OWNER_LEN {
        return Err(Error::InvalidAttemptQueueRecord(ERR_LEASE_OWNER_TOO_LONG));
    }
    Ok(())
}

pub(super) fn validate_cleanup_leases_input(input: &CleanupAttemptLeases) -> Result<()> {
    if input.lease_timeout_secs == 0 {
        return Err(Error::InvalidAttemptQueueRecord(ERR_LEASE_TIMEOUT_ZERO));
    }
    Ok(())
}

/// Leases an admitted ready row in place. The readiness instant is consumed by
/// the lease, so both spellings clear; `attempt_count` advances as this row's
/// lease-generation fence.
pub(super) fn lease_claimed_record(
    record: &mut AttemptRecord,
    lease_owner: &str,
    now: u64,
) -> Result<()> {
    record.state = AttemptState::Leased;
    record.lease_owner = Some(lease_owner.to_owned());
    record.attempt_count = record
        .attempt_count
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("attempt lease count"))?;
    if record.claimed_at.is_none() {
        record.claimed_at = Some(now);
    }
    record.scheduled_at = None;
    record.backoff_until = None;
    record.updated_at = now;
    Ok(())
}

pub(super) fn validate_transition_lease(
    record: &AttemptRecord,
    lease_owner: &str,
    attempt_count: u32,
    action: &'static str,
) -> Result<()> {
    if record.lease_owner.as_deref() != Some(lease_owner) {
        return Err(invalid_transition(action, "leased_by_other"));
    }
    if record.attempt_count != attempt_count {
        return Err(invalid_transition(action, "stale_attempt"));
    }
    Ok(())
}

pub(super) fn validate_attempt_events(events: &[AttemptEvent]) -> Result<()> {
    let mut previous_sequence = 0;
    for event in events {
        if event.sequence == 0 || event.sequence <= previous_sequence {
            return Err(Error::InvalidAttemptQueueRecord(
                "attempt event sequence must be strictly increasing",
            ));
        }
        validate_intervention_actor(&event.actor)?;
        validate_optional_intervention_note(event.note.as_deref())?;
        previous_sequence = event.sequence;
    }
    Ok(())
}

/// Refuses a row the `reference@version` wire form could not carry back.
///
/// `@` in a REFERENCE is rejected here (owner ruling R-20260807-04): it is the
/// delimiter, so a reference holding one makes [`ManifestEntry::parse_wire_form`]
/// ambiguous and lets a row name a skill the pack never loaded. A VERSION may
/// hold `@` freely — everything after the first delimiter is the version.
pub(super) fn validate_manifest_entry(entry: &ManifestEntry) -> Result<()> {
    if entry.reference.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_MANIFEST_REFERENCE_EMPTY,
        ));
    }
    if entry.reference.contains('@') {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_MANIFEST_REFERENCE_HAS_AT,
        ));
    }
    if entry.reference.len() > MAX_MANIFEST_REFERENCE_LEN {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_MANIFEST_REFERENCE_TOO_LONG,
        ));
    }
    if entry.version.is_empty() {
        return Err(Error::InvalidAttemptQueueRecord(ERR_MANIFEST_VERSION_EMPTY));
    }
    if entry.version.len() > MAX_MANIFEST_VERSION_LEN {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_MANIFEST_VERSION_TOO_LONG,
        ));
    }
    Ok(())
}

pub(super) fn validate_attempt_manifest(manifest: &[ManifestEntry]) -> Result<()> {
    if manifest.len() > MAX_ATTEMPT_MANIFEST_ENTRIES {
        return Err(Error::InvalidAttemptQueueRecord(ERR_MANIFEST_FULL));
    }
    for entry in manifest {
        validate_manifest_entry(entry)?;
    }
    Ok(())
}

pub(super) fn append_attempt_event(
    record: &mut AttemptRecord,
    kind: AttemptInterventionKind,
    actor: String,
    note: Option<String>,
    now: u64,
) -> Result<()> {
    let sequence = match record.events.last() {
        Some(event) => event
            .sequence
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("attempt event sequence"))?,
        None => 1,
    };
    record.events.push(AttemptEvent {
        sequence,
        at: now,
        actor,
        kind,
        note,
    });
    if record.events.len() > MAX_ATTEMPT_EVENTS_PER_RECORD {
        let excess = record.events.len() - MAX_ATTEMPT_EVENTS_PER_RECORD;
        record.events.drain(0..excess);
    }
    Ok(())
}
