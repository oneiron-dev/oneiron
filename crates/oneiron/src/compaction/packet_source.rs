//! The packet door's source bindings (FIX 4465). A conversation's packet
//! proves its turns through the witnessed TURN -> SESSION membership rows,
//! exactly as before. An executor run's log is numbered by its host: its
//! window's turns are the run's derived speech TURN in the run's derived
//! compaction session, which no membership row witnesses, and a derived id
//! is never passed off as a witnessed one. Its packet binds instead to the
//! run's retained replay record, read again here from the vault the summary
//! lands in: the span must be steps the run committed.

use super::{
    CompactionPacket, CompactionSnapshotRef, ValidatedCompactionPacket, validate_payload_kind,
    validate_payload_shape, validate_schema_version, validate_snapshot_match,
    validate_snapshot_ref, validate_turn_ids_non_empty,
};
use crate::entity_id::EntityId;
use crate::error::{CompactionPacketError, Error, Result};
use crate::vault::Vault;

/// Where a packet's turns were cut from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionSource<'a> {
    /// A conversation: the witnessed membership checks.
    Conversation,
    /// An executor run's host-numbered log.
    HostLog(CompactionHostLog<'a>),
}

/// An executor run's retained steps `first..=last`, by its host-derived run
/// source and its run id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionHostLog<'a> {
    pub run_ref: &'a str,
    pub run_id: EntityId,
    pub first: u64,
    pub last: u64,
}

/// What a host-log packet was admitted against. The witness keeps it, so a
/// landing can check the packet is its gated request's own run and span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostLogWitness {
    pub(crate) run_id: EntityId,
    pub(crate) first: u64,
    pub(crate) last: u64,
}

/// The packet door with its source named: a conversation's packet passes
/// [`super::admit_compaction_packet`] unchanged; a host log's passes the same
/// shape and snapshot axes, then its run's retained evidence. Read-only, as
/// the door is.
pub fn admit_compaction_source(
    vault: &Vault,
    p: CompactionPacket,
    source: CompactionSource<'_>,
    expected_snapshot: Option<&CompactionSnapshotRef>,
) -> Result<ValidatedCompactionPacket> {
    match source {
        CompactionSource::Conversation => {
            super::admit_compaction_packet(vault, p, expected_snapshot)
        }
        CompactionSource::HostLog(log) => admit_host_log(vault, p, log, expected_snapshot),
    }
}

fn admit_host_log(
    vault: &Vault,
    p: CompactionPacket,
    log: CompactionHostLog<'_>,
    expected_snapshot: Option<&CompactionSnapshotRef>,
) -> Result<ValidatedCompactionPacket> {
    validate_schema_version(p.schema_version)?;
    let payload_kind = validate_payload_kind(p.payload_kind)?;
    validate_payload_shape(&p, payload_kind)?;
    validate_snapshot_ref(&p.snapshot)?;
    validate_snapshot_match(&p.snapshot, expected_snapshot)?;
    validate_turn_ids_non_empty(&p.turn_ids)?;

    let session = crate::code_run::executor_compaction_session_id(log.run_ref, log.run_id)?;
    if p.session_ref != session {
        return Err(CompactionPacketError::UnknownSession {
            session: p.session_ref,
        }
        .into());
    }
    let turn = crate::code_run::executor_speech_turn_id_for_run(log.run_ref, log.run_id)?;
    if let Some(other) = p.turn_ids.iter().find(|id| **id != turn) {
        return Err(CompactionPacketError::TurnFromOtherSession {
            turn: *other,
            recorded: session,
        }
        .into());
    }
    // The retained evidence: the run's own replay record on this vault, its
    // steps committed through the span's end.
    let record = vault
        .get_code_run_replay_record(&log.run_id)?
        .ok_or(CompactionPacketError::UnknownSession { session })?;
    let committed = u64::try_from(record.step_checkpoints.len())
        .map_err(|_| Error::ArithmeticOverflow("executor step count"))?;
    if record.run_id != log.run_id || log.first > log.last || log.last >= committed {
        return Err(CompactionPacketError::PayloadShapeViolation(
            "the host-log span is not steps its run committed",
        )
        .into());
    }
    Ok(ValidatedCompactionPacket {
        packet: p,
        payload_kind,
        host_log: Some(HostLogWitness {
            run_id: log.run_id,
            first: log.first,
            last: log.last,
        }),
    })
}
