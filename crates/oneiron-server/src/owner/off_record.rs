//! Off-record sessions (ARCH-0052, OF-326): enter a room whose writes land
//! in an in-memory overlay, witness turns into it, flip it on or off the
//! record, promote chosen turns through the ordinary write door, and close
//! it. Close drops everything not promoted; nothing of the room reaches the
//! vault, its indexes, sync or exports otherwise. An anonymous session keeps
//! nothing at all and cannot be flipped or promoted.
//!
//! The room lives in this server process: a restart ends it, and nothing of
//! it survives.

use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::memory::{MemoryError, WitnessReceipt, WitnessTurn};
use oneiron::off_record::{
    OffRecordBackendClass, OffRecordMode, OffRecordSession, OffRecordSessionRecord,
};
use oneiron::{EntityId, ErrorKind, Vault};
use serde::{Deserialize, Serialize};

use super::stamp::rfc3339_secs;
use super::{OwnerError, OwnerResult, entity_id};

/// How a session starts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EnterMode {
    /// Turns stay in the room until promoted or dropped at close.
    OffRecord,
    /// No transcript, memory, telemetry or receipt is kept.
    Anonymous,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Enter {
    /// The host's own name for the session, 1 to 256 bytes.
    pub(crate) session_ref: String,
    pub(crate) mode: EnterMode,
    /// `local` when inference stays on this device, `remote_provider` when a
    /// model provider sees the turns (and may keep what it saw).
    pub(crate) backend: OffRecordBackendClass,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Flip {
    pub(crate) session_ref: String,
    /// `on_record` saves later turns as ordinary memory; `off_record` goes
    /// back to the overlay.
    pub(crate) mode: OffRecordMode,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Witness {
    pub(crate) session_ref: String,
    /// The turn, as `POST /v1/core/facade/witness` takes it; leave
    /// `conversation_ref` empty to write into the room's own conversation.
    pub(crate) turn: WitnessTurn,
    /// A summary of the turn; it stays in the room with the turn.
    #[serde(default)]
    pub(crate) summary: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Promote {
    pub(crate) session_ref: String,
    /// The turn id from the witness receipt's `receipt_ref`.
    pub(crate) turn: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionName {
    pub(crate) session_ref: String,
}

/// One live session as the owner sees it.
#[derive(Debug, Serialize)]
pub(crate) struct Session {
    pub(crate) session_ref: String,
    /// `off_record`, `on_record` or `anonymous`.
    pub(crate) mode: OffRecordMode,
    pub(crate) backend: OffRecordBackendClass,
    pub(crate) entered_at: String,
    /// Turns already saved to the vault; close keeps them.
    pub(crate) promoted_turns: Vec<String>,
    pub(crate) closing: bool,
}

impl From<OffRecordSessionRecord> for Session {
    fn from(record: OffRecordSessionRecord) -> Self {
        Self {
            session_ref: record.session_ref,
            mode: record.mode,
            backend: record.backend,
            entered_at: rfc3339_secs(record.entered_at),
            promoted_turns: record
                .promoted_turns
                .iter()
                .map(|turn| turn.iter().map(|byte| format!("{byte:02x}")).collect())
                .collect(),
            closing: record.closing,
        }
    }
}

/// What a promote wrote to the vault.
#[derive(Debug, Serialize)]
pub(crate) struct Promoted {
    /// Every row that entered the vault, by id.
    pub(crate) replayed: Vec<String>,
    /// Each in-room short id beside the vault's own short id for that row.
    pub(crate) short_ids: Vec<ShortIdPair>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ShortIdPair {
    pub(crate) room: String,
    pub(crate) vault: String,
}

/// What a save of the whole talk wrote to the vault.
#[derive(Debug, Serialize)]
pub(crate) struct Saved {
    pub(crate) saved: Vec<SavedTurn>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SavedTurn {
    pub(crate) turn: String,
    #[serde(flatten)]
    pub(crate) promoted: Promoted,
}

/// What close dropped and what it kept.
#[derive(Debug, Serialize)]
pub(crate) struct Closed {
    pub(crate) session_ref: String,
    pub(crate) turns_dropped: usize,
    pub(crate) context_receipts_dropped: usize,
    pub(crate) emit_receipts_dropped: usize,
    /// Emit receipts recorded after the session went on record.
    pub(crate) emit_receipts_kept: usize,
    pub(crate) promoted_turns_kept: usize,
}

pub(crate) fn enter(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &Enter,
) -> OwnerResult<Session> {
    vault.recheck_owner(owner)?;
    let rooms = vault.off_record_session_vault();
    let session = match request.mode {
        EnterMode::OffRecord => rooms.enter(&request.session_ref, request.backend),
        EnterMode::Anonymous => rooms.enter_anonymous(&request.session_ref, request.backend),
    }
    .map_err(|error| session_error(error, &request.session_ref))?;
    record(vault, owner, session.session_ref())
}

pub(crate) fn record(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    session_ref: &str,
) -> OwnerResult<Session> {
    let not_found = || OwnerError::NotFound("off-record session", session_ref.to_owned());
    let record = vault
        .off_record_session(session_ref)
        .map_err(|error| session_error(error, session_ref))?
        .ok_or_else(not_found)?;
    // A stretch in a room the owner is not in is the same 404 as none.
    if let Some(room) = record.room {
        let room = EntityId::from_bytes(room).map_err(OwnerError::from)?;
        if !vault.members(room)?.contains(&owner.actor()) {
            return Err(not_found());
        }
    }
    Ok(Session::from(record))
}

pub(crate) fn flip(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &Flip,
) -> OwnerResult<Session> {
    vault.recheck_owner(owner)?;
    let session = bind(vault, owner, &request.session_ref)?;
    match request.mode {
        OffRecordMode::OnRecord => session.flip_on_record_as(owner),
        OffRecordMode::OffRecord => session.flip_off_record(),
        OffRecordMode::Anonymous => {
            return Err(OwnerError::Invalid(
                "anonymous is chosen when a session starts, never by a flip".to_owned(),
            ));
        }
    }
    .map_err(|error| session_error(error, &request.session_ref))?;
    record(vault, owner, &request.session_ref)
}

/// Witnesses one turn into the session as the owner.
pub(crate) fn witness(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &Witness,
) -> OwnerResult<WitnessReceipt> {
    vault.recheck_owner(owner)?;
    let session = bind(vault, owner, &request.session_ref)?;
    vault
        .memory(owner.actor(), EdgeActorClass::Human)
        .witness_into_session_as(owner, &session, &request.turn, request.summary.as_deref())
        .map_err(|error| {
            // The proof is rechecked where the turn lands; one revoked while
            // the witness waited is the same refusal as at the door.
            if let Err(refusal) = vault.recheck_owner(owner) {
                return OwnerError::from(refusal);
            }
            witness_error(error)
        })
}

fn witness_error(error: MemoryError) -> OwnerError {
    match error.code.as_str() {
        oneiron::memory::MEMORY_CODE_BAD_REQUEST => OwnerError::Invalid(error.message),
        oneiron::memory::MEMORY_CODE_FORBIDDEN => OwnerError::Refused(error.message),
        oneiron::memory::MEMORY_CODE_INVALID_STATE => OwnerError::Changed(error.message),
        _ => OwnerError::Host(anyhow::anyhow!(
            "witness into off-record session: {}",
            error.message
        )),
    }
}

pub(crate) fn promote(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &Promote,
) -> OwnerResult<Promoted> {
    vault.recheck_owner(owner)?;
    let turn = entity_id("turn", &request.turn)?;
    let session = bind(vault, owner, &request.session_ref)?;
    let outcome = session
        .promote_turn_as(owner, &turn)
        .map_err(|error| session_error(error, &request.session_ref))?;
    Ok(Promoted {
        replayed: outcome.replayed.iter().map(EntityId::to_hex).collect(),
        short_ids: outcome
            .short_id_mapping
            .into_iter()
            .map(|(room, vault)| ShortIdPair { room, vault })
            .collect(),
    })
}

/// Saves every turn of the talk nobody saved yet, in one transaction.
pub(crate) fn save(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &SessionName,
) -> OwnerResult<Saved> {
    vault.recheck_owner(owner)?;
    let session = bind(vault, owner, &request.session_ref)?;
    let saved = session
        .save_talk_as(owner)
        .map_err(|error| session_error(error, &request.session_ref))?;
    Ok(Saved {
        saved: saved
            .into_iter()
            .map(|(turn, outcome)| SavedTurn {
                turn: turn.to_hex(),
                promoted: Promoted {
                    replayed: outcome.replayed.iter().map(EntityId::to_hex).collect(),
                    short_ids: outcome
                        .short_id_mapping
                        .into_iter()
                        .map(|(room, vault)| ShortIdPair { room, vault })
                        .collect(),
                },
            })
            .collect(),
    })
}

pub(crate) fn close(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    session_ref: &str,
) -> OwnerResult<Closed> {
    vault.recheck_owner(owner)?;
    let outcome = bind(vault, owner, session_ref)?
        .close()
        .map_err(|error| session_error(error, session_ref))?;
    Ok(Closed {
        session_ref: session_ref.to_owned(),
        turns_dropped: outcome.turns_deleted,
        context_receipts_dropped: outcome.context_receipts_deleted,
        emit_receipts_dropped: outcome.emit_receipts_deleted,
        emit_receipts_kept: outcome.emit_receipts_retained.len(),
        promoted_turns_kept: outcome.promoted_turns_kept,
    })
}

/// The session, when the owner may act on it: their own 1:1, or a stretch in
/// a room they are in. Any other room's stretch is the same 404 as none.
fn bind<'vault>(
    vault: &'vault Vault,
    owner: &AuthenticatedOwner,
    session_ref: &str,
) -> OwnerResult<OffRecordSession<'vault>> {
    let session = vault
        .off_record_session_vault()
        .bind(session_ref)
        .map_err(|error| session_error(error, session_ref))?;
    if session
        .room()
        .map_err(|error| session_error(error, session_ref))?
        .is_some()
    {
        session
            .require_in_room(owner.actor())
            .map_err(|error| session_error(error, session_ref))?;
    }
    Ok(session)
}

fn session_error(error: oneiron::Error, session_ref: &str) -> OwnerError {
    match error.kind() {
        ErrorKind::OffRecordSessionNotFound | ErrorKind::OffRecordNotInRoom => {
            OwnerError::NotFound("off-record session", session_ref.to_owned())
        }
        ErrorKind::OffRecordSessionClosing => {
            OwnerError::Changed(format!("off-record session {session_ref} is closing"))
        }
        ErrorKind::OffRecordSessionAlreadyExists => {
            OwnerError::Changed(format!("off-record session {session_ref} already exists"))
        }
        ErrorKind::KillSwitchDisabled => {
            OwnerError::Refused("off-record sessions are turned off for this vault".to_owned())
        }
        ErrorKind::OffRecordTalkOnly => OwnerError::Refused(format!(
            "session {session_ref} is anonymous: it keeps nothing, so it cannot be saved or flipped"
        )),
        ErrorKind::OffRecordOverlayFull => OwnerError::Refused(
            "the session is full; promote or close it before writing more".to_owned(),
        ),
        _ => OwnerError::from(error),
    }
}
