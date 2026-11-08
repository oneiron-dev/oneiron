//! Caller-bound meeting imports over the native prepared-session hook path.

use crate::blob_artifact::BLOB_ARTIFACT_CONTENT_HASH_LEN;
use crate::calendar::transcript::{TranscriptFileDropRequest, TranscriptIngestOutcome};
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use crate::runtime_hooks::verb::VerbHookWaitStatus;
use crate::session_lifecycle::{SessionHintTimestamp, SessionImportHint, SessionKey};
use crate::{EntityId, Error};

use super::session_source::MeetingImportProvenance;
use super::{
    AudioError, AuthorizedMeetingImport, BulkImportAuthorizer, MeetingTranscriptImportOutcome,
    MeetingTranscriptSessionInput, StoredMeetingTranscript,
};

#[derive(Debug, thiserror::Error)]
pub enum MeetingTranscriptCallerImportError {
    #[error(transparent)]
    Storage(#[from] Error),
    #[error(transparent)]
    Audio(#[from] AudioError),
    #[error(transparent)]
    Caller(#[from] MemoryError),
}

mod owned;
pub use owned::OwnedMeetingTranscriptImportAttempt;

type Result<T> = std::result::Result<T, MeetingTranscriptCallerImportError>;

/// A pending hook has not landed either the SESSION or the NOTE. Resume the
/// same attempt after answering its ask; do not prepare another hook identity.
#[derive(Debug)]
pub enum MeetingTranscriptCallerImportOutcome {
    Imported(MeetingTranscriptImportOutcome),
    HookPending {
        session_ref: EntityId,
        ask: EntityId,
    },
}

/// An in-memory attempt, borrowing the actual caller and owner proof. It is
/// neither a serialized credential nor a durable queue. One fresh bulk consent
/// covers this attempt's exact artifact, including its hook continuations.
/// A completed attempt cannot import another SESSION.
pub struct MeetingTranscriptImportAttempt<'caller, 'vault> {
    memory: &'caller Memory<'vault>,
    owner: &'caller AuthenticatedOwner,
    state: MeetingTranscriptImportState,
}

struct MeetingTranscriptImportState {
    authorized: AuthorizedMeetingImport,
    input: MeetingTranscriptSessionInput,
    source: MeetingImportProvenance,
    hint: Option<SessionImportHint>,
    arrived_at_ms: u64,
    ask: Option<EntityId>,
    completed: bool,
}

impl<'vault> Memory<'vault> {
    /// Prepare an import as this actual owner's Human caller. Both selected
    /// versions must be readable through this handle, not just through the
    /// separate owner proof. The bulk callback runs outside any writer.
    /// Retain the returned attempt while a session-open hook is pending.
    pub fn prepare_meeting_transcript_import_as_owner<'caller, A: BulkImportAuthorizer + ?Sized>(
        &'caller self,
        owner: &'caller AuthenticatedOwner,
        stored: &StoredMeetingTranscript,
        authorizer: &mut A,
    ) -> Result<MeetingTranscriptImportAttempt<'caller, 'vault>> {
        Ok(MeetingTranscriptImportAttempt {
            memory: self,
            owner,
            state: MeetingTranscriptImportState::prepare(self, owner, stored, authorizer)?,
        })
    }
}

impl MeetingTranscriptImportAttempt<'_, '_> {
    /// Run native pre-hooks, then land the selected SESSION and NOTE in one
    /// writer. Native storage failures rearm consumed hook answers. Posts run
    /// only after commit, with the actual native EndedSession.
    pub fn resume(&mut self) -> Result<MeetingTranscriptCallerImportOutcome> {
        self.state.resume(self.memory, self.owner)
    }
}

impl MeetingTranscriptImportState {
    fn prepare<A: BulkImportAuthorizer + ?Sized>(
        memory: &Memory<'_>,
        owner: &AuthenticatedOwner,
        stored: &StoredMeetingTranscript,
        authorizer: &mut A,
    ) -> Result<Self> {
        let vault = memory.vault();
        {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            check_owner(memory, owner, &txn)?;
        }
        check_read_versions(memory, stored)?;
        let artifact = vault.read_meeting_transcript_as_owner(owner, stored)?;
        let authorized = artifact.authorize_import(authorizer)?;
        let input = authorized.artifact().session_input()?;
        let source = MeetingImportProvenance {
            stored: stored.clone(),
            receipt: authorized.receipt().clone(),
        };
        let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
        let (arrived_at_ms, hint) =
            vault.write_txn_door(crate::store::Callback::Audited, |txn| {
                memory.verify_actor_write_in_txn(txn)?;
                check_owner(memory, owner, txn)?;
                check_read_versions_in_txn(memory, &lane, txn, stored)?;
                let arrived_at_ms = vault
                    .instant_in_write_txn(txn)?
                    .secs()
                    .checked_mul(1_000)
                    .ok_or(Error::InvariantViolation("meeting import arrival overflow"))?;
                let hint = if input.transcript.turns.is_empty() {
                    None
                } else {
                    let machine = crate::identity::load_or_mint_machine_id_in_txn(vault, txn)?;
                    Some(vault.prepare_session_import_hint(
                        SessionKey {
                            actor: memory.actor(),
                            machine,
                        },
                        SessionHintTimestamp {
                            claimed_ms: input.transcript.claimed_started_ms,
                            arrival_ms: arrived_at_ms,
                            effective_ms: arrived_at_ms,
                        },
                        SessionHintTimestamp {
                            claimed_ms: input.transcript.claimed_ended_ms,
                            arrival_ms: arrived_at_ms,
                            effective_ms: arrived_at_ms,
                        },
                    )?)
                };
                Ok::<_, MeetingTranscriptCallerImportError>((arrived_at_ms, hint))
            })?;
        Ok(Self {
            authorized,
            input,
            source,
            hint,
            arrived_at_ms,
            ask: None,
            completed: false,
        })
    }

    fn resume(
        &mut self,
        memory: &Memory<'_>,
        owner: &AuthenticatedOwner,
    ) -> Result<MeetingTranscriptCallerImportOutcome> {
        if self.completed {
            return Err(
                MemoryError::bad_request("meeting import attempt already completed").into(),
            );
        }
        let vault = memory.vault();
        {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            check_owner(memory, owner, &txn)?;
        }
        check_read_versions(memory, &self.source.stored)?;
        let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
        let pre = if let Some(hint) = &self.hint {
            if let Some(ask) = self.ask {
                match vault.session_import_hook_wait(hint, ask, memory)? {
                    VerbHookWaitStatus::Waiting => {
                        return Ok(MeetingTranscriptCallerImportOutcome::HookPending {
                            session_ref: hint.id(),
                            ask,
                        });
                    }
                    VerbHookWaitStatus::Unavailable => {
                        return Err(MemoryError::bad_request(
                            "meeting saved hook invocation is unavailable",
                        )
                        .into());
                    }
                    VerbHookWaitStatus::Ready => {}
                }
            }
            match vault.pre_session_import_hooks(hint, memory)? {
                Ok(pre) => Some(pre),
                Err(crate::runtime_hooks::VerbHookStop::Pending { ask, .. }) => {
                    let ask = EntityId::from_hex(&ask)?;
                    self.ask = Some(ask);
                    return Ok(MeetingTranscriptCallerImportOutcome::HookPending {
                        session_ref: hint.id(),
                        ask,
                    });
                }
                Err(stop) => return Err(Error::from(stop).into()),
            }
        } else {
            None
        };
        let landed = vault.write_txn_door(crate::store::Callback::Audited, |txn| {
            memory.verify_actor_write_in_txn(txn)?;
            check_owner(memory, owner, txn)?;
            check_read_versions_in_txn(memory, &lane, txn, &self.source.stored)?;
            let (version, _, current) =
                super::persistence::stored_transcript(vault, txn, &self.source.stored)?;
            if current.json() != self.authorized.artifact().json() {
                return Err(
                    Error::InvalidClaimBody("meeting artifact changed during consent").into(),
                );
            }
            let (session, ended) = match (&self.hint, &pre) {
                (Some(hint), Some(pre)) => {
                    let (outcome, ended) =
                        crate::calendar::transcript::ingest_prepared_meeting_transcript_in_txn(
                            vault,
                            txn,
                            TranscriptFileDropRequest {
                                source_blob_ref: self.source.stored.transcript.artifact,
                                decoded_text: self.authorized.artifact().json(),
                                arrived_at_ms: self.arrived_at_ms,
                            },
                            &self.input.transcript,
                            hint,
                            pre,
                            &version,
                            &self.source,
                        )?;
                    (Some(outcome), ended)
                }
                _ => (None, None),
            };
            let note_fallback = self
                .input
                .note_fallback
                .as_ref()
                .map(|note| {
                    vault.land_meeting_transcript_note_in_txn(
                        txn,
                        memory.actor(),
                        &self.source,
                        note,
                        self.arrived_at_ms / 1_000,
                    )
                })
                .transpose()?;
            Ok::<_, MeetingTranscriptCallerImportError>((session, note_fallback, ended))
        });
        let (session, note_fallback, ended) = match landed {
            Ok(landed) => landed,
            Err(error) => {
                if matches!(&error, MeetingTranscriptCallerImportError::Storage(native)
                    if crate::runtime_hooks::verb::error_failed_storage(native))
                    && let Some(pre) = &pre
                {
                    vault.rearm_session_import_hooks(pre);
                }
                return Err(error);
            }
        };
        // The writer committed, including a possible NOTE beside a busy SESSION.
        self.completed = true;
        if let Some(pre) = pre {
            if matches!(
                session,
                Some(TranscriptIngestOutcome::RetryOpenSession { .. })
            ) {
                vault.rearm_session_import_hooks(&pre);
            } else if let (Some(hint), Some(ended)) = (&self.hint, ended) {
                vault.post_session_import_hooks(hint, pre, &ended);
            }
        }
        if let Some(TranscriptIngestOutcome::Session {
            session_ref,
            turn_refs,
            wake_turn_refs,
            ..
        }) = &session
        {
            memory.produced_from(
                std::iter::once(*session_ref)
                    .chain(turn_refs.iter().copied())
                    .chain(wake_turn_refs.iter().copied()),
            );
        }
        if let Some(TranscriptIngestOutcome::RetryOpenSession { open_session_ref }) = &session {
            memory.produced_from([*open_session_ref]);
        }
        if let Some(
            super::MeetingTranscriptNoteOutcome::Landed { note_ref }
            | super::MeetingTranscriptNoteOutcome::Retained { note_ref, .. },
        ) = &note_fallback
        {
            memory.produced_from([*note_ref]);
        }
        Ok(MeetingTranscriptCallerImportOutcome::Imported(
            MeetingTranscriptImportOutcome {
                session,
                note_fallback,
                stored: self.source.stored.clone(),
                bulk_receipt: self.authorized.receipt().clone(),
            },
        ))
    }
}

fn check_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    txn: &heed::RoTxn<'_>,
) -> Result<()> {
    if owner.revalidate_in_txn(memory.vault(), txn)? != memory.actor()
        || memory.actor_class() != crate::EdgeActorClass::Human
    {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "meeting import acts as the authenticated owner",
            &["Present the owner's own verified credential."],
        )
        .into());
    }
    Ok(())
}

fn check_read_versions(memory: &Memory<'_>, stored: &StoredMeetingTranscript) -> Result<()> {
    for pin in [&stored.transcript, &stored.source_audio] {
        let bytes = memory.read_blob_version(&pin.artifact.to_hex(), pin.version)?;
        check_read_hash(bytes.as_deref(), &pin.content_hash)?;
    }
    Ok(())
}

fn check_read_versions_in_txn(
    memory: &Memory<'_>,
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    stored: &StoredMeetingTranscript,
) -> Result<()> {
    let pins = [&stored.transcript, &stored.source_audio];
    if lane
        .entities_readable_in_txn(txn, &pins.map(|pin| pin.artifact))?
        .iter()
        .any(|readable| !readable)
    {
        return Err(MemoryError::not_found("meeting source is absent or withheld").into());
    }
    for pin in pins {
        let sight = memory.secret_sight_in_txn(txn)?;
        let bytes = memory.vault().read_blob_artifact_version_sighted_in_txn(
            txn,
            &pin.artifact,
            pin.version,
            sight,
        )?;
        check_read_hash(bytes.as_deref(), &pin.content_hash)?;
    }
    Ok(())
}

fn check_read_hash(
    bytes: Option<&[u8]>,
    expected: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<()> {
    if !bytes.is_some_and(|bytes| blake3::hash(bytes).as_bytes() == expected) {
        return Err(MemoryError::not_found("meeting source bytes are absent or withheld").into());
    }
    Ok(())
}
