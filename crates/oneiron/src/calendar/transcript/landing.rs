//! Shared mint/turn/close/wake landing for typed transcript inputs.

use super::{ParsedTranscript, TranscriptFileDropRequest, TranscriptIngestOutcome, persist_turns};

/// The shared landing used by the host helper and the caller-bound public door.
pub(super) fn ingest_parsed_transcript_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    request: TranscriptFileDropRequest<'_>,
    parsed: &ParsedTranscript,
    session_key: crate::session_lifecycle::SessionKey,
    fail_after_turns: bool,
    source_version: Option<&crate::blob_artifact::BlobArtifactVersion>,
) -> crate::Result<TranscriptIngestOutcome> {
    land(
        vault,
        wtxn,
        request,
        parsed,
        session_key,
        fail_after_turns,
        source_version,
        None,
        None,
    )
    .map(|landed| landed.outcome)
}

pub(super) struct TranscriptLanding {
    pub outcome: TranscriptIngestOutcome,
    pub ended: Option<crate::session_lifecycle::EndedSession>,
}

pub(super) fn ingest_prepared_transcript_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    request: TranscriptFileDropRequest<'_>,
    parsed: &ParsedTranscript,
    hint: &crate::session_lifecycle::SessionImportHint,
    pre: &crate::session_lifecycle::SessionImportPre,
    source_version: &crate::blob_artifact::BlobArtifactVersion,
) -> crate::Result<TranscriptLanding> {
    land(
        vault,
        wtxn,
        request,
        parsed,
        hint.key(),
        false,
        Some(source_version),
        Some((hint, pre)),
        None,
    )
}

pub(crate) fn ingest_meeting_transcript_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    request: TranscriptFileDropRequest<'_>,
    parsed: &ParsedTranscript,
    session_key: crate::session_lifecycle::SessionKey,
    source_version: &crate::blob_artifact::BlobArtifactVersion,
    source: &crate::ingest::meeting_audio::MeetingImportProvenance,
) -> crate::Result<TranscriptIngestOutcome> {
    land(
        vault,
        wtxn,
        request,
        parsed,
        session_key,
        false,
        Some(source_version),
        None,
        Some(source),
    )
    .map(|landed| landed.outcome)
}

pub(crate) fn ingest_prepared_meeting_transcript_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    request: TranscriptFileDropRequest<'_>,
    parsed: &ParsedTranscript,
    hint: &crate::session_lifecycle::SessionImportHint,
    pre: &crate::session_lifecycle::SessionImportPre,
    source_version: &crate::blob_artifact::BlobArtifactVersion,
    source: &crate::ingest::meeting_audio::MeetingImportProvenance,
) -> crate::Result<(
    TranscriptIngestOutcome,
    Option<crate::session_lifecycle::EndedSession>,
)> {
    land(
        vault,
        wtxn,
        request,
        parsed,
        hint.key(),
        false,
        Some(source_version),
        Some((hint, pre)),
        Some(source),
    )
    .map(|landed| (landed.outcome, landed.ended))
}

pub(super) fn land(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    request: TranscriptFileDropRequest<'_>,
    parsed: &ParsedTranscript,
    session_key: crate::session_lifecycle::SessionKey,
    fail_after_turns: bool,
    source_version: Option<&crate::blob_artifact::BlobArtifactVersion>,
    hooks: Option<(
        &crate::session_lifecycle::SessionImportHint,
        &crate::session_lifecycle::SessionImportPre,
    )>,
    meeting_source: Option<&crate::ingest::meeting_audio::MeetingImportProvenance>,
) -> crate::Result<TranscriptLanding> {
    let hint = crate::session_lifecycle::SessionHintTimestamp {
        claimed_ms: parsed.claimed_started_ms,
        arrival_ms: request.arrived_at_ms,
        effective_ms: request.arrived_at_ms,
    };
    let minted = match hooks {
        Some((prepared, _)) => vault.mint_import_session_in_txn(wtxn, prepared)?,
        None => vault.mint_session_from_hint_in_txn(wtxn, session_key, hint)?,
    };
    match minted {
        crate::session_lifecycle::SessionMintOutcome::AlreadyOpen(id) => Ok(TranscriptLanding {
            outcome: TranscriptIngestOutcome::RetryOpenSession {
                open_session_ref: id,
            },
            ended: None,
        }),
        crate::session_lifecycle::SessionMintOutcome::Minted(session_ref) => {
            let turn_refs = match meeting_source {
                Some(source) => super::persist_turns_with_source(
                    vault,
                    wtxn,
                    request.source_blob_ref,
                    session_ref,
                    &parsed.turns,
                    request.arrived_at_ms,
                    source_version,
                    Some(source),
                ),
                None => persist_turns(
                    vault,
                    wtxn,
                    request.source_blob_ref,
                    session_ref,
                    &parsed.turns,
                    request.arrived_at_ms,
                    source_version,
                ),
            }?;
            let wake = vault.plan_session_end_wake_in_txn(wtxn, &session_ref)?;
            let wake_turn_refs = wake.planned_turn_ids.clone();
            let end_hint = crate::session_lifecycle::SessionHintTimestamp {
                claimed_ms: parsed.claimed_ended_ms,
                arrival_ms: request.arrived_at_ms,
                effective_ms: request.arrived_at_ms,
            };
            let ended = match hooks {
                Some((prepared, pre)) => {
                    vault.close_import_session_in_txn(wtxn, prepared, pre, &wake)?
                }
                None => vault.end_session_with_wake_and_hint_in_txn(
                    wtxn,
                    &session_ref,
                    crate::session_lifecycle::SessionClosePredicate::Explicit,
                    request.arrived_at_ms / 1000,
                    &wake,
                    Some(end_hint),
                )?,
            }
            .ok_or(crate::Error::InvariantViolation(
                "file-drop session was not closed",
            ))?;
            // Exercise transaction rollback only after close and its wake writes landed.
            if fail_after_turns {
                return Err(crate::Error::InvariantViolation(
                    "file-drop transcript test failure injection",
                ));
            }
            Ok(TranscriptLanding {
                outcome: TranscriptIngestOutcome::Session {
                    session_ref,
                    turn_refs,
                    wake_turn_refs,
                    extraction_enqueued: !wake.plans.is_empty(),
                },
                ended: Some(ended),
            })
        }
    }
}
