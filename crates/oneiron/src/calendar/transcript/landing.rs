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
    let hint = crate::session_lifecycle::SessionHintTimestamp {
        claimed_ms: parsed.claimed_started_ms,
        arrival_ms: request.arrived_at_ms,
        effective_ms: request.arrived_at_ms,
    };
    match vault.mint_session_from_hint_in_txn(wtxn, session_key, hint)? {
        crate::session_lifecycle::SessionMintOutcome::AlreadyOpen(id) => {
            Ok(TranscriptIngestOutcome::RetryOpenSession {
                open_session_ref: id,
            })
        }
        crate::session_lifecycle::SessionMintOutcome::Minted(session_ref) => {
            let turn_refs = persist_turns(
                vault,
                wtxn,
                request.source_blob_ref,
                session_ref,
                &parsed.turns,
                request.arrived_at_ms,
                source_version,
            )?;
            let wake = vault.plan_session_end_wake_in_txn(wtxn, &session_ref)?;
            let wake_turn_refs = wake.planned_turn_ids.clone();
            let end_hint = crate::session_lifecycle::SessionHintTimestamp {
                claimed_ms: parsed.claimed_ended_ms,
                arrival_ms: request.arrived_at_ms,
                effective_ms: request.arrived_at_ms,
            };
            vault
                .end_session_with_wake_and_hint_in_txn(
                    wtxn,
                    &session_ref,
                    crate::session_lifecycle::SessionClosePredicate::Explicit,
                    request.arrived_at_ms / 1000,
                    &wake,
                    Some(end_hint),
                )?
                .ok_or(crate::Error::InvariantViolation(
                    "file-drop session was not closed",
                ))?;
            // Exercise transaction rollback only after close and its wake writes landed.
            if fail_after_turns {
                return Err(crate::Error::InvariantViolation(
                    "file-drop transcript test failure injection",
                ));
            }
            Ok(TranscriptIngestOutcome::Session {
                session_ref,
                turn_refs,
                wake_turn_refs,
                extraction_enqueued: !wake.plans.is_empty(),
            })
        }
    }
}
