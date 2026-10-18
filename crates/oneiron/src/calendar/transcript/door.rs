//! Caller-bound file-drop ingestion over the calendar transcript landing.
use serde::{Deserialize, Serialize};

use crate::claim::ClaimReadStatus;
use crate::memory::{MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult};
use crate::note::TakeTarget;
use crate::session_lifecycle::SessionKey;
use crate::EntityId;

use super::{TranscriptFileDropRequest, TranscriptIngestOutcome, TranscriptParse};

/// One uploaded UTF-8 transcript. `decoded_text` must match the stored head's
/// bytes exactly; it is not caller-asserted evidence for a different blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TranscriptFileDropInput {
    pub source_blob_ref: String,
    pub decoded_text: String,
    pub arrived_at_ms: u64,
}

impl Memory<'_> {
    /// Ingests the uploaded text as the bound caller, retaining source labels
    /// without treating them as verified speaker identities. Session close,
    /// ordered turns and the SessionEnd wake share the existing landing txn.
    pub fn calendar_transcript_ingest(
        &self,
        input: &TranscriptFileDropInput,
    ) -> MemoryResult<TranscriptIngestOutcome> {
        let source = EntityId::from_hex(&input.source_blob_ref)
            .map_err(|_| MemoryError::bad_request("source_blob_ref is not an entity id"))?;
        let read = self.get_entity(&input.source_blob_ref)?;
        if read.value.is_none() {
            return Err(MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                "transcript source is absent or withheld",
                &["Upload a transcript artifact the caller can read."],
            )
            .with_read_receipt(read.receipt));
        }
        let vault = self.vault();
        let head = vault.blob_artifact_head(&source)?.ok_or_else(|| {
            MemoryError::bad_request("transcript source has no uploaded blob version")
        })?;
        let bytes = self
            .read_blob_version(&input.source_blob_ref, head.version)?
            .ok_or_else(|| MemoryError::bad_request("transcript source bytes are unavailable"))?;
        if bytes != input.decoded_text.as_bytes() {
            return Err(MemoryError::bad_request(
                "decoded_text must match the uploaded UTF-8 transcript bytes",
            ));
        }
        let parsed = super::parsed_ingest_transcript(&input.decoded_text)?;
        self.produced_from([source]);
        let outcome = match parsed {
            TranscriptParse::NoteFallback { text } => {
                // NOTE authorship uses the caller's own gate, never the host
                // import MACHINE's system-class policy.
                let receipt = self.author_take(TakeTarget::Subject(source), text)?;
                TranscriptIngestOutcome::NoteFallback {
                    note_ref: EntityId::from_hex(&receipt.id_hex)?,
                }
            }
            TranscriptParse::Turns(parsed) => {
                let lane = self.read_lane(ClaimReadStatus::Recorded)?;
                self.with_verified_actor_write_txn(|txn| {
                    if !lane.entities_readable_in_txn(txn, &[source])?[0] {
                        return Err(MemoryError::new(
                            MEMORY_CODE_NOT_FOUND,
                            "transcript source is absent or withheld",
                            &["Upload a transcript artifact the caller can read."],
                        ));
                    }
                    let machine = crate::identity::load_or_mint_machine_id_in_txn(vault, txn)?;
                    Ok(super::ingest_parsed_transcript_in_txn(
                        vault,
                        txn,
                        TranscriptFileDropRequest {
                            source_blob_ref: source,
                            decoded_text: &input.decoded_text,
                            arrived_at_ms: input.arrived_at_ms,
                        },
                        &parsed,
                        SessionKey {
                            actor: self.actor(),
                            machine,
                        },
                        false,
                    )?)
                })?
            }
        };
        match &outcome {
            TranscriptIngestOutcome::Session {
                session_ref,
                turn_refs,
                wake_turn_refs,
                ..
            } => self.produced_from(
                std::iter::once(*session_ref)
                    .chain(turn_refs.iter().copied())
                    .chain(wake_turn_refs.iter().copied()),
            ),
            TranscriptIngestOutcome::RetryOpenSession { open_session_ref } => {
                self.produced_from([*open_session_ref]);
            }
            TranscriptIngestOutcome::NoteFallback { note_ref } => {
                self.produced_from([*note_ref]);
            }
        }
        Ok(outcome)
    }
}
