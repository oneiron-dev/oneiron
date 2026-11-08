//! An explicit owner POST approves the complete binding returned by read.

use super::*;
use oneiron::calendar::transcript::TranscriptIngestOutcome;
use oneiron::ingest::meeting_audio::{
    AudioError, AudioResult, BulkImportAuthorizer, BulkImportReceipt,
    MeetingTranscriptCallerImportOutcome, MeetingTranscriptNoteOutcome,
};
use oneiron::note::ImportedNoteStanding;

use crate::api::scoped_auth::credential_memory;
use crate::server::meeting_imports::import_error;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/meeting-transcripts/import",
                summary: "Approve and import the complete selected meeting artifact.",
                row: None,
                shape: Some(RestShape::json(import_schema, reply_schema)),
            },
            post(import),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/meeting-transcripts/import/resume",
                summary: "Continue the original meeting import after answering its hook ask.",
                row: None,
                shape: Some(RestShape::json(continuation_schema, reply_schema)),
            },
            post(resume),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/meeting-transcripts/import/discard",
                summary: "Forget a retained meeting import; never undo an import already committed.",
                row: None,
                shape: Some(RestShape::json(continuation_schema, discard_schema)),
            },
            post(discard),
        ),
    ]
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ImportRequest {
    stored: StoredTranscript,
    /// The complete binding reviewed by the owner, returned by read.
    binding: BulkImportBinding,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ContinuationRequest {
    session_ref: String,
}

#[derive(Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ImportReply {
    HookPending {
        session_ref: String,
        ask: String,
    },
    Imported {
        session: Option<TranscriptIngestOutcome>,
        note_fallback: Option<NoteReply>,
        stored: StoredTranscript,
        bulk_receipt: BulkImportReceipt,
    },
}

#[derive(Serialize, schemars::JsonSchema)]
struct NoteReply {
    note_ref: String,
    standing: &'static str,
}

#[derive(Serialize, schemars::JsonSchema)]
struct DiscardReply {
    removed: bool,
}

fn import_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ImportRequest>()
}

fn continuation_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ContinuationRequest>()
}

fn reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ImportReply>()
}

fn discard_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<DiscardReply>()
}

/// Constructed only after the actual owner door admits the explicit import
/// action. The requested binding is untrusted until the native callback's
/// independently derived binding equals it in full.
struct OwnerImportApproval {
    scope: String,
    reviewed: BulkImportBinding,
    receipt_ref: String,
}

impl BulkImportAuthorizer for OwnerImportApproval {
    fn vault_scope(&self) -> &str {
        &self.scope
    }

    fn authorize_import(
        &mut self,
        binding: &BulkImportBinding,
    ) -> AudioResult<Option<BulkImportReceipt>> {
        if binding != &self.reviewed {
            return Err(AudioError::BulkConsentMismatch);
        }
        Ok(Some(BulkImportReceipt {
            binding: binding.clone(),
            receipt_ref: self.receipt_ref.clone(),
        }))
    }
}

async fn import(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ImportRequest>,
) -> OwnerReply<ImportReply> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || {
        let stored = native_stored(&request.stored)?;
        let memory = credential_memory(
            server.vault(),
            Some(&auth),
            owner.actor_for_read(server.vault())?,
            oneiron::EdgeActorClass::Human,
        );
        let mut approval = OwnerImportApproval {
            scope: import_scope(server.vault()),
            reviewed: request.binding,
            receipt_ref: server.vault().new_entity_id()?.to_hex(),
        };
        let mut attempt = server
            .vault()
            .prepare_owned_meeting_transcript_import_as_owner(
                &memory,
                &owner,
                &stored,
                &mut approval,
            )
            .map_err(import_error)?;
        let result = attempt.resume(&memory, &owner).map_err(import_error)?;
        if let MeetingTranscriptCallerImportOutcome::HookPending { session_ref, .. } = &result {
            server.meeting_imports.retain(*session_ref, attempt)?;
        }
        Ok(ImportReply::from(result))
    })
    .await?;
    Ok(Json(reply))
}

async fn resume(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ContinuationRequest>,
) -> OwnerReply<ImportReply> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || {
        let session = entity_id("session_ref", &request.session_ref)?;
        let memory = credential_memory(
            server.vault(),
            Some(&auth),
            owner.actor_for_read(server.vault())?,
            oneiron::EdgeActorClass::Human,
        );
        server
            .meeting_imports
            .resume(session, &memory, &owner)
            .map(ImportReply::from)
    })
    .await?;
    Ok(Json(reply))
}

async fn discard(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ContinuationRequest>,
) -> OwnerReply<DiscardReply> {
    let _owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || {
        let session = entity_id("session_ref", &request.session_ref)?;
        Ok(DiscardReply {
            removed: server.meeting_imports.discard(session)?,
        })
    })
    .await?;
    Ok(Json(reply))
}

impl From<MeetingTranscriptCallerImportOutcome> for ImportReply {
    fn from(result: MeetingTranscriptCallerImportOutcome) -> Self {
        match result {
            MeetingTranscriptCallerImportOutcome::HookPending { session_ref, ask } => {
                Self::HookPending {
                    session_ref: session_ref.to_hex(),
                    ask: ask.to_hex(),
                }
            }
            MeetingTranscriptCallerImportOutcome::Imported(result) => Self::Imported {
                session: result.session,
                note_fallback: result.note_fallback.map(|note| match note {
                    MeetingTranscriptNoteOutcome::Landed { note_ref } => NoteReply {
                        note_ref: note_ref.to_hex(),
                        standing: "landed",
                    },
                    MeetingTranscriptNoteOutcome::Retained { note_ref, standing } => NoteReply {
                        note_ref: note_ref.to_hex(),
                        standing: match standing {
                            ImportedNoteStanding::New => "new",
                            ImportedNoteStanding::Unchanged => "unchanged",
                            ImportedNoteStanding::Changed => "changed",
                            ImportedNoteStanding::Removed => "removed",
                            ImportedNoteStanding::Refused => "refused",
                        },
                    },
                }),
                stored: StoredTranscript::from(&result.stored),
                bulk_receipt: result.bulk_receipt,
            },
        }
    }
}
