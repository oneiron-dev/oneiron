//! The nineteen checkpoint getters' pins (UC-10 PR 3, PR 4 and PR 5): one
//! fixed seed and one printed table over the getters as they are, run again
//! after they move onto the shared descriptor. Compiled only under `--cfg
//! oneiron_test_support`; never API.
//!
//! [`seed`] writes one fixed row per placement branch of each getter into a
//! source vault, [`pins`] captures, frames and restores each getter and
//! prints one line per owner, section row, restore and target row. The base
//! and head runs are separate processes, so every id and value is fixed: no
//! clock, no random source, no minted id.
//!
//! The seeds live in the child modules `seed_side_rows`, `seed_bodies` and
//! `seed_documents`; the capture, the restores and the printed lines in
//! `pin_lines`.

use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;
use oneiron_contracts::affect::Vad;
use oneiron_docedit::emit::oracle_cases::sha256_hex;
use oneiron_docedit::live::{OracleReceipt, StepOutcome};
use oneiron_store::entity_doc::side_keys::HexPair;

use crate::Vault;
use crate::agent_dispatch::{
    CheckpointRow, test_checkpoint_body_owner, test_checkpoint_key, test_checkpoint_row_bound,
    test_checkpoint_row_unbound,
};
use crate::artifact_hosting::{
    ArtifactExportRef, ArtifactPointerChannel, ArtifactServeTier,
    put_pins_artifact_admission_in_txn, put_pins_artifact_pointer_in_txn,
    put_pins_serving_blob_in_txn,
};
use crate::attempt_queue::AttemptId;
use crate::blob_artifact::{
    BlobArtifactVersion, BlobVersionProvenance, erase::pins_erased_producer,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::code_document::{
    CodeDocumentFrontier, CodeFileEdit, CodeOpProvenance, PinsCodeDocumentReceipt,
    put_pins_code_document_frontier_in_txn, put_pins_code_document_head_in_txn,
    put_pins_code_document_ingress_in_txn, put_pins_code_document_path_in_txn,
};
use crate::code_revision::{
    CodeCommitMetadata, CodeRevision, CodeRevisionFork, CodeRevisionProposal,
    put_pins_code_revision_frontier_in_txn, put_pins_code_revision_integrity_in_txn,
};
use crate::codebase::{
    put_pins_fork_index_row_in_txn, put_pins_project_index_row_in_txn,
    put_pins_repo_index_row_in_txn, put_pins_scope_index_row_in_txn,
};
use crate::edge::{EdgeActorClass, EdgeKind, encode_edge_value};
use crate::embed::{
    EmbeddingDevice, EmbeddingProvenance, put_pins_media_refusal_in_txn,
    put_pins_media_vector_in_txn,
};
use crate::entity_doc::{
    CitationPin, DocActor, EntityDoc, ForkRecord, ForkStatus, PinsCitationPin, PinsEntityDocHead,
    ProposalBundle, PurgeReceipt, SettleVerb, TextField, TextReceipt,
    put_pins_citation_floor_in_txn, put_pins_citation_pin_in_txn, put_pins_fork_snapshot_in_txn,
    put_pins_head_in_txn,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::identity_topology::{
    StoredIdentityOpAction, StoredIdentityOpEvent, encode_identity_topology_event_body,
    pins_author_attribution_action, pins_undo_action,
};
use crate::model_step_record::DREAMER_STEP_PREDICATE;
use crate::note::documents::{put_pins_note_proposal_doc_in_txn, set_head};
use crate::note::{
    ContextDefault, NoteActor, NoteDocumentView, NoteFork, NoteLandingReceipt,
    NoteOperationReceipt, NoteOverrides, NotePin, NoteReviewBundle, NoteScalarEditOutcome,
    NoteSeal, NoteVerdict, pins_note_proposal_snapshot, put_pins_fork_authority_in_txn,
    put_pins_pin_in_txn, put_pins_receipt_by_request_in_txn, put_pins_request_in_txn,
    put_pins_title_in_txn,
};
use crate::office_body::{
    AnsweringAuthority, BundleVerdict, ForkState, MemberAnswer, MemberVerdict,
    OfficeBodyExportAuthor, OfficeBodyExportRecord, OfficeBodyFork, OfficeBodyKind,
    OfficeBodyProposal, ProposalHeader, ProposalMember, ProposalSettlement, pins_version_key,
    put_pins_author_token_ref_in_txn, put_pins_export_token_ref_in_txn,
    put_pins_live_edit_route_in_txn, put_pins_office_source_in_txn, put_pins_oracle_in_txn,
};
use crate::origin::change_index::ORIGIN_CHANGE_PREDICATE;
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, INTENT_LEDGER_VALUE_KEYS, IntentLedgerError,
    IntentLedgerRecord, OutboundCallRequest,
};
use crate::ports::{DocumentSlot, DocumentUpdateKey, UpdateSeq};
use crate::provenance::ActorStamp;
use crate::provenance::body::{BodyLocation, BodyRef, BodyState, OwnedBody};
use crate::recovery::checkpoint::{getter_bytes_for_owner, getter_capture, getter_restore_in_txn};
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_NOTE,
    ENTITY_TYPE_PERSON, ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_SUSPICIOUS_WAKE,
    ENTITY_TYPE_WORLD_KEY_PAD,
};
use crate::secret_snapshot::SnapshotCustodyReport;
use crate::side_table::{
    self, HexId, LegacyCompact, LegacyJson, Named, Raw, SideCodec, SideKey, SideTable,
};
use crate::source_audience::HeldBack;
use crate::store::GateDecisionId;
use crate::store::Store;
use crate::store::checkpoint_payload::rows::{
    Captured, Getter, OpenedOwnerRows, OwnerRows, Restored,
};
use crate::store::code_snapshot::{CodebaseFileEntry, CodebaseSnapshot, RepoRef};
use crate::store::embedding::InputKind;
use crate::store::note_body::{NoteCore, NoteKind, encode_note_core};
use crate::store::row_birth::RowBirth;
use crate::temporal::TimeRange;
use crate::test_fixtures::entity_record;
use crate::typed_body::{
    BodyActor, TypedBodyFork, TypedBodyHead, TypedForkState, put_pins_erased_receipt_in_txn,
    put_pins_receipt_in_txn,
};
use crate::vault::entity_revision::{
    pins_frontier_document_value, pins_revision_doc_bytes, pins_revision_reference,
    put_pins_entity_revision_doc_in_txn, put_pins_entity_revision_frontier_in_txn,
    put_pins_entity_revision_state_in_txn, put_pins_pending_index_in_txn,
    put_pins_pending_phonetic_in_txn,
};
use crate::write_envelope::WriteActor;
use crate::write_envelope::claim_body::{ClaimBody, ClaimSubject, encode_claim_body};
use crate::write_envelope::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
};

mod pin_lines;
mod seed_bodies;
mod seed_documents;
mod seed_side_rows;

pub use self::pin_lines::pins;
use self::seed_bodies::{
    seed_blob_artifact, seed_code_document, seed_code_revision, seed_office_body,
};
use self::seed_documents::{seed_entities, seed_entity_doc, seed_entity_revision, seed_note};
use self::seed_side_rows::{
    seed_audience, seed_blocked, seed_codebase, seed_embed, seed_ledger, seed_phonetic,
    seed_provenance_birth, seed_provenance_body, seed_text, seed_tool_wait, seed_typed_body,
};

/// The text index's source text, as `store/text_index` declares it.
const TEXT_SOURCE: SideTable<EntityId, Vec<(String, String)>, Named> =
    SideTable::new(&side_table::INDEX_SOURCE_TEXT);

/// The phonetic index source, as `batch/phonetic_apply` declares it.
const PHONETIC_SOURCE: SideTable<EntityId, Vec<String>, Named> =
    SideTable::new(&side_table::BATCH_PHONETIC_INDEX_SOURCE);

/// Body descriptors, as `store/owned_body` declares them.
const BODY: SideTable<(EntityId, EntityId), OwnedBody, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY);

/// Digest holders, as `store/owned_body` declares them.
const BODY_DIGEST: SideTable<([u8; 32], EntityId), EntityId, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY_DIGEST);

/// Codebase snapshots, as `codebase/store` declares them.
const SNAPSHOTS: SideTable<EntityId, CodebaseSnapshot, Raw> =
    SideTable::new(&side_table::CODEBASE_SNAPSHOT);

/// Snapshot custody reports, as `codebase/store` declares them.
const CUSTODY_REPORTS: SideTable<String, SnapshotCustodyReport, Raw> =
    SideTable::new(&side_table::SECRET_SNAPSHOT_CODEBASE_CUSTODY);

/// The repo, project, fork and scope indexes, as `codebase/store` declares
/// them, for the raw dump only: their key types stay private to that module
/// and the seed writes them through its pins helpers.
const REPO_INDEX: SideTable<Vec<u8>, (), Raw> = SideTable::new(&side_table::CODEBASE_REPO_INDEX);
const PROJECT_INDEX: SideTable<Vec<u8>, (), Raw> =
    SideTable::new(&side_table::CODEBASE_PROJECT_INDEX);
const FORK_INDEX: SideTable<Vec<u8>, (), Raw> = SideTable::new(&side_table::CODEBASE_FORK_INDEX);
const SCOPE_INDEX: SideTable<Vec<u8>, (), Raw> = SideTable::new(&side_table::CODEBASE_SCOPE_INDEX);

/// Ledger records, as `outbound_intent_ledger/store` declares them.
const LEDGER: SideTable<[u8; 32], IntentLedgerRecord, Raw> =
    SideTable::new(&side_table::OUTBOUND_INTENT_LEDGER_RECORD);

/// One logical call's index key, as `outbound_intent_ledger/store` spells
/// it: the attempt id (16), then the call sequence big-endian (8). That
/// module's key type is private, so this door spells the same bytes.
#[derive(Clone, Copy, Debug)]
struct CallKey {
    attempt_id: AttemptId,
    call_seq: u64,
}

impl SideKey for CallKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.attempt_id.as_bytes());
        out.extend_from_slice(&self.call_seq.to_be_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (attempt, seq) = bytes.split_at_checked(16)?;
        Some(Self {
            attempt_id: AttemptId::from_bytes(attempt).ok()?,
            call_seq: u64::from_be_bytes(seq.try_into().ok()?),
        })
    }
}

/// The attempt index, as `outbound_intent_ledger/store` declares it.
const ATTEMPT_INDEX: SideTable<CallKey, [u8; 32], Raw> =
    SideTable::new(&side_table::OUTBOUND_INTENT_ATTEMPT_INDEX);

/// The unavailable calls, as the ledger getter declares them. Its value
/// type is private to that getter, so this door writes the same 48 bytes:
/// the bound (32), then the admission clocks big-endian (8 each).
const UNAVAILABLE: SideTable<CallKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::OUTBOUND_INTENT_UNAVAILABLE);

/// The kept call accounting, as the ledger getter declares it. Its value
/// type is private to that getter, so this door writes the same six-entry
/// map the getter's capture cuts out of a record ([`ACCOUNTING_KEYS`]).
const CALL_ACCOUNTING: SideTable<CallKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::OUTBOUND_INTENT_ACCOUNTING);

/// The entries of a record's own map that are its accounting and state.
const ACCOUNTING_KEYS: [&str; 6] = [
    INTENT_LEDGER_VALUE_KEYS[14],
    INTENT_LEDGER_VALUE_KEYS[15],
    INTENT_LEDGER_VALUE_KEYS[16],
    INTENT_LEDGER_VALUE_KEYS[17],
    INTENT_LEDGER_VALUE_KEYS[18],
    INTENT_LEDGER_VALUE_KEYS[19],
];

/// The blocked capture witnesses, as the blocked getter declares them.
const WITNESSES: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::COACH_BLOCKED_SOURCE_OWNER);

/// Media vectors, as `embed/space` declares them, for the raw dump only:
/// the row type stays private to that module.
const MEDIA_VECTOR: SideTable<([u8; 16], EntityId), Vec<u8>, Raw> =
    SideTable::new(&side_table::EMBEDDING_MEDIA_VECTOR);

/// Media device marks, as `embed/device` declares them.
const MEDIA_DEVICE: SideTable<([u8; 16], EntityId), EmbeddingProvenance, Named> =
    SideTable::new(&side_table::EMBEDDING_MEDIA_DEVICE);

/// Media refusals, as `embed/space` declares them, for the raw dump only:
/// the row type stays private to that module.
const MEDIA_REFUSED: SideTable<([u8; 16], EntityId), Vec<u8>, Named> =
    SideTable::new(&side_table::EMBEDDING_MEDIA_REFUSED);

/// The workflow checkpoints, as `agent_dispatch/workflow/tool_wait`
/// declares them.
const TOOL_WAIT: SideTable<EntityId, CheckpointRow, Named> =
    SideTable::new(&side_table::WORKFLOW_TOOL_CHECKPOINT);

/// The historical body-source facts, as `tool_wait/body_sources` declares
/// them: one 80-byte key per fact, an empty value.
const BODY_SOURCE: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::PROVENANCE_BODY_SOURCE);

/// Source-audience bindings, as `source_audience` declares them.
const RECORDS: SideTable<EntityId, EntityId, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_RECORD);

/// Source-audience holds, as `source_audience` declares them.
const HELD: SideTable<EntityId, HeldBack, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_HELD);

/// Typed-body heads, as `typed_body` declares them.
const TB_HEADS: SideTable<EntityId, TypedBodyHead, Named> =
    SideTable::new(&side_table::TYPED_BODY_HEAD);

/// Typed-body documents, as `typed_body` declares them.
const TB_DOCS: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::TYPED_BODY_DOC);

/// Typed-body forks, as `typed_body` declares them.
const TB_FORKS: SideTable<(EntityId, EntityId), TypedBodyFork, Named> =
    SideTable::new(&side_table::TYPED_BODY_FORK);

/// Open forks' documents, as `typed_body` declares them.
const TB_FORK_DOCS: SideTable<(EntityId, EntityId), Vec<u8>, Raw> =
    SideTable::new(&side_table::TYPED_BODY_FORK_DOC);

/// Commit receipts, as `typed_body/receipts` declares them, for the raw dump
/// only: the row type stays private to that module.
const TB_RECEIPTS: SideTable<(EntityId, u64), Vec<u8>, Named> =
    SideTable::new(&side_table::TYPED_BODY_RECEIPT);

/// Row births, as `store/birth_record` declares them.
const ROW_BIRTHS: SideTable<EntityId, RowBirth, Named> =
    SideTable::new(&side_table::PROVENANCE_ROW_BIRTH);

/// The born-from index, as `store/birth_record` declares it.
const BIRTH_BY_TRIGGER: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::PROVENANCE_BIRTH_BY_TRIGGER);

/// Code-document heads, as `code_document/storage` declares them, for the
/// raw dump only: the row type stays private to that module.
const DOC_HEAD: SideTable<[u8; 32], Vec<u8>, Named> =
    SideTable::new(&side_table::CODE_DOCUMENT_HEAD);

/// Tested frontiers, as `code_document/storage` declares them, for the raw
/// dump only.
const DOC_FRONTIER: SideTable<([u8; 32], [u8; 32]), Vec<u8>, Named> =
    SideTable::new(&side_table::CODE_DOCUMENT_FRONTIER);

/// Ingress receipts, as `code_document/storage` declares them, for the raw
/// dump only.
const DOC_INGRESS: SideTable<EntityId, Vec<u8>, Named> =
    SideTable::new(&side_table::CODE_DOCUMENT_INGRESS);

/// Path rows, as `code_document/storage` declares them.
const DOC_PATH: SideTable<[u8; 32], [u8; 32], Raw> =
    SideTable::new(&side_table::CODE_DOCUMENT_PATH);

/// Finalized revisions, as `code_revision/keys` declares them.
const REV_RECORDS: SideTable<EntityId, CodeRevision, Raw> =
    SideTable::new(&side_table::CODE_REVISION_RECORD);

/// Integrity folds, as `code_revision/keys` declares them, for the raw dump
/// only.
const REV_INTEGRITY: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::CODE_REVISION_INTEGRITY);

/// Session frontiers, as `code_revision/keys` declares them, for the raw
/// dump only.
const REV_FRONTIER: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::CODE_REVISION_FRONTIER);

/// Forks, as `code_revision/keys` declares them.
const REV_FORKS: SideTable<EntityId, CodeRevisionFork, Raw> =
    SideTable::new(&side_table::CODE_REVISION_FORK);

/// The session, parent and fork-parent indexes, as `code_revision/keys`
/// declares them.
const REV_SESSION_INDEX: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::CODE_REVISION_SESSION_INDEX);
const REV_PARENT_INDEX: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::CODE_REVISION_PARENT_INDEX);
const REV_FORK_PARENT_INDEX: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::CODE_REVISION_FORK_PARENT_INDEX);

/// Stranded proposals, as `code_revision/proposals` declares them.
const REV_PROPOSALS: SideTable<EntityId, CodeRevisionProposal, Raw> =
    SideTable::new(&side_table::CODE_REVISION_PROPOSAL);

/// Promotion receipts, as `code_revision` declares them.
const REV_PROMOTIONS: SideTable<EntityId, Vec<String>, LegacyCompact> =
    SideTable::new(&side_table::CODE_REVISION_PROMOTION);

/// Office sources, as `office_body/records` declares them, for the raw dump
/// only.
const OFF_SOURCES: SideTable<EntityId, Vec<u8>, Named> =
    SideTable::new(&side_table::OFFICE_BODY_HEAD);

/// Deck forks, as `office_body/records` declares them.
const OFF_FORKS: SideTable<(EntityId, EntityId), OfficeBodyFork, Named> =
    SideTable::new(&side_table::OFFICE_BODY_FORK);

/// Export records, as `office_body/records` declares them.
const OFF_EXPORTS: SideTable<Vec<u8>, OfficeBodyExportRecord, Named> =
    SideTable::new(&side_table::OFFICE_BODY_EXPORT);

/// Revision-author tokens, as `office_body/records` declares them.
const OFF_EXPORT_AUTHORS: SideTable<(EntityId, u64, u64), OfficeBodyExportAuthor, Named> =
    SideTable::new(&side_table::OFFICE_BODY_EXPORT_AUTHOR);

/// Proposals and fork memberships, as `office_body/consent` declares them.
const OFF_PROPOSALS: SideTable<EntityId, OfficeBodyProposal, Named> =
    SideTable::new(&side_table::OFFICE_BODY_PROPOSAL);
const OFF_MEMBERSHIP: SideTable<(EntityId, EntityId), EntityId, Named> =
    SideTable::new(&side_table::OFFICE_BODY_FORK_PROPOSAL);

/// The deck oracle and the live-edit routes, as `office_body` declares
/// them, for the raw dump only: neither restores, so both stay empty.
const OFF_ORACLE: SideTable<String, Vec<u8>, Named> =
    SideTable::new(&side_table::OFFICE_BODY_ORACLE);
const OFF_LIVE_EDIT: SideTable<EntityId, Vec<u8>, Named> =
    SideTable::new(&side_table::OFFICE_LIVE_EDIT_ASK_GROUP);

/// The author-token lookup, as `office_body/author_token` declares it, for
/// the raw dump only.
const OFF_TOKEN_INDEX: SideTable<String, Vec<u8>, Named> =
    SideTable::new(&side_table::OFFICE_BODY_EXPORT_TOKEN_INDEX);

/// Blob heads and versions, as `blob_artifact/versions` declares them.
const BLOB_HEAD: SideTable<EntityId, BlobArtifactVersion, Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_HEAD);
const BLOB_VERSIONS: SideTable<(EntityId, u64), BlobArtifactVersion, Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_VERSION);

/// Channel pointers, as `artifact_hosting` declares them, for the raw dump
/// only.
const BLOB_POINTERS: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::ARTIFACT_POINTER);

/// Publish admissions, as `artifact_hosting` declares them, for the raw
/// dump only.
const BLOB_ADMISSIONS: SideTable<EntityId, Vec<u8>, LegacyJson> =
    SideTable::new(&side_table::ARTIFACT_PUBLISH_ADMISSION);

/// Serving descriptors, as `artifact_hosting/serving_blob` declares them,
/// for the raw dump only.
const BLOB_SERVING: SideTable<(EntityId, u64), Vec<u8>, Named> =
    SideTable::new(&side_table::ARTIFACT_SERVING_BLOB);

/// NOTE heads, as `note/documents` declares them, for the raw dump and the
/// clear only: the row type stays private to that module, and the seed
/// writes heads through `set_head`.
const N_HEAD: SideTable<Vec<u8>, Vec<u8>, Raw> = SideTable::new(&side_table::NOTE_HEAD);

/// NOTE head markers, as `note/documents` declares them, for the raw dump
/// and the clear only.
const N_HEAD_DOC: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::NOTE_HEAD_DOC);

/// NOTE overrides, as `note/overrides` declares them.
const N_OVERRIDE: SideTable<EntityId, NoteOverrides, Named> =
    SideTable::new(&side_table::NOTE_OVERRIDE);

/// NOTE seals, as `note/lifecycle` declares them.
const N_SEAL: SideTable<EntityId, NoteSeal, Named> = SideTable::new(&side_table::NOTE_SEAL);

/// NOTE forks, as `note/proposals` declares them.
const N_FORK: SideTable<EntityId, NoteFork, Named> = SideTable::new(&side_table::NOTE_FORK);

/// NOTE proposal documents, as `note/documents` declares them, for the raw
/// dump and the clear only: the key type stays private to that module.
const N_PROPOSAL_DOC: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_PROPOSAL_DOC);

/// NOTE landing receipts, as `note/proposals` declares them.
const N_RECEIPT: SideTable<EntityId, NoteLandingReceipt, Named> =
    SideTable::new(&side_table::NOTE_RECEIPT);

/// NOTE review bundles, as `note/proposals` declares them.
const N_BUNDLE: SideTable<EntityId, NoteReviewBundle, Named> =
    SideTable::new(&side_table::NOTE_PROPOSAL_BUNDLE);

/// NOTE operation receipts, as `note/sync_rows` declares them.
const N_SYNC: SideTable<Vec<u8>, serde_json::Value, LegacyJson> =
    SideTable::new(&side_table::SYNC_NC_E);

/// NOTE fork authorities, as `note/sync_rows` declares them, for the raw
/// dump and the clear only: the key type stays private to that module.
const N_FORK_AUTHORITY: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_FORK_AUTHORITY);

/// NOTE command receipts, as `note/sync_rows` declares them, for the raw
/// dump and the clear only.
const N_RECEIPT_BY_REQUEST: SideTable<Vec<u8>, Vec<u8>, LegacyJson> =
    SideTable::new(&side_table::NOTE_RECEIPT_BY_REQUEST);

/// NOTE citation pins, as `note/pin_index` declares them, for the raw dump
/// and the clear only: the key types stay private to that module.
const N_PIN_SOURCE: SideTable<Vec<u8>, Vec<u8>, LegacyJson> =
    SideTable::new(&side_table::NOTE_PIN_SOURCE);
const N_PIN_CLAIM: SideTable<Vec<u8>, Vec<u8>, Raw> = SideTable::new(&side_table::NOTE_PIN_CLAIM);
const N_PIN_CITING: SideTable<Vec<u8>, Vec<u8>, Raw> = SideTable::new(&side_table::NOTE_PIN_CITING);
const N_PIN_REQUEST_CITING: SideTable<Vec<u8>, Vec<u8>, LegacyJson> =
    SideTable::new(&side_table::NOTE_PIN_REQUEST_CITING);
const N_PIN_REQUEST_CLAIM: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_PIN_REQUEST_CLAIM);
const N_PIN_REQUEST_SOURCE: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_PIN_REQUEST_SOURCE);

/// NOTE title reservations, as `note/title_index` declares them.
const N_TITLE_RESERVATION: SideTable<String, EntityId, Raw> =
    SideTable::new(&side_table::NOTE_TITLE_RESERVATION);

/// NOTE title reverses, as `note/title_index` declares them.
const N_TITLE_BY_NOTE: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_TITLE_BY_NOTE);

/// Entity-document heads, as `entity_doc/storage` declares them, for the
/// raw dump and the clear only: the row type stays private to that module.
const ED_HEAD: SideTable<Vec<u8>, Vec<u8>, Named> = SideTable::new(&side_table::ENTITY_DOC_HEAD);

/// Citation floors, as `entity_doc/citation_floor` declares them, for the
/// raw dump and the clear only.
const ED_FLOOR: SideTable<Vec<u8>, Vec<u8>, Named> =
    SideTable::new(&side_table::ENTITY_DOC_CITATION_FLOOR);

/// Document forks, as `entity_doc/forks` declares them.
const ED_FORK: SideTable<String, ForkRecord, Named> = SideTable::new(&side_table::ENTITY_DOC_FORK);

/// Fork snapshots, as `entity_doc/forks` declares them.
const ED_FORK_SNAPSHOT: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::ENTITY_DOC_FORK_SNAPSHOT);

/// Citation pins, as `entity_doc/pins` declares them, for the raw dump and
/// the clear only: the seed writes them through the pins helper.
const ED_PIN: SideTable<HexPair, CitationPin, Named> = SideTable::new(&side_table::ENTITY_DOC_PIN);

/// Purge receipts, as `entity_doc/pins` declares them.
const ED_PURGE: SideTable<HexPair, PurgeReceipt, Named> =
    SideTable::new(&side_table::ENTITY_DOC_PURGE_RECEIPT);

/// Settlement receipts, as `entity_doc/forks` declares them.
const ED_RECEIPT: SideTable<HexPair, TextReceipt, Named> =
    SideTable::new(&side_table::ENTITY_DOC_RECEIPT);

/// Proposal bundles, as `entity_doc/forks` declares them.
const ED_BUNDLE: SideTable<String, ProposalBundle, Named> =
    SideTable::new(&side_table::ENTITY_DOC_PROPOSAL_BUNDLE);

/// Document snapshots, as the document-row port declares them.
const ED_SNAPSHOT: SideTable<DocumentSlot, Vec<u8>, Raw> =
    SideTable::new(&side_table::DOCUMENT_SNAPSHOT);

/// Document updates, as the document-row port declares them.
const ED_UPDATE: SideTable<DocumentUpdateKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::DOCUMENT_UPDATE);

/// Revision states, as `entity_revision/storage` declares them, for the raw
/// dump and the clear only: the row type stays private to that module.
const ER_STATE: SideTable<Vec<u8>, Vec<u8>, Named> =
    SideTable::new(&side_table::ENTITY_REVISION_STATE);

/// Revision documents, as `entity_revision/storage` declares them.
const ER_DOC: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::ENTITY_REVISION_DOC);

/// Retained frontiers, as `entity_revision/storage` declares them.
const ER_FRONTIER: SideTable<(EntityId, [u8; 16]), Vec<u8>, Raw> =
    SideTable::new(&side_table::ENTITY_REVISION_FRONTIER);

/// Frontier identities, as `entity_revision/storage` declares them.
const ER_IDENTITY: SideTable<[u8; 16], EntityId, Raw> =
    SideTable::new(&side_table::ENTITY_REVISION_IDENTITY);

/// Memory timeline rows, as `entity_revision/timeline` declares them.
const ER_TIMELINE: SideTable<(EntityId, u64), [u8; 16], Raw> =
    SideTable::new(&side_table::ENTITY_REVISION_TIMELINE);

/// Vector refill markers, as `entity_revision/vector_refill` declares them.
const ER_REFILL: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::ENTITY_REVISION_VECTOR_REFILL);

/// Staged index inputs, as `entity_revision/pending_index` declares them,
/// for the raw dump and the clear only.
const ER_PENDING_INDEX: SideTable<Vec<u8>, Vec<u8>, Named> =
    SideTable::new(&side_table::ENTITY_REVISION_PENDING_INDEX_INPUTS);

/// Staged phonetic codes, as `entity_revision/phonetic` declares them, for
/// the raw dump and the clear only.
const ER_PENDING_PHONETIC: SideTable<Vec<u8>, Vec<u8>, Named> =
    SideTable::new(&side_table::ENTITY_REVISION_PENDING_PHONETIC);

/// One fixed entity id.
fn id(byte: u8) -> Result<EntityId> {
    EntityId::from_bytes([byte; 16])
}

/// One fixed attempt id.
fn attempt(byte: u8) -> Result<AttemptId> {
    AttemptId::from_bytes(&[byte; 16])
}

/// One fixed entity row: `entity_record` with occurred `1..1`, the pins
/// learned stamp and row version zero.
fn entity_row(kind: u8, body: &[u8]) -> Vec<u8> {
    entity_record(
        kind,
        TimeRange { start: 1, end: 1 },
        1_700_000_000_000,
        0,
        body,
    )
}

/// One fixed CLAIM body with `predicate`, over `subject`.
fn claim_body(predicate: &str, subject: EntityId) -> Result<ClaimBody> {
    ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        rmpv::Value::from("pins"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
}

/// One fixed identity-topology event row: `action` with a fixed envelope.
fn identity_row(action: StoredIdentityOpAction) -> Result<Vec<u8>> {
    let event = StoredIdentityOpEvent {
        seq: 1,
        validated_at_write: false,
        invalidated: false,
        at: 1_700_000_000_000,
        actor: None,
        source: ClaimSource::UserStated,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action,
    };
    let body = encode_identity_topology_event_body(&event)?;
    Ok(entity_row(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, &body))
}

/// Deletes every row of the Entities, EdgesOut and EdgesIn databases and
/// every row of each side table the four getters capture or own, in one
/// write transaction. A seeded open writes entity and edge rows, and
/// revision-ledger rows with a wall-clock stamp, that would differ between
/// the base and head processes; the seed calls this first so only fixed
/// rows remain.
///
/// # Errors
///
/// The vault's.
pub fn clear_four(vault: &Vault) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    vault.store.entities.clear(&mut txn)?;
    vault.store.edges_out.clear(&mut txn)?;
    vault.store.edges_in.clear(&mut txn)?;
    N_HEAD.delete_from(&vault.store, &mut txn, &[])?;
    N_HEAD_DOC.delete_from(&vault.store, &mut txn, &[])?;
    N_OVERRIDE.delete_from(&vault.store, &mut txn, &[])?;
    N_SEAL.delete_from(&vault.store, &mut txn, &[])?;
    N_FORK.delete_from(&vault.store, &mut txn, &[])?;
    N_PROPOSAL_DOC.delete_from(&vault.store, &mut txn, &[])?;
    N_RECEIPT.delete_from(&vault.store, &mut txn, &[])?;
    N_BUNDLE.delete_from(&vault.store, &mut txn, &[])?;
    N_SYNC.delete_from(&vault.store, &mut txn, &[])?;
    N_FORK_AUTHORITY.delete_from(&vault.store, &mut txn, &[])?;
    N_RECEIPT_BY_REQUEST.delete_from(&vault.store, &mut txn, &[])?;
    N_PIN_SOURCE.delete_from(&vault.store, &mut txn, &[])?;
    N_PIN_CLAIM.delete_from(&vault.store, &mut txn, &[])?;
    N_PIN_CITING.delete_from(&vault.store, &mut txn, &[])?;
    N_PIN_REQUEST_CITING.delete_from(&vault.store, &mut txn, &[])?;
    N_PIN_REQUEST_CLAIM.delete_from(&vault.store, &mut txn, &[])?;
    N_PIN_REQUEST_SOURCE.delete_from(&vault.store, &mut txn, &[])?;
    N_TITLE_RESERVATION.delete_from(&vault.store, &mut txn, &[])?;
    N_TITLE_BY_NOTE.delete_from(&vault.store, &mut txn, &[])?;
    ED_HEAD.delete_from(&vault.store, &mut txn, &[])?;
    ED_FLOOR.delete_from(&vault.store, &mut txn, &[])?;
    ED_FORK.delete_from(&vault.store, &mut txn, &[])?;
    ED_FORK_SNAPSHOT.delete_from(&vault.store, &mut txn, &[])?;
    ED_PIN.delete_from(&vault.store, &mut txn, &[])?;
    ED_PURGE.delete_from(&vault.store, &mut txn, &[])?;
    ED_RECEIPT.delete_from(&vault.store, &mut txn, &[])?;
    ED_BUNDLE.delete_from(&vault.store, &mut txn, &[])?;
    ED_SNAPSHOT.delete_from(&vault.store, &mut txn, &[])?;
    ED_UPDATE.delete_from(&vault.store, &mut txn, &[])?;
    ER_STATE.delete_from(&vault.store, &mut txn, &[])?;
    ER_DOC.delete_from(&vault.store, &mut txn, &[])?;
    ER_FRONTIER.delete_from(&vault.store, &mut txn, &[])?;
    ER_IDENTITY.delete_from(&vault.store, &mut txn, &[])?;
    ER_TIMELINE.delete_from(&vault.store, &mut txn, &[])?;
    ER_REFILL.delete_from(&vault.store, &mut txn, &[])?;
    ER_PENDING_INDEX.delete_from(&vault.store, &mut txn, &[])?;
    ER_PENDING_PHONETIC.delete_from(&vault.store, &mut txn, &[])?;
    txn.commit()?;
    Ok(())
}

/// Writes one fixed row per placement branch of each of the nineteen
/// getters.
///
/// # Errors
///
/// The vault's, or a fixed seed value the codecs refuse.
pub fn seed(vault: &Vault) -> Result<()> {
    clear_four(vault)?;
    let bound_attempt = attempt(0xd2)?;
    let body_owner = test_checkpoint_body_owner(bound_attempt)?;
    let mut txn = vault.store.env.write_txn()?;
    seed_text(vault, &mut txn)?;
    seed_phonetic(vault, &mut txn)?;
    seed_provenance_body(vault, &mut txn, &body_owner)?;
    seed_codebase(vault, &mut txn)?;
    seed_ledger(vault, &mut txn)?;
    seed_blocked(vault, &mut txn)?;
    seed_embed(vault, &mut txn)?;
    seed_tool_wait(vault, &mut txn, &bound_attempt, &body_owner)?;
    seed_audience(vault, &mut txn)?;
    seed_typed_body(vault, &mut txn)?;
    seed_provenance_birth(vault, &mut txn)?;
    seed_code_document(vault, &mut txn)?;
    seed_code_revision(vault, &mut txn)?;
    seed_office_body(vault, &mut txn)?;
    seed_blob_artifact(vault, &mut txn)?;
    seed_entities(vault, &mut txn)?;
    seed_note(vault, &mut txn)?;
    seed_entity_doc(vault, &mut txn)?;
    seed_entity_revision(vault, &mut txn)?;
    txn.commit()?;
    Ok(())
}
