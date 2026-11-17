//! The fifteen checkpoint getters' pins (UC-10 PR 3 and PR 4): one fixed
//! seed and one printed table over the getters as they are, run again after
//! they move onto the shared descriptor. Compiled only under `--cfg
//! oneiron_test_support`; never API.
//!
//! [`seed`] writes one fixed row per placement branch of each getter into a
//! source vault, [`pins`] captures, frames and restores each getter and
//! prints one line per owner, section row, restore and target row. The base
//! and head runs are separate processes, so every id and value is fixed: no
//! clock, no random source, no minted id.

use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;
use oneiron_docedit::emit::oracle_cases::sha256_hex;
use oneiron_docedit::live::{OracleReceipt, StepOutcome};

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
use crate::edge::EdgeActorClass;
use crate::embed::{
    EmbeddingDevice, EmbeddingProvenance, put_pins_media_refusal_in_txn,
    put_pins_media_vector_in_txn,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::office_body::{
    AnsweringAuthority, BundleVerdict, ForkState, MemberAnswer, MemberVerdict,
    OfficeBodyExportAuthor, OfficeBodyExportRecord, OfficeBodyFork, OfficeBodyKind,
    OfficeBodyProposal, ProposalHeader, ProposalMember, ProposalSettlement, pins_version_key,
    put_pins_author_token_ref_in_txn, put_pins_export_token_ref_in_txn,
    put_pins_live_edit_route_in_txn, put_pins_office_source_in_txn, put_pins_oracle_in_txn,
};
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, INTENT_LEDGER_VALUE_KEYS, IntentLedgerError,
    IntentLedgerRecord, OutboundCallRequest,
};
use crate::provenance::body::{BodyLocation, BodyRef, BodyState, OwnedBody};
use crate::recovery::checkpoint::{getter_bytes_for_owner, getter_capture, getter_restore_in_txn};
use crate::secret_snapshot::SnapshotCustodyReport;
use crate::side_table::{
    self, LegacyCompact, LegacyJson, Named, Raw, SideCodec, SideKey, SideTable,
};
use crate::source_audience::HeldBack;
use crate::store::GateDecisionId;
use crate::store::Store;
use crate::store::checkpoint_payload::rows::{
    Captured, Getter, OpenedOwnerRows, OwnerRows, Restored,
};
use crate::store::code_snapshot::{CodebaseFileEntry, CodebaseSnapshot, RepoRef};
use crate::store::embedding::InputKind;
use crate::store::row_birth::RowBirth;
use crate::typed_body::{
    BodyActor, TypedBodyFork, TypedBodyHead, TypedForkState, put_pins_erased_receipt_in_txn,
    put_pins_receipt_in_txn,
};
use crate::write_envelope::WriteActor;
use crate::write_envelope::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
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

/// One fixed entity id.
fn id(byte: u8) -> Result<EntityId> {
    EntityId::from_bytes([byte; 16])
}

/// One fixed attempt id.
fn attempt(byte: u8) -> Result<AttemptId> {
    AttemptId::from_bytes(&[byte; 16])
}

/// One text-source row: the bm25 getter's exact branch.
fn seed_text(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let fields = vec![("title".to_owned(), "pins document".to_owned())];
    TEXT_SOURCE.put(vault, txn, &id(0x01)?, &fields)?;
    Ok(())
}

/// One phonetic-source row: the batch getter's exact branch.
fn seed_phonetic(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    PHONETIC_SOURCE.put(vault, txn, &id(0x02)?, &vec!["pins-code".to_owned()])?;
    Ok(())
}

/// A body descriptor and its digest holder under `body_owner`'s
/// occurrence, and a descriptor whose owner differs from its key.
fn seed_provenance_body(vault: &Vault, txn: &mut RwTxn<'_>, body_owner: &EntityId) -> Result<()> {
    let occurrence = id(0x03)?;
    let held = BodyRef {
        blake3: [0xb1; 32],
        bytes: 9,
        location: BodyLocation::Inline,
    };
    BODY.put(
        vault,
        txn,
        &(*body_owner, occurrence),
        &OwnedBody {
            owner: *body_owner,
            occurrence,
            mark_occurrence: occurrence,
            state: BodyState::Complete { body: held },
            result: None,
            code_run_output: None,
        },
    )?;
    BODY_DIGEST.put(vault, txn, &([0xd1; 32], occurrence), body_owner)?;
    let stray_owner = id(0x06)?;
    let stray_occurrence = id(0x05)?;
    BODY.put(
        vault,
        txn,
        &(id(0x04)?, stray_occurrence),
        &OwnedBody {
            owner: stray_owner,
            occurrence: stray_occurrence,
            mark_occurrence: stray_occurrence,
            state: BodyState::Incomplete { retained: None },
            result: None,
            code_run_output: None,
        },
    )?;
    Ok(())
}

/// A snapshot with its repo, project, fork and scope rows, a scope row
/// naming nothing, and the fork's custody report.
fn seed_codebase(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let snapshot_id = id(0xc1)?;
    let snapshot = CodebaseSnapshot::new(
        "pins-project",
        RepoRef::parse("capture:pins/fixture")?,
        None,
        vec![CodebaseFileEntry::new("pins/main.rs", [0xc2; 32], 12)],
    )?;
    SNAPSHOTS.put(vault, txn, &snapshot_id, &snapshot)?;
    put_pins_repo_index_row_in_txn(
        &vault.store,
        txn,
        &snapshot.repo_ref.canonical(),
        &snapshot_id,
    )?;
    put_pins_project_index_row_in_txn(&vault.store, txn, &snapshot.project_id, &snapshot_id)?;
    put_pins_fork_index_row_in_txn(&vault.store, txn, &snapshot.fork_hash, &snapshot_id)?;
    put_pins_scope_index_row_in_txn(&vault.store, txn, &snapshot.scope_key, &snapshot_id)?;
    put_pins_scope_index_row_in_txn(&vault.store, txn, &[0xc3; 32], &id(0xc4)?)?;
    CUSTODY_REPORTS.put(
        vault,
        txn,
        &bytes_to_hex_lower(&snapshot.fork_hash),
        &SnapshotCustodyReport::default(),
    )?;
    Ok(())
}

/// One pending ledger record through the writer's own constructor.
fn ledger_record(
    attempt_id: AttemptId,
    call_seq: u64,
    server: &str,
    tool: &str,
    now_ms: u64,
) -> Result<IntentLedgerRecord> {
    let request = OutboundCallRequest::new(
        attempt_id,
        call_seq,
        server,
        tool,
        b"pins-payload".to_vec(),
        now_ms,
    );
    let marker = BudgetChargeMarker {
        key_ref: None,
        budget_class: BudgetClass::Operation,
        matched_rows: Vec::new(),
        sends_debit: 0,
        accounted_at_ms: now_ms,
    };
    IntentLedgerRecord::pending(request, false, marker).map_err(|error| match error {
        IntentLedgerError::Engine(error) => error,
        other => Error::InvalidConfig(format!("pins ledger seed: {other}")),
    })
}

/// The six accounting entries cut out of an encoded record, as the ledger
/// getter's capture keeps them beside a call.
fn accounting_of(record_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = record_bytes;
    let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvariantViolation("pins ledger seed is not a map"))?
    else {
        return Err(Error::InvariantViolation("pins ledger seed is not a map"));
    };
    let kept: Vec<(rmpv::Value, rmpv::Value)> = entries
        .into_iter()
        .filter(|(key, _)| {
            key.as_str()
                .is_some_and(|key| ACCOUNTING_KEYS.contains(&key))
        })
        .collect();
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(kept))
        .map_err(|_| Error::InvariantViolation("pins ledger seed did not encode"))?;
    Ok(out)
}

/// A record with its attempt binding, a record filed under another id, and
/// an unavailable and an accounting row of calls with no record.
fn seed_ledger(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let now_ms = 1_700_000_000_000;
    let attempt_id = attempt(0xa1)?;
    let record = ledger_record(attempt_id, 1, "pins-server", "pins-tool", now_ms)?;
    LEDGER.put(vault, txn, &record.id, &record)?;
    ATTEMPT_INDEX.put(
        vault,
        txn,
        &CallKey {
            attempt_id,
            call_seq: 1,
        },
        &record.id,
    )?;
    let stray = ledger_record(attempt(0xa2)?, 2, "pins-server", "pins-tool", now_ms)?;
    let mut wrong = stray.id;
    wrong[0] ^= 0x01;
    wrong[15] ^= 0x01;
    LEDGER.put(vault, txn, &wrong, &stray)?;
    let mut unavailable = [0xa3; 32].to_vec();
    unavailable.extend_from_slice(&(now_ms + 1).to_be_bytes());
    unavailable.extend_from_slice(&(now_ms + 1).to_be_bytes());
    UNAVAILABLE.put(
        vault,
        txn,
        &CallKey {
            attempt_id: attempt(0xa3)?,
            call_seq: 3,
        },
        &unavailable,
    )?;
    let shadow = ledger_record(attempt(0xa4)?, 4, "pins-server", "pins-tool", now_ms)?;
    let accounting = accounting_of(&LEDGER.encode_value(&shadow)?)?;
    CALL_ACCOUNTING.put(
        vault,
        txn,
        &CallKey {
            attempt_id: attempt(0xa4)?,
            call_seq: 4,
        },
        &accounting,
    )?;
    Ok(())
}

/// One witness key: its owner, its role byte, and its receipt.
fn witness_key(owner: &EntityId, role: u8, receipt: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.extend_from_slice(owner.as_bytes());
    key.push(role);
    key.extend_from_slice(receipt.as_bytes());
    key
}

/// A witness with an empty value, one with a non-empty value, and one with
/// a role byte that names no owner.
fn seed_blocked(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    WITNESSES.put(
        vault,
        txn,
        &witness_key(&id(0xe1)?, b'r', &id(0xe2)?),
        &Vec::new(),
    )?;
    WITNESSES.put(
        vault,
        txn,
        &witness_key(&id(0xe6)?, b'r', &id(0xe7)?),
        &vec![0xee],
    )?;
    WITNESSES.put(
        vault,
        txn,
        &witness_key(&id(0xe8)?, b'x', &id(0xe9)?),
        &Vec::new(),
    )?;
    Ok(())
}

/// A media vector, its device mark and a refusal of one document.
fn seed_embed(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let key = ([0xe0; 16], id(0xe3)?);
    put_pins_media_vector_in_txn(
        &vault.store,
        txn,
        &key,
        InputKind::Image,
        [0xe4; 32],
        b"pins-vector-row",
    )?;
    MEDIA_DEVICE.put(
        vault,
        txn,
        &key,
        &EmbeddingProvenance::new(EmbeddingDevice::Cpu, "pins-runtime"),
    )?;
    put_pins_media_refusal_in_txn(
        &vault.store,
        txn,
        &key,
        [0xe5; 32],
        "pins",
        1_700_000_000_002,
    )?;
    Ok(())
}

/// A bound row with a known source and a room, a binding-less row, a row
/// filed under another key, and the body-source fact its capture reads.
fn seed_tool_wait(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    bound_attempt: &AttemptId,
    body_owner: &EntityId,
) -> Result<()> {
    let bound = test_checkpoint_row_bound(
        *bound_attempt,
        3,
        id(0x07)?,
        Some(id(0x08)?),
        vec![id(0x09)?],
    )?;
    TOOL_WAIT.put(vault, txn, &test_checkpoint_key(*bound_attempt)?, &bound)?;
    let loose_attempt = attempt(0xd3)?;
    TOOL_WAIT.put(
        vault,
        txn,
        &test_checkpoint_key(loose_attempt)?,
        &test_checkpoint_row_unbound(loose_attempt, 1),
    )?;
    let stray_attempt = attempt(0xd4)?;
    let stray = test_checkpoint_row_bound(stray_attempt, 1, id(0x0a)?, None, Vec::new())?;
    let right = test_checkpoint_key(stray_attempt)?;
    let mut wrong = *right.as_bytes();
    wrong[0] ^= 0x01;
    wrong[15] ^= 0x01;
    TOOL_WAIT.put(vault, txn, &EntityId::from_bytes(wrong)?, &stray)?;
    let mut fact = Vec::with_capacity(80);
    fact.extend_from_slice(id(0x0b)?.as_bytes());
    fact.extend_from_slice(body_owner.as_bytes());
    fact.extend_from_slice(&[0xd5; 32]);
    fact.extend_from_slice(&[0xd6; 16]);
    BODY_SOURCE.put(vault, txn, &fact, &Vec::new())?;
    Ok(())
}

/// One bound row and its hold.
fn seed_audience(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    RECORDS.put(vault, txn, &id(0xa9)?, &id(0xaa)?)?;
    HELD.put(vault, txn, &id(0xa9)?, &HeldBack::Pending)?;
    Ok(())
}

/// A head and its document, an open fork with its document, a merged fork,
/// and a live and an erased receipt.
fn seed_typed_body(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let at = 1_700_000_000_007;
    let entity = id(0x51)?;
    let opener = id(0x52)?;
    let settler = id(0x53)?;
    let fork = id(0x54)?;
    let merged = id(0x55)?;
    TB_HEADS.put(
        vault,
        txn,
        &entity,
        &TypedBodyHead {
            entity,
            schema: "pins.typed.v1".to_owned(),
            birth: vec![0xb0; 8],
            frontier: vec![0xb1; 8],
            commits: 2,
            landed_at: Some(at),
        },
    )?;
    TB_DOCS.put(vault, txn, &entity, &vec![0xd0; 32])?;
    TB_FORKS.put(
        vault,
        txn,
        &(entity, fork),
        &TypedBodyFork {
            entity,
            fork,
            opener: BodyActor::Actor(opener),
            base: vec![0xb1; 8],
            commits: 1,
            opened_at: at,
            state: TypedForkState::Open,
            version: vec![0x60; 4],
        },
    )?;
    TB_FORK_DOCS.put(vault, txn, &(entity, fork), &vec![0xd1; 32])?;
    TB_FORKS.put(
        vault,
        txn,
        &(entity, merged),
        &TypedBodyFork {
            entity,
            fork: merged,
            opener: BodyActor::Actor(opener),
            base: vec![0xb1; 8],
            commits: 1,
            opened_at: at,
            state: TypedForkState::Merged {
                by: BodyActor::Actor(settler),
                at,
                head: vec![0xb1; 8],
            },
            version: vec![0x61; 4],
        },
    )?;
    let made_by = MadeBy {
        inputs: Vec::new(),
        process: MadeByProcess {
            actor: opener,
            class: MadeByClass::Stated,
            identity: "pins".to_owned(),
            version: "1".to_owned(),
            params_hash: sha256_hex(b"pins-typed-body"),
        },
        at,
        trigger: None,
    };
    put_pins_receipt_in_txn(
        &vault.store,
        txn,
        &(entity, 7),
        &WriteActor::new(opener, EdgeActorClass::Human),
        &made_by,
    )?;
    put_pins_erased_receipt_in_txn(&vault.store, txn, &(entity, 8), at)?;
    Ok(())
}

/// A birth naming its actor, and the born-from index row of its trigger.
fn seed_provenance_birth(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let at = 1_700_000_000_008;
    let born = id(0x61)?;
    let actor = id(0x62)?;
    let trigger = id(0x63)?;
    let prompt = id(0x64)?;
    let read: &[u8] = b"pins-birth-read";
    ROW_BIRTHS.put(
        vault,
        txn,
        &born,
        &RowBirth {
            made_by: MadeBy {
                inputs: vec![MadeByInput {
                    row: prompt,
                    role: MadeByInputRole::Prompt,
                }],
                process: MadeByProcess {
                    actor,
                    class: MadeByClass::Concluded,
                    identity: "pins.birth".to_owned(),
                    version: "1".to_owned(),
                    params_hash: sha256_hex(b"pins-birth"),
                },
                at,
                trigger: Some(MadeByTrigger::Task(trigger)),
            },
            content_hash: RowBirth::content_hash_of(&[read]),
            withheld: Vec::new(),
            room_evidence: None,
        },
    )?;
    BIRTH_BY_TRIGGER.put(vault, txn, &(trigger, born), &())?;
    Ok(())
}

/// A head with a named and a nameless receipt, a frontier, a named and a
/// nameless ingress receipt, a path row, and a head whose ids disagree.
fn seed_code_document(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let document = [0xd0; 32];
    let frontier = CodeDocumentFrontier {
        document_id: document,
        repo: "pins-repo".to_owned(),
        path: "pins/main.rs".to_owned(),
        version: vec![(7, 3)],
        op_fold: [0xf0; 32],
        text_hash: [0xb1; 32],
        file_presence: None,
    };
    let actor = id(0x71)?;
    let operation = id(0x72)?;
    let session = id(0x74)?;
    let receipt =
        |operation: EntityId, actor: Option<EntityId>, sequence: u64| PinsCodeDocumentReceipt {
            operation: operation.to_hex(),
            session: session.to_hex(),
            actor,
            actor_class: EdgeActorClass::Human as u8,
            provenance: CodeOpProvenance::default(),
            sequence,
            peer_id: 7,
            counter_start: 0,
            counter_end: 3,
            edit: CodeFileEdit::between("pins/main.rs", "a", "b"),
            metadata_edit: None,
            before: frontier.clone(),
            after: frontier.clone(),
        };
    put_pins_code_document_head_in_txn(
        &vault.store,
        txn,
        &document,
        &[0xbb; 32],
        &frontier,
        b"pins-snap",
        &[
            receipt(operation, Some(actor), 1),
            receipt(id(0x73)?, None, 2),
        ],
    )?;
    put_pins_code_document_frontier_in_txn(
        &vault.store,
        txn,
        &(document, [0xf0; 32]),
        &frontier,
        b"pins-snap",
    )?;
    put_pins_code_document_ingress_in_txn(
        &vault.store,
        txn,
        &operation,
        &receipt(operation, Some(actor), 1),
    )?;
    put_pins_code_document_ingress_in_txn(
        &vault.store,
        txn,
        &id(0x75)?,
        &receipt(id(0x75)?, None, 3),
    )?;
    put_pins_code_document_path_in_txn(&vault.store, txn, "pins-repo", "pins/main.rs", &document)?;
    put_pins_code_document_head_in_txn(
        &vault.store,
        txn,
        &[0xd1; 32],
        &[0xbb; 32],
        &frontier,
        b"pins-snap",
        &[],
    )?;
    Ok(())
}

/// A named and a nameless record, a record filed under another key, an
/// integrity, frontier, fork, session and parent row, a fork-parent row, a
/// stranded proposal, and a promotion.
fn seed_code_revision(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let at = 1_700_000_000_009;
    let session = id(0x81)?;
    let root = id(0x82)?;
    let child = id(0x83)?;
    let fork_session = id(0x84)?;
    let stray = id(0x85)?;
    let wrong = id(0x86)?;
    let author = id(0x8a)?;
    REV_RECORDS.put(
        vault,
        txn,
        &root,
        &CodeRevision::commit(root, session, at)
            .with_commit_metadata(CodeCommitMetadata::new(author, "pins root")),
    )?;
    REV_RECORDS.put(
        vault,
        txn,
        &child,
        &CodeRevision::commit_child(child, session, root, at),
    )?;
    REV_RECORDS.put(
        vault,
        txn,
        &wrong,
        &CodeRevision::commit(child, session, at),
    )?;
    put_pins_code_revision_integrity_in_txn(
        &vault.store,
        txn,
        &root,
        &root,
        &session,
        &[0x61; 32],
        &[0x62; 32],
        at,
    )?;
    put_pins_code_revision_frontier_in_txn(
        &vault.store,
        txn,
        &session,
        &session,
        &child,
        &[0x63; 32],
        at,
    )?;
    REV_FORKS.put(
        vault,
        txn,
        &fork_session,
        &CodeRevisionFork::new(fork_session, session, child, at),
    )?;
    REV_SESSION_INDEX.put(vault, txn, &(session, root), &())?;
    REV_SESSION_INDEX.put(vault, txn, &(session, child), &())?;
    REV_PARENT_INDEX.put(vault, txn, &(root, child), &())?;
    REV_PARENT_INDEX.put(vault, txn, &(root, stray), &())?;
    REV_FORK_PARENT_INDEX.put(vault, txn, &(session, fork_session), &())?;
    let proposal_session = id(0x88)?;
    let proposal = id(0x87)?;
    REV_PROPOSALS.put(
        vault,
        txn,
        &proposal,
        &CodeRevisionProposal {
            revision: CodeRevision::commit(proposal, proposal_session, at)
                .with_commit_metadata(CodeCommitMetadata::new(author, "pins stranded")),
            head_revision_id: child,
            head_fold: [0x64; 32],
            proposed_fold: [0x65; 32],
            artifact_body: b"pins-body".to_vec(),
        },
    )?;
    REV_PROMOTIONS.put(vault, txn, &root, &vec![id(0x89)?.to_hex()])?;
    Ok(())
}

/// A source, an open and a merged fork, an export with its author tokens, a
/// waiting and a settled proposal with their memberships, and the oracle
/// and live-edit rows no owner holds.
fn seed_office_body(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let at = 1_700_000_000_010;
    let artifact = id(0xb1)?;
    let opener = id(0xb4)?;
    put_pins_office_source_in_txn(
        &vault.store,
        txn,
        &artifact,
        OfficeBodyKind::Docx,
        7,
        &[0xb0; 32],
    )?;
    let fork = id(0xb2)?;
    OFF_FORKS.put(
        vault,
        txn,
        &(artifact, fork),
        &OfficeBodyFork {
            id: fork,
            artifact,
            opener: BodyActor::Actor(opener),
            base: b"pins-base".to_vec(),
            commits: 2,
            opened_at: at,
            state: ForkState::Open,
            run_root: None,
            origin: None,
        },
    )?;
    let landed = id(0xb3)?;
    let settler = id(0xb5)?;
    OFF_FORKS.put(
        vault,
        txn,
        &(artifact, landed),
        &OfficeBodyFork {
            id: landed,
            artifact,
            opener: BodyActor::Actor(opener),
            base: b"pins-base".to_vec(),
            commits: 2,
            opened_at: at,
            state: ForkState::Merged {
                by: BodyActor::Actor(settler),
                at,
                head: b"pins-head".to_vec(),
            },
            run_root: None,
            origin: None,
        },
    )?;
    let export_actor = id(0xb6)?;
    let export_key = pins_version_key(&artifact, 3);
    OFF_EXPORTS.put(
        vault,
        txn,
        &export_key,
        &OfficeBodyExportRecord {
            artifact,
            version: 3,
            frontier: b"pins-frontier".to_vec(),
            rebind_frontier: None,
            held_ids: None,
            source_version: 7,
            actor: BodyActor::Actor(export_actor),
            author: "pins author".to_owned(),
            token: Some("pins-token-1".to_owned()),
            at,
            changes: 1,
            recalc: None,
            recalc_failure: None,
            recalc_zone: None,
            effects: Vec::new(),
        },
    )?;
    let author_key = (artifact, 3, 0);
    OFF_EXPORT_AUTHORS.put(
        vault,
        txn,
        &author_key,
        &OfficeBodyExportAuthor {
            actor: Some(export_actor),
            token: "pins-token-1".to_owned(),
        },
    )?;
    let spare_key = (artifact, 3, 1);
    OFF_EXPORT_AUTHORS.put(
        vault,
        txn,
        &spare_key,
        &OfficeBodyExportAuthor {
            actor: None,
            token: "pins-token-2".to_owned(),
        },
    )?;
    put_pins_export_token_ref_in_txn(&vault.store, txn, &export_key, "pins-token-1")?;
    put_pins_author_token_ref_in_txn(&vault.store, txn, &author_key, "pins-token-1")?;
    put_pins_author_token_ref_in_txn(&vault.store, txn, &spare_key, "pins-token-2")?;
    let waiting = id(0xb7)?;
    let member_fork = id(0xb8)?;
    OFF_PROPOSALS.put(
        vault,
        txn,
        &waiting,
        &OfficeBodyProposal {
            header: ProposalHeader {
                proposal: waiting,
                artifact,
                opener: BodyActor::Actor(opener),
                run_root: None,
                opened_at: at,
            },
            members: vec![ProposalMember {
                artifact,
                fork: member_fork,
                opener: BodyActor::Actor(opener),
                run_root: None,
                origin: None,
                verdict: MemberVerdict::Waiting,
                answer: None,
            }],
            settlement: None,
            asks: Vec::new(),
            ask_refused: Vec::new(),
        },
    )?;
    OFF_MEMBERSHIP.put(vault, txn, &(artifact, member_fork), &waiting)?;
    let settled = id(0xb9)?;
    let member = id(0xba)?;
    let member_opener = id(0xbb)?;
    let person = id(0xbc)?;
    let caller = id(0xbd)?;
    let other = id(0xbe)?;
    let answer = |head: &[u8], fork_head: &[u8], landed: Option<&[u8]>| MemberAnswer {
        by: AnsweringAuthority::Word {
            person: BodyActor::Actor(person),
        },
        caller: BodyActor::Actor(caller),
        head: head.to_vec(),
        fork_head: fork_head.to_vec(),
        landed: landed.map(|bytes| bytes.to_vec()),
        at,
    };
    OFF_PROPOSALS.put(
        vault,
        txn,
        &settled,
        &OfficeBodyProposal {
            header: ProposalHeader {
                proposal: settled,
                artifact,
                opener: BodyActor::Actor(opener),
                run_root: None,
                opened_at: at,
            },
            members: vec![
                ProposalMember {
                    artifact,
                    fork: member,
                    opener: BodyActor::Actor(member_opener),
                    run_root: None,
                    origin: None,
                    verdict: MemberVerdict::Landed,
                    answer: Some(answer(b"h1", b"f1", Some(b"l1"))),
                },
                ProposalMember {
                    artifact,
                    fork: other,
                    opener: BodyActor::Actor(member_opener),
                    run_root: None,
                    origin: None,
                    verdict: MemberVerdict::Rejected,
                    answer: Some(answer(b"h2", b"f2", None)),
                },
            ],
            settlement: Some(ProposalSettlement {
                verdict: BundleVerdict::Mixed,
                at,
                reason: None,
            }),
            asks: Vec::new(),
            ask_refused: Vec::new(),
        },
    )?;
    OFF_MEMBERSHIP.put(vault, txn, &(artifact, member), &settled)?;
    OFF_MEMBERSHIP.put(vault, txn, &(artifact, other), &settled)?;
    put_pins_oracle_in_txn(
        &vault.store,
        txn,
        "pins-profile",
        &OracleReceipt {
            profile: "pins-profile".to_owned(),
            powerpoint_version: "pins-pp".to_owned(),
            macos_version: "pins-macos".to_owned(),
            font_versions: vec!["pins-font".to_owned()],
            steps: vec![StepOutcome::Passed; 8],
            clean: true,
            projector: "pins-projector".to_owned(),
            source_sha: "pins-source".to_owned(),
            case_manifest_sha256: "pins-case".to_owned(),
        },
        &BodyActor::Actor(export_actor),
        at,
    )?;
    put_pins_live_edit_route_in_txn(
        &vault.store,
        txn,
        &id(0xbf)?,
        &artifact,
        &id(0xaf)?,
        &[id(0xae)?, id(0xad)?],
        11,
    )?;
    Ok(())
}

/// A head and two versions of one artifact, an erased artifact's head and
/// version, a matching and a stray pointer and admission, a code pointer,
/// and a serving descriptor.
fn seed_blob_artifact(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let at = 1_700_000_000_011;
    let artifact = id(0x91)?;
    let producer = id(0x92)?;
    let version =
        |number: u64, claim: EntityId, actor: EntityId, parent: Option<u64>| BlobArtifactVersion {
            version: number,
            content_hash: [0xc0; 32],
            provenance: BlobVersionProvenance::UserUpload,
            calc_engine: None,
            claim_id: claim,
            created_at: at,
            export_name: "pins.bin".to_owned(),
            export_media_type: "application/octet-stream".to_owned(),
            parent_version: parent,
            fork_of_version: None,
            made_by: MadeBy {
                inputs: Vec::new(),
                process: MadeByProcess {
                    actor,
                    class: MadeByClass::Stated,
                    identity: "user_upload".to_owned(),
                    version: "1".to_owned(),
                    params_hash: sha256_hex(b"pins-blob"),
                },
                at,
                trigger: None,
            },
        };
    let head = version(2, id(0x95)?, producer, Some(1));
    BLOB_HEAD.put(vault, txn, &artifact, &head)?;
    BLOB_VERSIONS.put(
        vault,
        txn,
        &(artifact, 1),
        &version(1, id(0x94)?, producer, None),
    )?;
    BLOB_VERSIONS.put(vault, txn, &(artifact, 2), &head)?;
    let erased = id(0x98)?;
    let erased_producer = pins_erased_producer()?;
    let erased_head = version(1, id(0x96)?, erased_producer, None);
    BLOB_HEAD.put(vault, txn, &erased, &erased_head)?;
    BLOB_VERSIONS.put(vault, txn, &(erased, 1), &erased_head)?;
    let other = id(0x97)?;
    put_pins_artifact_pointer_in_txn(
        &vault.store,
        txn,
        ArtifactPointerChannel::Published,
        &artifact.to_hex(),
        ArtifactExportRef::BlobVersion {
            artifact_id: artifact,
            version: 2,
        },
        false,
        ArtifactServeTier::Private,
    )?;
    put_pins_artifact_pointer_in_txn(
        &vault.store,
        txn,
        ArtifactPointerChannel::Preview,
        &artifact.to_hex(),
        ArtifactExportRef::BlobVersion {
            artifact_id: other,
            version: 1,
        },
        false,
        ArtifactServeTier::Private,
    )?;
    put_pins_artifact_pointer_in_txn(
        &vault.store,
        txn,
        ArtifactPointerChannel::Published,
        "pins-code",
        ArtifactExportRef::ForkHash([0xf0; 32]),
        false,
        ArtifactServeTier::Private,
    )?;
    let gate = GateDecisionId::from_bytes([0x9a; 16]);
    let publish = WriteActor::new(producer, EdgeActorClass::Human);
    put_pins_artifact_admission_in_txn(
        &vault.store,
        txn,
        &id(0x99)?,
        &artifact.to_hex(),
        ArtifactPointerChannel::Published,
        ArtifactExportRef::BlobVersion {
            artifact_id: artifact,
            version: 2,
        },
        &artifact,
        &publish,
        &gate,
        at,
        false,
        ArtifactServeTier::Private,
    )?;
    put_pins_artifact_admission_in_txn(
        &vault.store,
        txn,
        &id(0x9b)?,
        &artifact.to_hex(),
        ArtifactPointerChannel::Preview,
        ArtifactExportRef::BlobVersion {
            artifact_id: artifact,
            version: 2,
        },
        &other,
        &publish,
        &gate,
        at,
        false,
        ArtifactServeTier::Private,
    )?;
    put_pins_serving_blob_in_txn(
        &vault.store,
        txn,
        &(artifact, 2),
        &[0xc2; 32],
        "pins.bin",
        "application/octet-stream",
    )?;
    Ok(())
}

/// Writes one fixed row per placement branch of each of the fifteen getters.
///
/// # Errors
///
/// The vault's, or a fixed seed value the codecs refuse.
pub fn seed(vault: &Vault) -> Result<()> {
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
    txn.commit()?;
    Ok(())
}

/// One getter's capture as lines: one per owner, then its structure,
/// dispatched and unclassified rows. Answers each owner's framed rows,
/// opened with its actor parts.
fn capture_pins(
    name: &'static str,
    captured: &Captured,
    frame: impl Fn(&OwnerRows) -> Result<Vec<u8>>,
    lines: &mut Vec<String>,
) -> Result<Vec<OpenedOwnerRows>> {
    let mut opened = Vec::new();
    for rows in captured.owners() {
        let framed = frame(rows)?;
        lines.push(format!(
            "OWNER {name} subtype={subtype:?} owner={owner} parts={parts:?} \
             deps={deps:?} actors={actors:?} sha256={framed}",
            subtype = rows.subtype,
            owner = bytes_to_hex_lower(&rows.owner32),
            parts = rows.rows,
            deps = rows.dependencies,
            actors = rows.actor_parts,
            framed = sha256_hex(&framed),
        ));
        opened.push(OpenedOwnerRows::open(
            &framed,
            rows.actor_parts.clone(),
            BTreeSet::new(),
        )?);
    }
    for row in &captured.structure {
        lines.push(format!("STRUCTURE {name} {row:?}"));
    }
    for row in &captured.dispatched {
        lines.push(format!("DISPATCHED {name} {row:?}"));
    }
    for row in &captured.unclassified {
        lines.push(format!("UNCLASSIFIED {name} {row:?}"));
    }
    Ok(opened)
}

/// One getter's restore into `target`, one write transaction, as lines: one
/// per owner with what it wrote and what it left out.
fn restore_pins(
    name: &'static str,
    target: &Vault,
    opened: Vec<OpenedOwnerRows>,
    restore: impl Fn(&Store, &mut RwTxn<'_>, OpenedOwnerRows) -> Result<Restored>,
    lines: &mut Vec<String>,
) -> Result<()> {
    let mut txn = target.store.env.write_txn()?;
    for owner_rows in opened {
        let owner = bytes_to_hex_lower(&owner_rows.owner32);
        let restored = restore(&target.store, &mut txn, owner_rows)?;
        lines.push(format!(
            "RESTORED {name} owner={owner} written={written} dropped={dropped:?}",
            written = restored.written,
            dropped = restored.dropped,
        ));
    }
    txn.commit()?;
    Ok(())
}

/// One of the six getters' restore into `bare` with no actor parts, one
/// write transaction, as lines: one per owner with what it wrote and what it
/// left out. Blob versions take the production path, which defers the rows
/// whose actor did not open instead of dropping them.
fn restore_bare_pins(
    name: &'static str,
    getter: Getter,
    captured: &Captured,
    bare: &Vault,
    lines: &mut Vec<String>,
) -> Result<()> {
    let mut txn = bare.store.env.write_txn()?;
    for rows in captured.owners() {
        let framed = getter_bytes_for_owner(getter, rows)?;
        let opened = OpenedOwnerRows::open(&framed, Vec::new(), BTreeSet::new())?;
        let owner = bytes_to_hex_lower(&opened.owner32);
        if getter == Getter::BlobArtifact {
            let total = opened.rows.len();
            let deferred = crate::blob_artifact::checkpoint::restore_or_defer_in_txn(
                &bare.store,
                &mut txn,
                opened,
            )?;
            match &deferred {
                None => {
                    lines.push(format!(
                        "RESTORED-BARE {name} owner={owner} written={total} dropped=[]"
                    ));
                    lines.push(format!("DEFERRED-BARE {name} owner={owner} rows=none"));
                }
                Some(deferred) => {
                    let dropped: Vec<_> =
                        deferred.rows.iter().map(|part| part.at().clone()).collect();
                    lines.push(format!(
                        "RESTORED-BARE {name} owner={owner} \
                         written={written} dropped={dropped:?}",
                        written = total - deferred.rows.len(),
                    ));
                    let parts: Vec<String> = deferred
                        .rows
                        .iter()
                        .map(|part| format!("{part:?}"))
                        .collect();
                    lines.push(format!("DEFERRED-BARE {name} owner={owner} rows={parts:?}"));
                }
            }
        } else {
            let restored = getter_restore_in_txn(getter, &bare.store, &mut txn, opened)?;
            lines.push(format!(
                "RESTORED-BARE {name} owner={owner} written={written} dropped={dropped:?}",
                written = restored.written,
                dropped = restored.dropped,
            ));
        }
    }
    txn.commit()?;
    Ok(())
}

/// Every raw row of `table` in `vault` into `into`, by full stored key.
fn raw_rows_into<K: SideKey, V, C: SideCodec<V>>(
    vault: &Vault,
    getter: &'static str,
    table: SideTable<K, V, C>,
    into: &mut BTreeMap<Vec<u8>, (&'static str, Vec<u8>)>,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    for row in table.iter_raw_from(&vault.store, &txn, &[])? {
        let (key, value) = row?;
        let mut full = table.decl().prefix.to_vec();
        full.extend_from_slice(&key);
        into.insert(full, (getter, value));
    }
    Ok(())
}

/// Every raw row of every getter's tables in `target`, in key order.
fn raw_pins(target: &Vault, lines: &mut Vec<String>) -> Result<()> {
    let mut rows: BTreeMap<Vec<u8>, (&'static str, Vec<u8>)> = BTreeMap::new();
    raw_rows_into(target, "bm25", TEXT_SOURCE, &mut rows)?;
    raw_rows_into(target, "batch", PHONETIC_SOURCE, &mut rows)?;
    raw_rows_into(target, "provenance_body", BODY, &mut rows)?;
    raw_rows_into(target, "provenance_body", BODY_DIGEST, &mut rows)?;
    raw_rows_into(target, "codebase", SNAPSHOTS, &mut rows)?;
    raw_rows_into(target, "codebase", REPO_INDEX, &mut rows)?;
    raw_rows_into(target, "codebase", PROJECT_INDEX, &mut rows)?;
    raw_rows_into(target, "codebase", FORK_INDEX, &mut rows)?;
    raw_rows_into(target, "codebase", SCOPE_INDEX, &mut rows)?;
    raw_rows_into(target, "codebase", CUSTODY_REPORTS, &mut rows)?;
    raw_rows_into(target, "outbound_ledger", LEDGER, &mut rows)?;
    raw_rows_into(target, "outbound_ledger", ATTEMPT_INDEX, &mut rows)?;
    raw_rows_into(target, "outbound_ledger", UNAVAILABLE, &mut rows)?;
    raw_rows_into(target, "outbound_ledger", CALL_ACCOUNTING, &mut rows)?;
    raw_rows_into(target, "blocked_reports", WITNESSES, &mut rows)?;
    raw_rows_into(target, "embed", MEDIA_VECTOR, &mut rows)?;
    raw_rows_into(target, "embed", MEDIA_DEVICE, &mut rows)?;
    raw_rows_into(target, "embed", MEDIA_REFUSED, &mut rows)?;
    raw_rows_into(target, "workflow_tool", TOOL_WAIT, &mut rows)?;
    raw_rows_into(target, "workflow_tool", BODY_SOURCE, &mut rows)?;
    raw_rows_into(target, "source_audience", RECORDS, &mut rows)?;
    raw_rows_into(target, "source_audience", HELD, &mut rows)?;
    for (key, (getter, value)) in rows {
        lines.push(format!(
            "RAW {getter} {key} {value}",
            key = bytes_to_hex_lower(&key),
            value = bytes_to_hex_lower(&value),
        ));
    }
    Ok(())
}

/// The nine getters, in pin order, each with the name its lines carry.
const PINNED: [(&str, Getter); 9] = [
    ("bm25", Getter::TextSource),
    ("batch", Getter::PhoneticSource),
    ("provenance_body", Getter::ProvenanceBody),
    ("codebase", Getter::Codebase),
    ("outbound_ledger", Getter::OutboundCall),
    ("blocked_reports", Getter::BlockedSourceOwner),
    ("embed", Getter::EmbedMedia),
    ("workflow_tool", Getter::WorkflowTool),
    ("source_audience", Getter::SourceAudience),
];

/// The six getters, in pin order, each with the name its lines carry.
const PINNED_SIX: [(&str, Getter); 6] = [
    ("typed_body", Getter::TypedBody),
    ("provenance_birth", Getter::ProvenanceBirth),
    ("code_document", Getter::CodeDocument),
    ("code_revision", Getter::CodeRevision),
    ("office_body", Getter::OfficeBody),
    ("blob_artifact", Getter::BlobArtifact),
];

/// Every raw row of the six getters' tables in `vault` into `into`, by full
/// stored key.
fn six_rows_into(
    vault: &Vault,
    into: &mut BTreeMap<Vec<u8>, (&'static str, Vec<u8>)>,
) -> Result<()> {
    raw_rows_into(vault, "typed_body", TB_HEADS, into)?;
    raw_rows_into(vault, "typed_body", TB_DOCS, into)?;
    raw_rows_into(vault, "typed_body", TB_FORKS, into)?;
    raw_rows_into(vault, "typed_body", TB_FORK_DOCS, into)?;
    raw_rows_into(vault, "typed_body", TB_RECEIPTS, into)?;
    raw_rows_into(vault, "provenance_birth", ROW_BIRTHS, into)?;
    raw_rows_into(vault, "provenance_birth", BIRTH_BY_TRIGGER, into)?;
    raw_rows_into(vault, "code_document", DOC_HEAD, into)?;
    raw_rows_into(vault, "code_document", DOC_FRONTIER, into)?;
    raw_rows_into(vault, "code_document", DOC_INGRESS, into)?;
    raw_rows_into(vault, "code_document", DOC_PATH, into)?;
    raw_rows_into(vault, "code_revision", REV_RECORDS, into)?;
    raw_rows_into(vault, "code_revision", REV_INTEGRITY, into)?;
    raw_rows_into(vault, "code_revision", REV_FRONTIER, into)?;
    raw_rows_into(vault, "code_revision", REV_FORKS, into)?;
    raw_rows_into(vault, "code_revision", REV_SESSION_INDEX, into)?;
    raw_rows_into(vault, "code_revision", REV_PARENT_INDEX, into)?;
    raw_rows_into(vault, "code_revision", REV_FORK_PARENT_INDEX, into)?;
    raw_rows_into(vault, "code_revision", REV_PROPOSALS, into)?;
    raw_rows_into(vault, "code_revision", REV_PROMOTIONS, into)?;
    raw_rows_into(vault, "office_body", OFF_SOURCES, into)?;
    raw_rows_into(vault, "office_body", OFF_FORKS, into)?;
    raw_rows_into(vault, "office_body", OFF_EXPORTS, into)?;
    raw_rows_into(vault, "office_body", OFF_EXPORT_AUTHORS, into)?;
    raw_rows_into(vault, "office_body", OFF_PROPOSALS, into)?;
    raw_rows_into(vault, "office_body", OFF_MEMBERSHIP, into)?;
    raw_rows_into(vault, "office_body", OFF_ORACLE, into)?;
    raw_rows_into(vault, "office_body", OFF_LIVE_EDIT, into)?;
    raw_rows_into(vault, "office_body", OFF_TOKEN_INDEX, into)?;
    raw_rows_into(vault, "blob_artifact", BLOB_HEAD, into)?;
    raw_rows_into(vault, "blob_artifact", BLOB_VERSIONS, into)?;
    raw_rows_into(vault, "blob_artifact", BLOB_POINTERS, into)?;
    raw_rows_into(vault, "blob_artifact", BLOB_ADMISSIONS, into)?;
    raw_rows_into(vault, "blob_artifact", BLOB_SERVING, into)?;
    Ok(())
}

/// Every raw row of the six getters' tables in `target`, then in `bare`, in
/// key order.
fn raw_pins_six(target: &Vault, bare: &Vault, lines: &mut Vec<String>) -> Result<()> {
    let mut rows: BTreeMap<Vec<u8>, (&'static str, Vec<u8>)> = BTreeMap::new();
    six_rows_into(target, &mut rows)?;
    for (key, (getter, value)) in rows {
        lines.push(format!(
            "RAW {getter} {key} {value}",
            key = bytes_to_hex_lower(&key),
            value = bytes_to_hex_lower(&value),
        ));
    }
    let mut bare_rows: BTreeMap<Vec<u8>, (&'static str, Vec<u8>)> = BTreeMap::new();
    six_rows_into(bare, &mut bare_rows)?;
    for (key, (getter, value)) in bare_rows {
        lines.push(format!(
            "RAW-BARE {getter} {key} {value}",
            key = bytes_to_hex_lower(&key),
            value = bytes_to_hex_lower(&value),
        ));
    }
    Ok(())
}

/// Captures, frames and restores each of the fifteen getters through the
/// checkpoint registry, as a capture and a restore dispatch them: one line
/// per owner, section row, restore and target row, in getter order. The six
/// also restore into `bare` with no actor parts.
///
/// # Errors
///
/// The vaults', or a row the getters' codecs refuse.
pub fn pins(source: &Vault, target: &Vault, bare: &Vault) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    let txn = source.store.env.read_txn()?;
    for (name, getter) in PINNED {
        let captured = getter_capture(getter, &source.store, &txn)?;
        let opened = capture_pins(
            name,
            &captured,
            |rows| getter_bytes_for_owner(getter, rows),
            &mut lines,
        )?;
        restore_pins(
            name,
            target,
            opened,
            |store, wtxn, opened| getter_restore_in_txn(getter, store, wtxn, opened),
            &mut lines,
        )?;
    }
    for (name, getter) in PINNED_SIX {
        let captured = getter_capture(getter, &source.store, &txn)?;
        let opened = capture_pins(
            name,
            &captured,
            |rows| getter_bytes_for_owner(getter, rows),
            &mut lines,
        )?;
        restore_pins(
            name,
            target,
            opened,
            |store, wtxn, opened| getter_restore_in_txn(getter, store, wtxn, opened),
            &mut lines,
        )?;
        restore_bare_pins(name, getter, &captured, bare, &mut lines)?;
    }
    raw_pins(target, &mut lines)?;
    raw_pins_six(target, bare, &mut lines)?;
    Ok(lines)
}
