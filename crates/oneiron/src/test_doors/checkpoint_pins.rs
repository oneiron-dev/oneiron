//! The nine checkpoint getters' pins (UC-10 PR 3): one fixed seed and one
//! printed table over the getters as they are, run again after they move
//! onto the shared descriptor. Compiled only under `--cfg
//! oneiron_test_support`; never API.
//!
//! [`seed`] writes one fixed row per placement branch of each getter into a
//! source vault, [`pins`] captures, frames and restores each getter and
//! prints one line per owner, section row, restore and target row. The base
//! and head runs are separate processes, so every id and value is fixed: no
//! clock, no random source, no minted id.

use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::agent_dispatch::{
    CheckpointRow, test_checkpoint_body_owner, test_checkpoint_key, test_checkpoint_row_bound,
    test_checkpoint_row_unbound,
};
use crate::attempt_queue::AttemptId;
use crate::codebase::{
    put_pins_fork_index_row_in_txn, put_pins_project_index_row_in_txn,
    put_pins_repo_index_row_in_txn, put_pins_scope_index_row_in_txn,
};
use crate::embed::{
    EmbeddingDevice, EmbeddingProvenance, put_pins_media_refusal_in_txn,
    put_pins_media_vector_in_txn,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, INTENT_LEDGER_VALUE_KEYS, IntentLedgerError,
    IntentLedgerRecord, OutboundCallRequest,
};
use crate::provenance::body::{BodyLocation, BodyRef, BodyState, OwnedBody};
use crate::recovery::checkpoint::{getter_bytes_for_owner, getter_capture, getter_restore_in_txn};
use crate::secret_snapshot::SnapshotCustodyReport;
use crate::side_table::{self, Named, Raw, SideCodec, SideKey, SideTable};
use crate::source_audience::HeldBack;
use crate::store::Store;
use crate::store::checkpoint_payload::rows::{
    Captured, Getter, OpenedOwnerRows, OwnerRows, Restored,
};
use crate::store::code_snapshot::{CodebaseFileEntry, CodebaseSnapshot, RepoRef};
use crate::store::embedding::InputKind;

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

/// One fixed entity id.
fn id(byte: u8) -> Result<EntityId> {
    EntityId::from_bytes([byte; 16])
}

/// One fixed attempt id.
fn attempt(byte: u8) -> Result<AttemptId> {
    AttemptId::from_bytes(&[byte; 16])
}

/// The hex of a sha256 digest.
fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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

/// Writes one fixed row per placement branch of each of the nine getters.
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

/// Captures, frames and restores each of the nine getters through the
/// checkpoint registry, as a capture and a restore dispatch them: one line
/// per owner, section row, restore and target row, in getter order.
///
/// # Errors
///
/// The vaults', or a row the getters' codecs refuse.
pub fn pins(source: &Vault, target: &Vault) -> Result<Vec<String>> {
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
    raw_pins(target, &mut lines)?;
    Ok(lines)
}
