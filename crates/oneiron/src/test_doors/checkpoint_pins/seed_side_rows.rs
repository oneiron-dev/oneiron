//! The checkpoint-pins door's side-row seeds: text and phonetic sources,
//! the provenance body, codebase indexes, the intent ledger and its
//! witnesses, media embeddings, tool waits, held-back audiences, typed
//! bodies and row births.

use super::*;

/// One text-source row: the bm25 getter's exact branch.
pub(super) fn seed_text(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let fields = vec![("title".to_owned(), "pins document".to_owned())];
    TEXT_SOURCE.put(vault, txn, &id(0x01)?, &fields)?;
    Ok(())
}

/// One phonetic-source row: the batch getter's exact branch.
pub(super) fn seed_phonetic(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    PHONETIC_SOURCE.put(vault, txn, &id(0x02)?, &vec!["pins-code".to_owned()])?;
    Ok(())
}

/// A body descriptor and its digest holder under `body_owner`'s
/// occurrence, and a descriptor whose owner differs from its key.
pub(super) fn seed_provenance_body(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    body_owner: &EntityId,
) -> Result<()> {
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
pub(super) fn seed_codebase(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
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
pub(super) fn seed_ledger(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
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
pub(super) fn seed_blocked(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
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
pub(super) fn seed_embed(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
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
pub(super) fn seed_tool_wait(
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
pub(super) fn seed_audience(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    RECORDS.put(vault, txn, &id(0xa9)?, &id(0xaa)?)?;
    HELD.put(vault, txn, &id(0xa9)?, &HeldBack::Pending)?;
    Ok(())
}

/// A head and its document, an open fork with its document, a merged fork,
/// and a live and an erased receipt.
pub(super) fn seed_typed_body(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
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
pub(super) fn seed_provenance_birth(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
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
