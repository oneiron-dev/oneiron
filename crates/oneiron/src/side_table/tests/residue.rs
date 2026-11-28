use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use heed::RoTxn;
use heed::types::Bytes;
use oneiron_contracts::fingerprint::ContentHash;

use super::{fixture_rows, plant_fixture_rows};
use crate::anchored_annotation::{Anchor, Locator};
use crate::batch::export::archive_retained_side_rows::{
    ArchiveRetainedSideRow, retained_side_row_key,
};
use crate::batch::export::archive_retained_subjects::{
    RETAINED_SUBJECT_RULES, RetainedSubjectRule, retained_subject_rule,
};
use crate::blob_artifact::{BlobArtifactBody, BlobBodyFile, BlobVersionProvenance};
use crate::consent::AuthenticatedOwner;
use crate::deletion::{
    DeleteReason, HARD_ERASE_SWEEP_PREFIX, WITHDRAWN_GENERATION_SWEEP_PREFIX,
    redaction_erase_final_id, redaction_sweep_completion_id,
};
use crate::edit_roundtrip::{
    EDIT_MANIFEST_SCHEMA_VERSION, EditManifest, EditProposal, MutationMode, OfficeFormat,
    RecalcStatus, StructureSummary, ValidationReport,
};
use crate::edit_settle::SettleConsent;
use crate::entity_id::bytes_to_hex_lower;
use crate::memory::DeleteRequestState;
use crate::ports::{ChangeLogStore, ChangeOp};
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
use crate::side_table::{self, Named, SideDb, SideTable, SideTableDecl, declared, declared_for};
use crate::store::{ASSET_INLINE_BODY_BYTES, DB_MANIFEST, Store};
use crate::verbs::{
    OwnerConfirmPreviewRequest, RecordEraseConfirmRequest, confirm_record_erase,
    preview_owner_confirm,
};
use crate::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

const SENTINEL_WORDS: &str = "quillwort harrow sentinel f7";
const PROPOSAL_REF: &str = "run:discard-f7";
const RETAINED_SOURCE: &str = "WEAVE_DIGEST_SETTINGS";
const AT: u64 = 10;
const POINT: TimeRange = TimeRange { start: AT, end: AT };

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Only the live archive specs whose *first* slot names a record in SideContext::travel.
const LIVE_ARCHIVE_LEADING: &[&SideTableDecl] = &[
    &side_table::BLOB_ARTIFACT_VERSION,
    &side_table::BLOB_ARTIFACT_DECK_ID_MARKS,
    &side_table::EDIT_SETTLE_RECORD,
    &side_table::BLOB_ARTIFACT_CLAIMED_HASH,
    &side_table::BLOB_ARTIFACT_HIGHWATER,
    &side_table::BLOB_ARTIFACT_HEAD,
    &side_table::ORIGIN_LFS_CHUNK_MARK,
    &side_table::ORIGIN_LFS_MANIFEST_REVERSE,
    &side_table::CODEBASE_SNAPSHOT,
    &side_table::CODE_REVISION_RECORD,
    &side_table::CODE_REVISION_INTEGRITY,
    &side_table::CODE_REVISION_PROPOSAL,
    &side_table::CODE_REVISION_PROMOTION,
    &side_table::CODE_REVISION_SESSION_INDEX,
    &side_table::CODE_REVISION_PARENT_INDEX,
    &side_table::CODE_REVISION_FORK,
    &side_table::CODE_REVISION_FORK_PARENT_INDEX,
    &side_table::CODE_REVISION_FRONTIER,
    &side_table::CODE_MEMORY_SLOT,
    &side_table::CODE_MEMORY_ATTACHMENT,
    &side_table::CODE_MEMORY_ALWAYS_ON,
    &side_table::CODE_MEMORY_TRANSFER,
];

// ID-leading tables no deletable record can hold a row in. A chunk mark makes its id a shared LFS
// chunk, and every delete refuses such an id before it starts (deletion/delete/guard.rs,
// origin::lfs::reject_direct_lfs_chunk_delete): the chunk goes when its manifest is deleted.
const NOT_PLANTED: &[&SideTableDecl] = &[&side_table::ORIGIN_LFS_CHUNK_MARK];

// Map Q2's no-fixture subset, restricted to the fixed offset-zero rules and live leading slots.
const NO_FIXTURE: &[&str] = &[
    "BLOB_ARTIFACT_CLAIMED_HASH",
    "BLOB_ARTIFACT_DECK_ID_MARKS",
    "BLOB_ARTIFACT_HIGHWATER",
    "BUDGET_RESIDENT_SHARE",
    "COMPACTION_CONVERSATION_RECEIPT",
    "CONVERSATION_ROLE_GRANT",
    "DREAMER_FREE_TIME_POLICY",
    "DREAMER_FREE_TIME_RECEIPT",
    "GPU_LINE",
    "GPU_LINE_PERIOD",
    "HOOKS_GRANT",
    "OFF_RECORD_COPY_RECEIPT",
    "PERSON_BILLING_ACCOUNT",
    "PROPOSAL_RECEIPT_HISTORY",
    "SYNC_RESIDENCE_MACHINE_TOUCH",
    "TYPED_BODY_RECEIPT",
    "VOICE_IDENTITY_CONSENT_VOID",
    "VOICE_IDENTITY_WITHDRAWAL_REQUESTED_AT",
    "WEAVE_DIGEST_SETTINGS",
    "WEAVE_DIGEST_SETTING_CHANGE",
];

// The H1 rows keep the key and lose their words. Highwater keeps the artifact's version counter.
// The e-sign audit trail stays queryable after its document's erase (blob_artifact/esign/ledger.rs,
// `esign_audit`); only its exact planted key is kept, and its words are still scanned.
const KEPT_TABLES: &[&SideTableDecl] = &[
    &side_table::EDIT_SETTLE_RECORD,
    &side_table::ANNOTATION_UNATTACHED,
    &side_table::BLOB_ARTIFACT_HIGHWATER,
    &side_table::ESIGN_AUDIT,
];

// Map Q7's ID-only exceptions. `keeps_id` narrows the prefix matches where the key is known.
// No pattern ever excuses a word hit.
const KEPT_ROWS: &[(&str, &[u8])] = &[
    ("sync_state", b"dt:"),
    ("sync_state", b"fedtombscope:"),
    ("sync_state", b"m:dw:"),
    ("sync_state", b"d:w:"),
    ("sync_state", b"u:w:"),
    ("sync_state", b"m:sr:"),
    ("sync_queue", b"q:"),
    ("sync_queue", b"d:"),
    ("sync_queue", b"pt:"),
    ("sync_queue", HARD_ERASE_SWEEP_PREFIX),
    ("sync_queue", WITHDRAWN_GENERATION_SWEEP_PREFIX),
    ("entities", b""),
    ("type_index", &[ENTITY_TYPE_REDACTION_AUDIT]),
    ("temporal_occurred_start", b""),
    ("temporal_learned", b""),
    ("vault_meta", side_table::PORTS_CHANGE.prefix),
    ("vault_meta", side_table::PORTS_CHANGE_BY_ACTOR.prefix),
    ("vault_meta", side_table::PORTS_CHANGE_BY_ENTITY.prefix),
    ("vault_meta", side_table::EDIT_SETTLE_RECORD.prefix),
    ("vault_meta", side_table::ANNOTATION_UNATTACHED.prefix),
    ("vault_meta", side_table::BLOB_ARTIFACT_HIGHWATER.prefix),
    ("vault_meta", side_table::ESIGN_AUDIT.prefix),
];

#[test]
fn an_owner_hard_delete_leaves_no_planted_row_and_no_sentinel_words() -> TestResult {
    residue_test(|vault, owner, id| {
        let outcome =
            vault.delete_entity_with_reason_as_owner(owner, &id, DeleteReason::UserHardDelete)?;
        assert!(
            outcome.existed,
            "the owner's hard delete found the workbook"
        );
        Ok(outcome
            .receipt_id
            .ok_or("hard delete did not write a receipt")?)
    })
}

#[test]
fn an_owner_erase_leaves_no_planted_row_and_no_sentinel_words() -> TestResult {
    residue_test(|vault, owner, id| {
        let memory = vault.memory(owner.actor(), EdgeActorClass::Human);
        let mut input = RecordEraseConfirmRequest {
            record: id,
            confirm: None,
            also_same_bytes: false,
            check_in_ref: None,
        };
        let preview = preview_owner_confirm(
            &memory,
            owner,
            OwnerConfirmPreviewRequest {
                verb: "vault.records.erase_confirm".to_owned(),
                input: serde_json::to_value(&input)?,
            },
        )?;
        input.confirm = Some(preview.confirm);
        let outcome = confirm_record_erase(&memory, owner, input)?;
        assert!(
            outcome.first.existed,
            "the owner's erase found the workbook"
        );
        assert_eq!(outcome.first.state, DeleteRequestState::Applied);
        let hex = outcome
            .first
            .receipt_ref
            .as_deref()
            .and_then(|reference| reference.strip_prefix("redaction:"))
            .ok_or("owner erase did not write a redaction receipt")?;
        Ok(EntityId::from_hex(hex)?)
    })
}

fn residue_test(
    act: impl FnOnce(&Vault, &AuthenticatedOwner, EntityId) -> TestResult<EntityId>,
) -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner = crate::test_util::embedded_owner_proof(&vault);
    let actor = WriteActor::new(owner.actor(), EdgeActorClass::Human);
    let (id, base_hash) = put_workbook(&vault, actor)?;
    let bodies = vault.path().join("bodies");
    assert!(
        !body_word_hits(&bodies)?.is_empty(),
        "the workbook did not spill a body file containing the sentinel words"
    );

    let known = plant_known_residues(&vault, id, base_hash, actor)?;
    let id_hex = id.to_hex();
    let tables = id_leading();
    let generic = plant_generic_rows(&vault, &id, &id_hex, &tables)?;
    let planted: Vec<_> = known.into_iter().chain(generic).collect();
    let txn = vault.store.env.read_txn()?;
    for row in &planted {
        let stored = row.get(&vault, &txn)?;
        assert!(stored.is_some(), "fixture not present: {}", row.label());
        if row.has_words {
            assert!(
                stored
                    .as_deref()
                    .is_some_and(|value| contains(value, SENTINEL_WORDS.as_bytes())),
                "sentinel seed has no words: {}",
                row.label()
            );
        }
    }
    drop(txn);
    assert_fixture_coverage(&tables, &planted);

    let receipt = act(&vault, &owner, id)?;
    if sweep_queued(&vault)? {
        crate::sweep::run_hard_erase_sweep(&vault)?;
        assert!(
            !sweep_queued(&vault)?,
            "hard-erase history sweep did not finish"
        );
    }
    let mut violations = residue_violations(&vault, &id, &id_hex, &receipt, &planted)?;
    for path in body_word_hits(&bodies)? {
        violations.push(format!(
            "6c: sentinel words in body file {}",
            path.display()
        ));
    }
    assert!(
        violations.is_empty(),
        "hard-delete residue:\n{}",
        violations.join("\n")
    );
    Ok(())
}

fn put_workbook(vault: &Vault, actor: WriteActor) -> TestResult<(EntityId, [u8; 32])> {
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &BlobArtifactBody::new(
            format!("{SENTINEL_WORDS}.xlsx"),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        POINT,
        AT,
    )?;
    // body_store.rs documents the result-body limit. For workbook bytes the separate
    // ASSET inline bound applies (store/asset_body/mod.rs); the file append stages the spill.
    let line = format!("{SENTINEL_WORDS}\n");
    let bytes = line.repeat(ASSET_INLINE_BODY_BYTES as usize / line.len() + 1);
    let mut file = tempfile::tempfile()?;
    file.write_all(bytes.as_bytes())?;
    let body = BlobBodyFile::measure(&file)?;
    let version = vault.append_blob_artifact_version_file(
        &id,
        &body,
        &BlobVersionProvenance::UserUpload,
        None,
        actor,
        POINT,
        AT,
    )?;
    Ok((id, version.content_hash))
}

fn plant_known_residues(
    vault: &Vault,
    id: EntityId,
    base_hash: [u8; 32],
    actor: WriteActor,
) -> crate::Result<[PlantedKey; 3]> {
    vault.settle_discard_edit_proposal(
        &id,
        &discard_proposal(base_hash),
        &SettleConsent::OwnerConsent { brief_ref: None },
        actor,
        SENTINEL_WORDS,
        AT + 2,
    )?;
    let settle = [
        side_table::EDIT_SETTLE_RECORD.prefix,
        id.as_bytes(),
        ContentHash::of(PROPOSAL_REF.as_bytes()).as_bytes(),
    ]
    .concat();

    // As in H1's detached-thread fixture: version 2 removes the span and the sweep quotes v1.
    let second = vault.append_blob_artifact_version(
        &id,
        b"Intro.\n",
        &BlobVersionProvenance::UserUpload,
        actor,
        POINT,
        AT + 3,
    )?;
    assert_eq!(second.version, 2);
    let thread = vault.open_annotation_thread(
        &Anchor::new(id, 1, Locator::text(0, SENTINEL_WORDS.len() as u64)?),
        actor,
        "Check this.",
        POINT,
        AT + 4,
    )?;
    let reanchor = vault.reanchor_annotation_threads(&id, 1, 2, &[], actor, POINT, AT + 5)?;
    assert_eq!(reanchor.drifted.len(), 1, "the annotation must drift");
    let unattached = [
        side_table::ANNOTATION_UNATTACHED.prefix,
        id.as_bytes(),
        thread.thread_id.as_bytes(),
    ]
    .concat();
    let retained = ArchiveRetainedSideRow {
        source_table: RETAINED_SOURCE.to_owned(),
        source_key: id.as_bytes().to_vec(),
        source_value: SENTINEL_WORDS.as_bytes().to_vec(),
        source_live: false,
    };
    assert_eq!(
        retained_subject_rule(RETAINED_SOURCE)
            .and_then(|rule| rule.records(&retained.source_key, &retained.source_value)),
        Some(vec![id]),
        "the H2 envelope must name the workbook"
    );
    assert!(
        declared().any(|table| table.name == RETAINED_SOURCE && table.actor.is_none()),
        "the H2 source table must not have an independent actor scrub"
    );
    let copy_key = retained_side_row_key(&retained);
    vault.with_write_txn(|txn| RETAINED.put(vault, txn, &copy_key, &retained))?;

    Ok([
        PlantedKey::seed(&side_table::EDIT_SETTLE_RECORD, settle),
        PlantedKey::seed(&side_table::ANNOTATION_UNATTACHED, unattached),
        PlantedKey::seed(RETAINED.decl(), RETAINED.key_bytes(&copy_key)),
    ])
}

// The production binding is private to batch::export.
const RETAINED: SideTable<[u8; 32], ArchiveRetainedSideRow, Named> =
    SideTable::new(&side_table::ARCHIVE_RETAINED_SIDE_ROW);

fn discard_proposal(base_hash: [u8; 32]) -> EditProposal {
    EditProposal {
        run_ref: PROPOSAL_REF.to_owned(),
        format: OfficeFormat::Xlsx,
        new_bytes: b"v2 bytes".to_vec(),
        manifest: EditManifest {
            schema_version: EDIT_MANIFEST_SCHEMA_VERSION,
            format: OfficeFormat::Xlsx,
            ops: Vec::new(),
            touched_parts: BTreeSet::new(),
            mutation_mode: MutationMode::Full,
            warnings: Vec::new(),
            pptx_holder_limits: None,
            slide_judgments: Vec::new(),
            paragraph_judgments: Vec::new(),
            paragraph_question: None,
            slide_question: None,
        },
        inspection: StructureSummary {
            format: OfficeFormat::Xlsx,
            sheets: Vec::new(),
            defined_names: Vec::new(),
            has_pivots: false,
            has_charts: false,
            has_macros: false,
            cross_sheet_dependencies: Vec::new(),
            unknown_parts: Vec::new(),
        },
        validation: ValidationReport {
            ok: true,
            checks: Vec::new(),
        },
        recalc: RecalcStatus::NotNeeded,
        calc_engine: None,
        base_version: Some(1),
        base_content_hash: base_hash,
        sheet_answers: None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdSlot {
    Raw,
    Hex,
}

fn id_leading() -> BTreeMap<&'static str, IdSlot> {
    let mut tables = BTreeMap::new();
    for &(name, rule) in RETAINED_SUBJECT_RULES {
        let layout = match rule {
            RetainedSubjectRule::RawIds { ids, .. } if ids.first() == Some(&0) => IdSlot::Raw,
            RetainedSubjectRule::HexIds { ids, .. } if ids.first() == Some(&0) => IdSlot::Hex,
            _ => continue,
        };
        tables.insert(name, layout);
    }
    for table in LIVE_ARCHIVE_LEADING {
        assert_eq!(
            *tables.entry(table.name).or_insert(IdSlot::Raw),
            IdSlot::Raw,
            "conflicting slot encodings for {}",
            table.name
        );
    }
    for table in NOT_PLANTED {
        tables.remove(table.name);
    }
    let declared: BTreeSet<_> = declared().map(|table| table.name).collect();
    let undeclared: Vec<_> = tables
        .keys()
        .copied()
        .filter(|name| !declared.contains(name))
        .collect();
    assert!(
        undeclared.is_empty(),
        "undeclared ID-leading tables: {undeclared:?}"
    );
    tables
}

struct PlantedKey {
    table: &'static SideTableDecl,
    key: Vec<u8>,
    has_words: bool,
}

impl PlantedKey {
    fn seed(table: &'static SideTableDecl, key: Vec<u8>) -> Self {
        Self {
            table,
            key,
            has_words: true,
        }
    }

    fn db(&self) -> &'static str {
        match self.table.db {
            SideDb::VaultMeta => "vault_meta",
            SideDb::SyncState => "sync_state",
        }
    }

    fn label(&self) -> String {
        format!(
            "{} ({}, {})",
            self.table.name,
            self.db(),
            key_hex_prefix(&self.key)
        )
    }

    fn is_kept(&self) -> bool {
        KEPT_TABLES
            .iter()
            .any(|table| table.name == self.table.name)
    }

    fn get<'txn>(
        &self,
        vault: &Vault,
        txn: &'txn RoTxn<'_>,
    ) -> TestResult<Option<std::borrow::Cow<'txn, [u8]>>> {
        Ok(match self.table.db {
            SideDb::VaultMeta => vault.store.vault_meta.get(txn, &self.key)?,
            SideDb::SyncState => vault
                .store
                .sync_state
                .get(txn, std::str::from_utf8(&self.key)?)?,
        })
    }
}

fn plant_generic_rows(
    vault: &Vault,
    id: &EntityId,
    id_hex: &str,
    tables: &BTreeMap<&str, IdSlot>,
) -> TestResult<Vec<PlantedKey>> {
    let mut rows = Vec::new();
    let mut keys = Vec::new();
    let txn = vault.store.env.read_txn()?;
    for (db, mut key, value) in fixture_rows() {
        let Some(table) = declared_for(db, &key) else {
            continue;
        };
        let Some(layout) = tables.get(table.name) else {
            continue;
        };
        let replacement: &[u8] = match layout {
            IdSlot::Raw => id.as_bytes(),
            IdSlot::Hex => id_hex.as_bytes(),
        };
        let start = table.prefix.len();
        let Some(slot) = key.get_mut(start..start + replacement.len()) else {
            continue;
        };
        slot.copy_from_slice(replacement);
        let planted = PlantedKey {
            table,
            key: key.clone(),
            has_words: false,
        };
        // The workbook's own rows (its head, its versions) stay as written, and still count:
        // a fixture value over them would corrupt the record the act deletes.
        if planted.get(vault, &txn)?.is_none() {
            rows.push((db, key, value));
        }
        keys.push(planted);
    }
    drop(txn);
    plant_fixture_rows(vault, &rows)?;
    Ok(keys)
}

fn assert_fixture_coverage(tables: &BTreeMap<&str, IdSlot>, planted: &[PlantedKey]) {
    let planted_tables: BTreeSet<_> = planted
        .iter()
        .filter(|row| !row.has_words)
        .map(|row| row.table.name)
        .collect();
    let uncovered: BTreeSet<_> = tables
        .keys()
        .copied()
        .filter(|name| !planted_tables.contains(name))
        .collect();
    let no_fixture: BTreeSet<_> = NO_FIXTURE.iter().copied().collect();
    assert_eq!(
        uncovered,
        no_fixture,
        "ID-leading fixture coverage changed: newly uncovered {:?}; stale NO_FIXTURE entries {:?}",
        uncovered.difference(&no_fixture).collect::<Vec<_>>(),
        no_fixture.difference(&uncovered).collect::<Vec<_>>(),
    );
}

fn sweep_queued(vault: &Vault) -> crate::Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let mut jobs = vault
        .store
        .sync_queue
        .prefix_iter(&txn, HARD_ERASE_SWEEP_PREFIX)?;
    Ok(jobs.next().transpose()?.is_some())
}

fn residue_violations(
    vault: &Vault,
    id: &EntityId,
    id_hex: &str,
    receipt: &EntityId,
    planted: &[PlantedKey],
) -> TestResult<Vec<String>> {
    let env = &vault.store.env;
    let _db_open = crate::store::lmdb_database_open_guard()?;
    let txn = env.read_txn()?;
    let mut violations = Vec::new();
    for row in planted {
        if !row.is_kept() && row.get(vault, &txn)?.is_some() {
            violations.push(format!("6a: planted row still present: {}", row.label()));
        }
    }

    let receipt_ids = [
        *receipt,
        redaction_sweep_completion_id(receipt)?,
        redaction_erase_final_id(receipt)?,
    ];
    let mut audit_keys = BTreeSet::new();
    for record in vault
        .store
        .port_changelog_list_by_entity(&txn, id, usize::MAX)?
    {
        // The put writes an immutable Create; the delete adds a Forget. Neither carries a patch.
        if record.entity == *id
            && record.patch.is_none()
            && matches!(record.op, ChangeOp::Create | ChangeOp::Forget)
        {
            audit_keys.insert([side_table::PORTS_CHANGE.prefix, &record.id].concat());
            for (table, subject) in [
                (&side_table::PORTS_CHANGE_BY_ACTOR, record.actor_principal),
                (&side_table::PORTS_CHANGE_BY_ENTITY, record.entity),
            ] {
                audit_keys.insert(
                    [
                        table.prefix,
                        subject.as_bytes(),
                        &record.recorded_at.to_be_bytes(),
                        &record.id,
                    ]
                    .concat(),
                );
            }
        }
    }

    let manifest: BTreeSet<_> = DB_MANIFEST.iter().map(|entry| entry.name).collect();
    let actual = crate::store::materialized_database_names(env, &txn)?;
    assert_eq!(
        actual.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        manifest,
        "the materialized database names match the manifest"
    );
    let mut opened = BTreeSet::new();
    for entry in DB_MANIFEST {
        let name = entry.name;
        let Some(db) = env.open_database::<Bytes, Bytes>(&txn, Some(name))? else {
            continue;
        };
        opened.insert(name);
        for row in db.iter(&txn)? {
            let (key, value) = row?;
            let mut kept = keeps_id(name, key, value, id, id_hex, &receipt_ids, &audit_keys);
            if kept
                && name == "sync_queue"
                && let Some(seq) = key.strip_prefix(b"q:")
            {
                // A normal pending update is not a delete-bearing delta.
                let sidecar = [b"d:", seq].concat();
                kept = db.get(&txn, &sidecar)? == Some(&[1][..]);
            }
            let kept_key = kept || keeps_planted_id_key(name, key, id, planted);
            for (location, bytes, allow_id) in [("key", key, kept_key), ("value", value, kept)] {
                for (kind, needle, allowed) in [
                    ("words", SENTINEL_WORDS.as_bytes(), false),
                    ("raw ID", id.as_bytes().as_slice(), allow_id),
                    ("hex ID", id_hex.as_bytes(), allow_id),
                ] {
                    if !allowed && contains(bytes, needle) {
                        violations.push(format!(
                            "6b: ({name}, {}, {kind}) in {location}",
                            key_hex_prefix(key)
                        ));
                    }
                }
            }
        }
    }
    assert_eq!(
        opened, manifest,
        "the unmasked scan opened every named database"
    );
    Ok(violations)
}

fn keeps_planted_id_key(db: &str, key: &[u8], id: &EntityId, planted: &[PlantedKey]) -> bool {
    db == "vault_meta"
        && KEPT_ROWS
            .iter()
            .any(|&(name, prefix)| name == db && key.starts_with(prefix))
        && (planted
            .iter()
            .any(|row| row.is_kept() && row.key.as_slice() == key)
            || key.strip_prefix(side_table::BLOB_ARTIFACT_HIGHWATER.prefix)
                == Some(id.as_bytes().as_slice()))
}

fn keeps_id(
    db: &str,
    key: &[u8],
    value: &[u8],
    id: &EntityId,
    id_hex: &str,
    receipt_ids: &[EntityId; 3],
    audit_keys: &BTreeSet<Vec<u8>>,
) -> bool {
    KEPT_ROWS.iter().any(|&(name, prefix)| {
        if name != db {
            return false;
        }
        let Some(suffix) = key.strip_prefix(prefix) else {
            return false;
        };
        match (db, prefix) {
            ("sync_state", b"dt:" | b"fedtombscope:" | b"m:dw:" | b"m:sr:") => {
                suffix == id_hex.as_bytes()
            }
            ("sync_queue", b"q:" | HARD_ERASE_SWEEP_PREFIX) => suffix.len() == 8,
            ("sync_queue", b"d:") => suffix.len() == 8 && value == [1],
            ("sync_queue", b"pt:") => {
                suffix.rsplit(|&byte| byte == b':').next() == Some(id_hex.as_bytes())
            }
            ("sync_queue", WITHDRAWN_GENERATION_SWEEP_PREFIX) => {
                suffix.len() == 24 && suffix.starts_with(id.as_bytes())
            }
            ("entities", _) => {
                value.first() == Some(&ENTITY_TYPE_REDACTION_AUDIT)
                    && receipt_ids.iter().any(|receipt| key == receipt.as_bytes())
            }
            ("type_index", _) => receipt_ids.iter().any(|receipt| {
                key == Store::encode_type_key(ENTITY_TYPE_REDACTION_AUDIT, receipt).as_slice()
            }),
            ("temporal_occurred_start" | "temporal_learned", _) => {
                key.len() == 24
                    && receipt_ids
                        .iter()
                        .any(|receipt| &key[8..] == receipt.as_bytes())
            }
            ("vault_meta", _) => audit_keys.contains(key),
            // The window snapshot and update carriers can still hold tombstones after compaction.
            ("sync_state", b"d:w:" | b"u:w:") => true,
            _ => false,
        }
    })
}

fn body_word_hits(root: &Path) -> io::Result<Vec<PathBuf>> {
    fn walk(dir: &Path, hits: &mut Vec<PathBuf>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let path = entry.path();
            if kind.is_dir() {
                walk(&path, hits)?;
            } else if kind.is_file() && contains(&fs::read(&path)?, SENTINEL_WORDS.as_bytes()) {
                hits.push(path);
            }
        }
        Ok(())
    }

    let mut hits = Vec::new();
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() => walk(root, &mut hits)?,
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    hits.sort();
    Ok(hits)
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

fn key_hex_prefix(key: &[u8]) -> String {
    bytes_to_hex_lower(&key[..key.len().min(24)])
}
