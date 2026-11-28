//! Artifact hard-delete empties settlement words but keeps the records
//! (FIX HARD-DELETE-SETTLED-WORDS-OUTLIVE-ARTIFACT).

use std::collections::BTreeSet;

use super::*;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::deletion::DeleteReason;
use crate::edge::EdgeActorClass;
use crate::edit_roundtrip::{
    EDIT_MANIFEST_SCHEMA_VERSION, EditManifest, EditOp, EditProposal, MutationMode, OfficeFormat,
    RecalcStatus, StructureSummary, ValidationReport,
};
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::test_util::embedding_test_config;
use crate::write_envelope::WriteActor;

/// The v1 bytes `put_workbook` uploads — the base every hand-built proposal is
/// pinned to (a proposal is produced FROM the head it edits).
const WORKBOOK_V1_BYTES: &[u8] = b"workbook bytes v1";

fn test_time(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn put_actor(vault: &Vault, at: u64) -> WriteActor {
    let actor_id = EntityId::now();
    vault
        .put_entity(&actor_id, ENTITY_TYPE_PERSON, test_time(at), at, b"human")
        .expect("put actor");
    WriteActor::new(actor_id, EdgeActorClass::Human)
}

fn put_workbook(vault: &Vault, actor: WriteActor, at: u64) -> EntityId {
    let artifact_id = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact_id,
            &BlobArtifactBody::new(
                "forecast.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
            test_time(at),
            at,
        )
        .expect("put workbook");
    vault
        .append_blob_artifact_version(
            &artifact_id,
            WORKBOOK_V1_BYTES,
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(at),
            at,
        )
        .expect("append v1");
    artifact_id
}

fn owner() -> SettleConsent {
    SettleConsent::OwnerConsent { brief_ref: None }
}

/// Builds a retained proposal by hand — settle never re-parses `new_bytes`, so
/// arbitrary non-empty bytes stand in for the edited xlsx. The proposal is
/// pinned to the v1 base `put_workbook` uploads, so it settles non-stale as long
/// as no intervening edit has moved the head.
fn proposal(run_ref: &str, new_bytes: &[u8], ops: Vec<EditOp>) -> EditProposal {
    EditProposal {
        run_ref: run_ref.to_owned(),
        format: OfficeFormat::Xlsx,
        new_bytes: new_bytes.to_vec(),
        manifest: EditManifest {
            schema_version: EDIT_MANIFEST_SCHEMA_VERSION,
            format: OfficeFormat::Xlsx,
            ops,
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
        base_content_hash: *blake3::hash(WORKBOOK_V1_BYTES).as_bytes(),
        sheet_answers: None,
    }
}

#[test]
fn hard_delete_of_an_artifact_empties_its_settlement_words_and_keeps_the_record() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let artifact = put_workbook(&vault, actor, 10);
    vault.settle_discard_edit_proposal(
        &artifact,
        &proposal("run:discard#1", b"v2 bytes", vec![]),
        &owner(),
        actor,
        "the B5 totals are wrong",
        12,
    )?;
    let query = || ReceiptQuery::new(50).with_kind(ReceiptKind::ArtifactSettle);
    let hex = artifact.to_hex();
    let before = vault.receipts(query())?;
    let ours: Vec<_> = before
        .iter()
        .filter(|rec| rec.fields.get("artifact_ref").map(String::as_str) == Some(hex.as_str()))
        .collect();
    assert_eq!(ours.len(), 1);
    assert_eq!(
        ours[0].fields.get("reason").map(String::as_str),
        Some("the B5 totals are wrong")
    );
    vault.delete_entity_with_reason(&artifact, DeleteReason::UserHardDelete)?;
    let rtxn = vault.store.env.read_txn()?;
    let rows = super::codec::RECORD.scan_from(&vault.store, &rtxn, artifact.as_bytes())?;
    // The receipt projection opens its own read txn: no nested one on this thread.
    drop(rtxn);
    let kept: Vec<_> = rows
        .into_iter()
        .filter(|((owner, _), _)| *owner == artifact)
        .collect();
    assert_eq!(kept.len(), 1);
    assert!(kept[0].1.reason.is_none());
    assert!(kept[0].1.discarded_words.is_some());
    let after = vault.receipts(query())?;
    assert!(!after.iter().any(|rec| rec.fields.contains_key("reason")));
    assert!(
        !after
            .iter()
            .flat_map(|rec| rec.fields.values())
            .any(|value| value.contains("B5 totals"))
    );
    Ok(())
}

#[test]
fn deleting_one_artifact_keeps_another_artifacts_settlement_words() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let first = put_workbook(&vault, actor, 10);
    let second = put_workbook(&vault, actor, 10);
    vault.settle_discard_edit_proposal(
        &first,
        &proposal("run:discard#1", b"v2 bytes", vec![]),
        &owner(),
        actor,
        "the B5 totals are wrong",
        12,
    )?;
    vault.settle_discard_edit_proposal(
        &second,
        &proposal("run:discard#2", b"v2 bytes", vec![]),
        &owner(),
        actor,
        "the C7 averages are stale",
        12,
    )?;
    vault.delete_entity_with_reason(&first, DeleteReason::UserHardDelete)?;
    let rtxn = vault.store.env.read_txn()?;
    let rows = super::codec::RECORD.scan_from(&vault.store, &rtxn, second.as_bytes())?;
    drop(rtxn);
    let kept: Vec<_> = rows
        .into_iter()
        .filter(|((owner, _), _)| *owner == second)
        .collect();
    assert_eq!(kept.len(), 1);
    assert_eq!(
        kept[0].1.reason.as_deref(),
        Some("the C7 averages are stale")
    );
    let hex = second.to_hex();
    let family = vault.receipts(ReceiptQuery::new(50).with_kind(ReceiptKind::ArtifactSettle))?;
    let ours: Vec<_> = family
        .iter()
        .filter(|rec| rec.fields.get("artifact_ref").map(String::as_str) == Some(hex.as_str()))
        .collect();
    assert_eq!(ours.len(), 1);
    assert_eq!(
        ours[0].fields.get("reason").map(String::as_str),
        Some("the C7 averages are stale")
    );
    Ok(())
}
