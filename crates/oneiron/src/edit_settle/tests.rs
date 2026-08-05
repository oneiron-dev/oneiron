//! ARTL-4 settle tests. Proposals are constructed directly (the ARTL-3 pipeline
//! and its `opc` fixtures are covered in `edit_roundtrip`); settle only reads a
//! proposal's bytes, manifest, and validation flag, never re-parsing the bytes.

use std::collections::BTreeSet;

use super::*;
use crate::anchored_annotation::Anchor;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::edge::EdgeActorClass;
use crate::edit_roundtrip::{
    EDIT_MANIFEST_SCHEMA_VERSION, EditManifest, EditOp, EditProposal, MutationMode, OfficeFormat,
    RecalcStatus, StructureSummary, ValidationReport,
};
use crate::error::Error;
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

fn xlsx_anchor(artifact_id: EntityId, version: u64, sheet: &str, range: &str) -> Anchor {
    Anchor::new(
        artifact_id,
        version,
        Locator::xlsx(sheet, range).expect("xlsx locator"),
    )
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
        base_version: Some(1),
        base_content_hash: *blake3::hash(WORKBOOK_V1_BYTES).as_bytes(),
    }
}

// Acceptance 1: an unsettled proposal is invisible to the version chain; a
// select makes exactly its bytes the new head version.
#[test]
fn unsettled_proposal_is_invisible_until_select() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let artifact = put_workbook(&vault, actor, 10);

    let prop = proposal("run:invisible", b"edited xlsx bytes v2", Vec::new());
    // Retained: nothing is a version yet, and there is no v2 to read.
    assert_eq!(vault.blob_artifact_versions(&artifact)?.len(), 1);
    assert_eq!(
        vault.blob_artifact_head(&artifact)?.map(|h| h.version),
        Some(1)
    );
    assert_eq!(vault.read_blob_artifact_version(&artifact, 2)?, None);

    let out =
        vault.settle_select_edit_proposal(&artifact, &prop, &owner(), actor, test_time(11), 11)?;
    assert_eq!(out.version.version, 2);
    // Now visible as v2 with exactly the proposal's bytes, provenance AgentRun.
    assert_eq!(vault.blob_artifact_versions(&artifact)?.len(), 2);
    assert_eq!(
        vault.read_blob_artifact_version(&artifact, 2)?.as_deref(),
        Some(b"edited xlsx bytes v2".as_slice())
    );
    assert_eq!(
        out.version.provenance,
        BlobVersionProvenance::AgentRun {
            run_ref: "run:invisible".to_owned(),
        }
    );
    Ok(())
}

// Acceptance 2: settlement is consume-once — select→select, select→discard,
// and discard→select are each a typed refusal, and a refused select appends no
// version.
#[test]
fn double_settle_is_refused_across_all_paths() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);

    // select then select.
    let artifact = put_workbook(&vault, actor, 10);
    let prop = proposal("run:ss", b"v2 bytes", Vec::new());
    vault.settle_select_edit_proposal(&artifact, &prop, &owner(), actor, test_time(11), 11)?;
    let err = vault
        .settle_select_edit_proposal(&artifact, &prop, &owner(), actor, test_time(12), 12)
        .expect_err("second select must refuse");
    assert!(matches!(
        err,
        Error::EditProposalAlreadySettled {
            outcome: "selected"
        }
    ));

    // select then discard.
    let artifact = put_workbook(&vault, actor, 10);
    let prop = proposal("run:sd", b"v2 bytes", Vec::new());
    vault.settle_select_edit_proposal(&artifact, &prop, &owner(), actor, test_time(11), 11)?;
    let err = vault
        .settle_discard_edit_proposal(&artifact, &prop, &owner(), actor, "changed mind", 12)
        .expect_err("discard after select must refuse");
    assert!(matches!(
        err,
        Error::EditProposalAlreadySettled {
            outcome: "selected"
        }
    ));

    // discard then select — and the refused select appends no version.
    let artifact = put_workbook(&vault, actor, 10);
    let prop = proposal("run:ds", b"v2 bytes", Vec::new());
    vault.settle_discard_edit_proposal(&artifact, &prop, &owner(), actor, "no thanks", 11)?;
    let err = vault
        .settle_select_edit_proposal(&artifact, &prop, &owner(), actor, test_time(12), 12)
        .expect_err("select after discard must refuse");
    assert!(matches!(
        err,
        Error::EditProposalAlreadySettled {
            outcome: "discarded"
        }
    ));
    assert_eq!(
        vault.blob_artifact_versions(&artifact)?.len(),
        1,
        "a refused select must not append a version"
    );
    Ok(())
}

// Acceptance 3 + 4: both paths land an OF-367 family receipt; the select
// receipt + door resolve artifact@version and the moved anchor, the discard
// receipt records the proposal ref.
#[test]
fn both_settle_paths_are_receipted_and_the_door_resolves() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let artifact = put_workbook(&vault, actor, 10);
    let thread = vault.open_annotation_thread(
        &xlsx_anchor(artifact, 1, "Sheet1", "B5:D8"),
        actor,
        "recompute this block",
        test_time(11),
        11,
    )?;
    let brief = vault.assign_annotation_thread_to_brief(
        &artifact,
        &thread.thread_id,
        None,
        actor,
        test_time(11),
        11,
    )?;

    let prop = proposal(
        "run:select#1",
        b"v2 bytes",
        vec![EditOp::InsertRows {
            sheet: "Sheet1".to_owned(),
            at: 1,
            count: 2,
        }],
    );
    let consent = SettleConsent::OwnerConsent {
        brief_ref: Some(brief.brief_ref.clone()),
    };
    let out =
        vault.settle_select_edit_proposal(&artifact, &prop, &consent, actor, test_time(12), 12)?;

    // Select receipt resolves artifact@version + the moved anchor, and joins the
    // brief's project view.
    let receipt = &out.receipt;
    assert_eq!(receipt.receipt_kind, ReceiptKind::ArtifactSettle);
    assert_eq!(receipt.outcome, "selected");
    assert_eq!(
        receipt.fields.get("artifact_ref").map(String::as_str),
        Some(artifact.to_hex().as_str())
    );
    assert_eq!(receipt.fields.get("version").map(String::as_str), Some("2"));
    // Before/after version pair (D6): the head it committed onto was v1.
    assert_eq!(
        receipt.fields.get("before_version").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        receipt.fields.get("anchor_moves").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        receipt.fields.get("anchor_drifts").map(String::as_str),
        Some("0")
    );
    assert_eq!(receipt.job_ref.as_deref(), Some(brief.brief_ref.as_str()));
    assert_eq!(
        receipt.trigger_ref.as_deref(),
        Some(format!("artifact:{}@2", artifact.to_hex()).as_str())
    );

    // The door resolves artifact@version + the anchor set that moved.
    let door = vault
        .settle_receipt_door(&artifact, "run:select#1")?
        .expect("select receipt door");
    assert_eq!(door.artifact_id, artifact);
    assert_eq!(door.version, 2);
    assert_eq!(door.anchors.len(), 1);
    assert_eq!(door.anchors[0].thread_id, thread.thread_id);
    assert!(!door.anchors[0].drifted);
    assert_eq!(
        door.anchors[0].locator,
        Locator::xlsx("Sheet1", "B7:D10").expect("locator")
    );

    // The unified receipt family surfaces the select receipt.
    let family = vault.receipts(ReceiptQuery::new(50).with_kind(ReceiptKind::ArtifactSettle))?;
    assert!(family.iter().any(|rec| {
        rec.outcome == "selected" && rec.fields.get("version").map(String::as_str) == Some("2")
    }));

    // Discard on a fresh proposal: receipt records the proposal ref + reason,
    // and there is no artifact@version door.
    let discard = proposal("run:discard#1", b"v2 alternate", Vec::new());
    let out = vault.settle_discard_edit_proposal(
        &artifact,
        &discard,
        &owner(),
        actor,
        "superseded by another edit",
        13,
    )?;
    assert_eq!(out.receipt.receipt_kind, ReceiptKind::ArtifactSettle);
    assert_eq!(out.receipt.outcome, "discarded");
    assert_eq!(
        out.receipt.fields.get("proposal_ref").map(String::as_str),
        Some("run:discard#1")
    );
    assert_eq!(
        out.receipt.trigger_ref.as_deref(),
        Some("proposal:run:discard#1")
    );
    assert_eq!(
        out.receipt.fields.get("reason").map(String::as_str),
        Some("superseded by another edit")
    );
    assert!(
        vault
            .settle_receipt_door(&artifact, "run:discard#1")?
            .is_none()
    );

    let family = vault.receipts(ReceiptQuery::new(50).with_kind(ReceiptKind::ArtifactSettle))?;
    assert!(family.iter().any(|rec| rec.outcome == "discarded"));
    assert!(family.iter().any(|rec| rec.outcome == "selected"));
    Ok(())
}

// Acceptance 6: on select the manifest's anchor effects replay onto threads — a
// thread on a moved cell remaps to the new version; a thread on a deleted range
// drifts and stays pinned to its origin version.
#[test]
fn select_replays_manifest_anchors_onto_threads() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let artifact = put_workbook(&vault, actor, 10);
    let moved = vault.open_annotation_thread(
        &xlsx_anchor(artifact, 1, "Sheet1", "B5:D8"),
        actor,
        "this block shifts down",
        test_time(11),
        11,
    )?;
    let deleted = vault.open_annotation_thread(
        &xlsx_anchor(artifact, 1, "Sheet1", "B20:C21"),
        actor,
        "this block is deleted",
        test_time(11),
        11,
    )?;

    // Insert two rows at the top (shifts every anchor down by 2), then delete the
    // two rows the second anchor now occupies (destroying it).
    let prop = proposal(
        "run:reanchor",
        b"v2 bytes",
        vec![
            EditOp::InsertRows {
                sheet: "Sheet1".to_owned(),
                at: 1,
                count: 2,
            },
            EditOp::DeleteRows {
                sheet: "Sheet1".to_owned(),
                at: 22,
                count: 2,
            },
        ],
    );
    let out =
        vault.settle_select_edit_proposal(&artifact, &prop, &owner(), actor, test_time(12), 12)?;
    assert_eq!(out.version.version, 2);
    assert_eq!(out.reanchor.remapped.len(), 1);
    assert_eq!(out.reanchor.drifted.len(), 1);

    // The moved thread advanced to v2 with a remapped locator.
    let moved = vault
        .get_annotation_thread(&artifact, &moved.thread_id)?
        .expect("moved thread");
    assert!(!moved.is_drifted());
    assert_eq!(moved.anchor.version, 2);
    assert_eq!(
        moved.anchor.locator,
        Locator::xlsx("Sheet1", "B7:D10").expect("locator")
    );

    // The deleted-range thread drifted, pinned to its origin version + locator.
    let deleted = vault
        .get_annotation_thread(&artifact, &deleted.thread_id)?
        .expect("deleted thread");
    assert!(deleted.is_drifted());
    assert_eq!(deleted.anchor.version, 1);
    assert_eq!(
        deleted.anchor.locator,
        Locator::xlsx("Sheet1", "B20:C21").expect("locator")
    );
    Ok(())
}

// Acceptance 5: with no covering DEC-0006 grant, StandingGrant consent fails
// closed (committing nothing) while owner consent settles the same proposal.
#[test]
fn standing_grant_consent_fails_closed_without_a_covering_grant() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let artifact = put_workbook(&vault, actor, 10);

    // No grant row exists, so there is no standing settle authority.
    assert!(!vault.settle_standing_grant_authorizes(actor, "brief:acme")?);

    let prop = proposal("run:grant", b"v2 bytes", Vec::new());
    let consent = SettleConsent::StandingGrant {
        brief_ref: "brief:acme".to_owned(),
    };
    let err = vault
        .settle_select_edit_proposal(&artifact, &prop, &consent, actor, test_time(11), 11)
        .expect_err("standing-grant consent has no covering grant");
    assert!(matches!(err, Error::SettleNotAuthorized(_)));
    // The refused settle committed nothing.
    assert_eq!(vault.blob_artifact_versions(&artifact)?.len(), 1);
    assert!(
        vault
            .blob_artifact_settlement(&artifact, "run:grant")?
            .is_none()
    );

    // Owner consent settles the same proposal.
    let out = vault.settle_select_edit_proposal(
        &artifact,
        &prop,
        &SettleConsent::OwnerConsent { brief_ref: None },
        actor,
        test_time(11),
        11,
    )?;
    assert_eq!(out.version.version, 2);
    Ok(())
}

/// DEC-0006: `settle_standing_grant_authorizes` accepts ONLY a live action
/// grant covering the acting actor + `artifact.settle` + the exact brief, and
/// rejects disclosure grants, other actors, wider-target assumptions, revoked
/// rows, and catastrophe classes.
#[test]
fn settle_standing_grant_requires_the_exact_actor_verb_class_and_brief() -> Result<()> {
    use crate::consent::{
        ActionClass, ActionEnvelope, ActorBound, AudienceBound, CATASTROPHE_FLOOR_V1,
        DisclosureClass, DisclosureEnvelope, GrantBound,
    };
    use crate::error::ErrorKind;
    use crate::store::GateDecisionId;

    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let other = put_actor(&vault, 10);
    let owner = vault.authenticate_owner(
        actor.entity_ref(),
        "principal:owner",
        true,
        GateDecisionId::now(),
    )?;

    let settle_bound = |actor: WriteActor, brief: &str| {
        GrantBound::action(
            ActorBound::new(actor.entity_ref().to_hex()).expect("actor"),
            ActionClass::new(SETTLE_VERB_CLASS).expect("class"),
            ActionEnvelope::new([brief.to_owned()])
                .expect("envelope")
                .with_target(brief)
                .expect("target"),
        )
        .expect("bound")
    };

    // A DISCLOSURE grant naming the same brief authorizes nothing: the two
    // domains are disjoint types.
    vault.create_standing_grant(
        &owner,
        GrantBound::disclosure(
            AudienceBound::singleton("contact:acme").expect("audience"),
            DisclosureClass::new(SETTLE_VERB_CLASS).expect("class"),
            DisclosureEnvelope::new(["brief:acme".to_owned()]).expect("envelope"),
        )
        .expect("bound"),
    )?;
    assert!(!vault.settle_standing_grant_authorizes(actor, "brief:acme")?);

    // ANOTHER ACTOR's settle grant does not authorize this actor.
    vault.create_standing_grant(&owner, settle_bound(other, "brief:acme"))?;
    assert!(!vault.settle_standing_grant_authorizes(actor, "brief:acme")?);

    // A grant on a DIFFERENT BRIEF does not cover this one, so a wider-target
    // assumption cannot be smuggled in.
    vault.create_standing_grant(&owner, settle_bound(actor, "brief:other"))?;
    assert!(!vault.settle_standing_grant_authorizes(actor, "brief:acme")?);

    // The exact bound DOES authorize, and the settle then commits.
    let exact = settle_bound(actor, "brief:acme");
    vault.create_standing_grant(&owner, exact.clone())?;
    assert!(vault.settle_standing_grant_authorizes(actor, "brief:acme")?);

    let artifact = put_workbook(&vault, actor, 10);
    let prop = proposal("run:standing", b"v2 bytes", Vec::new());
    let consent = SettleConsent::StandingGrant {
        brief_ref: "brief:acme".to_owned(),
    };
    let out =
        vault.settle_select_edit_proposal(&artifact, &prop, &consent, actor, test_time(11), 11)?;
    assert_eq!(out.version.version, 2);

    // REVOCATION is immediate: the same consent stops authorizing at once.
    vault.revoke_consent_grant(&owner, &exact.digest().to_hex())?;
    assert!(!vault.settle_standing_grant_authorizes(actor, "brief:acme")?);
    let prop2 = proposal("run:standing-2", b"v3 bytes", Vec::new());
    let err = vault
        .settle_select_edit_proposal(&artifact, &prop2, &consent, actor, test_time(12), 12)
        .expect_err("revoked grant authorizes nothing");
    assert!(matches!(err, Error::SettleNotAuthorized(_)));

    // A CATASTROPHE class can never become a settle grant in the first place.
    for catastrophe in CATASTROPHE_FLOOR_V1 {
        let bound = GrantBound::action(
            ActorBound::new(actor.entity_ref().to_hex()).expect("actor"),
            ActionClass::new(catastrophe.as_str()).expect("class"),
            ActionEnvelope::new(["brief:acme".to_owned()]).expect("envelope"),
        )
        .expect("bound");
        assert_eq!(
            vault
                .create_standing_grant(&owner, bound)
                .expect_err("catastrophe bound")
                .kind(),
            ErrorKind::ConsentCatastropheNotRememberable
        );
    }
    Ok(())
}

#[test]
fn settlement_record_round_trips_through_msgpack() -> Result<()> {
    let selected = SettlementRecord {
        proposal_ref: "run:codec".to_owned(),
        outcome: SettleOutcomeKind::Selected,
        settled_at: 42,
        actor_ref: Some("cafef00d".to_owned()),
        brief_ref: Some("brief:codec".to_owned()),
        before_version: Some(6),
        version: Some(7),
        content_hash: Some([0xA5; BLOB_ARTIFACT_CONTENT_HASH_LEN]),
        manifest_ref: Some([0xB6; 32]),
        manifest_ops: 3,
        anchors: vec![
            SettledAnchor {
                thread_id: EntityId::now(),
                locator: Locator::xlsx("Sheet1", "B7:D10").expect("locator"),
                drifted: false,
            },
            SettledAnchor {
                thread_id: EntityId::now(),
                locator: Locator::xlsx("Sheet1", "B20:C21").expect("locator"),
                drifted: true,
            },
        ],
        reason: None,
    };
    let bytes = encode_settlement_record(&selected)?;
    assert_eq!(decode_settlement_record(&bytes)?, selected);

    let discarded = SettlementRecord {
        proposal_ref: "run:codec-d".to_owned(),
        outcome: SettleOutcomeKind::Discarded,
        settled_at: 43,
        actor_ref: None,
        brief_ref: None,
        before_version: None,
        version: None,
        content_hash: None,
        manifest_ref: None,
        manifest_ops: 0,
        anchors: Vec::new(),
        reason: Some("not wanted".to_owned()),
    };
    let bytes = encode_settlement_record(&discarded)?;
    assert_eq!(decode_settlement_record(&bytes)?, discarded);
    Ok(())
}

// P1 rider + atomicity: a stale proposal (its base no longer matches the head
// after an intervening edit) is refused, and the refused select is atomic —
// nothing is appended and no ledger row is written.
#[test]
fn stale_base_select_is_refused_atomically() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let artifact = put_workbook(&vault, actor, 10);

    // A proposal produced from v1.
    let prop = proposal("run:stale", b"agent edit off v1", Vec::new());

    // An intervening user edit moves the head to v2 before the agent proposal
    // settles.
    vault.append_blob_artifact_version(
        &artifact,
        b"human edit v2",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(11),
        11,
    )?;

    // Settling the now-stale proposal is refused: its base (v1) no longer
    // matches the head (v2).
    let err = vault
        .settle_select_edit_proposal(&artifact, &prop, &owner(), actor, test_time(12), 12)
        .expect_err("a stale proposal must be refused");
    assert_eq!(err.kind(), crate::error::ErrorKind::EditProposalStale);

    // Atomic refusal: no v3 appended, no ledger row, no receipt.
    assert_eq!(vault.blob_artifact_versions(&artifact)?.len(), 2);
    assert!(
        vault
            .blob_artifact_settlement(&artifact, "run:stale")?
            .is_none()
    );
    assert!(
        vault
            .receipts(ReceiptQuery::new(50).with_kind(ReceiptKind::ArtifactSettle))?
            .is_empty()
    );
    Ok(())
}

// Rider 7: a discard on a nonexistent (or wrong-type) artifact is refused and
// lands no durable ledger row.
#[test]
fn discard_on_nonexistent_artifact_is_refused() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let bogus = EntityId::now(); // never created as a BLOB_ARTIFACT
    let prop = proposal("run:bogus", b"v2 bytes", Vec::new());

    let err = vault
        .settle_discard_edit_proposal(&bogus, &prop, &owner(), actor, "no", 11)
        .expect_err("discard on a nonexistent artifact must refuse");
    assert_eq!(err.kind(), crate::error::ErrorKind::EntityNotFound);
    assert!(
        vault
            .blob_artifact_settlement(&bogus, "run:bogus")?
            .is_none()
    );
    Ok(())
}

// Rider 6: a discard validates the proposal ref (the same bar select applies)
// before persisting a ledger row — a blank ref is refused.
#[test]
fn discard_validates_proposal_ref() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let artifact = put_workbook(&vault, actor, 10);
    let prop = proposal("   ", b"v2 bytes", Vec::new());

    let err = vault
        .settle_discard_edit_proposal(&artifact, &prop, &owner(), actor, "no", 11)
        .expect_err("a blank proposal ref must be refused");
    assert_eq!(err.kind(), crate::error::ErrorKind::EditRoundtripFailed);
}
