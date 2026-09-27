//! PPTX thread identity/drift and consume-once settlement using actual package bytes.
use super::*;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::edit_roundtrip::pptx::tests::support;
use crate::edit_roundtrip::pptx::{PptxCommentAction, run_comment_roundtrip};
use crate::edit_settle::SettleConsent;
use crate::error::{ArtifactError, Error};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::test_util::{embedding_test_config, open_test_vault_with};

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}
fn setup(missing: bool) -> (tempfile::TempDir, Vault, EntityId, WriteActor, Vec<u8>) {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let person = EntityId::now();
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, at(1), 1, b"reviewer")
        .unwrap();
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let artifact = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new(
                "deck.pptx",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ),
            at(2),
            2,
        )
        .unwrap();
    let bytes = support::bytes(&support::parts(missing));
    vault
        .append_blob_artifact_version(
            &artifact,
            &bytes,
            &BlobVersionProvenance::UserUpload,
            actor,
            at(3),
            3,
        )
        .unwrap();
    (dir, vault, artifact, actor, bytes)
}

#[test]
fn comment_settle_preserves_managed_thread_and_forks_once() {
    let (_dir, vault, artifact, actor, input) = setup(false);
    let thread = vault
        .open_annotation_thread(
            &Anchor::new(artifact, 1, Locator::pptx(1, support::SHAPE).unwrap()),
            actor,
            "High severity",
            at(4),
            4,
        )
        .unwrap();
    let mut patch = support::patch(true);
    patch.thread_id = thread.thread_id;
    patch.comment_id = thread.thread_id;
    let proposal = vault
        .propose_pptx_comment_edit(&artifact, &[patch], "pptx-settle")
        .unwrap();
    assert_eq!(proposal.base_version, Some(1));
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)
            .unwrap()
            .unwrap()
            .version,
        1
    );
    let consent = SettleConsent::OwnerConsent { brief_ref: None };
    let result = vault
        .settle_select_edit_proposal(&artifact, &proposal, &consent, actor, at(5), 5)
        .unwrap();
    assert_eq!(result.version.version, 2);
    assert_eq!(result.version.parent_version, Some(1));
    assert!(result.version.fork_of_version.is_some());
    assert_eq!(result.reanchor.remapped.len(), 1);
    assert!(result.reanchor.drifted.is_empty());
    assert_eq!(result.reanchor.remapped[0].anchor.version, 2);
    assert_eq!(
        result.reanchor.remapped[0].anchor.locator,
        Locator::pptx(1, support::SHAPE).unwrap()
    );
    assert_eq!(
        vault
            .read_blob_artifact_version(&artifact, 1)
            .unwrap()
            .unwrap(),
        input
    );
    assert_eq!(
        vault
            .read_blob_artifact_version(&artifact, 2)
            .unwrap()
            .unwrap(),
        proposal.new_bytes
    );
    assert!(matches!(
        vault.settle_select_edit_proposal(&artifact, &proposal, &consent, actor, at(6), 6),
        Err(Error::Artifact(
            ArtifactError::EditProposalAlreadySettled { .. }
        ))
    ));
}

#[test]
fn minted_slide_identity_advances_thread_and_explicit_unknown_pins_it() {
    for unknown in [false, true] {
        let (_dir, vault, artifact, actor, input) = setup(true);
        let thread = vault
            .open_annotation_thread(
                &Anchor::new(artifact, 1, Locator::pptx(1, support::SHAPE).unwrap()),
                actor,
                "Review",
                at(4),
                4,
            )
            .unwrap();
        let mut patch = support::patch(true);
        patch.thread_id = thread.thread_id;
        patch.comment_id = thread.thread_id;
        if let PptxCommentAction::Add { target, .. } = &mut patch.action {
            target.slide_creation_id = None;
            if unknown {
                target.shape_fingerprint = Some([99; 32]);
            }
        }
        let proposal =
            run_comment_roundtrip(&input, &[patch], if unknown { "unknown" } else { "mint" })
                .unwrap();
        let ops: Vec<_> = proposal
            .manifest
            .anchor_effects()
            .iter()
            .map(ReanchorOp::from)
            .collect();
        // Exercise the transaction-composable sweep against the uncommitted
        // new asset/version. No read transaction outside this write can see it.
        let summary = vault
            .with_write_txn(|txn| {
                vault.append_blob_artifact_version_in_txn(
                    txn,
                    &artifact,
                    &proposal.new_bytes,
                    &BlobVersionProvenance::UserUpload,
                    actor,
                    at(5),
                    5,
                )?;
                vault.reanchor_annotation_threads_in_txn(
                    txn,
                    &artifact,
                    1,
                    2,
                    &ops,
                    actor,
                    at(6),
                    6,
                )
            })
            .unwrap();
        if unknown {
            assert!(summary.remapped.is_empty());
            assert_eq!(summary.drifted.len(), 1);
            assert_eq!(summary.drifted[0].anchor.version, 1);
            assert_eq!(
                summary.drifted[0].drift,
                Some(DriftMarker {
                    drifted_at_version: 2,
                    pinned_version: 1
                })
            );
        } else {
            assert_eq!(summary.remapped.len(), 1);
            assert_eq!(summary.remapped[0].anchor.version, 2);
            assert!(summary.drifted.is_empty());
        }
    }
}

#[test]
fn deleted_shape_drifts_in_own_transaction_sweep() {
    let (_dir, vault, artifact, actor, _) = setup(false);
    let thread = vault
        .open_annotation_thread(
            &Anchor::new(artifact, 1, Locator::pptx(1, "2").unwrap()),
            actor,
            "Review",
            at(4),
            4,
        )
        .unwrap();
    let mut changed = support::parts(false);
    support::with_text(
        &mut changed,
        "ppt/slides/slide9.xml",
        support::SHAPE,
        "{11111111-2222-4333-8444-555555555555}",
    );
    vault
        .append_blob_artifact_version(
            &artifact,
            &support::bytes(&changed),
            &BlobVersionProvenance::UserUpload,
            actor,
            at(5),
            5,
        )
        .unwrap();
    let outcome = vault
        .reanchor_annotation_threads(&artifact, 1, 2, &[], actor, at(6), 6)
        .unwrap();
    assert_eq!(outcome.drifted.len(), 1);
    assert_eq!(outcome.drifted[0].thread_id, thread.thread_id);
    assert_eq!(outcome.drifted[0].anchor.version, 1);
}

#[test]
fn stale_or_tampered_pptx_preview_never_appends() {
    let (_dir, vault, artifact, actor, input) = setup(false);
    let patch = support::patch(false);
    let proposal = vault
        .propose_pptx_comment_edit(&artifact, std::slice::from_ref(&patch), "stale-pptx")
        .unwrap();
    let consent = SettleConsent::OwnerConsent { brief_ref: None };
    let mut tampered = proposal.clone();
    tampered.new_bytes = support::bytes(&support::parts(true));
    assert!(matches!(
        vault.settle_select_edit_proposal(&artifact, &tampered, &consent, actor, at(4), 4),
        Err(Error::Artifact(ArtifactError::InvalidEditManifest(_)))
    ));
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)
            .unwrap()
            .unwrap()
            .version,
        1
    );
    let other =
        run_comment_roundtrip(&input, &[support::patch(false)], "intervening-pptx").unwrap();
    vault
        .append_blob_artifact_version(
            &artifact,
            &other.new_bytes,
            &BlobVersionProvenance::UserUpload,
            actor,
            at(5),
            5,
        )
        .unwrap();
    let stale = vault
        .settle_select_edit_proposal(&artifact, &proposal, &consent, actor, at(6), 6)
        .unwrap();
    assert!(stale.stranded_proposal.is_some());
    assert_eq!(stale.receipt.outcome, "proposed");
    assert!(
        vault
            .get_annotation_thread(&artifact, &patch.thread_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)
            .unwrap()
            .unwrap()
            .version,
        2
    );
}

#[test]
fn keep_creates_managed_thread_and_engine_author_owns_resolution() {
    let (_dir, vault, artifact, actor, _) = setup(false);
    let consent = SettleConsent::OwnerConsent { brief_ref: None };
    let add = support::patch(true);
    let proposal = vault
        .propose_pptx_comment_edit(&artifact, std::slice::from_ref(&add), "managed-add")
        .unwrap();
    assert!(
        vault
            .get_annotation_thread(&artifact, &add.thread_id)
            .unwrap()
            .is_none()
    );
    vault
        .settle_select_edit_proposal(&artifact, &proposal, &consent, actor, at(4), 4)
        .unwrap();
    let thread = vault
        .get_annotation_thread(&artifact, &add.thread_id)
        .unwrap()
        .unwrap();
    assert_eq!(thread.anchor.version, 2);
    assert_eq!(
        thread.anchor.locator,
        Locator::pptx(1, support::SHAPE).unwrap()
    );
    let comments = vault
        .annotation_thread_comments(&artifact, &add.thread_id)
        .unwrap();
    assert_eq!(comments.len(), 1);
    if let PptxCommentAction::Add { text, .. } = &add.action {
        assert_eq!(&comments[0].text, text);
    }
    assert_eq!(comments[0].author, actor.entity_ref());
    let other = EntityId::now();
    vault
        .put_entity(&other, ENTITY_TYPE_PERSON, at(5), 5, b"other")
        .unwrap();
    let other_actor = WriteActor::new(other, EdgeActorClass::Human);
    let mut reply = add.clone();
    reply.comment_id = EntityId::now();
    reply.action = PptxCommentAction::Reply {
        text: "Another opinion".into(),
    };
    let reply_proposal = vault
        .propose_pptx_comment_edit(&artifact, &[reply], "managed-reply")
        .unwrap();
    vault
        .settle_select_edit_proposal(&artifact, &reply_proposal, &consent, other_actor, at(6), 6)
        .unwrap();
    let mut resolve = add.clone();
    resolve.action = PptxCommentAction::Resolve { resolved: true };
    let resolution = vault
        .propose_pptx_comment_edit(&artifact, &[resolve], "managed-resolve")
        .unwrap();
    // Export GUID is deliberately the owner's. Engine authorization must still
    // reject the other actor and roll back the attempted append and ledger.
    assert!(matches!(
        vault.settle_select_edit_proposal(&artifact, &resolution, &consent, other_actor, at(7), 7),
        Err(Error::Artifact(ArtifactError::SettleNotAuthorized(_)))
    ));
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)
            .unwrap()
            .unwrap()
            .version,
        3
    );
    assert!(
        vault
            .blob_artifact_settlement(&artifact, "managed-resolve")
            .unwrap()
            .is_none()
    );
    vault
        .settle_select_edit_proposal(&artifact, &resolution, &consent, actor, at(8), 8)
        .unwrap();
    let thread = vault
        .get_annotation_thread(&artifact, &add.thread_id)
        .unwrap()
        .unwrap();
    assert_eq!(thread.state, ThreadState::Resolved);
    assert_eq!(thread.anchor.version, 4);
    assert_eq!(
        vault
            .annotation_thread_comments(&artifact, &add.thread_id)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn discard_keeps_file_and_managed_thread_absent() {
    let (_dir, vault, artifact, actor, input) = setup(false);
    let add = support::patch(false);
    let proposal = vault
        .propose_pptx_comment_edit(&artifact, std::slice::from_ref(&add), "discard-pptx")
        .unwrap();
    vault
        .settle_discard_edit_proposal(
            &artifact,
            &proposal,
            &SettleConsent::OwnerConsent { brief_ref: None },
            actor,
            "discarded",
            4,
        )
        .unwrap();
    assert!(
        vault
            .get_annotation_thread(&artifact, &add.thread_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)
            .unwrap()
            .unwrap()
            .version,
        1
    );
    assert_eq!(
        vault
            .read_blob_artifact_version(&artifact, 1)
            .unwrap()
            .unwrap(),
        input
    );
}

#[test]
fn minted_identity_is_disclosed_by_the_durable_settle_receipt() {
    let (_dir, vault, artifact, actor, _input) = setup(true);
    let mut patch = support::patch(true);
    if let PptxCommentAction::Add { target, .. } = &mut patch.action {
        target.slide_creation_id = None;
    }
    let asker = patch.asked_by;
    let answerer = patch.answered_by;
    let exported = patch.author.guid.clone();
    let proposal = vault
        .propose_pptx_comment_edit(&artifact, &[patch], "mint-disclosure")
        .unwrap();
    let selected = vault
        .settle_select_edit_proposal(
            &artifact,
            &proposal,
            &SettleConsent::OwnerConsent { brief_ref: None },
            actor,
            at(5),
            5,
        )
        .unwrap();
    let mints: Vec<(u64, u32)> =
        serde_json::from_str(&selected.receipt.fields["pptx_slide_creation_id_mints"]).unwrap();
    assert_eq!(mints.len(), 1);
    assert_eq!(mints[0].0, 1);
    let record = vault
        .blob_artifact_settlement(&artifact, "mint-disclosure")
        .unwrap()
        .unwrap();
    assert_eq!(record.pptx_slide_creation_id_mints, mints);
    assert_eq!(record.pptx_review_identities.len(), 1);
    let identity = &record.pptx_review_identities[0];
    assert_eq!(identity.asked_by, asker);
    assert_eq!(identity.answered_by, answerer);
    assert_eq!(identity.export_author_guid, exported);
    assert_ne!(identity.asked_by, identity.answered_by);
    let receipt: serde_json::Value =
        serde_json::from_str(&selected.receipt.fields["pptx_review_identities"]).unwrap();
    assert_eq!(receipt[0]["asked_by"], asker.to_hex());
    assert_eq!(receipt[0]["answered_by"], answerer.to_hex());
    assert_eq!(receipt[0]["export_author_guid"], exported);
}

#[test]
fn pptx_proposal_cannot_settle_on_a_non_pptx_artifact() {
    let (_dir, vault, _deck, actor, bytes) = setup(false);
    let artifact = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new(
                "mislabelled.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
            at(10),
            10,
        )
        .unwrap();
    vault
        .append_blob_artifact_version(
            &artifact,
            &bytes,
            &BlobVersionProvenance::UserUpload,
            actor,
            at(11),
            11,
        )
        .unwrap();
    let mut proposal =
        run_comment_roundtrip(&bytes, &[support::patch(false)], "wrong-media").unwrap();
    proposal.base_version = Some(1);
    assert!(
        vault
            .propose_pptx_comment_edit(&artifact, &[support::patch(false)], "wrong-media-direct")
            .is_err()
    );
    assert!(matches!(
        vault.settle_select_edit_proposal(
            &artifact,
            &proposal,
            &SettleConsent::OwnerConsent { brief_ref: None },
            actor,
            at(12),
            12,
        ),
        Err(Error::Artifact(ArtifactError::InvalidEditManifest(_)))
    ));
    assert_eq!(vault.blob_artifact_versions(&artifact).unwrap().len(), 1);
}
