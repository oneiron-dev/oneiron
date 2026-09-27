//! Native DOCX proposal proofs at the public edit door.

use super::{EditOp, EditOutcome, OfficeFormat, run_docx_revision};
use oneiron_docedit::Document;

const DOCX: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../oneiron-docedit/vendor/stemma-engine/testdata/simple-text/before.docx"
));

fn replace_first_paragraph(guard: &str) -> String {
    let doc = Document::parse(DOCX).expect("fixture parses");
    let block = &doc.read().blocks[0];
    serde_json::json!({
        "ops": [{ "op": "replace", "target": block.id, "guard": guard,
            "content": { "type": "paragraph", "content": [
                {"type": "text", "text": "A tracked replacement."}
            ]}
        }],
        "revision": { "author": "Editor" }
    })
    .to_string()
}

#[test]
fn native_docx_proposal_contains_word_revisions_and_retains_unedited_parts() {
    let doc = Document::parse(DOCX).unwrap();
    let json = replace_first_paragraph(&doc.read().blocks[0].guard);
    let EditOutcome::Proposed(proposal) = run_docx_revision(DOCX, &json, "docx-run").unwrap()
    else {
        panic!("valid native revision must produce a settleable proposal");
    };
    assert_eq!(proposal.format, OfficeFormat::Docx);
    assert!(proposal.validation.ok);
    assert!(
        proposal
            .manifest
            .touched_parts
            .contains("word/document.xml")
    );
    assert!(matches!(
        proposal.manifest.ops.as_slice(),
        [EditOp::DocxRevision { transaction }] if transaction == &json
    ));
    let package = super::opc::read(&proposal.new_bytes).unwrap();
    let xml = std::str::from_utf8(package.part("word/document.xml").unwrap()).unwrap();
    assert!(xml.contains("w:ins"), "Word insertion mark absent");
    assert!(xml.contains("w:del"), "Word deletion mark absent");
    let edited = Document::parse(&proposal.new_bytes).unwrap();
    assert!(
        edited
            .read_accepted()
            .unwrap()
            .to_text()
            .contains("A tracked replacement.")
    );
    assert!(
        !edited
            .read_rejected()
            .unwrap()
            .to_text()
            .contains("A tracked replacement.")
    );
}

#[test]
fn native_docx_refuses_stale_guard_and_invalid_transactions() {
    assert!(run_docx_revision(DOCX, &replace_first_paragraph("stale"), "run").is_err());
    assert!(run_docx_revision(DOCX, "{not-json}", "run").is_err());
    assert!(run_docx_revision(DOCX, "{}", "run").is_err());
}

#[test]
fn docx_artifact_proposal_settles_through_the_receipted_version_door() -> crate::error::Result<()> {
    use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
    use crate::edge::EdgeActorClass;
    use crate::edit_settle::SettleConsent;
    use crate::entity_id::EntityId;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::temporal::TimeRange;
    use crate::test_util::embedding_test_config;
    use crate::write_envelope::WriteActor;

    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let at = TimeRange { start: 10, end: 10 };
    let actor_id = EntityId::now();
    vault.put_entity(&actor_id, ENTITY_TYPE_PERSON, at, 10, b"owner")?;
    let actor = WriteActor::new(actor_id, EdgeActorClass::Human);
    let artifact = EntityId::now();
    vault.put_blob_artifact(
        &artifact,
        &BlobArtifactBody::new(
            "edited.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        at,
        10,
    )?;
    vault.append_blob_artifact_version(
        &artifact,
        DOCX,
        &BlobVersionProvenance::UserUpload,
        actor,
        at,
        10,
    )?;
    let guard = Document::parse(DOCX).unwrap().read().blocks[0]
        .guard
        .clone();
    let json = replace_first_paragraph(&guard);
    let EditOutcome::Proposed(proposal) =
        vault.propose_blob_artifact_docx_revision(&artifact, &json, "tracked-docx")?
    else {
        panic!("valid Word edit must propose");
    };
    assert_eq!(proposal.base_version, Some(1));
    let out = vault.settle_select_edit_proposal(
        &artifact,
        &proposal,
        &SettleConsent::OwnerConsent { brief_ref: None },
        actor,
        TimeRange { start: 11, end: 11 },
        11,
    )?;
    assert_eq!(out.version.version, 2);
    assert_eq!(
        vault.read_blob_artifact_version(&artifact, 2)?.as_deref(),
        Some(proposal.new_bytes.as_slice())
    );
    assert_eq!(out.receipt.outcome, "selected");
    Ok(())
}

#[test]
fn docx_artifact_refuses_direct_mode_over_another_authors_pending_edit() -> crate::error::Result<()>
{
    use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
    use crate::edge::EdgeActorClass;
    use crate::entity_id::EntityId;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::temporal::TimeRange;
    use crate::test_util::embedding_test_config;
    use crate::write_envelope::WriteActor;

    let original = Document::parse(DOCX).unwrap();
    let first = &original.read().blocks[0];
    let earlier = serde_json::json!({
        "ops": [{"op": "replace", "target": first.id, "guard": first.guard,
            "content": {"type": "paragraph", "content": [
                {"type": "text", "text": "Earlier author's pending edit."}
            ]}}],
        "revision": {"author": "Earlier Author"}
    })
    .to_string();
    let pending = oneiron_docedit::revise(DOCX, &earlier).unwrap();
    let doc = Document::parse(&pending).unwrap();
    let block = &doc.read().blocks[0];
    let direct = serde_json::json!({
        "ops": [{"op": "replace", "target": block.id, "guard": block.guard,
            "content": {"type": "paragraph", "content": [
                {"type": "text", "text": "Untracked overwrite."}
            ]}}],
        "materialization_mode": "direct",
        "revision": {"author": "New Editor"}
    })
    .to_string();
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let at = TimeRange { start: 10, end: 10 };
    let actor_id = EntityId::now();
    vault.put_entity(&actor_id, ENTITY_TYPE_PERSON, at, 10, b"owner")?;
    let actor = WriteActor::new(actor_id, EdgeActorClass::Human);
    let artifact = EntityId::now();
    vault.put_blob_artifact(
        &artifact,
        &BlobArtifactBody::new(
            "pending.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        at,
        10,
    )?;
    vault.append_blob_artifact_version(
        &artifact,
        &pending,
        &BlobVersionProvenance::UserUpload,
        actor,
        at,
        10,
    )?;
    assert!(
        vault
            .propose_blob_artifact_docx_revision(&artifact, &direct, "run:direct")
            .is_err()
    );
    assert_eq!(vault.blob_artifact_versions(&artifact)?.len(), 1);
    assert_eq!(
        vault.read_blob_artifact_version(&artifact, 1)?.as_deref(),
        Some(pending.as_slice())
    );
    assert_eq!(vault.read_blob_artifact_version(&artifact, 2)?, None);
    assert!(
        vault
            .blob_artifact_settlement(&artifact, "run:direct")?
            .is_none()
    );
    Ok(())
}
