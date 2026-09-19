//! Native Word proposals use the same ledger, byte append and anchor sweep.
use super::*;
use oneiron_docedit::docx::{DocxOp, DocxPlan, DocxSpan, RevisionMark};

fn native_document() -> Vec<u8> {
    use oneiron_docedit::opc::{OpcPackage, OpcPart};
    let parts = [
        (
            "[Content_Types].xml",
            r#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#,
        ),
        (
            "word/document.xml",
            r#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>abcdef</w:t></w:r></w:p><w:p><w:r><w:t>second</w:t></w:r></w:p><w:sectPr/></w:body></w:document>"#,
        ),
        (
            "word/_rels/document.xml.rels",
            r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>"#,
        ),
    ];
    oneiron_docedit::opc::write(&OpcPackage::from_parts(
        parts
            .into_iter()
            .map(|(name, xml)| OpcPart {
                name: name.to_owned(),
                data: xml.as_bytes().to_vec(),
            })
            .collect(),
    ))
}

#[test]
fn docx_settle_is_once_reanchors_and_persists_engine_stamp() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let artifact = EntityId::now();
    vault.put_blob_artifact(
        &artifact,
        &BlobArtifactBody::new(
            "native.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        test_time(10),
        10,
    )?;
    let uploaded = vault.append_blob_artifact_version(
        &artifact,
        &native_document(),
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(10),
        10,
    )?;
    assert_eq!(uploaded.engine.engine, "unattested-import");
    let thread = vault.open_annotation_thread(
        &Anchor::new(artifact, 1, Locator::docx("body/p1", 3, 6)?),
        actor,
        "follow text",
        test_time(11),
        11,
    )?;
    let plan = DocxPlan::new(
        vec![DocxOp::InsertText {
            span: DocxSpan::new(1, 0, 0)?,
            text: "new ".to_owned(),
        }],
        RevisionMark::new("native-writer", "2026-09-19T00:00:00Z")?,
    );
    let crate::edit_roundtrip::EditOutcome::Proposed(proposal) =
        vault.propose_blob_artifact_docx_edit(&artifact, &plan, "run:native")?
    else {
        panic!("native edit rejected");
    };
    let mut forged = proposal.clone();
    forged.engine.version = "different-engine-version".to_owned();
    assert!(matches!(
        vault.settle_select_edit_proposal(&artifact, &forged, &owner(), actor, test_time(12), 12),
        Err(Error::Artifact(ArtifactError::EditProposalCommitMismatch))
    ));
    assert_eq!(
        vault.blob_artifact_head(&artifact)?.expect("head").version,
        1
    );
    let selected = vault.settle_select_edit_proposal(
        &artifact,
        &proposal,
        &owner(),
        actor,
        test_time(12),
        12,
    )?;
    assert_eq!(selected.version.engine, proposal.engine);
    assert_eq!(
        vault
            .blob_artifact_version_metadata(&artifact, 2)?
            .expect("metadata")
            .engine,
        proposal.engine
    );
    assert_eq!(
        vault.read_blob_artifact_version(&artifact, 2)?,
        Some(proposal.new_bytes.clone())
    );
    let door = vault
        .settle_receipt_door(&artifact, "run:native")?
        .expect("door");
    assert_eq!(door.anchors[0].thread_id, thread.thread_id);
    assert_eq!(door.anchors[0].locator, Locator::docx("body/p1", 7, 10)?);
    assert!(!door.anchors[0].drifted);
    assert!(matches!(
        vault.settle_select_edit_proposal(&artifact, &proposal, &owner(), actor, test_time(13), 13),
        Err(Error::Artifact(
            ArtifactError::EditProposalAlreadySettled { .. }
        ))
    ));
    assert_eq!(vault.blob_artifact_versions(&artifact)?.len(), 2);
    Ok(())
}
