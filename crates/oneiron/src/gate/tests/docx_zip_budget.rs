//! Archive budgets live in trusted policy, not in the DOCX organ's graph.

use super::*;
use oneiron_docedit::ArchiveLimits;

fn row(vault: ArchiveLimits, holders: Vec<Value>) -> (Value, Value) {
    (
        Value::from("docx_archive_limits"),
        Value::Map(vec![
            (
                Value::from("vault"),
                Value::Map(vec![
                    (
                        Value::from("max_entries"),
                        Value::from(vault.max_entries as u64),
                    ),
                    (
                        Value::from("max_part_bytes"),
                        Value::from(vault.max_part_bytes),
                    ),
                    (
                        Value::from("max_total_bytes"),
                        Value::from(vault.max_total_bytes),
                    ),
                ]),
            ),
            (Value::from("holders"), Value::Array(holders)),
        ]),
    )
}

fn holder(actor: EntityId, max_entries: u64, max_part_bytes: u64) -> Value {
    Value::Map(vec![
        (Value::from("actor"), Value::from(actor.to_hex())),
        (Value::from("max_entries"), Value::from(max_entries)),
        (Value::from("max_part_bytes"), Value::from(max_part_bytes)),
    ])
}

#[test]
fn exact_holder_budget_is_enforced_at_proposal_and_settlement() -> Result<()> {
    use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
    use crate::edit_roundtrip::{EditOutcome, run_docx_revision};
    use crate::edit_settle::SettleConsent;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::temporal::TimeRange;
    use crate::write_envelope::WriteActor;
    let (_dir, vault) = temp_vault();
    let actor_id = test_id(0x73);
    let actor = WriteActor::new(actor_id, crate::edge::EdgeActorClass::Human);
    let at = TimeRange { start: 10, end: 10 };
    vault.put_entity(&actor_id, ENTITY_TYPE_PERSON, at, 10, b"owner")?;
    let artifact = test_id(0x74);
    vault.put_blob_artifact(
        &artifact,
        &BlobArtifactBody::new(
            "budget.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        at,
        10,
    )?;
    let input = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-docedit/vendor/stemma-engine/testdata/simple-text/before.docx"
    ));
    vault.append_blob_artifact_version(
        &artifact,
        input,
        &BlobVersionProvenance::UserUpload,
        actor,
        at,
        10,
    )?;
    let doc = oneiron_docedit::Document::parse(input).unwrap();
    let first = &doc.read().blocks[0];
    let transaction = serde_json::json!({
        "ops": [{"op": "replace", "target": first.id, "guard": first.guard,
            "content": {"type": "paragraph", "content": [
                {"type": "text", "text": "Tracked."}
            ]}}],
        "revision": {"author": "Editor"}
    })
    .to_string();
    let limits = ArchiveLimits::DEFAULT;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x76),
        &encode_policy_manifest(vec![row(
            limits,
            vec![holder(actor_id, 1, limits.max_part_bytes)],
        )]),
    )?;
    // Vault defaults and other holders admit the same input; this exact
    // holder's restrictive entry count refuses before it can edit anything.
    let EditOutcome::Proposed(proposal) =
        vault.propose_blob_artifact_docx_revision(&artifact, &transaction, "run:holder")?
    else {
        panic!("vault default must permit proposal")
    };
    assert!(
        vault
            .propose_blob_artifact_docx_revision_for_holder(
                &artifact,
                &transaction,
                "run:holder",
                Some(actor_id),
            )
            .is_err()
    );
    assert!(
        vault
            .propose_blob_artifact_docx_revision_for_holder(
                &artifact,
                &transaction,
                "run:other",
                Some(test_id(0x75)),
            )
            .is_ok()
    );
    // Settlement resolves the authenticated actor in its write txn, so even
    // an unscoped or forged caller proposal cannot override its holder cap.
    assert!(
        vault
            .settle_select_edit_proposal(
                &artifact,
                &proposal,
                &SettleConsent::OwnerConsent { brief_ref: None },
                actor,
                TimeRange { start: 11, end: 11 },
                11,
            )
            .is_err()
    );
    assert_eq!(vault.blob_artifact_versions(&artifact)?.len(), 1);
    assert!(
        vault
            .blob_artifact_settlement(&artifact, "run:holder")?
            .is_none()
    );
    // The raw door still has standalone defaults; no actor-based privilege.
    assert!(matches!(
        run_docx_revision(input, &transaction, "run:raw")?,
        EditOutcome::Proposed(_)
    ));
    Ok(())
}
