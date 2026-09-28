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
fn shipped_default_and_trusted_rows_narrow_exact_holder_only() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = test_id(0x32);
    let other = test_id(0x33);
    let limits = ArchiveLimits {
        max_entries: 60,
        max_part_bytes: 4_000,
        max_total_bytes: 10_000,
    };
    assert_eq!(
        resolve(&vault)?.docx_archive_limits(None),
        Some(ArchiveLimits::DEFAULT)
    );
    put_policy_manifest_bytes(
        &vault,
        test_id(0x34),
        &encode_policy_manifest(vec![row(limits, vec![holder(actor, 20, 1_000)])]),
    )?;
    let policy = resolve(&vault)?;
    assert_eq!(policy.docx_archive_limits(None), Some(limits));
    assert_eq!(policy.docx_archive_limits(Some(other)), Some(limits));
    assert_eq!(
        policy.docx_archive_limits(Some(actor)),
        Some(ArchiveLimits {
            max_entries: 20,
            max_part_bytes: 1_000,
            max_total_bytes: 10_000,
        })
    );
    // All trusted contributions compose field-wise, never last-writer-wins.
    let second = ArchiveLimits {
        max_entries: 50,
        max_part_bytes: 3_000,
        max_total_bytes: 8_000,
    };
    put_policy_manifest_bytes(
        &vault,
        test_id(0x35),
        &encode_policy_manifest(vec![row(second, vec![])]),
    )?;
    let folded = resolve(&vault)?;
    assert_eq!(
        folded.docx_archive_limits(Some(actor)),
        Some(ArchiveLimits {
            max_entries: 20,
            max_part_bytes: 1_000,
            max_total_bytes: 8_000
        })
    );
    assert_ne!(policy.read_frontier_hash()?, folded.read_frontier_hash()?);
    Ok(())
}

#[test]
fn malformed_or_widening_archive_rows_fail_closed() -> Result<()> {
    let valid = ArchiveLimits {
        max_entries: 20,
        max_part_bytes: 1_000,
        max_total_bytes: 2_000,
    };
    // Letter-bearing hex proves uppercase is non-canonical, not a no-op.
    let actor = test_id(0xab);
    let cases = vec![
        Value::from(10_u64),
        Value::Map(vec![(Value::from("vault"), Value::Map(vec![]))]),
        Value::Map(vec![
            (Value::from("vault"), row(valid, vec![]).1),
            (Value::from("extra"), Value::from(1_u64)),
        ]),
        row(valid, vec![holder(actor, 21, 1_000)]).1,
        row(
            valid,
            vec![Value::Map(vec![
                (
                    Value::from("actor"),
                    Value::from(actor.to_hex().to_uppercase()),
                ),
                (Value::from("max_entries"), Value::from(10_u64)),
            ])],
        )
        .1,
        row(
            ArchiveLimits {
                max_entries: ArchiveLimits::DEFAULT.max_entries + 1,
                ..valid
            },
            vec![],
        )
        .1,
        row(
            ArchiveLimits {
                max_part_bytes: 0,
                ..valid
            },
            vec![],
        )
        .1,
    ];
    for (index, invalid) in cases.into_iter().enumerate() {
        let (_dir, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(0x34),
            &encode_policy_manifest(vec![(Value::from("docx_archive_limits"), invalid.clone())]),
        )?;
        let resolved = resolve(&vault)?;
        assert!(
            resolved.diagnostics().malformed_manifest_seen,
            "case {index}: {invalid:?}"
        );
        assert!(resolved.docx_archive_limits(None).is_none());
    }
    Ok(())
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
