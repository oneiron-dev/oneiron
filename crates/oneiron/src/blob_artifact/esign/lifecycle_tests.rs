use super::*;
use crate::{EntityId, Result, TimeRange, Vault, VaultConfig};

fn fixture() -> Result<(tempfile::TempDir, Vault, EntityId, EsignDocument)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &crate::blob_artifact::BlobArtifactBody::new("document.pdf", "application/pdf"),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    vault.append_blob_artifact_version(
        &id,
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
        )),
        &crate::blob_artifact::BlobVersionProvenance::UserUpload,
        crate::write_envelope::WriteActor::new(owner, crate::edge::EdgeActorClass::Human),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let doc = EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: false,
        expires_at: 0,
        items: vec![EsignItem {
            artifact_ref: id.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: EntityId::now().to_hex(),
            email: "signer@example.test".into(),
            name: "Signer".into(),
            role: RecipientRole::Signer,
            order: 0,
            expires_at: 0,
            principal_ref: None,
            automated: false,
        }],
        fields: vec![],
        full_trail_appendix: false,
        lifecycle: None,
    };
    Ok((dir, vault, id, doc))
}
fn rules() -> EsignLifecycleRules {
    EsignLifecycleRules {
        expiry_after_seconds: 90 * 86400,
        first_reminder_after_seconds: 5 * 86400,
        repeat_reminder_every_seconds: 2 * 86400,
        reminder_cap_seconds: 30 * 86400,
        notices: EsignNoticeSwitches::default(),
    }
}
#[test]
fn pack_rules_materialize_deadlines_and_claim_ladder_until_unsealed_expiry() -> Result<()> {
    let (_dir, vault, id, doc) = fixture()?;
    let sent = 10;
    vault.create_esign_document_with_lifecycle(
        id,
        &doc,
        EsignAuditActor {
            actor: "owner".into(),
            ip: None,
            user_agent: None,
        },
        2,
        &rules(),
    )?;
    let state = vault.esign_document(id)?;
    assert_eq!(state.document.expires_at, 2 + 90 * 86400);
    assert_eq!(
        state.recipients[&doc.recipients[0].id].expires_at,
        state.document.expires_at
    );
    vault.with_write_txn(|txn| {
        super::ledger::append(
            &vault,
            txn,
            id,
            EsignEvent::Sent,
            EsignAuditActor {
                actor: "owner".into(),
                ip: None,
                user_agent: None,
            },
            sent,
        )
        .map(|_| ())
    })?;
    let due = |at| {
        let txn = vault.store.env.read_txn()?;
        super::lifecycle::reminder_due(&vault, &txn, id, &doc.recipients[0].id, at)
    };
    assert_eq!(due(sent + 5 * 86400 - 1)?, None);
    let reminder = |rung, at| {
        vault.with_write_txn(|txn| {
            super::ledger::append(
                &vault,
                txn,
                id,
                EsignEvent::Reminded {
                    recipient: doc.recipients[0].id.clone(),
                    rung,
                },
                EsignAuditActor {
                    actor: "owner".into(),
                    ip: None,
                    user_agent: None,
                },
                at,
            )
            .map(|_| ())
        })
    };
    assert!(reminder(0, sent + 5 * 86400 - 1).is_err());
    assert!(reminder(1, sent + 5 * 86400).is_err());
    assert_eq!(due(sent + 5 * 86400)?, Some(0));
    reminder(0, sent + 5 * 86400)?;
    assert_eq!(due(sent + 7 * 86400 - 1)?, None);
    assert_eq!(due(sent + 7 * 86400)?, Some(1));
    assert_eq!(due(sent + 30 * 86400 + 1)?, None);
    assert!(reminder(1, sent + 30 * 86400 + 1).is_err());
    assert_eq!(
        vault.sweep_esign_expiry(&[id], state.document.expires_at - 1)?,
        0
    );
    assert_eq!(
        vault.sweep_esign_expiry(&[id], state.document.expires_at)?,
        1
    );
    assert_eq!(
        vault.sweep_esign_expiry(&[id], state.document.expires_at + 1)?,
        0
    );
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Expired);
    assert!(vault.esign_document(id)?.sealed_sha256.is_empty());
    assert_eq!(
        vault.esign_audit(id)?.last().unwrap().event,
        EsignEvent::Expired {
            recipient: Some(doc.recipients[0].id.clone())
        }
    );
    assert_eq!(due(state.document.expires_at)?, None);
    Ok(())
}
#[test]
fn disabled_expiry_notice_preserves_claim_and_no_edge_handoff() -> Result<()> {
    let (_dir, vault, id, doc) = fixture()?;
    let mut config = rules();
    config.notices.expiry = false;
    vault.create_esign_document_with_lifecycle(
        id,
        &doc,
        EsignAuditActor {
            actor: "owner".into(),
            ip: None,
            user_agent: None,
        },
        2,
        &config,
    )?;
    assert_eq!(vault.sweep_esign_expiry(&[id], 2 + 90 * 86400)?, 1);
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Expired);
    assert!(
        !crate::attempt_queue::AttemptQueue::new(&vault)
            .list()?
            .iter()
            .any(|a| a.kind == "esign.delivery")
    );
    Ok(())
}

#[test]
fn recipient_window_precedes_document_and_viewer_window_does_not_terminalize() -> Result<()> {
    let (_dir, vault, id, mut doc) = fixture()?;
    let signer = doc.recipients[0].id.clone();
    doc.recipients[0].expires_at = 100;
    let mut viewer = doc.recipients[0].clone();
    viewer.id = EntityId::now().to_hex();
    viewer.role = RecipientRole::Viewer;
    viewer.expires_at = 50;
    doc.recipients.push(viewer);
    vault.create_esign_document_with_lifecycle(
        id,
        &doc,
        EsignAuditActor {
            actor: "owner".into(),
            ip: None,
            user_agent: None,
        },
        2,
        &rules(),
    )?;
    assert_eq!(
        vault.esign_document(id)?.document.expires_at,
        2 + 90 * 86400
    );
    assert_eq!(vault.sweep_esign_expiry(&[id], 50)?, 0);
    assert_eq!(vault.sweep_esign_expiry(&[id], 99)?, 0);
    let forged = vault.with_write_txn(|txn| {
        super::ledger::append(
            &vault,
            txn,
            id,
            EsignEvent::Expired {
                recipient: Some(doc.recipients[1].id.clone()),
            },
            EsignAuditActor {
                actor: "owner".into(),
                ip: None,
                user_agent: None,
            },
            100,
        )
    });
    assert!(forged.is_err());
    assert_eq!(vault.sweep_esign_expiry(&[id], 100)?, 1);
    assert_eq!(vault.sweep_esign_expiry(&[id], 101)?, 0);
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Expired);
    assert_eq!(
        vault.esign_audit(id)?.last().unwrap().event,
        EsignEvent::Expired {
            recipient: Some(signer)
        }
    );
    Ok(())
}
