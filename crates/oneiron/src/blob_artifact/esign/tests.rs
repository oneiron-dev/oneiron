use super::ledger::append;
use super::*;
use crate::{EntityId, Result, TimeRange, Vault, VaultConfig};
fn actor() -> EsignAuditActor {
    EsignAuditActor {
        actor: "test-owner".into(),
        ip: Some("127.0.0.1".into()),
        user_agent: Some("test".into()),
    }
}
fn document(artifact: EntityId) -> EsignDocument {
    let first = EntityId::now().to_hex();
    let second = EntityId::now().to_hex();
    EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: true,
        expires_at: 1000,
        items: vec![EsignItem {
            artifact_ref: artifact.to_hex(),
            original_version: 1,
        }],
        recipients: [first.clone(), second]
            .into_iter()
            .enumerate()
            .map(|(i, id)| EsignRecipient {
                id,
                email: format!("signer{i}@example.test"),
                name: format!("Signer {i}"),
                role: RecipientRole::Signer,
                order: i as u32,
                expires_at: 1000,
                principal_ref: None,
                automated: false,
            })
            .collect(),
        fields: vec![EsignField {
            id: EntityId::now().to_hex(),
            item: 0,
            recipient: first,
            required: true,
            geometry: FieldGeometry {
                page: 1,
                x_percent: 10.0,
                y_percent: 10.0,
                width_percent: 20.0,
                height_percent: 5.0,
            },
            meta: FieldMeta::Text { max_bytes: 50 },
        }],
        full_trail_appendix: true,
    }
}
fn setup() -> Result<(tempfile::TempDir, Vault, EntityId, EsignDocument)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let artifact = EntityId::now();
    vault.put_blob_artifact(
        &artifact,
        &crate::blob_artifact::BlobArtifactBody::new("agreement.pdf", "application/pdf"),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    // Model test only: the native prepare/seal gate owns PDF syntax validation.
    vault.append_blob_artifact_version(
        &artifact,
        b"%PDF-1.7\n",
        &crate::blob_artifact::BlobVersionProvenance::UserUpload,
        crate::write_envelope::WriteActor::new(person, crate::edge::EdgeActorClass::Human),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let body = document(artifact);
    vault.create_esign_document(artifact, &body, actor(), 2)?;
    Ok((dir, vault, artifact, body))
}
fn event(vault: &Vault, id: EntityId, event: EsignEvent, at: u64) -> Result<EsignState> {
    vault.with_write_txn(|txn| append(vault, txn, id, event, actor(), at))
}
#[test]
fn claims_enforce_required_fields_sequential_promotion_and_seal_only_terminals() -> Result<()> {
    let (_dir, vault, id, doc) = setup()?;
    let first = doc.recipients[0].id.clone();
    let second = doc.recipients[1].id.clone();
    event(&vault, id, EsignEvent::Sent, 3)?;
    assert!(
        event(
            &vault,
            id,
            EsignEvent::Viewed {
                recipient: second.clone()
            },
            4
        )
        .is_err()
    );
    event(
        &vault,
        id,
        EsignEvent::Viewed {
            recipient: first.clone(),
        },
        4,
    )?;
    assert!(
        event(
            &vault,
            id,
            EsignEvent::Signed {
                recipient: first.clone(),
                next: None
            },
            5
        )
        .is_err()
    );
    let signature = SignatureRow {
        field: doc.fields[0].id.clone(),
        recipient: first.clone(),
        value: FieldValue::Text("accepted".into()),
        at: 5,
    };
    event(
        &vault,
        id,
        EsignEvent::FieldSaved {
            signature,
        },
        5,
    )?;
    let pending = event(
        &vault,
        id,
        EsignEvent::Signed {
            recipient: first,
            next: Some(second.clone()),
        },
        6,
    )?;
    assert_eq!(pending.status, DocumentStatus::Pending);
    assert_eq!(pending.signatures.len(), 1);
    assert_eq!(pending.recipients[&second].signing, SigningStatus::Ready);
    event(
        &vault,
        id,
        EsignEvent::Viewed {
            recipient: second.clone(),
        },
        7,
    )?;
    let pending = event(
        &vault,
        id,
        EsignEvent::Signed {
            recipient: second,
            next: None,
        },
        8,
    )?;
    assert!(pending.ready_to_seal());
    assert_eq!(pending.status, DocumentStatus::Pending);
    // The event writer is crate-private. Public claim puts cannot mint this verdict.
    let mut forged = crate::claim::ClaimBody::new(
        "esign.completed",
        crate::claim::ClaimSubject::Entity(id),
        rmpv::Value::Nil,
        1.0,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    forged.source = Some(crate::claim::ClaimSource::Observed);
    assert!(
        vault
            .put_claim(&EntityId::now(), &forged, TimeRange { start: 9, end: 9 }, 9)
            .is_err()
    );
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Pending);
    assert_eq!(vault.esign_audit(id)?.len(), 7);
    Ok(())
}
#[test]
fn void_and_expiry_are_unsealed_and_never_trigger_sealing() -> Result<()> {
    for expire in [false, true] {
        let (_dir, vault, id, _) = setup()?;
        let event_kind = if expire {
            EsignEvent::Expired
        } else {
            EsignEvent::Voided {
                reason: "withdrawn".into(),
            }
        };
        let state = event(&vault, id, event_kind, 1001)?;
        assert_eq!(
            state.status,
            if expire {
                DocumentStatus::Expired
            } else {
                DocumentStatus::Voided
            }
        );
        assert!(!state.ready_to_seal());
        assert!(
            event(
                &vault,
                id,
                EsignEvent::Sealed {
                    rejected: false,
                    item_sha256: vec![[1; 32]]
                },
                1002
            )
            .is_err()
        );
        assert!(state.sealed_sha256.is_empty());
    }
    Ok(())
}

fn ceremony_setup() -> Result<(
    tempfile::TempDir,
    Vault,
    EntityId,
    EsignDocument,
    crate::consent::AuthenticatedOwner,
)> {
    let (dir, vault, id, mut doc) = setup()?;
    let now = crate::unix_seconds_now();
    doc.expires_at = now + 3600;
    for recipient in &mut doc.recipients {
        recipient.expires_at = doc.expires_at;
    }
    doc.fields[0].meta = FieldMeta::Date;
    doc.recipients[0].automated = true;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        b"owner",
    )?;
    doc.recipients[0].principal_ref = Some(owner.to_hex());
    event(
        &vault,
        id,
        EsignEvent::Drafted {
            document: doc.clone(),
        },
        now,
    )?;
    let auth = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::from_bytes(*EntityId::now().as_bytes()),
    )?;
    let manifest = serde_json::json!({
        "schema_version":"1.1", "pack_id":"esign-test", "pack_version":"v1",
        "min_engine_version":env!("CARGO_PKG_VERSION"),
        "defaults":{"criticality":"normal","sensitivity":"normal"},
        "rules":[], "actor_ceilings":[{"actor_class":"human","actor_ref":owner.to_hex(),"ceiling":"auto"}],
        "scoped_grants":(["send_for_signature","remind","void"].into_iter().map(|verb|serde_json::json!({"actor_ref":owner.to_hex(),"effector":format!("external:{verb}"),"scope":{"channel":"esign"}})).collect::<Vec<_>>())
    });
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &rmp_serde::to_vec_named(&manifest).unwrap(),
    )?;
    Ok((dir, vault, id, doc, auth))
}
fn send_request(
    id: EntityId,
    owner: EntityId,
    verb: EsignOutboundVerb,
    key: &str,
) -> crate::outbound::OutboundDispatchRequest {
    use crate::outbound::*;
    OutboundDispatchRequest::new(
        format!("receipt:{key}"),
        key,
        OutboundIntent::from_trigger(
            OutboundIntentDraft {
                actor: owner.to_hex(),
                on_behalf_of: None,
                verb: verb.as_str().into(),
                channel: "esign".into(),
                target: id.to_hex(),
                content_ref: None,
                idempotency_key: Some(key.into()),
                dedupe_key: Some(key.into()),
            },
            OutboundIntentTrigger {
                source: OutboundIntentSource::AgentImmediate,
                trigger_ref: key.into(),
                job_ref: None,
            },
        ),
        OutboundDispatchActor {
            actor_class: "human".into(),
            actor_ref: Some(owner.to_hex()),
            actor_entity_ref: Some(owner),
        },
        OutboundDispatchGate::allow_when_policy_grants(),
        crate::unix_seconds_now(),
        OutboundDeliveryWindowDecision::DeliverNow,
    )
}
#[test]
fn capability_ceremony_gates_turn_date_consent_and_default_closed_automation() -> Result<()> {
    let (_dir, vault, id, doc, owner) = ceremony_setup()?;
    let tokens = vault.issue_esign_capabilities(&owner, id)?;
    assert!(vault.issue_esign_capabilities(&owner, id).is_err());
    let command = EsignOutboundCommand {
        document: id.to_hex(),
        recipient_count: 2,
        verb: EsignOutboundVerb::SendForSignature,
        reason: None,
    };
    let request = send_request(id, owner.actor(), command.verb, "first-send");
    let sent = vault
        .dispatch_esign(request.clone(), &command, None, None)
        .unwrap();
    assert_eq!(
        sent.outcome,
        crate::outbound::OutboundDispatchOutcome::DeliveredToChannel,
        "{sent:?}"
    );
    let before = vault.esign_audit(id)?.len();
    assert_eq!(
        vault
            .dispatch_esign(request, &command, None, None)
            .unwrap()
            .outcome,
        crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(vault.esign_audit(id)?.len(), before);
    let first = &tokens[0].1;
    let second = &tokens[1].1;
    assert!(
        vault
            .esign_pdf_for_capability(second, 0, None, None)
            .is_err()
    );
    assert_eq!(
        vault.esign_pdf_for_capability(first, 0, None, None)?,
        b"%PDF-1.7\n"
    );
    assert!(
        vault
            .esign_pdf_for_capability(first, 1, None, None)
            .is_err()
    );
    assert_eq!(
        vault.execute_signing_action(second, &SigningAction::Load, None, None)?,
        SigningOutcome::NotYourTurn
    );
    assert_eq!(
        vault.esign_document(id)?.recipients[&doc.recipients[1].id].delivery,
        DeliveryStatus::Sent
    );
    assert!(matches!(
        vault.execute_signing_action(first, &SigningAction::Load, None, None)?,
        SigningOutcome::Page(_)
    ));
    let mut image_bytes = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        1,
        1,
        image::Rgba([1, 2, 3, 255]),
    ))
    .write_to(&mut image_bytes, image::ImageFormat::Png)
    .unwrap();
    let mut transparent = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        1,
        1,
        image::Rgba([0, 0, 0, 0]),
    ))
    .write_to(&mut transparent, image::ImageFormat::Png)
    .unwrap();
    assert!(
        vault
            .upload_esign_signature_image(first, transparent.get_ref())
            .is_err()
    );
    let image = vault.upload_esign_signature_image(first, image_bytes.get_ref())?;
    let preview = vault.esign_signature_image_for_capability(first, &image)?;
    assert_eq!(
        image::load_from_memory(&preview)
            .unwrap()
            .to_rgba8()
            .get_pixel(0, 0)
            .0,
        [1, 2, 3, 255]
    );
    assert!(
        vault
            .esign_signature_image_for_capability(second, &image)
            .is_err()
    );
    assert!(
        vault
            .esign_signature_image_for_capability(first, &EntityId::now().to_hex())
            .is_err()
    );

    let image_version = vault
        .blob_artifact_head(&EntityId::from_hex(&image)?)?
        .unwrap();
    assert_eq!(
        image_version.provenance,
        crate::blob_artifact::BlobVersionProvenance::CapabilityUpload
    );
    assert_eq!(
        vault.get_claim(&image_version.claim_id)?.unwrap().approval,
        crate::claim::ClaimApprovalStatus::Proposed
    );
    assert_eq!(
        vault.upload_esign_signature_image(first, image_bytes.get_ref())?,
        image
    );
    assert!(
        vault
            .upload_esign_signature_image(second, image_bytes.get_ref())
            .is_err()
    );
    assert!(
        vault
            .upload_esign_signature_image(first, b"not an image")
            .is_err()
    );
    let field = doc.fields[0].id.clone();
    let saved = vault.execute_signing_action(
        first,
        &SigningAction::SaveField {
            field: field.clone(),
            value: FieldValue::Text("forged-date".into()),
        },
        None,
        None,
    )?;
    let SigningOutcome::Page(page) = saved else {
        panic!("page expected")
    };
    assert_ne!(
        page.values[&field].value,
        FieldValue::Text("forged-date".into())
    );
    assert_eq!(
        vault.execute_signing_action(
            first,
            &SigningAction::Complete {
                consent: false,
                next: None
            },
            None,
            None
        )?,
        SigningOutcome::ConsentRequired
    );
    assert_eq!(
        vault.execute_signing_action(
            first,
            &SigningAction::Complete {
                consent: true,
                next: None
            },
            None,
            None
        )?,
        SigningOutcome::HumanActionRequired
    );
    vault.set_signing_principals(
        &owner,
        &[SigningPrincipal {
            principal_ref: owner.actor().to_hex(),
            autonomy: SigningAutonomy::AutonomousInEnvelope,
            automated_sign_action: true,
        }],
    )?;
    assert_eq!(
        vault.execute_signing_action(
            first,
            &SigningAction::Complete {
                consent: true,
                next: Some(doc.recipients[1].id.clone())
            },
            None,
            None
        )?,
        SigningOutcome::AwaitingSeal
    );
    assert!(matches!(
        vault.execute_signing_action(second, &SigningAction::Load, None, None)?,
        SigningOutcome::Page(_)
    ));
    assert_eq!(
        vault.execute_signing_action(
            second,
            &SigningAction::Reject {
                reason: "declined".into()
            },
            None,
            None
        )?,
        SigningOutcome::AwaitingSeal
    );
    assert!(vault.esign_document(id)?.ready_to_seal());
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Pending);
    let attempts = crate::attempt_queue::AttemptQueue::new(&vault).list()?;
    assert_eq!(
        attempts
            .iter()
            .filter(|a| a.kind == ESIGN_SEAL_ATTEMPT_KIND)
            .count(),
        1
    );
    assert!(
        vault
            .esign_signature_image_for_capability(first, &image)
            .is_err()
    );
    vault.revoke_esign_capability(&owner, second)?;
    assert!(
        vault
            .execute_signing_action(second, &SigningAction::Load, None, None)
            .is_err()
    );
    Ok(())
}
#[test]
fn outbound_gate_and_resend_count_are_not_bypassable() -> Result<()> {
    let (_dir, vault, id, _doc, owner) = ceremony_setup()?;
    let mut command = EsignOutboundCommand {
        document: id.to_hex(),
        recipient_count: 2,
        verb: EsignOutboundVerb::SendForSignature,
        reason: None,
    };
    let mut denied = send_request(id, owner.actor(), command.verb, "denied-send");
    denied.gate.has_permission = false;
    let result = vault.dispatch_esign(denied, &command, None, None).unwrap();
    assert_ne!(
        result.outcome,
        crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Draft);
    let sent = vault
        .dispatch_esign(
            send_request(id, owner.actor(), command.verb, "allowed-send"),
            &command,
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        sent.outcome,
        crate::outbound::OutboundDispatchOutcome::DeliveredToChannel,
        "{sent:?}"
    );
    command.verb = EsignOutboundVerb::Remind;
    command.recipient_count = 1;
    assert!(
        vault
            .dispatch_esign(
                send_request(id, owner.actor(), command.verb, "bad-remind"),
                &command,
                None,
                None
            )
            .is_err()
    );
    command.verb = EsignOutboundVerb::Void;
    command.recipient_count = 2;
    command.reason = Some("withdrawn".into());
    let voided = vault
        .dispatch_esign(
            send_request(id, owner.actor(), command.verb, "void"),
            &command,
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        voided.outcome,
        crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Voided);
    assert!(!vault.esign_document(id)?.ready_to_seal());
    Ok(())
}

#[test]
fn send_autonomy_never_inherits_the_sign_action_dial() -> Result<()> {
    let (_dir, vault, _id, _doc, owner) = ceremony_setup()?;
    for (autonomy, allowed) in [
        (SigningAutonomy::ScopedRead, false),
        (SigningAutonomy::Draft, false),
        (SigningAutonomy::SendWithApproval, false),
        (SigningAutonomy::AutonomousInEnvelope, true),
    ] {
        vault.set_signing_principals(
            &owner,
            &[SigningPrincipal {
                principal_ref: owner.actor().to_hex(),
                autonomy,
                automated_sign_action: false,
            }],
        )?;
        let txn = vault.store.env.read_txn()?;
        assert_eq!(
            super::principals::automated_outbound_allowed(
                &vault,
                &txn,
                Some(&owner.actor().to_hex())
            )?,
            allowed
        );
        assert!(!super::principals::automated_signing_allowed(
            &vault,
            &txn,
            Some(&owner.actor().to_hex())
        )?);
    }
    Ok(())
}

#[test]
fn read_only_recipient_cannot_own_unfillable_fields() -> Result<()> {
    let (_dir, vault, id, mut doc) = setup()?;
    doc.recipients[0].role = RecipientRole::Cc;
    assert!(event(&vault, id, EsignEvent::Drafted { document: doc }, 3).is_err());
    Ok(())
}

#[test]
fn resumed_signature_preview_uses_the_ceremony_rate_budget() -> Result<()> {
    let (_dir, vault, id, _doc, owner) = ceremony_setup()?;
    let tokens = vault.issue_esign_capabilities(&owner, id)?;
    let command = EsignOutboundCommand {
        document: id.to_hex(),
        recipient_count: 2,
        verb: EsignOutboundVerb::SendForSignature,
        reason: None,
    };
    vault
        .dispatch_esign(
            send_request(id, owner.actor(), command.verb, "image-rate"),
            &command,
            None,
            None,
        )
        .unwrap();
    let mut bytes = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        1,
        1,
        image::Rgba([1, 2, 3, 255]),
    ))
    .write_to(&mut bytes, image::ImageFormat::Png)
    .unwrap();
    let token = &tokens[0].1;
    let image = vault.upload_esign_signature_image(token, bytes.get_ref())?;
    assert!(
        !vault
            .esign_signature_image_for_capability(token, &image)?
            .is_empty()
    );
    // Allow a minute boundary without depending on the private counter layout.
    assert!((0..300).any(|_| {
        vault
            .esign_signature_image_for_capability(token, &image)
            .is_err()
    }));
    Ok(())
}
