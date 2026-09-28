use super::ledger::append;
use super::*;
use crate::{EntityId, Error, Result, TimeRange, Vault, VaultConfig};
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
                // The pinned fixture has a 200pt-square page.
                width_percent: 50.0,
                height_percent: 20.0,
            },
            meta: FieldMeta::Text { max_bytes: 50 },
        }],
        full_trail_appendix: true,
        lifecycle: None,
    }
}
fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}
fn setup() -> Result<(tempfile::TempDir, Vault, EntityId, EsignDocument)> {
    setup_with(VaultConfig::default(), 1000)
}
fn setup_with(
    config: VaultConfig,
    expires_at: u64,
) -> Result<(tempfile::TempDir, Vault, EntityId, EsignDocument)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), config)?;
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
    vault.append_blob_artifact_version(
        &artifact,
        original_pdf(),
        &crate::blob_artifact::BlobVersionProvenance::UserUpload,
        crate::write_envelope::WriteActor::new(person, crate::edge::EdgeActorClass::Human),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let mut body = document(artifact);
    body.expires_at = expires_at;
    for recipient in &mut body.recipients {
        recipient.expires_at = expires_at;
    }
    vault.create_esign_document(artifact, &body, actor(), 2)?;
    Ok((dir, vault, artifact, body))
}
#[test]
fn capability_preview_and_signature_share_injected_time_and_ids() -> Result<()> {
    use crate::ports::{ChangeLogStore, ManualClock};
    let clock = ManualClock::new(100);
    let config = VaultConfig {
        store_clock: clock.bundle(),
        ..VaultConfig::default()
    };
    let (_dir, vault, document, doc) = setup_with(config, 200)?;
    let owner = EntityId::from_bytes([0x42; 16])?;
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let auth = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::from_bytes([0x43; 16]),
    )?;
    let tokens = vault.issue_esign_capabilities(&auth, document)?;
    assert_eq!(tokens.len(), 2);
    event(&vault, document, EsignEvent::Sent, 100)?;
    let token = &tokens[0].1;
    assert!(matches!(
        vault.execute_signing_action(token, &SigningAction::Load, None, None)?,
        SigningOutcome::Page(_)
    ));
    let (_, pdf) = vault.esign_preview_for_capability(token, 0, None, None)?;
    assert_eq!(pdf, original_pdf());
    let mut encoded = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        1,
        1,
        image::Rgba([1, 2, 3, 255]),
    ))
    .write_to(&mut encoded, image::ImageFormat::Png)
    .unwrap();
    let image = vault.upload_esign_signature_image(token, encoded.get_ref())?;
    assert!(
        !vault
            .esign_signature_image_for_capability(token, &image)?
            .is_empty()
    );
    // The event CLAIM and the version actor are persisted IDs, not host ULIDs.
    assert!(vault.claims_for_subject(&document)?.iter().any(|id| {
        id.as_bytes()[0] == 0x71
            && vault
                .get_claim(id)
                .ok()
                .flatten()
                .is_some_and(|claim| claim.predicate.starts_with("esign."))
    }));
    let image_id = EntityId::from_hex(&image)?;
    let txn = vault.store.env.read_txn()?;
    let changes = vault.port_changelog_list_by_entity(&txn, &image_id, 100)?;
    let machine = changes
        .iter()
        .find(|row| row.reason.as_deref() == Some("blob version appended"))
        .expect("capability upload audit actor")
        .actor_principal;
    assert_eq!(machine.as_bytes()[0], 0x71);
    drop(txn);
    assert_eq!(
        vault.get_entity_type(&machine)?,
        Some(crate::registry::ENTITY_TYPE_MACHINE)
    );
    clock.set(201);
    assert!(
        vault
            .esign_preview_for_capability(token, 0, None, None)
            .is_err()
    );
    assert!(
        vault
            .esign_signature_image_for_capability(token, &image)
            .is_err()
    );
    assert!(
        vault
            .upload_esign_signature_image(token, encoded.get_ref())
            .is_err()
    );
    assert_eq!(doc.expires_at, 200);
    Ok(())
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
    event(&vault, id, EsignEvent::FieldSaved { signature }, 5)?;
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
        let (_dir, vault, id, doc) = setup()?;
        let event_kind = if expire {
            EsignEvent::Expired {
                recipient: Some(doc.recipients[0].id.clone()),
            }
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
        "schema_version":"1.2", "pack_id":"esign-test", "pack_version":"v1",
        "min_engine_version":env!("CARGO_PKG_VERSION"),
        "defaults":{"criticality":"normal","sensitivity":"normal"},
        "rules":[], "actor_ceilings":[{"actor_class":"human","actor_ref":owner.to_hex(),"ceiling":"auto"}],
        "scoped_grants":(["send_for_signature","remind","void"].into_iter().map(|verb|serde_json::json!({"actor_ref":owner.to_hex(),"effector":format!("external:{verb}"),"scope":crate::federation::scope_codec::effect_preset(),"selectors":{"channel":"esign"}})).collect::<Vec<_>>())
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
    assert!(vault.issue_esign_capabilities(&owner, id)?.is_empty());
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
        original_pdf()
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
    let unminted = vault
        .dispatch_esign(
            send_request(id, owner.actor(), command.verb, "unminted-send"),
            &command,
            None,
            None,
        )
        .unwrap();
    assert_ne!(
        unminted.outcome,
        crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Draft);
    assert!(
        crate::attempt_queue::AttemptQueue::new(&vault)
            .list()?
            .is_empty()
    );
    vault.issue_esign_capabilities(&owner, id)?;
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
fn lifecycle_sweep_uses_gate_and_claims_each_due_recipient_once() -> Result<()> {
    let (_dir, vault, id, doc, owner) = ceremony_setup()?;
    let rules = EsignLifecycleRules {
        expiry_after_seconds: 3600,
        first_reminder_after_seconds: 1,
        repeat_reminder_every_seconds: 2,
        reminder_cap_seconds: 60,
        notices: EsignNoticeSwitches::default(),
    };
    let mut policy_doc = doc.clone();
    policy_doc.lifecycle = Some(rules);
    event(
        &vault,
        id,
        EsignEvent::Drafted {
            document: policy_doc,
        },
        crate::unix_seconds_now(),
    )?;
    vault.issue_esign_capabilities(&owner, id)?;
    let command = EsignOutboundCommand {
        document: id.to_hex(),
        recipient_count: 2,
        verb: EsignOutboundVerb::SendForSignature,
        reason: None,
    };
    let sent = vault
        .dispatch_esign(
            send_request(id, owner.actor(), command.verb, "lifecycle-send"),
            &command,
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        sent.outcome,
        crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
    );
    let sent_at = vault.esign_audit(id)?.last().unwrap().at;
    let due = |at| {
        vault.sweep_esign_reminders(&[id], at, |id, recipient, rung| {
            let mut req = send_request(
                id,
                owner.actor(),
                EsignOutboundVerb::Remind,
                &format!("lifecycle-remind-{}-{rung}", recipient.id),
            );
            req.occurred_at = at;
            req
        })
    };
    assert_eq!(due(sent_at).unwrap(), 0);
    assert_eq!(due(sent_at + 1).unwrap(), 1);
    assert_eq!(due(sent_at + 1).unwrap(), 0);
    assert_eq!(vault.esign_document(id)?.reminders.len(), 1);
    assert_eq!(due(sent_at + 3).unwrap(), 1);
    let deliveries = crate::attempt_queue::AttemptQueue::new(&vault).list()?;
    let notices = deliveries
        .iter()
        .filter(|a| a.kind == "esign.delivery")
        .map(|a| serde_json::from_slice::<serde_json::Value>(&a.payload))
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        notices
            .iter()
            .filter(|v| v["transition"] == "reminder")
            .count(),
        2
    );
    assert_eq!(
        notices
            .iter()
            .filter(|v| v["transition"] == "invite")
            .count(),
        doc.recipients.len()
    );
    assert_eq!(vault.sweep_esign_expiry(&[id], doc.expires_at)?, 1);
    assert_eq!(vault.sweep_esign_expiry(&[id], doc.expires_at + 1)?, 0);
    assert_eq!(due(doc.expires_at).unwrap(), 0);
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Expired);
    assert!(vault.esign_document(id)?.sealed_sha256.is_empty());
    assert_eq!(
        vault.esign_audit(id)?.last().unwrap().event,
        EsignEvent::Expired {
            recipient: Some(doc.recipients[0].id.clone())
        }
    );
    let queued = crate::attempt_queue::AttemptQueue::new(&vault).list()?;
    assert!(queued.iter().all(|a| a.kind != ESIGN_SEAL_ATTEMPT_KIND));
    assert_eq!(
        queued
            .iter()
            .filter(|a| a.kind == ESIGN_NOTICE_ATTEMPT_KIND
                && serde_json::from_slice::<serde_json::Value>(&a.payload)
                    .is_ok_and(|v| v["transition"] == "expiry"))
            .count(),
        doc.recipients.len()
    );
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
fn resumed_signature_preview_raises_a_check_without_refusing() -> Result<()> {
    let (_dir, vault, id, doc, owner) = ceremony_setup()?;
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
    // Even across a minute boundary, 300 successful reads cross at least one
    // recipient window. The PDF, preview and ceremony then remain usable.
    for _ in 0..300 {
        assert!(
            !vault
                .esign_signature_image_for_capability(token, &image)?
                .is_empty()
        );
    }
    assert_eq!(
        vault.esign_pdf_for_capability(token, 0, None, None)?,
        original_pdf()
    );
    assert!(matches!(
        vault.esign_preview_for_capability(token, 0, None, None)?,
        (SigningPage { .. }, _)
    ));
    assert!(matches!(
        vault.execute_signing_action(token, &SigningAction::Load, None, None)?,
        SigningOutcome::Page(_)
    ));
    let checks = vault.esign_rate_checks(id)?;
    assert!(checks.iter().any(|check| {
        check.receipt.recipient.as_deref() == Some(doc.recipients[0].id.as_str())
            && check.receipt.count == 121
            && check.threshold == 120
            && EsignRateCheck::KIND == "esign_ceremony_burst"
    }));
    let receipt = vault
        .esign_rate_receipt(id, Some(&doc.recipients[0].id))?
        .unwrap();
    assert!(receipt.count > 0);
    Ok(())
}

#[test]
fn signing_field_save_survives_reopen_without_rotating_the_bearer() -> Result<()> {
    let (dir, vault, id, doc, owner) = ceremony_setup()?;
    let tokens = vault.issue_esign_capabilities(&owner, id)?;
    let command = EsignOutboundCommand {
        document: id.to_hex(),
        recipient_count: doc.recipients.len(),
        verb: EsignOutboundVerb::SendForSignature,
        reason: None,
    };
    let sent = vault
        .dispatch_esign(
            send_request(id, owner.actor(), command.verb, "resume-send"),
            &command,
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        sent.outcome,
        crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
    );
    let field = &doc.fields[0].id;
    let SigningOutcome::Page(saved) = vault.execute_signing_action(
        &tokens[0].1,
        &SigningAction::SaveField {
            field: field.clone(),
            value: FieldValue::Text("forged-date".into()),
        },
        Some("192.0.2.1".into()),
        Some("ceremony-test".into()),
    )?
    else {
        panic!("field save returns the resumable page")
    };
    let date = chrono::DateTime::from_timestamp(saved.values[field].at as i64, 0)
        .unwrap()
        .format("%Y-%m-%d")
        .to_string();
    assert_eq!(saved.values[field].value, FieldValue::Text(date));
    let audit = vault.esign_audit(id)?;
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    let resumed =
        reopened.execute_signing_action(&tokens[0].1, &SigningAction::Load, None, None)?;
    assert_eq!(resumed, SigningOutcome::Page(saved));
    assert_eq!(reopened.esign_audit(id)?, audit);
    assert_eq!(
        reopened.execute_signing_action(&tokens[1].1, &SigningAction::Load, None, None)?,
        SigningOutcome::NotYourTurn
    );
    assert_eq!(reopened.esign_audit(id)?, audit);
    Ok(())
}

#[test]
fn audit_chain_survives_document_deletion_and_reopen() -> Result<()> {
    let (dir, vault, id, doc) = setup()?;
    event(&vault, id, EsignEvent::Sent, 3)?;
    event(
        &vault,
        id,
        EsignEvent::Viewed {
            recipient: doc.recipients[0].id.clone(),
        },
        4,
    )?;
    let audit = vault.esign_audit(id)?;
    assert_eq!(audit.len(), 3);

    assert!(
        vault.delete_entity_with_options(
            &id,
            crate::deletion::DeleteEntityOptions { purge: true }
        )?
    );
    assert!(vault.get_blob_artifact(&id)?.is_none());
    assert_eq!(vault.esign_audit(id)?, audit);

    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    assert!(reopened.get_blob_artifact(&id)?.is_none());
    assert_eq!(reopened.esign_audit(id)?, audit);
    Ok(())
}

#[test]
fn added_draft_recipients_get_only_missing_capabilities_and_preview_admits_once() -> Result<()> {
    let (_dir, vault, id, mut doc, owner) = ceremony_setup()?;
    let original = vault.issue_esign_capabilities(&owner, id)?;
    let mut added = doc.recipients[1].clone();
    added.id = EntityId::now().to_hex();
    added.order = 2;
    doc.recipients.push(added.clone());
    let now = crate::unix_seconds_now();
    event(
        &vault,
        id,
        EsignEvent::Drafted {
            document: doc.clone(),
        },
        now,
    )?;
    let issued = vault.issue_esign_capabilities(&owner, id)?;
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0].0, added.id);
    let command = EsignOutboundCommand {
        document: id.to_hex(),
        recipient_count: 3,
        verb: EsignOutboundVerb::SendForSignature,
        reason: None,
    };
    assert_eq!(
        vault
            .dispatch_esign(
                send_request(id, owner.actor(), command.verb, "added-send"),
                &command,
                None,
                None
            )
            .unwrap()
            .outcome,
        crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
    );
    // More than half the 120-load minute budget must succeed: double admission
    // would refuse preview 61. The old bearer remains usable after the edit.
    for _ in 0..61 {
        let (page, bytes) = vault.esign_preview_for_capability(&original[0].1, 0, None, None)?;
        assert_eq!(page.recipient, doc.recipients[0].id);
        assert_eq!(bytes, original_pdf());
    }
    assert!(vault.issue_esign_capabilities(&owner, id).is_err());
    Ok(())
}

#[test]
fn seal_backstop_obeys_both_time_bounds_and_expiry_stays_unsealed() -> Result<()> {
    for (age, expected) in [(899, 0), (900, 1), (21600, 1), (21601, 0)] {
        let (_dir, vault, id, _doc) = setup()?;
        event(&vault, id, EsignEvent::Sent, 3)?;
        let first = vault.esign_document(id)?.document.recipients[0].id.clone();
        event(
            &vault,
            id,
            EsignEvent::Viewed {
                recipient: first.clone(),
            },
            4,
        )?;
        event(
            &vault,
            id,
            EsignEvent::Declined {
                recipient: first,
                reason: "declined".into(),
            },
            5,
        )?;
        assert_eq!(vault.sweep_esign_seals(&[id], 5 + age)?, expected);
        assert_eq!(vault.sweep_esign_seals(&[id], 5 + age)?, expected);
        assert_eq!(
            crate::attempt_queue::AttemptQueue::new(&vault)
                .list()?
                .iter()
                .filter(|a| a.kind == ESIGN_SEAL_ATTEMPT_KIND)
                .count(),
            expected
        );
    }
    let (_dir, vault, id, doc) = setup()?;
    event(&vault, id, EsignEvent::Sent, 3)?;
    vault.expire_esign_document(id, doc.expires_at - 1)?;
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Pending);
    vault.expire_esign_document(id, doc.expires_at)?;
    let audit = vault.esign_audit(id)?;
    vault.expire_esign_document(id, doc.expires_at + 1)?;
    assert_eq!(vault.esign_audit(id)?, audit);
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Expired);
    assert!(vault.esign_document(id)?.sealed_sha256.is_empty());
    assert_eq!(vault.sweep_esign_seals(&[id], doc.expires_at + 900)?, 0);
    let queued = crate::attempt_queue::AttemptQueue::new(&vault).list()?;
    assert!(queued.iter().all(|a| a.kind != ESIGN_SEAL_ATTEMPT_KIND));
    assert_eq!(
        queued
            .iter()
            .filter(|a| a.kind == ESIGN_NOTICE_ATTEMPT_KIND)
            .count(),
        doc.recipients.len()
    );
    Ok(())
}

#[test]
fn individual_events_cannot_be_deleted_or_retyped_but_subject_erasure_retains_audit() -> Result<()>
{
    let (_dir, vault, id, _) = setup()?;
    event(&vault, id, EsignEvent::Sent, 3)?;
    let state = vault.esign_document(id)?;
    let audit = vault.esign_audit(id)?;
    let (claim_id, body) = vault
        .claims_for_subject(&id)?
        .into_iter()
        .map(|claim| Ok((claim, vault.get_claim(&claim)?.expect("claim"))))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .find(|(_, body)| body.predicate == "esign.sent")
        .expect("sent event");
    assert!(matches!(
        vault.batch().delete(&claim_id).commit(),
        Err(Error::InvalidClaimBody(_))
    ));
    for reason in [
        crate::DeleteReason::UserDelete,
        crate::DeleteReason::UserHardDelete,
    ] {
        assert!(matches!(
            vault.delete_entity_with_reason(&claim_id, reason),
            Err(Error::InvalidClaimBody(_))
        ));
    }
    let mut changed = body.clone();
    changed.predicate = "other.fact".into();
    assert!(
        vault
            .put_claim(&claim_id, &changed, TimeRange { start: 3, end: 3 }, 3)
            .is_err()
    );
    assert_eq!(vault.get_claim(&claim_id)?, Some(body));
    assert_eq!(vault.esign_document(id)?, state);
    assert_eq!(vault.esign_audit(id)?, audit);
    assert!(
        vault.delete_entity_with_options(
            &id,
            crate::deletion::DeleteEntityOptions { purge: true }
        )?
    );
    assert_eq!(vault.esign_audit(id)?, audit);
    Ok(())
}

#[test]
fn deleted_documents_refuse_every_capability_door_but_retain_audit() -> Result<()> {
    for deletion in ["hard", "batch", "soft"] {
        let (dir, vault, original, doc, owner) = ceremony_setup()?;
        // Keep the pinned item live so a failed read proves document admission,
        // not incidental loss of the original PDF during artifact cleanup.
        let id = EntityId::now();
        let now = crate::unix_seconds_now();
        vault.put_blob_artifact(
            &id,
            &crate::blob_artifact::BlobArtifactBody::new("envelope.pdf", "application/pdf"),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        vault.create_esign_document(id, &doc, actor(), now)?;
        let tokens = vault.issue_esign_capabilities(&owner, id)?;
        let token = &tokens[0].1;
        let command = EsignOutboundCommand {
            document: id.to_hex(),
            recipient_count: doc.recipients.len(),
            verb: EsignOutboundVerb::SendForSignature,
            reason: None,
        };
        assert_eq!(
            vault
                .dispatch_esign(
                    send_request(id, owner.actor(), command.verb, "delete-send"),
                    &command,
                    None,
                    None,
                )
                .unwrap()
                .outcome,
            crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
        );
        let mut image_bytes = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            1,
            1,
            image::Rgba([1, 2, 3, 255]),
        ))
        .write_to(&mut image_bytes, image::ImageFormat::Png)
        .unwrap();
        let image = vault.upload_esign_signature_image(token, image_bytes.get_ref())?;
        assert!(
            !vault
                .esign_signature_image_for_capability(token, &image)?
                .is_empty()
        );
        assert!(
            !vault
                .esign_preview_for_capability(token, 0, None, None)?
                .1
                .is_empty()
        );
        let audit = vault.esign_audit(id)?;
        match deletion {
            "hard" => {
                assert!(vault.delete_entity_with_options(
                    &id,
                    crate::deletion::DeleteEntityOptions { purge: true }
                )?);
            }
            "batch" => {
                vault.batch().delete(&id).commit()?;
            }
            "soft" => {
                vault.delete_entity_with_reason(&id, crate::DeleteReason::UserDelete)?;
            }
            _ => unreachable!(),
        }
        assert!(vault.read_blob_artifact_version(&original, 1)?.is_some());
        for action in [
            SigningAction::Load,
            SigningAction::SaveField {
                field: doc.fields[0].id.clone(),
                value: FieldValue::Text("value".into()),
            },
            SigningAction::Complete {
                consent: true,
                next: None,
            },
            SigningAction::Reject {
                reason: "declined".into(),
            },
        ] {
            assert!(
                vault
                    .execute_signing_action(token, &action, None, None)
                    .is_err(),
                "{deletion}"
            );
        }
        assert!(
            vault
                .esign_pdf_for_capability(token, 0, None, None)
                .is_err(),
            "{deletion}"
        );
        assert!(
            vault
                .esign_preview_for_capability(token, 0, None, None)
                .is_err(),
            "{deletion}"
        );
        assert!(
            vault
                .esign_signature_image_for_capability(token, &image)
                .is_err(),
            "{deletion}"
        );
        assert!(
            vault
                .upload_esign_signature_image(token, image_bytes.get_ref())
                .is_err(),
            "{deletion}"
        );
        assert_eq!(vault.esign_audit(id)?, audit);
        drop(vault);
        let reopened = Vault::open(dir.path(), VaultConfig::default())?;
        assert!(
            reopened
                .esign_pdf_for_capability(token, 0, None, None)
                .is_err(),
            "{deletion}"
        );
        assert_eq!(reopened.esign_audit(id)?, audit);
    }
    Ok(())
}

#[test]
fn actionable_recipient_is_required_for_send_and_seal_but_not_draft_editing() -> Result<()> {
    let (_dir, vault, id, mut doc, owner) = ceremony_setup()?;
    let mut actionable = doc.recipients[0].clone();
    actionable.id = EntityId::now().to_hex();
    actionable.role = RecipientRole::Approver;
    actionable.automated = false;
    doc.fields.clear();
    let now = crate::unix_seconds_now();
    for roles in [
        vec![],
        vec![RecipientRole::Viewer],
        vec![RecipientRole::Cc],
        vec![RecipientRole::Viewer, RecipientRole::Cc],
    ] {
        doc.recipients = roles
            .iter()
            .map(|role| {
                let mut recipient = actionable.clone();
                recipient.id = EntityId::now().to_hex();
                recipient.role = *role;
                recipient
            })
            .collect();
        event(
            &vault,
            id,
            EsignEvent::Drafted {
                document: doc.clone(),
            },
            now,
        )?;
        vault.issue_esign_capabilities(&owner, id)?;
        let audit = vault.esign_audit(id)?;
        let command = EsignOutboundCommand {
            document: id.to_hex(),
            recipient_count: doc.recipients.len(),
            verb: EsignOutboundVerb::SendForSignature,
            reason: None,
        };
        assert_ne!(
            vault
                .dispatch_esign(
                    send_request(id, owner.actor(), command.verb, &format!("empty-{roles:?}")),
                    &command,
                    None,
                    None,
                )
                .unwrap()
                .outcome,
            crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
        );
        let mut state = vault.esign_document(id)?;
        assert_eq!(state.status, DocumentStatus::Draft);
        assert_eq!(vault.esign_audit(id)?, audit);
        assert!(
            crate::attempt_queue::AttemptQueue::new(&vault)
                .list()?
                .is_empty()
        );
        // Pin the readiness backstop independently of send admission.
        state.status = DocumentStatus::Pending;
        assert!(!state.ready_to_seal());
        state.reseal_pending = true;
        assert!(!state.ready_to_seal());
        assert!(
            event(
                &vault,
                id,
                EsignEvent::Sealed {
                    rejected: false,
                    item_sha256: vec![[1; 32]],
                },
                now
            )
            .is_err()
        );
    }
    doc.kind = DocumentKind::Template;
    doc.recipients.clear();
    event(
        &vault,
        id,
        EsignEvent::Drafted {
            document: doc.clone(),
        },
        now,
    )?;
    assert_eq!(vault.esign_document(id)?.document, doc);
    doc.kind = DocumentKind::Document;
    doc.recipients = vec![actionable.clone()];
    event(
        &vault,
        id,
        EsignEvent::Drafted {
            document: doc.clone(),
        },
        now,
    )?;
    let tokens = vault.issue_esign_capabilities(&owner, id)?;
    assert_eq!(tokens.len(), 1);
    let command = EsignOutboundCommand {
        document: id.to_hex(),
        recipient_count: 1,
        verb: EsignOutboundVerb::SendForSignature,
        reason: None,
    };
    assert_eq!(
        vault
            .dispatch_esign(
                send_request(id, owner.actor(), command.verb, "approver-send"),
                &command,
                None,
                None,
            )
            .unwrap()
            .outcome,
        crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
    );
    assert!(!vault.esign_document(id)?.ready_to_seal());
    assert_eq!(
        vault.execute_signing_action(
            &tokens[0].1,
            &SigningAction::Complete {
                consent: false,
                next: None
            },
            None,
            None
        )?,
        SigningOutcome::ConsentRequired
    );
    assert!(!vault.esign_document(id)?.ready_to_seal());
    assert_eq!(
        vault.execute_signing_action(
            &tokens[0].1,
            &SigningAction::Complete {
                consent: true,
                next: None
            },
            None,
            None
        )?,
        SigningOutcome::AwaitingSeal
    );
    assert!(vault.esign_document(id)?.ready_to_seal());
    assert_eq!(
        vault.esign_document(id)?.recipients[&actionable.id].signing,
        SigningStatus::Completed
    );
    Ok(())
}

#[test]
fn draft_reissuance_replaces_only_revoked_expired_or_short_lived_capabilities() -> Result<()> {
    for cause in ["revoked", "expired", "deadline_extended"] {
        let (_dir, vault, original, mut doc, owner) = ceremony_setup()?;
        let now = crate::unix_seconds_now();
        doc.sequential = false;
        doc.fields.clear();
        for recipient in &mut doc.recipients {
            recipient.automated = false;
        }
        // Historical drafts let the expiry case run without sleeping or a
        // process-global clock override. The original PDF stays pinned.
        let id = if cause == "expired" {
            doc.expires_at = 1000;
            for recipient in &mut doc.recipients {
                recipient.expires_at = 1000;
            }
            let id = EntityId::now();
            vault.put_blob_artifact(
                &id,
                &crate::blob_artifact::BlobArtifactBody::new("envelope.pdf", "application/pdf"),
                TimeRange { start: 1, end: 1 },
                1,
            )?;
            vault.create_esign_document(id, &doc, actor(), 2)?;
            id
        } else {
            event(
                &vault,
                original,
                EsignEvent::Drafted {
                    document: doc.clone(),
                },
                now,
            )?;
            original
        };
        let original_tokens = vault.issue_esign_capabilities(&owner, id)?;
        assert_eq!(original_tokens.len(), 2);
        if cause == "revoked" {
            vault.revoke_esign_capability(&owner, &original_tokens[0].1)?;
        } else {
            doc.expires_at = now + 7200;
            for recipient in &mut doc.recipients {
                recipient.expires_at = doc.expires_at;
            }
            event(
                &vault,
                id,
                EsignEvent::Drafted {
                    document: doc.clone(),
                },
                now,
            )?;
        }
        let mut command = EsignOutboundCommand {
            document: id.to_hex(),
            recipient_count: doc.recipients.len(),
            verb: EsignOutboundVerb::SendForSignature,
            reason: None,
        };
        assert_ne!(
            vault
                .dispatch_esign(
                    send_request(id, owner.actor(), command.verb, "unusable-send"),
                    &command,
                    None,
                    None,
                )
                .unwrap()
                .outcome,
            crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
        );
        assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Draft);
        assert!(
            crate::attempt_queue::AttemptQueue::new(&vault)
                .list()?
                .is_empty()
        );
        let replacements = vault.issue_esign_capabilities(&owner, id)?;
        assert_eq!(replacements.len(), if cause == "revoked" { 1 } else { 2 });
        for ((recipient, replacement), (old_recipient, old_token)) in
            replacements.iter().zip(&original_tokens)
        {
            assert_eq!(recipient, old_recipient);
            assert_ne!(
                replacement.expose_for_delivery(),
                old_token.expose_for_delivery()
            );
        }
        assert!(vault.issue_esign_capabilities(&owner, id)?.is_empty());
        assert_eq!(
            vault
                .dispatch_esign(
                    send_request(id, owner.actor(), command.verb, "replacement-send"),
                    &command,
                    None,
                    None,
                )
                .unwrap()
                .outcome,
            crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
        );
        for (index, (_, old)) in original_tokens.iter().enumerate() {
            if cause == "revoked" && index == 1 {
                assert!(matches!(
                    vault.execute_signing_action(old, &SigningAction::Load, None, None)?,
                    SigningOutcome::Page(_)
                ));
            } else {
                assert!(
                    vault
                        .execute_signing_action(old, &SigningAction::Load, None, None)
                        .is_err(),
                    "{cause}"
                );
            }
        }
        for (_, replacement) in &replacements {
            assert!(matches!(
                vault.execute_signing_action(replacement, &SigningAction::Load, None, None)?,
                SigningOutcome::Page(_)
            ));
        }
        command.verb = EsignOutboundVerb::Remind;
        assert_eq!(
            vault
                .dispatch_esign(
                    send_request(id, owner.actor(), command.verb, "replacement-remind"),
                    &command,
                    None,
                    None,
                )
                .unwrap()
                .outcome,
            crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
        );
        assert!(vault.issue_esign_capabilities(&owner, id).is_err());
        assert!(matches!(
            vault.execute_signing_action(&replacements[0].1, &SigningAction::Load, None, None)?,
            SigningOutcome::Page(_)
        ));
    }
    Ok(())
}

#[test]
fn unrenderable_fields_are_refused_before_save_and_final_signature_without_locking_correction()
-> Result<()> {
    let (_dir, vault, id, mut doc, owner) = ceremony_setup()?;
    doc.recipients.truncate(1);
    doc.recipients[0].automated = false;
    doc.fields[0].meta = FieldMeta::Text { max_bytes: 1024 };
    let now = crate::unix_seconds_now();
    event(
        &vault,
        id,
        EsignEvent::Drafted {
            document: doc.clone(),
        },
        now,
    )?;
    let tokens = vault.issue_esign_capabilities(&owner, id)?;
    let token = &tokens[0].1;
    let command = EsignOutboundCommand {
        document: id.to_hex(),
        recipient_count: 1,
        verb: EsignOutboundVerb::SendForSignature,
        reason: None,
    };
    assert_eq!(
        vault
            .dispatch_esign(
                send_request(id, owner.actor(), command.verb, "renderable-send"),
                &command,
                None,
                None,
            )
            .unwrap()
            .outcome,
        crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
    );
    vault.execute_signing_action(token, &SigningAction::Load, None, None)?;
    let before = vault.esign_document(id)?;
    let audit = vault.esign_audit(id)?;
    let field = &doc.fields[0].id;
    for invalid_text in ["😀".into(), "control\tcharacter".into(), "W".repeat(1024)] {
        assert!(matches!(
            vault.execute_signing_action(
                token,
                &SigningAction::SaveField {
                    field: field.clone(),
                    value: FieldValue::Text(invalid_text),
                },
                None,
                None
            ),
            Err(Error::InvalidConfig(_))
        ));
        assert_eq!(vault.esign_document(id)?, before);
        assert_eq!(vault.esign_audit(id)?, audit);
    }
    let complete = SigningAction::Complete {
        consent: true,
        next: None,
    };
    assert!(
        vault
            .execute_signing_action(token, &complete, None, None)
            .is_err()
    );
    assert_eq!(vault.esign_document(id)?, before);

    // Reproduce a value admitted before field-layout validation. This fixture
    // uses the reserved writer, not the public claim/capability mutation door.
    let legacy = EsignEventRow {
        sequence: audit.len() as u64,
        previous_sha256: super::ledger::hash(audit.last().unwrap())?,
        event: EsignEvent::FieldSaved {
            signature: SignatureRow {
                field: field.clone(),
                recipient: doc.recipients[0].id.clone(),
                value: FieldValue::Text("W".repeat(1024)),
                at: now,
            },
        },
        actor: actor(),
        at: crate::unix_seconds_now(),
    };
    let encoded = super::ledger::encoded(&legacy)?;
    let mut claim = crate::claim::ClaimBody::new(
        "esign.field",
        crate::claim::ClaimSubject::Entity(id),
        rmpv::Value::Binary(encoded.clone()),
        1.0,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    claim.source = Some(crate::claim::ClaimSource::Observed);
    vault.with_write_txn(|txn| {
        vault.put_reserved_claim_in_txn(
            txn,
            &EntityId::now(),
            &claim,
            TimeRange {
                start: legacy.at,
                end: legacy.at,
            },
            legacy.at,
        )?;
        vault.store.vault_meta.put(
            txn,
            &[
                b"esign.audit.v1/".as_slice(),
                id.as_bytes(),
                &legacy.sequence.to_be_bytes(),
            ]
            .concat(),
            &encoded,
        )?;
        Ok(())
    })?;
    let stored = vault.esign_document(id)?;
    let audit = vault.esign_audit(id)?;
    assert_eq!(
        stored.signatures[field].value,
        FieldValue::Text("W".repeat(1024))
    );
    assert!(matches!(
        vault.execute_signing_action(token, &complete, None, None),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(vault.esign_document(id)?, stored);
    assert_eq!(vault.esign_audit(id)?, audit);
    assert_eq!(
        stored.recipients[&doc.recipients[0].id].signing,
        SigningStatus::Ready
    );
    assert!(
        crate::attempt_queue::AttemptQueue::new(&vault)
            .list()?
            .iter()
            .all(|attempt| attempt.kind != ESIGN_SEAL_ATTEMPT_KIND)
    );

    let corrected = FieldValue::Text("Café\nAccepted".into());
    let SigningOutcome::Page(page) = vault.execute_signing_action(
        token,
        &SigningAction::SaveField {
            field: field.clone(),
            value: corrected.clone(),
        },
        None,
        None,
    )?
    else {
        panic!("correction returns the page")
    };
    assert_eq!(page.values[field].value, corrected);
    assert_eq!(
        vault.execute_signing_action(token, &complete, None, None)?,
        SigningOutcome::AwaitingSeal
    );
    let final_state = vault.esign_document(id)?;
    assert!(final_state.ready_to_seal());
    assert_eq!(
        final_state.recipients[&doc.recipients[0].id].signing,
        SigningStatus::Completed
    );
    let prepared = render::prepare_esign_pdf(
        original_pdf(),
        render::PdfPreparation {
            document_ref: &id.to_hex(),
            item: 0,
            state: &final_state,
            audit: &vault.esign_audit(id)?,
            canonical_url: &format!("https://example.test/sign#{}", token.expose_for_delivery()),
            signature_images: &std::collections::BTreeMap::new(),
        },
    )
    .unwrap();
    assert_eq!(prepared.original_pages, 1);
    Ok(())
}

#[test]
fn committed_signature_or_decline_wins_expiry_and_void_while_sealing() -> Result<()> {
    for decline in [false, true] {
        let (_dir, vault, id, mut doc) = setup()?;
        doc.fields.clear();
        doc.sequential = false;
        event(
            &vault,
            id,
            EsignEvent::Drafted {
                document: doc.clone(),
            },
            3,
        )?;
        event(&vault, id, EsignEvent::Sent, 4)?;
        let first = doc.recipients[0].id.clone();
        event(
            &vault,
            id,
            EsignEvent::Viewed {
                recipient: first.clone(),
            },
            5,
        )?;
        if decline {
            event(
                &vault,
                id,
                EsignEvent::Declined {
                    recipient: first.clone(),
                    reason: "no".into(),
                },
                6,
            )?;
        } else {
            event(
                &vault,
                id,
                EsignEvent::Signed {
                    recipient: first.clone(),
                    next: None,
                },
                6,
            )?;
            let second = doc.recipients[1].id.clone();
            event(
                &vault,
                id,
                EsignEvent::Viewed {
                    recipient: second.clone(),
                },
                7,
            )?;
            event(
                &vault,
                id,
                EsignEvent::Signed {
                    recipient: second,
                    next: None,
                },
                8,
            )?;
        }
        assert!(vault.esign_document(id)?.ready_to_seal());
        let before = vault.esign_audit(id)?.len();
        assert_eq!(vault.sweep_esign_expiry(&[id], doc.expires_at)?, 0);
        assert_eq!(vault.sweep_esign_expiry(&[id], doc.expires_at + 100)?, 0);
        assert!(
            event(
                &vault,
                id,
                EsignEvent::Expired {
                    recipient: Some(first)
                },
                doc.expires_at
            )
            .is_err()
        );
        assert!(
            event(
                &vault,
                id,
                EsignEvent::Voided {
                    reason: "too late".into()
                },
                doc.expires_at
            )
            .is_err()
        );
        assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Pending);
        assert_eq!(vault.esign_audit(id)?.len(), before);
        assert!(
            crate::attempt_queue::AttemptQueue::new(&vault)
                .list()?
                .iter()
                .all(|a| a.kind != ESIGN_NOTICE_ATTEMPT_KIND)
        );
    }
    Ok(())
}

#[test]
fn transition_mail_is_staged_then_denied_held_retried_and_allowed_via_outbound_gate() -> Result<()>
{
    use crate::attempt_queue::{AttemptQueue, AttemptState};
    use crate::outbound::{
        OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
        OutboundDispatchOutcome, OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft,
        OutboundIntentTrigger,
    };
    let (dir, vault, id, doc) = setup()?;
    let sender = EntityId::now();
    vault.put_entity(
        &sender,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"sender",
    )?;
    event(
        &vault,
        id,
        EsignEvent::Drafted {
            document: doc.clone(),
        },
        3,
    )?;
    vault.with_write_txn(|txn| {
        super::ledger::append(
            &vault,
            txn,
            id,
            EsignEvent::Sent,
            EsignAuditActor {
                actor: sender.to_hex(),
                ip: None,
                user_agent: None,
            },
            4,
        )
        .map(|_| ())
    })?;
    let manifest = serde_json::json!({
        "schema_version":"1.2", "pack_id":"esign-mail-test", "pack_version":"v1",
        "min_engine_version":env!("CARGO_PKG_VERSION"),
        "defaults":{"criticality":"normal","sensitivity":"normal"}, "rules":[],
        "actor_ceilings":[{"actor_class":"human","actor_ref":sender.to_hex(),"ceiling":"auto"}],
        "scoped_grants":[{"actor_ref":sender.to_hex(),"effector":"external:send",
            "scope":crate::federation::scope_codec::effect_preset(),"selectors":{"channel":"email"}}]
    });
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &rmp_serde::to_vec_named(&manifest).unwrap(),
    )?;
    let put_sender = |sender_id: EntityId| {
        let identity = crate::test_util::self_held_identity_in_state(
            "email",
            &format!("sender-{}@example.com", sender_id.to_hex()),
            crate::channel_identity::SelfHeldShape::DedicatedAddress,
            crate::channel_identity::ChannelIdentityBinding::actor(sender),
            crate::channel_identity::ChannelIdentityState::Active,
            1_000,
        );
        vault.create_channel_identity(&sender_id, &identity)
    };
    let original_sender = EntityId::now();
    put_sender(original_sender)?;
    assert_eq!(vault.sweep_esign_expiry(&[id], doc.expires_at)?, 1);
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()?
            .iter()
            .filter(|a| a.kind == ESIGN_NOTICE_ATTEMPT_KIND)
            .count(),
        2
    );
    assert!(
        AttemptQueue::new(&vault)
            .list()?
            .iter()
            .all(|a| a.kind != "esign.delivery")
    );
    let request = |notice: &EsignNotice, at: u64, key: &str, opted_in: bool, permitted: bool| {
        OutboundDispatchRequest::new(
            format!("receipt:{key}"),
            key,
            OutboundIntent::from_trigger(
                OutboundIntentDraft {
                    actor: sender.to_hex(),
                    on_behalf_of: None,
                    verb: "send".into(),
                    channel: "email".into(),
                    target: notice.email.clone(),
                    content_ref: None,
                    idempotency_key: None,
                    dedupe_key: None,
                },
                OutboundIntentTrigger::record_transition(notice.event_ref.clone().unwrap()),
            ),
            OutboundDispatchActor {
                actor_class: "human".into(),
                actor_ref: Some(sender.to_hex()),
                actor_entity_ref: Some(sender),
            },
            OutboundDispatchGate {
                has_opted_in: opted_in,
                has_permission: permitted,
                policy_risk: Default::default(),
            },
            at,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    let (held_attempt, held) = vault
        .claim_esign_notice("notice-worker", crate::unix_seconds_now())?
        .unwrap();
    assert_eq!(held.principal.as_deref(), Some(sender.to_hex().as_str()));
    let held_result = vault
        .dispatch_esign_notice(&held_attempt, request(&held, 1002, "hold", true, false))
        .unwrap();
    assert_eq!(held_result.outcome, OutboundDispatchOutcome::Held);
    assert!(
        AttemptQueue::new(&vault)
            .list()?
            .iter()
            .all(|a| a.kind != "esign.delivery")
    );
    // The other recipient's original row precedes the scheduled retry.
    let (other, other_notice) = vault
        .claim_esign_notice("notice-worker", crate::unix_seconds_now())?
        .unwrap();
    assert_ne!(other_notice, held);
    let (retry, same_notice) = vault
        .claim_esign_notice("notice-worker", crate::unix_seconds_now())?
        .unwrap();
    assert_eq!(same_notice, held);
    assert_eq!(retry.state, AttemptState::Leased);
    let mut initial_send = request(&same_notice, 1065, "allow", true, true);
    initial_send.channel_identity_ref = Some(original_sender);
    let sent = vault.dispatch_esign_notice(&retry, initial_send).unwrap();
    assert_eq!(
        sent.outcome,
        OutboundDispatchOutcome::DeliveredToChannel,
        "{sent:?}"
    );
    // A later sender becoming available must not replace the one the rail froze.
    let different_sender = EntityId::now();
    put_sender(different_sender)?;
    let gates_before = vault.gate_decisions(100)?;
    let replay = vault
        .dispatch_esign_notice(&retry, request(&same_notice, 1065, "allow", true, true))
        .unwrap();
    assert_eq!(replay.outcome, sent.outcome);
    assert_eq!(replay.receipt, sent.receipt);
    assert!(
        vault
            .dispatch_esign_notice(
                &retry,
                request(&same_notice, 1065, "changed-receipt", true, true)
            )
            .is_err()
    );
    let mut same_sender = request(&same_notice, 1065, "allow", true, true);
    same_sender.channel_identity_ref = Some(original_sender);
    assert_eq!(
        vault
            .dispatch_esign_notice(&retry, same_sender)
            .unwrap()
            .receipt,
        sent.receipt
    );
    for mutation in ["sender", "counterparty", "session"] {
        let mut changed = request(&same_notice, 1065, "allow", true, true);
        match mutation {
            "sender" => changed.channel_identity_ref = Some(different_sender),
            "counterparty" => changed.counterparty_ref = Some("counterparty:different".into()),
            "session" => changed.originating_session_ref = Some("session:different".into()),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                vault.dispatch_esign_notice(&retry, changed),
                Err(crate::outbound::OutboundDispatchError::Chokepoint(
                    crate::outbound_intent_ledger::IntentLedgerError::InvalidRecord(_)
                ))
            ),
            "{mutation} must fail at shared replay validation"
        );
    }
    assert_eq!(vault.gate_decisions(100)?, gates_before);
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()?
            .iter()
            .filter(|a| a.kind == "esign.delivery")
            .count(),
        1
    );
    let key_id = EntityId::now();
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active("email", None, Vec::new(), 1066),
    )?;
    let pending = vault.propose_connector_charter(&key_id, "never send on email", 1067)?;
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1068)?;
    let mut denied_request = request(&other_notice, 1070, "hard-deny", true, true);
    denied_request.channel_identity_ref = Some(original_sender);
    let denied_result = vault.dispatch_esign_notice(&other, denied_request).unwrap();
    assert_eq!(denied_result.gate_outcome, "deny", "{denied_result:?}");
    assert_eq!(denied_result.outcome, OutboundDispatchOutcome::Suppressed);
    // All three outcomes are audit rows in the public outbound receipt family.
    let receipt_query =
        crate::receipt::ReceiptQuery::new(100).with_kind(crate::receipt::ReceiptKind::Outbound);
    let expected = [held_result.receipt, sent.receipt, denied_result.receipt];
    for entry in &expected {
        assert!(vault.receipts(receipt_query.clone())?.contains(entry));
        assert!(
            vault
                .scan_receipts(receipt_query.clone())?
                .records
                .contains(entry)
        );
    }
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    for entry in &expected {
        assert!(reopened.receipts(receipt_query.clone())?.contains(entry));
        let scan = reopened.scan_receipts(receipt_query.clone())?;
        assert!(scan.complete);
        assert!(scan.records.contains(entry));
    }
    let vault = reopened;
    let replay = vault
        .dispatch_esign_notice(&retry, request(&same_notice, 1065, "allow", true, true))
        .unwrap();
    assert_eq!(replay.receipt, expected[1]);
    let mut wrong_after_reopen = request(&same_notice, 1065, "allow", true, true);
    wrong_after_reopen.counterparty_ref = Some("counterparty:after-reopen".into());
    assert!(matches!(
        vault.dispatch_esign_notice(&retry, wrong_after_reopen),
        Err(crate::outbound::OutboundDispatchError::Chokepoint(
            crate::outbound_intent_ledger::IntentLedgerError::InvalidRecord(_)
        ))
    ));
    let rows = AttemptQueue::new(&vault).list()?;
    assert_eq!(
        rows.iter().filter(|a| a.kind == "esign.delivery").count(),
        1
    );
    assert_eq!(
        rows.iter()
            .filter(|a| a.kind == "esign.delivery")
            .map(
                |a| serde_json::from_slice::<serde_json::Value>(&a.payload).unwrap()["transition"]
                    .clone()
            )
            .collect::<Vec<_>>(),
        vec!["expiry"]
    );
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Expired);
    Ok(())
}

#[test]
fn completed_recipient_window_cannot_expire_a_different_pending_signer() -> Result<()> {
    let (_dir, vault, id, mut doc) = setup()?;
    doc.fields.clear();
    doc.sequential = false;
    doc.recipients[0].expires_at = 100;
    let first = doc.recipients[0].id.clone();
    let second = doc.recipients[1].id.clone();
    event(
        &vault,
        id,
        EsignEvent::Drafted {
            document: doc.clone(),
        },
        3,
    )?;
    event(&vault, id, EsignEvent::Sent, 4)?;
    event(&vault, id, EsignEvent::Viewed { recipient: first }, 5)?;
    event(
        &vault,
        id,
        EsignEvent::Signed {
            recipient: doc.recipients[0].id.clone(),
            next: None,
        },
        6,
    )?;
    assert!(!vault.esign_document(id)?.ready_to_seal());
    assert_eq!(vault.sweep_esign_expiry(&[id], 100)?, 0);
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Pending);
    assert_eq!(vault.sweep_esign_expiry(&[id], doc.expires_at)?, 1);
    assert_eq!(
        vault.esign_audit(id)?.last().unwrap().event,
        EsignEvent::Expired {
            recipient: Some(second)
        }
    );
    Ok(())
}
