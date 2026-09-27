//! The real native PAdES engine, not a simulated successful sealer.
use super::*;
use crate::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use crate::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_seal::*;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::pkcs8::DecodePrivateKey;
use std::sync::Arc;
struct Backend {
    key: p256::ecdsa::SigningKey,
    cert: Vec<u8>,
}
#[async_trait::async_trait]
impl SealBackend for Backend {
    fn signing_identity(&self) -> std::result::Result<SigningIdentity, BackendError> {
        Ok(SigningIdentity {
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            signer_certificate_der: self.cert.clone(),
            certificate_chain_der: vec![],
        })
    }
    async fn sign_digest(
        &self,
        request: SignDigestRequest,
    ) -> std::result::Result<BackendSignature, BackendError> {
        let signature: p256::ecdsa::Signature = self
            .key
            .sign_prehash(&request.digest)
            .map_err(|_| BackendError::MalformedSignature)?;
        Ok(BackendSignature::EcdsaP256Der {
            bytes: signature.to_der().as_bytes().to_vec(),
        })
    }
}
struct Clock;
impl SealClock for Clock {
    fn unix_time_ms(&self) -> u64 {
        crate::unix_seconds_now() * 1000
    }
}
struct RejectVerify<'a>(&'a NativeSealEngine);
#[async_trait::async_trait]
impl PdfSealEngine for RejectVerify<'_> {
    async fn seal_pdf(
        &self,
        input: &[u8],
        request: &SealRequest,
    ) -> std::result::Result<SealedPdf, SealError> {
        self.0.seal_pdf(input, request).await
    }
    fn verify_sealed_pdf(&self, bytes: &[u8]) -> std::result::Result<VerifyReport, SealError> {
        let mut report = self.0.verify_sealed_pdf(bytes)?;
        let Some(check) = report
            .signatures
            .iter_mut()
            .flat_map(|signature| signature.checks.iter_mut())
            .find(|check| check.kind == VerifyCheckKind::ContentDigest)
        else {
            panic!("fixture must have a content-digest check");
        };
        check.status = VerifyCheckStatus::Fail;
        check.finding = Some(VerifyFindingCode::DigestMismatch);
        Ok(report)
    }
}
fn run<F: std::future::Future>(future: F) -> F::Output {
    struct Wake(std::thread::Thread);
    impl std::task::Wake for Wake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(Wake(std::thread::current())));
    let mut ctx = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut ctx) {
            std::task::Poll::Ready(out) => return out,
            std::task::Poll::Pending => std::thread::park(),
        }
    }
}
#[test]
fn native_seal_verifies_before_atomic_terminal_and_retries_from_pristine_original()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let cert = params.self_signed(&key)?.der().to_vec();
    let backend = Backend {
        key: p256::ecdsa::SigningKey::from_pkcs8_der(&key.serialize_der())?,
        cert: cert.clone(),
    };
    let engine = NativeSealEngine::new(
        SealConfig {
            trust_anchors_der: vec![cert],
            timestamp_authorities: vec![],
            fetch_policy: FetchPolicy::default(),
            resource_limits: SealResourceLimits::default(),
        },
        Arc::new(backend),
        Arc::new(OfflineFetcher),
        Arc::new(Clock),
    )?;
    let dir = tempfile::tempdir()?;
    let now = crate::unix_seconds_now();
    let clock = crate::ports::ManualClock::new(now);
    let config = VaultConfig {
        store_clock: clock.bundle(),
        ..VaultConfig::default()
    };
    let vault = Vault::open(dir.path(), config)?;
    let at = TimeRange {
        start: now,
        end: now,
    };
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        now,
        b"owner",
    )?;
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &crate::blob_artifact::BlobArtifactBody::new("original.pdf", "application/pdf"),
        at,
        now,
    )?;
    let original = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ));
    vault.append_blob_artifact_version(
        &id,
        original,
        &crate::blob_artifact::BlobVersionProvenance::UserUpload,
        crate::write_envelope::WriteActor::new(owner, crate::edge::EdgeActorClass::Human),
        at,
        now,
    )?;
    let document = EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: false,
        expires_at: now + 3600,
        items: vec![EsignItem {
            artifact_ref: id.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: EntityId::now().to_hex(),
            email: "reader@example.test".into(),
            name: "Reader".into(),
            role: RecipientRole::Approver,
            order: 0,
            expires_at: now + 3600,
            principal_ref: None,
            automated: false,
        }],
        fields: vec![],
        full_trail_appendix: true,
        lifecycle: None,
    };
    let actor = EsignAuditActor {
        actor: owner.to_hex(),
        ip: None,
        user_agent: None,
    };
    vault.create_esign_document(id, &document, actor.clone(), now)?;
    let owner_auth = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let capabilities = vault.issue_esign_capabilities(&owner_auth, id)?;
    let canonical_url = format!(
        "https://example.test/sign#{}",
        capabilities[0].1.expose_for_delivery()
    );
    vault.with_write_txn(|txn| {
        super::ledger::append(&vault, txn, id, EsignEvent::Sent, actor, now)?;
        Ok(())
    })?;
    assert!(!vault.esign_document(id)?.ready_to_seal());
    assert_eq!(
        vault.execute_signing_action(
            &capabilities[0].1,
            &SigningAction::Complete {
                consent: true,
                next: None
            },
            None,
            None,
        )?,
        SigningOutcome::AwaitingSeal
    );
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(attempt) = queue.claim_kind(
        ESIGN_SEAL_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "seal-test".into(),
            now: crate::unix_seconds_now(),
        },
    )?
    else {
        panic!("seal job missing")
    };
    let url = canonical_url.as_str();
    assert!(matches!(
        run(vault.seal_esign_attempt(
            &attempt,
            &RejectVerify(&engine),
            PadesProfile::BaselineB,
            url
        )),
        Err(EsignSealError::Verification)
    ));
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Pending);
    assert!(vault.sealed_esign_document(id)?.is_none());
    // The document deadline does not erase the committed signature while a
    // delayed/retried seal still owns the derived completion outcome.
    assert_eq!(vault.sweep_esign_expiry(&[id], now + 3600)?, 0);
    assert!(vault.esign_document(id)?.ready_to_seal());
    let sealed = run(vault.seal_esign_attempt(&attempt, &engine, PadesProfile::BaselineB, url))?;
    assert_eq!(
        EntityId::from_hex(&sealed.items[0].sealed_artifact)?.as_bytes()[0],
        0x71
    );
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Completed);
    assert!(vault.verify_esign_item(id, 0, &engine)?.valid());
    let notices = AttemptQueue::new(&vault).list()?;
    let completion = notices
        .iter()
        .filter(|a| a.kind == ESIGN_NOTICE_ATTEMPT_KIND)
        .map(|a| serde_json::from_slice::<serde_json::Value>(&a.payload))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(completion.len(), 1);
    assert_eq!(completion[0]["transition"], "completed");
    assert_eq!(
        completion[0]["sealed_items"][0]["sealed_artifact"],
        sealed.items[0].sealed_artifact
    );
    // Completion has only a frozen notice until email.send passes OF-327.
    assert!(
        AttemptQueue::new(&vault)
            .list()?
            .iter()
            .all(|a| a.kind != "esign.delivery")
    );
    let sealed_bytes = vault
        .read_blob_artifact_version(&EntityId::from_hex(&sealed.items[0].sealed_artifact)?, 1)?
        .unwrap();
    assert!(lopdf::Document::load_mem(&sealed_bytes)?.get_pages().len() > 1);
    assert_eq!(
        vault.esign_pdf_for_capability(
            &capabilities[0].1,
            0,
            Some("127.0.0.1".into()),
            Some("test".into())
        )?,
        sealed_bytes
    );
    assert_eq!(
        vault.read_blob_artifact_version(&id, 1)?.as_deref(),
        Some(original.as_slice())
    );
    assert_eq!(
        run(vault.seal_esign_attempt(&attempt, &engine, PadesProfile::BaselineB, url))?,
        sealed
    );
    let owner = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    assert!(
        vault
            .request_esign_reseal(&owner, id, "not-a-grant", None, None)
            .is_err()
    );
    let bound = crate::consent::GrantBound::action(
        crate::consent::ActorBound::new(owner.actor().to_hex())?,
        crate::consent::ActionClass::new("esign.reseal")?,
        crate::consent::ActionEnvelope::new([format!("document:{}", id.to_hex())])?,
    )?;
    let grant_ref = bound.digest().to_hex();
    vault.create_standing_grant(&owner, bound)?;
    vault.request_esign_reseal(&owner, id, &grant_ref, None, None)?;
    let ClaimOutcome::Claimed(reseal) = queue.claim_kind(
        ESIGN_SEAL_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "reseal-test".into(),
            now: crate::unix_seconds_now(),
        },
    )?
    else {
        panic!("reseal job missing")
    };
    let resealed = run(vault.seal_esign_attempt(&reseal, &engine, PadesProfile::BaselineB, url))?;
    assert_ne!(
        resealed.items[0].sealed_artifact,
        sealed.items[0].sealed_artifact
    );
    let staged = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|a| a.kind == ESIGN_NOTICE_ATTEMPT_KIND)
        .map(|a| serde_json::from_slice::<serde_json::Value>(&a.payload))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(staged.len(), 2);
    assert_ne!(staged[0]["generation"], staged[1]["generation"]);
    assert_eq!(
        staged[0]["sealed_items"][0]["sealed_artifact"],
        sealed.items[0].sealed_artifact
    );
    assert_eq!(
        staged[1]["sealed_items"][0]["sealed_artifact"],
        resealed.items[0].sealed_artifact
    );
    assert_eq!(
        run(vault.seal_esign_attempt(&reseal, &engine, PadesProfile::BaselineB, url))?,
        resealed
    );
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()?
            .iter()
            .filter(|a| a.kind == ESIGN_NOTICE_ATTEMPT_KIND)
            .count(),
        2
    );
    // The old completion is still queued during reseal. Its frozen PDF is
    // retired; the new generation alone may cross the email dispatch gate.
    let mail_policy = serde_json::json!({
        "schema_version":"1.2", "pack_id":"esign-sealed-mail", "pack_version":"v1",
        "min_engine_version":env!("CARGO_PKG_VERSION"),
        "defaults":{"criticality":"normal","sensitivity":"normal"}, "rules":[],
        "actor_ceilings":[{"actor_class":"human","actor_ref":owner.actor().to_hex(),"ceiling":"auto"}],
        "scoped_grants":[{"actor_ref":owner.actor().to_hex(),"effector":"external:send",
            "scope":crate::federation::scope_codec::effect_preset(),"selectors":{"channel":"email"}}]
    });
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &rmp_serde::to_vec_named(&mail_policy)?,
    )?;
    let outgoing = |notice: &EsignNotice, key: &str| {
        crate::outbound::OutboundDispatchRequest::new(
            format!("receipt:{key}"),
            key,
            crate::outbound::OutboundIntent::from_trigger(
                crate::outbound::OutboundIntentDraft::new(
                    owner.actor().to_hex(),
                    "send",
                    "email",
                    notice.email.clone(),
                ),
                crate::outbound::OutboundIntentTrigger::record_transition(
                    notice.event_ref.clone().unwrap(),
                ),
            ),
            crate::outbound::OutboundDispatchActor {
                actor_class: "human".into(),
                actor_ref: Some(owner.actor().to_hex()),
                actor_entity_ref: Some(owner.actor()),
            },
            crate::outbound::OutboundDispatchGate::allow_when_policy_grants(),
            crate::unix_seconds_now(),
            crate::outbound::OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    let (old_attempt, old_notice) = vault
        .claim_esign_notice("sealed-mail", crate::unix_seconds_now())?
        .expect("original completion staged");
    assert!(
        vault
            .dispatch_esign_notice(&old_attempt, outgoing(&old_notice, "stale-completion"))
            .is_err()
    );
    let (new_attempt, new_notice) = vault
        .claim_esign_notice("sealed-mail", crate::unix_seconds_now())?
        .expect("resealed completion staged");
    let delivered =
        vault.dispatch_esign_notice(&new_attempt, outgoing(&new_notice, "resealed-completion"))?;
    assert_eq!(
        delivered.outcome,
        crate::outbound::OutboundDispatchOutcome::DeliveredToChannel
    );
    let final_delivery = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .find(|a| a.kind == "esign.delivery")
        .expect("email-gated delivery");
    let payload: serde_json::Value = serde_json::from_slice(&final_delivery.payload)?;
    assert_eq!(
        payload["sealed_items"][0]["sealed_artifact"],
        resealed.items[0].sealed_artifact
    );
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()?
            .iter()
            .filter(|a| a.kind == "esign.delivery")
            .count(),
        1
    );
    assert!(vault.verify_esign_item(id, 0, &engine)?.valid());
    assert_eq!(
        vault.read_blob_artifact_version(&id, 1)?.as_deref(),
        Some(original.as_slice())
    );
    let audit = vault.esign_audit(id)?;
    let canonical = vault.esign_pdf_for_capability(&capabilities[0].1, 0, None, None)?;
    assert!(
        vault.delete_entity_with_options(
            &id,
            crate::deletion::DeleteEntityOptions { purge: true }
        )?
    );
    // The separately stored sealed artifact still exists; deletion revokes its
    // public route, not the independent audit or owner-side storage read.
    assert_eq!(
        vault.read_blob_artifact_version(
            &EntityId::from_hex(&resealed.items[0].sealed_artifact)?,
            resealed.items[0].sealed_version,
        )?,
        Some(canonical)
    );
    assert!(
        vault
            .esign_pdf_for_capability(&capabilities[0].1, 0, None, None)
            .is_err()
    );
    assert!(
        vault
            .execute_signing_action(&capabilities[0].1, &SigningAction::Load, None, None)
            .is_err()
    );
    assert_eq!(vault.esign_audit(id)?, audit);
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    assert!(
        reopened
            .esign_pdf_for_capability(&capabilities[0].1, 0, None, None)
            .is_err()
    );
    assert_eq!(reopened.esign_audit(id)?, audit);
    Ok(())
}
