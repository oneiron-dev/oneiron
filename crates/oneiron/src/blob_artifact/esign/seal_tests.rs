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
        report.valid = false;
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
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let now = crate::unix_seconds_now();
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
            role: RecipientRole::Cc,
            order: 0,
            expires_at: now + 3600,
            principal_ref: None,
            automated: false,
        }],
        fields: vec![],
        full_trail_appendix: true,
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
        super::ceremony::enqueue_seal(&vault, txn, id, now)
    })?;
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(attempt) = queue.claim_kind(
        ESIGN_SEAL_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "seal-test".into(),
            now,
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
    let sealed = run(vault.seal_esign_attempt(&attempt, &engine, PadesProfile::BaselineB, url))?;
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Completed);
    assert!(vault.verify_esign_item(id, 0, &engine)?.valid);
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
    assert!(vault.verify_esign_item(id, 0, &engine)?.valid);
    assert_eq!(
        vault.read_blob_artifact_version(&id, 1)?.as_deref(),
        Some(original.as_slice())
    );
    Ok(())
}
