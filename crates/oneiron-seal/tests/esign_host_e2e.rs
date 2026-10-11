//! The engine's seal task over the real organ host and the real seal organ
//! process, not a simulated sealer: a failed self-verification commits
//! nothing, the retry seals from the pristine original, a reseal stages a
//! new generation and fences the old notice, and the audit survives
//! deletion and reopen. The engine never links this crate; it reaches the
//! seal through its port, `EsignSealer`, and the host adapter, which keeps
//! the key. Keys and certificates are synthetic, made fresh by rcgen.
#![cfg(unix)]

use std::time::Instant;

use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::blob_artifact::esign::{
    DocumentKind, DocumentStatus, ESIGN_NOTICE_ATTEMPT_KIND, ESIGN_SEAL_ATTEMPT_KIND,
    EsignAuditActor, EsignDocument, EsignItem, EsignNotice, EsignRecipient, EsignSealError,
    EsignSealRequest, EsignSealed, EsignSealer, EsignSealerError, EsignVerdict, RecipientRole,
    SealProfile, SealVerdict, SigningAction, SigningOutcome,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_organ_host::seal::{
    HostedSealer, SealAlgorithm, SealIdentity, SealKeyError, SealKeys, SealSettings, SealTsa,
    seal_spec,
};
use oneiron_organ_host::{FetchGrant, HostConfig, OrganHost};
use oneiron_seal::organ::MAX_REPORT_JSON_BYTES;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::pkcs8::DecodePrivateKey;

const ORGAN: &str = env!("CARGO_BIN_EXE_oneiron-seal-organ");
const ORIGINAL: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/pdf-input/classic_1page.pdf"
));

/// A synthetic P-256 key and its self-signed certificate, held engine-side.
struct Keys {
    key: p256::ecdsa::SigningKey,
    cert: Vec<u8>,
}

impl SealKeys for Keys {
    fn identity(&self, _: Instant) -> Result<SealIdentity, SealKeyError> {
        Ok(SealIdentity {
            algorithm: SealAlgorithm::EcdsaP256Sha256,
            signer_certificate: self.cert.clone(),
            chain: Vec::new(),
        })
    }

    fn sign_prehash(
        &self,
        _: &str,
        digest: &[u8; 32],
        _: Instant,
    ) -> Result<Vec<u8>, SealKeyError> {
        let signature: p256::ecdsa::Signature =
            self.key.sign_prehash(digest).map_err(|err| SealKeyError {
                detail: err.to_string(),
                retryable: false,
            })?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// The real sealer, whose verifier reports a failed content digest.
struct RejectVerify<'a>(&'a dyn EsignSealer);

impl EsignSealer for RejectVerify<'_> {
    fn seal(
        &self,
        pdf: &[u8],
        request: &EsignSealRequest,
    ) -> Result<EsignSealed, EsignSealerError> {
        self.0.seal(pdf, request)
    }

    fn verify(&self, pdf: &[u8]) -> Result<EsignVerdict, EsignSealerError> {
        let mut verdict = self.0.verify(pdf)?;
        verdict.verdict = SealVerdict::Failed;
        verdict.reasons.push("digest_mismatch".to_owned());
        verdict.self_verify_ok = false;
        Ok(verdict)
    }
}

/// A synthetic P-256 key and its self-signed certificate.
fn synthetic_keys() -> std::result::Result<(Keys, Vec<u8>), Box<dyn std::error::Error>> {
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let cert = params.self_signed(&key)?.der().to_vec();
    let keys = Keys {
        key: p256::ecdsa::SigningKey::from_pkcs8_der(&key.serialize_der())?,
        cert: cert.clone(),
    };
    Ok((keys, cert))
}

fn unix_seconds_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[test]
fn seal_organ_verifies_before_atomic_terminal_and_retries_from_pristine_original()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (keys, cert) = synthetic_keys()?;
    let host = OrganHost::new(HostConfig::default());
    host.install(seal_spec(ORGAN, FetchGrant::default()));
    let dir = tempfile::tempdir()?;
    let now = unix_seconds_now();
    let clock = oneiron::store::ports::ManualClock::new(now);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    let sealer = HostedSealer::new(&host, &vault, &keys, SealSettings::new(vec![cert], "seal"));
    let at = TimeRange {
        start: now,
        end: now,
    };
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        oneiron::registry::ENTITY_TYPE_PERSON,
        at,
        now,
        b"owner",
    )?;
    // The artifact actor is a MACHINE: it signs with a host-held key, so the
    // vault is host-rooted and its owner holds a human binding (ONE-1634).
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &oneiron::blob_artifact::BlobArtifactBody::new("original.pdf", "application/pdf"),
        at,
        now,
    )?;
    vault.append_blob_artifact_version(
        &id,
        ORIGINAL,
        &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
        oneiron::write_envelope::WriteActor::new(owner, oneiron::edge::EdgeActorClass::Human),
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
        oneiron::store::GateDecisionId::now(),
    )?;
    let capabilities = vault.issue_esign_capabilities(&owner_auth, id)?;
    let canonical_url = format!(
        "https://example.test/sign#{}",
        capabilities[0].1.expose_for_delivery()
    );
    oneiron::test_support::mark_esign_sent(&vault, id, actor, now)?;
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
            now: unix_seconds_now(),
        },
    )?
    else {
        panic!("seal job missing")
    };
    let url = canonical_url.as_str();
    assert!(matches!(
        vault.seal_esign_attempt(
            &attempt,
            &RejectVerify(&sealer),
            SealProfile::BaselineB,
            url
        ),
        Err(EsignSealError::Verification)
    ));
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Pending);
    assert!(vault.sealed_esign_document(id)?.is_none());
    // The document deadline does not erase the committed signature while a
    // delayed/retried seal still owns the derived completion outcome.
    assert_eq!(vault.sweep_esign_expiry(&[id], now + 3600)?, 0);
    assert!(vault.esign_document(id)?.ready_to_seal());
    let sealed = vault.seal_esign_attempt(&attempt, &sealer, SealProfile::BaselineB, url)?;
    assert_eq!(
        EntityId::from_hex(&sealed.items[0].sealed_artifact)?.as_bytes()[0],
        0x71
    );
    assert_eq!(vault.esign_document(id)?.status, DocumentStatus::Completed);
    assert!(vault.verify_esign_item(id, 0, &sealer)?.valid());
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
        Some(ORIGINAL)
    );
    assert_eq!(
        vault.seal_esign_attempt(&attempt, &sealer, SealProfile::BaselineB, url)?,
        sealed
    );
    let owner = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        oneiron::store::GateDecisionId::now(),
    )?;
    assert!(
        vault
            .request_esign_reseal(&owner, id, "not-a-grant", None, None)
            .is_err()
    );
    let bound = oneiron::consent::GrantBound::action(
        oneiron::consent::ActorBound::new(owner.actor().to_hex())?,
        oneiron::consent::ActionClass::new("esign.reseal")?,
        oneiron::consent::ActionEnvelope::new([format!("document:{}", id.to_hex())])?,
    )?;
    let grant_ref = bound.digest().to_hex();
    vault.create_standing_grant(&owner, bound)?;
    vault.request_esign_reseal(&owner, id, &grant_ref, None, None)?;
    let ClaimOutcome::Claimed(reseal) = queue.claim_kind(
        ESIGN_SEAL_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "reseal-test".into(),
            now: unix_seconds_now(),
        },
    )?
    else {
        panic!("reseal job missing")
    };
    let resealed = vault.seal_esign_attempt(&reseal, &sealer, SealProfile::BaselineB, url)?;
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
        vault.seal_esign_attempt(&reseal, &sealer, SealProfile::BaselineB, url)?,
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
            "scope":oneiron::test_support::effect_preset(),"selectors":{"channel":"email"}}]
    });
    oneiron::test_support::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &rmp_serde::to_vec_named(&mail_policy)?,
    )?;
    let outgoing = |notice: &EsignNotice, key: &str| {
        oneiron::outbound::OutboundDispatchRequest::new(
            format!("receipt:{key}"),
            key,
            oneiron::outbound::OutboundIntent::from_trigger(
                oneiron::outbound::OutboundIntentDraft::new(
                    owner.actor().to_hex(),
                    "send",
                    "email",
                    notice.email.clone(),
                ),
                oneiron::outbound::OutboundIntentTrigger::record_transition(
                    notice.event_ref.clone().unwrap(),
                ),
            ),
            oneiron::outbound::OutboundDispatchActor {
                actor_class: "human".into(),
                actor_ref: Some(owner.actor().to_hex()),
                actor_entity_ref: Some(owner.actor()),
            },
            oneiron::outbound::OutboundDispatchGate::allow_when_policy_grants(),
            unix_seconds_now(),
            oneiron::outbound::OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    let (old_attempt, old_notice) = vault
        .claim_esign_notice("sealed-mail", unix_seconds_now())?
        .expect("original completion staged");
    assert!(
        vault
            .dispatch_esign_notice(&old_attempt, outgoing(&old_notice, "stale-completion"))
            .is_err()
    );
    let (new_attempt, new_notice) = vault
        .claim_esign_notice("sealed-mail", unix_seconds_now())?
        .expect("resealed completion staged");
    let delivered =
        vault.dispatch_esign_notice(&new_attempt, outgoing(&new_notice, "resealed-completion"))?;
    assert_eq!(
        delivered.outcome,
        oneiron::outbound::OutboundDispatchOutcome::DeliveredToChannel
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
    assert!(vault.verify_esign_item(id, 0, &sealer)?.valid());
    assert_eq!(
        vault.read_blob_artifact_version(&id, 1)?.as_deref(),
        Some(ORIGINAL)
    );
    let audit = vault.esign_audit(id)?;
    let canonical = vault.esign_pdf_for_capability(&capabilities[0].1, 0, None, None)?;
    assert!(
        vault.delete_entity_with_options(
            &id,
            oneiron::deletion::DeleteEntityOptions { purge: true }
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
    drop(sealer);
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

#[test]
fn a_tsa_url_with_a_query_is_refused_before_the_organ_starts()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (keys, cert) = synthetic_keys()?;
    let host = OrganHost::new(HostConfig::default());
    host.install(seal_spec(ORGAN, FetchGrant::default()));
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let mut settings = SealSettings::new(vec![cert], "seal");
    // The URL would cross to the organ, and a query may carry a key.
    settings.timestamp_authorities = vec![SealTsa {
        url: "https://tsa.example/timestamp?api_key=placeholder".to_owned(),
        policy_oid: None,
    }];
    let sealer = HostedSealer::new(&host, &vault, &keys, settings);
    let request = EsignSealRequest {
        operation_id: "op".to_owned(),
        profile: SealProfile::BaselineT,
    };
    let refused = sealer.seal(ORIGINAL, &request);
    assert!(
        matches!(&refused, Err(EsignSealerError::Fatal { code, .. }) if code == "invalid_configuration"),
        "{refused:?}"
    );
    assert_eq!(host.status("seal").map(|status| status.spawns), Some(0));
    Ok(())
}

/// A 100 KB PDF whose 1,024 signature fields all name one 64 KiB string,
/// so its full verification report is over 64 MiB.
fn many_long_named_fields() -> Vec<u8> {
    let name = "A".repeat(64 * 1024);
    let fields = "<< /FT /Sig /T 7 0 R /V 6 0 R >> ".repeat(1024);
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>".to_owned(),
        "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
        format!("<< /Fields [{fields}] >>"),
        "<< /Type /Sig /SubFilter /ETSI.CAdES.detached /ByteRange [0 0 0 0] /Contents <> >>"
            .to_owned(),
        format!("({name})"),
    ];
    let mut pdf = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (n, body) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", n + 1).as_bytes());
    }
    let xref = pdf.len();
    let size = objects.len() + 1;
    pdf.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f \n").as_bytes());
    for offset in offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    pdf
}

#[test]
fn a_verdict_whose_report_is_too_large_still_crosses()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (keys, cert) = synthetic_keys()?;
    let host = OrganHost::new(HostConfig::default());
    host.install(seal_spec(ORGAN, FetchGrant::default()));
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let sealer = HostedSealer::new(&host, &vault, &keys, SealSettings::new(vec![cert], "seal"));
    let verdict = sealer.verify(&many_long_named_fields())?;
    assert_eq!(verdict.verdict, SealVerdict::Failed);
    let report: serde_json::Value = serde_json::from_slice(&verdict.report_json)?;
    assert_eq!(report["omitted_over_bytes"], MAX_REPORT_JSON_BYTES);
    Ok(())
}
