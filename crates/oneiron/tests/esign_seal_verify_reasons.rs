#![cfg(oneiron_test_support)]

use oneiron::blob_artifact::esign::{
    DocumentKind, ESIGN_SEAL_ATTEMPT_KIND, EsignAuditActor, EsignDocument, EsignEvent,
    EsignField, EsignItem, EsignRecipient, EsignSealError, EsignSealGetRequest,
    EsignSealProducer, EsignSealRequest, EsignSealRun, EsignSealed, EsignSealer,
    EsignSealerError, EsignState, EsignVerdict, FieldGeometry, FieldMeta, RecipientRole,
    SealActiveContentFacts, SealProfile, SealVerdict, render,
};
use oneiron::test_doors::esign_seal_verify_reasons::append_event;
use oneiron::{EntityId, Result, TimeRange, Vault, VaultConfig};

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
        token_expires_at: None,
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
                natural_person: None,
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
        project: None,
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
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    // The artifact actor is a MACHINE: it signs with a host-held key, so the
    // vault is host-rooted and its owner verbs need a human binding (ONE-1634).
    oneiron::test_support::provision_engine_machines(&vault);
    let artifact = EntityId::now();
    vault.put_blob_artifact(
        &artifact,
        &oneiron::blob_artifact::BlobArtifactBody::new("agreement.pdf", "application/pdf"),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    vault.append_blob_artifact_version(
        &artifact,
        original_pdf(),
        &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
        oneiron::write_envelope::WriteActor::new(person, oneiron::edge::EdgeActorClass::Human),
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

fn event(vault: &Vault, id: EntityId, event: EsignEvent, at: u64) -> Result<EsignState> {
    append_event(vault, id, event, actor(), at)
}

/// A failed self-verification keeps the same summary on the run and the
/// door, every native code in order, and seals nothing: a sealer
/// `VerifyFailed` with ordered codes including
/// `validation_material_possible_tampering`, and a no-code coherence
/// rejection with empty reasons.
#[test]
fn failed_verification_keeps_same_summary_and_ordered_verify_reasons_without_canonical_output()
-> Result<()> {
    use sha2::{Digest, Sha256};

    enum SealFailureMode {
        VerifyFailed { reasons: Vec<String> },
        CoherenceEmpty,
    }

    struct FailingSealer {
        mode: SealFailureMode,
        profile: SealProfile,
    }

    impl FailingSealer {
        fn passing_verdict(&self) -> EsignVerdict {
            EsignVerdict {
                verdict: SealVerdict::Passed,
                reasons: Vec::new(),
                achieved: Some(self.profile),
                self_verify_ok: true,
                report_json: Vec::new(),
                active_content: SealActiveContentFacts::default(),
            }
        }

        fn indeterminate_verdict(&self, reasons: Vec<String>) -> EsignVerdict {
            EsignVerdict {
                verdict: SealVerdict::Indeterminate,
                reasons,
                achieved: None,
                self_verify_ok: false,
                report_json: Vec::new(),
                active_content: SealActiveContentFacts::default(),
            }
        }

        fn sealed(&self, self_verify: EsignVerdict) -> EsignSealed {
            let bytes = b"failing-seal".to_vec();
            let evidence_sha256: [u8; 32] = Sha256::digest(&bytes).into();
            EsignSealed {
                bytes,
                evidence_sha256,
                requested: SealProfile::BaselineT,
                achieved: self.profile,
                degraded: Vec::new(),
                self_verify,
            }
        }
    }

    impl EsignSealer for FailingSealer {
        fn seal(
            &self,
            _request: &EsignSealRequest,
            _producer: &mut dyn EsignSealProducer,
        ) -> std::result::Result<EsignSealed, EsignSealError> {
            match &self.mode {
                SealFailureMode::VerifyFailed { reasons } => Err(EsignSealerError::VerifyFailed {
                    verdict: Box::new(self.indeterminate_verdict(reasons.clone())),
                }
                .into()),
                SealFailureMode::CoherenceEmpty => Ok(self.sealed(self.passing_verdict())),
            }
        }

        fn verify(&self, _pdf: &[u8]) -> std::result::Result<EsignVerdict, EsignSealerError> {
            Ok(self.passing_verdict())
        }

        fn prepare_esign_pdf(
            &self,
            _original: &[u8],
            _request: &render::PdfPreparation<'_>,
            _chain: [u8; 32],
            _trail: &[String],
        ) -> std::result::Result<Option<render::PreparedEsignPdf>, EsignSealerError> {
            Ok(None)
        }
    }

    let ordered = vec![
        "validation_material_unavailable".to_owned(),
        "validation_material_possible_tampering".to_owned(),
        "trust_root_unavailable".to_owned(),
    ];
    let cases: Vec<(&str, SealFailureMode, Vec<String>, &str)> = vec![
        (
            "verify_failed_with_codes",
            SealFailureMode::VerifyFailed {
                reasons: ordered.clone(),
            },
            ordered.clone(),
            "the sealed PDF failed its own verification",
        ),
        (
            "coherence_empty",
            SealFailureMode::CoherenceEmpty,
            Vec::new(),
            "sealed PDF failed post-seal verification",
        ),
    ];

    for (name, mode, expected_reasons, expected_summary) in cases {
        let (_dir, vault, id, mut doc) = setup()?;
        doc.fields.clear();
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
        event(
            &vault,
            id,
            EsignEvent::Declined {
                recipient: first,
                reason: "declined".into(),
            },
            6,
        )?;
        assert!(vault.esign_document(id)?.ready_to_seal(), "{name}");
        assert_eq!(vault.sweep_esign_seals(&[id], 906)?, 1, "{name}");
        let sealer = FailingSealer {
            mode,
            profile: SealProfile::BaselineB,
        };
        let runs = vault.run_esign_seals(
            &sealer,
            SealProfile::BaselineB,
            "https://example.test/sign",
            "test-seal-worker",
            1,
        )?;
        assert_eq!(runs.len(), 1, "{name}");
        let reason = match &runs[0] {
            EsignSealRun::Failed { document, reason } => {
                assert_eq!(*document, Some(id), "{name}");
                reason.clone()
            }
            EsignSealRun::Sealed { .. } => panic!("{name}: the seal must fail"),
        };
        assert_eq!(reason, expected_summary, "{name}");
        let reader = EntityId::now();
        vault.put_entity(
            &reader,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"reader",
        )?;
        let view = vault
            .memory(reader, oneiron::edge::EdgeActorClass::Human)
            .esign_seal_get(&EsignSealGetRequest {
                document_ref: id.to_hex(),
            })
            .unwrap_or_else(|error| panic!("{name}: esign_seal_get failed: {error:?}"));
        assert_eq!(view.document_ref, id.to_hex(), "{name}");
        assert_eq!(view.attempts.len(), 1, "{name}");
        let attempt = &view.attempts[0];
        assert_eq!(attempt.kind, ESIGN_SEAL_ATTEMPT_KIND, "{name}");
        assert_eq!(attempt.state, "failed", "{name}");
        assert_eq!(
            attempt.last_error.as_deref(),
            Some(expected_summary),
            "{name}"
        );
        assert_eq!(
            reason,
            attempt.last_error.as_deref().unwrap(),
            "{name}: the run and the door keep the same summary"
        );
        assert_eq!(
            attempt.verify_reasons, expected_reasons,
            "{name}: every verify_reasons in order"
        );
        assert!(view.sealed.is_none(), "{name}: no canonical output");
        assert!(
            vault.sealed_esign_document(id)?.is_none(),
            "{name}: no canonical output"
        );
    }
    Ok(())
}
