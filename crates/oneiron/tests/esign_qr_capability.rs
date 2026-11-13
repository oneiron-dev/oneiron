#![cfg(oneiron_test_support)]
//! The QR capability a sealed certificate prints (ARCH-0064a section 6 "QR
//! capability-URL", [SGN-05]; FIX [ESIGN-QR-CAPABILITY-PAGE]): the seal
//! prints the QR page with a fresh 256-bit capability as its fragment; the
//! page that capability opens shows the seal's metadata and hashes, never an
//! email or the token; an unknown, foreign, expired or revoked capability
//! gets one refusal; the owner sets its expiry or revokes it; and it opens
//! no PDF door, which only a party's own signing link reads, unless the
//! vault owner turns on the document's QR PDF download (`qr_pdf_download`,
//! RULING ESIGN-QR-POSSESSION-FACTOR B).

use std::sync::{Arc, Mutex, PoisonError};

use oneiron::blob_artifact::esign::{
    DocumentKind, EsignAuditActor, EsignCapability, EsignCreateRequest, EsignDocument, EsignItem,
    EsignQrCapability, EsignQrOutcome, EsignQrSigner, EsignRecipient, EsignSealError,
    EsignSealProducer, EsignSealRequest, EsignSealRun, EsignSealed, EsignSealer, EsignSealerError,
    EsignVerdict, RecipientRole, SealActiveContentFacts, SealProfile, SealVerdict, SigningAction,
    SigningOutcome, render,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::ports::ManualClock;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use sha2::{Digest, Sha256};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The QR page the host names; the seal adds the capability.
const QR_PAGE: &str = "https://example.test/esign/verify";

fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Seals the original back as its own output, and keeps the certificate URL
/// each preparation printed.
#[derive(Default)]
struct CapturingSealer {
    printed: Mutex<Vec<String>>,
}

impl CapturingSealer {
    fn verdict() -> EsignVerdict {
        EsignVerdict {
            verdict: SealVerdict::Passed,
            reasons: Vec::new(),
            achieved: Some(SealProfile::BaselineB),
            self_verify_ok: true,
            report_json: Vec::new(),
            active_content: SealActiveContentFacts::default(),
        }
    }

    fn printed(&self) -> Vec<String> {
        self.printed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl EsignSealer for CapturingSealer {
    fn seal(
        &self,
        _request: &EsignSealRequest,
        _producer: &mut dyn EsignSealProducer,
    ) -> std::result::Result<EsignSealed, EsignSealError> {
        let bytes = original_pdf().to_vec();
        let evidence_sha256: [u8; 32] = Sha256::digest(&bytes).into();
        Ok(EsignSealed {
            bytes,
            evidence_sha256,
            requested: SealProfile::BaselineB,
            achieved: SealProfile::BaselineB,
            degraded: Vec::new(),
            self_verify: Self::verdict(),
        })
    }

    fn verify(&self, _pdf: &[u8]) -> std::result::Result<EsignVerdict, EsignSealerError> {
        Ok(Self::verdict())
    }

    fn prepare_esign_pdf(
        &self,
        _original: &[u8],
        request: &render::PdfPreparation<'_>,
        _chain: [u8; 32],
        _trail: &[String],
    ) -> std::result::Result<Option<render::PreparedEsignPdf>, EsignSealerError> {
        self.printed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request.canonical_url.to_owned());
        Ok(None)
    }
}

/// A host-rooted vault whose one-approver document was approved and sealed
/// through [`CapturingSealer`].
struct Sealed {
    vault: Vault,
    clock: Arc<ManualClock>,
    owner: AuthenticatedOwner,
    id: EntityId,
    /// The approver's signing capability.
    signing: EsignCapability,
    /// The certificate URL the seal printed.
    printed: String,
    now: u64,
    _dir: tempfile::TempDir,
}

/// How the fixture drafts its document.
#[derive(Clone, Copy)]
enum Draft {
    /// The vault's own create door, as every QR test before the switch.
    Vault,
    /// `vault.esign.create` as the vault owner, with this QR PDF download.
    OwnerVerb { qr_pdf_download: bool },
}

/// The one-approver, one-item draft on `artifact`.
fn agreement(artifact: EntityId, now: u64) -> EsignDocument {
    EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: false,
        expires_at: now + 3600,
        token_expires_at: None,
        items: vec![EsignItem {
            artifact_ref: artifact.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: EntityId::now().to_hex(),
            email: "owen@example.com".into(),
            name: "Owen".into(),
            role: RecipientRole::Approver,
            order: 0,
            expires_at: now + 3600,
            principal_ref: None,
            automated: false,
            natural_person: None,
        }],
        fields: vec![],
        full_trail_appendix: true,
        lifecycle: None,
        project: None,
        commitments: Vec::new(),
    }
}

fn sealed() -> TestResult<Sealed> {
    sealed_with(Draft::Vault)
}

fn sealed_with(draft: Draft) -> TestResult<Sealed> {
    let dir = tempfile::tempdir()?;
    let now = 1_800_000_000;
    let clock = ManualClock::new(now);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let at = TimeRange {
        start: now,
        end: now,
    };
    let person = vault.ensure_embedded_owner_actor()?;
    vault.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        at,
        now,
        b"owner",
    )?;
    // The artifact actor is a MACHINE: it signs with a host-held key, so the
    // vault is host-rooted and its owner holds a human binding (ONE-1634).
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, person)?;
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &oneiron::blob_artifact::BlobArtifactBody::new("agreement.pdf", "application/pdf"),
        at,
        now,
    )?;
    vault.append_blob_artifact_version(
        &id,
        original_pdf(),
        &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
        oneiron::write_envelope::WriteActor::new(person, oneiron::edge::EdgeActorClass::Human),
        at,
        now,
    )?;
    let document = agreement(id, now);
    let actor = EsignAuditActor {
        actor: person.to_hex(),
        ip: None,
        user_agent: None,
    };
    match draft {
        Draft::Vault => vault.create_esign_document(id, &document, actor.clone(), now)?,
        Draft::OwnerVerb { qr_pdf_download } => {
            vault
                .memory(person, EdgeActorClass::Human)
                .esign_create(&EsignCreateRequest {
                    document_ref: id.to_hex(),
                    draft: document,
                    qr_pdf_download,
                })?;
        }
    }
    let owner = vault.authenticate_owner(
        person,
        &person.to_hex(),
        true,
        oneiron::store::GateDecisionId::now(),
    )?;
    let signing = vault
        .issue_esign_capabilities(&owner, id)?
        .into_iter()
        .next()
        .ok_or("no signing capability")?
        .1;
    oneiron::test_support::mark_esign_sent(&vault, id, actor, now)?;
    assert_eq!(
        vault.execute_signing_action(
            &signing,
            &SigningAction::Complete {
                consent: true,
                next: None
            },
            None,
            None,
        )?,
        SigningOutcome::AwaitingSeal
    );
    let sealer = CapturingSealer::default();
    let runs = vault.run_esign_seals(
        &sealer,
        SealProfile::BaselineB,
        QR_PAGE,
        "test-seal-worker",
        1,
    )?;
    match runs.as_slice() {
        [EsignSealRun::Sealed { document }] => assert_eq!(*document, Some(id)),
        other => panic!("the seal must land once: {other:?}"),
    }
    let printed = match sealer.printed().as_slice() {
        [one] => one.clone(),
        other => panic!("one item prints one certificate URL: {other:?}"),
    };
    Ok(Sealed {
        vault,
        clock,
        owner,
        id,
        signing,
        printed,
        now,
        _dir: dir,
    })
}

/// The capability the certificate printed, from its URL's fragment.
fn printed_capability(printed: &str) -> TestResult<(String, EsignQrCapability)> {
    let fragment = printed
        .strip_prefix(&format!("{QR_PAGE}#"))
        .unwrap_or_else(|| {
            panic!("the certificate names the QR page with a capability: {printed}")
        });
    assert_eq!(fragment.len(), 64, "256 bits as lower hex");
    assert!(
        fragment
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "lower hex: {fragment}"
    );
    Ok((fragment.to_owned(), EsignQrCapability::parse(fragment)?))
}

/// The QR page shows what the seal proved: the document's metadata, who
/// signed and when, each item's sealed version and hash and the seal's
/// profile evidence, and never the approver's email or the capability. A
/// capability no seal printed, and the approver's own signing capability,
/// get the one refusal.
#[test]
fn a_sealed_certificate_prints_a_qr_capability_whose_page_shows_only_the_seal_evidence()
-> TestResult {
    let sealed = sealed()?;
    let (fragment, token) = printed_capability(&sealed.printed)?;
    let manifest = sealed
        .vault
        .sealed_esign_document(sealed.id)?
        .ok_or("the sealed manifest")?;
    let page = sealed.vault.esign_qr_page(&token)?;
    assert_eq!(page.document_ref, sealed.id.to_hex());
    assert_eq!(page.title, "Agreement");
    assert_eq!(page.outcome, EsignQrOutcome::Completed);
    assert_eq!(page.sealed_at, sealed.now);
    assert_eq!(page.audit_chain_sha256, hex(&manifest.audit_chain_sha256));
    assert_eq!(
        page.signers,
        vec![EsignQrSigner {
            name: "Owen".into(),
            role: RecipientRole::Approver,
            signed_at: sealed.now,
        }]
    );
    assert_eq!(page.items.len(), 1);
    let item = &page.items[0];
    assert_eq!(item.item, 0);
    assert_eq!(item.sealed_artifact, manifest.items[0].sealed_artifact);
    assert_eq!(item.sealed_version, manifest.items[0].sealed_version);
    assert_eq!(item.sha256, hex(&manifest.items[0].sha256));
    assert_eq!(item.profile, manifest.items[0].profile);
    assert_eq!(item.profile.achieved, SealProfile::BaselineB);
    assert_eq!(item.self_verify, SealVerdict::Passed);
    let json = serde_json::to_string(&page)?;
    assert!(!json.contains("owen@example.com"), "no email: {json}");
    assert!(!json.contains(&fragment), "no capability: {json}");

    let unknown = sealed
        .vault
        .esign_qr_page(&EsignQrCapability::parse(&"ab".repeat(32))?)
        .expect_err("a capability no seal printed is refused")
        .to_string();
    let foreign = sealed
        .vault
        .esign_qr_page(&EsignQrCapability::parse(
            sealed.signing.expose_for_delivery(),
        )?)
        .expect_err("a signing capability opens no QR page")
        .to_string();
    assert_eq!(foreign, unknown, "one refusal");
    let malformed = EsignQrCapability::parse("not-a-capability")
        .expect_err("a malformed capability is refused")
        .to_string();
    assert_eq!(malformed, unknown, "one refusal");
    Ok(())
}

/// The owner's expiry closes the page at its time and can be lifted; a
/// revoke closes it for good, whatever expiry comes after. Each closed
/// page answers the same refusal as an unknown capability.
#[test]
fn the_owner_expires_and_revokes_a_documents_qr_capability() -> TestResult {
    let sealed = sealed()?;
    let (_, token) = printed_capability(&sealed.printed)?;
    let vault = &sealed.vault;
    let unknown = vault
        .esign_qr_page(&EsignQrCapability::parse(&"cd".repeat(32))?)
        .expect_err("a capability no seal printed is refused")
        .to_string();

    assert_eq!(
        vault.set_esign_qr_capability_expiry(&sealed.owner, sealed.id, Some(sealed.now + 100))?,
        1
    );
    vault.esign_qr_page(&token)?;
    sealed.clock.set(sealed.now + 100);
    let expired = vault
        .esign_qr_page(&token)
        .expect_err("no read at its expiry")
        .to_string();
    assert_eq!(expired, unknown, "one refusal");
    assert_eq!(
        vault.set_esign_qr_capability_expiry(&sealed.owner, sealed.id, None)?,
        1
    );
    vault.esign_qr_page(&token)?;

    assert_eq!(
        vault.revoke_esign_qr_capabilities(&sealed.owner, sealed.id)?,
        1
    );
    let revoked = vault
        .esign_qr_page(&token)
        .expect_err("a revoked capability is refused")
        .to_string();
    assert_eq!(revoked, unknown, "one refusal");
    assert_eq!(
        vault.revoke_esign_qr_capabilities(&sealed.owner, sealed.id)?,
        0,
        "a revoked capability keeps its first revocation"
    );
    assert_eq!(
        vault.set_esign_qr_capability_expiry(&sealed.owner, sealed.id, None)?,
        0,
        "an expiry change leaves a revoked capability revoked"
    );
    assert!(vault.esign_qr_page(&token).is_err());
    Ok(())
}

/// The QR capability is no possession factor (ARCH-0064a section 6: the
/// PDF sits behind a separate one): it has the signing capability's form,
/// so it reaches the signing doors' parser, and every door that reads the
/// PDF or loads the signing page refuses it. The party's own signing link
/// still reads the sealed copy after the seal: that is the factor.
#[test]
fn a_qr_capability_opens_no_pdf_door_and_the_signing_link_reads_the_sealed_copy() -> TestResult {
    let sealed = sealed()?;
    let (fragment, _) = printed_capability(&sealed.printed)?;
    let vault = &sealed.vault;
    let manifest = vault
        .sealed_esign_document(sealed.id)?
        .ok_or("the sealed manifest")?;
    let as_signing = EsignCapability::parse(&fragment)?;
    assert!(
        vault
            .esign_pdf_for_capability(&as_signing, 0, None, None)
            .is_err(),
        "a QR capability reads no PDF"
    );
    assert!(
        vault
            .esign_preview_for_capability(&as_signing, 0, None, None)
            .is_err(),
        "a QR capability opens no preview"
    );
    assert!(
        vault
            .execute_signing_action(&as_signing, &SigningAction::Load, None, None)
            .is_err(),
        "a QR capability loads no signing page"
    );

    let copy = vault.esign_pdf_for_capability(&sealed.signing, 0, None, None)?;
    assert_eq!(
        hex(&Sha256::digest(&copy)),
        hex(&manifest.items[0].sha256),
        "the signing link reads the sealed, hash-checked copy"
    );
    Ok(())
}

/// RULING ESIGN-QR-POSSESSION-FACTOR B: every envelope is sensitive until
/// the vault owner turns on its QR PDF download. Off, a usable QR capability
/// reads no PDF and its page says so; on, it reads the hash-checked sealed
/// PDF it was printed in, the same bytes the signing link reads. The switch
/// is read live, and a revoked capability reads nothing whatever it says.
/// Each closed read answers the one refusal.
#[test]
fn the_owner_turns_a_documents_qr_pdf_download_on_and_off() -> TestResult {
    let sealed = sealed()?;
    let (_, token) = printed_capability(&sealed.printed)?;
    let vault = &sealed.vault;
    let manifest = vault
        .sealed_esign_document(sealed.id)?
        .ok_or("the sealed manifest")?;
    let unknown = vault
        .esign_qr_page(&EsignQrCapability::parse(&"ef".repeat(32))?)
        .expect_err("a capability no seal printed is refused")
        .to_string();

    assert!(!vault.esign_qr_page(&token)?.pdf_download, "off by default");
    let off = vault
        .esign_qr_sealed_pdf(&token, 0)
        .expect_err("a QR capability reads no PDF while the download is off")
        .to_string();
    assert_eq!(off, unknown, "one refusal");

    assert!(
        !vault.set_esign_qr_pdf_download(&sealed.owner, sealed.id, true)?,
        "it was off"
    );
    assert!(vault.esign_qr_page(&token)?.pdf_download);
    let copy = vault.esign_qr_sealed_pdf(&token, 0)?;
    assert_eq!(
        hex(&Sha256::digest(&copy)),
        hex(&manifest.items[0].sha256),
        "the QR reads the sealed, hash-checked copy"
    );
    assert_eq!(
        copy,
        vault.esign_pdf_for_capability(&sealed.signing, 0, None, None)?,
        "the same bytes the signing link reads"
    );
    let missing = vault
        .esign_qr_sealed_pdf(&token, 1)
        .expect_err("an item the seal did not print is refused")
        .to_string();
    assert_eq!(missing, unknown, "one refusal");
    let stranger = vault
        .esign_qr_sealed_pdf(&EsignQrCapability::parse(&"ef".repeat(32))?, 0)
        .expect_err("a capability no seal printed reads no PDF")
        .to_string();
    assert_eq!(stranger, unknown, "one refusal");

    assert!(
        vault.set_esign_qr_pdf_download(&sealed.owner, sealed.id, false)?,
        "it was on"
    );
    assert!(!vault.esign_qr_page(&token)?.pdf_download);
    let closed = vault
        .esign_qr_sealed_pdf(&token, 0)
        .expect_err("turning the download off closes the next read")
        .to_string();
    assert_eq!(closed, unknown, "one refusal");

    vault.set_esign_qr_pdf_download(&sealed.owner, sealed.id, true)?;
    vault.revoke_esign_qr_capabilities(&sealed.owner, sealed.id)?;
    let revoked = vault
        .esign_qr_sealed_pdf(&token, 0)
        .expect_err("a revoked capability reads no PDF")
        .to_string();
    assert_eq!(revoked, unknown, "one refusal");
    assert!(
        vault
            .set_esign_qr_pdf_download(&sealed.owner, EntityId::now(), true)
            .is_err(),
        "no switch for a document never drafted"
    );
    Ok(())
}

/// The switch at drafting: the vault owner drafting through
/// `vault.esign.create` with `qr_pdf_download` gets a QR that downloads the
/// sealed PDF; an agent asking for it is refused before anything lands.
#[test]
fn only_the_owner_drafts_a_document_with_its_qr_pdf_download_on() -> TestResult {
    let sealed = sealed_with(Draft::OwnerVerb {
        qr_pdf_download: true,
    })?;
    let (_, token) = printed_capability(&sealed.printed)?;
    let vault = &sealed.vault;
    let manifest = vault
        .sealed_esign_document(sealed.id)?
        .ok_or("the sealed manifest")?;
    assert!(vault.esign_qr_page(&token)?.pdf_download);
    assert_eq!(
        hex(&Sha256::digest(&vault.esign_qr_sealed_pdf(&token, 0)?)),
        hex(&manifest.items[0].sha256)
    );

    let other = EntityId::now();
    let refused = vault
        .memory(EntityId::now(), EdgeActorClass::Agent)
        .esign_create(&EsignCreateRequest {
            document_ref: other.to_hex(),
            draft: agreement(sealed.id, sealed.now),
            qr_pdf_download: true,
        })
        .expect_err("only the vault owner turns the QR PDF download on");
    assert!(
        refused.to_string().contains("only the vault owner"),
        "the refusal names the owner: {refused}"
    );
    assert!(vault.esign_audit(other)?.is_empty(), "nothing was drafted");

    let default_off = sealed_with(Draft::OwnerVerb {
        qr_pdf_download: false,
    })?;
    let (_, token) = printed_capability(&default_off.printed)?;
    assert!(!default_off.vault.esign_qr_page(&token)?.pdf_download);
    assert!(default_off.vault.esign_qr_sealed_pdf(&token, 0).is_err());
    Ok(())
}
