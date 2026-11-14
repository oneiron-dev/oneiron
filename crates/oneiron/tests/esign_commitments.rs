#![cfg(oneiron_test_support)]

//! `ESIGN-COMMITMENTS` (ARCH-0064 §3, the OF-187 wire): a signed document
//! opens the commitments it names.
//!
//! A draft that names obligations mints each as an inert commitment bound to
//! the document; `esign.completed` opens each with the completion and the
//! sealed bytes as evidence; a decline, void or expiry releases them. The
//! events land through the ledger writer's test door, the one the seal tests
//! use, so no seal producer runs.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test esign_commitments`.

use oneiron::blob_artifact::esign::esign_seal_verify_reasons::append_event;
use oneiron::blob_artifact::esign::{
    DocumentKind, EsignAuditActor, EsignCommitmentTerm, EsignDocument, EsignEvent, EsignItem,
    EsignRecipient, EsignState, RecipientRole, SealProfile, SealProfileEvidence,
    esign_document_commitment_id,
};
use oneiron::commitment::{
    CommitmentBirthKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
    decode_commitment_claim,
};
use oneiron::memory::commitment_doors::{
    CommitmentContent, CommitmentObligor, CommitmentObligorKind, CommitmentSchedule,
};
use oneiron::test_doors::esign_commitments::commitment_status_evidence;
use oneiron::{EntityId, Result, TimeRange, Vault, VaultConfig};
use oneiron_store::blob_artifact::esign::model::{
    EsignAuthenticationMethod, EsignSigningEvidence, EsignSigningIntent,
};
use rmpv::Value;

/// The two obligations every fixture draft names, in draft order.
const OBLIGATIONS: [&str; 2] = ["Deliver the audit report", "Pay the first invoice"];

/// A live vault holding one drafted signing document that names
/// [`OBLIGATIONS`].
struct Fixture {
    /// The vault directory, held so the vault's files outlive the test.
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    /// The vault under test.
    vault: Vault,
    /// The signing document, drafted on its own PDF artifact.
    document: EntityId,
    /// The one signer.
    signer: String,
    /// Who owes each obligation.
    obligor: EntityId,
    /// Whom each obligation is owed to.
    beneficiary: EntityId,
}

fn actor() -> EsignAuditActor {
    EsignAuditActor {
        actor: "test-owner".into(),
        ip: Some("127.0.0.1".into()),
        user_agent: Some("test".into()),
    }
}

fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}

fn person(vault: &Vault, name: &[u8]) -> Result<EntityId> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        name,
    )?;
    Ok(id)
}

/// A one-signer, field-less draft on `artifact` that names [`OBLIGATIONS`].
fn draft(
    artifact: EntityId,
    signer: &str,
    obligor: EntityId,
    beneficiary: EntityId,
) -> EsignDocument {
    EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Statement of work".into(),
        sequential: false,
        expires_at: 1000,
        token_expires_at: None,
        items: vec![EsignItem {
            artifact_ref: artifact.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: signer.to_owned(),
            email: "signer@example.test".into(),
            name: "Signer".into(),
            role: RecipientRole::Signer,
            order: 0,
            expires_at: 1000,
            principal_ref: None,
            automated: false,
            natural_person: None,
        }],
        fields: Vec::new(),
        full_trail_appendix: true,
        lifecycle: None,
        project: None,
        commitments: OBLIGATIONS
            .iter()
            .map(|text| EsignCommitmentTerm {
                obligor: CommitmentObligor {
                    kind: CommitmentObligorKind::Owner,
                    entity_ref: obligor.to_hex(),
                },
                beneficiary: beneficiary.to_hex(),
                content: CommitmentContent {
                    text: (*text).to_owned(),
                    payload_ref: None,
                },
                schedule: CommitmentSchedule::Once { due: 5000 },
                lead_seconds: None,
            })
            .collect(),
    }
}

fn setup() -> Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = person(&vault, b"owner")?;
    oneiron::test_support::provision_engine_machines(&vault);
    let document = EntityId::now();
    vault.put_blob_artifact(
        &document,
        &oneiron::blob_artifact::BlobArtifactBody::new("sow.pdf", "application/pdf"),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    vault.append_blob_artifact_version(
        &document,
        original_pdf(),
        &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
        oneiron::write_envelope::WriteActor::new(owner, oneiron::edge::EdgeActorClass::Human),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let obligor = person(&vault, b"obligor")?;
    let beneficiary = person(&vault, b"beneficiary")?;
    let signer = EntityId::now().to_hex();
    vault.create_esign_document(
        document,
        &draft(document, &signer, obligor, beneficiary),
        actor(),
        2,
    )?;
    Ok(Fixture {
        dir,
        vault,
        document,
        signer,
        obligor,
        beneficiary,
    })
}

fn event(fixture: &Fixture, event: EsignEvent, at: u64) -> Result<EsignState> {
    append_event(&fixture.vault, fixture.document, event, actor(), at)
}

/// The commitment born from term `index`, read at the head of its status
/// chain.
fn commitment(fixture: &Fixture, index: u32) -> Result<(EntityId, CommitmentRecord)> {
    let id = esign_document_commitment_id(&fixture.document, index)?;
    let record = fixture
        .vault
        .get_commitment_claim(&id)?
        .unwrap_or_else(|| panic!("term {index} has a commitment at its derived id"));
    Ok((id, record))
}

fn field<'a>(map: &'a Value, key: &str) -> &'a Value {
    map.as_map()
        .and_then(|entries| entries.iter().find(|(k, _)| k.as_str() == Some(key)))
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("evidence carries `{key}`: {map:?}"))
}

/// The `esign` part of the evidence on commitment `id`'s current status.
fn esign_evidence(fixture: &Fixture, id: &EntityId) -> Result<Value> {
    let evidence = commitment_status_evidence(&fixture.vault, id)?
        .unwrap_or_else(|| panic!("the status change names its evidence"));
    Ok(field(&evidence, "esign").clone())
}

fn signing_evidence() -> EsignSigningEvidence {
    EsignSigningEvidence {
        authentication_method: EsignAuthenticationMethod::Person,
        disclosure_version: None,
        consent: true,
        intent: EsignSigningIntent::Direct,
        check_in: None,
    }
}

fn assert_released_by(fixture: &Fixture, predicate: &str) -> Result<()> {
    for index in 0..2 {
        let (id, record) = commitment(fixture, index)?;
        assert_eq!(
            record.status,
            CommitmentStatus::Released,
            "{predicate} releases term {index}"
        );
        let esign = esign_evidence(fixture, &id)?;
        assert_eq!(field(&esign, "event").as_str(), Some(predicate));
        assert_eq!(
            field(&esign, "document").as_str(),
            Some(fixture.document.to_hex().as_str())
        );
    }
    Ok(())
}

/// A draft that names two obligations gives two inert commitments, each
/// bound to the document by its derived id and its birth provenance.
#[test]
fn draft_with_two_obligations_mints_two_inert_commitments() -> Result<()> {
    let fixture = setup()?;
    for (index, text) in (0_u32..).zip(OBLIGATIONS) {
        let (_, record) = commitment(&fixture, index)?;
        assert_eq!(record.status, CommitmentStatus::Inert, "term {index}");
        assert_eq!(record.content.text, text);
        assert_eq!(record.strength, CommitmentStrength::Commitment);
        assert_eq!(record.obligor.entity_ref, fixture.obligor);
        assert_eq!(record.beneficiary, fixture.beneficiary);
        assert_eq!(
            record.birth_provenance.kind,
            CommitmentBirthKind::EsignDocument
        );
        assert_eq!(record.birth_provenance.reference, fixture.document.to_hex());
    }
    assert!(
        fixture
            .vault
            .get_commitment_claim(&esign_document_commitment_id(&fixture.document, 2)?)?
            .is_none(),
        "only the named terms are minted"
    );
    Ok(())
}

/// Sends the document and has its one signer view and sign it, leaving it
/// ready to seal.
fn sign(fixture: &Fixture) -> Result<EsignState> {
    event(fixture, EsignEvent::Sent, 4)?;
    event(
        fixture,
        EsignEvent::Viewed {
            recipient: fixture.signer.clone(),
        },
        5,
    )?;
    event(
        fixture,
        EsignEvent::Signed {
            recipient: fixture.signer.clone(),
            next: None,
            evidence: signing_evidence(),
            items: vec![EsignItem {
                artifact_ref: fixture.document.to_hex(),
                original_version: 1,
            }],
        },
        6,
    )
}

/// The sha256 the fixture's seal reports for the one sealed item.
const SEALED_SHA256: [u8; 32] = [7; 32];

/// Lands the verified seal: `esign.completed`.
fn seal(fixture: &Fixture) -> Result<EsignState> {
    event(
        fixture,
        EsignEvent::Sealed {
            rejected: false,
            item_sha256: vec![SEALED_SHA256],
            item_profiles: vec![SealProfileEvidence {
                requested: SealProfile::BaselineB,
                achieved: SealProfile::BaselineB,
                degraded: Vec::new(),
            }],
        },
        7,
    )
}

/// The texts of the open commitments among the obligor's claims whose birth
/// names the document, sorted: read through the generic claim reads.
fn open_commitments_named_by_the_document(fixture: &Fixture) -> Result<Vec<String>> {
    let mut texts = Vec::new();
    for id in fixture.vault.claims_for_subject(&fixture.obligor)? {
        let Some(body) = fixture.vault.get_claim(&id)? else {
            continue;
        };
        let Some(record) = decode_commitment_claim(&body)? else {
            continue;
        };
        if record.status == CommitmentStatus::Open
            && record.birth_provenance.reference == fixture.document.to_hex()
        {
            texts.push(record.content.text);
        }
    }
    texts.sort();
    Ok(texts)
}

/// `esign.completed` opens both commitments, each with the completion claim,
/// the document and the sealed bytes of each item as its evidence.
#[test]
fn completion_opens_each_commitment_with_the_sealed_version_as_evidence() -> Result<()> {
    let fixture = setup()?;
    assert!(sign(&fixture)?.ready_to_seal());
    for index in 0..2 {
        assert_eq!(
            commitment(&fixture, index)?.1.status,
            CommitmentStatus::Inert,
            "a signature short of completion opens nothing"
        );
    }
    seal(&fixture)?;
    for index in 0..2 {
        let (id, record) = commitment(&fixture, index)?;
        assert_eq!(
            record.status,
            CommitmentStatus::Open,
            "esign.completed opens term {index}"
        );
        let esign = esign_evidence(&fixture, &id)?;
        assert_eq!(field(&esign, "event").as_str(), Some("esign.completed"));
        assert_eq!(
            field(&esign, "document").as_str(),
            Some(fixture.document.to_hex().as_str())
        );
        let claim = EntityId::from_hex(field(&esign, "claim").as_str().expect("claim ref"))?;
        assert_eq!(
            fixture.vault.get_claim(&claim)?.map(|body| body.predicate),
            Some("esign.completed".to_owned()),
            "the evidence names the completion claim"
        );
        let items = field(&esign, "items").as_array().expect("sealed items");
        assert_eq!(items.len(), 1);
        assert_eq!(
            field(&items[0], "artifact_ref").as_str(),
            Some(fixture.document.to_hex().as_str())
        );
        assert_eq!(field(&items[0], "original_version").as_u64(), Some(1));
        assert_eq!(
            field(&items[0], "sealed_sha256").as_str(),
            Some("07".repeat(32).as_str())
        );
    }
    Ok(())
}

/// After `esign.completed`, the obligor's own claims hold the two promises
/// the document names as open commitments; before it, none.
#[test]
fn completion_opens_the_named_commitments_among_the_obligors_claims() -> Result<()> {
    let fixture = setup()?;
    sign(&fixture)?;
    assert_eq!(
        open_commitments_named_by_the_document(&fixture)?,
        Vec::<String>::new(),
        "nothing the document names is open before it completes"
    );
    seal(&fixture)?;
    assert_eq!(
        open_commitments_named_by_the_document(&fixture)?,
        OBLIGATIONS.map(str::to_owned).to_vec(),
        "esign.completed opens the commitments the document names"
    );
    Ok(())
}

/// A void before anyone signs releases both commitments.
#[test]
fn void_releases_each_inert_commitment() -> Result<()> {
    let fixture = setup()?;
    event(&fixture, EsignEvent::Sent, 4)?;
    event(
        &fixture,
        EsignEvent::Voided {
            reason: "withdrawn".into(),
        },
        5,
    )?;
    assert_released_by(&fixture, "esign.voided")
}

/// A signer's decline releases both commitments.
#[test]
fn decline_releases_each_inert_commitment() -> Result<()> {
    let fixture = setup()?;
    event(&fixture, EsignEvent::Sent, 4)?;
    event(
        &fixture,
        EsignEvent::Viewed {
            recipient: fixture.signer.clone(),
        },
        5,
    )?;
    event(
        &fixture,
        EsignEvent::Declined {
            recipient: fixture.signer.clone(),
            reason: "terms changed".into(),
        },
        6,
    )?;
    assert_released_by(&fixture, "esign.declined")
}

/// A document whose signing window lapses can never complete, so its expiry
/// releases both commitments too.
#[test]
fn expiry_releases_each_inert_commitment() -> Result<()> {
    let fixture = setup()?;
    event(
        &fixture,
        EsignEvent::Expired {
            recipient: Some(fixture.signer.clone()),
        },
        1001,
    )?;
    assert_released_by(&fixture, "esign.expired")
}
