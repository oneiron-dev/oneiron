#![cfg(oneiron_test_support)]

//! `ESIGN-DRAFT-FIELD-PAGE-UNCHECKED`: a draft's fields are laid out against
//! the pinned PDF's page count at the draft door.
//!
//! On main before the fix a `Drafted` event laid out no fields, so a draft
//! could name page 2 of a one-page PDF and the document then stuck at the
//! signer's save or sign. The page-2 tests are red there (the draft is
//! accepted) and green after the fix; the page-1 test passes on both.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test esign_draft_field_page_unchecked`.

use oneiron::blob_artifact::esign::{
    DocumentKind, DocumentStatus, EsignAuditActor, EsignCreateRequest, EsignDocument, EsignField,
    EsignItem, EsignRecipient, FieldGeometry, FieldMeta, RecipientRole,
};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::{EdgeActorClass, EntityId, Result, TimeRange, Vault, VaultConfig, WriteActor};

/// A live vault holding one genuine one-page PDF original.
struct Fixture {
    /// The vault directory, held so the vault's files outlive the test.
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    /// The vault under test.
    vault: Vault,
    /// The person the original's version is written by, and the verb door's
    /// bound actor.
    person: EntityId,
    /// The genuine one-page PDF original every draft names.
    artifact: EntityId,
}

/// The audit actor the vault door's draft lands under.
fn actor() -> EsignAuditActor {
    EsignAuditActor {
        actor: "test-owner".into(),
        ip: Some("127.0.0.1".into()),
        user_agent: Some("test".into()),
    }
}

/// The pinned genuine one-page PDF every original in this file carries.
fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}

/// A one-signer draft on `artifact`, its one text field on page `page`.
fn draft(artifact: EntityId, page: u32) -> EsignDocument {
    let signer = EntityId::now().to_hex();
    EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: false,
        expires_at: 1000,
        token_expires_at: None,
        items: vec![EsignItem {
            artifact_ref: artifact.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: signer.clone(),
            email: "signer@example.test".into(),
            name: "Signer".into(),
            role: RecipientRole::Signer,
            order: 0,
            expires_at: 1000,
            principal_ref: None,
            automated: false,
            natural_person: None,
        }],
        fields: vec![EsignField {
            id: EntityId::now().to_hex(),
            item: 0,
            recipient: signer,
            required: true,
            geometry: FieldGeometry {
                page,
                x_percent: 10.0,
                y_percent: 10.0,
                width_percent: 50.0,
                height_percent: 20.0,
            },
            meta: FieldMeta::Text { max_bytes: 50 },
        }],
        full_trail_appendix: true,
        lifecycle: None,
        project: None,
        commitments: Vec::new(),
    }
}

/// Builds the vault and its one-page PDF original.
///
/// # Errors
/// Any vault write the fixture needs.
fn setup() -> Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let time = TimeRange { start: 1, end: 1 };
    let person = EntityId::now();
    vault.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        time,
        1,
        b"owner",
    )?;
    oneiron::test_support::provision_engine_machines(&vault);
    let artifact = EntityId::now();
    vault.put_blob_artifact(
        &artifact,
        &BlobArtifactBody::new("agreement.pdf", "application/pdf"),
        time,
        1,
    )?;
    vault.append_blob_artifact_version(
        &artifact,
        original_pdf(),
        &BlobVersionProvenance::UserUpload,
        WriteActor::new(person, EdgeActorClass::Human),
        time,
        1,
    )?;
    Ok(Fixture {
        dir,
        vault,
        person,
        artifact,
    })
}

/// A fresh signing overlay artifact a draft can land on.
///
/// # Errors
/// The blob artifact write.
fn overlay(vault: &Vault) -> Result<EntityId> {
    let document = EntityId::now();
    vault.put_blob_artifact(
        &document,
        &BlobArtifactBody::new("envelope.pdf", "application/pdf"),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    Ok(document)
}

/// A draft whose one field names page 2 of a one-page PDF is refused at the
/// vault's create door, and nothing of it lands.
#[test]
fn draft_field_beyond_last_page_is_refused_at_create() -> Result<()> {
    let fixture = setup()?;
    let document = overlay(&fixture.vault)?;
    let result =
        fixture
            .vault
            .create_esign_document(document, &draft(fixture.artifact, 2), actor(), 2);
    assert!(
        result.is_err(),
        "a field on page 2 of a one-page PDF must be refused at draft, got {result:?}"
    );
    assert!(
        fixture.vault.esign_audit(document)?.is_empty(),
        "a refused draft lands no event"
    );
    Ok(())
}

/// The same draft with its field on page 1 drafts as before.
#[test]
fn draft_field_on_first_page_drafts_as_today() -> Result<()> {
    let fixture = setup()?;
    let document = overlay(&fixture.vault)?;
    fixture
        .vault
        .create_esign_document(document, &draft(fixture.artifact, 1), actor(), 2)?;
    let state = fixture.vault.esign_document(document)?;
    assert_eq!(state.status, DocumentStatus::Draft);
    assert_eq!(state.document.fields.len(), 1);
    assert_eq!(state.document.fields[0].geometry.page, 1);
    Ok(())
}

/// The `vault.esign.create` verb door refuses the same page-2 field, after
/// the same door has drafted the page-1 field: the refusal is the page, not
/// the fixture.
#[test]
fn draft_field_beyond_last_page_is_refused_at_esign_create() -> Result<()> {
    let fixture = setup()?;
    // The verb door drafts at the vault's own clock, not at time 2.
    let verb_draft = |page: u32| {
        let mut body = draft(fixture.artifact, page);
        let expires = fixture.vault.now_recorded_at() + 3600;
        body.expires_at = expires;
        for recipient in &mut body.recipients {
            recipient.expires_at = expires;
        }
        body
    };
    let drafted = overlay(&fixture.vault)?;
    let view = fixture
        .vault
        .memory(fixture.person, EdgeActorClass::Human)
        .esign_create(&EsignCreateRequest {
            document_ref: drafted.to_hex(),
            draft: verb_draft(1),
            qr_pdf_download: false,
        })
        .expect("a field on page 1 drafts through the verb door");
    assert_eq!(view.status, DocumentStatus::Draft);
    assert_eq!(view.fields, 1);

    let document = overlay(&fixture.vault)?;
    let result = fixture
        .vault
        .memory(fixture.person, EdgeActorClass::Human)
        .esign_create(&EsignCreateRequest {
            document_ref: document.to_hex(),
            draft: verb_draft(2),
            qr_pdf_download: false,
        });
    assert!(
        result.is_err(),
        "the verb door must refuse a field on page 2 of a one-page PDF, got {result:?}"
    );
    assert!(
        fixture.vault.esign_audit(document)?.is_empty(),
        "a refused draft lands no event"
    );
    Ok(())
}
