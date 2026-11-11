#![cfg(oneiron_test_support)]

//! `ESIGN-AUDIT-CLAIM-FACET`: an `esign.*` claim reads only with its document.
//!
//! An `esign.*` claim is admitted on the generic claim reads only when the
//! reader is also admitted to the live signing document and to every original
//! artifact the document's trail names. The three tests are red at `3bc823bb`
//! (each failing assertion carries a `FAILBEFORE ESIGN-AUDIT-CLAIM-FACET:`
//! message) and green after the fix. Every assertion goes through public
//! items only; the fixture needs no setup door.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test esign_audit_document_admission`.

use std::collections::BTreeSet;

use oneiron::authority::{HostSlipIssuer, SlipCaveat, VerifiedSlip};
use oneiron::blob_artifact::esign::{
    DocumentKind, EsignAuditActor, EsignDocument, EsignEvent, EsignField, EsignGetRequest,
    EsignItem, EsignRecipient, FieldGeometry, FieldMeta, RecipientRole,
};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::federation::record_scope::ScopeView;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EdgeActorClass, EntityId, Result, TimeRange, Vault, VaultConfig, WriteActor};

/// A live vault holding one drafted signing document and its audit claim.
struct Fixture {
    /// The vault directory, held so the vault's files outlive the test.
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    /// The vault under test.
    vault: Vault,
    /// The host issuer the vault is rooted under.
    issuer: HostSlipIssuer,
    /// The credential holder the narrowed proofs are minted for.
    reader: EntityId,
    /// The genuine PDF original the draft names.
    artifact: EntityId,
    /// The signing document overlay drafted on the original.
    document: EntityId,
    /// The `esign.draft` claim the draft stamped.
    claim: EntityId,
    /// The stored facet the draft stamped the claim at, read off the claim.
    facet: EntityId,
    /// The draft as submitted, for audit equality.
    draft: EsignDocument,
}

/// The audit actor the draft lands under.
fn actor() -> EsignAuditActor {
    EsignAuditActor {
        actor: "test-owner".into(),
        ip: Some("127.0.0.1".into()),
        user_agent: Some("test".into()),
    }
}

/// A project-less draft on `artifact`, with two signers and one text field.
fn draft(artifact: EntityId) -> EsignDocument {
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
            .zip([0_u32, 1])
            .map(|(id, order)| EsignRecipient {
                id,
                email: format!("signer{order}@example.test"),
                name: format!("Signer {order}"),
                role: RecipientRole::Signer,
                order,
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

/// The pinned genuine one-page PDF every original in this file carries.
fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}

/// The `esign.draft` claim about `document`.
///
/// # Errors
/// The subject scan or a claim read.
fn drafted_claim(vault: &Vault, document: &EntityId) -> Result<EntityId> {
    let mut found = None;
    for id in vault.claims_for_subject(document)? {
        let body = vault.get_claim(&id)?.expect("a stored claim reads back");
        if body.predicate == "esign.draft" {
            found = Some(id);
        }
    }
    Ok(found.expect("the draft stamps one esign.draft claim"))
}

/// Builds the vault, the PDF original, the draft on it, and the reader.
///
/// The Drafted claim lands at the vault-default facet through the normal
/// ledger path; the facet is read off the stored claim, never hard-coded.
///
/// # Errors
/// Any vault write or read the fixture needs.
fn setup() -> Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let time = TimeRange { start: 1, end: 1 };
    let person = EntityId::now();
    vault.put_entity(&person, ENTITY_TYPE_PERSON, time, 1, b"owner")?;
    let reader = EntityId::now();
    vault.put_entity(&reader, ENTITY_TYPE_PERSON, time, 1, b"reader")?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
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
    let document = EntityId::now();
    vault.put_blob_artifact(
        &document,
        &BlobArtifactBody::new("envelope.pdf", "application/pdf"),
        time,
        1,
    )?;
    let expected = draft(artifact);
    vault.create_esign_document(document, &expected, actor(), 2)?;
    let claim = drafted_claim(&vault, &document)?;
    let stored = vault
        .get_claim(&claim)?
        .expect("the drafted claim reads back");
    let facet = stored.scope_facet;
    let document_scope = vault.record_scope(&document)?;
    let claim_scope = vault.record_scope(&claim)?;
    assert_ne!(
        document_scope, claim_scope,
        "precondition: the claim's stored scope differs from the document's own"
    );
    let facets_differ = match (&document_scope, &claim_scope) {
        (Some(left), Some(right)) => left.facets != right.facets,
        _ => false,
    };
    assert!(
        facets_differ,
        "precondition: the claim is stamped at a facet the document's own scope does not name"
    );
    Ok(Fixture {
        dir,
        vault,
        issuer,
        reader,
        artifact,
        document,
        claim,
        facet,
        draft: expected,
    })
}

/// A fresh slip id from two UUIDv7 stamps.
fn slip_id() -> [u8; 32] {
    let first = EntityId::now();
    let second = EntityId::now();
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(first.as_bytes());
    id[16..].copy_from_slice(second.as_bytes());
    id
}

/// A whole-vault scope narrowed to the single facet `facet`.
fn facet_scope(facet: EntityId) -> Scope {
    let mut scope = Scope::top();
    scope.facets = ScopeAxis::Some(BTreeSet::from([ScopeId(facet)]));
    scope
}

/// A whole-vault scope narrowed to the `read` verb alone.
fn read_verb_scope() -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    scope
}

/// A caveat narrowing the scope to `scope`.
fn scope_caveat(scope: Scope) -> SlipCaveat {
    SlipCaveat {
        scope: Some(scope),
        ..Default::default()
    }
}

/// A caveat naming exactly the records `ids`.
fn records_caveat(ids: &[EntityId]) -> SlipCaveat {
    SlipCaveat {
        records: Some(ids.iter().map(EntityId::to_hex).collect()),
        ..Default::default()
    }
}

/// A verified slip for the fixture reader, narrowed by `caveat` when one is
/// given. Facet, verb and records bounds are all public [`SlipCaveat`] axes.
///
/// # Errors
/// The mint, the narrowing, or the verification.
fn mint_reader_proof(
    fixture: &Fixture,
    caveat: Option<SlipCaveat>,
    challenge: &[u8],
) -> Result<VerifiedSlip> {
    let root = fixture.vault.ensure_host_root_slip(&fixture.issuer)?;
    let mut claims = root.claims;
    claims.slip_id = slip_id();
    claims.holder_ref = fixture.reader.to_hex();
    claims.actor_class = Some("human".to_owned());
    let mut slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)?;
    if let Some(caveat) = caveat {
        fixture.issuer.attenuate(&mut slip, caveat)?;
    }
    let binding = fixture.issuer.binding_proof(&slip, challenge)?;
    fixture
        .vault
        .verify_capability_slip(&fixture.issuer.public_key(), &slip, challenge, &binding)
}

/// The live body of `id` as `proof` reads it through the public credential
/// raw door.
///
/// # Errors
/// The credential key or the read.
fn credential_body(vault: &Vault, proof: &VerifiedSlip, id: &EntityId) -> Result<Option<Vec<u8>>> {
    vault.with_credential_raw_read(proof, |read| read.entity_body(id))
}

/// A facet-limited credential reads no `esign.*` claim its document withholds.
///
/// The credential carries no records caveat, so the class path judges the
/// claim. Red at the base: the claim's own scope admits it there.
#[test]
fn facet_limited_credential_reads_no_esign_claim_its_document_withholds() -> Result<()> {
    let fixture = setup()?;
    let proof = mint_reader_proof(
        &fixture,
        Some(scope_caveat(facet_scope(fixture.facet))),
        b"esign audit facet read",
    )?;
    let body = credential_body(&fixture.vault, &proof, &fixture.claim)?;
    assert!(
        body.is_none(),
        "FAILBEFORE ESIGN-AUDIT-CLAIM-FACET: the facet-limited credential reads no esign claim its document withholds"
    );
    let request = EsignGetRequest {
        document_ref: fixture.document.to_hex(),
    };
    let refused = fixture
        .vault
        .memory(fixture.reader, EdgeActorClass::Human)
        .with_read_proof(&proof)
        .esign_get(&request);
    assert!(
        refused.is_err(),
        "control: the same credential does not reach the signing document itself"
    );
    let whole = mint_reader_proof(&fixture, None, b"esign audit whole read")?;
    let body = credential_body(&fixture.vault, &whole, &fixture.claim)?;
    assert!(
        body.is_some(),
        "control: an unattenuated whole-vault credential still reads the claim"
    );
    assert_eq!(
        body,
        fixture.vault.get(&fixture.claim)?,
        "control: the unrestricted read returns the claim's stored body bytes"
    );
    let read_only = mint_reader_proof(
        &fixture,
        Some(scope_caveat(read_verb_scope())),
        b"esign audit verb read",
    )?;
    let body = credential_body(&fixture.vault, &read_only, &fixture.claim)?;
    assert!(
        body.is_some(),
        "control: a read-verb whole-vault credential still reads the claim"
    );
    let audit = fixture.vault.esign_audit(fixture.document)?;
    assert_eq!(
        audit.len(),
        1,
        "control: the unrestricted handle still audits the document's single event"
    );
    assert!(
        matches!(
            audit.first(),
            Some(row)
                if matches!(
                    &row.event,
                    EsignEvent::Drafted { document } if document == &fixture.draft
                )
        ),
        "control: the unrestricted handle still audits the full drafted document"
    );
    Ok(())
}

/// The scoped record doors withhold an `esign.*` claim their selector keeps
/// its document from. Red at the base: each door judges the claim's own
/// position there.
#[test]
fn scoped_record_doors_withhold_an_esign_claim_their_selector_keeps_its_document_from() -> Result<()>
{
    let fixture = setup()?;
    let selector = facet_scope(fixture.facet);
    let top = Scope::top();
    let rows = fixture
        .vault
        .records_in_scope(&selector, &top, &top, ScopeView::Normal)?;
    assert!(
        !rows.iter().any(|row| row.id == fixture.claim),
        "FAILBEFORE ESIGN-AUDIT-CLAIM-FACET: the scoped read door withholds an esign claim whose document its selector keeps from it"
    );
    let rows = fixture
        .vault
        .export_records_in_scope(&selector, &top, &top)?;
    assert!(
        !rows.iter().any(|row| row.id == fixture.claim),
        "FAILBEFORE ESIGN-AUDIT-CLAIM-FACET: the scoped export door withholds an esign claim whose document its selector keeps from it"
    );
    let rows = fixture
        .vault
        .records_in_scope(&top, &top, &top, ScopeView::Normal)?;
    assert!(
        rows.iter().any(|row| row.id == fixture.claim),
        "control: the top selector still reads the claim"
    );
    assert!(
        rows.iter().any(|row| row.id == fixture.document),
        "control: the top selector still reads the document"
    );
    let rows = fixture.vault.export_records_in_scope(&top, &top, &top)?;
    assert!(
        rows.iter().any(|row| row.id == fixture.claim),
        "control: the top-selector export still carries the claim"
    );
    assert!(
        rows.iter().any(|row| row.id == fixture.document),
        "control: the top-selector export still carries the document"
    );
    Ok(())
}

/// A record-bounded credential reads an `esign.*` claim only with its
/// document and its original.
///
/// The records caveat takes the row path. The full caveat is the green
/// control; the partial one is red at the base, where the claim's own
/// admission does not ask for the original.
#[test]
fn record_bounded_credential_reads_an_esign_claim_only_with_its_document_and_original() -> Result<()>
{
    let fixture = setup()?;
    let full = mint_reader_proof(
        &fixture,
        Some(records_caveat(&[
            fixture.claim,
            fixture.document,
            fixture.artifact,
        ])),
        b"esign audit records full",
    )?;
    let body = credential_body(&fixture.vault, &full, &fixture.claim)?;
    assert!(
        body.is_some(),
        "control: a records caveat naming the claim, the document and the original still reads the claim"
    );
    let partial = mint_reader_proof(
        &fixture,
        Some(records_caveat(&[fixture.claim, fixture.document])),
        b"esign audit records partial",
    )?;
    let body = credential_body(&fixture.vault, &partial, &fixture.claim)?;
    assert!(
        body.is_none(),
        "FAILBEFORE ESIGN-AUDIT-CLAIM-FACET: a records caveat leaving out the original reads no esign claim"
    );
    Ok(())
}
