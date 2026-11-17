#![cfg(oneiron_test_support)]
//! Fields placed on a draft are the fields every surface serves (ARCH-0064 SGN-07: "One shared
//! field renderer for editor/ceremony/export"; the DRAFT rung: "The agent prepares the document +
//! places fields; a human sends"). A drafted document's fields move through
//! `vault.esign.fields.place`, in the shape the owner's field editor exports, until it is sent:
//! the signer's ceremony then holds exactly the placed fields, the signing preview lays them out
//! at the rectangles the editor's own layout gives them, and the door is refused once the
//! document has left Draft. The door is called by name, so this file builds where it does not
//! exist and fails there by its asserts.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test esign_field_editor`.

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::blob_artifact::esign::{
    DocumentKind, DocumentStatus, EsignCapability, EsignCreateRequest, EsignDispatchRequest,
    EsignDocument, EsignEvent, EsignField, EsignItem, EsignRecipient, EsignSigningPreviewView,
    FieldGeometry, FieldMeta, RecipientRole, SigningAction, SigningOutcome, layout_esign_preview,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{Memory, MemoryError};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::sdk::invoke;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const PLACE: &str = "vault.esign.fields.place";
const PREVIEW: &str = "vault.esign.signing.preview";
const T0: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}

/// The verb's answer, failing the test with the refusal when it has none.
fn answer(memory: &Memory<'_>, verb: &str, input: Value) -> TestResult<Value> {
    let answered: Result<Value, MemoryError> = invoke(memory, verb, input);
    assert!(answered.is_ok(), "{verb} answers: {answered:?}");
    Ok(answered?)
}

/// A fresh proof of the embedded owner, for the owner's own link issue.
fn owner_proof(vault: &Vault, owner: EntityId) -> TestResult<AuthenticatedOwner> {
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

/// `recipient`'s signature field `id` on the first page of the only item, at `geometry`.
fn signature_field(id: &str, recipient: &str, geometry: [f64; 4]) -> EsignField {
    let [x_percent, y_percent, width_percent, height_percent] = geometry;
    EsignField {
        id: id.into(),
        item: 0,
        recipient: recipient.into(),
        required: true,
        geometry: FieldGeometry {
            page: 1,
            x_percent,
            y_percent,
            width_percent,
            height_percent,
        },
        meta: FieldMeta::Signature,
    }
}

/// The input `vault.esign.fields.place` takes: the document and its fields, each in the shape
/// the editor's geography pack holds.
fn placement(document: EntityId, fields: &[EsignField]) -> TestResult<Value> {
    Ok(json!({
        "document_ref": document.to_hex(),
        "fields": serde_json::to_value(fields)?,
    }))
}

struct Signing {
    vault: Vault,
    clock: Arc<ManualClock>,
    owner: EntityId,
    document: EntityId,
    recipient: String,
    drafted: EsignField,
    _dir: tempfile::TempDir,
}

/// A rooted vault on a manual clock at `T0` whose embedded owner drafted a one-signer document
/// on an uploaded one-page PDF, with one signature field near the top left. The policy lets the
/// owner send on the e-sign channel.
fn signing_draft() -> TestResult<Signing> {
    let dir = tempfile::tempdir()?;
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let at = TimeRange { start: T0, end: T0 };
    let owner = vault.ensure_embedded_owner_actor()?;
    vault.put_entity(
        &owner,
        oneiron::registry::ENTITY_TYPE_PERSON,
        at,
        T0,
        b"owner",
    )?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let policy = json!({
        "schema_version": "1.2", "pack_id": "esign-field-editor-test", "pack_version": "v1",
        "min_engine_version": "0.0.0",
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [{"actor_class": "human", "actor_ref": owner.to_hex(), "ceiling": "auto"}],
        "scoped_grants": [{
            "actor_ref": owner.to_hex(),
            "effector": "external:send_for_signature",
            "scope": oneiron::test_support::effect_preset(),
            "selectors": {"channel": "esign"},
        }],
    });
    oneiron::test_support::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &rmp_serde::to_vec_named(&policy)?,
    )?;
    let document = EntityId::now();
    vault.put_blob_artifact(
        &document,
        &oneiron::blob_artifact::BlobArtifactBody::new("agreement.pdf", "application/pdf"),
        at,
        T0,
    )?;
    vault.append_blob_artifact_version(
        &document,
        original_pdf(),
        &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
        oneiron::write_envelope::WriteActor::new(owner, EdgeActorClass::Human),
        at,
        T0,
    )?;
    let recipient = EntityId::now().to_hex();
    let drafted = signature_field(
        &EntityId::now().to_hex(),
        &recipient,
        [10.0, 10.0, 30.0, 8.0],
    );
    let draft = EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: false,
        expires_at: T0 + 90 * DAY,
        token_expires_at: None,
        items: vec![EsignItem {
            artifact_ref: document.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: recipient.clone(),
            email: "owen@example.com".into(),
            name: "Owen".into(),
            role: RecipientRole::Signer,
            order: 0,
            expires_at: T0 + 90 * DAY,
            principal_ref: None,
            automated: false,
            natural_person: None,
        }],
        fields: vec![drafted.clone()],
        full_trail_appendix: true,
        lifecycle: None,
        project: None,
        commitments: Vec::new(),
    };
    vault
        .memory(owner, EdgeActorClass::Human)
        .esign_create(&EsignCreateRequest {
            document_ref: document.to_hex(),
            draft,
            qr_pdf_download: false,
        })?;
    Ok(Signing {
        vault,
        clock,
        owner,
        document,
        recipient,
        drafted,
        _dir: dir,
    })
}

/// The one link the draft issued, which is `recipient`'s.
fn only_link(
    issued: Vec<(String, EsignCapability)>,
    recipient: &str,
) -> TestResult<EsignCapability> {
    let [(id, link)]: [(String, EsignCapability); 1] = issued
        .try_into()
        .map_err(|rest: Vec<_>| format!("the draft issues one link, it issued {}", rest.len()))?;
    assert_eq!(id, recipient, "the link is the recipient's");
    Ok(link)
}

#[test]
fn placed_fields_reach_the_ceremony_and_preview_until_send() -> TestResult {
    let signing = signing_draft()?;
    let Signing {
        vault,
        clock,
        owner,
        document,
        recipient,
        drafted,
        ..
    } = &signing;
    let memory = vault.memory(*owner, EdgeActorClass::Human);

    // The recipient's link is minted on the first draft, before any field moves.
    clock.set(T0 + 60);
    let link = only_link(
        vault.issue_esign_capabilities(&owner_proof(vault, *owner)?, *document)?,
        recipient,
    )?;

    // The owner moves the signature field to the lower right, as the editor exports it.
    clock.set(T0 + 120);
    let moved = signature_field(&drafted.id, recipient, [55.0, 70.0, 30.0, 8.0]);
    let placed = answer(
        &memory,
        PLACE,
        placement(*document, std::slice::from_ref(&moved))?,
    )?;
    assert_eq!(
        placed["status"], "draft",
        "the document stays a draft: {placed}"
    );
    assert_eq!(
        placed["fields"], 1,
        "the draft holds the one placed field: {placed}"
    );
    let state = vault.esign_document(*document)?;
    assert_eq!(state.status, DocumentStatus::Draft);
    assert_eq!(
        state.document.fields,
        std::slice::from_ref(&moved),
        "the draft holds the placed field in place of its own"
    );
    let audit = vault.esign_audit(*document)?;
    assert_eq!(audit.len(), 2, "the placement is one more trail event");
    let EsignEvent::Drafted { document: redraft } = &audit[1].event else {
        return Err(format!("the placement lands as a redraft: {:?}", audit[1].event).into());
    };
    assert_eq!(
        redraft.fields,
        std::slice::from_ref(&moved),
        "the redraft holds the placed field"
    );
    assert_eq!(
        audit[1].actor.actor,
        owner.to_hex(),
        "the redraft names its placer"
    );

    // A field for no recipient of the draft is refused, and the draft keeps the placed field.
    let stranger = signature_field(
        &EntityId::now().to_hex(),
        &EntityId::now().to_hex(),
        [10.0, 40.0, 30.0, 8.0],
    );
    let refused = invoke(&memory, PLACE, placement(*document, &[stranger])?);
    assert!(
        refused.is_err(),
        "a field for no recipient is refused: {refused:?}"
    );
    assert_eq!(
        vault.esign_document(*document)?.document.fields,
        std::slice::from_ref(&moved)
    );

    // The owner sends; the ceremony and the preview hold the placed field.
    clock.set(T0 + 180);
    let sent = memory.esign_send_for_signature(&EsignDispatchRequest {
        document_ref: document.to_hex(),
        recipient_count: 1,
        on_behalf_of: None,
        idempotency_key: Some("send-1".into()),
    })?;
    assert_eq!(
        sent.outcome, "delivered_to_channel",
        "the owner's send lands: {sent:?}"
    );
    let SigningOutcome::Page(page) =
        vault.execute_signing_action(&link, &SigningAction::Load, None, None)?
    else {
        return Err("the signer's link opens the signing page".into());
    };
    assert_eq!(
        page.fields,
        std::slice::from_ref(&moved),
        "the ceremony serves the placed field"
    );
    let preview: EsignSigningPreviewView = serde_json::from_value(answer(
        &memory,
        PREVIEW,
        json!({"token": link.expose_for_delivery(), "item": 0}),
    )?)?;
    let editor = layout_esign_preview(
        std::slice::from_ref(&moved),
        &BTreeMap::new(),
        preview.pages.clone(),
    )
    .map_err(|error| format!("the editor lays the placed field out: {error:?}"))?;
    assert_eq!(
        preview.fields, editor.fields,
        "the signing preview lays the placed field out where the editor does"
    );
    let first = layout_esign_preview(
        std::slice::from_ref(drafted),
        &BTreeMap::new(),
        preview.pages.clone(),
    )
    .map_err(|error| format!("the editor lays the drafted field out: {error:?}"))?;
    assert_ne!(
        preview.fields[0].rect, first.fields[0].rect,
        "the preview no longer shows the field where it was drafted"
    );

    // Once sent, the fields are frozen.
    clock.set(T0 + 240);
    let frozen = invoke(
        &memory,
        PLACE,
        placement(*document, std::slice::from_ref(drafted))?,
    );
    assert!(
        frozen
            .as_ref()
            .is_err_and(|error| error.to_string().contains("sent content is frozen")),
        "a sent document's fields do not move: {frozen:?}"
    );
    let state = vault.esign_document(*document)?;
    assert_eq!(state.status, DocumentStatus::Pending);
    assert_eq!(state.document.fields, std::slice::from_ref(&moved));
    Ok(())
}
