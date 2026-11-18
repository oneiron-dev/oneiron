#![cfg(oneiron_test_support)]
//! A send lands only on the draft its binding named (blind review round 1 of #8157, P1). An
//! e-sign act binds its command to the document as it stands (`esign-command:<sha256>`, the
//! value an approval names), and its writer runs later. `vault.esign.fields.place` changes a
//! draft in place, so a placement that lands in between, in the same recorded second, would
//! have the writer send a draft the binding never named. The test door runs that placement
//! inline right after the binding; the send must then not land, and the draft keeps the
//! placement. A fresh send binds the placed draft and lands.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test esign_send_binding`.

use std::sync::Arc;

use oneiron::blob_artifact::esign::{
    DocumentKind, DocumentStatus, EsignCreateRequest, EsignDispatchRequest, EsignDocument,
    EsignEvent, EsignField, EsignItem, EsignRecipient, FieldGeometry, FieldMeta, RecipientRole,
};
use oneiron::memory::MemoryError;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::esign_send_binding::race_after_command_binding;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const PLACE: &str = "vault.esign.fields.place";
const T0: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
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
        "schema_version": "1.2", "pack_id": "esign-send-binding-test", "pack_version": "v1",
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

/// The owner's send of the one-signer draft, retried under `key`.
fn send(key: &str, document: EntityId) -> EsignDispatchRequest {
    EsignDispatchRequest {
        document_ref: document.to_hex(),
        recipient_count: 1,
        on_behalf_of: None,
        idempotency_key: Some(key.into()),
    }
}

#[test]
fn a_send_lands_only_on_the_draft_its_binding_named() -> TestResult {
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
    clock.set(T0 + 60);

    // The owner sends the draft as it stands. Right after the send binds it, in the same
    // recorded second, the draft's field is placed again at the lower right.
    let moved = signature_field(&drafted.id, recipient, [55.0, 70.0, 30.0, 8.0]);
    let input: Value = json!({
        "document_ref": document.to_hex(),
        "fields": serde_json::to_value(std::slice::from_ref(&moved))?,
    });
    let placer = *owner;
    race_after_command_binding(move |vault: &Vault| {
        let memory = vault.memory(placer, EdgeActorClass::Human);
        let placed: Result<Value, MemoryError> = invoke(&memory, PLACE, input);
        assert!(
            placed.is_ok(),
            "the placement between the binding and the writer lands: {placed:?}"
        );
    });
    let sent = memory.esign_send_for_signature(&send("send-1", *document));
    let state = vault.esign_document(*document)?;
    assert_eq!(
        state.document.fields,
        std::slice::from_ref(&moved),
        "the placement landed between the binding and the writer"
    );
    assert!(
        !sent
            .as_ref()
            .is_ok_and(|view| view.outcome == "delivered_to_channel"),
        "a send whose draft changed after its binding does not land: {sent:?}"
    );
    assert_eq!(
        state.status,
        DocumentStatus::Draft,
        "the document is not sent"
    );
    assert!(
        !vault
            .esign_audit(*document)?
            .iter()
            .any(|row| matches!(row.event, EsignEvent::Sent)),
        "no Sent event lands"
    );

    // A fresh send binds the placed draft and lands on it.
    clock.set(T0 + 120);
    let resent = memory.esign_send_for_signature(&send("send-2", *document))?;
    assert_eq!(
        resent.outcome, "delivered_to_channel",
        "a send bound to the draft as it stands lands: {resent:?}"
    );
    let state = vault.esign_document(*document)?;
    assert_eq!(state.status, DocumentStatus::Pending);
    assert_eq!(state.document.fields, std::slice::from_ref(&moved));
    Ok(())
}
