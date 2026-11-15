#![cfg(oneiron_test_support)]
//! The ceremony's review-before-complete step (ARCH-0064 :235, :241; SGN-08;
//! RULING ESIGN-REVIEW-BEFORE-COMPLETE = A): UETA section 10 gives a signer a
//! real chance to find and correct an error before the signature binds. A
//! Review act binds the frozen items and the signer's own field values;
//! Complete is refused, citing the e-sign rule pack's UETA section 10 row,
//! until a Review that still stands exists; a field saved after the Review
//! voids it; Review then Complete signs.
//!
//! The Review act and the refusal outcome are named through their wire form
//! (`{"action":"review"}`, `review_required`), so this file builds on a tree
//! without them and fails there by its asserts.

use std::sync::Arc;

use oneiron::blob_artifact::esign::{
    DocumentKind, EsignAuditActor, EsignCapability, EsignDocument, EsignField, EsignItem,
    EsignRecipient, FieldGeometry, FieldMeta, FieldValue, RecipientRole, SigningAction,
    SigningOutcome, SigningStatus,
};
use oneiron::store::ports::ManualClock;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The e-sign rule pack's UETA section 10 row a refused Complete cites.
const UETA_REVIEW_ROW: &str = "us.ueta.s10.review_before_complete";

/// The one field the signer fills.
const FIELD: &str = "field-name";

fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}

/// A sent one-signer document with one required text field, and the
/// signer's capability.
struct Sent {
    vault: Vault,
    id: EntityId,
    recipient: String,
    signing: EsignCapability,
    _dir: tempfile::TempDir,
}

fn sent() -> TestResult<Sent> {
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
    let recipient = EntityId::now().to_hex();
    let document = EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: false,
        expires_at: now + 3600,
        token_expires_at: None,
        items: vec![EsignItem {
            artifact_ref: id.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: recipient.clone(),
            email: "sam@example.com".into(),
            name: "Sam".into(),
            role: RecipientRole::Signer,
            order: 0,
            expires_at: now + 3600,
            principal_ref: None,
            automated: false,
            natural_person: None,
        }],
        fields: vec![EsignField {
            id: FIELD.into(),
            item: 0,
            recipient: recipient.clone(),
            required: true,
            geometry: FieldGeometry {
                page: 1,
                x_percent: 10.0,
                y_percent: 10.0,
                width_percent: 40.0,
                height_percent: 5.0,
            },
            meta: FieldMeta::Text { max_bytes: 64 },
        }],
        full_trail_appendix: true,
        lifecycle: None,
        project: None,
        commitments: Vec::new(),
    };
    let actor = EsignAuditActor {
        actor: person.to_hex(),
        ip: None,
        user_agent: None,
    };
    vault.create_esign_document(id, &document, actor.clone(), now)?;
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
    Ok(Sent {
        vault,
        id,
        recipient,
        signing,
        _dir: dir,
    })
}

impl Sent {
    fn act(&self, action: &SigningAction) -> TestResult<SigningOutcome> {
        Ok(self
            .vault
            .execute_signing_action(&self.signing, action, None, None)?)
    }

    fn save(&self, text: &str) -> TestResult<SigningOutcome> {
        self.act(&SigningAction::SaveField {
            field: FIELD.into(),
            value: FieldValue::Text(text.into()),
        })
    }

    /// The Review act, by its wire name.
    fn review(&self) -> TestResult<SigningOutcome> {
        let review: SigningAction = serde_json::from_value(json!({"action": "review"}))?;
        self.act(&review)
    }

    fn complete(&self) -> TestResult<SigningOutcome> {
        self.act(&SigningAction::Complete {
            consent: true,
            next: None,
        })
    }

    fn signing_status(&self) -> TestResult<SigningStatus> {
        Ok(self.vault.esign_document(self.id)?.recipients[&self.recipient].signing)
    }

    /// The trail's events of one kind, as their wire form.
    fn trail(&self, kind: &str) -> TestResult<Vec<Value>> {
        let mut events = Vec::new();
        for row in self.vault.esign_audit(self.id)? {
            let event = serde_json::to_value(&row.event)?;
            if event["event"] == kind {
                events.push(event);
            }
        }
        Ok(events)
    }
}

/// The refusal a Complete with no standing review answers.
fn review_required() -> Value {
    json!({"outcome": "review_required", "data": {"row": UETA_REVIEW_ROW}})
}

#[test]
fn complete_requires_review_before_complete_row() -> TestResult {
    let sent = sent()?;
    assert!(matches!(sent.save("Sam Signer")?, SigningOutcome::Page(_)));

    // 1. Complete without a Review is refused, citing the UETA section 10
    //    row, and signs nothing.
    let refused = serde_json::to_value(sent.complete()?)?;
    assert_eq!(
        refused,
        review_required(),
        "a Complete with no Review is refused citing the UETA row"
    );
    assert_eq!(sent.signing_status()?, SigningStatus::Ready);
    assert!(sent.trail("signed")?.is_empty(), "nothing signed");

    // 2. The Review binds the frozen items and the signer's values, and
    //    answers the page.
    assert!(matches!(sent.review()?, SigningOutcome::Page(_)));
    let reviewed = sent.trail("reviewed")?;
    assert_eq!(reviewed.len(), 1, "one Review on the trail: {reviewed:?}");
    assert_eq!(reviewed[0]["recipient"], sent.recipient.as_str());
    assert_eq!(reviewed[0]["items"][0]["artifact_ref"], sent.id.to_hex());
    assert_eq!(reviewed[0]["items"][0]["original_version"], 1);
    assert_eq!(
        reviewed[0]["values"][FIELD],
        json!({"kind": "text", "value": "Sam Signer"})
    );

    // 3. A field saved after the Review voids it: Complete is refused again.
    assert!(matches!(
        sent.save("Sam Q. Signer")?,
        SigningOutcome::Page(_)
    ));
    assert_eq!(
        serde_json::to_value(sent.complete()?)?,
        review_required(),
        "a field saved after the Review voids it"
    );
    assert_eq!(sent.signing_status()?, SigningStatus::Ready);

    // 4. Review then Complete signs, on the values the second Review bound.
    assert!(matches!(sent.review()?, SigningOutcome::Page(_)));
    assert_eq!(sent.complete()?, SigningOutcome::AwaitingSeal);
    assert_eq!(sent.signing_status()?, SigningStatus::Completed);
    let reviewed = sent.trail("reviewed")?;
    assert_eq!(reviewed.len(), 2, "two Reviews on the trail: {reviewed:?}");
    assert_eq!(
        reviewed[1]["values"][FIELD],
        json!({"kind": "text", "value": "Sam Q. Signer"})
    );
    assert_eq!(sent.trail("signed")?.len(), 1, "one signature");
    Ok(())
}
