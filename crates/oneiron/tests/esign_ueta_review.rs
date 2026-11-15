#![cfg(oneiron_test_support)]
//! The ceremony's review-before-complete step (ARCH-0064 :235, :241; SGN-08;
//! RULING ESIGN-REVIEW-BEFORE-COMPLETE = A): UETA section 10 gives a signer a
//! real chance to find and correct an error before the signature binds. A
//! Review act binds the frozen items and the signer's own field values;
//! Complete is refused, citing the e-sign rule pack's UETA section 10 row,
//! until a Review that still stands exists; a field saved after the Review
//! voids it; a person's Complete stands only on a person's review; Review
//! then Complete signs. An agent's Complete the signing dial holds for a role
//! holder's answer (ARCH-0064 D6) lands on that answer only on the values it
//! was made on, while their review still stands.
//!
//! The Review act and the refusal outcome are named through their wire form
//! (`{"action":"review"}`, `review_required`), so this file builds on a tree
//! without them and fails there by its asserts.

use std::sync::Arc;

use oneiron::blob_artifact::esign::{
    DocumentKind, EsignAuditActor, EsignCapability, EsignDocument, EsignField, EsignItem,
    EsignRecipient, FieldGeometry, FieldMeta, FieldValue, HeldSigning, HeldSigningAnswer,
    HeldSigningState, RecipientRole, SigningAction, SigningCaller, SigningOutcome, SigningStatus,
};
use oneiron::model_decision::{AnswerActor, RoleRank};
use oneiron::store::ports::ManualClock;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The e-sign rule pack's UETA section 10 row a refused Complete cites.
const UETA_REVIEW_ROW: &str = "us.ueta.s10.review_before_complete";

/// The test clock's start.
const START: u64 = 1_800_000_000;

fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}

/// A sent one-signer document with one required text field (`field`), and
/// the signer's capability.
struct Sent {
    vault: Vault,
    clock: Arc<ManualClock>,
    /// The vault owner, who answers a held sign act.
    person: EntityId,
    id: EntityId,
    recipient: String,
    field: String,
    signing: EsignCapability,
    _dir: tempfile::TempDir,
}

fn sent() -> TestResult<Sent> {
    let dir = tempfile::tempdir()?;
    let now = START;
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
    // A field id is an entity reference, as a recipient id is.
    let field = EntityId::now().to_hex();
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
            id: field.clone(),
            item: 0,
            recipient: recipient.clone(),
            required: true,
            geometry: FieldGeometry {
                page: 1,
                x_percent: 10.0,
                y_percent: 10.0,
                width_percent: 50.0,
                height_percent: 20.0,
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
        clock,
        person,
        id,
        recipient,
        field,
        signing,
        _dir: dir,
    })
}

impl Sent {
    fn act(&self, caller: SigningCaller, action: &SigningAction) -> TestResult<SigningOutcome> {
        Ok(self
            .vault
            .execute_signing_action_as(&self.signing, action, caller, None, None, None)?)
    }

    fn save(&self, caller: SigningCaller, text: &str) -> TestResult<SigningOutcome> {
        self.act(
            caller,
            &SigningAction::SaveField {
                field: self.field.clone(),
                value: FieldValue::Text(text.into()),
            },
        )
    }

    /// The Review act, by its wire name.
    fn review(&self, caller: SigningCaller) -> TestResult<SigningOutcome> {
        let review: SigningAction = serde_json::from_value(json!({"action": "review"}))?;
        self.act(caller, &review)
    }

    fn complete(&self, caller: SigningCaller) -> TestResult<SigningOutcome> {
        self.act(
            caller,
            &SigningAction::Complete {
                consent: true,
                next: None,
            },
        )
    }

    /// An agent's Complete, which the closed signing dial holds: the hold's
    /// time.
    fn held(&self) -> TestResult<u64> {
        match self.complete(AGENT)? {
            SigningOutcome::HeldForOwner { held_at } => Ok(held_at),
            other => Err(format!("the agent's Complete was not held: {other:?}").into()),
        }
    }

    /// The vault owner allows the hold made at `held_at`.
    fn allow(&self, held_at: u64) -> TestResult<HeldSigning> {
        Ok(self.vault.settle_esign_hold(
            &self.id.to_hex(),
            &self.recipient,
            held_at,
            HeldSigningAnswer::Allow {
                by: AnswerActor::Actor(self.person),
                role: RoleRank::Owner,
            },
        )?)
    }

    /// Sets the clock `minutes` after the start, so each hold has its own
    /// time.
    fn tick(&self, minutes: u64) {
        self.clock.set(START + minutes * 60);
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

/// The browser signer: the capability alone.
const BEARER: SigningCaller = SigningCaller::Bearer;
/// An agent signing for the recipient, with no principal whose dial opens
/// automated signing: its Complete is held.
const AGENT: SigningCaller = SigningCaller::Agent;

/// The refusal a Complete with no standing review answers.
fn review_required() -> Value {
    json!({"outcome": "review_required", "data": {"row": UETA_REVIEW_ROW}})
}

#[test]
fn complete_requires_review_before_complete_row() -> TestResult {
    let sent = sent()?;
    assert!(matches!(
        sent.save(BEARER, "Sam Signer")?,
        SigningOutcome::Page(_)
    ));

    // 1. Complete without a Review is refused, citing the UETA section 10
    //    row, and signs nothing.
    let refused = serde_json::to_value(sent.complete(BEARER)?)?;
    assert_eq!(
        refused,
        review_required(),
        "a Complete with no Review is refused citing the UETA row"
    );
    assert_eq!(sent.signing_status()?, SigningStatus::Ready);
    assert!(sent.trail("signed")?.is_empty(), "nothing signed");

    // 2. The Review binds the frozen items and the signer's values, and
    //    answers the page.
    assert!(matches!(sent.review(BEARER)?, SigningOutcome::Page(_)));
    let reviewed = sent.trail("reviewed")?;
    assert_eq!(reviewed.len(), 1, "one Review on the trail: {reviewed:?}");
    assert_eq!(reviewed[0]["recipient"], sent.recipient.as_str());
    assert_eq!(reviewed[0]["items"][0]["artifact_ref"], sent.id.to_hex());
    assert_eq!(reviewed[0]["items"][0]["original_version"], 1);
    assert_eq!(
        reviewed[0]["values"][sent.field.as_str()],
        json!({"kind": "text", "value": "Sam Signer"})
    );
    assert_eq!(reviewed[0]["authentication_method"], "bearer");

    // 3. A field saved after the Review voids it: Complete is refused again.
    assert!(matches!(
        sent.save(BEARER, "Sam Q. Signer")?,
        SigningOutcome::Page(_)
    ));
    assert_eq!(
        serde_json::to_value(sent.complete(BEARER)?)?,
        review_required(),
        "a field saved after the Review voids it"
    );
    assert_eq!(sent.signing_status()?, SigningStatus::Ready);

    // 4. An agent's Review does not stand for the person's Complete: the
    //    signer reviews what they sign.
    assert!(matches!(sent.review(AGENT)?, SigningOutcome::Page(_)));
    assert_eq!(
        serde_json::to_value(sent.complete(BEARER)?)?,
        review_required(),
        "a person's Complete needs a person's Review"
    );
    assert_eq!(sent.signing_status()?, SigningStatus::Ready);

    // 5. Review then Complete signs, on the values the last Review bound.
    assert!(matches!(sent.review(BEARER)?, SigningOutcome::Page(_)));
    assert_eq!(sent.complete(BEARER)?, SigningOutcome::AwaitingSeal);
    assert_eq!(sent.signing_status()?, SigningStatus::Completed);
    let reviewed = sent.trail("reviewed")?;
    assert_eq!(
        reviewed.len(),
        3,
        "three Reviews on the trail: {reviewed:?}"
    );
    assert_eq!(reviewed[1]["authentication_method"], "agent");
    assert_eq!(
        reviewed[2]["values"][sent.field.as_str()],
        json!({"kind": "text", "value": "Sam Q. Signer"})
    );
    assert_eq!(sent.trail("signed")?.len(), 1, "one signature");
    Ok(())
}

#[test]
fn held_complete_lands_only_on_its_reviewed_values() -> TestResult {
    let sent = sent()?;
    let page = |outcome: SigningOutcome| matches!(outcome, SigningOutcome::Page(_));

    // 1. Reviewed, Complete held, then a field saved: the review is void,
    //    and the owner's allow lands nothing.
    assert!(page(sent.save(AGENT, "Sam Signer")?));
    assert!(page(sent.review(AGENT)?));
    let first = sent.held()?;
    assert!(page(sent.save(AGENT, "Sam Q. Signer")?));
    let settled = sent.allow(first)?;
    assert!(
        matches!(settled.state, HeldSigningState::Superseded { .. }),
        "a field saved after the held Complete supersedes it: {settled:?}"
    );
    assert!(sent.trail("signed")?.is_empty(), "nothing signed");
    assert_eq!(sent.signing_status()?, SigningStatus::Ready);

    // 2. Held on reviewed values, then other values reviewed with no
    //    Complete after them: the allow lands nothing.
    sent.tick(1);
    assert!(page(sent.review(AGENT)?));
    let second = sent.held()?;
    assert!(page(sent.save(AGENT, "Samuel Signer")?));
    assert!(page(sent.review(AGENT)?));
    let settled = sent.allow(second)?;
    assert!(
        matches!(settled.state, HeldSigningState::Superseded { .. }),
        "a review of other values with no Complete after it supersedes the hold: {settled:?}"
    );
    assert!(sent.trail("signed")?.is_empty(), "nothing signed");

    // 3. Held, then saved, reviewed and completed again: the repeat call
    //    counts on the open hold, and the allow lands on its values.
    sent.tick(2);
    let third = sent.held()?;
    assert!(page(sent.save(AGENT, "Sam Signer")?));
    assert!(page(sent.review(AGENT)?));
    assert_eq!(
        sent.held()?,
        third,
        "a repeat Complete counts on the open hold"
    );
    let settled = sent.allow(third)?;
    assert!(
        matches!(settled.state, HeldSigningState::Allowed { .. }),
        "the hold lands on the values its last call reviewed: {settled:?}"
    );
    assert_eq!(settled.calls, 2);
    assert_eq!(sent.signing_status()?, SigningStatus::Completed);
    assert_eq!(sent.trail("signed")?.len(), 1, "one signature");
    let signatures = sent.vault.esign_document(sent.id)?.signatures;
    assert_eq!(
        signatures[&sent.field].value,
        FieldValue::Text("Sam Signer".into()),
        "signed on the reviewed value"
    );
    Ok(())
}
