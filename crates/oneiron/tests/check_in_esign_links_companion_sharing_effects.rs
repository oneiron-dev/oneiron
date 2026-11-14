//! ROLES-CHECKIN P2.5, row 2k8e2 (ARCH-0082 #act-table "Widen another's
//! grant" and #owner-own-acts; Engine rulings P25-SHAPE Q1 = A, 14 Nov
//! 13:39, and P25-2K8-SCOPE Q1 = A, 19:32): two Owner-proof doors take the
//! 2j apply shape, `vault.esign.links.issue` and
//! `vault.companions.sharing.set`.
//!
//! - The Owner's act is never gated: it goes on their own proof, and the
//!   answer records that decision.
//! - The Owner applies another asker's approved check-in for that exact
//!   act: the act's writer spends it, and the answer names it and its
//!   asker. An approval for another act changes nothing and stays unspent.
//! - A link issue pins the draft's recipients: an approval asked over
//!   another recipient list applies to none. An issue that mints no link
//!   (every recipient still holds a usable one) records no decision.
//! - A sharing yes settles one frozen clearance offer an agent filed for a
//!   contact of the team lead's model PERSON (seeded on open); a refused
//!   yes leaves the offer unsettled and the contact uncleared.
//!
//! On its base, 2k8e's head, this file does not build: neither request has
//! a `check_in_ref`, and neither answer a `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_esign_links_companion_sharing_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::blob_artifact::esign::{
    DocumentKind, EsignAuditActor, EsignDocument, EsignItem, EsignLinksIssueRequest,
    EsignLinksView, EsignRecipient, RecipientRole, esign_links_issue_effect_digest,
};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::check_in::ActClass;
use oneiron::consent::{AuthenticatedOwner, ContactDisclosureOffer};
use oneiron::counterparty_contact::{CounterpartyContactRecord, CounterpartyContactStatus};
use oneiron::disclosure::DisclosureScopeStatus;
use oneiron::federation::Scope;
use oneiron::memory::MemoryResult;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::subject_model::PersonSubstrate;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{CompanionSharingSetRequest, companion_sharing_set_effect_digest};
use oneiron::workspace_roster::CompanionSharingView;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, WriteActor};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}

fn audit_actor() -> EsignAuditActor {
    EsignAuditActor {
        actor: "fixture".into(),
        ip: None,
        user_agent: None,
    }
}

/// A drafted two-recipient document on a PDF of its own: its id and its
/// recipients' ids, in the draft's order.
fn draft(vault: &Vault, owner: EntityId) -> (EntityId, Vec<String>) {
    let document = EntityId::now();
    vault
        .put_blob_artifact(
            &document,
            &BlobArtifactBody::new("agreement.pdf", "application/pdf"),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("the PDF artifact");
    vault
        .append_blob_artifact_version(
            &document,
            original_pdf(),
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(owner, EdgeActorClass::Human),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("the PDF's first version");
    let now = vault.now_recorded_at();
    let expires_at = now + 3600;
    let recipients: Vec<String> = (0..2).map(|_| EntityId::now().to_hex()).collect();
    let recipient = |order: usize, name: &str, email: &str| EsignRecipient {
        id: recipients[order].clone(),
        email: email.into(),
        name: name.into(),
        role: RecipientRole::Signer,
        order: u32::try_from(order).expect("a small order"),
        expires_at,
        principal_ref: None,
        automated: false,
        natural_person: None,
    };
    let body = EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Services agreement".into(),
        sequential: false,
        expires_at,
        token_expires_at: None,
        items: vec![EsignItem {
            artifact_ref: document.to_hex(),
            original_version: 1,
        }],
        recipients: vec![
            recipient(0, "Owen", "owen@example.com"),
            recipient(1, "Yuki", "yuki@example.com"),
        ],
        fields: Vec::new(),
        full_trail_appendix: false,
        lifecycle: None,
        project: None,
        commitments: Vec::new(),
    };
    vault
        .create_esign_document(document, &body, audit_actor(), now)
        .expect("the draft");
    (document, recipients)
}

/// The Owner's `vault.esign.links.issue` on `document`, applying
/// `check_in` when given.
fn issue(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    document: EntityId,
    rotate: bool,
    check_in: Option<EntityId>,
) -> MemoryResult<EsignLinksView> {
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .esign_links_issue(&EsignLinksIssueRequest {
            document_ref: document.to_hex(),
            rotate,
            check_in_ref: check_in.map(|id| id.to_hex()),
        })
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_link_issue_only() {
    let (_dir, vault, owner, owner_proof) = rooted();

    let (own_document, _) = draft(&vault, owner);
    let own = issue(&vault, owner, &owner_proof, own_document, false, None)
        .expect("the Owner mints the draft's links");
    assert_eq!(own.issued.len(), 2, "each recipient gets a link");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own issue records their own proof"
    );
    let repeat = issue(&vault, owner, &owner_proof, own_document, false, None)
        .expect("the Owner repeats the issue");
    assert!(repeat.issued.is_empty(), "every link still holds");
    assert_eq!(repeat.unchanged.len(), 2, "both recipients keep theirs");
    assert_eq!(
        repeat.check_in, None,
        "an issue that mints none records none"
    );

    let (asked_document, recipients) = draft(&vault, owner);
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.esign.links.issue",
        ActClass::GrantWiden,
        &esign_links_issue_effect_digest(asked_document, false, &recipients),
    );

    let (other_document, _) = draft(&vault, owner);
    let refused = issue(
        &vault,
        owner,
        &owner_proof,
        other_document,
        false,
        Some(check_in),
    );
    assert!(
        refused.is_err(),
        "the approval covers the document it was asked for only; seen {refused:?}"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );
    let other = issue(&vault, owner, &owner_proof, other_document, false, None)
        .expect("the Owner's own issue on the other draft");
    assert_eq!(
        other.issued.len(),
        2,
        "the refused call minted no link on the other draft"
    );

    let (stale, _) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.esign.links.issue",
        ActClass::GrantWiden,
        &esign_links_issue_effect_digest(asked_document, false, &recipients[..1]),
    );
    let refused = issue(
        &vault,
        owner,
        &owner_proof,
        asked_document,
        false,
        Some(stale),
    );
    assert!(
        refused.is_err(),
        "an approval asked over other recipients applies to none; seen {refused:?}"
    );
    assert!(!spent(&vault, &stale), "a refused call leaves it unspent");

    let applied = issue(
        &vault,
        owner,
        &owner_proof,
        asked_document,
        false,
        Some(check_in),
    )
    .expect("the Owner applies the approved ask");
    assert_eq!(
        applied.issued.len(),
        2,
        "the refused call minted no link, so the applied one mints both"
    );
    assert!(spent(&vault, &check_in), "the issue spent the check-in");
    assert_eq!(
        applied.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the applied check-in and its asker"
    );
}

/// The seeded team lead's model PERSON: a companion no onboarding claimed.
fn model_companion(vault: &Vault) -> EntityId {
    let (team_lead, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")
        .expect("the seeded team lead reads")
        .expect("the team lead is seeded on open");
    let companion = vault
        .actor_subject_anchor(&team_lead, vault.now_recorded_at())
        .expect("the team lead's anchor reads")
        .expect("the team lead holds a subject anchor")
        .subject_ref;
    assert_eq!(
        vault
            .person_substrate(&companion, vault.now_recorded_at())
            .expect("the substrate reads"),
        Some(PersonSubstrate::Model),
        "the anchored subject is the team lead's model PERSON"
    );
    companion
}

/// A new active contact `counterparty` and one frozen clearance offer for it
/// that `offerer` filed: the Owner's sharing request for that offer, with no
/// `check_in_ref`.
fn offered(
    vault: &Vault,
    owner: EntityId,
    companion: EntityId,
    offerer: EntityId,
    counterparty: &str,
) -> CompanionSharingSetRequest {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("the contact's PERSON");
    let contact = EntityId::now();
    vault
        .create_counterparty_contact(
            &contact,
            &CounterpartyContactRecord::public(person, counterparty, vault.now_recorded_at())
                .expect("a public contact"),
        )
        .expect("the contact");
    assert_eq!(
        vault
            .get_counterparty_contact(&contact)
            .expect("the contact reads")
            .expect("stored")
            .status,
        CounterpartyContactStatus::Active,
        "a new contact is active"
    );
    let proposal = vault
        .offer_contact_disclosure_as_engine(
            WriteActor::new(offerer, EdgeActorClass::Agent),
            ContactDisclosureOffer {
                contact_ref: contact,
                scope: Scope::top(),
                purpose: "Share context with this contact".to_owned(),
                channel: "email".to_owned(),
                beneficiary_ref: contact.to_hex(),
                ask_ref: None,
            },
            &owner.to_hex(),
            vault.now_recorded_at() + 1800,
        )
        .expect("the agent files one frozen clearance offer");
    let request = CompanionSharingSetRequest {
        companion_ref: companion.to_hex(),
        contact_ref: contact.to_hex(),
        proposal_ref: proposal.proposal_ref,
        expected_delta: proposal
            .canonical_delta
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        check_in_ref: None,
    };
    assert_eq!(
        request.delta().expect("the delta decodes"),
        proposal.canonical_delta
    );
    request
}

/// The Owner's `vault.companions.sharing.set` for `request`, applying
/// `check_in` when given.
fn share(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    request: &CompanionSharingSetRequest,
    check_in: Option<EntityId>,
) -> MemoryResult<CompanionSharingView> {
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .companion_sharing_set(&CompanionSharingSetRequest {
            check_in_ref: check_in.map(|id| id.to_hex()),
            ..request.clone()
        })
}

/// Whether `request`'s contact holds an active, top clearance.
fn cleared(vault: &Vault, request: &CompanionSharingSetRequest) -> bool {
    let contact = request.target().expect("the target parses").contact;
    vault
        .counterparty_disclosure_scope(&contact)
        .expect("the clearance reads")
        .is_some_and(|clearance| {
            clearance.status == DisclosureScopeStatus::Active && clearance.scope == Scope::top()
        })
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_companion_sharing_yes_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let companion = model_companion(&vault);
    let offerer = define_agent(&vault, "clearance-offerer").expect("an agent definition");
    let own = offered(&vault, owner, companion, offerer, "owen@example.com");
    let asked = offered(&vault, owner, companion, offerer, "yuki@example.com");
    let other = offered(&vault, owner, companion, offerer, "noor@example.com");

    let own_view = share(&vault, owner, &owner_proof, &own, None).expect("the Owner's own yes");
    assert_eq!(
        own_view.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own yes records their own proof"
    );
    assert!(cleared(&vault, &own), "the own yes stands");

    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.companions.sharing.set",
        ActClass::GrantWiden,
        &companion_sharing_set_effect_digest(&asked).expect("the yes's digest"),
    );
    let refused = share(&vault, owner, &owner_proof, &other, Some(check_in));
    assert!(
        refused.is_err(),
        "the approval covers the offer it was asked for only; seen {refused:?}"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );
    assert!(!cleared(&vault, &other), "the refused call cleared nothing");
    let other_view = share(&vault, owner, &owner_proof, &other, None)
        .expect("the refused call left the other offer unsettled");
    assert_eq!(
        other_view.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own yes on the other offer records their own proof"
    );

    let applied = share(&vault, owner, &owner_proof, &asked, Some(check_in))
        .expect("the Owner applies the approved ask");
    assert!(cleared(&vault, &asked), "the asked-for yes stands");
    assert!(spent(&vault, &check_in), "the yes spent the check-in");
    assert_eq!(
        applied.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the applied check-in and its asker"
    );
}
