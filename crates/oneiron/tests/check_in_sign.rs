//! ROLES-CHECKIN P2.5, row 2k6b (ARCH-0082 #act-table "Sign act (C)", "Sign:
//! anyone signs in their own name. The row is binding the vault's
//! principal."; Engine rulings P25-SHAPE Q1 = A, 14 Nov 13:39, and
//! ESIGN-CHECKIN Q2 and Q3 = A, 14 Nov 17:52): `vault.esign.signing.act`
//! judges a credentialed person's Complete of a recipient whose principal
//! is the vault's own, in the act's writer, and the signature's evidence
//! records the decision.
//!
//! - The Owner signs as the vault's principal on their own proof. A
//!   `check_in_ref` on it is refused and signs nothing.
//! - A Deputy's Complete of the Owner's recipient always asks (the
//!   catastrophe row): it answers `check_in_pending` naming the check-in
//!   and signs nothing; a repeat names the same one, and naming it before the
//!   Owner approves signs nothing. Once approved, the Complete that names it
//!   signs, spends it and its evidence names it.
//! - An Admin's Complete of a recipient whose principal is in the signing
//!   principal set waits too.
//! - A Member completing a recipient whose principal is their own person
//!   signs in their own name: not judged. Nor is a Complete of an outside
//!   recipient (no principal), or a bearer's call of the Owner's recipient.
//!
//! The vault is rooted, and its human binding is the owner's (H149), so each
//! other person calls with the host key bound to them, then the key goes
//! back to the owner. Each case drafts a one-recipient document on its own
//! PDF, mints the recipient's link while it is a draft, and marks it sent.
//!
//! On 2k6a (580209a90a6) this file does not build: a Complete has no
//! `check_in_ref`, an outcome no `CheckInPending`, and a signature's
//! evidence no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_sign`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::blob_artifact::esign::esign_seal_verify_reasons::append_event;
use oneiron::blob_artifact::esign::{
    DocumentKind, EsignAuditActor, EsignDocument, EsignEvent, EsignItem, EsignRecipient,
    EsignSigningRequest, RecipientRole, SigningAction, SigningAutonomy, SigningOutcome,
    SigningPrincipal,
};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::MemoryResult;
use oneiron::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_store::blob_artifact::esign::model::EsignCheckInDecision;
use serde_json::json;

const SHARED: u64 = 46;

fn entity(vault: &Vault, id: EntityId, kind: u8) {
    vault
        .put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, b"human")
        .expect("a live entity");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// `member` accepts its founding invitation to the shared vault at `role`.
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

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

struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    deputy: EntityId,
    admin: EntityId,
    member: EntityId,
}

/// One sent document's single recipient and their signing link.
struct Signing {
    document: EntityId,
    recipient: String,
    token: String,
}

impl Org {
    /// A rooted vault whose shared vault holds the owner, a Deputy, an
    /// Admin and a Member, each of whom accepted.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let [deputy, admin, member] = std::array::from_fn(|_| EntityId::now());
        for id in [deputy, admin, member] {
            entity(&vault, id, ENTITY_TYPE_PERSON);
        }
        let founding = |member_ref, role| InitialSharedMember {
            member_ref,
            role: Some(role),
        };
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[
                    founding(owner, Role::Owner),
                    founding(deputy, Role::Deputy),
                    founding(admin, Role::Admin),
                    founding(member, Role::Member),
                ],
                1,
            )
            .expect("a shared vault with a Deputy, an Admin and a Member");
        accept(&vault, deputy, Role::Deputy);
        accept(&vault, admin, Role::Admin);
        accept(&vault, member, Role::Member);
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            deputy,
            admin,
            member,
        }
    }

    /// A sent one-recipient document on a PDF of its own, whose recipient's
    /// principal is `principal`, with that recipient's signing link.
    fn sent(&self, principal: Option<EntityId>) -> Signing {
        let document = EntityId::now();
        self.vault
            .put_blob_artifact(
                &document,
                &BlobArtifactBody::new("agreement.pdf", "application/pdf"),
                TimeRange { start: 1, end: 1 },
                1,
            )
            .expect("the PDF artifact");
        self.vault
            .append_blob_artifact_version(
                &document,
                original_pdf(),
                &BlobVersionProvenance::UserUpload,
                WriteActor::new(self.owner, EdgeActorClass::Human),
                TimeRange { start: 1, end: 1 },
                1,
            )
            .expect("the PDF's first version");
        let now = self.vault.now_recorded_at();
        let expires_at = now + 3600;
        let recipient = EntityId::now().to_hex();
        let draft = EsignDocument {
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
            recipients: vec![EsignRecipient {
                id: recipient.clone(),
                email: "owen@example.com".into(),
                name: "Owen".into(),
                role: RecipientRole::Signer,
                order: 0,
                expires_at,
                principal_ref: principal.map(|id| id.to_hex()),
                automated: false,
                natural_person: None,
            }],
            fields: Vec::new(),
            full_trail_appendix: false,
            lifecycle: None,
            project: None,
            commitments: Vec::new(),
        };
        self.vault
            .create_esign_document(document, &draft, audit_actor(), now)
            .expect("the draft");
        let token = self
            .vault
            .issue_esign_capabilities(&proof(&self.vault, self.owner), document)
            .expect("the recipient's link")
            .remove(0)
            .1
            .expose_for_delivery()
            .to_owned();
        append_event(&self.vault, document, EsignEvent::Sent, audit_actor(), now)
            .expect("the document is sent");
        Signing {
            document,
            recipient,
            token,
        }
    }

    /// `person`'s Complete of `signing`'s recipient through
    /// `vault.esign.signing.act`, with the host key bound to them for a
    /// member's call.
    fn complete(
        &self,
        person: EntityId,
        signing: &Signing,
        check_in_ref: Option<&str>,
    ) -> MemoryResult<SigningOutcome> {
        let request = EsignSigningRequest {
            token: signing.token.clone(),
            action: SigningAction::Complete {
                consent: true,
                next: None,
                check_in_ref: check_in_ref.map(str::to_owned),
            },
        };
        let call = || {
            self.vault
                .memory(person, EdgeActorClass::Human)
                .esign_signing_act(&request)
        };
        if person == self.owner {
            return call();
        }
        bind_host_actor(&self.vault, &self.issuer, person, "human")
            .expect("the host key bound to the member for their call");
        let answer = call();
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        answer
    }

    /// Whether `signing`'s recipient signed, and the decision its
    /// signature's evidence records.
    fn signed(&self, signing: &Signing) -> Option<Option<EsignCheckInDecision>> {
        self.vault
            .esign_audit(signing.document)
            .expect("the trail reads")
            .into_iter()
            .find_map(|row| match row.event {
                EsignEvent::Signed {
                    recipient,
                    evidence,
                    ..
                } if recipient == signing.recipient => Some(evidence.check_in),
                _ => None,
            })
    }

    /// The Owner approves pending check-in `id` over the effect it waits on,
    /// through `vault.check_in.answer`.
    fn owner_approves(&self, id: &str) {
        let row = self
            .vault
            .pending_check_in(&EntityId::from_hex(id).expect("a check-in id"))
            .expect("read the check-in")
            .expect("the check-in is stored");
        let digest: String = row
            .effect_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let settled = invoke(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            "vault.check_in.answer",
            json!({ "handle": id, "answer": "approve", "effect_digest": digest }),
        )
        .expect("the Owner answers");
        assert_eq!(
            settled["eligible"].as_str(),
            Some("approved"),
            "the Owner's approval makes the sign act eligible: {settled}"
        );
    }

    /// Whether check-in `id` is spent.
    fn spent(&self, id: &str) -> bool {
        self.vault
            .pending_check_in(&EntityId::from_hex(id).expect("a check-in id"))
            .expect("read the check-in")
            .expect("stored")
            .consumed_at
            .is_some()
    }
}

/// The check-in a waiting Complete names.
fn pending_id(outcome: MemoryResult<SigningOutcome>) -> String {
    match outcome.expect("the Complete answers") {
        SigningOutcome::CheckInPending { check_in_ref } => check_in_ref,
        other => panic!("the Complete waits on a check-in: {other:?}"),
    }
}

fn decision(
    role: &str,
    mode: Option<&str>,
    basis: &str,
    check_in: Option<&str>,
) -> EsignCheckInDecision {
    EsignCheckInDecision {
        act_class: "sign".to_owned(),
        role: role.to_owned(),
        mode: mode.map(str::to_owned),
        basis: basis.to_owned(),
        check_in: check_in.map(str::to_owned),
        requester: None,
    }
}

#[test]
fn the_owner_signs_as_the_vaults_principal_on_their_own_proof() {
    let org = Org::new();
    let named = org.sent(Some(org.owner));
    org.complete(org.owner, &named, Some(&EntityId::now().to_hex()))
        .expect_err("the Owner's sign act names no check-in");
    assert_eq!(org.signed(&named), None, "the refused act signed nothing");

    let signing = org.sent(Some(org.owner));
    assert_eq!(
        org.complete(org.owner, &signing, None)
            .expect("the Owner signs"),
        SigningOutcome::AwaitingSeal
    );
    assert_eq!(
        org.signed(&signing),
        Some(Some(decision("owner", None, "own_proof", None))),
        "the signature's evidence records the Owner's own proof"
    );
}

#[test]
fn a_deputys_sign_act_as_the_owner_waits_until_the_owner_approves() {
    let org = Org::new();
    let signing = org.sent(Some(org.owner));
    let id = pending_id(org.complete(org.deputy, &signing, None));
    assert_eq!(org.signed(&signing), None, "a waiting act signs nothing");
    assert_eq!(
        pending_id(org.complete(org.deputy, &signing, None)),
        id,
        "a repeat names the same check-in"
    );
    org.complete(org.deputy, &signing, Some(&id))
        .expect_err("an unanswered check-in signs nothing");
    assert_eq!(org.signed(&signing), None);
    assert!(!org.spent(&id), "an unanswered check-in stays unspent");

    org.owner_approves(&id);
    assert_eq!(
        org.complete(org.deputy, &signing, Some(&id))
            .expect("the approved act signs"),
        SigningOutcome::AwaitingSeal
    );
    assert_eq!(
        org.signed(&signing),
        Some(Some(decision(
            "deputy",
            Some("manual"),
            "approved",
            Some(&id)
        ))),
        "the signature's evidence names the check-in it spent"
    );
    assert!(org.spent(&id), "the sign act spent its check-in");
}

#[test]
fn an_admins_sign_act_for_a_signing_principal_waits() {
    let org = Org::new();
    let company = EntityId::now();
    entity(&org.vault, company, ENTITY_TYPE_ORG);
    org.vault
        .set_signing_principals(
            &proof(&org.vault, org.owner),
            &[SigningPrincipal {
                principal_ref: company.to_hex(),
                autonomy: SigningAutonomy::ScopedRead,
                automated_sign_action: false,
            }],
        )
        .expect("the Owner names the company a signing principal");
    let signing = org.sent(Some(company));
    let id = pending_id(org.complete(org.admin, &signing, None));
    assert!(!id.is_empty(), "the waiting act names its check-in");
    assert_eq!(org.signed(&signing), None, "a waiting act signs nothing");
}

#[test]
fn a_signature_in_the_signers_own_name_is_not_judged() {
    let org = Org::new();
    let own = org.sent(Some(org.member));
    assert_eq!(
        org.complete(org.member, &own, None)
            .expect("the Member signs their own recipient"),
        SigningOutcome::AwaitingSeal
    );
    assert_eq!(
        org.signed(&own),
        Some(None),
        "a signature in the signer's own name records no decision"
    );

    let outside = org.sent(None);
    assert_eq!(
        org.complete(org.deputy, &outside, None)
            .expect("an outside recipient's act signs"),
        SigningOutcome::AwaitingSeal
    );
    assert_eq!(org.signed(&outside), Some(None), "no principal: not judged");

    let bearer = org.sent(Some(org.owner));
    let capability =
        oneiron::blob_artifact::esign::EsignCapability::parse(&bearer.token).expect("the link");
    assert_eq!(
        org.vault
            .execute_signing_action(
                &capability,
                &SigningAction::Complete {
                    consent: true,
                    next: None,
                    check_in_ref: None,
                },
                None,
                None,
            )
            .expect("a bearer signs on the capability alone"),
        SigningOutcome::AwaitingSeal
    );
    assert_eq!(
        org.signed(&bearer),
        Some(None),
        "a bearer's call stays on main's gates"
    );
}
