//! ROLES-CHECKIN P2.5, row 2k6a (ARCH-0082 #act-table "Legal: prepare and
//! send for signature", #role-defaults and #owner-own-acts; Engine ruling
//! P25-SHAPE Q1 = A, 14 Nov 13:39): `vault.esign.send_for_signature`, a door
//! every bound person reaches, takes the writer judge (2i) before its
//! dispatch.
//!
//! - The Owner's send is never gated: it goes on their own proof, and its
//!   view records that decision. A `check_in_ref` on it is refused as a bad
//!   request and sends nothing.
//! - A Deputy's send goes on their own judgment (`sure`), and its view names
//!   the role and why it went.
//! - An Admin's send waits (the table's Admin cell is "propose"; the door
//!   admits the Admin, so it asks): the door commits the pending check-in
//!   alone, sends nothing and answers `CHECK_IN_PENDING` naming it; a repeat
//!   names the same one, and naming it before the Owner approves sends
//!   nothing. Once approved, the call that names it dispatches, spends it
//!   and its view names it; a retry that names it again is the same send.
//! - A Member's send waits too (no power of its own in the table).
//! - A reminder that names a check-in is refused: only a send checks in.
//!
//! The vault is rooted, and its human binding is the owner's (H149), so each
//! other person sends with the host key bound to them for the call, then the
//! key goes back to the owner (as check_in_mail_compliance_effects.rs does).
//! Each send drafts its own one-recipient document on its own PDF, since a
//! document sends once.
//!
//! On 2k5e (e3fe73eb068) this file does not build: a dispatch request has no
//! `check_in_ref`, and a dispatch view no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_legal_send`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::blob_artifact::esign::{
    DocumentKind, DocumentStatus, EsignAuditActor, EsignDispatchRequest, EsignDispatchView,
    EsignDocument, EsignItem, EsignRecipient, RecipientRole,
};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::check_in::CheckInDecision;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::{
    CHECK_IN_PENDING_REASON_PREFIX, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_CHECK_IN_PENDING,
    MemoryResult,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

const SHARED: u64 = 45;

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
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

struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    deputy: EntityId,
    admin: EntityId,
    member: EntityId,
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
            person(&vault, id);
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

    /// A one-recipient signing document drafted on a PDF of its own, by
    /// its artifact id.
    fn draft(&self) -> EntityId {
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
                id: EntityId::now().to_hex(),
                email: "yuki@example.com".into(),
                name: "Yuki".into(),
                role: RecipientRole::Signer,
                order: 0,
                expires_at,
                principal_ref: None,
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
            .create_esign_document(
                document,
                &draft,
                EsignAuditActor {
                    actor: self.owner.to_hex(),
                    ip: None,
                    user_agent: None,
                },
                now,
            )
            .expect("the draft");
        document
    }

    fn request(document: EntityId, check_in_ref: Option<&str>) -> EsignDispatchRequest {
        EsignDispatchRequest {
            document_ref: document.to_hex(),
            recipient_count: 1,
            on_behalf_of: None,
            idempotency_key: Some(format!("send-{}", document.to_hex())),
            check_in_ref: check_in_ref.map(str::to_owned),
        }
    }

    /// `person`'s call through the host, with the host key bound to them
    /// for a member's call.
    fn as_person<T>(&self, person: EntityId, call: impl FnOnce() -> T) -> T {
        if person == self.owner {
            return call();
        }
        bind_host_actor(&self.vault, &self.issuer, person, "human")
            .expect("the host key bound to the member for their call");
        let answer = call();
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        answer
    }

    /// `person`'s `vault.esign.send_for_signature` of `document`.
    fn send(
        &self,
        person: EntityId,
        document: EntityId,
        check_in_ref: Option<&str>,
    ) -> MemoryResult<EsignDispatchView> {
        let request = Self::request(document, check_in_ref);
        self.as_person(person, || {
            self.vault
                .memory(person, EdgeActorClass::Human)
                .esign_send_for_signature(&request)
        })
    }

    fn status(&self, document: EntityId) -> DocumentStatus {
        self.vault
            .esign_document(document)
            .expect("the document reads")
            .status
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
            "the Owner's approval makes the send eligible: {settled}"
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

/// The check-in a waiting send names.
fn pending_id(result: MemoryResult<EsignDispatchView>) -> String {
    let refused = result.expect_err("the send waits on a check-in");
    assert_eq!(
        refused.code, MEMORY_CODE_CHECK_IN_PENDING,
        "the send waits: {refused:?}"
    );
    refused
        .reason_codes
        .first()
        .and_then(|code| code.strip_prefix(CHECK_IN_PENDING_REASON_PREFIX))
        .expect("the reason code names the check-in")
        .to_owned()
}

fn decision(
    role: &str,
    mode: Option<&str>,
    basis: &str,
    check_in: Option<&str>,
) -> CheckInDecision {
    CheckInDecision {
        act_class: "legal_send".to_owned(),
        role: role.to_owned(),
        mode: mode.map(str::to_owned),
        basis: basis.to_owned(),
        check_in: check_in.map(str::to_owned),
        requester: None,
    }
}

#[test]
fn the_owners_send_goes_on_their_own_proof_and_records_it() {
    let org = Org::new();
    let named = org.draft();
    let refused = org
        .send(org.owner, named, Some(&EntityId::now().to_hex()))
        .expect_err("an Owner's send names no check-in");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    assert_eq!(
        org.status(named),
        DocumentStatus::Draft,
        "the refused send sent nothing"
    );
    let document = org.draft();
    let view = org
        .send(org.owner, document, None)
        .expect("the Owner's send answers");
    assert_eq!(
        view.check_in,
        Some(decision("owner", None, "own_proof", None)),
        "the Owner's send records their own proof: {view:?}"
    );
}

#[test]
fn a_deputys_send_goes_on_their_own_judgment_and_records_why() {
    let org = Org::new();
    let document = org.draft();
    let view = org
        .send(org.deputy, document, None)
        .expect("the Deputy's send answers");
    assert_eq!(
        view.check_in,
        Some(decision("deputy", Some("auto"), "sure", None)),
        "the Deputy's view names the role and why the send went: {view:?}"
    );
}

#[test]
fn an_admins_send_waits_until_the_owner_approves_then_spends_the_check_in() {
    let org = Org::new();
    let document = org.draft();
    let id = pending_id(org.send(org.admin, document, None));
    assert_eq!(
        org.status(document),
        DocumentStatus::Draft,
        "a waiting send sends nothing"
    );
    assert_eq!(
        pending_id(org.send(org.admin, document, None)),
        id,
        "a repeat names the same check-in"
    );
    org.send(org.admin, document, Some(&id))
        .expect_err("an unanswered check-in sends nothing");
    assert_eq!(org.status(document), DocumentStatus::Draft);
    assert!(!org.spent(&id), "an unanswered check-in stays unspent");

    org.owner_approves(&id);
    let view = org
        .send(org.admin, document, Some(&id))
        .expect("the approved send answers");
    let approved = decision("admin", Some("manual"), "approved", Some(&id));
    assert_eq!(
        view.check_in,
        Some(approved.clone()),
        "the view names the check-in the send spent: {view:?}"
    );
    assert!(org.spent(&id), "the send spent its check-in");
    let retry = org
        .send(org.admin, document, Some(&id))
        .expect("a retry of the approved send answers");
    assert_eq!(
        retry.check_in,
        Some(approved),
        "a retry is the same send, on the same check-in: {retry:?}"
    );
}

#[test]
fn a_members_send_waits_on_a_check_in() {
    let org = Org::new();
    let document = org.draft();
    let id = pending_id(org.send(org.member, document, None));
    assert!(!id.is_empty(), "the waiting send names its check-in");
    assert_eq!(
        org.status(document),
        DocumentStatus::Draft,
        "a waiting send sends nothing"
    );
}

#[test]
fn a_reminder_that_names_a_check_in_is_refused() {
    let org = Org::new();
    let document = org.draft();
    let request = Org::request(document, Some(&EntityId::now().to_hex()));
    let refused = org
        .as_person(org.admin, || {
            org.vault
                .memory(org.admin, EdgeActorClass::Human)
                .esign_remind(&request)
        })
        .expect_err("a reminder checks in nowhere");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
}
