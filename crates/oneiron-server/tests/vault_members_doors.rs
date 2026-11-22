//! Public-door promise tests for the `vault.members` family: an Admin invites
//! through `vault.members.add`, the invitee lists (`invitations`), accepts
//! (`accept`) or declines (`decline`) on their own credential, an `add_member`
//! holder takes an invitation back (`withdraw_invitation`), an Admin moves a
//! member (`change`) or removes one (`remove`), and a member who is not an
//! Owner leaves (`leave`).
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! `POST /v1/core/facade/<verb>` for the eight verbs. Each case owns its
//! vault: a shared vault whose Owner, Admin and Member were stood by the
//! engine's own creation and founding-accept calls, and every caller holds a
//! live PERSON with a directly minted human credential (the invitee's own
//! independent credential at `accept`, FIX 8745), except the owner on the host
//! root credential and one live person on an agent-class credential. No
//! sleeps, no models, no test doors.
//!
//! The promises, with their canon lines:
//! - an invited person lists and accepts their own invitation, and only
//!   their own (ARCH-0043 member-federation; the invitation's own slip or the
//!   invitee's own independent credential, FIX 8745; the invitee's doors,
//!   FIX 1925);
//! - a Member wields no Admin power (ARCH-0043: Admin "Cannot self-grant
//!   blanket access"; the named-power allowlist, `OrgAdminPower`);
//! - the Owner role is unassignable through these doors and Owners are
//!   untouchable by them (ARCH-0043: "Cannot touch the org root");
//! - Steward and Deputy come only from an Owner (ARCH-0043 Steward;
//!   ARCH-0082 Deputy);
//! - a declined, withdrawn or stranger invitation grants nothing (the Pending
//!   gate of `accept`);
//! - a removal revokes the removed member's slips at admission, and a leave
//!   closes the leaver's membership (FIX 4328 liveness binding);
//! - an agent is refused at all eight doors, and nothing changes (each door
//!   takes a live person's own proof).
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in the PR: `seed_members_faults.py`.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! vault_members_doors`. The test calls no test door; it needs
//! `oneiron/test-support` for `MemoryKeystore`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const ADD: &str = "vault.members.add";
const ACCEPT: &str = "vault.members.accept";
const DECLINE: &str = "vault.members.decline";
const INVITATIONS: &str = "vault.members.invitations";
const WITHDRAW: &str = "vault.members.withdraw_invitation";
const CHANGE: &str = "vault.members.change";
const REMOVE: &str = "vault.members.remove";
const LEAVE: &str = "vault.members.leave";

/// The shared vault every fixture stands, by the id its creation names.
const SHARED: u64 = 43;

/// One credential a test holds: its actor, its holder key, its slip and its
/// token. Each holder signs with a key of its own.
struct Holder {
    actor: EntityId,
    key: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

/// A served vault with a shared vault in it: the owner on the host root
/// credential, a live Admin, Member and agent-class caller on their own
/// minted credentials, and spare live persons for invitees.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner: EntityId,
    admin: Holder,
    member: Holder,
    agent: Holder,
    spares: Vec<Holder>,
}

/// Who sends a request.
#[derive(Clone, Copy, Debug)]
enum Caller {
    /// The owner on the host root credential.
    Owner,
    /// The shared vault's Admin on their own minted human credential.
    Admin,
    /// The shared vault's Member on their own minted human credential.
    Member,
    /// A live person on an agent-class credential.
    Agent,
    /// A spare live person, by index, on their own minted human credential.
    Spare(usize),
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

/// A live PERSON row.
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

/// A person proof, for fixture setup calls only.
fn proof(vault: &Vault, who: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(who, &who.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A credential this host mints `who` at `class`, holding `read` and `write`:
/// a direct mint to their own key, naming no invitation, grant or
/// organization, so a human holder's is their own independent credential.
fn credential(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
    class: &str,
    seed: u8,
) -> Holder {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut claims = vault
        .ensure_host_root_slip(issuer)
        .expect("the host root slip")
        .claims;
    claims.slip_id = [seed; 32];
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some(class.to_owned());
    claims.binding_key = key.verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let slip = vault
        .mint_capability_slip(issuer, claims)
        .expect("a credential");
    let token = slip.to_token().expect("credential token");
    Holder {
        actor: who,
        key,
        slip,
        token,
    }
}

/// A self-hosted served vault on the wall clock, with a shared vault whose
/// Admin and Member accepted their founding invitations.
async fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-members-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault
        .bootstrap_host_slip_issuer()
        .expect("host slip issuer");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the owner's PERSON");
    let admin_person = EntityId::now();
    person(&vault, admin_person);
    let member_person = EntityId::now();
    person(&vault, member_person);
    let agent_person = EntityId::now();
    person(&vault, agent_person);
    let owner_proof = proof(&vault, owner);
    let row = |member_ref, role| InitialSharedMember {
        member_ref,
        role: Some(role),
    };
    vault
        .initialize_shared_vault(
            &owner_proof,
            SHARED,
            None,
            &[
                row(owner, Role::Owner),
                row(admin_person, Role::Admin),
                row(member_person, Role::Member),
            ],
            1,
        )
        .expect("a shared vault with an Admin and a Member");
    for (who, role) in [(admin_person, Role::Admin), (member_person, Role::Member)] {
        let member_proof = proof(&vault, who);
        let invitation = vault
            .shared_invitations(&member_proof, SHARED)
            .expect("founding invitations")
            .into_iter()
            .find(|open| open.role == role)
            .expect("the founding invitation");
        vault
            .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
            .expect("the founding member accepts");
    }
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    let app = build_app(server);
    let admin = credential(&vault, &issuer, admin_person, "human", 0xA1);
    let member = credential(&vault, &issuer, member_person, "human", 0xB2);
    let agent = credential(&vault, &issuer, agent_person, "agent", 0xC3);
    let mut spares = Vec::new();
    for seed in [0xD1, 0xD2, 0xD3, 0xD4] {
        let who = EntityId::now();
        person(&vault, who);
        spares.push(credential(&vault, &issuer, who, "human", seed));
    }
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        owner,
        admin,
        member,
        agent,
        spares,
    }
}

impl Served {
    fn holder(&self, caller: Caller) -> Option<&Holder> {
        match caller {
            Caller::Owner => None,
            Caller::Admin => Some(&self.admin),
            Caller::Member => Some(&self.member),
            Caller::Agent => Some(&self.agent),
            Caller::Spare(index) => Some(&self.spares[index]),
        }
    }

    /// The request binding `caller` proves afresh for one request: the owner
    /// through the host issuer, anyone else through their own holder key.
    fn binding(&self, caller: Caller) -> String {
        match self.holder(caller) {
            None => {
                let timestamp = self.vault.now_recorded_at();
                let nonce = EntityId::now().to_hex();
                let challenge = format!("oneiron-request:{timestamp}:{nonce}");
                let signature = hex(&self
                    .issuer
                    .binding_proof(&self.owner_slip, challenge.as_bytes())
                    .expect("owner holder proof"));
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
            }
            Some(holder) => holder_proof(&holder.slip, &holder.key, self.vault.now_recorded_at())
                .expect("holder proof")
                .to_string(),
        }
    }

    fn token(&self, caller: Caller) -> &str {
        match self.holder(caller) {
            None => self.owner_token.as_str(),
            Some(holder) => holder.token.as_str(),
        }
    }

    /// `caller` sends `method` to `uri` with an optional JSON `body`: the
    /// status and the body.
    async fn send(
        &self,
        caller: Caller,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", self.token(caller)))
            .header("x-oneiron-binding", self.binding(caller));
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .expect("response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// `caller` posts `verb` with `input` to its facade door.
    async fn post(&self, caller: Caller, verb: &str, input: Value) -> (StatusCode, Value) {
        self.send(
            caller,
            Method::POST,
            &format!("/v1/core/facade/{verb}"),
            Some(input),
        )
        .await
    }

    /// `caller` posts `verb` and expects a 200: the answer.
    async fn ok(&self, caller: Caller, verb: &str, input: Value) -> Value {
        let (status, body) = self.post(caller, verb, input).await;
        assert_eq!(status, StatusCode::OK, "{caller:?} at {verb}: {body}");
        body
    }

    /// The Admin invites `invitee` at `role`: the invitation id.
    async fn invite(&self, invitee: &str, role: &str) -> String {
        let receipt = self
            .ok(
                Caller::Admin,
                ADD,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": invitee,
                    "role": role,
                }),
            )
            .await;
        let invited = &receipt["change"]["member_invited"];
        assert_eq!(invited["member"], invitee, "{receipt}");
        assert_eq!(invited["role"], role, "{receipt}");
        invited["invitation"]
            .as_str()
            .expect("invitation id")
            .to_owned()
    }

    /// `caller`'s pending invitations in the shared vault.
    async fn invitations(&self, caller: Caller) -> Vec<Value> {
        self.ok(caller, INVITATIONS, json!({"vault_id": SHARED.to_string()}))
            .await
            .as_array()
            .expect("an invitations list")
            .clone()
    }
}

/// An Admin invites a live person, who lists their own pending invitation and
/// accepts it on their own credential. (Door: the invitee's own proof admits;
/// the invitation is spent.)
#[test]
fn admin_invites_member_who_lists_and_accepts() {
    run_on_engine_stack("members-invite-accept", || async {
        let served = served().await;
        let invitee = served.spares[0].actor.to_hex();
        let invitation = served.invite(&invitee, "member").await;

        let listed = served.invitations(Caller::Spare(0)).await;
        assert_eq!(listed.len(), 1, "the invitee lists one: {listed:?}");
        assert_eq!(listed[0]["id"], invitation, "{listed:?}");
        assert_eq!(listed[0]["invitee"], invitee, "{listed:?}");
        assert_eq!(listed[0]["role"], "member", "{listed:?}");
        assert_eq!(listed[0]["state"], "pending", "{listed:?}");

        let receipt = served
            .ok(
                Caller::Spare(0),
                ACCEPT,
                json!({
                    "vault_id": SHARED.to_string(),
                    "invitation": invitation.clone(),
                }),
            )
            .await;
        let accepted = &receipt["change"]["invitation_accepted"];
        assert_eq!(accepted["invitation"], invitation, "{receipt}");
        assert_eq!(accepted["member"], invitee, "{receipt}");
        assert_eq!(accepted["role"], "member", "{receipt}");

        let listed = served.invitations(Caller::Spare(0)).await;
        assert!(
            listed.is_empty(),
            "the spent invitation lists no more: {listed:?}"
        );
    });
}

/// A Member is refused at each Admin power: add, change, remove and
/// withdraw_invitation. (P1+P3: the named-power allowlist; roles decide verbs.)
#[test]
fn member_cannot_wield_admin_powers() {
    run_on_engine_stack("members-no-admin-powers", || async {
        let served = served().await;
        let target = served.spares[0].actor.to_hex();
        let invitation = served.invite(&target, "member").await;
        let admin_hex = served.admin.actor.to_hex();
        let doors = [
            (
                ADD,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": served.spares[1].actor.to_hex(),
                    "role": "member",
                }),
            ),
            (
                CHANGE,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": admin_hex.clone(),
                    "role": "viewer",
                }),
            ),
            (
                REMOVE,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": admin_hex.clone(),
                }),
            ),
            (
                WITHDRAW,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": target.clone(),
                    "invitation": invitation.clone(),
                }),
            ),
        ];
        for (verb, input) in doors {
            let (status, body) = served.post(Caller::Member, verb, input).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "a Member at {verb}: {body}");
            assert_eq!(
                error_code(&body),
                Some("FORBIDDEN"),
                "a Member at {verb}: {body}"
            );
        }

        let listed = served.invitations(Caller::Spare(0)).await;
        assert_eq!(listed.len(), 1, "the invitation stands: {listed:?}");
        assert_eq!(listed[0]["id"], invitation, "{listed:?}");
    });
}

/// The Owner role is unassignable through these doors, and Owners are
/// untouchable by them: add and change at Owner, change and remove of the
/// Owner, and the Owner's own leave are all refused. (P1+P2: the org root is
/// untouchable.)
#[test]
fn root_role_is_unassignable_and_owners_untouchable() {
    run_on_engine_stack("members-owners-untouchable", || async {
        let served = served().await;
        let owner_hex = served.owner.to_hex();
        let member_hex = served.member.actor.to_hex();
        let spare_hex = served.spares[0].actor.to_hex();
        let doors = [
            (
                "add at Owner",
                Caller::Admin,
                ADD,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": spare_hex.clone(),
                    "role": "owner",
                }),
            ),
            (
                "change to Owner",
                Caller::Admin,
                CHANGE,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": member_hex.clone(),
                    "role": "owner",
                }),
            ),
            (
                "change of the Owner",
                Caller::Admin,
                CHANGE,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": owner_hex.clone(),
                    "role": "member",
                }),
            ),
            (
                "remove of the Owner",
                Caller::Admin,
                REMOVE,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": owner_hex.clone(),
                }),
            ),
            (
                "the Owner's leave",
                Caller::Owner,
                LEAVE,
                json!({"vault_id": SHARED.to_string()}),
            ),
        ];
        for (what, caller, verb, input) in doors {
            let (status, body) = served.post(caller, verb, input).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {body}");
            assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{what}: {body}");
        }
    });
}

/// Steward and Deputy come only from an Owner: an Admin's add and change at
/// either are refused, while the Owner's add at Steward goes. (P2: no blanket
/// self-grant.)
#[test]
fn steward_and_deputy_need_an_owner() {
    run_on_engine_stack("members-reserved-roles", || async {
        let served = served().await;
        let spare_hex = served.spares[0].actor.to_hex();
        let member_hex = served.member.actor.to_hex();
        for role in ["steward", "deputy"] {
            let (status, body) = served
                .post(
                    Caller::Admin,
                    ADD,
                    json!({
                        "vault_id": SHARED.to_string(),
                        "member": spare_hex.clone(),
                        "role": role,
                    }),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "an Admin adds at {role}: {body}"
            );
            assert_eq!(
                error_code(&body),
                Some("FORBIDDEN"),
                "an Admin adds at {role}: {body}"
            );
            let (status, body) = served
                .post(
                    Caller::Admin,
                    CHANGE,
                    json!({
                        "vault_id": SHARED.to_string(),
                        "member": member_hex.clone(),
                        "role": role,
                    }),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "an Admin changes to {role}: {body}"
            );
            assert_eq!(
                error_code(&body),
                Some("FORBIDDEN"),
                "an Admin changes to {role}: {body}"
            );
        }

        let invitee = served.spares[1].actor.to_hex();
        let receipt = served
            .ok(
                Caller::Owner,
                ADD,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": invitee.clone(),
                    "role": "steward",
                }),
            )
            .await;
        let invitation = receipt["change"]["member_invited"]["invitation"]
            .as_str()
            .expect("invitation id")
            .to_owned();
        let receipt = served
            .ok(
                Caller::Spare(1),
                DECLINE,
                json!({
                    "vault_id": SHARED.to_string(),
                    "invitation": invitation.clone(),
                }),
            )
            .await;
        assert_eq!(
            receipt["change"]["invitation_declined"]["invitation"], invitation,
            "{receipt}"
        );
    });
}

/// A declined invitation is gone, a withdrawn one no longer admits, and a
/// stranger's acceptance of another's invitation is refused. (Door: only a
/// pending invitation of one's own grants.)
#[test]
fn invitation_lifecycle_decline_withdraw_and_stranger() {
    run_on_engine_stack("members-invitation-lifecycle", || async {
        let served = served().await;
        let first = served.spares[0].actor.to_hex();
        let invitation = served.invite(&first, "member").await;
        let receipt = served
            .ok(
                Caller::Spare(0),
                DECLINE,
                json!({
                    "vault_id": SHARED.to_string(),
                    "invitation": invitation.clone(),
                }),
            )
            .await;
        let declined = &receipt["change"]["invitation_declined"];
        assert_eq!(declined["invitation"], invitation, "{receipt}");
        assert_eq!(declined["member"], first, "{receipt}");
        let listed = served.invitations(Caller::Spare(0)).await;
        assert!(
            listed.is_empty(),
            "a declined invitation is gone: {listed:?}"
        );

        let second = served.spares[1].actor.to_hex();
        let invitation = served.invite(&second, "member").await;
        let receipt = served
            .ok(
                Caller::Admin,
                WITHDRAW,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": second.clone(),
                    "invitation": invitation.clone(),
                }),
            )
            .await;
        let withdrawn = &receipt["change"]["invitation_withdrawn"];
        assert_eq!(withdrawn["invitation"], invitation, "{receipt}");
        assert_eq!(withdrawn["member"], second, "{receipt}");
        let (status, body) = served
            .post(
                Caller::Spare(1),
                ACCEPT,
                json!({
                    "vault_id": SHARED.to_string(),
                    "invitation": invitation.clone(),
                }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "accept after withdraw: {body}"
        );
        assert_eq!(
            error_code(&body),
            Some("BAD_REQUEST"),
            "accept after withdraw: {body}"
        );

        let third = served.spares[2].actor.to_hex();
        let invitation = served.invite(&third, "member").await;
        let (status, body) = served
            .post(
                Caller::Member,
                ACCEPT,
                json!({
                    "vault_id": SHARED.to_string(),
                    "invitation": invitation.clone(),
                }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a stranger accepts: {body}"
        );
        assert_eq!(
            error_code(&body),
            Some("BAD_REQUEST"),
            "a stranger accepts: {body}"
        );
        let receipt = served
            .ok(
                Caller::Spare(2),
                ACCEPT,
                json!({
                    "vault_id": SHARED.to_string(),
                    "invitation": invitation.clone(),
                }),
            )
            .await;
        assert_eq!(
            receipt["change"]["invitation_accepted"]["member"], third,
            "the stranger consumed nothing: {receipt}"
        );
    });
}

/// An Admin's removal revokes the removed member's slips, so the old
/// credential is refused at admission, and a member's own leave closes their
/// membership. (P2+Door: removal ends standing; leave is a member's own act.)
#[test]
fn remove_revokes_slips_and_leave_closes_membership() {
    run_on_engine_stack("members-remove-leave", || async {
        let served = served().await;
        let member_hex = served.member.actor.to_hex();
        let receipt = served
            .ok(
                Caller::Admin,
                REMOVE,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": member_hex.clone(),
                }),
            )
            .await;
        assert_eq!(
            receipt["change"]["member_removed"]["member"], member_hex,
            "{receipt}"
        );
        let revoked = receipt["revoked_slips"].as_array().expect("revoked slips");
        assert!(
            !revoked.is_empty(),
            "the removal revokes the member's slips: {receipt}"
        );

        let (status, body) = served
            .post(
                Caller::Member,
                INVITATIONS,
                json!({"vault_id": SHARED.to_string()}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the removed member's old credential: {body}"
        );
        assert_eq!(
            error_code(&body),
            Some("UNAUTHORIZED"),
            "the removed member's old credential: {body}"
        );

        let leaver = served.spares[0].actor.to_hex();
        let invitation = served.invite(&leaver, "member").await;
        served
            .ok(
                Caller::Spare(0),
                ACCEPT,
                json!({
                    "vault_id": SHARED.to_string(),
                    "invitation": invitation.clone(),
                }),
            )
            .await;
        let receipt = served
            .ok(
                Caller::Spare(0),
                LEAVE,
                json!({"vault_id": SHARED.to_string()}),
            )
            .await;
        assert_eq!(
            receipt["change"]["member_left"]["member"], leaver,
            "{receipt}"
        );
    });
}

/// An agent is refused at all eight doors on a live person's proof, and
/// nothing changes: the seeded invitation still lists and still accepts.
/// (Door: membership is a live person's own act.)
#[test]
fn agent_is_refused_at_all_eight_member_doors() {
    run_on_engine_stack("members-agent-refused", || async {
        let served = served().await;
        let invitee = served.spares[0].actor.to_hex();
        let invitation = served.invite(&invitee, "member").await;
        let member_hex = served.member.actor.to_hex();
        let doors = [
            (
                ADD,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": served.spares[1].actor.to_hex(),
                    "role": "member",
                }),
            ),
            (
                CHANGE,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": member_hex.clone(),
                    "role": "viewer",
                }),
            ),
            (
                REMOVE,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": member_hex.clone(),
                }),
            ),
            (LEAVE, json!({"vault_id": SHARED.to_string()})),
            (INVITATIONS, json!({"vault_id": SHARED.to_string()})),
            (
                ACCEPT,
                json!({
                    "vault_id": SHARED.to_string(),
                    "invitation": invitation.clone(),
                }),
            ),
            (
                DECLINE,
                json!({
                    "vault_id": SHARED.to_string(),
                    "invitation": invitation.clone(),
                }),
            ),
            (
                WITHDRAW,
                json!({
                    "vault_id": SHARED.to_string(),
                    "member": invitee.clone(),
                    "invitation": invitation.clone(),
                }),
            ),
        ];
        for (verb, input) in doors {
            let (status, body) = served.post(Caller::Agent, verb, input).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "an agent at {verb}: {body}");
            assert_eq!(
                error_code(&body),
                Some("FORBIDDEN"),
                "an agent at {verb}: {body}"
            );
            let message = body["error"]["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("live person's own act"),
                "an agent at {verb}: {body}"
            );
        }

        let listed = served.invitations(Caller::Spare(0)).await;
        assert_eq!(listed.len(), 1, "the invitation stands: {listed:?}");
        assert_eq!(listed[0]["id"], invitation, "{listed:?}");
        let receipt = served
            .ok(
                Caller::Spare(0),
                ACCEPT,
                json!({
                    "vault_id": SHARED.to_string(),
                    "invitation": invitation.clone(),
                }),
            )
            .await;
        assert_eq!(
            receipt["change"]["invitation_accepted"]["role"], "member",
            "the agent consumed nothing: {receipt}"
        );
    });
}

/// Each invitee lists only their own pending invitations. (P2: invitations
/// name only the caller's own membership rows.)
#[test]
fn invitations_list_only_the_callers_own() {
    run_on_engine_stack("members-own-invitations", || async {
        let served = served().await;
        let first = served.spares[0].actor.to_hex();
        let second = served.spares[1].actor.to_hex();
        let first_invitation = served.invite(&first, "member").await;
        let second_invitation = served.invite(&second, "viewer").await;

        let listed = served.invitations(Caller::Spare(0)).await;
        assert_eq!(listed.len(), 1, "the first invitee lists one: {listed:?}");
        assert_eq!(listed[0]["id"], first_invitation, "{listed:?}");
        assert_eq!(listed[0]["role"], "member", "{listed:?}");

        let listed = served.invitations(Caller::Spare(1)).await;
        assert_eq!(listed.len(), 1, "the second invitee lists one: {listed:?}");
        assert_eq!(listed[0]["id"], second_invitation, "{listed:?}");
        assert_eq!(listed[0]["role"], "viewer", "{listed:?}");
    });
}
