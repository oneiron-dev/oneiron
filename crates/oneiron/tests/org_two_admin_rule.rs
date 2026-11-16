//! UNBUILT-06 PR 2, the org two-admin rule (canon identity.md:223, ORG-1 A;
//! lead ORG-TWO-ADMIN-SCOPE 15 Nov 20:1x; Engine RULING UNBUILT06-SHAPE
//! 20:51, Q1, Q2 and Q4 = A).
//!
//! - Off by default: an Admin's add goes at once. An Owner turns the rule on
//!   with the `org.two_admin` Setting key.
//! - On: an Admin's or a Deputy's power act is held. Nothing runs; the door
//!   stores the act as written (verb, input, first admin) and asks each other
//!   live Owner, Admin and Deputy in the inbox, and the call answers
//!   `ADMIN_ACT_HELD` with the reason code `admin_act:<id>`.
//! - A second, distinct live admin's approve re-runs the stored verb under
//!   the approver's own proof: the act lands, and its receipt names the
//!   approver as `actor` and the first admin as `proposer`. The invitee of a
//!   held add then accepts as usual: the accept is the invitee's act.
//! - An Owner's own act is never held.
//! - The first admin cannot approve their own act, and a Member cannot
//!   approve one; the first admin may withdraw it while it waits.
//! - A held act lapses after `org.two_admin_lapse_secs` (default 7 days):
//!   the housekeeping pass marks it lapsed and tells the first admin, and a
//!   lapsed act no longer lands.
//!
//! The Sol review of #8482 (legs/review-8482) added five:
//! - A held delegate mint lands on a second admin's approve: the delegate is
//!   minted from the first admin's parent grant under the approver's proof.
//! - An approve cut short after its re-run's write (a crash before its
//!   settle) has landed the act already: the write lands it, and its receipt
//!   names the first admin as `first_admin`.
//! - An approve cut short before its write leaves the act approving, and the
//!   housekeeping pass lapses it with the notice: it never ran.
//! - An Admin's lone admin ruling refuses with the hold's reason while the
//!   rule is on (no held verb fronts it); an Owner's goes.
//! - An Admin's held Steward add never lands, even on an Owner's approve: an
//!   approval lifts only the rule, and the Steward role is an Owner's to give.
//!
//! The Astra review of #8482 (lanes/engine-tools/astra-reviews/
//! unbuilt-b1c-8482-two-admin) added seven:
//! - H1: an Admin's `vault.delete` of a Member's NOTE refuses with the hold's
//!   reason while the rule is on; the Admin's own NOTE and an Owner's delete
//!   still go.
//! - H2: a Deputy's remove asks an Owner first (the Deputy's own check-in
//!   comes before the rule); once approved, the call with its ref is held, and
//!   a second admin's approve spends the Deputy's check-in as it lands.
//! - H2: a held act whose first admin an Owner removed lands no more.
//! - H3: an approve claimed before `lapses_at` whose re-run reaches its write
//!   after it lands nothing.
//! - H4: `org.two_admin_lapse_secs` refuses a value above 90 days.
//! - H5: a hard erase of the first admin scrubs `first_admin` from the
//!   receipt of their approved act.
//! - H7: a first admin an Owner removed cannot withdraw their act.
//!
//! The Astra delta review (astra-reviews/unbuilt-b1c-8482-delta) added two:
//! - D3: a held act lands no more once an Owner's role move took its first
//!   admin's named power (a holder row narrows what they hold at the new
//!   role), though they still stand as an admin.
//! - D4: a landing check past `lapses_at` refuses, whatever time its writer
//!   read before it.
//!
//! On the base (#8259, a2cb32313b0) this file does not build: there is no
//! `org.two_admin` key, no `MEMORY_CODE_ADMIN_ACT_HELD` and no held-act
//! verbs.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test org_two_admin_rule`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrantRole as Role, HeldAdminAct, HeldAdminActStatus, InitialSharedMember,
    NOTIFICATION_PRODUCER_ADMIN_ACT_HELD, NOTIFICATION_PRODUCER_ADMIN_ACT_LAPSED, Scope,
    SharedActExecutionReceipt,
};
use oneiron::inbox::{NotificationBody, NotificationKind, decode_notification_body};
use oneiron::memory::{
    ADMIN_ACT_HELD_REASON_PREFIX, CHECK_IN_PENDING_REASON_PREFIX, MEMORY_CODE_ADMIN_ACT_HELD,
    MEMORY_CODE_CHECK_IN_PENDING, MemoryError, MemoryResult, SafeDeleteReason,
    TWO_ADMIN_HOLD_REASON_CODE,
};
use oneiron::note::TakeTarget;
use oneiron::registry::{
    ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_PERSON,
};
use oneiron::setting::{SetSetting, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::held_admin_act as cut_short;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::verbs::{
    FederationDelegateRequest, HeldAdminActRequest, SharedMemberAddRequest,
    SharedMemberRemoveRequest, SharedMemberRoleRequest, add_shared_member_as,
    approve_held_admin_act_as, change_shared_member_as, create_federation_delegate_as,
    read_held_admin_acts, remove_shared_member_as, withdraw_held_admin_act_as,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

const SHARED: u64 = 47;

struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    admin: EntityId,
    /// The first Admin's own membership grant: the parent of their delegate.
    admin_grant: EntityId,
    admin_b: EntityId,
    /// A Deputy, who asks an Owner before a remove (check-in).
    deputy: EntityId,
    member: EntityId,
}

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

/// `member` accepts its pending invitation to the shared vault at `role`.
/// `member` accepts their founding invitation at `role`; answers the grant
/// the accept minted.
fn accept(vault: &Vault, member: EntityId, role: Role) -> EntityId {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the invitation");
    let receipt = vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
    let [grant] = receipt.grants.as_slice() else {
        panic!("the accept mints one grant: {receipt:?}");
    };
    EntityId::from_hex(grant).expect("a grant id")
}

/// The id an `ADMIN_ACT_HELD` answer names in its one reason code.
fn held_id(err: &MemoryError) -> String {
    assert_eq!(err.code, MEMORY_CODE_ADMIN_ACT_HELD, "{err:?}");
    let [code] = err.reason_codes.as_slice() else {
        panic!("one reason code: {err:?}");
    };
    code.strip_prefix(ADMIN_ACT_HELD_REASON_PREFIX)
        .expect("the admin_act: reason code")
        .to_owned()
}

impl Org {
    /// A rooted vault whose shared vault holds the owner, two Admins, a
    /// Deputy and a Member, each of whom accepted.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let [admin, admin_b, deputy, member] = std::array::from_fn(|_| EntityId::now());
        for id in [admin, admin_b, deputy, member] {
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
                    founding(admin, Role::Admin),
                    founding(admin_b, Role::Admin),
                    founding(deputy, Role::Deputy),
                    founding(member, Role::Member),
                ],
                1,
            )
            .expect("a shared vault with two Admins, a Deputy and a Member");
        let admin_grant = accept(&vault, admin, Role::Admin);
        accept(&vault, admin_b, Role::Admin);
        accept(&vault, deputy, Role::Deputy);
        accept(&vault, member, Role::Member);
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            admin,
            admin_grant,
            admin_b,
            deputy,
            member,
        }
    }

    /// Runs `act` with the host key bound to `person`, then binds the key
    /// back to the owner: a rooted vault admits only a bound writer, and the
    /// host key holds one live binding.
    fn as_person<T>(&self, person: EntityId, act: impl FnOnce() -> T) -> T {
        bind_host_actor(&self.vault, &self.issuer, person, "human")
            .expect("the host key bound to the person for its act");
        let answer = act();
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        answer
    }

    /// An Owner sets the vault-wide key `key` to `value`.
    fn owner_sets(&self, key: &str, value: serde_json::Value) {
        self.vault
            .set_setting(
                SettingCaller::Owner(&proof(&self.vault, self.owner)),
                SetSetting::vault_value(key, value),
            )
            .expect("an Owner sets the org key");
    }

    /// A fresh live person nobody has invited yet.
    fn newcomer(&self) -> EntityId {
        let id = EntityId::now();
        person(&self.vault, id);
        id
    }

    /// `by` adds `newcomer` as a Member through `vault.members.add`.
    fn add(&self, by: EntityId, newcomer: EntityId) -> MemoryResult<SharedActExecutionReceipt> {
        self.as_person(by, || {
            add_shared_member_as(
                &self.vault,
                &proof(&self.vault, by),
                SharedMemberAddRequest {
                    vault_id: SHARED,
                    member: newcomer.to_hex(),
                    role: Some(Role::Member),
                    check_in_ref: None,
                },
            )
        })
    }

    /// `by` approves held act `held` through `vault.members.held.approve`.
    fn approve(&self, by: EntityId, held: &str) -> MemoryResult<serde_json::Value> {
        self.as_person(by, || {
            approve_held_admin_act_as(
                &self.vault,
                &proof(&self.vault, by),
                Some(&self.issuer),
                HeldAdminActRequest {
                    vault_id: SHARED,
                    held: held.to_owned(),
                },
            )
            .map(|approved| approved.output)
        })
    }

    /// Held act `held` as `reader` lists it.
    fn held_as(&self, reader: EntityId, held: &str) -> HeldAdminAct {
        self.as_person(reader, || {
            read_held_admin_acts(
                &self.vault,
                &proof(&self.vault, reader),
                oneiron::task_verb::sdk::SharedVaultRequest { vault_id: SHARED },
            )
        })
        .expect("a live admin lists the held acts")
        .into_iter()
        .find(|act| act.id == held)
        .expect("the held act is listed")
    }

    /// Every inbox notification stored for `recipient` by `producer`.
    fn notices(&self, recipient: EntityId, producer: &str) -> Vec<NotificationBody> {
        self.vault
            .entities_by_type(ENTITY_TYPE_NOTIFICATION)
            .expect("notifications")
            .into_iter()
            .filter_map(|id| self.vault.get(&id).expect("notification row"))
            .filter_map(|raw| decode_notification_body(&raw).ok())
            .filter(|body| {
                body.source.producer == producer
                    && body.recipient.as_deref() == Some(recipient.to_hex().as_str())
            })
            .collect()
    }

    /// Whether `newcomer` holds a pending invitation that `inviter` issued.
    fn invited_by(&self, newcomer: EntityId, inviter: EntityId) -> bool {
        self.vault
            .shared_invitations(&proof(&self.vault, newcomer), SHARED)
            .expect("the newcomer reads their invitations")
            .iter()
            .any(|open| open.inviter == inviter.to_hex())
    }

    /// `by` removes `member` through `vault.members.remove`, naming
    /// `check_in` once an Owner approved an earlier call's check-in.
    fn remove(
        &self,
        by: EntityId,
        member: EntityId,
        check_in: Option<&str>,
    ) -> MemoryResult<SharedActExecutionReceipt> {
        self.as_person(by, || {
            remove_shared_member_as(
                &self.vault,
                &proof(&self.vault, by),
                Some(&self.issuer),
                SharedMemberRemoveRequest {
                    vault_id: SHARED,
                    member: member.to_hex(),
                    check_in_ref: check_in.map(str::to_owned),
                },
            )
        })
    }

    /// `by` withdraws held act `held` through `vault.members.held.withdraw`.
    fn withdraw(&self, by: EntityId, held: &str) -> MemoryResult<HeldAdminAct> {
        self.as_person(by, || {
            withdraw_held_admin_act_as(
                &self.vault,
                &proof(&self.vault, by),
                HeldAdminActRequest {
                    vault_id: SHARED,
                    held: held.to_owned(),
                },
            )
        })
    }

    /// The role `member` holds in the shared vault now, from its grant rows.
    fn role_of(&self, member: EntityId) -> Option<Role> {
        self.vault
            .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
            .expect("grants")
            .into_iter()
            .find_map(|id| {
                let body = self.vault.get(&id).expect("grant row")?;
                let grant = oneiron::federation::decode_federation_grant_body(&body).ok()?;
                (grant.member_ref == member && grant.role != Role::Delegate).then_some(grant.role)
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
            "the Owner's approval makes the act eligible: {settled}"
        );
    }

    /// A NOTE `author` writes about a fresh person, with the host key bound
    /// to them for that one write.
    fn note_of(&self, author: EntityId) -> String {
        let subject = self.newcomer();
        self.as_person(author, || {
            self.vault
                .memory(author, EdgeActorClass::Human)
                .author_take(TakeTarget::Subject(subject), "a take about the subject")
                .expect("author a NOTE")
                .id_hex
        })
    }

    fn deleted(&self, note: &str) -> bool {
        self.vault
            .is_deleted_shell(&EntityId::from_hex(note).expect("note id"))
            .expect("shell read")
    }

    /// The live `human` credential this host mints `person`, verified as a
    /// transport verifies the slip a request presents.
    fn credential(&self, person: EntityId) -> VerifiedSlip {
        static NEXT: AtomicU8 = AtomicU8::new(1);
        let root = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip");
        let issued_at = self.vault.capability_slip_now().expect("slip clock");
        let mut claims = root.claims;
        claims.slip_id = [NEXT.fetch_add(1, Ordering::Relaxed); 32];
        claims.holder_ref = person.to_hex();
        claims.actor_class = Some("human".into());
        claims.issued_at = issued_at;
        claims.expires_at = issued_at + 3_600;
        claims.ttl_secs = 3_600;
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the person's credential");
        let challenge = b"two-admin-delete";
        let binding = self
            .issuer
            .binding_proof(&slip, challenge)
            .expect("binding proof");
        self.vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &binding)
            .expect("a verified credential")
    }

    /// `person` deletes `note` through `vault.delete` over its own
    /// credential, as a person other than the owner acts on a rooted vault.
    fn delete_with_credential(&self, person: EntityId, note: &str) -> MemoryResult<bool> {
        let credential = self.credential(person);
        self.vault
            .memory(person, EdgeActorClass::Human)
            .with_transport_invocation()
            .with_read_proof(&credential)
            .safe_delete(note, SafeDeleteReason::UserDelete)
            .map(|receipt| receipt.existed)
    }
}

#[test]
fn two_admin_opt_in_holds_a_single_admin_act() {
    let org = Org::new();
    // Off by default: an Admin's add goes at once.
    let first = org.newcomer();
    let receipt = org
        .add(org.admin, first)
        .expect("an Admin's add goes while the rule is off");
    assert_eq!(receipt.actor, org.admin.to_hex());
    assert!(org.invited_by(first, org.admin));

    org.owner_sets("org.two_admin", json!(true));
    let second = org.newcomer();
    let err = org
        .add(org.admin, second)
        .expect_err("the rule holds an Admin's add");
    let held = held_id(&err);
    assert!(
        !org.invited_by(second, org.admin),
        "a held add runs nothing: no invitation"
    );
    let act = org.held_as(org.admin_b, &held);
    assert_eq!(act.verb, "vault.members.add");
    assert_eq!(act.first_admin, org.admin.to_hex());
    assert_eq!(act.status, HeldAdminActStatus::Open);
    assert_eq!(act.input["member"], json!(second.to_hex()));
    // Each other live admin is asked in the inbox; the first admin is not.
    for asked in [org.owner, org.admin_b] {
        let asks = org.notices(asked, NOTIFICATION_PRODUCER_ADMIN_ACT_HELD);
        assert_eq!(asks.len(), 1, "one ask to {asked}");
        assert_eq!(asks[0].kind, NotificationKind::Ask);
        assert_eq!(asks[0].source.result.as_deref(), Some(held.as_str()));
    }
    assert!(
        org.notices(org.admin, NOTIFICATION_PRODUCER_ADMIN_ACT_HELD)
            .is_empty()
    );
    assert!(
        org.notices(org.member, NOTIFICATION_PRODUCER_ADMIN_ACT_HELD)
            .is_empty()
    );
}

#[test]
fn two_admin_second_approval_lands_the_act() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    let newcomer = org.newcomer();
    let held = held_id(&org.add(org.admin, newcomer).expect_err("held"));

    let output = org
        .approve(org.admin_b, &held)
        .expect("a second, distinct live Admin approves");
    let receipt: SharedActExecutionReceipt =
        serde_json::from_value(output).expect("the add's receipt");
    assert_eq!(receipt.actor, org.admin_b.to_hex(), "the approver acts");
    assert_eq!(
        receipt.proposer,
        Some(org.admin.to_hex()),
        "both names on the receipt"
    );
    assert!(org.invited_by(newcomer, org.admin_b));
    let act = org.held_as(org.admin, &held);
    assert_eq!(
        act.status,
        HeldAdminActStatus::Landed {
            approver: org.admin_b.to_hex()
        }
    );
    assert!(
        org.approve(org.owner, &held).is_err(),
        "a landed act lands once"
    );
    // The invitee's accept is the invitee's own act, never held.
    accept(&org.vault, newcomer, Role::Member);
}

#[test]
fn an_owners_act_is_never_held() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    let newcomer = org.newcomer();
    let receipt = org
        .add(org.owner, newcomer)
        .expect("an Owner's add goes at once with the rule on");
    assert_eq!(receipt.actor, org.owner.to_hex());
    assert_eq!(receipt.proposer, None);
    assert!(org.invited_by(newcomer, org.owner));
}

#[test]
fn the_first_admin_cannot_approve_their_own_act() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    let newcomer = org.newcomer();
    let held = held_id(&org.add(org.admin, newcomer).expect_err("held"));

    assert!(
        org.approve(org.admin, &held).is_err(),
        "the first admin is not the second"
    );
    assert!(
        org.approve(org.member, &held).is_err(),
        "a Member approves no admin act"
    );
    assert_eq!(
        org.held_as(org.admin, &held).status,
        HeldAdminActStatus::Open
    );
    assert!(!org.invited_by(newcomer, org.admin));

    // The first admin may withdraw it; a withdrawn act lands no more.
    let withdrawn = org
        .as_person(org.admin, || {
            withdraw_held_admin_act_as(
                &org.vault,
                &proof(&org.vault, org.admin),
                HeldAdminActRequest {
                    vault_id: SHARED,
                    held: held.clone(),
                },
            )
        })
        .expect("the first admin withdraws their own act");
    assert_eq!(withdrawn.status, HeldAdminActStatus::Withdrawn);
    assert!(org.approve(org.admin_b, &held).is_err());
    assert!(!org.invited_by(newcomer, org.admin_b));
}

#[test]
fn a_held_act_lapses_with_a_notice_to_the_first_admin() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    org.owner_sets("org.two_admin_lapse_secs", json!(0));
    let newcomer = org.newcomer();
    let held = held_id(&org.add(org.admin, newcomer).expect_err("held"));

    org.vault
        .notify_matured_shared_acts()
        .expect("the housekeeping pass");
    assert_eq!(
        org.held_as(org.admin_b, &held).status,
        HeldAdminActStatus::Lapsed
    );
    let notices = org.notices(org.admin, NOTIFICATION_PRODUCER_ADMIN_ACT_LAPSED);
    assert_eq!(notices.len(), 1, "one lapse notice to the first admin");
    assert_eq!(notices[0].source.result.as_deref(), Some(held.as_str()));
    assert!(
        org.notices(org.admin_b, NOTIFICATION_PRODUCER_ADMIN_ACT_LAPSED)
            .is_empty()
    );
    // A second pass tells nobody again, and a lapsed act lands no more.
    org.vault
        .notify_matured_shared_acts()
        .expect("the housekeeping pass again");
    assert_eq!(
        org.notices(org.admin, NOTIFICATION_PRODUCER_ADMIN_ACT_LAPSED)
            .len(),
        1
    );
    assert!(org.approve(org.admin_b, &held).is_err());
    assert!(!org.invited_by(newcomer, org.admin_b));
}

/// The wall clock in seconds, as the store clock counts them.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs()
}

#[test]
fn a_held_delegate_lands_on_a_second_approval() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    let delegate = org.newcomer();
    let request = FederationDelegateRequest {
        parent_grant: org.admin_grant,
        member_ref: delegate,
        authority_scope: Scope::default(),
        expires_at: now_secs() + 600,
    };
    let held = held_id(
        &org.as_person(org.admin, || {
            create_federation_delegate_as(&org.vault, &proof(&org.vault, org.admin), request)
        })
        .expect_err("an Admin's delegate mint is held"),
    );

    let output = org
        .approve(org.admin_b, &held)
        .expect("a second admin's approve mints the first admin's delegate");
    assert!(
        output.to_string().contains(&delegate.to_hex()),
        "the minted delegate names its member: {output}"
    );
    assert_eq!(
        org.held_as(org.owner, &held).status,
        HeldAdminActStatus::Landed {
            approver: org.admin_b.to_hex()
        }
    );
}

#[test]
fn an_approve_cut_short_after_its_write_has_landed_the_act() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    let newcomer = org.newcomer();
    let held = held_id(&org.add(org.admin, newcomer).expect_err("held"));
    let request = HeldAdminActRequest {
        vault_id: SHARED,
        held: held.clone(),
    };

    let receipt = org
        .as_person(org.admin_b, || {
            cut_short::approve_held_add_unsettled(
                &org.vault,
                &proof(&org.vault, org.admin_b),
                &request,
            )
        })
        .expect("the re-run ran, and the approve stopped before its settle");
    // Its own write landed it: nothing was left for the settle, and nobody
    // approves it again.
    assert_eq!(
        org.held_as(org.owner, &held).status,
        HeldAdminActStatus::Landed {
            approver: org.admin_b.to_hex()
        }
    );
    assert_eq!(receipt["actor"], json!(org.admin_b.to_hex()));
    assert_eq!(receipt["first_admin"], json!(org.admin.to_hex()));
    assert!(org.invited_by(newcomer, org.admin_b));
    assert!(org.approve(org.owner, &held).is_err());
}

#[test]
fn an_approve_cut_short_before_its_write_lapses_with_a_notice() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    org.owner_sets("org.two_admin_lapse_secs", json!(3));
    let newcomer = org.newcomer();
    let held = held_id(&org.add(org.admin, newcomer).expect_err("held"));
    let request = HeldAdminActRequest {
        vault_id: SHARED,
        held: held.clone(),
    };
    let claimed = org
        .as_person(org.admin_b, || {
            cut_short::claim_held_admin_act(&org.vault, &proof(&org.vault, org.admin_b), &request)
        })
        .expect("the approve claims the act, then stops");
    assert_eq!(
        claimed.status,
        HeldAdminActStatus::Approving {
            approver: org.admin_b.to_hex()
        }
    );

    std::thread::sleep(std::time::Duration::from_secs(4));
    org.vault
        .notify_matured_shared_acts()
        .expect("the housekeeping pass");
    assert_eq!(
        org.held_as(org.owner, &held).status,
        HeldAdminActStatus::Lapsed
    );
    let notices = org.notices(org.admin, NOTIFICATION_PRODUCER_ADMIN_ACT_LAPSED);
    assert_eq!(notices.len(), 1, "one lapse notice to the first admin");
    assert_eq!(notices[0].source.result.as_deref(), Some(held.as_str()));
    assert!(!org.invited_by(newcomer, org.admin_b));
}

#[test]
fn an_admins_lone_ruling_refuses_while_the_rule_is_on() {
    let org = Org::new();
    let ruling = |by: EntityId, value: &str| {
        org.as_person(by, || {
            org.vault.append_admin_ruling(
                &proof(&org.vault, by),
                SHARED,
                "setting",
                json!(value),
                2,
            )
        })
    };
    ruling(org.admin, "off").expect("with the rule off, an Admin's ruling goes at once");

    org.owner_sets("org.two_admin", json!(true));
    let refusal = MemoryError::from(ruling(org.admin, "alone").expect_err("held"));
    assert!(
        refusal
            .reason_codes
            .iter()
            .any(|code| code == TWO_ADMIN_HOLD_REASON_CODE),
        "an Admin's lone ruling refuses with the hold's reason: {refusal:?}"
    );
    ruling(org.owner, "owner").expect("an Owner's ruling is never held");
}

#[test]
fn an_admins_held_steward_add_never_lands_by_an_owners_approve() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    let newcomer = org.newcomer();
    let steward_add = |by: EntityId| {
        org.as_person(by, || {
            add_shared_member_as(
                &org.vault,
                &proof(&org.vault, by),
                SharedMemberAddRequest {
                    vault_id: SHARED,
                    member: newcomer.to_hex(),
                    role: Some(Role::Steward),
                    check_in_ref: None,
                },
            )
        })
    };
    let held = held_id(&steward_add(org.admin).expect_err("held"));

    org.approve(org.owner, &held)
        .expect_err("the Steward role is no Admin's to give, so an approve cannot land it");
    assert_eq!(
        org.held_as(org.owner, &held).status,
        HeldAdminActStatus::Open
    );
    assert!(!org.invited_by(newcomer, org.owner));
    steward_add(org.owner).expect("an Owner gives the Steward role at once");
    assert!(org.invited_by(newcomer, org.owner));
}

/// Whether `err` carries the hold's own reason code.
fn held_by_the_rule(err: &MemoryError) -> bool {
    err.reason_codes
        .iter()
        .any(|code| code == TWO_ADMIN_HOLD_REASON_CODE)
}

#[test]
fn an_admins_delete_of_a_members_note_refuses_while_the_rule_is_on() {
    let org = Org::new();
    let note = org.note_of(org.member);
    let own = org.note_of(org.admin);
    org.owner_sets("org.two_admin", json!(true));

    let refusal = org
        .delete_with_credential(org.admin, &note)
        .expect_err("an Admin's delete of a Member's NOTE is an admin power act");
    assert!(
        held_by_the_rule(&refusal),
        "it refuses with the hold's reason: {refusal:?}"
    );
    assert!(!org.deleted(&note), "the Member's NOTE is untouched");

    assert!(
        org.delete_with_credential(org.admin, &own)
            .expect("an Admin's delete of their own NOTE is their own act")
    );
    assert!(org.deleted(&own));
    assert!(
        org.vault
            .memory(org.owner, EdgeActorClass::Human)
            .safe_delete(&note, SafeDeleteReason::UserDelete)
            .expect("an Owner's delete is never held")
            .existed
    );
    assert!(org.deleted(&note));
}

#[test]
fn a_deputys_held_remove_spends_the_deputys_own_check_in() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));

    // The Deputy's own check-in comes first: an Owner answers it before the
    // rule holds the act.
    let waits = org
        .remove(org.deputy, org.member, None)
        .expect_err("a Deputy's remove waits");
    assert_eq!(waits.code, MEMORY_CODE_CHECK_IN_PENDING, "{waits:?}");
    let [code] = waits.reason_codes.as_slice() else {
        panic!("one reason code: {waits:?}");
    };
    let check_in = code
        .strip_prefix(CHECK_IN_PENDING_REASON_PREFIX)
        .expect("the check-in reason code")
        .to_owned();
    assert_eq!(org.role_of(org.member), Some(Role::Member));

    org.owner_approves(&check_in);
    let held = held_id(
        &org.remove(org.deputy, org.member, Some(&check_in))
            .expect_err("with its check-in approved, the rule holds the Deputy's remove"),
    );
    assert_eq!(
        org.role_of(org.member),
        Some(Role::Member),
        "a held remove runs nothing"
    );

    let output = org
        .approve(org.admin_b, &held)
        .expect("a second admin's approve lands the Deputy's remove");
    let receipt: SharedActExecutionReceipt =
        serde_json::from_value(output).expect("the remove's receipt");
    let decision = receipt.check_in.expect("the receipt records the check-in");
    assert_eq!(decision.role, "deputy", "the check-in is the first admin's");
    assert_eq!(decision.check_in.as_deref(), Some(check_in.as_str()));
    assert_eq!(org.role_of(org.member), None, "the Member is gone");
    let spent = org
        .vault
        .pending_check_in(&EntityId::from_hex(&check_in).expect("a check-in id"))
        .expect("read the check-in")
        .expect("the check-in is stored");
    assert!(spent.consumed_at.is_some(), "the re-run spent it");
}

#[test]
fn a_removed_first_admins_act_lands_no_more() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    let newcomer = org.newcomer();
    let held = held_id(&org.add(org.admin, newcomer).expect_err("held"));

    org.remove(org.owner, org.admin, None)
        .expect("an Owner removes the first admin at once");
    assert!(
        org.approve(org.admin_b, &held).is_err(),
        "an approval lifts only the rule: the act is no longer its first admin's to make"
    );
    assert!(!org.invited_by(newcomer, org.admin_b));
    assert_eq!(
        org.held_as(org.owner, &held).status,
        HeldAdminActStatus::Open
    );
}

#[test]
fn an_approve_claimed_in_time_lands_nothing_after_the_lapse() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    org.owner_sets("org.two_admin_lapse_secs", json!(3));
    let newcomer = org.newcomer();
    let held = held_id(&org.add(org.admin, newcomer).expect_err("held"));
    let request = HeldAdminActRequest {
        vault_id: SHARED,
        held: held.clone(),
    };

    let late = org.as_person(org.admin_b, || {
        cut_short::approve_held_add_after_pause(
            &org.vault,
            &proof(&org.vault, org.admin_b),
            &request,
            std::time::Duration::from_secs(4),
        )
    });
    assert!(
        late.is_err(),
        "a re-run that reaches its write past lapses_at lands nothing: {late:?}"
    );
    assert!(!org.invited_by(newcomer, org.admin_b));
    assert_ne!(
        org.held_as(org.owner, &held).status,
        HeldAdminActStatus::Landed {
            approver: org.admin_b.to_hex()
        }
    );
}

#[test]
fn a_lapse_past_ninety_days_refuses() {
    const CEILING: u64 = 90 * 24 * 60 * 60;
    let org = Org::new();
    let set = |value: u64| {
        org.vault.set_setting(
            SettingCaller::Owner(&proof(&org.vault, org.owner)),
            SetSetting::vault_value("org.two_admin_lapse_secs", json!(value)),
        )
    };
    for value in [u64::MAX, CEILING + 1] {
        assert!(
            set(value).is_err(),
            "a lapse of {value} s would hold an act past any deadline"
        );
    }
    set(CEILING).expect("90 days is the longest lapse");
}

#[test]
fn a_hard_erase_scrubs_the_first_admin_from_the_receipt() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    let newcomer = org.newcomer();
    let held = held_id(&org.add(org.admin, newcomer).expect_err("held"));
    let receipt: SharedActExecutionReceipt = serde_json::from_value(
        org.approve(org.admin_b, &held)
            .expect("a second admin approves"),
    )
    .expect("the add's receipt");
    let erased = org.admin.to_hex();
    assert_eq!(receipt.first_admin.as_deref(), Some(erased.as_str()));

    let ran = oneiron::test_doors::inquiry::erase_actor_in_tables_in_order(
        &org.vault,
        &org.admin,
        &["SHARED_ACT_RECEIPT"],
    )
    .expect("the receipt table's actor scrub");
    assert_eq!(ran, 1, "the receipt table registers an actor scrub");
    let read = org
        .as_person(org.admin_b, || {
            org.vault
                .shared_act_receipt(&proof(&org.vault, org.admin_b), &receipt.id)
        })
        .expect("the approver reads the receipt");
    assert_ne!(
        read.first_admin.as_deref(),
        Some(erased.as_str()),
        "the erased first admin is named no more: {read:?}"
    );
    assert_ne!(read.proposer.as_deref(), Some(erased.as_str()));
    assert_eq!(read.actor, org.admin_b.to_hex(), "the approver stays");
}

#[test]
fn a_removed_first_admin_withdraws_nothing() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    let newcomer = org.newcomer();
    let held = held_id(&org.add(org.admin, newcomer).expect_err("held"));

    org.remove(org.owner, org.admin, None)
        .expect("an Owner removes the first admin at once");
    assert!(
        org.withdraw(org.admin, &held).is_err(),
        "a first admin with no live grant here withdraws nothing"
    );
    assert_eq!(
        org.held_as(org.owner, &held).status,
        HeldAdminActStatus::Open
    );
}

#[test]
fn a_held_act_lands_no_more_once_its_first_admin_lost_the_power() {
    let org = Org::new();
    // The Owner's standing word: at the Admin role, the Deputy holds only
    // read and write.
    oneiron::test_doors::steward::write_holder_row(
        &org.vault,
        Role::Admin,
        SHARED,
        org.deputy,
        &["read", "write"],
    )
    .expect("the Owner's holder row");
    org.owner_sets("org.two_admin", json!(true));
    let newcomer = org.newcomer();
    let held = held_id(
        &org.add(org.deputy, newcomer)
            .expect_err("the Deputy's add is held"),
    );

    org.as_person(org.owner, || {
        change_shared_member_as(
            &org.vault,
            &proof(&org.vault, org.owner),
            Some(&org.issuer),
            SharedMemberRoleRequest {
                vault_id: SHARED,
                member: org.deputy.to_hex(),
                role: Role::Admin,
                check_in_ref: None,
            },
        )
    })
    .expect("an Owner moves the Deputy to Admin at once");
    assert_eq!(org.role_of(org.deputy), Some(Role::Admin));
    assert!(
        org.approve(org.admin_b, &held).is_err(),
        "the first admin stands as an Admin but holds the add-member power no more"
    );
    assert!(!org.invited_by(newcomer, org.admin_b));
}

#[test]
fn a_landing_check_past_the_lapse_refuses_whatever_time_its_writer_read() {
    let org = Org::new();
    org.owner_sets("org.two_admin", json!(true));
    org.owner_sets("org.two_admin_lapse_secs", json!(3));
    let newcomer = org.newcomer();
    let held = held_id(&org.add(org.admin, newcomer).expect_err("held"));
    let request = HeldAdminActRequest {
        vault_id: SHARED,
        held: held.clone(),
    };

    let landed = org.as_person(org.admin_b, || {
        cut_short::land_with_stale_time(
            &org.vault,
            &proof(&org.vault, org.admin_b),
            &request,
            std::time::Duration::from_secs(4),
        )
    });
    assert!(
        landed.is_err(),
        "a landing check past lapses_at refuses: {landed:?}"
    );
    assert_ne!(
        org.held_as(org.owner, &held).status,
        HeldAdminActStatus::Landed {
            approver: org.admin_b.to_hex()
        }
    );
}
