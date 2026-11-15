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
//! On the base (#8259, a2cb32313b0) this file does not build: there is no
//! `org.two_admin` key, no `MEMORY_CODE_ADMIN_ACT_HELD` and no held-act
//! verbs.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test org_two_admin_rule`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrantRole as Role, HeldAdminAct, HeldAdminActStatus, InitialSharedMember,
    NOTIFICATION_PRODUCER_ADMIN_ACT_HELD, NOTIFICATION_PRODUCER_ADMIN_ACT_LAPSED,
    SharedActExecutionReceipt,
};
use oneiron::inbox::{NotificationBody, NotificationKind, decode_notification_body};
use oneiron::memory::{
    ADMIN_ACT_HELD_REASON_PREFIX, MEMORY_CODE_ADMIN_ACT_HELD, MemoryError, MemoryResult,
};
use oneiron::registry::{ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_PERSON};
use oneiron::setting::{SetSetting, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::verbs::{
    HeldAdminActRequest, SharedMemberAddRequest, add_shared_member_as, approve_held_admin_act_as,
    read_held_admin_acts, withdraw_held_admin_act_as,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

const SHARED: u64 = 47;

struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    admin: EntityId,
    admin_b: EntityId,
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
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
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
    /// A rooted vault whose shared vault holds the owner, two Admins and a
    /// Member, each of whom accepted.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let [admin, admin_b, member] = std::array::from_fn(|_| EntityId::now());
        for id in [admin, admin_b, member] {
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
                    founding(member, Role::Member),
                ],
                1,
            )
            .expect("a shared vault with two Admins and a Member");
        let org = Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            admin,
            admin_b,
            member,
        };
        accept(&org.vault, admin, Role::Admin);
        accept(&org.vault, admin_b, Role::Admin);
        accept(&org.vault, member, Role::Member);
        org
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
