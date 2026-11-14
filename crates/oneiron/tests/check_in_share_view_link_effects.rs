//! ROLES-CHECKIN P2.5, row 2k8f3 (ARCH-0082 #act-table "Widen another's
//! grant", #role-defaults and #owner-own-acts; Engine rulings P25-SHAPE Q1
//! = A, 14 Nov 13:39, and MEMBER-SHARE-OWN = B, 19:33):
//! `vault.shares.issue_view_link`, the door a person reaches by role, takes
//! the widen judge (2k8f) after every check that refuses the call and
//! before any link is drawn.
//!
//! - The Owner's link is never gated: it goes on their own proof, and its
//!   answer records that decision. A `check_in_ref` on it is refused as a
//!   bad request and draws nothing.
//! - A Deputy's link to another's share goes on their own judgment
//!   (`sure`); an Admin's never asks. Each answer names the role and why
//!   the link went.
//! - A Steward's and a Member's link to another's share always ask: the
//!   door commits the pending check-in alone, draws no link and answers
//!   `CHECK_IN_PENDING` naming it; a repeat names the same one. Before the
//!   Owner approves, the named check-in runs nothing. Once approved, the
//!   call that names it answers a link, spends it and names it.
//! - A Member's link to its own share (the share it issued) goes at once
//!   with basis `own_item`.
//!
//! The vault is rooted, and its human binding is the owner's, so each other
//! person links while the fixture binds the host key to them, then the key
//! goes back to the owner: anyone but the share's issuer must be a human
//! whose binding is active. Each share is admitted by its issuer under the
//! Gate permission the fixture grants them.
//!
//! The answer carries the link's code, a secret, so it has no `Debug`: the
//! waits are read by matching the refusal.
//!
//! On its base, 2k8f2's head (8833f0a2cb1), this file does not build: the
//! link request has no `check_in_ref`, and the door answers a pairing link
//! with no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_share_view_link_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::access_grant::AccessGrantStatus;
use oneiron::authority::HostSlipIssuer;
use oneiron::check_in::CheckInDecision;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::{
    CHECK_IN_PENDING_REASON_PREFIX, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_CHECK_IN_PENDING,
    MemoryResult,
};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::share::Share;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{
    ShareViewLink, ShareViewLinkRequest, invoke, issue_share_view_link_with_issuer,
};
use oneiron::temporal::TimeRange;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use serde_json::json;

const SHARED: u64 = 43;
/// The recipient credential's lifetime each link asks for.
const LINK_LIFETIME_SECS: u64 = 3_600;

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

/// Keep the shipped policy, adding each `issuer`'s explicit permission to
/// create a brief share on this channel.
fn permit_brief_shares(vault: &Vault, issuers: &[EntityId]) {
    let id = oneiron_store::policy_record::default_policy_manifest_id()
        .expect("the default manifest id");
    let bytes = vault
        .get(&id)
        .expect("read default manifest")
        .expect("the shipped manifest is stored");
    let mut manifest: serde_json::Value =
        rmp_serde::from_slice(&bytes).expect("decode shipped manifest");
    let grants = manifest["scoped_grants"]
        .as_array_mut()
        .expect("the shipped scoped-grant table");
    for issuer in issuers {
        grants.push(json!({
            "actor_ref": issuer.to_hex(),
            "effector": "external:share_brief",
            "scope": oneiron::test_support::effect_preset(),
            "selectors": { "channel": "shared_brief" },
        }));
    }
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest).expect("encode share permission"),
    )
    .expect("store the share permission beside the shipped policy");
}

/// A rooted shared vault: its owner, a Deputy, an Admin, a Steward and a
/// Member, each of whom accepted, and the PERSON each share is for. The
/// Owner and the Member may each create a brief share.
struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    deputy: EntityId,
    admin: EntityId,
    steward: EntityId,
    member: EntityId,
    recipient: EntityId,
}

impl Org {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let [deputy, admin, steward, member, recipient] = std::array::from_fn(|_| EntityId::now());
        for id in [deputy, admin, steward, member, recipient] {
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
                    founding(steward, Role::Steward),
                    founding(member, Role::Member),
                ],
                1,
            )
            .expect("a shared vault with a Deputy, an Admin, a Steward and a Member");
        accept(&vault, deputy, Role::Deputy);
        accept(&vault, admin, Role::Admin);
        accept(&vault, steward, Role::Steward);
        accept(&vault, member, Role::Member);
        permit_brief_shares(&vault, &[owner, member]);
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            deputy,
            admin,
            steward,
            member,
            recipient,
        }
    }

    /// A NOTE brief `author` writes about `about`: anyone but the owner
    /// writes while the host key is bound to them. By its id hex.
    fn brief(&self, author: EntityId, about: EntityId, text: &str) -> String {
        let call = || {
            self.vault
                .memory(author, EdgeActorClass::Human)
                .author_take(TakeTarget::Subject(about), text)
                .expect("the author writes a NOTE brief")
                .id_hex
        };
        if author == self.owner {
            return call();
        }
        bind_host_actor(&self.vault, &self.issuer, author, "human")
            .expect("the host key bound to the author for its write");
        let brief = call();
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        brief
    }

    /// An admitted brief share `issuer` issues to the recipient for `brief`:
    /// the Gate admits it under the permission the fixture grants them. By
    /// its id.
    fn create_share(&self, issuer: EntityId, brief: &str) -> EntityId {
        let share_id = EntityId::now();
        let share = Share {
            recipient_ref: self.recipient,
            brief_ref: brief.to_owned(),
            world_refs: BTreeSet::new(),
            facet_refs: BTreeSet::new(),
            include_unscoped: true,
            status: AccessGrantStatus::Active,
            created_at: self.vault.now_recorded_at(),
            revoked_at: None,
            expires_at: None,
            mention: None,
        };
        self.vault
            .create_share(
                &share_id,
                &WriteActor::new(issuer, EdgeActorClass::Human),
                &share,
            )
            .expect("the issuer's brief share is admitted");
        share_id
    }

    /// `person`'s `vault.shares.issue_view_link` for `share`, naming
    /// `check_in_ref` when given: the owner's on the in-process handle,
    /// anyone else's while the host key is bound to them.
    fn link(
        &self,
        person: EntityId,
        share: &EntityId,
        check_in_ref: Option<&str>,
    ) -> MemoryResult<ShareViewLink> {
        let build = || ShareViewLinkRequest {
            share_ref: share.to_hex(),
            actor_class: "human".to_owned(),
            slip_lifetime_secs: LINK_LIFETIME_SECS,
            check_in_ref: check_in_ref.map(str::to_owned),
        };
        if person == self.owner {
            return issue_share_view_link_with_issuer(
                &self.vault.memory(person, EdgeActorClass::Human),
                &self.issuer,
                build(),
            );
        }
        bind_host_actor(&self.vault, &self.issuer, person, "human")
            .expect("the host key bound to the caller for their link");
        let answer = issue_share_view_link_with_issuer(
            &self.vault.memory(person, EdgeActorClass::Human),
            &self.issuer,
            build(),
        );
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        answer
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
            "the Owner's approval makes the link eligible: {settled}"
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

/// The check-in a waiting link names.
fn pending_id(result: MemoryResult<ShareViewLink>) -> String {
    let Err(refused) = result else {
        panic!("the link waits on a check-in, yet a link was drawn");
    };
    assert_eq!(
        refused.code, MEMORY_CODE_CHECK_IN_PENDING,
        "the link waits: {refused:?}"
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
        act_class: "grant_widen".to_owned(),
        role: role.to_owned(),
        mode: mode.map(str::to_owned),
        basis: basis.to_owned(),
        check_in: check_in.map(str::to_owned),
        requester: None,
    }
}

#[test]
fn an_owners_share_is_linked_by_role_and_a_members_link_waits_for_the_owner() {
    let org = Org::new();
    let brief = org.brief(org.owner, org.recipient, "a brief for the recipient");
    let share = org.create_share(org.owner, &brief);

    let owner = org.link(org.owner, &share, None).expect("the Owner links");
    assert!(!owner.code.is_empty(), "the Owner's call draws a link");
    assert_eq!(
        owner.check_in,
        Some(decision("owner", None, "own_proof", None)),
        "the Owner's link records their own proof"
    );
    let deputy = org
        .link(org.deputy, &share, None)
        .expect("the Deputy links");
    assert!(!deputy.code.is_empty(), "the Deputy's call draws a link");
    assert_eq!(
        deputy.check_in,
        Some(decision("deputy", Some("auto"), "sure", None)),
        "the Deputy's answer names their own judgment"
    );
    let admin = org.link(org.admin, &share, None).expect("the Admin links");
    assert!(!admin.code.is_empty(), "the Admin's call draws a link");
    assert_eq!(
        admin.check_in,
        Some(decision("admin", Some("full-access"), "never_ask", None)),
        "the Admin's answer names why it went"
    );

    let steward_first = pending_id(org.link(org.steward, &share, None));
    let member_first = pending_id(org.link(org.member, &share, None));
    assert_ne!(
        steward_first, member_first,
        "each waiter holds its own check-in"
    );
    assert_eq!(
        pending_id(org.link(org.member, &share, None)),
        member_first,
        "a repeat names the same check-in"
    );
    assert!(
        org.link(org.member, &share, Some(&member_first)).is_err(),
        "an unanswered check-in draws no link"
    );

    org.owner_approves(&member_first);
    let receipt = org
        .link(org.member, &share, Some(&member_first))
        .expect("the approved link is drawn");
    assert!(!receipt.code.is_empty(), "the approved call draws a link");
    assert!(org.spent(&member_first), "the link spent its check-in");
    assert!(!org.spent(&steward_first), "the Steward's wait stands");
    assert_eq!(
        receipt.check_in,
        Some(decision(
            "member",
            Some("manual"),
            "approved",
            Some(&member_first)
        )),
        "the answer names the check-in the link spent"
    );
}

#[test]
fn a_member_links_its_own_share_at_once_as_own_item() {
    let org = Org::new();
    let brief = org.brief(org.member, org.recipient, "a member's brief");
    let share = org.create_share(org.member, &brief);
    let link = org
        .link(org.member, &share, None)
        .expect("the Member links its own share at once");
    assert!(!link.code.is_empty(), "the call draws a link");
    assert_eq!(
        link.check_in,
        Some(decision("member", Some("full-access"), "own_item", None)),
        "the answer names its own share as why it went"
    );
}

#[test]
fn an_owners_link_naming_a_check_in_is_refused() {
    let org = Org::new();
    let brief = org.brief(org.owner, org.recipient, "a brief for the recipient");
    let share = org.create_share(org.owner, &brief);
    let named = EntityId::now().to_hex();
    let Err(refused) = org.link(org.owner, &share, Some(&named)) else {
        panic!("an Owner's link names no check-in, yet a link was drawn");
    };
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");

    let link = org.link(org.owner, &share, None).expect("the Owner links");
    assert_eq!(
        link.check_in,
        Some(decision("owner", None, "own_proof", None)),
        "the Owner's link records their own proof"
    );
}
