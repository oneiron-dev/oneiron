//! ROLES-CHECKIN P2.5, row 2k8g (ARCH-0082 #act-table "Widen another's
//! grant", #role-defaults and #owner-own-acts; Engine rulings P25-SHAPE Q1
//! = A, 14 Nov 13:39, P25-2K8-SCOPE Q5 = A, 19:32, and MEMBER-SHARE-OWN =
//! B, 19:33): `vault.shares.create`, the door a person reaches by role,
//! takes the widen judge (2k8f) in the writer that lands the share.
//!
//! - The Owner's share is never gated: it lands on their own proof, and its
//!   answer records that decision. A `check_in_ref` on it is refused as a
//!   bad request and lands nothing.
//! - A Deputy's share of a brief another wrote lands on their own judgment
//!   (`sure`); an Admin's never asks. Each answer names the role and why
//!   the share went.
//! - A Steward's and a Member's share of a brief another wrote always ask:
//!   the door commits the pending check-in alone, lands no share and
//!   answers `CHECK_IN_PENDING` naming it; a repeat names the same one.
//!   Before the Owner approves, the named check-in lands nothing. Once
//!   approved, the call that names it lands the share under the id it
//!   asked for, spends the check-in and names it.
//! - A Member's share of its own brief (the NOTE it wrote) lands at once
//!   with basis `own_item`.
//!
//! The vault is rooted, and its human binding is the owner's, so each other
//! person writes its brief and calls the door while the fixture binds the
//! host key to them, then the key goes back to the owner. The fixture gives
//! each of the five the Gate's permission to create a brief share, so every
//! share the judge lets go lands.
//!
//! On its base, 2k8f3's head (bd84cea1cc1), this file does not build: the
//! create request has no `check_in_ref`, and its answer no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_share_create_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

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
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{ShareCreateRequest, ShareCreated, create_share_as_caller, invoke};
use oneiron::temporal::TimeRange;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const SHARED: u64 = 43;

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
/// Member, each of whom accepted, and the PERSON each share is for. Each of
/// the five may create a brief share under the Gate.
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
        permit_brief_shares(&vault, &[owner, deputy, admin, steward, member]);
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

    /// `person`'s `vault.shares.create` of `brief` for the recipient, under
    /// `share_id` and naming `check_in_ref` when given: the owner's on the
    /// in-process handle, anyone else's while the host key is bound to them.
    fn create(
        &self,
        person: EntityId,
        brief: &str,
        share_id: Option<EntityId>,
        check_in_ref: Option<&str>,
    ) -> MemoryResult<ShareCreated> {
        let build = || ShareCreateRequest {
            share_id: share_id.map(|id| id.to_hex()),
            recipient: self.recipient.to_hex(),
            brief_ref: brief.to_owned(),
            world_refs: Vec::new(),
            facet_refs: Vec::new(),
            include_unscoped: true,
            expires_at: None,
            travel: None,
            mention: None,
            check_in_ref: check_in_ref.map(str::to_owned),
        };
        if person == self.owner {
            return create_share_as_caller(
                &self.vault.memory(person, EdgeActorClass::Human),
                build(),
            );
        }
        bind_host_actor(&self.vault, &self.issuer, person, "human")
            .expect("the host key bound to the caller for their share");
        let answer =
            create_share_as_caller(&self.vault.memory(person, EdgeActorClass::Human), build());
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        answer
    }

    /// Whether share `id` landed.
    fn landed(&self, id: &EntityId) -> bool {
        self.vault.get_share(id).expect("read the share").is_some()
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
            "the Owner's approval makes the share eligible: {settled}"
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

/// The check-in a waiting share names.
fn pending_id(result: MemoryResult<ShareCreated>) -> String {
    let refused = result.expect_err("the share waits on a check-in, yet it landed");
    assert_eq!(
        refused.code, MEMORY_CODE_CHECK_IN_PENDING,
        "the share waits: {refused:?}"
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
fn an_owners_brief_is_shared_by_role_and_a_members_share_waits_for_the_owner() {
    let org = Org::new();
    let brief = org.brief(org.owner, org.recipient, "a brief for the recipient");

    let owner = org
        .create(org.owner, &brief, None, None)
        .expect("the Owner shares");
    assert_eq!(
        owner.check_in,
        Some(decision("owner", None, "own_proof", None)),
        "the Owner's share records their own proof"
    );
    let deputy = org
        .create(org.deputy, &brief, None, None)
        .expect("the Deputy shares");
    assert_eq!(
        deputy.check_in,
        Some(decision("deputy", Some("auto"), "sure", None)),
        "the Deputy's answer names their own judgment"
    );
    let admin = org
        .create(org.admin, &brief, None, None)
        .expect("the Admin shares");
    assert_eq!(
        admin.check_in,
        Some(decision("admin", Some("full-access"), "never_ask", None)),
        "the Admin's answer names why it went"
    );
    for answer in [&owner, &deputy, &admin] {
        let id = EntityId::from_hex(&answer.share_id).expect("a share id");
        assert!(org.landed(&id), "each share that went landed");
    }

    let steward_share = EntityId::now();
    let steward_first = pending_id(org.create(org.steward, &brief, Some(steward_share), None));
    let member_share = EntityId::now();
    let member_first = pending_id(org.create(org.member, &brief, Some(member_share), None));
    assert_ne!(
        steward_first, member_first,
        "each waiter holds its own check-in"
    );
    assert_eq!(
        pending_id(org.create(org.member, &brief, Some(member_share), None)),
        member_first,
        "a repeat names the same check-in"
    );
    assert!(
        org.create(org.member, &brief, Some(member_share), Some(&member_first))
            .is_err(),
        "an unanswered check-in lands no share"
    );
    assert!(
        !org.landed(&steward_share) && !org.landed(&member_share),
        "a waiting share lands nothing"
    );

    org.owner_approves(&member_first);
    let receipt = org
        .create(org.member, &brief, Some(member_share), Some(&member_first))
        .expect("the approved share lands");
    assert_eq!(
        receipt.share_id,
        member_share.to_hex(),
        "the share lands under the id it asked for"
    );
    assert!(org.landed(&member_share), "the approved share landed");
    assert!(org.spent(&member_first), "the share spent its check-in");
    assert!(!org.spent(&steward_first), "the Steward's wait stands");
    assert!(
        !org.landed(&steward_share),
        "the Steward's share still waits"
    );
    assert_eq!(
        receipt.check_in,
        Some(decision(
            "member",
            Some("manual"),
            "approved",
            Some(&member_first)
        )),
        "the answer names the check-in the share spent"
    );
}

#[test]
fn a_member_shares_its_own_brief_at_once_as_own_item() {
    let org = Org::new();
    let brief = org.brief(org.member, org.recipient, "a member's brief");
    let share = org
        .create(org.member, &brief, None, None)
        .expect("the Member shares its own brief at once");
    assert!(
        org.landed(&EntityId::from_hex(&share.share_id).expect("a share id")),
        "the share landed"
    );
    assert_eq!(
        share.check_in,
        Some(decision("member", Some("full-access"), "own_item", None)),
        "the answer names its own brief as why it went"
    );
}

#[test]
fn an_owners_share_naming_a_check_in_is_refused() {
    let org = Org::new();
    let brief = org.brief(org.owner, org.recipient, "a brief for the recipient");
    let share = EntityId::now();
    let named = EntityId::now().to_hex();
    let refused = org
        .create(org.owner, &brief, Some(share), Some(&named))
        .expect_err("an Owner's share names no check-in, yet it landed");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    assert!(!org.landed(&share), "the refused share landed nothing");

    let landed = org
        .create(org.owner, &brief, Some(share), None)
        .expect("the Owner shares");
    assert!(org.landed(&share), "the Owner's share landed");
    assert_eq!(
        landed.check_in,
        Some(decision("owner", None, "own_proof", None)),
        "the Owner's share records their own proof"
    );
}
