//! The vault logs each admin act and tells the other admins (UNBUILT-06 PR 1;
//! canon identity.md #cloud-agent-recovery, ORG-1 A: "Any one admin acts
//! alone. The vault logs each admin act and notifies the other admins.";
//! Engine RULING UNBUILT06-SHAPE Q3 = A, 15 Nov 20:51).
//!
//! - A membership change made under an admin power is told to every live
//!   Owner, Admin and Deputy, not only to the Owners and the actor. A
//!   Steward or a Member who is not its subject is not told.
//! - An admin door that changes no membership row writes its own receipt and
//!   tells the same people: here a workspace setting (the preset an Owner
//!   establishes, the work-companion policy an Admin sets) and an Admin's
//!   delegate mint. A set that changes nothing logs nothing.
//!
//! - A house mind its org link seats at Deputy (the link's default role,
//!   canon HOUSE-BIND = A) is a live Deputy too: it is told of an Admin's
//!   setting and of an Admin's membership change (blind review of #8384).
//!
//! On main the Deputy is told of none of these: the membership writer tells
//! the live Owners, the actor and the change's subject, and the workspace
//! and delegate doors write no notice at all, so each case fails at its
//! first look at the Deputy's notices. At 4387aaa7ceb the house case fails
//! at its first look: the notice scan admitted live PERSON holders only.
//!
//! The vault is rooted, and a rooted vault admits only a writer its
//! authority log binds, so each person's acts and reads run while the
//! fixture binds the host key to that person (`Org::as_person`, as
//! check_in_membership_effects.rs does).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test admin_act_notice`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

#[path = "admin_step_up/fixture.rs"]
mod admin_step_up;

const SHARED: u64 = 43;
/// The stored workspace whose settings the settings case changes.
const WORKSPACE: &str = "admin-act-notice-workspace";

struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    deputy: EntityId,
    admin: EntityId,
    /// The Admin's proof on its own credential, stepped up with TOTP: an
    /// org Admin's act stands on a current MFA step-up (L7-17), and one
    /// person steps up once, so every Admin act reuses it.
    admin_proof: AuthenticatedOwner,
    steward: EntityId,
    member_a: EntityId,
    member_b: EntityId,
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

impl Org {
    /// A rooted vault whose shared vault holds the owner, a Deputy, an Admin,
    /// a Steward and two Members, each of whom accepted.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let [deputy, admin, steward, member_a, member_b] = std::array::from_fn(|_| EntityId::now());
        for id in [deputy, admin, steward, member_a, member_b] {
            person(&vault, id);
        }
        let member = |member_ref, role| InitialSharedMember {
            member_ref,
            role: Some(role),
        };
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[
                    member(owner, Role::Owner),
                    member(deputy, Role::Deputy),
                    member(admin, Role::Admin),
                    member(steward, Role::Steward),
                    member(member_a, Role::Member),
                    member(member_b, Role::Member),
                ],
                1,
            )
            .expect("a shared vault with a Deputy, an Admin, a Steward and two Members");
        accept(&vault, deputy, Role::Deputy);
        accept(&vault, admin, Role::Admin);
        accept(&vault, steward, Role::Steward);
        accept(&vault, member_a, Role::Member);
        accept(&vault, member_b, Role::Member);
        bind_host_actor(&vault, &issuer, admin, "human").expect("the host key bound to the Admin");
        let admin_proof = admin_step_up::stepped_up_proof(&vault, &issuer, admin);
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding again");
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            deputy,
            admin,
            admin_proof,
            steward,
            member_a,
            member_b,
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

    /// `reader`'s own outcome notices in the shared vault, as
    /// `vault.shared.outcomes` reads them.
    fn notices(&self, reader: EntityId) -> Vec<oneiron::federation::SharedActOutcome> {
        self.as_person(reader, || {
            self.vault
                .shared_act_outcomes(&proof(&self.vault, reader), SHARED)
        })
        .expect("the reader's notices")
    }

    /// Whether `reader` holds a notice of receipt `receipt`.
    fn was_told(&self, reader: EntityId, receipt: &str) -> bool {
        self.notices(reader)
            .iter()
            .any(|notice| notice.receipt_id == receipt)
    }

    /// How many of `reader`'s notices carry `change`, in its JSON form.
    fn told_of(&self, reader: EntityId, change: &Value) -> usize {
        self.notices(reader)
            .iter()
            .filter(|notice| {
                serde_json::to_value(&notice.change).expect("a change's JSON") == *change
            })
            .count()
    }

    /// How many outcome notices the shared vault holds for `house`, an agent
    /// definition with no person proof to read `vault.shared.outcomes` with:
    /// its `outcome:<recipient>:<receipt>` rows (test door).
    fn house_notices(&self, house: EntityId) -> Vec<String> {
        let prefix = format!("outcome:{}:", house.to_hex());
        oneiron::test_doors::shared_act_family::rows_naming(&self.vault, house)
            .expect("the shared-act rows naming the house")
            .into_iter()
            .filter(|row| row.starts_with(&prefix))
            .collect()
    }

    /// The Owner stores the workspace [`WORKSPACE`] over the shared vault,
    /// with the seeded `sys.default` agent as its house mind, and the
    /// work-companion policy `Choose`. Returns the house.
    fn store_workspace(&self) -> EntityId {
        let org_row = EntityId::now();
        self.vault
            .put_entity(
                &org_row,
                ENTITY_TYPE_ORG,
                TimeRange { start: 1, end: 1 },
                1,
                b"admin act notice org",
            )
            .expect("org row");
        let (house, _) = self
            .vault
            .get_seeded_agent_definition_by_logical_id("sys.default")
            .expect("read the seeded agents")
            .expect("sys.default is seeded on open");
        let preset = WorkspaceRosterPreset {
            workspace_ref: WORKSPACE.to_owned(),
            workspace_vault_id: SHARED,
            org_ref: org_row,
            venture_name: "Garden Works".to_owned(),
            house_display_name: None,
            house_actor_ref: house,
            house_identity_ref: None,
        };
        self.vault
            .establish_workspace_preset(
                &preset,
                WorkCompanionPolicy::Choose,
                &proof(&self.vault, self.owner),
            )
            .expect("the Owner stores the workspace");
        house
    }

    /// The id of the shared vault grant that seats `member` at `role`.
    fn grant_of(&self, member: EntityId, role: Role) -> EntityId {
        self.vault
            .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
            .expect("grants")
            .into_iter()
            .find(|id| {
                self.vault
                    .get(id)
                    .expect("grant row")
                    .and_then(|body| oneiron::federation::decode_federation_grant_body(&body).ok())
                    .is_some_and(|grant| grant.member_ref == member && grant.role == role)
            })
            .expect("the member's grant")
    }
}

#[test]
fn an_admins_membership_change_is_told_to_every_admin() {
    let org = Org::new();
    let moved = org
        .as_person(org.admin, || {
            org.vault.change_shared_member_role(
                &org.admin_proof,
                SHARED,
                org.member_b,
                Role::Viewer,
                None,
            )
        })
        .expect("the Admin moves a Member to Viewer");
    assert!(
        org.was_told(org.deputy, &moved.id),
        "the Deputy is told of the Admin's move"
    );
    assert!(
        org.was_told(org.owner, &moved.id),
        "the Owner is told, as before"
    );
    assert!(
        org.was_told(org.admin, &moved.id),
        "and the Admin, its actor"
    );
    assert!(
        !org.was_told(org.steward, &moved.id),
        "a Steward is no admin and is not told"
    );
    assert!(
        !org.was_told(org.member_a, &moved.id),
        "nor is a Member the move does not name"
    );
}

#[test]
fn a_workspace_setting_is_logged_to_every_admin() {
    let org = Org::new();
    let settings = json!({ "workspace_settings_changed": { "workspace": WORKSPACE } });
    org.store_workspace();
    assert_eq!(
        org.told_of(org.deputy, &settings),
        1,
        "the Deputy is told the Owner stored the workspace"
    );
    assert_eq!(org.told_of(org.admin, &settings), 1, "and so is the Admin");

    org.as_person(org.admin, || {
        org.vault.set_workspace_work_companion(
            WORKSPACE,
            WorkCompanionPolicy::Require,
            &org.admin_proof,
        )
    })
    .expect("the Admin sets the work-companion policy");
    for (reader, who) in [
        (org.owner, "the Owner"),
        (org.deputy, "the Deputy"),
        (org.admin, "the Admin, the second act's actor"),
    ] {
        assert_eq!(
            org.told_of(reader, &settings),
            2,
            "{who} is told of both settings acts"
        );
    }
    assert_eq!(
        org.told_of(org.steward, &settings),
        0,
        "a Steward is no admin and is not told"
    );

    org.as_person(org.admin, || {
        org.vault.set_workspace_work_companion(
            WORKSPACE,
            WorkCompanionPolicy::Require,
            &org.admin_proof,
        )
    })
    .expect("the Admin sets the same policy again");
    assert_eq!(
        org.told_of(org.owner, &settings),
        2,
        "a set that changes nothing logs nothing"
    );
}

#[test]
fn an_admins_delegate_mint_is_told_to_every_admin() {
    let org = Org::new();
    let helper = EntityId::now();
    person(&org.vault, helper);
    let parent = org.grant_of(org.admin, Role::Admin);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let delegate = org
        .as_person(org.admin, || {
            org.vault
                .create_federation_delegate(&org.admin_proof, parent, helper, now, now + 3600)
        })
        .expect("the Admin mints a delegate");
    let minted = json!({
        "delegate_granted": { "grant": delegate.to_hex(), "member": helper.to_hex() }
    });
    for (reader, who) in [
        (org.deputy, "the Deputy"),
        (org.owner, "the Owner"),
        (org.admin, "the Admin, its actor"),
    ] {
        assert_eq!(org.told_of(reader, &minted), 1, "{who} is told of the mint");
    }
    assert_eq!(
        org.told_of(org.steward, &minted),
        0,
        "a Steward is no admin and is not told"
    );
}

#[test]
fn a_house_seated_at_deputy_is_told_of_each_admin_act() {
    let org = Org::new();
    let house = org.store_workspace();
    org.vault
        .set_house_role(&proof(&org.vault, org.owner), WORKSPACE, Role::Deputy)
        .expect("the Owner seats the house at deputy");
    let before = org.house_notices(house).len();

    org.as_person(org.admin, || {
        org.vault.set_workspace_work_companion(
            WORKSPACE,
            WorkCompanionPolicy::Require,
            &org.admin_proof,
        )
    })
    .expect("the Admin sets the work-companion policy");
    assert_eq!(
        org.house_notices(house).len(),
        before + 1,
        "the house, a live Deputy, is told of the Admin's setting"
    );

    let moved = org
        .as_person(org.admin, || {
            org.vault.change_shared_member_role(
                &org.admin_proof,
                SHARED,
                org.member_b,
                Role::Viewer,
                None,
            )
        })
        .expect("the Admin moves a Member to Viewer");
    let told = format!("outcome:{}:{}", house.to_hex(), moved.id);
    assert!(
        org.house_notices(house).contains(&told),
        "and of the Admin's membership change"
    );
    assert!(
        !org.was_told(org.steward, &moved.id),
        "a Steward is still no admin and is not told"
    );
}
