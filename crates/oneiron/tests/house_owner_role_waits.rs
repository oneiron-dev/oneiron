//! HOUSE-OWNER-ROLE-VIA-ADD-OWNER (Engine RULING HOUSE-UNBIND-AUTHORITY = A,
//! 10 Nov 08:46; ARCH-0043 #vault-owner-changes; ARCH-0063 #house-bind):
//! seating the workspace's house mind at the Owner role makes it a co-Owner,
//! so it waits as a person's Owner add waits.
//!
//! On main `set_house_role(.., owner)` and a bind at Owner wrote the Owner
//! grant at once, past the vault's owner-change wait and its objection
//! window. Now `set_house_role(.., owner)` over the shared vault starts the
//! same `add_owner` act, under its policy row, the common owner-change wait
//! and the objection window, and the act's executor writes the link with
//! its bind receipt. A bind at Owner that the wait would hold is refused.
//! With no wait (the default) the seat is still instant.
//!
//! Red on main: `an_owner_house_link_waits_the_enabled_owner_change_wait`,
//! `a_second_owner_objects_and_the_house_is_not_seated` (the house is seated
//! at once and no act is started) and
//! `a_bind_at_owner_that_the_wait_would_hold_is_refused` (the bind seats the
//! house). Guard, green on main too:
//! `an_owner_house_link_is_instant_with_the_wait_off`.
//!
//! Every call here is on main, so the file builds on main and on the head.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test house_owner_role_waits`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrantRole as Role, InitialSharedMember, PendingActStarted, SharedActPolicy,
    SharedActPrecedence,
};
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_support::bind_host_owner;
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

/// The workspace's shared vault. Not 7, the own-device residence scope's id.
const SHARED: u64 = 43;
const WORKSPACE: &str = "house-owner-role-waits-workspace";
const T0: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const ADD_OWNER: &str = "add_owner";

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    id
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A rooted vault on a manual clock: the owner bound by the host root, the
/// root signed once, a shared vault with two live Owners (the owner, and a
/// co-Owner the owner added at once), and a stored workspace whose house is
/// the seeded `sys.default` agent, not yet seated.
struct Org {
    _dir: tempfile::TempDir,
    clock: Arc<ManualClock>,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    co_owner_proof: AuthenticatedOwner,
    house: EntityId,
}

impl Org {
    fn new() -> Self {
        let clock = ManualClock::new(T0);
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config).expect("vault on its manual clock");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let owner_proof = proof(&vault, owner);
        let root = vault.root_project().expect("the root project");
        vault
            .sign_owner_project(
                &owner_proof,
                &vault.owner_project_signer(&issuer).expect("signer"),
                root,
            )
            .expect("the root's first signature");
        vault
            .initialize_shared_vault(
                &owner_proof,
                SHARED,
                None,
                &[InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                }],
                vault.now_recorded_at(),
            )
            .expect("a shared vault");
        let co_owner = person(&vault);
        let act = vault
            .propose_add_owner(&owner_proof, SHARED, co_owner)
            .expect("the owner starts add_owner");
        vault
            .execute_completed_shared_act(&owner_proof, &act.id, Some(&issuer))
            .expect("a sole Owner's add_owner runs at once");
        let co_owner_proof = proof(&vault, co_owner);
        let org = EntityId::now();
        vault
            .put_entity(
                &org,
                ENTITY_TYPE_ORG,
                TimeRange { start: 1, end: 1 },
                1,
                b"house owner role org",
            )
            .expect("org row");
        let (house, _) = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")
            .expect("read the seeded agents")
            .expect("sys.default is seeded on open");
        let preset = WorkspaceRosterPreset {
            workspace_ref: WORKSPACE.to_owned(),
            workspace_vault_id: SHARED,
            org_ref: org,
            venture_name: "Garden Works".to_owned(),
            house_display_name: None,
            house_actor_ref: house,
            house_identity_ref: None,
        };
        vault
            .establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &owner_proof)
            .expect("the owner stores the workspace");
        Self {
            _dir: dir,
            clock,
            vault,
            issuer,
            owner,
            owner_proof,
            co_owner_proof,
            house,
        }
    }

    /// The vault's common owner-change wait, in days, set by the owner.
    fn owner_change_wait_days(&self, days: u64) {
        self.vault
            .set_owner_change_wait_days(&self.owner_proof, SHARED, Some(days))
            .expect("the owner sets the owner-change wait");
    }

    /// The `add_owner` policy row, as shipped but with a one-day window an
    /// Owner may object in, approved by both Owners.
    fn add_owner_objection_window(&self) {
        let row = SharedActPolicy {
            wait_secs: DAY,
            objector_roles: vec![Role::Owner],
            initiator_roles: vec![Role::Owner],
            policy_editor_roles: vec![Role::Owner],
            required_verb: "admin".to_owned(),
            starter_may_object: true,
            max_act_name_bytes: 128,
            max_payload_bytes: 1_048_576,
            precedence: SharedActPrecedence::HolderMayNarrow,
        };
        self.vault
            .set_shared_act_policy(
                &self.owner_proof,
                &[&self.co_owner_proof],
                SHARED,
                ADD_OWNER,
                Some(row),
                self.vault.now_recorded_at(),
            )
            .expect("both Owners set the add_owner row");
    }

    /// The `add_owner` acts the co-Owner was told of that name no person:
    /// the house's seat. The co-Owner's own add was told to the owner only.
    fn house_seat_events(&self) -> Vec<PendingActStarted> {
        self.vault
            .pending_act_started_events(&self.co_owner_proof, SHARED, self.vault.now_recorded_at())
            .expect("the co-Owner reads its started events")
            .into_iter()
            .filter(|event| event.act == ADD_OWNER)
            .collect()
    }

    /// The house link receipts, oldest first.
    fn receipts(&self) -> Vec<ReceiptRecord> {
        let mut receipts: Vec<ReceiptRecord> = self
            .vault
            .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::IdentityLifecycle))
            .expect("read the receipts")
            .into_iter()
            .filter(|receipt| receipt.receipt_id.starts_with("house_link:"))
            .collect();
        receipts.sort_by_key(|receipt| receipt.receipt_id.clone());
        receipts
    }

    /// The roles the house was bound at, oldest first, each by the owner.
    fn bound_roles(&self) -> Vec<String> {
        self.receipts()
            .iter()
            .map(|receipt| {
                assert_eq!(receipt.outcome, "bind");
                assert_eq!(field(receipt, "house"), self.house.to_hex());
                assert_eq!(field(receipt, "binder"), self.owner.to_hex());
                field(receipt, "role").to_owned()
            })
            .collect()
    }

    /// Moves the store clock past `deadline`.
    fn pass(&self, deadline: u64) {
        self.clock.set(deadline + 1);
    }
}

fn field<'r>(receipt: &'r ReceiptRecord, name: &str) -> &'r str {
    receipt
        .fields
        .get(name)
        .map(String::as_str)
        .unwrap_or_default()
}

#[test]
fn an_owner_house_link_waits_the_enabled_owner_change_wait() {
    let org = Org::new();
    org.owner_change_wait_days(1);
    let started = org.vault.now_recorded_at();

    org.vault
        .set_house_role(&org.owner_proof, WORKSPACE, Role::Owner)
        .expect("the owner seats the house at Owner");

    assert!(
        org.bound_roles().is_empty(),
        "the house holds no Owner seat while the owner-change wait runs"
    );
    let events = org.house_seat_events();
    let [event] = events.as_slice() else {
        panic!("one add_owner act names the house, and the co-Owner is told: {events:?}");
    };
    assert!(
        event.deadline >= started + DAY,
        "the act waits the vault's one-day owner-change wait: {event:?}"
    );
    assert!(
        org.vault
            .execute_completed_shared_act(&org.owner_proof, &event.act_id, Some(&org.issuer))
            .is_err(),
        "the act does not run inside its wait"
    );
    assert!(org.bound_roles().is_empty());

    org.pass(event.deadline);
    org.vault
        .execute_completed_shared_act(&org.owner_proof, &event.act_id, Some(&org.issuer))
        .expect("the matured act runs");
    assert_eq!(
        org.bound_roles(),
        ["owner"],
        "the act's executor seats the house at Owner, with one bind receipt naming the owner"
    );
}

#[test]
fn an_owner_house_link_is_instant_with_the_wait_off() {
    let org = Org::new();

    org.vault
        .set_house_role(&org.owner_proof, WORKSPACE, Role::Owner)
        .expect("the owner seats the house at Owner");

    assert_eq!(
        org.bound_roles(),
        ["owner"],
        "with no wait the house is an Owner at once, as before"
    );
    org.vault
        .set_house_role(&org.owner_proof, WORKSPACE, Role::Owner)
        .expect("the same seat again is a retry");
    assert_eq!(
        org.bound_roles(),
        ["owner"],
        "a retry keeps no second receipt"
    );
}

#[test]
fn a_second_owner_objects_and_the_house_is_not_seated() {
    let org = Org::new();
    org.add_owner_objection_window();

    org.vault
        .set_house_role(&org.owner_proof, WORKSPACE, Role::Owner)
        .expect("the owner seats the house at Owner");
    let events = org.house_seat_events();
    let [event] = events.as_slice() else {
        panic!("one add_owner act names the house: {events:?}");
    };
    org.vault
        .change_authority_objection(&org.co_owner_proof, &event.act_id, true)
        .expect("the co-Owner objects inside the window");

    org.pass(event.deadline);
    assert!(
        org.vault
            .execute_completed_shared_act(&org.owner_proof, &event.act_id, Some(&org.issuer))
            .is_err(),
        "an act a live Owner objects to does not run"
    );
    assert!(
        org.bound_roles().is_empty(),
        "the house holds no Owner seat after the objection"
    );
}

#[test]
fn a_bind_at_owner_that_the_wait_would_hold_is_refused() {
    let org = Org::new();
    org.owner_change_wait_days(1);
    let signer = org
        .vault
        .owner_project_signer(&org.issuer)
        .expect("the owner's project signer");

    let error = org
        .vault
        .bind_workspace_house_leader(WORKSPACE, Role::Owner, &org.owner_proof, &signer)
        .expect_err("a bind at Owner skips no owner-change wait");
    assert!(
        error.to_string().contains("owner-change wait"),
        "the refusal names the wait: {error}"
    );
    assert!(
        org.bound_roles().is_empty(),
        "the refused bind writes nothing"
    );

    org.vault
        .bind_workspace_house_leader(WORKSPACE, Role::Deputy, &org.owner_proof, &signer)
        .expect("a bind below Owner is instant");
    org.vault
        .set_house_role(&org.owner_proof, WORKSPACE, Role::Owner)
        .expect("the owner raises the house to Owner");
    assert_eq!(
        org.bound_roles(),
        ["deputy"],
        "the house stays Deputy while the raise waits"
    );
    let events = org.house_seat_events();
    let [event] = events.as_slice() else {
        panic!("one add_owner act names the house: {events:?}");
    };
    org.pass(event.deadline);
    org.vault
        .execute_completed_shared_act(&org.owner_proof, &event.act_id, Some(&org.issuer))
        .expect("the matured raise runs");
    assert_eq!(org.bound_roles(), ["deputy", "owner"]);
}
