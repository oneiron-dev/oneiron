//! The shared fixture of `house_owner_role_waits.rs` and
//! `house_owner_role_act.rs` (FIX HOUSE-OWNER-ROLE-VIA-ADD-OWNER): a rooted
//! vault on a manual clock whose shared vault has two live Owners and a
//! stored workspace whose house is not seated yet. Every call is on main.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::new_without_default
)]

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
pub(crate) const SHARED: u64 = 43;
pub(crate) const WORKSPACE: &str = "house-owner-role-waits-workspace";
pub(crate) const T0: u64 = 1_800_000_000;
pub(crate) const DAY: u64 = 86_400;
pub(crate) const ADD_OWNER: &str = "add_owner";

pub(crate) fn person(vault: &Vault) -> EntityId {
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

pub(crate) fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A rooted vault on a manual clock: the owner bound by the host root, the
/// root signed once, a shared vault with two live Owners (the owner, and a
/// co-Owner the owner added at once), and a stored workspace whose house is
/// the seeded `sys.default` agent, not yet seated.
pub(crate) struct Org {
    pub(crate) _dir: tempfile::TempDir,
    pub(crate) clock: Arc<ManualClock>,
    pub(crate) vault: Vault,
    pub(crate) issuer: HostSlipIssuer,
    pub(crate) owner: EntityId,
    pub(crate) owner_proof: AuthenticatedOwner,
    pub(crate) co_owner_proof: AuthenticatedOwner,
    pub(crate) house: EntityId,
}

impl Org {
    pub(crate) fn new() -> Self {
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
    pub(crate) fn owner_change_wait_days(&self, days: u64) {
        self.vault
            .set_owner_change_wait_days(&self.owner_proof, SHARED, Some(days))
            .expect("the owner sets the owner-change wait");
    }

    /// The `add_owner` policy row, as shipped but with a one-day window an
    /// Owner may object in, approved by both Owners.
    pub(crate) fn add_owner_objection_window(&self) {
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
    pub(crate) fn house_seat_events(&self) -> Vec<PendingActStarted> {
        self.vault
            .pending_act_started_events(&self.co_owner_proof, SHARED, self.vault.now_recorded_at())
            .expect("the co-Owner reads its started events")
            .into_iter()
            .filter(|event| event.act == ADD_OWNER)
            .collect()
    }

    /// The house link receipts, oldest first.
    pub(crate) fn receipts(&self) -> Vec<ReceiptRecord> {
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
    pub(crate) fn bound_roles(&self) -> Vec<String> {
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
    pub(crate) fn pass(&self, deadline: u64) {
        self.clock.set(deadline + 1);
    }
}

pub(crate) fn field<'r>(receipt: &'r ReceiptRecord, name: &str) -> &'r str {
    receipt
        .fields
        .get(name)
        .map(String::as_str)
        .unwrap_or_default()
}
