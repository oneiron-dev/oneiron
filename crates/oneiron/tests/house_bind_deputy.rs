//! HOUSE-ROLE-DEPUTY-AFTER-7071 = A (the Engine, 12 Nov 09:36), on DEPUTY = A
//! (the owner, 10 Nov 07:45) and HOUSE-UNBIND-AUTHORITY = A: a house mind
//! runs its org as deputy, and only an Owner seats it there.
//!
//! The house role takes `deputy` beside member, steward, admin and owner. A
//! house bound at deputy is gated as a deputy, an Admin's powers without the
//! org root, and reads `runs <org> as deputy` on the PEOPLE roster. Who may
//! set it is the role table's rule for a role above Admin: only an Owner
//! seats a house at deputy, and only an Owner moves or clears it from there.
//! Steward is the owner's to give as well (C1, #6988; the Engine's ruling of
//! 12 Nov 09:36 on HOUSE-ROLE-DEPUTY-AFTER-7071), so the same holds for a
//! steward house. An Admin keeps setting member and admin.
//!
//! The first case opens a vault as a host starts one (rooted under the host,
//! the owner bound, the root signed once) and the owner binds the stored
//! workspace's house, the seeded `sys.default` agent. The other cases' vault
//! is unrooted, so its Admin writes on its grant alone, as in
//! `house_bind_link.rs`. No `cfg` is needed. The finish's default role,
//! deputy, is the server's (`oneiron-server/tests/house_finish_role.rs`).
//!
//! Fleet command: `cargo test --locked -p oneiron --all-features --test
//! house_bind_deputy`.

use std::collections::BTreeSet;

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{
    FederationGrantRole, OrgAdminPower, Scope, ScopeAxis, ScopeId, SharedVaultChange,
    SharedVaultWrite,
};
use oneiron::memory::PeopleListRequest;
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset, parse_house_role};
use oneiron::{EntityId, Result, TimeRange, Vault, VaultConfig, WriteActor};

const WORKSPACE: &str = "house-bind-deputy-workspace";
/// The workspace's shared vault. Not 7, the own-device residence scope's id.
const VAULT_ID: u64 = 43;
const VENTURE: &str = "Garden Works";
/// The role table's refusal for an assigner who may not assign the role.
const ASSIGNER_REFUSAL: &str = "whoever may assign that role";

/// The house link receipts, oldest first.
fn link_receipts(vault: &Vault) -> Result<Vec<ReceiptRecord>> {
    let query = ReceiptQuery::new(100).with_kind(ReceiptKind::IdentityLifecycle);
    let mut receipts: Vec<ReceiptRecord> = vault
        .receipts(query)?
        .into_iter()
        .filter(|receipt| receipt.receipt_id.starts_with("house_link:"))
        .collect();
    receipts.sort_by_key(|receipt| receipt.receipt_id.clone());
    Ok(receipts)
}

/// The receipt's named field.
fn field<'r>(receipt: &'r ReceiptRecord, name: &str) -> &'r str {
    receipt
        .fields
        .get(name)
        .map(String::as_str)
        .unwrap_or_default()
}

/// `house`'s row role on `owner`'s PEOPLE roster, the line the context
/// board's `<people>` block renders.
fn house_row_role(vault: &Vault, owner: EntityId, house: EntityId) -> String {
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let mut page = 0;
    loop {
        let listed = memory
            .people_list(&PeopleListRequest {
                vault: None,
                page: Some(page),
            })
            .expect("the owner lists the vault's people");
        if let Some(row) = listed
            .people
            .into_iter()
            .find(|row| row.actors.contains(&house))
        {
            return row.role;
        }
        assert!(listed.more > 0, "the PEOPLE roster lists the house");
        page += 1;
    }
}

/// The stored workspace whose house is the seeded `sys.default` agent, over
/// `org`. Its house.
fn store_workspace(vault: &Vault, owner_proof: &AuthenticatedOwner, org: EntityId) -> EntityId {
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .expect("read the seeded agents")
        .expect("sys.default is seeded on open");
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: VAULT_ID,
        org_ref: org,
        venture_name: VENTURE.to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    vault
        .establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, owner_proof)
        .expect("the owner stores the workspace");
    house
}

#[test]
fn an_owner_binds_a_house_at_deputy_and_it_is_gated_as_a_deputy() -> Result<()> {
    assert_eq!(
        parse_house_role("deputy"),
        Some(FederationGrantRole::Deputy),
        "deputy is a house role's spelling"
    );
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer: HostSlipIssuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let root = vault.root_project()?;
    vault.sign_owner_project(&owner_proof, &vault.owner_project_signer(&issuer)?, root)?;
    let org = EntityId::now();
    vault.put_entity(
        &org,
        ENTITY_TYPE_ORG,
        TimeRange { start: 1, end: 1 },
        1,
        b"house bind deputy org",
    )?;
    vault.initialize_shared_vault(&owner_proof, VAULT_ID, None, &[], vault.now_recorded_at())?;
    let house = store_workspace(&vault, &owner_proof, org);

    vault
        .bind_workspace_house_leader(
            WORKSPACE,
            FederationGrantRole::Deputy,
            &owner_proof,
            &vault.owner_project_signer(&issuer)?,
        )
        .expect("the owner binds the house at deputy");

    let receipts = link_receipts(&vault)?;
    assert_eq!(receipts.len(), 1, "the bind keeps one receipt");
    assert_eq!(receipts[0].outcome, "bind");
    assert_eq!(field(&receipts[0], "role"), "deputy");
    assert_eq!(field(&receipts[0], "binder"), owner.to_hex());
    assert_eq!(
        house_row_role(&vault, owner, house),
        format!("runs {VENTURE} as deputy"),
        "the PEOPLE roster reads the house's role back"
    );

    // content, workspace settings, add a member, the org root: an Admin's
    // powers, never the org root.
    oneiron::test_support::bind_host_actor(&vault, &issuer, house, "agent")?;
    let actor = WriteActor::new(house, EdgeActorClass::Agent);
    let mut content = Scope::top();
    content.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    content.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(default_project_id())]));
    let asks = [
        SharedVaultWrite::Content(content),
        SharedVaultWrite::WorkspaceSettings,
        SharedVaultWrite::Admin(OrgAdminPower::AddMember),
        SharedVaultWrite::OrgRoot,
    ];
    let gates = asks.map(|ask| {
        vault
            .authorize_shared_vault_write(VAULT_ID, &actor, &ask)
            .is_ok()
    });
    assert_eq!(
        gates,
        [true, true, true, false],
        "a deputy house holds an Admin's powers and never the org root"
    );
    Ok(())
}

/// An unrooted vault with a shared vault, an Admin and a Member who joined
/// it, and a stored workspace: the owner's proof, the Admin's and the
/// Member's, the owner and the house.
struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    admin: EntityId,
    admin_proof: AuthenticatedOwner,
    member_proof: AuthenticatedOwner,
}

/// `person` joins the shared vault at `role`: the owner invites, the person
/// accepts. Their proof.
fn join(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    person: EntityId,
    role: FederationGrantRole,
) -> Result<AuthenticatedOwner> {
    let invited = vault.add_shared_member(owner_proof, VAULT_ID, person, Some(role))?;
    let SharedVaultChange::MemberInvited { invitation, .. } = invited.change else {
        panic!("the owner's add is an invitation");
    };
    let proof = vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?;
    vault.accept_shared_invitation(&proof, VAULT_ID, &invitation)?;
    Ok(proof)
}

fn org() -> Result<Org> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let row = |entity_type: u8| -> Result<EntityId> {
        let id = EntityId::now();
        vault.put_entity(
            &id,
            entity_type,
            TimeRange { start: 1, end: 1 },
            1,
            b"house bind deputy fixture",
        )?;
        Ok(id)
    };
    let org = row(ENTITY_TYPE_ORG)?;
    let admin = row(ENTITY_TYPE_PERSON)?;
    let member = row(ENTITY_TYPE_PERSON)?;
    vault.initialize_shared_vault(&owner_proof, VAULT_ID, None, &[], vault.now_recorded_at())?;
    let admin_proof = join(&vault, &owner_proof, admin, FederationGrantRole::Admin)?;
    let member_proof = join(&vault, &owner_proof, member, FederationGrantRole::Member)?;
    store_workspace(&vault, &owner_proof, org);
    Ok(Org {
        _dir: dir,
        vault,
        owner,
        owner_proof,
        admin,
        admin_proof,
        member_proof,
    })
}

#[test]
fn only_an_owner_seats_a_house_at_deputy_and_moves_it_from_there() -> Result<()> {
    let fx = org()?;

    let error = fx
        .vault
        .set_house_role(&fx.admin_proof, WORKSPACE, FederationGrantRole::Deputy)
        .expect_err("an Admin cannot seat the house at deputy");
    assert!(error.to_string().contains(ASSIGNER_REFUSAL), "{error}");
    let error = fx
        .vault
        .set_house_role(&fx.member_proof, WORKSPACE, FederationGrantRole::Deputy)
        .expect_err("a Member cannot seat the house at deputy");
    assert!(error.to_string().contains(ASSIGNER_REFUSAL), "{error}");
    assert!(
        link_receipts(&fx.vault)?.is_empty(),
        "the refused sets keep no receipt"
    );

    fx.vault
        .set_house_role(&fx.owner_proof, WORKSPACE, FederationGrantRole::Deputy)
        .expect("the Owner seats the house at deputy");
    let receipts = link_receipts(&fx.vault)?;
    assert_eq!(receipts.len(), 1, "the Owner's set keeps one receipt");
    assert_eq!(receipts[0].outcome, "bind");
    assert_eq!(
        receipts[0].actor.as_deref(),
        Some(fx.owner.to_hex().as_str())
    );
    assert_eq!(field(&receipts[0], "role"), "deputy");

    // The role a set replaces is assigned too: an Admin cannot move a deputy
    // house down to Member, nor clear it.
    let error = fx
        .vault
        .set_house_role(&fx.admin_proof, WORKSPACE, FederationGrantRole::Member)
        .expect_err("an Admin cannot move a deputy house");
    assert!(error.to_string().contains(ASSIGNER_REFUSAL), "{error}");
    let error = fx
        .vault
        .clear_house_role(&fx.admin_proof, WORKSPACE)
        .expect_err("an Admin cannot clear a deputy house");
    assert!(error.to_string().contains(ASSIGNER_REFUSAL), "{error}");
    assert_eq!(
        link_receipts(&fx.vault)?.len(),
        1,
        "the Admin's refused move and clear keep no receipt"
    );

    assert!(
        fx.vault.clear_house_role(&fx.owner_proof, WORKSPACE)?,
        "the Owner clears the deputy house"
    );
    let receipts = link_receipts(&fx.vault)?;
    assert_eq!(receipts.len(), 2, "the Owner's clear keeps one receipt");
    assert_eq!(receipts[1].outcome, "unbind");
    assert_eq!(field(&receipts[1], "role"), "deputy");
    Ok(())
}

#[test]
fn only_an_owner_seats_a_house_at_steward_and_moves_it_from_there() -> Result<()> {
    let fx = org()?;

    let error = fx
        .vault
        .set_house_role(&fx.admin_proof, WORKSPACE, FederationGrantRole::Steward)
        .expect_err("an Admin cannot seat the house at steward");
    assert!(error.to_string().contains(ASSIGNER_REFUSAL), "{error}");
    assert!(
        link_receipts(&fx.vault)?.is_empty(),
        "the refused set keeps no receipt"
    );

    fx.vault
        .set_house_role(&fx.owner_proof, WORKSPACE, FederationGrantRole::Steward)
        .expect("the Owner seats the house at steward");
    let receipts = link_receipts(&fx.vault)?;
    assert_eq!(receipts.len(), 1, "the Owner's set keeps one receipt");
    assert_eq!(field(&receipts[0], "role"), "steward");

    // The role a set replaces is assigned too: an Admin cannot move a
    // steward house to Member, nor clear it.
    let error = fx
        .vault
        .set_house_role(&fx.admin_proof, WORKSPACE, FederationGrantRole::Member)
        .expect_err("an Admin cannot move a steward house");
    assert!(error.to_string().contains(ASSIGNER_REFUSAL), "{error}");
    let error = fx
        .vault
        .clear_house_role(&fx.admin_proof, WORKSPACE)
        .expect_err("an Admin cannot clear a steward house");
    assert!(error.to_string().contains(ASSIGNER_REFUSAL), "{error}");
    assert_eq!(
        link_receipts(&fx.vault)?.len(),
        1,
        "the Admin's refused move and clear keep no receipt"
    );

    assert!(
        fx.vault.clear_house_role(&fx.owner_proof, WORKSPACE)?,
        "the Owner clears the steward house"
    );
    assert_eq!(link_receipts(&fx.vault)?.len(), 2);
    Ok(())
}

#[test]
fn an_admin_still_seats_a_house_at_member_or_admin() -> Result<()> {
    let fx = org()?;
    for role in [FederationGrantRole::Member, FederationGrantRole::Admin] {
        fx.vault
            .set_house_role(&fx.admin_proof, WORKSPACE, role)
            .unwrap_or_else(|error| panic!("an Admin seats the house at {role:?}: {error}"));
    }
    let receipts = link_receipts(&fx.vault)?;
    let roles: Vec<&str> = receipts
        .iter()
        .map(|receipt| field(receipt, "role"))
        .collect();
    assert_eq!(roles, ["member", "admin"]);
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.actor.as_deref() == Some(fx.admin.to_hex().as_str())),
        "each set names the Admin"
    );
    Ok(())
}

#[test]
fn no_house_runs_its_org_as_viewer_delegate_or_guest() {
    for spelling in ["viewer", "delegate", "guest", "auditor", "Deputy", ""] {
        assert_eq!(
            parse_house_role(spelling),
            None,
            "{spelling:?} is no house role"
        );
    }
    for (spelling, role) in [
        ("member", FederationGrantRole::Member),
        ("steward", FederationGrantRole::Steward),
        ("admin", FederationGrantRole::Admin),
        ("owner", FederationGrantRole::Owner),
    ] {
        assert_eq!(parse_house_role(spelling), Some(role), "{spelling}");
    }
}
