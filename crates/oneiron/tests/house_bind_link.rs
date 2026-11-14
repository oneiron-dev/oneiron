//! HOUSE-BIND = A (the owner, 10 Nov 07:43; the Engine's link shapes, 07:5x):
//! the house mind runs its org through a link, never through its anchor.
//!
//! Binding the workspace's house makes it the root's leader and seats it in
//! the workspace's shared vault through one FEDERATION_GRANT at the role its
//! binder names. The house keeps its model PERSON anchor and its actor class,
//! the existing membership gate judges it as that role, and each bind and
//! unbind keeps one `IdentityLifecycle` receipt. The owner's unbind removes
//! the grant and gives the lead back to `sys.team_lead` in a new signed
//! state. The context board's PEOPLE row for the house reads `runs <org> as
//! <role>` while the link is live. Who may set or clear the role is the role
//! table's rule (HOUSE-UNBIND-AUTHORITY = A): `set_house_role` and
//! `clear_house_role` change the role alone under it.
//!
//! Each case but the last opens a vault as a host starts one: rooted under
//! the host, the owner bound, the root signed once. The owner then creates the
//! workspace's shared vault and stores a workspace whose house is the seeded
//! `sys.default` agent. The last case's vault is unrooted, so its Admin and
//! Member write on their grants alone. No `cfg` is needed.

use std::collections::BTreeSet;

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::context_board::PersonRow;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{
    FederationGrantRole, OrgAdminPower, Scope, ScopeAxis, ScopeId, SharedVaultChange,
    SharedVaultWrite,
};
use oneiron::identity_topology::EntityLifecycleState;
use oneiron::memory::PeopleListRequest;
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::subject_model::actor_subject_anchor;
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EntityId, Result, TimeRange, Vault, VaultConfig, WriteActor};

const WORKSPACE: &str = "house-bind-link-workspace";
/// The workspace's shared vault. Not 7, the own-device residence scope's id,
/// whose Owner grants read as device access.
const VAULT_ID: u64 = 41;
const VENTURE: &str = "Garden Works";

/// A started host's vault with one stored workspace, before its house binds.
struct Workspace {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    root: EntityId,
    /// The workspace's house: the seeded `sys.default` agent.
    house: EntityId,
    /// The root's seeded leader, `sys.team_lead`.
    seeded_leader: EntityId,
    org: EntityId,
}

fn workspace() -> Result<Workspace> {
    workspace_shared(true)
}

/// [`workspace`], its shared vault created by the owner first when `shared`.
fn workspace_shared(shared: bool) -> Result<Workspace> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let root = vault.root_project()?;
    vault.sign_owner_project(&owner_proof, &vault.owner_project_signer(&issuer)?, root)?;

    let org = EntityId::from_bytes([0xB2; 16])?;
    vault.put_entity(
        &org,
        ENTITY_TYPE_ORG,
        TimeRange { start: 1, end: 1 },
        1,
        b"house bind link org",
    )?;
    if shared {
        vault.initialize_shared_vault(
            &owner_proof,
            VAULT_ID,
            None,
            &[],
            vault.now_recorded_at(),
        )?;
    }
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("sys.default is seeded on open");
    let (seeded_leader, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")?
        .expect("sys.team_lead is seeded on open");
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: VAULT_ID,
        org_ref: org,
        venture_name: VENTURE.to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    vault.establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &owner_proof)?;
    Ok(Workspace {
        _dir: dir,
        vault,
        issuer,
        owner,
        owner_proof,
        root,
        house,
        seeded_leader,
        org,
    })
}

impl Workspace {
    /// The owner's finish of the workspace: its house leads the root and
    /// runs its org at `role`.
    fn bind(&self, role: FederationGrantRole) -> Result<()> {
        self.vault.bind_workspace_house_leader(
            WORKSPACE,
            role,
            &self.owner_proof,
            &self.vault.owner_project_signer(&self.issuer)?,
        )
    }

    /// The owner's unbind of the root's house.
    fn unbind(&self) -> Result<bool> {
        self.vault.unbind_house_leader(
            &self.owner_proof,
            &self.vault.owner_project_signer(&self.issuer)?,
        )
    }

    fn leader(&self) -> Result<Option<String>> {
        Ok(self.vault.project(self.root)?.map(|project| project.leader))
    }

    /// The FEDERATION_GRANT rows that stand: every one not deleted.
    fn grants(&self) -> Result<BTreeSet<EntityId>> {
        let mut live = BTreeSet::new();
        for grant in self.vault.entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)? {
            if !self.vault.is_deleted_shell(&grant)? {
                live.insert(grant);
            }
        }
        Ok(live)
    }

    /// The house link receipts the owner's acts kept, oldest first.
    fn receipts(&self) -> Result<Vec<ReceiptRecord>> {
        link_receipts(&self.vault, Some(self.owner))
    }

    /// The house's row on the owner's PEOPLE roster, the rows the context
    /// board's `<people>` block renders.
    fn house_row(&self) -> Result<PersonRow> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
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
                .find(|row| row.actors.contains(&self.house))
            {
                return Ok(row);
            }
            assert!(listed.more > 0, "the PEOPLE roster lists the house");
            page += 1;
        }
    }

    /// The house's gates as the shared vault's membership gate reads them:
    /// a content write, a workspace setting, adding a member, the org root.
    /// The host key is bound to the house, as an agent, to ask.
    fn house_gates(&self) -> Result<[bool; 4]> {
        oneiron::test_support::bind_host_actor(&self.vault, &self.issuer, self.house, "agent")?;
        let house = WriteActor::new(self.house, EdgeActorClass::Agent);
        let mut content = Scope::top();
        content.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
        content.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(default_project_id())]));
        let asks = [
            SharedVaultWrite::Content(content),
            SharedVaultWrite::WorkspaceSettings,
            SharedVaultWrite::Admin(OrgAdminPower::AddMember),
            SharedVaultWrite::OrgRoot,
        ];
        Ok(asks.map(|ask| {
            self.vault
                .authorize_shared_vault_write(VAULT_ID, &house, &ask)
                .is_ok()
        }))
    }
}

/// The house link receipts, oldest first: those `actor` kept, or all.
fn link_receipts(vault: &Vault, actor: Option<EntityId>) -> Result<Vec<ReceiptRecord>> {
    let mut query = ReceiptQuery::new(100).with_kind(ReceiptKind::IdentityLifecycle);
    if let Some(actor) = actor {
        query = query.with_actor(actor.to_hex());
    }
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

fn assert_receipt(fx: &Workspace, receipt: &ReceiptRecord, act: &str, role: &str) {
    assert_eq!(receipt.outcome, act);
    assert_eq!(receipt.actor.as_deref(), Some(fx.owner.to_hex().as_str()));
    assert_eq!(field(receipt, "binder"), fx.owner.to_hex());
    assert_eq!(field(receipt, "house"), fx.house.to_hex());
    assert_eq!(field(receipt, "org"), fx.org.to_hex());
    assert_eq!(field(receipt, "role"), role);
    assert_eq!(field(receipt, "workspace_ref"), WORKSPACE);
}

#[test]
fn binding_a_seeded_house_leads_the_root_and_keeps_its_model_person() -> Result<()> {
    let fx = workspace()?;
    let now = fx.vault.now_recorded_at();
    let anchor = actor_subject_anchor(&fx.vault, &fx.house, now)?.expect("the house's anchor");
    assert_eq!(
        fx.vault.get_entity_type(&anchor)?,
        Some(ENTITY_TYPE_PERSON),
        "a seeded agent is anchored to its model PERSON"
    );

    fx.bind(FederationGrantRole::Member)
        .expect("the bind succeeds: it no longer re-anchors the house");
    assert_eq!(
        fx.leader()?,
        Some(fx.house.to_hex()),
        "the house leads the root"
    );
    assert_eq!(
        actor_subject_anchor(&fx.vault, &fx.house, fx.vault.now_recorded_at())?,
        Some(anchor),
        "the house keeps its model PERSON"
    );
    let receipts = fx.receipts()?;
    assert_eq!(receipts.len(), 1, "one bind receipt");
    assert_receipt(&fx, &receipts[0], "bind", "member");

    // Binding again at the same role changes nothing and keeps no receipt.
    let grants = fx.grants()?;
    fx.bind(FederationGrantRole::Member)?;
    assert_eq!(fx.grants()?, grants);
    assert_eq!(fx.receipts()?.len(), 1);
    Ok(())
}

#[test]
fn bind_then_unbind_restores_the_leader_and_the_grant_set_with_two_receipts() -> Result<()> {
    let fx = workspace()?;
    let leader = fx.leader()?;
    assert_eq!(leader, Some(fx.seeded_leader.to_hex()));
    let grants = fx.grants()?;
    let revisions = fx.vault.project_revisions(fx.root)?.len();

    fx.bind(FederationGrantRole::Admin)?;
    let bound = fx.grants()?;
    assert_eq!(
        bound.difference(&grants).count(),
        1,
        "the bind adds one grant"
    );
    assert!(grants.is_subset(&bound), "the bind removes no grant");
    let bound_revisions = fx.vault.project_revisions(fx.root)?.len();
    assert_eq!(bound_revisions, revisions + 1, "the bind signs one state");

    assert!(fx.unbind()?, "the unbind removes the link");
    assert_eq!(fx.leader()?, leader, "the seeded leader leads again");
    assert_eq!(fx.grants()?, grants, "the grant set is the pre-bind one");
    assert_eq!(
        fx.vault.project_revisions(fx.root)?.len(),
        bound_revisions + 1,
        "the unbind is a new signed state, not a rollback"
    );
    let receipts = fx.receipts()?;
    assert_eq!(receipts.len(), 2, "one bind and one unbind receipt");
    assert_receipt(&fx, &receipts[0], "bind", "admin");
    assert_receipt(&fx, &receipts[1], "unbind", "admin");
    assert_eq!(
        field(&receipts[0], "grant"),
        field(&receipts[1], "grant"),
        "the unbind names the grant the bind wrote"
    );

    // Nothing is left to unbind.
    assert!(!fx.unbind()?);
    assert_eq!(fx.receipts()?.len(), 2);
    assert_eq!(fx.leader()?, leader);
    Ok(())
}

#[test]
fn the_house_keeps_its_anchor_and_history_across_bind_and_unbind() -> Result<()> {
    let fx = workspace()?;
    let before = fx.vault.now_recorded_at();
    let anchor = actor_subject_anchor(&fx.vault, &fx.house, before)?;
    let definition = fx.vault.get_agent_definition(&fx.house)?;
    let about_house = fx.vault.claims_for_subject(&fx.house)?;
    let person = anchor.expect("the house's anchor");
    let about_person = fx.vault.claims_for_subject(&person)?;
    let history = |stage: &str| -> Result<()> {
        let now = fx.vault.now_recorded_at();
        assert_eq!(
            actor_subject_anchor(&fx.vault, &fx.house, before)?,
            anchor,
            "{stage}: the anchor as of before the bind"
        );
        assert_eq!(
            actor_subject_anchor(&fx.vault, &fx.house, now)?,
            anchor,
            "{stage}: the anchor now"
        );
        assert_eq!(
            fx.vault.get_agent_definition(&fx.house)?,
            definition,
            "{stage}: the agent's definition"
        );
        assert_eq!(
            fx.vault.claims_for_subject(&fx.house)?,
            about_house,
            "{stage}: the claims about the agent"
        );
        assert_eq!(
            fx.vault.claims_for_subject(&person)?,
            about_person,
            "{stage}: the claims about its PERSON"
        );
        Ok(())
    };

    fx.bind(FederationGrantRole::Steward)?;
    history("bound")?;
    assert!(fx.unbind()?);
    history("unbound")?;
    Ok(())
}

#[test]
fn the_house_is_gated_exactly_as_the_role_it_was_bound_at() -> Result<()> {
    // content, workspace settings, add a member, the org root
    let cases = [
        (FederationGrantRole::Member, [true, false, false, false]),
        (FederationGrantRole::Steward, [false, false, false, false]),
        (FederationGrantRole::Admin, [true, true, true, false]),
        (FederationGrantRole::Owner, [true, true, true, true]),
    ];
    for (role, expected) in cases {
        let fx = workspace()?;
        fx.bind(role)?;
        assert_eq!(
            fx.house_gates()?,
            expected,
            "the house bound as {} is gated as that role",
            role.as_str()
        );
    }
    Ok(())
}

/// The vault's live people, and the owners and members among them.
#[derive(Debug, Default, PartialEq, Eq)]
struct Census {
    people: BTreeSet<EntityId>,
    owners: BTreeSet<EntityId>,
    members: BTreeSet<EntityId>,
}

fn census(vault: &Vault) -> Result<Census> {
    let mut census = Census::default();
    for person in vault.entities_by_type(ENTITY_TYPE_PERSON)? {
        if vault.get_entity_type(&person)? != Some(ENTITY_TYPE_PERSON)
            || !matches!(
                vault.entity_lifecycle_state(&person)?,
                EntityLifecycleState::Active
            )
            || vault.is_deleted_shell(&person)?
        {
            continue;
        }
        census.people.insert(person);
        if vault.is_live_owner_person(&person)? {
            census.owners.insert(person);
        }
        if vault.is_live_member_person(&person)? {
            census.members.insert(person);
        }
    }
    Ok(census)
}

#[test]
fn owner_census_holds_and_the_token_stays_agent_class_for_an_owner_house() -> Result<()> {
    let fx = workspace()?;
    let before = census(&fx.vault)?;
    assert!(
        before.owners.contains(&fx.owner),
        "the census reads the owner"
    );
    let person = actor_subject_anchor(&fx.vault, &fx.house, fx.vault.now_recorded_at())?
        .expect("the house's anchor");
    assert!(
        before.people.contains(&person),
        "the census reads the house's model PERSON"
    );

    fx.bind(FederationGrantRole::Owner)?;
    assert_eq!(
        census(&fx.vault)?,
        before,
        "an Owner link adds no owner, no member and no person"
    );

    // The house's credential, as a host mints its agent's.
    let root = fx.vault.ensure_host_root_slip(&fx.issuer)?;
    let issued_at = fx.vault.capability_slip_now()?;
    let mut claims = root.claims;
    claims.slip_id = [0x5A; 32];
    claims.holder_ref = fx.house.to_hex();
    claims.actor_class = Some("agent".into());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    let slip = fx.vault.mint_capability_slip(&fx.issuer, claims)?;
    let challenge = b"house-bind-link";
    let proof = fx.issuer.binding_proof(&slip, challenge)?;
    let verified =
        fx.vault
            .verify_capability_slip(&fx.issuer.public_key(), &slip, challenge, &proof)?;
    assert_eq!(verified.claims().actor_class.as_deref(), Some("agent"));
    assert!(
        !fx.vault.credential_owner_held(&verified)?,
        "the Owner house's credential is not the vault owner's"
    );
    let key = fx.vault.credential_read_key(&verified)?;
    assert_eq!(
        key.as_ref().and_then(ScopedReadActorKey::actor_class),
        Some("agent"),
        "the house reads as an agent"
    );
    Ok(())
}

#[test]
fn the_people_board_shows_the_house_running_its_org_while_bound() -> Result<()> {
    let fx = workspace()?;
    assert_eq!(fx.house_row()?.role, "preset", "an unbound seeded agent");

    fx.bind(FederationGrantRole::Steward)?;
    let row = fx.house_row()?;
    assert_eq!(row.role, format!("runs {VENTURE} as steward"));
    assert!(
        row.toon_row()
            .contains(&format!("runs {VENTURE} as steward")),
        "the board's row says it"
    );
    let receipts = fx.receipts()?;
    assert_eq!(receipts.len(), 1);
    assert_receipt(&fx, &receipts[0], "bind", "steward");

    assert!(fx.unbind()?);
    assert_eq!(
        fx.house_row()?.role,
        "preset",
        "the link is gone from the board"
    );
    let receipts = fx.receipts()?;
    assert_eq!(receipts.len(), 2);
    assert_receipt(&fx, &receipts[0], "bind", "steward");
    assert_receipt(&fx, &receipts[1], "unbind", "steward");
    Ok(())
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

#[test]
fn an_admin_who_set_a_house_role_clears_it_and_a_member_is_refused() -> Result<()> {
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
            b"house bind link fixture",
        )?;
        Ok(id)
    };
    let org = row(ENTITY_TYPE_ORG)?;
    let admin = row(ENTITY_TYPE_PERSON)?;
    let member = row(ENTITY_TYPE_PERSON)?;
    vault.initialize_shared_vault(&owner_proof, VAULT_ID, None, &[], vault.now_recorded_at())?;
    // An Admin's assignment stands on an MFA step-up (L7-17). An unrooted
    // vault holds no slip to step up on, so this Admin's proof carries a
    // managed supervisor's signed `mfa_verified` claim instead
    // (`tests/org_admin_step_up.rs` steps up with TOTP on a rooted vault).
    let admin_proof = vault.bind_managed_mfa_verified(join(
        &vault,
        &owner_proof,
        admin,
        FederationGrantRole::Admin,
    )?)?;
    let member_proof = join(&vault, &owner_proof, member, FederationGrantRole::Member)?;
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
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
    vault.establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &owner_proof)?;
    let refusal = "whoever may assign that role";

    vault.set_house_role(&admin_proof, WORKSPACE, FederationGrantRole::Member)?;
    let receipts = link_receipts(&vault, None)?;
    assert_eq!(receipts.len(), 1, "the Admin's set keeps one receipt");
    assert_eq!(receipts[0].outcome, "bind");
    assert_eq!(receipts[0].actor.as_deref(), Some(admin.to_hex().as_str()));
    assert_eq!(field(&receipts[0], "role"), "member");

    // An Admin assigns up to Admin: it cannot grant the Owner's powers.
    let error = vault
        .set_house_role(&admin_proof, WORKSPACE, FederationGrantRole::Owner)
        .expect_err("an Admin cannot make the house an Owner");
    assert!(error.to_string().contains(refusal), "{error}");
    let receipts = link_receipts(&vault, None)?;
    assert_eq!(receipts.len(), 1, "the refused Owner set keeps no receipt");
    vault.set_house_role(&admin_proof, WORKSPACE, FederationGrantRole::Admin)?;
    let receipts = link_receipts(&vault, None)?;
    assert_eq!(receipts.len(), 2, "an Admin may set the house up to Admin");
    assert_eq!(field(&receipts[1], "role"), "admin");
    vault.set_house_role(&admin_proof, WORKSPACE, FederationGrantRole::Member)?;
    let error = vault
        .clear_house_role(&member_proof, WORKSPACE)
        .expect_err("a Member cannot clear the house's role");
    assert!(error.to_string().contains(refusal), "{error}");
    assert_eq!(
        link_receipts(&vault, None)?.len(),
        3,
        "the Member's refused clear keeps no receipt"
    );

    assert!(vault.clear_house_role(&admin_proof, WORKSPACE)?);
    let receipts = link_receipts(&vault, None)?;
    assert_eq!(receipts.len(), 4, "the Admin's clear keeps one receipt");
    assert_eq!(receipts[3].outcome, "unbind");
    assert_eq!(receipts[3].actor.as_deref(), Some(admin.to_hex().as_str()));
    assert_eq!(field(&receipts[3], "role"), "member");
    assert!(
        !vault.clear_house_role(&admin_proof, WORKSPACE)?,
        "nothing is left to clear"
    );
    assert_eq!(link_receipts(&vault, None)?.len(), 4);
    Ok(())
}

#[test]
fn a_person_membership_move_refuses_the_house() -> Result<()> {
    let fx = workspace()?;
    fx.bind(FederationGrantRole::Member)?;
    let grants = fx.grants()?;
    let error = fx
        .vault
        .change_shared_member_role(
            &fx.owner_proof,
            VAULT_ID,
            fx.house,
            FederationGrantRole::Admin,
            None,
        )
        .expect_err("a person's role change does not move the house");
    assert!(error.to_string().contains("set_house_role"), "{error}");
    let error = fx
        .vault
        .remove_shared_member(&fx.owner_proof, VAULT_ID, fx.house, None)
        .expect_err("a person's removal does not remove the house");
    assert!(error.to_string().contains("clear_house_role"), "{error}");
    assert_eq!(
        fx.grants()?,
        grants,
        "the house's grant is as the bind left it"
    );
    assert_eq!(fx.receipts()?.len(), 1, "only the bind's receipt");
    assert_eq!(fx.house_row()?.role, format!("runs {VENTURE} as member"));
    Ok(())
}

#[test]
fn a_vault_shared_after_its_house_bound_keeps_the_link() -> Result<()> {
    let fx = workspace_shared(false)?;
    fx.bind(FederationGrantRole::Member)?;
    fx.vault
        .initialize_shared_vault(
            &fx.owner_proof,
            VAULT_ID,
            None,
            &[],
            fx.vault.now_recorded_at(),
        )
        .expect("a house link is no prior membership: the owner shares the vault");
    assert_eq!(fx.house_row()?.role, format!("runs {VENTURE} as member"));
    assert!(census(&fx.vault)?.owners.contains(&fx.owner));
    assert!(fx.unbind()?, "the link still unbinds");
    assert_eq!(fx.receipts()?.len(), 2);
    Ok(())
}

/// A second workspace of the same house, over the own-device residence vault.
const OWN_DEVICE_WORKSPACE: &str = "house-bind-link-own-device-workspace";

#[test]
fn an_owner_house_link_over_the_own_device_vault_is_refused() -> Result<()> {
    let fx = workspace_shared(false)?;
    let preset = WorkspaceRosterPreset {
        workspace_ref: OWN_DEVICE_WORKSPACE.to_owned(),
        workspace_vault_id: 7,
        org_ref: fx.org,
        venture_name: VENTURE.to_owned(),
        house_display_name: None,
        house_actor_ref: fx.house,
        house_identity_ref: None,
    };
    fx.vault
        .establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &fx.owner_proof)?;
    let grants = fx.grants()?;
    let leader = fx.leader()?;
    let bind = |role| {
        fx.vault.bind_workspace_house_leader(
            OWN_DEVICE_WORKSPACE,
            role,
            &fx.owner_proof,
            &fx.vault.owner_project_signer(&fx.issuer)?,
        )
    };

    // An Owner grant over vault 7 would read as the owner's device access.
    let error = bind(FederationGrantRole::Owner)
        .expect_err("no house is linked as Owner over the own-device residence vault");
    assert!(
        error.to_string().contains("own-device residence vault"),
        "{error}"
    );
    assert_eq!(fx.grants()?, grants, "the refused bind writes no grant");
    assert!(fx.receipts()?.is_empty(), "and keeps no receipt");
    assert_eq!(fx.leader()?, leader, "and leaves the root's leader");

    // A Member grant over vault 7 has no own-device shape, and binds.
    bind(FederationGrantRole::Member)?;
    let receipts = fx.receipts()?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(field(&receipts[0], "workspace_vault_id"), "7");
    assert_eq!(field(&receipts[0], "role"), "member");
    Ok(())
}
