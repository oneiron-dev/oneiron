//! HOUSE-BIND = A and OWN-DEVICE-GRANT-PURPOSE-MARKER: a house bound as an
//! Owner holds no own-device grant. `federation::is_own_device_grant` reads a
//! grant's shape alone (an Owner grant over the own-device residence vault,
//! neither delegated nor a guest's), so the link refuses that one vault for
//! an Owner house (house_bind_link.rs,
//! `an_owner_house_link_over_the_own_device_vault_is_refused`). This case
//! reads the predicate itself on the grant an Owner bind writes, through its
//! test door. Built only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use oneiron::federation::{FederationGrantRole, own_device_residence_scope};
use oneiron::receipt::{ReceiptKind, ReceiptQuery};
use oneiron::registry::ENTITY_TYPE_ORG;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::house_link::is_own_device_grant;
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EntityId, Result, TimeRange, Vault, VaultConfig};

const WORKSPACE: &str = "house-bind-own-device-workspace";
/// The workspace's shared vault. Not 7, the own-device residence scope's id.
const VAULT_ID: u64 = 41;

#[test]
fn an_owner_house_grant_is_no_own_device_grant() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let signer = vault.owner_project_signer(&issuer)?;
    vault.sign_owner_project(&owner_proof, &signer, vault.root_project()?)?;
    let org = EntityId::from_bytes([0xB2; 16])?;
    vault.put_entity(
        &org,
        ENTITY_TYPE_ORG,
        TimeRange { start: 1, end: 1 },
        1,
        b"house bind own device org",
    )?;
    vault.initialize_shared_vault(&owner_proof, VAULT_ID, None, &[], vault.now_recorded_at())?;
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("sys.default is seeded on open");
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: VAULT_ID,
        org_ref: org,
        venture_name: "Garden Works".to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    vault.establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &owner_proof)?;

    vault.bind_workspace_house_leader(
        WORKSPACE,
        FederationGrantRole::Owner,
        &owner_proof,
        &signer,
    )?;
    let grant = vault
        .receipts(
            ReceiptQuery::new(100)
                .with_kind(ReceiptKind::IdentityLifecycle)
                .with_outcome("bind"),
        )?
        .into_iter()
        .find(|receipt| receipt.receipt_id.starts_with("house_link:"))
        .and_then(|receipt| receipt.fields.get("grant").cloned())
        .expect("the bind receipt names its grant");
    let grant = EntityId::from_hex(&grant)?;
    assert!(
        !is_own_device_grant(&vault, grant)?,
        "the Owner house's grant is no own-device grant"
    );
    assert_ne!(
        oneiron::federation::FederationGrantScope::vault(VAULT_ID),
        own_device_residence_scope(),
        "its scope is the workspace's vault, not the own-device residence scope"
    );
    Ok(())
}
