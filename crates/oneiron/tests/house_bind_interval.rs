//! HOUSE-BIND = A, S3 (the Engine, 07:5x and 08:11): the org a house ran at
//! a given time comes from its bind and unbind receipts alone, so an unbind
//! never changes how a statement written before it reads. Statement bylines
//! will read it at each statement's write time (FIX row
//! SPEAKER-BYLINE-FOR-ORG); this case reads it through its test door on both
//! sides of an unbind, after the unbind.
//!
//! The vault runs on an injected clock, moved on between the bind and the
//! unbind, so the two receipts carry different times. Built only under
//! `--cfg oneiron_test_support`, which compiles the test door.
#![cfg(oneiron_test_support)]

use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::federation::FederationGrantRole;
use oneiron::receipt::{ReceiptKind, ReceiptQuery};
use oneiron::registry::ENTITY_TYPE_ORG;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::house_link::house_org_at;
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EntityId, Result, TimeRange, Vault, VaultConfig};

const WORKSPACE: &str = "house-bind-interval-workspace";

/// The time of the house link receipt that records `act`, the latest one.
fn receipt_time(vault: &Vault, owner: EntityId, act: &str) -> Result<u64> {
    Ok(vault
        .receipts(
            ReceiptQuery::new(100)
                .with_kind(ReceiptKind::IdentityLifecycle)
                .with_actor(owner.to_hex())
                .with_outcome(act),
        )?
        .into_iter()
        .filter(|receipt| receipt.receipt_id.starts_with("house_link:"))
        .map(|receipt| receipt.occurred_at)
        .max()
        .expect("the house link receipt"))
}

#[test]
fn the_house_runs_its_org_inside_its_bind_interval_and_not_after_its_unbind() -> Result<()> {
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();
    let clock = ManualClock::new(start);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), config)?;
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
        b"house bind interval org",
    )?;
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("sys.default is seeded on open");
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: 41,
        org_ref: org,
        venture_name: "Garden Works".to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    vault.establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &owner_proof)?;

    vault.bind_workspace_house_leader(
        WORKSPACE,
        FederationGrantRole::Member,
        &owner_proof,
        &signer,
    )?;
    let bound_at = receipt_time(&vault, owner, "bind")?;
    assert_eq!(house_org_at(&vault, house, u64::MAX)?, Some(org), "bound");

    clock.set(start + 600);
    assert!(vault.unbind_house_leader(&owner_proof, &signer)?);
    let unbound_at = receipt_time(&vault, owner, "unbind")?;
    assert!(unbound_at > bound_at, "the clock moved between the two");

    // Read after the unbind, on both sides of it.
    assert_eq!(
        house_org_at(&vault, house, bound_at - 1)?,
        None,
        "before the bind the house ran no org"
    );
    assert_eq!(
        house_org_at(&vault, house, bound_at)?,
        Some(org),
        "from the bind it ran the org"
    );
    assert_eq!(
        house_org_at(&vault, house, unbound_at - 1)?,
        Some(org),
        "a statement written just before the unbind still reads the org"
    );
    assert_eq!(
        house_org_at(&vault, house, unbound_at)?,
        None,
        "from the unbind it runs none"
    );
    assert_eq!(house_org_at(&vault, house, u64::MAX)?, None, "unbound");

    // A second bind opens a second interval and leaves the first as it read.
    clock.set(start + 1_200);
    vault.bind_workspace_house_leader(
        WORKSPACE,
        FederationGrantRole::Admin,
        &owner_proof,
        &signer,
    )?;
    let rebound_at = receipt_time(&vault, owner, "bind")?;
    assert!(rebound_at > unbound_at);
    assert_eq!(house_org_at(&vault, house, unbound_at - 1)?, Some(org));
    assert_eq!(
        house_org_at(&vault, house, rebound_at - 1)?,
        None,
        "between the two binds it ran none"
    );
    assert_eq!(house_org_at(&vault, house, rebound_at)?, Some(org));
    Ok(())
}
