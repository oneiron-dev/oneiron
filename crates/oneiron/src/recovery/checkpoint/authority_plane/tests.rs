use super::super::RestoreReason;
use crate::authority::{CapabilitySlip, HostSlipIssuer};
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound};
use crate::federation::ScopeAxis;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::GateDecisionId;
use crate::{EntityId, Vault, VaultConfig, temporal::TimeRange};
use std::collections::BTreeSet;

const SECRET: &[u8] = b"checkpoint-authority-plane-host";

fn child_slip(vault: &Vault, issuer: &HostSlipIssuer, id: u8) -> CapabilitySlip {
    let root = vault.ensure_host_root_slip(issuer).unwrap();
    let mut claims = root.claims.clone();
    claims.slip_id = [id; 32];
    claims.parent_id = Some(root.claims.slip_id);
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.mint_capability_slip(issuer, claims).unwrap()
}

fn person(vault: &Vault, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )
        .unwrap();
    id
}

#[test]
fn restore_keeps_live_revocations_and_slips_but_returns_old_content() {
    let root = tempfile::tempdir().unwrap();
    let live = Vault::open(root.path().join("vault"), VaultConfig::device()).unwrap();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let revoked_later = child_slip(&live, &issuer, 7);
    let before = person(&live, b"before the backup");
    let image = root.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();

    let after = person(&live, b"after the backup");
    live.revoke_capability_slip(&issuer, revoked_later.claims.slip_id)
        .unwrap();
    let minted_later = child_slip(&live, &issuer, 8);
    assert!(!live.capability_slip_id_is_live(&[7; 32]).unwrap());

    let (restored, report) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &root.path().join("restored"),
        VaultConfig::device(),
        &live,
        200,
    )
    .unwrap();
    assert_eq!(report.epoch.reason, RestoreReason::Restore);
    assert!(restored.get(&before).unwrap().is_some());
    assert!(restored.get(&after).unwrap().is_none());
    // Authority is the live vault's: the revocation holds and the newer slip lives.
    assert!(!restored.capability_slip_id_is_live(&[7; 32]).unwrap());
    assert!(
        restored
            .capability_slip_id_is_live(&minted_later.claims.slip_id)
            .unwrap()
    );
    drop(restored);

    // The plain image restore is the rollback this path exists to prevent.
    let (plain, _) = Vault::restore_checkpoint(
        &image,
        &root.path().join("plain"),
        VaultConfig::device(),
        RestoreReason::Restore,
        200,
    )
    .unwrap();
    assert!(plain.capability_slip_id_is_live(&[7; 32]).unwrap());
    assert!(!plain.capability_slip_id_is_live(&[8; 32]).unwrap());
}

#[test]
fn restore_refuses_to_roll_back_a_guarded_grant_before_creating_anything() {
    let root = tempfile::tempdir().unwrap();
    let live = Vault::open(root.path().join("vault"), VaultConfig::device()).unwrap();
    let owner_id = person(&live, b"owner");
    let image = root.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();
    let owner = live
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .unwrap();
    let bound = GrantBound::action(
        ActorBound::new(owner_id.to_hex()).unwrap(),
        ActionClass::new("claim.put").unwrap(),
        ActionEnvelope::new(["world:home".to_owned()]).unwrap(),
    )
    .unwrap();
    live.create_standing_grant(&owner, bound).unwrap();

    let destination = root.path().join("restored");
    let Err(error) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &destination,
        VaultConfig::device(),
        &live,
        200,
    ) else {
        panic!("the restore must be refused");
    };
    assert!(
        error.to_string().contains("standing consent grants"),
        "{error}"
    );
    assert!(!destination.exists());
}

#[test]
fn restore_refuses_another_vaults_checkpoint() {
    let root = tempfile::tempdir().unwrap();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let other = Vault::open(root.path().join("other"), VaultConfig::device()).unwrap();
    other
        .ensure_host_root_slip(&HostSlipIssuer::from_secret(b"another vault's host").unwrap())
        .unwrap();
    let image = root.path().join("backup");
    other.snapshot_checkpoint(&image, 100).unwrap();
    let live = Vault::open(root.path().join("vault"), VaultConfig::device()).unwrap();
    live.ensure_host_root_slip(&issuer).unwrap();
    let destination = root.path().join("restored");
    let Err(error) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &destination,
        VaultConfig::device(),
        &live,
        200,
    ) else {
        panic!("the restore must be refused");
    };
    assert!(error.to_string().contains("another vault"), "{error}");
    assert!(!destination.exists());
}
