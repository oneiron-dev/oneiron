use super::super::RestoreReason;
use crate::authority::{CapabilitySlip, HostSlipIssuer};
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound};
use crate::federation::ScopeAxis;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
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
    // Neither vault has an authority log yet: the store id alone tells them apart.
    let other = Vault::open(root.path().join("other"), VaultConfig::device()).unwrap();
    person(&other, b"another vault's content");
    let image = root.path().join("backup");
    other.snapshot_checkpoint(&image, 100).unwrap();
    let live = Vault::open(root.path().join("vault"), VaultConfig::device()).unwrap();
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

#[test]
fn restore_never_revives_a_spent_approval() {
    use crate::consent::{
        ComposedEffect, EffectFacts, approve_once_authorization_in_txn, spend_approve_once_in_txn,
    };
    let root = tempfile::tempdir().unwrap();
    let live = Vault::open(root.path().join("vault"), VaultConfig::device()).unwrap();
    let owner_id = person(&live, b"owner");
    let owner = live
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .unwrap();
    let digest = ComposedEffect::new(EffectFacts::new("claims.import.review").unwrap()).digest();
    live.approve_once(&owner, digest).unwrap();
    let image = root.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();
    // Spent after the checkpoint, in the image still available.
    live.with_write_txn(|txn| {
        let authorization = approve_once_authorization_in_txn(&live.store, txn, &digest)?
            .expect("approved and unspent");
        spend_approve_once_in_txn(&live.store, txn, &authorization)
    })
    .unwrap();

    let (restored, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &root.path().join("restored"),
        VaultConfig::device(),
        &live,
        200,
    )
    .unwrap();
    let txn = restored.store.env.read_txn().unwrap();
    assert!(matches!(
        approve_once_authorization_in_txn(&restored.store, &txn, &digest),
        Err(error) if error.kind() == crate::ErrorKind::ConsentApproveOnceSpent
    ));
}

#[test]
fn restore_refuses_to_revive_an_owner_deleted_since() {
    let root = tempfile::tempdir().unwrap();
    let live = Vault::open(root.path().join("vault"), VaultConfig::device()).unwrap();
    let owner = live.ensure_embedded_owner_actor().unwrap();
    let image = root.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();
    live.delete_entity_with_options(&owner, crate::deletion::DeleteEntityOptions { purge: true })
        .unwrap();
    assert!(live.live_member_ids().unwrap().is_empty());
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
    assert!(error.to_string().contains("vault owner"), "{error}");
    assert!(!destination.exists());
}

/// ASTRA-9A-2 F1: the secret-scan switch is live policy. Backed up while
/// off, switched on, restored: the scan stays on, its receipts stay, and a
/// credential-shaped write is still refused.
#[test]
fn restore_keeps_the_secret_scan_the_owner_switched_on_since() {
    use crate::policy_model::SecretScanMode;
    let root = tempfile::tempdir().unwrap();
    let live = Vault::open(root.path().join("vault"), VaultConfig::device()).unwrap();
    let owner_id = live.ensure_embedded_owner_actor().unwrap();
    let owner = live
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .unwrap();
    let at = live.now_recorded_at();
    live.set_secret_scan_mode(&owner, SecretScanMode::Off, at)
        .unwrap();
    let image = root.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();
    live.set_secret_scan_mode(&owner, SecretScanMode::On, at + 1)
        .unwrap();

    let (restored, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &root.path().join("restored"),
        VaultConfig::device(),
        &live,
        200,
    )
    .unwrap();
    assert_eq!(restored.secret_scan_mode().unwrap(), SecretScanMode::On);
    assert_eq!(
        restored.secret_scan_change_log().unwrap(),
        live.secret_scan_change_log().unwrap()
    );
    let leak = EntityId::now();
    let refused = restored.put_entity(
        &leak,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"note to self: ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
    );
    assert!(
        refused.is_err(),
        "the scan refuses a credential-shaped write"
    );
    assert!(restored.get(&leak).unwrap().is_none());
}

/// SOL-9A-2-R2 F11: a relationship's participants decide who reads its
/// scoped records. Removing one is a narrowing a restore over the vault from
/// before it must not undo.
#[test]
fn restore_refuses_to_bring_back_a_relationship_participant_removed_since() {
    let root = tempfile::tempdir().unwrap();
    let live = Vault::open(root.path().join("vault"), VaultConfig::device()).unwrap();
    let participant = person(&live, b"participant");
    let relationship = EntityId::now();
    let body = |participants: &[EntityId]| {
        rmp_serde::to_vec_named(&serde_json::json!({
            "participant_ids": participants,
        }))
        .unwrap()
    };
    let at = TimeRange { start: 1, end: 1 };
    live.put_entity(
        &relationship,
        ENTITY_TYPE_RELATIONSHIP,
        at,
        1,
        &body(&[participant]),
    )
    .unwrap();
    let image = root.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();
    live.put_entity(&relationship, ENTITY_TYPE_RELATIONSHIP, at, 2, &body(&[]))
        .unwrap();

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
        error.to_string().contains("relationship participants"),
        "{error}"
    );
    assert!(!destination.exists());
}

/// SOL-9A-2-R2 F18: every vault carries a PROJECT kind it registers at run
/// time. An ordinary edit to a project, here its reason, is content and does
/// not block a restore over the vault.
#[test]
fn restore_goes_ahead_past_an_ordinary_project_edit() {
    let root = tempfile::tempdir().unwrap();
    let live = Vault::open(root.path().join("vault"), VaultConfig::device()).unwrap();
    let project = live.root_project().unwrap();
    let image = root.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();
    let mut record = live.project(project).unwrap().expect("the root project");
    record.why = Some("the reason the owner wrote down".to_owned());
    live.put_project(project, &record, 150).unwrap();

    let (restored, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &root.path().join("restored"),
        VaultConfig::device(),
        &live,
        200,
    )
    .unwrap();
    assert_eq!(restored.project(project).unwrap().unwrap().why, None);
}

/// ASTRA-9A-2-R2 F6: a kind is the engine's by its pack and short-id prefix
/// together. Another pack's kind under the CAMPAIGN prefix is not CAMPAIGN
/// content, so a restore over the vault past an edit to one of its rows is
/// refused like any unclassified kind.
#[test]
fn restore_refuses_a_changed_row_of_another_packs_kind_under_an_engine_prefix() {
    let root = tempfile::tempdir().unwrap();
    let live = Vault::open(root.path().join("vault"), VaultConfig::device()).unwrap();
    let kind = (crate::registry::TYPE_BYTE_ZONE_COMPILED_PRODUCT_START
        ..=crate::registry::TYPE_BYTE_ZONE_COMPILED_PRODUCT_END)
        .find(|byte| {
            crate::registry::entity_type_registry_entry(*byte).is_none()
                && live.structural_kind_registration(*byte).is_none()
        })
        .unwrap();
    live.register_structural_kind(
        kind,
        crate::campaign::CAMPAIGN_SHORT_ID_PREFIX,
        crate::registry::TypeByteZone::CompiledProduct,
        "other-pack",
    )
    .unwrap();
    let row = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    live.put_entity(&row, kind, at, 1, b"first").unwrap();
    let image = root.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();
    live.put_entity(&row, kind, at, 2, b"second").unwrap();

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
        error
            .to_string()
            .contains("entities of an unregistered kind"),
        "{error}"
    );
    assert!(!destination.exists());
}

/// SOL-9A-2-R3 F29: the install executor acts on an approved, active board
/// plugin install even when it is stale, so withdrawing one is a narrowing. A
/// restore over the vault from before the withdrawal is refused rather than
/// bring the install back.
#[test]
fn restore_refuses_to_return_a_stale_plugin_install_withdrawn_since() {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    // No policy manifest, as the other restore regressions run: the write
    // gate's criticality floor would park both the approved body and its
    // retraction for an owner ceremony this fixture does not stage.
    let (_dir, live) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let backups = tempfile::tempdir().unwrap();
    let hub = person(&live, b"hub");
    let mut install = ClaimBody::new(
        crate::context_board::PREDICATE_PLUGIN_SECTION_INSTALL,
        ClaimSubject::Entity(hub),
        rmpv::Value::from("install"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    install.stale = true;
    let claim = EntityId::now();
    live.put_claim(&claim, &install, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let stored = live.get_claim(&claim).unwrap().unwrap();
    assert_eq!(
        (stored.approval, stored.lifecycle, stored.stale),
        (
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
            true
        )
    );
    let image = backups.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();
    live.retract_claim(&claim, 10).unwrap();

    let destination = backups.path().join("restored");
    let error = Vault::restore_checkpoint_keeping_authority(
        &image,
        &destination,
        VaultConfig::device(),
        &live,
        200,
    )
    .err()
    .expect("the restore must be refused");
    assert!(error.to_string().contains("board plugins"), "{error}");
    assert!(!destination.exists());
}
