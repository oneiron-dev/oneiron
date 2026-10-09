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

/// An evidence-bearing `comm.jurisdiction` observation of `recipient`.
fn jurisdiction_observation(
    recipient: EntityId,
    jurisdiction: &str,
    observed_at: u64,
) -> crate::claim::ClaimBody {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    let mut observation = ClaimBody::new(
        crate::campaign::claims::PREDICATE_COMM_JURISDICTION,
        ClaimSubject::Entity(recipient),
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("jurisdiction"),
                rmpv::Value::from(jurisdiction),
            ),
            (
                rmpv::Value::from("observed_at"),
                rmpv::Value::from(observed_at),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    observation.evidence = Some(rmpv::Value::from("connector:profile-region"));
    observation
}

/// Enrolls `recipient` in a campaign by email, returning the membership.
fn enroll(live: &Vault, recipient: EntityId) -> EntityId {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    let entry = |key: &str, value: rmpv::Value| (rmpv::Value::from(key), value);
    let reference = || rmpv::Value::from(EntityId::now().to_hex());
    let member = ClaimBody::new(
        crate::campaign::claims::PREDICATE_CAMPAIGN_MEMBER,
        ClaimSubject::Entity(recipient),
        rmpv::Value::Map(vec![
            entry("campaign", reference()),
            entry(
                "state",
                rmpv::Value::Map(vec![entry("kind", rmpv::Value::from("enrolled"))]),
            ),
            entry(
                "channels",
                rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                    entry("channel", rmpv::Value::from("email")),
                    entry("basis_evidence", reference()),
                    entry("sender_ref", reference()),
                ])]),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    let id = EntityId::now();
    live.put_claim(&id, &member, TimeRange { start: 5, end: 5 }, 5)
        .unwrap();
    id
}

/// ASTRA-9A-2-R3 F4: a campaign recipient's newest `comm.jurisdiction`
/// observation picks which compliance rules bind a campaign send. A restore
/// from before a newer observation that moved it is refused rather than send
/// under the older jurisdiction's rules. A refreshed observation with the
/// same result, or a moved one for someone in no campaign (SOL-9A-2-R3 F31),
/// does not block the restore.
#[test]
fn restore_refuses_to_roll_back_a_recipient_jurisdiction_moved_since() {
    // Reopened at once so it holds the policy a restored copy's open seeds.
    let (dir, live) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let live = crate::test_util::reopen_test_vault(&dir, live);
    let backups = tempfile::tempdir().unwrap();
    let recipient = person(&live, b"recipient");
    let bystander = person(&live, b"bystander");
    enroll(&live, recipient);
    let observe = |subject: EntityId, jurisdiction: &str, observed_at: u64| {
        live.put_claim(
            &EntityId::now(),
            &jurisdiction_observation(subject, jurisdiction, observed_at),
            TimeRange {
                start: observed_at,
                end: observed_at,
            },
            observed_at,
        )
        .unwrap();
    };
    observe(recipient, "UK", 10);
    observe(bystander, "UK", 10);
    let image = backups.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();
    let restore = |name: &str| {
        Vault::restore_checkpoint_keeping_authority(
            &image,
            &backups.path().join(name),
            VaultConfig::device(),
            &live,
            200,
        )
        .map(drop)
    };

    observe(bystander, "US", 15);
    restore("bystander").expect("a jurisdiction outside every campaign is content");
    observe(recipient, "uk", 20);
    restore("refreshed").expect("the same jurisdiction, observed again, restores");

    observe(recipient, "US", 30);
    let error = restore("moved").expect_err("a moved jurisdiction refuses the restore");
    assert!(
        error.to_string().contains("recipient jurisdictions"),
        "{error}"
    );
    assert!(!backups.path().join("moved").exists());
}

/// ASTRA-9A-2-R3 F5: an older jurisdiction observation rewritten under its id
/// into another claim and made private keeps its read scope compared, though
/// the jurisdiction the campaign gate selects did not move.
#[test]
fn restore_refuses_to_reopen_a_jurisdiction_claim_made_private_since() {
    let (_dir, live) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let backups = tempfile::tempdir().unwrap();
    let recipient = person(&live, b"recipient");
    let older = EntityId::now();
    for (id, observed_at) in [(older, 10), (EntityId::now(), 20)] {
        live.put_claim(
            &id,
            &jurisdiction_observation(recipient, "UK", observed_at),
            TimeRange {
                start: observed_at,
                end: observed_at,
            },
            observed_at,
        )
        .unwrap();
    }
    let image = backups.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();

    let mut rewritten = live.get_claim(&older).unwrap().unwrap();
    rewritten.predicate = "profile.region".to_owned();
    let mut scope = match rewritten.scope.take() {
        Some(rmpv::Value::Map(entries)) => entries,
        _ => Vec::new(),
    };
    scope.retain(|(key, _)| key.as_str() != Some("private"));
    scope.push((rmpv::Value::from("private"), rmpv::Value::from(true)));
    rewritten.scope = Some(rmpv::Value::Map(scope));
    live.put_claim(&older, &rewritten, TimeRange { start: 10, end: 10 }, 30)
        .unwrap();
    assert!(crate::claim::claim_access_axes(&live.get_claim(&older).unwrap().unwrap()).1);

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
    assert!(error.to_string().contains("claim privacy"), "{error}");
    assert!(!destination.exists());
}

/// ASTRA-9A-2-R3 F6 / SOL-9A-2-R3 F32: the campaign gate finds a subject's
/// membership and jurisdiction claims through their `claim_of` edges,
/// whatever subject a body now names. A membership rewritten under its id to
/// name someone else before the backup still enrolls the recipient it was
/// written for, so that recipient's jurisdiction moved since refuses the
/// restore.
#[test]
fn restore_reads_campaign_recipients_through_their_claim_of_edges() {
    let (_dir, live) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let backups = tempfile::tempdir().unwrap();
    let recipient = person(&live, b"recipient");
    let other = person(&live, b"other");
    let member = enroll(&live, recipient);
    let mut retargeted = live.get_claim(&member).unwrap().unwrap();
    retargeted.subject = crate::claim::ClaimSubject::Entity(other);
    live.put_claim(&member, &retargeted, TimeRange { start: 5, end: 5 }, 6)
        .unwrap();
    let observation = EntityId::now();
    live.put_claim(
        &observation,
        &jurisdiction_observation(recipient, "UK", 10),
        TimeRange { start: 10, end: 10 },
        10,
    )
    .unwrap();
    let image = backups.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();

    let mut moved = live.get_claim(&observation).unwrap().unwrap();
    moved.value = jurisdiction_observation(recipient, "US", 30).value;
    live.put_claim(&observation, &moved, TimeRange { start: 10, end: 10 }, 30)
        .unwrap();

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
    assert!(
        error.to_string().contains("recipient jurisdictions"),
        "{error}"
    );
    assert!(!destination.exists());
}

/// SOL-9A-2-R3 F33: the campaign gate reads the jurisdiction of the PERSON a
/// recipient's address resolves to, and of nothing else. A moved
/// jurisdiction of another kind of entity a membership reaches is content.
#[test]
fn restore_goes_ahead_past_a_moved_jurisdiction_of_a_non_person() {
    // Reopened at once so it holds the policy a restored copy's open seeds.
    let (dir, live) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let live = crate::test_util::reopen_test_vault(&dir, live);
    let backups = tempfile::tempdir().unwrap();
    let org = EntityId::now();
    live.put_entity(
        &org,
        crate::registry::ENTITY_TYPE_ORG,
        TimeRange { start: 1, end: 1 },
        1,
        b"org",
    )
    .unwrap();
    enroll(&live, org);
    let observe = |jurisdiction: &str, observed_at: u64| {
        live.put_claim(
            &EntityId::now(),
            &jurisdiction_observation(org, jurisdiction, observed_at),
            TimeRange {
                start: observed_at,
                end: observed_at,
            },
            observed_at,
        )
        .unwrap();
    };
    observe("UK", 10);
    let image = backups.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();
    observe("US", 30);

    Vault::restore_checkpoint_keeping_authority(
        &image,
        &backups.path().join("restored"),
        VaultConfig::device(),
        &live,
        200,
    )
    .expect("an organisation's jurisdiction binds no campaign send");
}

/// ASTRA-9A-2-R3 F7: an ordinary claim rewritten under its id into a
/// jurisdiction observation of someone in no campaign changes no authority,
/// so it does not block the restore; making it private as well does.
#[test]
fn restore_compares_only_the_read_scope_of_a_claim_rewritten_into_a_jurisdiction() {
    // Reopened at once so it holds the policy a restored copy's open seeds.
    let (dir, live) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let live = crate::test_util::reopen_test_vault(&dir, live);
    let backups = tempfile::tempdir().unwrap();
    let subject = person(&live, b"subject");
    let claim = EntityId::now();
    let mut ordinary = jurisdiction_observation(subject, "UK", 10);
    ordinary.predicate = "profile.region".to_owned();
    live.put_claim(&claim, &ordinary, TimeRange { start: 10, end: 10 }, 10)
        .unwrap();
    let image = backups.path().join("backup");
    live.snapshot_checkpoint(&image, 100).unwrap();
    let restore = |name: &str| {
        Vault::restore_checkpoint_keeping_authority(
            &image,
            &backups.path().join(name),
            VaultConfig::device(),
            &live,
            200,
        )
        .map(drop)
    };

    let mut rewritten = live.get_claim(&claim).unwrap().unwrap();
    rewritten.predicate = crate::campaign::claims::PREDICATE_COMM_JURISDICTION.to_owned();
    live.put_claim(&claim, &rewritten, TimeRange { start: 10, end: 10 }, 20)
        .unwrap();
    restore("rewritten").expect("the same read scope, now a jurisdiction, restores");

    let mut scope = match rewritten.scope.take() {
        Some(rmpv::Value::Map(entries)) => entries,
        _ => Vec::new(),
    };
    scope.retain(|(key, _)| key.as_str() != Some("private"));
    scope.push((rmpv::Value::from("private"), rmpv::Value::from(true)));
    rewritten.scope = Some(rmpv::Value::Map(scope));
    live.put_claim(&claim, &rewritten, TimeRange { start: 10, end: 10 }, 30)
        .unwrap();
    let error = restore("private").expect_err("a narrowed read scope refuses the restore");
    assert!(error.to_string().contains("claim privacy"), "{error}");
}
