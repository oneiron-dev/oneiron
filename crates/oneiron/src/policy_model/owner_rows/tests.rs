use super::*;
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound};
use crate::edge::EdgeActorClass;
use crate::federation::{FederationGrantRole, InitialSharedMember};
use crate::gate::{PolicyRowAction, PolicyRowScope};
use crate::store::GateDecisionId;
use crate::{EntityId, TimeRange, VaultConfig};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn open() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let id = crate::vault::embedded_owner_actor_id()?;
    let owner = vault.authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, owner))
}
fn person(vault: &Vault, byte: u8) -> Result<AuthenticatedOwner> {
    let id = EntityId::from_bytes([byte; 16])?;
    vault.put_entity(
        &id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    vault.authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())
}
fn change(
    text: &str,
    action: PolicyRowAction,
    scope: PolicyRowScope,
    add: bool,
) -> PolicyRowChange {
    if add {
        PolicyRowChange::Add {
            row_ref: "quiet".into(),
            text: text.into(),
            action,
            scope,
        }
    } else {
        PolicyRowChange::Edit {
            row_ref: "quiet".into(),
            text: text.into(),
            action,
            scope,
        }
    }
}

#[test]
fn owner_lands_add_tighten_loosen_and_revert_with_four_events() -> TestResult {
    let (_dir, vault, owner) = open()?;
    let original = change(
        "Keep this private",
        PolicyRowAction::Warn,
        PolicyRowScope::Vault,
        true,
    );
    let r1 = vault.change_policy_row(&owner, original, 100)?;
    let r2 = vault.change_policy_row(
        &owner,
        change(
            "Keep this private",
            PolicyRowAction::Block,
            PolicyRowScope::Vault,
            false,
        ),
        101,
    )?;
    let r3 = vault.change_policy_row(
        &owner,
        change(
            "Keep this private",
            PolicyRowAction::Warn,
            PolicyRowScope::Vault,
            false,
        ),
        102,
    )?;
    let r4 = vault.change_policy_row(
        &owner,
        change(
            "Keep this private",
            PolicyRowAction::Block,
            PolicyRowScope::Vault,
            false,
        ),
        103,
    )?;
    assert_eq!(r2.previous_receipt_id, Some(r1.receipt_id));
    assert_eq!(r3.previous_receipt_id, Some(r2.receipt_id));
    assert_eq!(r4.previous_receipt_id, Some(r3.receipt_id));
    let txn = vault.store.env.read_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    assert!(policy.owner_policy_enabled());
    assert_eq!(
        policy.active_owner_policy_rows(None)[0].action,
        crate::gate::OwnerRowAction::Block
    );
    drop(txn);
    assert_eq!(vault.policy_row_change_log()?.len(), 4);
    let events = vault.policy_changed_events()?;
    assert_eq!(events.len(), 4);
    assert!(events.iter().all(|event| event.kind == "policy.changed"
        && event.scope == PolicyRowScope::Vault
        && event.author == owner.actor().to_hex()));
    assert!(vault.policy_queued_notifications()?.is_empty());
    Ok(())
}

#[test]
fn admin_without_power_and_agent_both_propose_in_either_direction_first_holder_rules() -> TestResult
{
    let (_dir, vault, owner) = open()?;
    let admin = person(&vault, 0x35)?;
    let other = person(&vault, 0x36)?;
    let agent = person(&vault, 0x37)?;
    vault.initialize_shared_vault(
        &owner,
        42,
        None,
        &[
            InitialSharedMember {
                member_ref: owner.actor(),
                role: Some(FederationGrantRole::Owner),
            },
            InitialSharedMember {
                member_ref: other.actor(),
                role: Some(FederationGrantRole::Owner),
            },
            InitialSharedMember {
                member_ref: admin.actor(),
                role: Some(FederationGrantRole::Admin),
            },
        ],
        10,
    )?;
    let add = change(
        "Protect information",
        PolicyRowAction::Block,
        PolicyRowScope::World("w1".into()),
        true,
    );
    let PolicyRowSubmission::Proposed(proposal) =
        vault.submit_policy_row_change(&admin, add.clone(), 11)?
    else {
        panic!("admin without the policy grant must propose");
    };
    assert_eq!(proposal.holders.len(), 2);
    assert_eq!(vault.policy_row_proposals_for(&owner, 11)?.len(), 1);
    assert_eq!(vault.policy_row_proposals_for(&other, 11)?.len(), 1);
    assert!(vault.change_policy_row(&admin, add, 11).is_err());
    assert!(vault.policy_row_change_log()?.is_empty());
    let landed = vault
        .rule_policy_row_proposal(&other, &proposal.proposal_id, true, 12)?
        .expect("approved");
    assert_eq!(landed.author, other.actor().to_hex());
    assert!(
        vault
            .rule_policy_row_proposal(&owner, &proposal.proposal_id, false, 13)
            .is_err()
    );
    let power = GrantBound::action(
        ActorBound::new(admin.actor().to_hex())?.with_actor_class("human")?,
        ActionClass::new("policy.change")?,
        ActionEnvelope::new(["owner_policy_rows".to_owned()])?,
    )?;
    vault.create_standing_grant(&owner, power)?;
    let loose = change(
        "Protect information",
        PolicyRowAction::Warn,
        PolicyRowScope::World("w1".into()),
        false,
    );
    vault.change_policy_row(&admin, loose.clone(), 14)?;
    let tighten = vault
        .memory(agent.actor(), EdgeActorClass::Agent)
        .propose_policy_row_change(
            change(
                "Protect information",
                PolicyRowAction::Block,
                PolicyRowScope::World("w1".into()),
                false,
            ),
            15,
        )?;
    let loosen = vault
        .memory(agent.actor(), EdgeActorClass::Agent)
        .propose_policy_row_change(loose, 15)?;
    assert_eq!(tighten.holders.len(), 3);
    assert_eq!(loosen.holders.len(), 3);
    assert_eq!(vault.policy_row_proposals_for(&admin, 15)?.len(), 2);
    assert_eq!(vault.policy_row_change_log()?.len(), 2);
    let txn = vault.store.env.read_txn()?;
    let resolved = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    assert_eq!(
        resolved.active_owner_policy_rows(Some("w1"))[0].action,
        crate::gate::OwnerRowAction::Warn,
        "a later holder ruling wins; neither agent proposal edits the row"
    );
    drop(txn);
    Ok(())
}

#[test]
fn notification_rule_is_data_default_and_override_dials_win() -> TestResult {
    let (_dir, vault, owner) = open()?;
    let other = person(&vault, 0x38)?;
    vault.initialize_shared_vault(
        &owner,
        44,
        None,
        &[
            InitialSharedMember {
                member_ref: owner.actor(),
                role: Some(FederationGrantRole::Owner),
            },
            InitialSharedMember {
                member_ref: other.actor(),
                role: Some(FederationGrantRole::Owner),
            },
        ],
        10,
    )?;
    vault.change_policy_row(
        &owner,
        change(
            "Initial",
            PolicyRowAction::Warn,
            PolicyRowScope::Vault,
            true,
        ),
        11,
    )?;
    let queued = vault.policy_queued_notifications()?;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].recipient, other.actor().to_hex());
    assert_eq!(queued[0].mode, PolicyNotificationMode::PushAll);
    vault.change_policy_row(
        &owner,
        change(
            "Override",
            PolicyRowAction::Warn,
            PolicyRowScope::World("world-1".into()),
            true,
        ),
        12,
    )?;
    assert_eq!(vault.policy_queued_notifications()?.len(), 1);
    vault.change_policy_row(
        &owner,
        change(
            "Project override",
            PolicyRowAction::Block,
            PolicyRowScope::Project("project-1".into()),
            true,
        ),
        12,
    )?;
    assert_eq!(vault.policy_queued_notifications()?.len(), 1);
    let events = vault.policy_changed_events()?;
    assert!(
        events
            .iter()
            .any(|e| e.scope == PolicyRowScope::Vault && e.author == owner.actor().to_hex())
    );
    assert!(
        events
            .iter()
            .any(|e| e.scope == PolicyRowScope::World("world-1".into())
                && e.author == owner.actor().to_hex())
    );
    assert!(
        events
            .iter()
            .any(|e| e.scope == PolicyRowScope::Project("project-1".into())
                && e.author == owner.actor().to_hex())
    );
    vault.change_policy_notification_rule(
        &owner,
        PolicyRowScope::Vault,
        PolicyNotificationRule::LogOnly,
        13,
    )?;
    vault.change_policy_row(
        &owner,
        change(
            "Edited",
            PolicyRowAction::Block,
            PolicyRowScope::Vault,
            false,
        ),
        14,
    )?;
    assert_eq!(vault.policy_queued_notifications()?.len(), 1);
    vault.set_policy_notification_mode(&other, PolicyNotificationMode::PushAll)?;
    vault.change_policy_row(
        &owner,
        change(
            "Edited again",
            PolicyRowAction::Warn,
            PolicyRowScope::Vault,
            false,
        ),
        15,
    )?;
    assert_eq!(vault.policy_queued_notifications()?.len(), 2);
    Ok(())
}

#[test]
fn queued_policy_push_enters_the_existing_human_followup_ladder() -> TestResult {
    use crate::channel_identity::{
        ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityState,
        SelfHeldShape,
    };
    use crate::comm::resolve_or_create_comm_party;
    use crate::counterparty_contact::CounterpartyContactRecord;
    use crate::human_task::human_followup_record;

    const NOW: u64 = 1_772_600_000;
    let (_dir, vault, owner) = open()?;
    let other = resolve_or_create_comm_party(&vault, "policy-holder@example.test")?;
    let face = EntityId::from_bytes([0x6c; 16])?;
    vault.create_channel_identity(
        &face,
        &ChannelIdentity::requested(
            "email",
            "sender@example.test",
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::vault(1),
            NOW,
        ),
    )?;
    vault.transition_channel_identity(
        &face,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        NOW,
        None,
    )?;
    vault.transition_channel_identity(&face, ChannelIdentityState::Active, None, NOW, None)?;
    vault.create_counterparty_contact(
        &EntityId::from_bytes([0x6d; 16])?,
        &CounterpartyContactRecord::user_introduction(face, "policy-holder@example.test", NOW)?,
    )?;
    vault.initialize_shared_vault(
        &owner,
        56,
        None,
        &[
            InitialSharedMember {
                member_ref: owner.actor(),
                role: Some(FederationGrantRole::Owner),
            },
            InitialSharedMember {
                member_ref: other,
                role: Some(FederationGrantRole::Owner),
            },
        ],
        NOW,
    )?;
    let receipt = vault.change_policy_row(
        &owner,
        change(
            "Protect this information",
            PolicyRowAction::Block,
            PolicyRowScope::Vault,
            true,
        ),
        NOW,
    )?;
    let queued = vault.policy_queued_notifications()?;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].receipt_id, receipt.receipt_id);
    assert!(queued[0].followup_task.is_none());
    assert_eq!(vault.drive_policy_notification_queue(NOW + 1, 10)?, 1);
    let linked = vault.policy_queued_notifications()?;
    let task_ref = EntityId::from_hex(linked[0].followup_task.as_deref().expect("follow-up task"))?;
    let cursor = human_followup_record(&vault, task_ref)?.expect("human follow-up cursor");
    assert_eq!(cursor.assignee_ref, other);
    assert_eq!(vault.drive_policy_notification_queue(NOW + 2, 10)?, 0);
    Ok(())
}

#[test]
fn expiring_delegate_needs_an_owner_minted_named_policy_grant() -> TestResult {
    use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, apply_ops};
    use crate::federation::{
        FederationGrant, decode_federation_grant_body, encode_federation_grant_body,
    };
    let (_dir, vault, owner) = open()?;
    let delegate = person(&vault, 0x39)?;
    let creation = vault.initialize_shared_vault(
        &owner,
        57,
        None,
        &[InitialSharedMember {
            member_ref: owner.actor(),
            role: Some(FederationGrantRole::Owner),
        }],
        10,
    )?;
    let owner_grant = creation
        .grant_refs
        .iter()
        .find_map(|reference| {
            let id = EntityId::from_hex(reference).ok()?;
            let raw = vault.get_raw(&id).ok()??;
            let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]).ok()?;
            (grant.member_ref == owner.actor()).then_some(grant)
        })
        .expect("stored owner grant");
    let now = vault.store.clock.now_recorded_at();
    let scoped =
        FederationGrant::attenuated_delegate(&owner_grant, delegate.actor(), now, now + 3600)?;
    vault.with_write_txn(|txn| {
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![BatchOp::Put {
                id: EntityId::now(),
                entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data: encode_federation_grant_body(&scoped)?,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    })?;
    let add = change(
        "Keep this safe",
        PolicyRowAction::Block,
        PolicyRowScope::Project("project-1".into()),
        true,
    );
    assert!(matches!(
        vault.submit_policy_row_change(&delegate, add.clone(), now)?,
        PolicyRowSubmission::Proposed(_)
    ));
    let bound = GrantBound::action(
        ActorBound::new(delegate.actor().to_hex())?.with_actor_class("human")?,
        ActionClass::new("policy.change")?,
        ActionEnvelope::new(["owner_policy_rows".to_owned()])?,
    )?;
    vault.create_standing_grant(&owner, bound)?;
    let PolicyRowSubmission::Landed(receipt) =
        vault.submit_policy_row_change(&delegate, add, now)?
    else {
        panic!("owner-granted delegate should land now");
    };
    assert_eq!(receipt.author, delegate.actor().to_hex());
    assert_eq!(
        receipt.change.scope(),
        &PolicyRowScope::Project("project-1".into())
    );
    Ok(())
}
