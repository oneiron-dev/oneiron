//! Sol on the device-local reads (F2, F5): a caller off this device learns
//! nothing of a device-local claim from the gate's receipts or its consent
//! tray, on the Memory doors and the live-view adapters alike, and such a
//! claim takes no place in a page. Nor does it learn how a claim it was
//! served, or one it proposed, has changed since.

use super::*;
use crate::claim::{CallerLocality, ClaimBody, ClaimSubject};
use crate::store::{GateDecisionId, GateDecisionRecord, PendingGateConsentRecord};

/// A proposed claim about `owner` in `world`, with its gate decision and its
/// place in the consent tray at `queued_at`.
fn gated_claim(
    vault: &crate::Vault,
    owner: EntityId,
    world: Option<EntityId>,
    queued_at: u64,
) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "test.device_local_receipt",
        ClaimSubject::Entity(owner),
        rmpv::Value::from("fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = world;
    vault
        .put_claim(&id, &body, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let decision = GateDecisionRecord {
        version: 0,
        decision_id: GateDecisionId::now(),
        created_at: queued_at,
        outcome: "pending".to_owned(),
        reason_codes: vec!["gate.pending.review".to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: "human".to_owned(),
        actor_ref: Some(owner.to_hex()),
        content_kind: "claim".to_owned(),
        policy_manifest_version: "test-policy".to_owned(),
        claim_id: Some(*id.as_bytes()),
        grant_ref: None,
        diff_handle: vec![0xA5],
        read_frontier_hash: [0xB6; 32],
        redacted_at: None,
    };
    let pending = PendingGateConsentRecord {
        version: 0,
        claim_id: *id.as_bytes(),
        decision_id: decision.decision_id,
        created_at: queued_at,
        diff_handle: vec![0xA5],
        read_frontier_hash: [0xB6; 32],
        reason_codes: vec!["gate.pending.review".to_owned()],
        dreamer_run_id: None,
    };
    vault
        .with_write_txn_grouped(|wtxn| {
            vault.store.append_gate_decision_in_txn(wtxn, &decision)?;
            vault.store.put_pending_gate_consent_in_txn(wtxn, &pending)
        })
        .unwrap();
    id
}

#[test]
fn a_caller_off_this_device_reads_no_receipt_or_consent_of_a_device_local_claim() {
    let (_dir, vault) = open_vault();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let world = EntityId::now();
    vault
        .put_entity(
            &world,
            crate::registry::ENTITY_TYPE_WORLD,
            TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .unwrap();
    // Receipts list the newest decision first and the tray the oldest
    // proposal first: the device-local claim leads both, so a page of one
    // is its own unless it is withheld before the page fills.
    let open = gated_claim(&vault, owner, None, 20);
    let kept = gated_claim(&vault, owner, Some(world), 10);
    vault
        .keep_world_on_this_machine_for_test(world, true)
        .unwrap();

    for (locality, first) in [
        (CallerLocality::OnDevice, kept),
        (CallerLocality::OffDevice, open),
    ] {
        let memory = vault.memory(owner, EdgeActorClass::Human).at(locality);
        let receipts = memory.receipts(1).unwrap();
        assert_eq!(
            receipts
                .iter()
                .map(|receipt| receipt.claim_ref.clone())
                .collect::<Vec<_>>(),
            vec![Some(first.to_hex())],
            "{locality:?}"
        );
        let pending = memory.pending_writes(1).unwrap();
        assert_eq!(
            pending
                .iter()
                .map(|pending| pending.claim_ref.clone())
                .collect::<Vec<_>>(),
            vec![first.to_hex()],
            "{locality:?}"
        );
        #[cfg(feature = "sync")]
        {
            let (actor, in_world) = (owner.to_hex(), world.to_hex());
            let seen = usize::from(locality == CallerLocality::OnDevice);
            let receipts = crate::sync::bridge::scoped_subscription_receipts(
                &vault,
                &actor,
                Some(&in_world),
                locality,
                10,
            )
            .unwrap();
            assert_eq!(receipts.len(), seen, "{locality:?}");
            let pending = crate::sync::bridge::scoped_subscription_pending(
                &vault,
                &actor,
                Some(&in_world),
                locality,
                10,
            )
            .unwrap();
            assert_eq!(pending.len(), seen, "{locality:?}");
        }
    }
}

#[test]
fn a_caller_off_this_device_learns_no_later_state_of_a_device_local_claim() {
    let (_dir, vault) = open_vault();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let world = EntityId::now();
    vault
        .put_entity(
            &world,
            crate::registry::ENTITY_TYPE_WORLD,
            TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .unwrap();
    // A claim a session was served, or proposed, retracted since. A board
    // read reports each served row whose state moved, and each own proposal.
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.orchid",
        ClaimSubject::Entity(owner),
        rmpv::Value::from("fact"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Retracted,
    )
    .unwrap();
    body.world = Some(world);
    vault
        .put_claim(&id, &body, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    vault
        .keep_world_on_this_machine_for_test(world, true)
        .unwrap();

    for (locality, state) in [
        (
            CallerLocality::OnDevice,
            Some(crate::context_board::ServedLifecycle::Retracted),
        ),
        (CallerLocality::OffDevice, None),
    ] {
        let read =
            vault.scoped_read(crate::claim::ScopedReadActorKey::vault_owner(owner).at(locality));
        assert_eq!(read.read_set_lifecycle(&id).unwrap(), state, "{locality:?}");
        // Sol R2 F5: the session's own proposals fold apart from that read.
        let session: crate::context_board::SessionReadSet =
            serde_json::from_value(serde_json::json!({
                "rows": {},
                "loaded_skills": {},
                "proposal_count": 0,
                "own_proposals": [format!("claim:{}", id.to_hex())],
            }))
            .unwrap();
        let mut line = crate::context_board::ChangedLine::default();
        session
            .fold_own_changes(&vault, Some(owner), locality, &mut line, 16)
            .unwrap();
        assert_eq!(
            line.events.len(),
            usize::from(state.is_some()),
            "{locality:?}"
        );
    }
}

/// Sol R3 F4: a recall's census of other worlds reads its first 512 claims
/// and says when it stopped there. Off this device a claim a device-local
/// world keeps takes no place among them, so a vault whose claims are all
/// device-local reads as uncapped.
#[test]
fn a_recall_off_this_device_counts_no_device_local_claim_toward_its_census_cap() {
    let (_dir, vault) = open_vault();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let world = EntityId::now();
    vault
        .put_entity(
            &world,
            crate::registry::ENTITY_TYPE_WORLD,
            TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .unwrap();
    for _ in 0..512 {
        let mut body = ClaimBody::new(
            "profile.orchid",
            ClaimSubject::Entity(owner),
            rmpv::Value::from("fact"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.world = Some(world);
        vault
            .put_claim(&EntityId::now(), &body, TimeRange { start: 1, end: 1 }, 1)
            .unwrap();
    }
    vault
        .keep_world_on_this_machine_for_test(world, true)
        .unwrap();

    let capped = |locality| {
        vault
            .memory(owner, EdgeActorClass::Human)
            .at(locality)
            .recall(
                "lighthouse",
                Effort::Light,
                &RecallScope::default(),
                10,
                None,
                None,
            )
            .unwrap()
            .scope_honesty
            .census_capped
    };
    assert!(capped(CallerLocality::OnDevice));
    assert!(!capped(CallerLocality::OffDevice));
}
