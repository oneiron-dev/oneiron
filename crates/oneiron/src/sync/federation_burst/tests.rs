use super::*;
use crate::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, encode_federation_grant_body,
};
use crate::sync::{SyncSelectorWorld, encode_selector_vv_request};
use crate::temporal::TimeRange;

pub(in crate::sync) fn test_peer(vault: &Vault) -> FederationPeer {
    let principal = EntityId::now();
    let grant_id = EntityId::now();
    let scope = FederationGrantScope::vault(7);
    let grant = FederationGrant::new(
        scope,
        principal,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    put_grant(vault, grant_id, &grant);
    let selector = SyncSelector::new(grant_id, principal, SyncSelectorWorld::All, vec![], vec![]);
    FederationPeer::authorize(vault, principal, scope, &selector).unwrap()
}

fn put_grant(vault: &Vault, id: EntityId, grant: &FederationGrant) {
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_federation_grant_body(grant).unwrap(),
        )
        .commit()
        .unwrap();
}

fn request(peer: &FederationPeer) -> Vec<u8> {
    encode_selector_vv_request(&peer.selector, &loro::VersionVector::new().encode()).unwrap()
}

fn inputs(decision: FederationBurstDecision) -> NormalizedBurstInputs {
    match decision {
        FederationBurstDecision::Allow(inputs) | FederationBurstDecision::Defer { inputs, .. } => {
            inputs
        }
    }
}

#[test]
fn normalized_observations_survive_reopen_and_do_not_debit_another_peer() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let peer = test_peer(&vault);
    let other = test_peer(&vault);
    let key = WindowKey::new("2026-01");
    let payload = request(&peer);
    let first = admit_work_at(&vault, &peer, &key, WorkKind::Selector, &payload, (1, 10))
        .unwrap()
        .0;
    assert!(matches!(first, FederationBurstDecision::Allow(_)));
    // Peer state belongs to the vault, not a connection or the process.
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let second = admit_work_at(&vault, &peer, &key, WorkKind::Selector, &payload, (10, 10))
        .unwrap()
        .0;
    assert!(matches!(second, FederationBurstDecision::Defer { .. }));
    let independent = admit_work_at(
        &vault,
        &other,
        &key,
        WorkKind::Selector,
        &request(&other),
        (1, 10),
    )
    .unwrap()
    .0;
    assert!(matches!(independent, FederationBurstDecision::Allow(_)));
    assert!(inputs(second).rate_ratio > inputs(first).rate_ratio);
    assert!(vault.sync_state_keys_with_prefix("rm:").unwrap().is_empty());
}

#[test]
fn peer_baseline_and_vault_growth_reduce_the_same_burst() {
    let dirs = [
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    ];
    let vaults: Vec<_> = dirs
        .iter()
        .map(|dir| Vault::open(dir.path(), crate::VaultConfig::device()).unwrap())
        .collect();
    let peers: Vec<_> = vaults.iter().map(test_peer).collect();
    for (index, (vault, peer)) in vaults.iter().zip(&peers).enumerate() {
        admit_work_at(
            vault,
            peer,
            &WindowKey::new("2026-01"),
            WorkKind::Selector,
            &request(peer),
            (if index == 1 { 20 } else { 1 }, 10),
        )
        .unwrap();
    }
    for _ in 0..100 {
        let id = EntityId::now();
        vaults[2]
            .batch()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .commit()
            .unwrap();
    }
    let decisions: Vec<_> = vaults
        .iter()
        .zip(&peers)
        .map(|(vault, peer)| {
            admit_work_at(
                vault,
                peer,
                &WindowKey::new("2026-02"),
                WorkKind::Selector,
                &request(peer),
                (10, 11),
            )
            .unwrap()
            .0
        })
        .collect();
    assert!(matches!(
        decisions[0],
        FederationBurstDecision::Defer { .. }
    ));
    assert!(matches!(decisions[1], FederationBurstDecision::Allow(_)));
    assert!(matches!(decisions[2], FederationBurstDecision::Allow(_)));
    let ratios: Vec<_> = decisions
        .into_iter()
        .map(|decision| inputs(decision).rate_ratio)
        .collect();
    assert!(ratios[1] < ratios[0]);
    assert!(ratios[2] < ratios[0]);
}

#[test]
fn structural_streak_survives_defer_and_success_resets_it() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let peer = test_peer(&vault);
    let control = test_peer(&vault);
    let baseline = prepare_selector_fetch(
        &vault,
        control.principal,
        control.scope,
        &WindowKey::new("2026-01"),
        &request(&control),
    )
    .unwrap();
    assert!(matches!(
        baseline.decision,
        FederationBurstDecision::Allow(_)
    ));
    // Choose the streak against the observable baseline, not an assumed number
    // of seeded vault rows. The same one-row rate must now defer.
    let expected_streak = (1.0 / inputs(baseline.decision).rate_ratio).ceil() as u32;
    for _ in 0..expected_streak {
        record_outcome(&vault, &peer, true).unwrap();
    }
    let payload = request(&peer);
    let (decision, work) = admit_work_at(
        &vault,
        &peer,
        &WindowKey::new("2026-01"),
        WorkKind::Selector,
        &payload,
        (1, 10),
    )
    .unwrap();
    assert_eq!(inputs(decision).streak, expected_streak);
    assert!(matches!(decision, FederationBurstDecision::Defer { .. }));
    // A duplicate retained request does not advance the observation/streak.
    let replay = admit_work_at(
        &vault,
        &peer,
        &WindowKey::new("2026-01"),
        WorkKind::Selector,
        &payload,
        (100, 10),
    )
    .unwrap()
    .0;
    assert_eq!(inputs(replay), inputs(decision));
    work.unwrap().complete(&vault, &peer).unwrap();
    let success = admit_work_at(
        &vault,
        &peer,
        &WindowKey::new("2026-02"),
        WorkKind::Selector,
        &payload,
        (1, 11),
    )
    .unwrap()
    .0;
    assert_eq!(inputs(success).streak, 0);
}

#[test]
fn selector_replay_is_durable_and_bound_to_current_principal_grant_and_payload() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let peer = test_peer(&vault);
    let key = WindowKey::new("2026-01");
    let payload = request(&peer);
    let (decision, _) =
        admit_work_at(&vault, &peer, &key, WorkKind::Selector, &payload, (100, 10)).unwrap();
    let FederationBurstDecision::Defer { request_id, .. } = decision else {
        panic!("expected defer")
    };
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    assert!(
        replay_selector_fetch(
            &vault,
            EntityId::now(),
            peer.scope,
            &key,
            &request_id,
            &payload
        )
        .is_err()
    );
    assert!(
        replay_selector_fetch(
            &vault,
            peer.principal,
            peer.scope,
            &WindowKey::new("2026-02"),
            &request_id,
            &payload
        )
        .is_err()
    );
    let prepared = replay_selector_fetch(
        &vault,
        peer.principal,
        peer.scope,
        &key,
        &request_id,
        &payload,
    )
    .unwrap();
    assert_eq!(prepared.selector, peer.selector);
    assert!(matches!(
        prepared.decision,
        FederationBurstDecision::Allow(_)
    ));
    // Grant replacement is checked at replay, not just at queue creation.
    let replacement = FederationGrant::new(
        peer.scope,
        EntityId::now(),
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    put_grant(&vault, peer.selector.grant_id, &replacement);
    assert!(
        replay_selector_fetch(
            &vault,
            peer.principal,
            peer.scope,
            &key,
            &request_id,
            &payload
        )
        .is_err()
    );
    let restored = FederationGrant::new(
        peer.scope,
        peer.principal,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    put_grant(&vault, peer.selector.grant_id, &restored);
    replay_selector_fetch(
        &vault,
        peer.principal,
        peer.scope,
        &key,
        &request_id,
        &payload,
    )
    .unwrap()
    .complete(&vault)
    .unwrap();
    // Lost UPDATE after direct enqueue can redeem the completed ticket again.
    assert!(matches!(
        replay_selector_fetch(
            &vault,
            peer.principal,
            peer.scope,
            &key,
            &request_id,
            &payload
        )
        .unwrap()
        .decision,
        FederationBurstDecision::Allow(_)
    ));
    let fresh_key = WindowKey::new("2026-03");
    let fabricated = DeferredWork::new(&peer, &fresh_key, WorkKind::Selector, &payload).unwrap();
    assert!(
        replay_selector_fetch(
            &vault,
            peer.principal,
            peer.scope,
            &fresh_key,
            &fabricated.id,
            &payload
        )
        .is_err()
    );
}

#[test]
fn malformed_and_unauthorized_selector_requests_never_train_the_peer() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let peer = test_peer(&vault);
    let control = test_peer(&vault);
    let key = WindowKey::new("2026-01");
    assert!(
        prepare_selector_fetch(&vault, peer.principal, peer.scope, &key, b"bad request").is_err()
    );
    assert!(
        prepare_selector_fetch(&vault, EntityId::now(), peer.scope, &key, &request(&peer)).is_err()
    );
    let prepared =
        prepare_selector_fetch(&vault, peer.principal, peer.scope, &key, &request(&peer)).unwrap();
    let untouched = prepare_selector_fetch(
        &vault,
        control.principal,
        control.scope,
        &key,
        &request(&control),
    )
    .unwrap();
    assert_eq!(inputs(prepared.decision), inputs(untouched.decision));
}

#[test]
fn deferred_payloads_coalesce_into_one_review_bundle_and_replay_without_a_human() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let peer = test_peer(&vault);
    let payload = request(&peer);
    let mut tickets = Vec::new();
    for window in ["2026-01", "2026-02"] {
        let key = WindowKey::new(window);
        let (decision, _) =
            admit_work_at(&vault, &peer, &key, WorkKind::Selector, &payload, (100, 10)).unwrap();
        let FederationBurstDecision::Defer { request_id, .. } = decision else {
            panic!("burst must defer")
        };
        tickets.push((key, request_id));
    }
    let bundles = vault.federation_burst_review_bundles().unwrap();
    assert_eq!(bundles.len(), 1);
    assert_eq!(bundles[0].request_refs.len(), 2);
    assert!(bundles[0].quarantined && bundles[0].replay_automatic);
    for (key, id) in tickets {
        replay_selector_fetch(&vault, peer.principal, peer.scope, &key, &id, &payload)
            .unwrap()
            .complete(&vault)
            .unwrap();
    }
    assert!(vault.federation_burst_review_bundles().unwrap().is_empty());
}

#[test]
fn deferred_storage_budget_preserves_existing_work_and_is_shared_across_selectors() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let peer = test_peer(&vault);
    vault.config.map_size = 65_536;
    let payload = request(&peer);
    let mut accepted = Vec::new();
    for month in 1..=12 {
        let key = WindowKey::new(format!("2026-{month:02}"));
        let work = DeferredWork::new(&peer, &key, WorkKind::Selector, &payload).unwrap();
        match vault.with_write_txn(|txn| work.put_in_txn(&vault, txn)) {
            Ok(()) => accepted.push((key, work)),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::StorageFull => break,
            other => panic!("unexpected storage result: {other:?}"),
        }
    }
    assert!(!accepted.is_empty() && accepted.len() < 12);
    let mut narrow_selector = peer.selector.clone();
    narrow_selector.world = SyncSelectorWorld::Base;
    let narrowed =
        FederationPeer::authorize(&vault, peer.principal, peer.scope, &narrow_selector).unwrap();
    let narrow_work = DeferredWork::new(
        &narrowed,
        &WindowKey::new("2026-12"),
        WorkKind::Selector,
        &request(&narrowed),
    )
    .unwrap();
    assert!(
        matches!(vault.with_write_txn(|txn| narrow_work.put_in_txn(&vault, txn)), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::StorageFull)
    );
    let bundles = vault.federation_burst_review_bundles().unwrap();
    assert_eq!(bundles[0].request_refs.len(), accepted.len());
    let (key, saved) = &accepted[0];
    let replay =
        admit_work_at(&vault, &peer, key, WorkKind::Selector, &payload, (1000, 1)).unwrap();
    assert!(matches!(replay.0, FederationBurstDecision::Allow(_)));
    assert_eq!(replay.1.unwrap().id, saved.id);
    // Replacing the exact item is free, and completion frees capacity without discarding another item.
    vault
        .with_write_txn(|txn| saved.put_in_txn(&vault, txn))
        .unwrap();
    saved.complete(&vault, &peer).unwrap();
    let another = DeferredWork::new(
        &peer,
        &WindowKey::new("2027-01"),
        WorkKind::Selector,
        &payload,
    )
    .unwrap();
    vault
        .with_write_txn(|txn| another.put_in_txn(&vault, txn))
        .unwrap();
    assert_eq!(
        vault.federation_burst_review_bundles().unwrap()[0]
            .request_refs
            .len(),
        accepted.len()
    );
}
