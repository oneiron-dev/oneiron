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
