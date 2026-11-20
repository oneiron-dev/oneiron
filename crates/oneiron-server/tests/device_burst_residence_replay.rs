#![cfg(oneiron_test_support)]
// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! Case 2 of BURST-REPLAY-ROUND2-TESTS (#9226 review round 2, P1 2): an own
//! device's edit that a residence socket sent to a window it promoted, held
//! while the world of its row was already kept off the device, persists
//! nothing when the home's drain replays it. The writer that persists the
//! replay judges its destination for the device again, as it judges the
//! socket's own write; the held authority did not change, so only that check
//! stops it. Beside it, the same edit held while its world still reads on the
//! device lands. Green-only: the round-1 head 9cc1dbcc293d has no door that
//! holds a burst under its row admission.
//!
//! The device's edit is a delta over the home's window document as the
//! server serves it, so it lands over the home's own carrier of the row.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support
//! --no-fail-fast --test device_burst_residence_replay`.

#[path = "support/device_burst_home.rs"]
mod device_burst_home;
#[path = "support/engine_stack.rs"]
mod engine_stack;

use device_burst_home::{Home, eventually, host_issuer};
use engine_stack::run_on_engine_stack;
use loro::ExportMode;
use oneiron::authority::PeerMachine;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, own_device_residence_scope,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::sync::federation_burst::{
    BurstPeer, DeviceBurstAdmission, DevicePeer, FederationBurstBaseline, FederationBurstOutcome,
    FederationBurstPolicy, FederationBurstWorkState, admit_device_residence_update,
    admit_promoted_device_window_update,
};
use oneiron::sync::window::load_window_from_state;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, put_selector_test_federation_grant,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
};
use oneiron_server::test_doors::device_burst_drain::drain_device_bursts_once;
use oneiron_server::test_doors::residence::serve_window;

/// The id of the slip that bound the device's Write credential.
const SLIP: [u8; 32] = [0x52; 32];
/// The stored row's metadata header ahead of its body.
const ROW_HEADER_LEN: usize = 25;
/// The confidence the device's edit gives the CLAIM.
const EDITED_CONFIDENCE: f32 = 0.75;

#[test]
fn a_residence_burst_held_after_its_world_left_the_device_persists_nothing_at_replay() {
    run_on_engine_stack("device-burst-residence-withheld", || {
        replay_held_residence_edit(true)
    });
}

#[test]
fn a_residence_burst_held_while_its_world_reads_on_the_device_lands_at_replay() {
    run_on_engine_stack("device-burst-residence-reads", || {
        replay_held_residence_edit(false)
    });
}

/// Re-encodes a CLAIM body with a new confidence: an edit of the record that
/// keeps its identity, predicate, value and world.
fn with_confidence(body: &[u8], confidence: f32) -> Vec<u8> {
    let rmpv::Value::Map(mut entries) = rmpv::decode::read_value(&mut &body[..]).unwrap() else {
        panic!("claim body is a map");
    };
    let slot = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("conf"))
        .unwrap();
    slot.1 = rmpv::Value::F32(confidence);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries)).unwrap();
    out
}

/// Whether `vault`'s CLAIM row carries `confidence` past its metadata header.
fn carries_confidence(vault: &Vault, claim: EntityId, confidence: f32) -> bool {
    let Some(raw) = vault.get_raw(&claim).unwrap() else {
        return false;
    };
    let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut &raw[ROW_HEADER_LEN..]).unwrap()
    else {
        return false;
    };
    entries.iter().any(|(key, value)| {
        key.as_str() == Some("conf") && value.as_f64() == Some(f64::from(confidence))
    })
}

/// A paired device's edit of a CLAIM, admitted row by row as its residence
/// socket's UPDATE arm admits it and held as a burst, then replayed by the
/// home's drain. With `keep_claim_world_off`, the owner kept the CLAIM's
/// world on the home before the edit came; otherwise another world.
async fn replay_held_residence_edit(keep_claim_world_off: bool) {
    let device = DevicePeer::of_connection(PeerMachine::Unknown, Some(SLIP));
    let home = Home::new(device, 1).await;
    // A baseline far under one write a second: one edit is a burst.
    home.vault
        .set_federation_burst_policy(
            home.owner(),
            BurstPeer::Device(&device),
            FederationBurstPolicy {
                baseline: Some(FederationBurstBaseline {
                    name: "one edit in a thousand seconds".into(),
                    writes_per_sec: 0.001,
                    structural_streak: 1.0,
                }),
                unusual_rate: FederationBurstOutcome::Defer,
                unusual_streak: FederationBurstOutcome::IsolateAndPropose,
            },
        )
        .unwrap();
    let owner = home.vault.ensure_embedded_owner_actor().unwrap();
    let at = TimeRange {
        start: home.now,
        end: home.now,
    };

    // The CLAIM the device edits: a fact in a world, about a PERSON.
    let world = EntityId::now();
    home.vault
        .put_entity(&world, ENTITY_TYPE_WORLD, at, home.now, b"world")
        .unwrap();
    let other_world = EntityId::now();
    home.vault
        .put_entity(
            &other_world,
            ENTITY_TYPE_WORLD,
            at,
            home.now,
            b"other world",
        )
        .unwrap();
    let subject = EntityId::now();
    home.vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at, home.now, b"subject")
        .unwrap();
    let mut body = ClaimBody::new(
        "test.device_burst_residence_replay",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("world fact"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world);
    let claim = EntityId::now();
    home.vault.put_claim(&claim, &body, at, home.now).unwrap();
    let key = WindowKey::for_world(home.now, world);

    // The owner's own-device grant, as pairing provisions it, and the
    // device's Write credential under it, proved on its connection.
    let grant_id = EntityId::now();
    let grant = FederationGrant::new(
        own_device_residence_scope(),
        owner,
        FederationGrantRole::Owner,
        FederationGrantPreset::Owner,
    );
    put_selector_test_federation_grant(&home.vault, &grant_id, &grant, home.now).unwrap();
    let issuer = host_issuer();
    let root = home.vault.ensure_host_root_slip(&issuer).unwrap();
    let issued_at = home.vault.capability_slip_now().unwrap();
    let mut claims = root.claims.clone();
    claims.slip_id = SLIP;
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".into());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    claims.grant_ref = Some(grant_id.to_hex());
    let slip = home.vault.mint_capability_slip(&issuer, claims).unwrap();
    let challenge = b"device-burst-residence-replay";
    let binding = issuer.binding_proof(&slip, challenge).unwrap();
    let proof = home
        .vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &binding)
        .unwrap();
    let selector = SyncSelector::new(grant_id, owner, SyncSelectorWorld::All, vec![], vec![]);

    // The owner keeps a world on the home before the edit comes: no machine
    // the device proved may read it.
    let kept = if keep_claim_world_off {
        world
    } else {
        other_world
    };
    home.vault
        .keep_world_on_this_machine_under_for_test(&issuer, kept, true)
        .unwrap();

    // The device's edit, a delta over the home's window as the server serves
    // it.
    serve_window(&home.server, key.as_str()).await.unwrap();
    let source = load_window_from_state(&home.vault, "", &key).unwrap();
    let edit = source.fork();
    let before = edit.oplog_vv();
    let raw = home.vault.get_raw(&claim).unwrap().unwrap();
    let mut blob = raw[..ROW_HEADER_LEN].to_vec();
    blob.extend(with_confidence(&raw[ROW_HEADER_LEN..], EDITED_CONFIDENCE));
    edit.get_map("entities")
        .insert(&claim.to_hex(), blob)
        .unwrap();
    edit.commit();
    let update = edit.export(ExportMode::updates(&before)).unwrap();

    // Its rows pass the residence arm's row admission, which judges them
    // against the grant alone, and the burst core holds it.
    let admission = admit_promoted_device_window_update(
        &home.vault,
        &device,
        &source,
        (own_device_residence_scope(), &selector, &proof),
        &update,
    )
    .unwrap();
    let batch_ref = match admit_device_residence_update(
        &home.vault,
        &device,
        &key,
        &update,
        &[claim],
        admission,
    )
    .unwrap()
    {
        DeviceBurstAdmission::Defer { batch_ref } => batch_ref,
        other => panic!("an edit over the device's baseline is held: {other:?}"),
    };

    // Two seconds on, the device's rate is back at its baseline, and the
    // drain replays the edit.
    home.clock.set(home.now + 2);
    let landed = drain_device_bursts_once(&home.server).await.unwrap();
    if keep_claim_world_off {
        assert_eq!(
            landed, 0,
            "an edit whose world left the device before it was held lands nothing at replay"
        );
        assert!(
            !carries_confidence(&home.vault, claim, EDITED_CONFIDENCE),
            "the CLAIM keeps its stored body"
        );
        assert_eq!(
            home.receipt(device, &batch_ref).state,
            FederationBurstWorkState::Pending,
            "the batch stays held: nothing of it persisted"
        );
    } else {
        assert_eq!(landed, 1, "the drain lands the held edit");
        assert!(
            eventually(|| carries_confidence(&home.vault, claim, EDITED_CONFIDENCE)).await,
            "the edit reaches the CLAIM at the home"
        );
        assert_eq!(
            home.receipt(device, &batch_ref).state,
            FederationBurstWorkState::Imported
        );
    }
}
