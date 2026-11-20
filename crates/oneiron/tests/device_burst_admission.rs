//! L7-41: an own device's window update at its home gets the same relative
//! burst response a federated peer's does (arch-0023b
//! `#decision-federation-26`): a trickle is allowed, a burst over the
//! device's own baseline is deferred, or isolated and proposed, and the home
//! gets it back by itself once the device's rate is at its baseline again.
//! A held burst whose device no longer stands as its connection proved it
//! (its Write credential's slip expired or revoked since) ends
//! `StaleAuthority` and is never handed back. So does one whose slip still
//! stands but whose write authority changed since it was held: its grant
//! narrowed in place, another grant it may write under expired, or a world
//! kept off its device (BURST-REPLAY-SKIPS-ROW-ADMISSION).
//!
//! The last test reads a receipt stored before own devices had receipts
//! through the ledger's door (the lead's M-1 STORED-CHANGE-RULE, Engine
//! RULING L7-41-STORED-RECEIPT = B).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test device_burst_admission`.

use std::collections::BTreeSet;
use std::sync::Arc;

use loro::{ExportMode, LoroDoc};
use oneiron::authority::{HostSlipIssuer, PeerMachine};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, ScopeAxis, ScopeId,
    own_device_residence_scope,
};
use oneiron::registry::ENTITY_TYPE_WORLD;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::sync::federation_burst::{
    BurstPeer, DeviceBurstAdmission, DevicePeer, FederationBurstBaseline,
    FederationBurstBaselineState, FederationBurstDisposition, FederationBurstOutcome,
    FederationBurstPeerRef, FederationBurstPolicy, FederationBurstReceipt,
    FederationBurstWorkState, admit_device_window_update, ready_device_work,
};
use oneiron::sync::{WindowKey, put_selector_test_federation_grant};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::burst_receipt_stored_shape::decode_burst_receipt_row;
use oneiron::test_doors::device_burst_work_stands::device_burst_work_stands;
use oneiron::{EntityId, Vault, VaultConfig};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const NOW: u64 = 1_700_000_000;

/// Rows in one burst: far over a baseline of one write a second on a fresh
/// vault's size.
const BURST_ROWS: usize = 100;

/// A device's home whose owner set the device's baseline to one write a
/// second; `unusual_rate` routes a burst over it.
struct Home {
    _dir: TempDir,
    clock: Arc<ManualClock>,
    vault: Vault,
    owner: AuthenticatedOwner,
    machine: EntityId,
    device: DevicePeer,
    window: WindowKey,
    doc: LoroDoc,
}

fn home(unusual_rate: FederationBurstOutcome) -> TestResult<Home> {
    let dir = TempDir::new()?;
    let clock = ManualClock::new(NOW);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let machine = EntityId::now();
    let device = DevicePeer::of_connection(
        PeerMachine::Proven {
            machine,
            key: [7; 32],
        },
        None,
    );
    vault.set_federation_burst_policy(&owner, BurstPeer::Device(&device), steady(unusual_rate))?;
    let window = WindowKey::try_new("2023-11").ok_or("window key")?;
    Ok(Home {
        _dir: dir,
        clock,
        vault,
        owner,
        machine,
        device,
        window,
        doc: LoroDoc::new(),
    })
}

/// The owner's policy for a device here: a baseline of one write a second,
/// a burst over it routed to `unusual_rate`.
fn steady(unusual_rate: FederationBurstOutcome) -> FederationBurstPolicy {
    FederationBurstPolicy {
        baseline: Some(FederationBurstBaseline {
            name: "steady".into(),
            writes_per_sec: 1.0,
            structural_streak: 1.0,
        }),
        unusual_rate,
        unusual_streak: FederationBurstOutcome::IsolateAndPropose,
    }
}

impl Home {
    /// Mints the slip `slip_id` for the owner from the host root, live for
    /// `ttl_secs` from now, and answers the issuer that can revoke it.
    fn mint_slip(&self, slip_id: [u8; 32], ttl_secs: u64) -> TestResult<HostSlipIssuer> {
        self.mint_slip_under(slip_id, ttl_secs, None)
    }

    /// [`Self::mint_slip`] naming `grant` as the grant it was minted under,
    /// as a paired device's slip names its owner's own-device grant.
    fn mint_slip_under(
        &self,
        slip_id: [u8; 32],
        ttl_secs: u64,
        grant: Option<EntityId>,
    ) -> TestResult<HostSlipIssuer> {
        let owner = self.vault.ensure_embedded_owner_actor()?;
        let issuer =
            HostSlipIssuer::from_secret(b"device-burst-test-host-secret").expect("host issuer");
        let root = self.vault.ensure_host_root_slip(&issuer)?;
        let issued_at = self.vault.capability_slip_now()?;
        let mut claims = root.claims.clone();
        claims.slip_id = slip_id;
        claims.holder_ref = owner.to_hex();
        claims.actor_class = Some("human".into());
        claims.issued_at = issued_at;
        claims.expires_at = issued_at + ttl_secs;
        claims.ttl_secs = ttl_secs;
        claims.grant_ref = grant.map(|grant| grant.to_hex());
        self.vault.mint_capability_slip(&issuer, claims)?;
        Ok(issuer)
    }

    /// A device of this home whose connection proved `machine` and bound its
    /// Write credential with the slip `slip`, under the steady baseline that
    /// defers a burst.
    fn device_with_slip(&self, machine: PeerMachine, slip: [u8; 32]) -> TestResult<DevicePeer> {
        let device = DevicePeer::of_connection(machine, Some(slip));
        self.vault.set_federation_burst_policy(
            &self.owner,
            BurstPeer::Device(&device),
            steady(FederationBurstOutcome::Defer),
        )?;
        Ok(device)
    }

    /// A burst of `device` over its baseline, held: answers its batch's
    /// address.
    fn hold_burst(&self, device: &DevicePeer) -> TestResult<String> {
        let burst = self.rows_update(BURST_ROWS)?;
        match admit_device_window_update(&self.vault, device, &self.window, &burst, &[])? {
            DeviceBurstAdmission::Defer { batch_ref } => Ok(batch_ref),
            other => panic!("a burst over the device's baseline is deferred: {other:?}"),
        }
    }

    /// A WORLD row of this home.
    fn world(&self, seed: u8) -> TestResult<EntityId> {
        let world = EntityId::from_bytes([seed; 16]).map_err(|_| "a world id")?;
        self.vault.put_entity(
            &world,
            ENTITY_TYPE_WORLD,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            b"world",
        )?;
        Ok(world)
    }

    /// One update from the device adding `rows` rows to the window.
    fn rows_update(&self, rows: usize) -> TestResult<Vec<u8>> {
        let before = self.doc.oplog_vv();
        let entities = self.doc.get_map("entities");
        for _ in 0..rows {
            entities.insert(&EntityId::now().to_hex(), vec![1_u8, 2, 3])?;
        }
        self.doc.commit();
        Ok(self.doc.export(ExportMode::updates(&before))?)
    }

    fn admit(&self, update: &[u8]) -> TestResult<DeviceBurstAdmission> {
        Ok(admit_device_window_update(
            &self.vault,
            &self.device,
            &self.window,
            update,
            &[],
        )?)
    }

    fn receipt(&self, batch_ref: &str) -> TestResult<FederationBurstReceipt> {
        self.receipt_of(&self.device, batch_ref)
    }

    fn receipt_of(
        &self,
        device: &DevicePeer,
        batch_ref: &str,
    ) -> TestResult<FederationBurstReceipt> {
        Ok(self.vault.federation_burst_disposition_as_owner(
            &self.owner,
            BurstPeer::Device(device),
            batch_ref,
        )?)
    }
}

#[test]
fn a_device_burst_over_its_baseline_defers_and_a_trickle_is_allowed() -> TestResult {
    let home = home(FederationBurstOutcome::Defer)?;

    let trickle = home.rows_update(1)?;
    let work = match home.admit(&trickle)? {
        DeviceBurstAdmission::Allow(work) => work,
        other => panic!("one row at the device's baseline is allowed: {other:?}"),
    };
    assert_eq!(work.window_key(), home.window.as_str());
    assert_eq!(work.update(), trickle.as_slice());
    work.complete(&home.vault)?;
    let landed = home.receipt(&work.batch_ref())?;
    assert_eq!(
        landed.peer(),
        Some(FederationBurstPeerRef::Machine {
            machine: home.machine
        })
    );
    assert_eq!((landed.principal, landed.grant), (None, None));
    assert_eq!(landed.disposition, FederationBurstDisposition::Allow);
    assert_eq!(landed.state, FederationBurstWorkState::Imported);

    let burst = home.rows_update(BURST_ROWS)?;
    let batch_ref = match home.admit(&burst)? {
        DeviceBurstAdmission::Defer { batch_ref } => batch_ref,
        other => panic!("a burst over the device's baseline is deferred: {other:?}"),
    };
    let held = home.receipt(&batch_ref)?;
    assert_eq!(
        held.peer(),
        Some(FederationBurstPeerRef::Machine {
            machine: home.machine
        })
    );
    assert_eq!((held.principal, held.grant), (None, None));
    assert_eq!(
        held.disposition,
        FederationBurstDisposition::Defer {
            replay_ref: batch_ref.clone()
        }
    );
    assert_eq!(held.state, FederationBurstWorkState::Pending);
    assert!(
        held.baseline.rate_ratio > 1.0,
        "the burst's rate ratio is over its baseline: {}",
        held.baseline.rate_ratio
    );
    Ok(())
}

#[test]
fn a_retained_device_burst_is_ready_once_the_rate_returns_to_baseline() -> TestResult {
    let home = home(FederationBurstOutcome::Defer)?;
    let burst = home.rows_update(BURST_ROWS)?;
    let batch_ref = match home.admit(&burst)? {
        DeviceBurstAdmission::Defer { batch_ref } => batch_ref,
        other => panic!("a burst over the device's baseline is deferred: {other:?}"),
    };
    assert!(
        ready_device_work(&home.vault)?.is_empty(),
        "nothing is due while the device's rate is over its baseline"
    );

    home.clock.set(NOW + 2);
    let due = ready_device_work(&home.vault)?;
    let [work] = due.as_slice() else {
        panic!("the deferred burst alone is due once the rate is back at its baseline: {due:?}");
    };
    assert_eq!(work.batch_ref(), batch_ref);
    assert_eq!(work.peer(), home.device);
    assert_eq!(work.update(), burst.as_slice());
    work.complete(&home.vault)?;
    let landed = home.receipt(&batch_ref)?;
    assert_eq!(landed.state, FederationBurstWorkState::Imported);
    assert_eq!(
        landed.disposition,
        FederationBurstDisposition::Defer {
            replay_ref: batch_ref.clone()
        }
    );
    assert!(
        ready_device_work(&home.vault)?.is_empty(),
        "a completed batch is not handed back again"
    );
    Ok(())
}

#[test]
fn an_isolated_device_burst_is_proposed_and_replays_without_a_human() -> TestResult {
    let home = home(FederationBurstOutcome::IsolateAndPropose)?;
    let burst = home.rows_update(BURST_ROWS)?;
    let (batch_ref, bundle_ref) = match home.admit(&burst)? {
        DeviceBurstAdmission::IsolateAndPropose {
            batch_ref,
            bundle_ref,
        } => (batch_ref, bundle_ref),
        other => panic!("a burst over the device's baseline is isolated: {other:?}"),
    };
    let bundles = home.vault.federation_burst_reviews_as_owner(&home.owner)?;
    let bundle = bundles
        .iter()
        .find(|bundle| bundle.bundle_ref == bundle_ref)
        .ok_or("the burst is proposed to the owner in the device's review bundle")?;
    assert_eq!(bundle.request_refs, vec![batch_ref.clone()]);
    assert!(
        ready_device_work(&home.vault)?.is_empty(),
        "nothing is due while the device's rate is over its baseline"
    );

    home.clock.set(NOW + 2);
    let due = ready_device_work(&home.vault)?;
    let [work] = due.as_slice() else {
        panic!("the isolated burst alone is due once the rate is back at its baseline: {due:?}");
    };
    assert_eq!(work.batch_ref(), batch_ref);
    work.complete(&home.vault)?;
    let landed = home.receipt(&batch_ref)?;
    assert_eq!(landed.state, FederationBurstWorkState::Imported);
    assert!(
        matches!(
            landed.disposition,
            FederationBurstDisposition::IsolateAndPropose { .. }
        ),
        "the receipt keeps the original disposition: {:?}",
        landed.disposition
    );
    Ok(())
}

#[test]
fn a_held_burst_ends_stale_once_its_slip_expires() -> TestResult {
    let home = home(FederationBurstOutcome::Defer)?;
    let slip = [0x41; 32];
    home.mint_slip(slip, 60)?;
    let device = home.device_with_slip(PeerMachine::Unknown, slip)?;
    let batch_ref = home.hold_burst(&device)?;
    assert_eq!(
        home.receipt_of(&device, &batch_ref)?.state,
        FederationBurstWorkState::Pending
    );

    // Past the slip's lifetime, and the device's rate back at its baseline.
    home.clock.set(NOW + 120);
    let due = ready_device_work(&home.vault)?;
    assert!(
        due.is_empty(),
        "a burst held under a slip that has expired since is not handed back: {due:?}"
    );
    assert_eq!(
        home.receipt_of(&device, &batch_ref)?.state,
        FederationBurstWorkState::StaleAuthority
    );
    Ok(())
}

#[test]
fn a_held_burst_ends_stale_once_its_machines_slip_is_revoked() -> TestResult {
    let home = home(FederationBurstOutcome::Defer)?;
    let slip = [0x42; 32];
    let issuer = home.mint_slip(slip, 3_600)?;
    let device = home.device_with_slip(
        PeerMachine::Proven {
            machine: home.machine,
            key: [7; 32],
        },
        slip,
    )?;
    let batch_ref = home.hold_burst(&device)?;

    home.vault.revoke_capability_slip(&issuer, slip)?;
    home.clock.set(NOW + 2);
    let due = ready_device_work(&home.vault)?;
    assert!(
        due.is_empty(),
        "a burst held under a machine whose slip is revoked since is not handed back: {due:?}"
    );
    let ended = home.receipt_of(&device, &batch_ref)?;
    assert_eq!(ended.state, FederationBurstWorkState::StaleAuthority);
    assert_eq!(
        ended.peer(),
        Some(FederationBurstPeerRef::Machine {
            machine: home.machine
        })
    );
    Ok(())
}

#[test]
fn a_held_burst_ends_stale_once_its_grant_narrows_in_place() -> TestResult {
    let home = home(FederationBurstOutcome::Defer)?;
    let owner = home.vault.ensure_embedded_owner_actor()?;
    // The owner's own-device grant, as pairing provisions it: the grant a
    // paired device's residence selector names and its slip carries.
    let grant_id = EntityId::now();
    let grant = FederationGrant::new(
        own_device_residence_scope(),
        owner,
        FederationGrantRole::Owner,
        FederationGrantPreset::Owner,
    );
    put_selector_test_federation_grant(&home.vault, &grant_id, &grant, NOW)?;
    let slip = [0x43; 32];
    home.mint_slip_under(slip, 3_600, Some(grant_id))?;
    let device = home.device_with_slip(PeerMachine::Unknown, slip)?;
    let batch_ref = home.hold_burst(&device)?;

    // The owner narrows that grant in place to one other world: the same
    // id, still live and conferring, and the slip naming it still stands.
    home.clock.set(NOW + 1);
    let mut narrowed = grant.clone();
    narrowed.authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(EntityId::now())]));
    put_selector_test_federation_grant(&home.vault, &grant_id, &narrowed, NOW + 1)?;
    home.clock.set(NOW + 2);
    let due = ready_device_work(&home.vault)?;
    assert!(
        due.is_empty(),
        "a burst held under a grant narrowed since is not handed back: {due:?}"
    );
    assert_eq!(
        home.receipt_of(&device, &batch_ref)?.state,
        FederationBurstWorkState::StaleAuthority
    );
    Ok(())
}

#[test]
fn a_held_burst_ends_stale_once_another_residence_grant_of_its_holder_expires() -> TestResult {
    let home = home(FederationBurstOutcome::Defer)?;
    let owner = home.vault.ensure_embedded_owner_actor()?;
    // The own-device grant the device's slip names. It never expires.
    let named_id = EntityId::now();
    let named = FederationGrant::new(
        own_device_residence_scope(),
        owner,
        FederationGrantRole::Owner,
        FederationGrantPreset::Owner,
    );
    put_selector_test_federation_grant(&home.vault, &named_id, &named, NOW)?;
    // A second grant of the slip's holder under the residence scope, which
    // the device's selector may name instead of the slip's: a Delegate
    // grant that ends at NOW + 1.
    let delegate_id = EntityId::now();
    let mut delegate = FederationGrant::new(
        own_device_residence_scope(),
        owner,
        FederationGrantRole::Delegate,
        FederationGrantPreset::Delegate,
    );
    delegate.expires_at = Some(NOW + 1);
    put_selector_test_federation_grant(&home.vault, &delegate_id, &delegate, NOW)?;
    let slip = [0x45; 32];
    home.mint_slip_under(slip, 3_600, Some(named_id))?;
    let device = home.device_with_slip(PeerMachine::Unknown, slip)?;
    let batch_ref = home.hold_burst(&device)?;

    // Two seconds on, the device's rate is back at its baseline and the
    // Delegate grant has ended. No row changed and the slip still stands,
    // but a write held under that grant no longer does.
    home.clock.set(NOW + 2);
    let due = ready_device_work(&home.vault)?;
    assert!(
        due.is_empty(),
        "a burst held under a grant that has expired since is not handed back: {due:?}"
    );
    assert_eq!(
        home.receipt_of(&device, &batch_ref)?.state,
        FederationBurstWorkState::StaleAuthority
    );
    Ok(())
}

#[test]
fn a_handed_back_burst_no_longer_stands_once_its_grant_narrows() -> TestResult {
    let home = home(FederationBurstOutcome::Defer)?;
    let owner = home.vault.ensure_embedded_owner_actor()?;
    let grant_id = EntityId::now();
    let grant = FederationGrant::new(
        own_device_residence_scope(),
        owner,
        FederationGrantRole::Owner,
        FederationGrantPreset::Owner,
    );
    put_selector_test_federation_grant(&home.vault, &grant_id, &grant, NOW)?;
    let slip = [0x46; 32];
    home.mint_slip_under(slip, 3_600, Some(grant_id))?;
    let device = home.device_with_slip(PeerMachine::Unknown, slip)?;
    let batch_ref = home.hold_burst(&device)?;

    // Two seconds on, the drain's read hands the burst back, and it stands
    // as that read judged it.
    home.clock.set(NOW + 2);
    let due = ready_device_work(&home.vault)?;
    let [work] = due.as_slice() else {
        return Err(format!("one burst is handed back: {due:?}").into());
    };
    assert!(device_burst_work_stands(&home.vault, work)?);

    // While the home loads the window, the owner narrows the grant in place:
    // the writer that would persist the replay finds the batch no longer
    // standing, so it lands nothing, and the drain's next pass ends it.
    let mut narrowed = grant.clone();
    narrowed.authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(EntityId::now())]));
    put_selector_test_federation_grant(&home.vault, &grant_id, &narrowed, NOW + 2)?;
    assert!(
        !device_burst_work_stands(&home.vault, work)?,
        "a handed-back burst whose grant narrowed since does not stand in the persist's writer"
    );
    assert!(ready_device_work(&home.vault)?.is_empty());
    assert_eq!(
        home.receipt_of(&device, &batch_ref)?.state,
        FederationBurstWorkState::StaleAuthority
    );
    Ok(())
}

#[test]
fn a_handed_back_burst_no_longer_stands_once_its_batch_has_ended() -> TestResult {
    let home = home(FederationBurstOutcome::Defer)?;
    let slip = [0x47; 32];
    home.mint_slip(slip, 3_600)?;
    let device = home.device_with_slip(PeerMachine::Unknown, slip)?;
    home.hold_burst(&device)?;
    home.clock.set(NOW + 2);
    let due = ready_device_work(&home.vault)?;
    let [work] = due.as_slice() else {
        return Err(format!("one burst is handed back: {due:?}").into());
    };
    assert!(device_burst_work_stands(&home.vault, work)?);

    // Another pass ended the batch first: it is no longer held, so this
    // replay's writer persists nothing of it.
    work.complete(&home.vault)?;
    assert!(
        !device_burst_work_stands(&home.vault, work)?,
        "a burst whose batch has ended does not stand in the persist's writer"
    );
    Ok(())
}

#[test]
fn a_held_burst_ends_stale_once_a_world_is_kept_off_its_device() -> TestResult {
    let home = home(FederationBurstOutcome::Defer)?;
    let slip = [0x44; 32];
    let issuer = home.mint_slip(slip, 3_600)?;
    // One world the owner already keeps on the home, so the home stands
    // enrolled and its owner bound before the burst is held: below, only
    // the second world's read setting changes.
    let kept = home.world(0x91)?;
    let world = home.world(0x92)?;
    home.vault
        .keep_world_on_this_machine_under_for_test(&issuer, kept, true)?;
    let device = home.device_with_slip(PeerMachine::Unknown, slip)?;
    let batch_ref = home.hold_burst(&device)?;

    // The owner keeps a second world on the home: no machine the device
    // proved may read it now. The device's slip still stands.
    home.vault
        .keep_world_on_this_machine_under_for_test(&issuer, world, true)?;
    home.clock.set(NOW + 2);
    let due = ready_device_work(&home.vault)?;
    assert!(
        due.is_empty(),
        "a burst held before a world was kept off its device is not handed back: {due:?}"
    );
    assert_eq!(
        home.receipt_of(&device, &batch_ref)?.state,
        FederationBurstWorkState::StaleAuthority
    );
    Ok(())
}

/// Review round 2 of #8386, P1 1: a device that sends its held update again
/// before its rate is back at its baseline is answered as held again, not
/// handed the work to land, deferred or isolated and released alike; once
/// the rate is back, the same bytes are the same work.
#[test]
fn a_held_device_burst_sent_again_before_its_rate_is_back_stays_held() -> TestResult {
    let home = home(FederationBurstOutcome::Defer)?;
    let burst = home.rows_update(BURST_ROWS)?;
    let batch_ref = match home.admit(&burst)? {
        DeviceBurstAdmission::Defer { batch_ref } => batch_ref,
        other => panic!("a burst over the device's baseline is deferred: {other:?}"),
    };
    let again = home.admit(&burst)?;
    assert!(
        matches!(&again, DeviceBurstAdmission::Defer { batch_ref: held } if *held == batch_ref),
        "the same bytes sent again in the same tick are held again: {again:?}"
    );
    assert_eq!(
        home.receipt(&batch_ref)?.state,
        FederationBurstWorkState::Pending
    );

    home.clock.set(NOW + 2);
    match home.admit(&burst)? {
        DeviceBurstAdmission::Allow(work) => assert_eq!(work.batch_ref(), batch_ref),
        other => panic!("once the rate is back, the held bytes are the same work: {other:?}"),
    }

    let isolating = home(FederationBurstOutcome::IsolateAndPropose)?;
    let burst = isolating.rows_update(BURST_ROWS)?;
    let (batch_ref, bundle_ref) = match isolating.admit(&burst)? {
        DeviceBurstAdmission::IsolateAndPropose {
            batch_ref,
            bundle_ref,
        } => (batch_ref, bundle_ref),
        other => panic!("a burst over the device's baseline is isolated: {other:?}"),
    };
    isolating
        .vault
        .release_federation_burst_review(&isolating.owner, &bundle_ref)?;
    let again = isolating.admit(&burst)?;
    assert!(
        !matches!(again, DeviceBurstAdmission::Allow(_)),
        "a released isolated burst sent again before the rate is back is held: {again:?}"
    );
    assert_eq!(
        isolating.receipt(&batch_ref)?.state,
        FederationBurstWorkState::Pending
    );
    Ok(())
}

/// Review round 2 of #8386, P1 2: a batch its owner rejected at review, or
/// one that already landed, is settled. The device that sends the same
/// bytes again is answered by that receipt; it never gets them back as work
/// to land, and the drain never hands them out.
#[test]
fn a_settled_device_batch_sent_again_is_never_handed_back_to_land() -> TestResult {
    let home = home(FederationBurstOutcome::IsolateAndPropose)?;
    let burst = home.rows_update(BURST_ROWS)?;
    let (batch_ref, bundle_ref) = match home.admit(&burst)? {
        DeviceBurstAdmission::IsolateAndPropose {
            batch_ref,
            bundle_ref,
        } => (batch_ref, bundle_ref),
        other => panic!("a burst over the device's baseline is isolated: {other:?}"),
    };
    home.vault
        .reject_federation_burst_review(&home.owner, &bundle_ref)?;
    assert_eq!(
        home.receipt(&batch_ref)?.state,
        FederationBurstWorkState::Rejected
    );
    for at in [NOW, NOW + 2] {
        home.clock.set(at);
        let again = home.admit(&burst)?;
        assert!(
            !matches!(again, DeviceBurstAdmission::Allow(_)),
            "a rejected batch sent again at {at} is not work to land: {again:?}"
        );
        assert!(
            matches!(
                &again,
                DeviceBurstAdmission::Settled {
                    batch_ref: settled,
                    state: FederationBurstWorkState::Rejected,
                } if *settled == batch_ref
            ),
            "its receipt answers it: {again:?}"
        );
        assert!(
            ready_device_work(&home.vault)?.is_empty(),
            "the drain hands out no rejected batch at {at}"
        );
        assert_eq!(
            home.receipt(&batch_ref)?.state,
            FederationBurstWorkState::Rejected
        );
    }

    let landing = home(FederationBurstOutcome::Defer)?;
    let trickle = landing.rows_update(1)?;
    let work = match landing.admit(&trickle)? {
        DeviceBurstAdmission::Allow(work) => work,
        other => panic!("one row at the device's baseline is allowed: {other:?}"),
    };
    work.complete(&landing.vault)?;
    let again = landing.admit(&trickle)?;
    assert!(
        !matches!(again, DeviceBurstAdmission::Allow(_)),
        "a batch that landed, sent again, is not work to land again: {again:?}"
    );
    assert!(
        matches!(
            &again,
            DeviceBurstAdmission::Settled {
                batch_ref,
                state: FederationBurstWorkState::Imported,
            } if *batch_ref == work.batch_ref()
        ),
        "its receipt answers it: {again:?}"
    );
    assert_eq!(
        landing.receipt(&work.batch_ref())?.state,
        FederationBurstWorkState::Imported
    );
    Ok(())
}

/// A federated peer's burst receipt as a vault stored it before own devices
/// had receipts: it names the peer by `principal` and `grant`, field for
/// field in the order the ledger wrote them.
#[derive(serde::Serialize)]
struct ReceiptStoredBeforeDevices {
    batch_ref: String,
    principal: EntityId,
    grant: EntityId,
    window_key: String,
    disposition: FederationBurstDisposition,
    state: FederationBurstWorkState,
    baseline: FederationBurstBaselineState,
}

#[test]
fn a_receipt_stored_before_device_peers_loads_and_lists_as_before() -> TestResult {
    let principal = EntityId::now();
    let grant = EntityId::now();
    let batch_ref = "a1".repeat(32);
    let stored_row = ReceiptStoredBeforeDevices {
        batch_ref: batch_ref.clone(),
        principal,
        grant,
        window_key: "base".to_owned(),
        disposition: FederationBurstDisposition::Defer {
            replay_ref: batch_ref.clone(),
        },
        state: FederationBurstWorkState::Pending,
        baseline: FederationBurstBaselineState {
            baseline: FederationBurstBaseline {
                name: "peer".to_owned(),
                writes_per_sec: 1.0,
                structural_streak: 1.0,
            },
            learned: true,
            vault_size: 64,
            recent_writes: 5,
            rate_ratio: 5.0,
            streak: 1,
            streak_ratio: 1.0,
        },
    };
    let stored = rmp_serde::to_vec_named(&stored_row)?;
    let federated = FederationBurstPeerRef::Federated { principal, grant };

    let loaded = decode_burst_receipt_row(&stored, &federated, &batch_ref)
        .map_err(|error| format!("a receipt stored before own devices loads: {error}"))?;
    assert_eq!(
        serde_json::to_value(&loaded)?,
        serde_json::to_value(&stored_row)?,
        "it lists as the peer's burst doors answered it before"
    );
    assert_eq!(
        rmp_serde::to_vec_named(&loaded)?,
        stored,
        "written again, a federated receipt keeps its stored bytes"
    );

    let other_peer = FederationBurstPeerRef::Federated {
        principal: EntityId::now(),
        grant,
    };
    assert!(
        decode_burst_receipt_row(&stored, &other_peer, &batch_ref).is_err(),
        "another peer does not read it"
    );
    Ok(())
}
