//! L7-41: an own device's window update at its home gets the same relative
//! burst response a federated peer's does (arch-0023b
//! `#decision-federation-26`): a trickle is allowed, a burst over the
//! device's own baseline is deferred, or isolated and proposed, and the home
//! gets it back by itself once the device's rate is at its baseline again.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test device_burst_admission`.

use std::sync::Arc;

use loro::{ExportMode, LoroDoc};
use oneiron::authority::PeerMachine;
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::sync::WindowKey;
use oneiron::sync::federation_burst::{
    BurstPeer, DeviceBurstAdmission, DevicePeer, FederationBurstBaseline,
    FederationBurstDisposition, FederationBurstOutcome, FederationBurstPeerRef,
    FederationBurstPolicy, FederationBurstReceipt, FederationBurstWorkState,
    admit_device_window_update, ready_device_work,
};
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
    vault.set_federation_burst_policy(
        &owner,
        BurstPeer::Device(&device),
        FederationBurstPolicy {
            baseline: Some(FederationBurstBaseline {
                name: "steady".into(),
                writes_per_sec: 1.0,
                structural_streak: 1.0,
            }),
            unusual_rate,
            unusual_streak: FederationBurstOutcome::IsolateAndPropose,
        },
    )?;
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

impl Home {
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
        Ok(self.vault.federation_burst_disposition_as_owner(
            &self.owner,
            BurstPeer::Device(&self.device),
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
        landed.peer,
        FederationBurstPeerRef::Machine {
            machine: home.machine
        }
    );
    assert_eq!(landed.disposition, FederationBurstDisposition::Allow);
    assert_eq!(landed.state, FederationBurstWorkState::Imported);

    let burst = home.rows_update(BURST_ROWS)?;
    let batch_ref = match home.admit(&burst)? {
        DeviceBurstAdmission::Defer { batch_ref } => batch_ref,
        other => panic!("a burst over the device's baseline is deferred: {other:?}"),
    };
    let held = home.receipt(&batch_ref)?;
    assert_eq!(
        held.peer,
        FederationBurstPeerRef::Machine {
            machine: home.machine
        }
    );
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
