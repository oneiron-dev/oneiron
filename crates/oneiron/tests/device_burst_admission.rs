//! L7-41: an own device's window update at its home gets the same relative
//! burst response a federated peer's does (arch-0023b
//! `#decision-federation-26`): a trickle is allowed, a burst over the
//! device's own baseline is deferred, or isolated and proposed, and the home
//! gets it back by itself once the device's rate is at its baseline again.
//! A held burst whose device no longer stands as its connection proved it
//! (its Write credential's slip expired or revoked since) ends
//! `StaleAuthority` and is never handed back.
//!
//! The last test reads a receipt stored before own devices had receipts
//! through the ledger's door (the lead's M-1 STORED-CHANGE-RULE, Engine
//! RULING L7-41-STORED-RECEIPT = B).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test device_burst_admission`.

use std::sync::Arc;

use loro::{ExportMode, LoroDoc};
use oneiron::authority::{HostSlipIssuer, PeerMachine};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::sync::WindowKey;
use oneiron::sync::federation_burst::{
    BurstPeer, DeviceBurstAdmission, DevicePeer, FederationBurstBaseline,
    FederationBurstBaselineState, FederationBurstDisposition, FederationBurstOutcome,
    FederationBurstPeerRef, FederationBurstPolicy, FederationBurstReceipt,
    FederationBurstWorkState, admit_device_window_update, ready_device_work,
};
use oneiron::test_doors::burst_receipt_stored_shape::decode_burst_receipt_row;
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
