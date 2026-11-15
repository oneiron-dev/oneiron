//! FIX 7946 (RULING FIX-SERVER-7946-EGRESS-BODY = B, Engine 15 Nov 19:27): a
//! code sandbox's egress reads a response body whole under the vault's host
//! byte floor and the request deadline. `max_response_bytes` no longer
//! refuses a body; a full floor is waited for until it frees, and only a
//! floor still full at the deadline refuses, as the floor's own typed
//! saturation.
//!
//! Each test serves its body from the proxy's fixture origin
//! (`http://127.0.0.1:8080/`, public `OpenEgressProxy::with_fixture`), whose
//! read is the same floor-bound read an upstream body takes.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test sandbox_egress_body_floor`.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use oneiron::code_sandbox::egress::{EgressConfig, OpenEgressProxy};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_container::{
    EgressRelay, HOST_NET_BYTE_FLOOR, HostNetFloor, HostNetPermit, HttpRequest, floor_saturated,
    saturated_floor,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A body four times the configured `max_response_bytes`.
const PAST_BOUND_BYTES: usize = 4096;
/// A body within it, so only the floor decides its fate.
const WITHIN_BOUND_BYTES: usize = 512;
/// The bound main refused every body past.
const MAX_RESPONSE_BYTES: usize = 1024;

/// A floor that refuses its first `full_for` byte charges as full, then
/// takes every charge; it counts every charge it was asked.
struct FillingFloor {
    full_for: u64,
    asked: AtomicU64,
}

impl FillingFloor {
    fn new(full_for: u64) -> Arc<Self> {
        Arc::new(Self {
            full_for,
            asked: AtomicU64::new(0),
        })
    }

    fn asked(&self) -> u64 {
        self.asked.load(Ordering::SeqCst)
    }
}

impl HostNetFloor for FillingFloor {
    fn acquire(&self, _fds: usize, _workers: usize) -> io::Result<HostNetPermit> {
        Ok(HostNetPermit::new(()))
    }

    fn acquire_bytes(&self, _bytes: u64) -> io::Result<HostNetPermit> {
        let asked = self.asked.fetch_add(1, Ordering::SeqCst);
        if asked < self.full_for {
            Err(floor_saturated(HOST_NET_BYTE_FLOOR))
        } else {
            Ok(HostNetPermit::new(()))
        }
    }
}

struct Fixture {
    _vault_dir: tempfile::TempDir,
    _root: tempfile::TempDir,
    vault: Arc<Vault>,
    proxy: OpenEgressProxy,
    body: Vec<u8>,
}

impl Fixture {
    fn new(
        body_bytes: usize,
        request_timeout: Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let vault_dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(vault_dir.path(), VaultConfig::device())?);
        let root = tempfile::tempdir()?;
        let body: Vec<u8> = (0..body_bytes).map(|at| (at % 251) as u8).collect();
        std::fs::write(root.path().join("owen.bin"), &body)?;
        let config = EgressConfig {
            max_response_bytes: MAX_RESPONSE_BYTES,
            request_timeout,
            ..EgressConfig::default()
        };
        let proxy = OpenEgressProxy::new(Arc::clone(&vault), EntityId::now(), config)
            .with_fixture(Some(root.path().to_path_buf()));
        Ok(Self {
            _vault_dir: vault_dir,
            _root: root,
            vault,
            proxy,
            body,
        })
    }

    fn fetch(&self) -> io::Result<oneiron_container::HttpResponse> {
        self.proxy.fetch(HttpRequest {
            url: "http://127.0.0.1:8080/owen.bin".to_owned(),
            method: "GET".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
            follow_redirects: false,
        })
    }
}

#[test]
fn a_body_past_max_response_bytes_is_delivered_whole() -> TestResult {
    let fixture = Fixture::new(PAST_BOUND_BYTES, Duration::from_secs(30))?;
    let answer = fixture.fetch().map_err(|error| {
        format!(
            "a {PAST_BOUND_BYTES}-byte body past the {MAX_RESPONSE_BYTES}-byte bound was refused: {error}"
        )
    })?;
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.body.as_ref(),
        fixture.body.as_slice(),
        "the body past max_response_bytes is delivered whole, byte for byte"
    );
    Ok(())
}

#[test]
fn a_full_byte_floor_is_waited_for_until_it_frees() -> TestResult {
    let fixture = Fixture::new(WITHIN_BOUND_BYTES, Duration::from_secs(30))?;
    let floor = FillingFloor::new(3);
    let attached = Arc::clone(&floor);
    fixture
        .vault
        .attach_host_net_floor(move || attached as Arc<dyn HostNetFloor>);
    let answer = fixture.fetch().map_err(|error| {
        format!("a floor that frees after three full answers refused the body: {error}")
    })?;
    assert_eq!(answer.body.as_ref(), fixture.body.as_slice());
    assert!(
        floor.asked() > 3,
        "the body's bytes are charged on the host byte floor, waiting out its three full answers; asked {}",
        floor.asked()
    );
    Ok(())
}

#[test]
fn a_byte_floor_still_full_at_the_deadline_refuses_as_the_floor() -> TestResult {
    let deadline = Duration::from_millis(300);
    let fixture = Fixture::new(WITHIN_BOUND_BYTES, deadline)?;
    let floor = FillingFloor::new(u64::MAX);
    let attached = Arc::clone(&floor);
    fixture
        .vault
        .attach_host_net_floor(move || attached as Arc<dyn HostNetFloor>);
    let started = Instant::now();
    let refused = match fixture.fetch() {
        Ok(answer) => {
            return Err(format!(
                "a floor full past the deadline delivered {} bytes; asked {}",
                answer.body.len(),
                floor.asked()
            )
            .into());
        }
        Err(error) => error,
    };
    let waited = started.elapsed();
    assert_eq!(
        refused.kind(),
        io::ErrorKind::WouldBlock,
        "the refusal is the floor's typed saturation: {refused}"
    );
    assert_eq!(
        saturated_floor(&refused),
        Some(HOST_NET_BYTE_FLOOR),
        "the refusal names the host byte floor: {refused}"
    );
    assert!(
        waited >= deadline,
        "the full floor was waited for until the request deadline ({deadline:?}); refused after {waited:?}"
    );
    assert!(
        floor.asked() > 1,
        "a full floor is asked again while the wait lasts; asked {}",
        floor.asked()
    );
    Ok(())
}
