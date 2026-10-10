//! A stopped organ gives its descriptors back: hosts whose organ was
//! unloaded, revoked or crashed hold no more open files than they started
//! with. Alone in its own test binary, so no other test opens files while it
//! counts.
#![cfg(target_os = "linux")]

use std::thread;
use std::time::{Duration, Instant};

use oneiron::{Vault, VaultConfig};
use oneiron_organ_host::{CallClass, HostConfig, HostError, OrganCall, OrganHost, OrganSpec};

const PROBE: &str = env!("CARGO_BIN_EXE_oneiron-organ-probe");

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("fd table")
        .count()
}

/// A host whose organ was started, then unloaded, revoked, or crashed under
/// a call (by `n`), with nothing called after.
fn stopped(vault: &Vault, n: usize) -> OrganHost {
    let host = OrganHost::new(HostConfig::default());
    let mut spec = OrganSpec::first_party("probe", PROBE);
    spec.verbs = ["probe.crash".to_owned()].into();
    host.install(spec);
    host.warm("probe").expect("warm");
    match n % 3 {
        0 => assert!(host.unload("probe")),
        1 => host.revoke("probe"),
        _ => {
            let crash = OrganCall {
                organ: "probe".into(),
                verb: "probe.crash".into(),
                schema: 1,
                args: rmpv::Value::Nil,
                body: None,
                inputs: Vec::new(),
                class: CallClass::Agent,
                deadline: Duration::from_secs(10),
                grant: "g".into(),
            };
            let crashed = host.call(vault, crash);
            assert!(matches!(crashed, Err(HostError::Crashed(_))), "{crashed:?}");
        }
    }
    host
}

#[test]
fn stopped_organs_give_their_descriptors_back() {
    // Round-4 and round-5 repro: an unloaded, revoked or crashed organ kept
    // its two sockets for as long as its host lived.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    // The first starts may open what the process keeps for good.
    let mut hosts: Vec<OrganHost> = (0..3).map(|n| stopped(&vault, n)).collect();
    let before = open_fds();
    for n in 3..66 {
        hosts.push(stopped(&vault, n));
    }
    // Each reader thread closes its clone as it exits, just after the stop.
    let until = Instant::now() + Duration::from_secs(5);
    while open_fds() > before && Instant::now() < until {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        open_fds(),
        before,
        "63 hosts with a stopped organ still hold descriptors"
    );
    drop(hosts);
}
