//! A stopped organ gives its descriptors back: hosts that start and stop
//! their organ hold no more open files than they started with. Alone in its
//! own test binary, so no other test opens files while it counts.
#![cfg(target_os = "linux")]

use std::thread;
use std::time::{Duration, Instant};

use oneiron_organ_host::{HostConfig, OrganHost, OrganSpec};

const PROBE: &str = env!("CARGO_BIN_EXE_oneiron-organ-probe");

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").expect("fd table").count()
}

/// A host whose organ was started, then unloaded (even `n`) or revoked.
fn stopped(n: usize) -> OrganHost {
    let host = OrganHost::new(HostConfig::default());
    host.install(OrganSpec::first_party("probe", PROBE));
    host.warm("probe").expect("warm");
    if n % 2 == 0 {
        assert!(host.unload("probe"));
    } else {
        host.revoke("probe");
    }
    host
}

#[test]
fn stopped_organs_give_their_descriptors_back() {
    // Round-4 repro: an unloaded or revoked organ kept its two sockets for
    // as long as its host lived.
    // The first starts may open what the process keeps for good.
    let mut hosts = vec![stopped(0), stopped(1)];
    let before = open_fds();
    for n in 2..66 {
        hosts.push(stopped(n));
    }
    // Each reader thread closes its clone as it exits, just after the stop.
    let until = Instant::now() + Duration::from_secs(5);
    while open_fds() > before && Instant::now() < until {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        open_fds(),
        before,
        "64 hosts with a stopped organ still hold descriptors"
    );
    drop(hosts);
}
