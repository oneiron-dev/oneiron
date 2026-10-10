//! A stopped organ gives its descriptors back: a host that starts and stops
//! organ after organ holds no more open files than it started with. Alone
//! in its own test binary, so no other test opens files while it counts.
#![cfg(target_os = "linux")]

use std::thread;
use std::time::{Duration, Instant};

use oneiron_organ_host::{HostConfig, OrganHost, OrganSpec};

const PROBE: &str = env!("CARGO_BIN_EXE_oneiron-organ-probe");

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").expect("fd table").count()
}

#[test]
fn stopped_organs_give_their_descriptors_back() {
    // Round-4 repro: each unloaded or revoked organ kept its two sockets.
    let host = OrganHost::new(HostConfig::default());
    let cycle = |n: usize| {
        let name = format!("probe-{n}");
        host.install(OrganSpec::first_party(&name, PROBE));
        host.warm(&name).expect("warm");
        if n % 2 == 0 {
            assert!(host.unload(&name));
        } else {
            host.revoke(&name);
        }
    };
    // The first start may open what the process keeps for good.
    cycle(0);
    cycle(1);
    let before = open_fds();
    for n in 2..66 {
        cycle(n);
    }
    // Each reader thread closes its clone as it exits, just after the stop.
    let until = Instant::now() + Duration::from_secs(5);
    while open_fds() > before && Instant::now() < until {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(open_fds(), before, "64 stopped organs still hold descriptors");
}
