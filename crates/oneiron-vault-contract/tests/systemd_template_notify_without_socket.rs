//! A `Type=notify` unit without socket activation still sets `NOTIFY_SOCKET`:
//! the plain host reports `READY=1` and `STOPPING=1` there, the way the
//! activated host does, so the shipped unit does not wait out
//! `TimeoutStartSec` while `oneiron.socket` is off
//! (FIX SYSTEMD-TEMPLATE-NOTIFY-WITHOUT-SOCKET). Unix only: `DesktopHost`
//! is a Unix adapter.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use oneiron_vault_contract::host::Host;
use oneiron_vault_contract::host_adapters::DesktopHost;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

/// Without activation the plain host answers; with `NOTIFY_SOCKET` set it
/// must report readiness and stopping to the service manager.
#[test]
fn plain_host_notifies_without_socket_activation() {
    // SAFETY: this binary holds a single test, so no other thread reads or
    // writes the process environment while these run.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("NOTIFY_SOCKET");
    }
    let addr = "127.0.0.1:0".parse().unwrap();
    let mut host = DesktopHost::detect(addr, "Listeners", "com.oneiron.server").unwrap();
    assert_eq!(host.adapter(), "in_process");
    // No manager to report to: both calls stay silent no-ops.
    host.ready().unwrap();
    host.on_stop().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notify.sock");
    let notify = UnixDatagram::bind(&path).unwrap();
    notify
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    // SAFETY: as above; nothing else in this process touches `NOTIFY_SOCKET`.
    unsafe {
        std::env::set_var("NOTIFY_SOCKET", &path);
    }
    host.ready().unwrap();
    let mut message = [0_u8; 64];
    let read = notify
        .recv(&mut message)
        .expect("the plain host sends READY=1 to NOTIFY_SOCKET");
    assert_eq!(&message[..read], b"READY=1");
    host.on_stop().unwrap();
    let read = notify
        .recv(&mut message)
        .expect("the plain host sends STOPPING=1 to NOTIFY_SOCKET");
    assert_eq!(&message[..read], b"STOPPING=1");
    // SAFETY: as above.
    unsafe {
        std::env::remove_var("NOTIFY_SOCKET");
    }
}
