//! A guest-local Fetch entry to the VM's existing host-policy relay.
//!
//! Native PID 1 owns this listener and its IO threads. Returning from
//! `native::run` exits PID 1; the host session lease also tears down the VM.

use oneiron_container::{HttpRequest, RelayReply, RelayRequest, read_relay, write_relay};
use std::{
    io,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
};

pub(super) const SOCKET: &str = "/run/oneiron-native/egress.sock";

pub(super) fn bind() -> io::Result<UnixListener> {
    let listener = UnixListener::bind(SOCKET)?;
    std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

pub(super) fn serve(listener: UnixListener) -> io::Result<()> {
    std::thread::Builder::new().spawn(move || {
        for guest in listener.incoming() {
            let Ok(guest) = guest else { return };
            // Thread creation failure closes this client, not the listener.
            let _ = std::thread::Builder::new().spawn(move || {
                let _ = forward(guest);
            });
        }
    })?;
    Ok(())
}

fn forward(mut guest: UnixStream) -> io::Result<()> {
    // This endpoint accepts a Fetch body only, not arbitrary relay commands
    // or caller-supplied refusal receipts.
    let request: HttpRequest = read_relay(&mut guest)?;
    let mut host = crate::boot::connect_vsock_port(54).map_err(io::Error::other)?;
    write_relay(&mut host, &RelayRequest::Fetch { request })?;
    let reply: RelayReply = read_relay(&mut host)?;
    write_relay(&mut guest, &reply)
}
