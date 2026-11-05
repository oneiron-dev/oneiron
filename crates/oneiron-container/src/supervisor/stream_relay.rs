//! A guest stream's relay to its remote, and its relay to the host's DNS.

use super::State;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Relays one admitted stream both ways. A `gated` stream's opening bytes
/// pass the relay's name gate after the guest's connect was answered and
/// before any reaches the remote; a refused one ends with nothing sent
/// (FIX 7652).
pub(super) fn relay_stream(
    mut guest: UnixStream,
    mut remote: std::net::TcpStream,
    target: SocketAddr,
    gated: bool,
    state: Arc<State>,
) {
    std::thread::spawn(move || {
        let (Ok(mut incoming), Ok(mut outgoing)) = (remote.try_clone(), guest.try_clone()) else {
            return;
        };
        let _ = incoming.set_read_timeout(Some(Duration::from_millis(250)));
        let _ = guest.set_read_timeout(Some(Duration::from_millis(250)));
        let alive = Arc::clone(&state.alive);
        let relay = Arc::clone(&state.relay);
        let upload = std::thread::spawn(move || {
            if gated {
                let opening = relay.open_upload(target, &mut guest, &alive);
                if opening.and_then(|bytes| remote.write_all(&bytes)).is_err() {
                    let _ = remote.shutdown(Shutdown::Both);
                    return;
                }
            }
            let mut bytes = [0; 32768];
            while alive.load(Ordering::Acquire) {
                match guest.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(n) => {
                        if remote.write_all(&bytes[..n]).is_err() {
                            break;
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            let _ = remote.shutdown(Shutdown::Write);
        });
        let mut hash = blake3::Hasher::new();
        let mut total = 0;
        let mut bytes = [0; 32768];
        while state.alive.load(Ordering::Acquire) {
            match incoming.read(&mut bytes) {
                Ok(0) => break,
                Ok(n) => {
                    hash.update(&bytes[..n]);
                    total += n as u64;
                    if outgoing.write_all(&bytes[..n]).is_err() {
                        break;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
        let _ = incoming.shutdown(Shutdown::Both);
        let _ = outgoing.shutdown(Shutdown::Both);
        let _ = upload.join();
        state
            .relay
            .transferred(target, *hash.finalize().as_bytes(), total);
    });
}

pub(super) fn relay_dns(mut guest: UnixStream, target: SocketAddr, state: Arc<State>) {
    std::thread::spawn(move || {
        while state.alive.load(Ordering::Acquire) {
            let mut len = [0; 2];
            if guest.read_exact(&mut len).is_err() {
                break;
            }
            let mut query = vec![0; u16::from_be_bytes(len) as usize];
            if guest.read_exact(&mut query).is_err() {
                break;
            }
            let Ok(answer) = state.relay.datagram(target, &query) else {
                break;
            };
            if guest
                .write_all(&(answer.len() as u16).to_be_bytes())
                .and_then(|()| guest.write_all(&answer))
                .is_err()
            {
                break;
            }
        }
        let _ = guest.shutdown(Shutdown::Both);
    });
}
