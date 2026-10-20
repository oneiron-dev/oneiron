//! Native VM network channels terminate at the engine's one egress proxy.
//!
//! Each vsock request is host work: it takes its room on the relay's host
//! floor before its thread starts, and a full floor answers it `EAGAIN`
//! naming the floor, unread (FIX 5979). The VM's own floor charges nothing:
//! this is where the VM's network work is counted on the host.
use oneiron_container::{EgressRelay, RelayReply, RelayRequest, read_relay, write_relay};
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::{UnixListener, UnixStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// What one vsock request holds of the host floor until it ends, as
/// (descriptors, workers): its channel, the relay's own socket, and its
/// thread.
const REQUEST: (usize, usize) = (2, 1);
/// What a relayed stream holds besides: the copies of its channel and of
/// the remote socket, and its upload thread.
const STREAM: (usize, usize) = (2, 1);

pub(super) fn serve(listener: UnixListener, relay: Arc<dyn EgressRelay>, alive: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        while alive.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let (fds, workers) = REQUEST;
                    let room = match relay.host_net_floor().acquire(fds, workers) {
                        Ok(room) => room,
                        Err(error) => {
                            back_pressure(stream, &error);
                            continue;
                        }
                    };
                    let relay = Arc::clone(&relay);
                    let alive = Arc::clone(&alive);
                    // A thread the host cannot start drops the channel and
                    // its room; the VM reads the channel's end.
                    let _ = std::thread::Builder::new().spawn(move || {
                        let _ = request(stream, relay, alive);
                        drop(room);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => return,
            }
        }
    });
}
fn request(
    mut channel: UnixStream,
    relay: Arc<dyn EgressRelay>,
    alive: Arc<AtomicBool>,
) -> std::io::Result<()> {
    channel.set_read_timeout(Some(Duration::from_secs(30)))?;
    channel.set_write_timeout(Some(Duration::from_secs(30)))?;
    let op: RelayRequest = read_relay(&mut channel)?;
    let mut reply = RelayReply {
        errno: 0,
        bytes: Vec::new(),
        floor: None,
    };
    let result = match op {
        RelayRequest::Connect { target } => match relay
            .host_net_floor()
            .acquire(STREAM.0, STREAM.1)
            .and_then(|room| relay.connect(target).map(|remote| (room, remote)))
        {
            Ok((_room, mut remote)) => {
                write_relay(&mut channel, &reply)?;
                let mut upload = channel.try_clone()?;
                let mut send = remote.try_clone()?;
                let upload_alive = Arc::clone(&alive);
                upload.set_read_timeout(Some(Duration::from_millis(250)))?;
                remote.set_read_timeout(Some(Duration::from_millis(250)))?;
                let thread = std::thread::spawn(move || {
                    let mut bytes = [0; 32768];
                    while upload_alive.load(Ordering::Acquire) {
                        match upload.read(&mut bytes) {
                            Ok(0) => break,
                            Ok(n) => {
                                if send.write_all(&bytes[..n]).is_err() {
                                    break;
                                }
                            }
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) =>
                            {
                                continue;
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = send.shutdown(Shutdown::Write);
                });
                let mut hash = blake3::Hasher::new();
                let mut count = 0;
                let mut bytes = [0; 32768];
                while alive.load(Ordering::Acquire) {
                    match remote.read(&mut bytes) {
                        Ok(0) => break,
                        Ok(n) => {
                            hash.update(&bytes[..n]);
                            count += n as u64;
                            if channel.write_all(&bytes[..n]).is_err() {
                                break;
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            continue;
                        }
                        Err(_) => break,
                    }
                }
                let _ = remote.shutdown(Shutdown::Both);
                let _ = channel.shutdown(Shutdown::Both);
                let _ = thread.join();
                relay.transferred(target, *hash.finalize().as_bytes(), count);
                return Ok(());
            }
            Err(error) => Err(error),
        },
        RelayRequest::AuthorizeDatagram { target } => relay.authorize_datagram(target),
        RelayRequest::Refusal(refusal) => relay.record_refusal(&refusal),
        RelayRequest::Datagram { target, bytes } => relay
            .datagram(target, &bytes)
            .map(|bytes| reply.bytes = bytes),
    };
    if let Err(error) = result {
        reply = failed(&error);
    }
    write_relay(&mut channel, &reply)
}

/// The reply to a request that failed. A host floor's back-pressure is
/// `EAGAIN`, carrying the floor's name.
fn failed(error: &std::io::Error) -> RelayReply {
    let floor = oneiron_container::saturated_floor(error);
    RelayReply {
        errno: match floor {
            Some(_) => libc::EAGAIN,
            None => error.raw_os_error().unwrap_or(libc::EIO),
        },
        bytes: Vec::new(),
        floor: floor.map(str::to_owned),
    }
}

/// Answers a request the host floor has no room for, unread and on the
/// accepting thread, so never by a wait: an answer that does not fit the
/// fresh channel at once goes with it.
fn back_pressure(mut channel: UnixStream, error: &std::io::Error) {
    let _ = channel.set_nonblocking(true);
    let _ = write_relay(&mut channel, &failed(error));
}
