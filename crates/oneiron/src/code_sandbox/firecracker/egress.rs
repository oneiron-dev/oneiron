//! Native VM network channels terminate at the engine's one egress proxy.
use oneiron_container::{EgressRelay, RelayReply, RelayRequest, read_relay, write_relay};
use std::{io::{Read, Write}, net::Shutdown, os::unix::net::{UnixListener, UnixStream}, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};

pub(super) fn serve(listener: UnixListener, relay: Arc<dyn EgressRelay>, alive: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        while alive.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream,_)) => { let relay = Arc::clone(&relay); let alive = Arc::clone(&alive);
                    std::thread::spawn(move || { let _ = request(stream, relay, alive); }); }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => return,
            }
        }
    });
}
fn request(mut channel: UnixStream, relay: Arc<dyn EgressRelay>, alive: Arc<AtomicBool>) -> std::io::Result<()> {
    channel.set_read_timeout(Some(Duration::from_secs(30)))?;
    channel.set_write_timeout(Some(Duration::from_secs(30)))?;
    let op: RelayRequest = read_relay(&mut channel)?;
    let mut reply = RelayReply { errno: 0, bytes: Vec::new() };
    let result = match op {
        RelayRequest::Connect { target } => {
            match relay.connect(target) {
                Ok(mut remote) => {
                    write_relay(&mut channel, &reply)?;
                    let mut upload = channel.try_clone()?;
                    let mut send = remote.try_clone()?;
                    let upload_alive = Arc::clone(&alive);
                    upload.set_read_timeout(Some(Duration::from_millis(250)))?;
                    remote.set_read_timeout(Some(Duration::from_millis(250)))?;
                    let thread = std::thread::spawn(move || {
                        let mut bytes = [0;32768];
                        while upload_alive.load(Ordering::Acquire) {
                            match upload.read(&mut bytes) {
                                Ok(0) => break,
                                Ok(n) => if send.write_all(&bytes[..n]).is_err() { break; },
                                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                                Err(_) => break,
                            }
                        }
                        let _ = send.shutdown(Shutdown::Write);
                    });
                    let mut hash = blake3::Hasher::new(); let mut count = 0;
                    let mut bytes = [0;32768];
                    while alive.load(Ordering::Acquire) {
                        match remote.read(&mut bytes) {
                            Ok(0) => break,
                            Ok(n) => { hash.update(&bytes[..n]); count += n as u64; if channel.write_all(&bytes[..n]).is_err() { break; } }
                            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                            Err(_) => break,
                        }
                    }
                    let _ = remote.shutdown(Shutdown::Both); let _ = channel.shutdown(Shutdown::Both); let _ = thread.join();
                    relay.transferred(target, *hash.finalize().as_bytes(), count);
                    return Ok(());
                }
                Err(error) => Err(error),
            }
        }
        RelayRequest::AuthorizeDatagram { target } => relay.authorize_datagram(target),
        RelayRequest::Datagram { target, bytes } => relay.datagram(target, &bytes).map(|bytes| reply.bytes = bytes),
    };
    if let Err(error) = result { reply.errno = error.raw_os_error().unwrap_or(libc::EIO); }
    write_relay(&mut channel, &reply)
}
