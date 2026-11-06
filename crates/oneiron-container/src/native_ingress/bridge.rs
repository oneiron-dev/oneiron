use super::{
    CHUNK, CLOSED,
    io::{self, SocketIo},
};
use crate::HostNetPermit;
use std::{
    fs::File,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

struct Bridge {
    local: UnixStream,
    wire: File,
    alive: Arc<AtomicBool>,
    failed: AtomicBool,
    uploaded: AtomicBool,
    _room: HostNetPermit,
}

impl Bridge {
    fn waiting(&self) -> bool {
        self.alive.load(Ordering::Acquire) && !self.failed.load(Ordering::Acquire)
    }

    fn receiving(&self) -> bool {
        self.waiting()
            && !(self.uploaded.load(Ordering::Acquire) && io::hung_up(self.local.as_raw_fd()))
    }

    fn abort(&self) {
        self.failed.store(true, Ordering::Release);
        io::shutdown(self.local.as_raw_fd(), libc::SHUT_RDWR);
        io::shutdown(self.wire.as_raw_fd(), libc::SHUT_RDWR);
    }
}

pub(super) fn spawn(
    local: UnixStream,
    wire: File,
    alive: Arc<AtomicBool>,
    room: HostNetPermit,
) -> std::io::Result<()> {
    local.set_nonblocking(true)?;
    let bridge = Arc::new(Bridge {
        local,
        wire,
        alive,
        _room: room,
        failed: AtomicBool::new(false),
        uploaded: AtomicBool::new(false),
    });
    let upload = Arc::clone(&bridge);
    let thread = std::thread::Builder::new().spawn(move || {
        if send(&upload).is_err() {
            upload.abort();
        }
    })?;
    let download = Arc::clone(&bridge);
    if let Err(error) = std::thread::Builder::new().spawn(move || {
        if receive(&download).is_err() {
            // A peer that fully closes after its earlier write-half-close
            // also cancels the other direction; EOF alone must not do so.
            if download.waiting()
                && download.uploaded.load(Ordering::Acquire)
                && io::hung_up(download.local.as_raw_fd())
            {
                let waiting = || download.waiting();
                let mut wire = SocketIo {
                    socket: &download.wire,
                    waiting: &waiting,
                };
                let _ = wire.write_all(&CLOSED.to_be_bytes());
            }
            download.abort();
        }
    }) {
        bridge.abort();
        let _ = thread.join();
        return Err(error);
    }
    Ok(())
}

fn send(bridge: &Bridge) -> std::io::Result<()> {
    let waiting = || bridge.waiting();
    let mut local = SocketIo {
        socket: &bridge.local,
        waiting: &waiting,
    };
    let mut wire = SocketIo {
        socket: &bridge.wire,
        waiting: &waiting,
    };
    let mut bytes = [0; CHUNK];
    loop {
        let count = local.read(&mut bytes)?;
        if count == 0 {
            let closed = io::hung_up(bridge.local.as_raw_fd());
            wire.write_all(&(if closed { CLOSED } else { 0 }).to_be_bytes())?;
            bridge.uploaded.store(true, Ordering::Release);
            if closed {
                bridge.abort();
            }
            return Ok(());
        }
        wire.write_all(&(count as u32).to_be_bytes())?;
        wire.write_all(&bytes[..count])?;
    }
}

fn receive(bridge: &Bridge) -> std::io::Result<()> {
    let receiving = || bridge.receiving();
    let mut wire = SocketIo {
        socket: &bridge.wire,
        waiting: &receiving,
    };
    let mut local = SocketIo {
        socket: &bridge.local,
        waiting: &receiving,
    };
    let mut bytes = [0; CHUNK];
    loop {
        let mut count = [0; 4];
        wire.read_exact(&mut count)?;
        let count = u32::from_be_bytes(count);
        match count {
            0 => {
                io::shutdown(bridge.local.as_raw_fd(), libc::SHUT_WR);
                return Ok(());
            }
            CLOSED => {
                bridge.abort();
                return Ok(());
            }
            count if count as usize <= CHUNK => {
                let bytes = &mut bytes[..count as usize];
                wire.read_exact(bytes)?;
                local.write_all(bytes)?;
            }
            _ => return Err(std::io::Error::from_raw_os_error(libc::EPROTO)),
        }
    }
}
