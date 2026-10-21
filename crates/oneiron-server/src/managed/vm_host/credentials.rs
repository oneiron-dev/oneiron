//! A cold restore's read of C, its credential frame (FIX 7078). C is read
//! once R has ended, and its frame is exactly 64 bytes and then EOF
//! ([`read_credentials`]), which a supervisor that never writes or closes C
//! never gives; the restore has no deadline, so nothing ends that wait but
//! the restore's own end. The read runs on a blocking worker that owns C
//! and waits on it and on a private cancel pipe at once, with no timeout,
//! and the future awaiting the worker holds the pipe's write end. Dropping
//! that future, as a SIGTERM, a stop or the VMM's exit does, closes it: the
//! worker returns, and C closes on the worker's own thread. No other task
//! ever closes C.

use crate::managed::ManagedError;
use oneiron_vault_contract::{Credentials, read_credentials};
use std::fs::File;
use std::io::{ErrorKind, PipeReader, Read};
use std::os::fd::{AsRawFd as _, OwnedFd};

/// C's credential frame, read and refused as a node's engine reads it, on a
/// worker that this future's drop wakes and ends.
pub(super) async fn read_credential_frame(credentials: OwnedFd) -> anyhow::Result<Credentials> {
    let (cancel, held) = std::io::pipe()?;
    let reader = Cancellable {
        credentials: File::from(credentials),
        cancel,
    };
    let worker = tokio::task::spawn_blocking(move || {
        read_credentials(reader).map_err(|error| ManagedError::CredentialsRejected {
            reason: error.to_string(),
        })
    });
    let read = worker.await;
    // Only now: until the worker returned, this end kept it reading.
    drop(held);
    Ok(read??)
}

/// C, read only once it is ready, and a cancellation once the cancel pipe's
/// write end is gone.
struct Cancellable {
    credentials: File,
    /// Never written: an event on it is its write end closed.
    cancel: PipeReader,
}

impl Read for Cancellable {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut ready = [
            libc::pollfd {
                fd: self.credentials.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.cancel.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let count = ready.len() as libc::nfds_t;
        loop {
            // SAFETY: `ready` is `count` initialised `pollfd`s naming
            // descriptors this reader owns and keeps open across the call.
            let polled = unsafe { libc::poll(ready.as_mut_ptr(), count, -1) };
            if polled < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            // Not `Interrupted`, which the frame's reader retries.
            if ready[1].revents != 0 {
                return Err(std::io::Error::other(
                    "the restore ended before C's credential frame was read",
                ));
            }
            if ready[0].revents != 0 {
                return self.credentials.read(buf);
            }
        }
    }
}
