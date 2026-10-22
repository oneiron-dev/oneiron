//! The supervisor pipes a driver reads to their end: a cold restore's C, its
//! credential frame (FIX 7078), and the custody anchor's owner credential
//! (FIX 9501). C is read once R has ended, and its frame is exactly 64 bytes
//! and then EOF ([`read_credentials`]), which a supervisor that never writes
//! or closes C never gives; the anchor's pipe is read to its EOF the same
//! way. Neither read has a deadline, so nothing ends that wait but the boot's
//! own end. Each read runs on a thread of its own that owns its pipe and
//! waits on it and on a private cancel pipe at once, with no timeout, and the
//! future awaiting the thread holds the cancel pipe's write end and the
//! thread's handle. Dropping that future, as a SIGTERM, a stop or the VMM's
//! exit does, closes the write end: the thread wakes, its reader wipes what
//! it read, the pipe closes on the thread's own side, and the drop joins the
//! thread before it returns. No other task ever closes the pipe.

use crate::managed::ManagedError;
use oneiron_vault_contract::{Credentials, read_credentials};
use std::fs::File;
use std::io::{ErrorKind, PipeReader, PipeWriter, Read};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::thread::JoinHandle;

/// C's credential frame, read and refused as a node's engine reads it, on a
/// thread that this future's drop wakes, ends and joins.
pub(super) async fn read_credential_frame(credentials: OwnedFd) -> anyhow::Result<Credentials> {
    read_cancellable(credentials, |reader| {
        read_credentials(reader).map_err(|error| {
            ManagedError::CredentialsRejected {
                reason: error.to_string(),
            }
            .into()
        })
    })
    .await
}

/// `read` over `pipe`, on a thread of its own that owns the pipe and reads
/// it only once it is ready: the future's drop ends the read and joins the
/// thread, which closes the pipe as it ends.
pub(super) async fn read_cancellable<T: Send + 'static>(
    pipe: OwnedFd,
    read: impl FnOnce(&mut Cancellable) -> anyhow::Result<T> + Send + 'static,
) -> anyhow::Result<T> {
    let (cancel, held) = std::io::pipe()?;
    let mut reader = Cancellable {
        source: File::from(pipe),
        cancel,
    };
    let (answer, answered) = tokio::sync::oneshot::channel();
    let thread = std::thread::Builder::new()
        .name("vm-pipe-read".into())
        .spawn(move || {
            let _ = answer.send(read(&mut reader));
            // `reader`, and the pipe it owns, close here on this thread.
        })?;
    let mut worker = Worker {
        held: Some(held),
        thread: Some(thread),
    };
    let read = answered.await;
    worker.join();
    read.map_err(|_| anyhow::anyhow!("a supervisor pipe's reader ended without an answer"))?
}

/// The reading thread and the cancel pipe's write end it waits on.
struct Worker {
    held: Option<PipeWriter>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    /// Closes the cancel pipe's write end, which wakes the thread if it
    /// still waits, and joins it.
    fn join(&mut self) {
        drop(self.held.take());
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::warn!(
                reason = "vm_pipe_reader_panicked",
                "a vault VM supervisor pipe's reader panicked"
            );
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.join();
    }
}

/// A supervisor pipe, read only once it is ready, and a cancellation once
/// the cancel pipe's write end is gone.
pub(super) struct Cancellable {
    source: File,
    /// Never written: an event on it is its write end closed.
    cancel: PipeReader,
}

impl Read for Cancellable {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut ready = [
            libc::pollfd {
                fd: self.source.as_raw_fd(),
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
            // Not `Interrupted`, which a frame's reader retries.
            if ready[1].revents != 0 {
                return Err(std::io::Error::other(
                    "the boot ended before the supervisor's pipe was read",
                ));
            }
            if ready[0].revents != 0 {
                return self.source.read(buf);
            }
        }
    }
}
