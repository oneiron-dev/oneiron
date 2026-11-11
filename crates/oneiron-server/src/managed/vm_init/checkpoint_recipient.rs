//! The provisioned public recipient's pipe into the managed engine.

use std::ffi::OsString;
use std::io::{PipeReader, Write as _};
use std::os::fd::{AsRawFd as _, RawFd};

use oneiron_vault_contract::checkpoint_recipient::CheckpointHostHoldsRecipient;

pub(super) struct RecipientPipe(PipeReader);

impl RecipientPipe {
    /// Only a usable public frame gets a pipe. Its writer is closed before
    /// exec, so the engine reads the complete object and EOF without a
    /// forwarding worker. Failure leaves the optional recipient missing.
    pub(super) fn prepare(wire: Option<&CheckpointHostHoldsRecipient>) -> Option<Self> {
        let wire = wire?;
        let prepared = (|| {
            crate::managed::checkpoint_recipient::decode(wire)?;
            let (read, mut write) =
                std::io::pipe().map_err(|_| "the public recipient pipe could not be created")?;
            let flags = rustix::fs::fcntl_getfl(&write)
                .map_err(|_| "the public recipient pipe flags did not read")?;
            rustix::fs::fcntl_setfl(&write, flags | rustix::fs::OFlags::NONBLOCK)
                .map_err(|_| "the public recipient pipe could not be made nonblocking")?;
            serde_json::to_writer(&mut write, wire)
                .map_err(|_| "the public recipient pipe did not take its complete object")?;
            write
                .flush()
                .map_err(|_| "the public recipient pipe did not flush")?;
            drop(write);
            Ok::<_, &'static str>(Self(read))
        })();
        match prepared {
            Ok(pipe) => Some(pipe),
            Err(reason) => {
                tracing::warn!(
                    reason,
                    "checkpoint host-order recipient unavailable; VM start continues"
                );
                None
            }
        }
    }

    pub(super) fn flags(&self) -> [OsString; 2] {
        [
            "--checkpoint-host-holds-recipient-fd".into(),
            self.0.as_raw_fd().to_string().into(),
        ]
    }

    /// All bootstrap pipes use their own still-open descriptor as the child
    /// target. Keeping this reader alive through spawn makes its number
    /// distinct from the anchor's and both restore pipes' live descriptors.
    pub(super) fn fds(&self) -> [(RawFd, RawFd); 1] {
        let fd = self.0.as_raw_fd();
        [(fd, fd)]
    }
}
