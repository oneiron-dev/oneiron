//! An official seat run's output drains: each pipe spooled on its own
//! thread under the disk floor and the run's deadline, and watched without
//! waiting while the child runs (FIX 5152).
use std::io::Read;
use std::sync::{Arc, mpsc};
use std::time::Instant;

use oneiron::dispatch_byoa::{ByoaError, ByoaResult, ByoaStream};
use oneiron::origin::smart_http::SpillFloor;

/// Drains every byte `reader` yields into a spooled stream on its own thread.
/// The disk floor and the run's deadline are its only stops; a read failure
/// is an error, never an early end of the stream.
pub(super) fn drain_spooled(
    mut reader: impl Read + Send + 'static,
    floor: Option<Arc<dyn SpillFloor>>,
    deadline: Instant,
) -> mpsc::Receiver<ByoaResult<ByoaStream>> {
    let (done, drain) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut stream = ByoaStream::writer(floor, Some(deadline));
        let mut chunk = [0_u8; 8192];
        let spooled = loop {
            match reader.read(&mut chunk) {
                Ok(0) => break stream.finish(),
                Ok(read) => {
                    if let Err(error) = stream.append(&chunk[..read]) {
                        break Err(error);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    break Err(ByoaError::Backend(
                        "official seat output read failed".to_owned(),
                    ));
                }
            }
        };
        let _ = done.send(spooled);
    });
    drain
}

/// One drain, read without waiting while its child runs (FIX 5152): a
/// drain that stopped early, at the disk floor say, is seen at once, and a
/// stream that ended is kept for after the child exits.
pub(super) struct Drain {
    receiver: mpsc::Receiver<ByoaResult<ByoaStream>>,
    ended: Option<ByoaResult<ByoaStream>>,
}

impl Drain {
    pub(super) fn new(receiver: mpsc::Receiver<ByoaResult<ByoaStream>>) -> Self {
        Self {
            receiver,
            ended: None,
        }
    }

    /// The drain's failure, once it stopped with one; it is taken, so the
    /// run reports it once.
    pub(super) fn failure(&mut self) -> Option<ByoaError> {
        if self.ended.is_none() {
            self.ended = self.receiver.try_recv().ok();
        }
        match self.ended.take() {
            Some(Err(error)) => Some(error),
            ended => {
                self.ended = ended;
                None
            }
        }
    }

    /// The drain's stream, waited for no later than the run's deadline.
    pub(super) fn stream(self, deadline: Instant) -> ByoaResult<ByoaStream> {
        match self.ended {
            Some(ended) => ended,
            None => drained(&self.receiver, deadline),
        }
    }
}

/// A drain's stream, waited for no later than the run's deadline.
fn drained(
    drain: &mpsc::Receiver<ByoaResult<ByoaStream>>,
    deadline: Instant,
) -> ByoaResult<ByoaStream> {
    drain
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .unwrap_or_else(|error| {
            Err(match error {
                mpsc::RecvTimeoutError::Timeout => ByoaError::SpoolDeadline,
                mpsc::RecvTimeoutError::Disconnected => {
                    ByoaError::Backend("official seat output drain stopped".to_owned())
                }
            })
        })
}
