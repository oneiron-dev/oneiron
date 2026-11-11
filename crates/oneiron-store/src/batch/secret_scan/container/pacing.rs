//! Scheduling data for one live container read. It grants no read authority.
use std::sync::Arc;

use super::{Stop, Walked};
use lopdf::{DecodeAdmission, DecodeAdmissionError};

/// A checkpoint before the native read continues. It contains no file bytes.
#[derive(Clone, Copy, Debug)]
pub enum ReadProgress {
    Container,
    Member,
    Pdf(lopdf::DecodeReadProgress),
    Allocation,
    Complete,
}

#[derive(Clone, Copy, Debug)]
pub struct ReadCancelled;

/// A live read's owner resumes this exact checkpoint, or drops the read.
/// Returning an error cancels; waiting here retains the native parse stack.
pub trait ReadPacer: Send + Sync {
    fn checkpoint(&self, at: ReadProgress) -> Result<(), ReadCancelled>;
}

/// Explicit per-operation scheduling; ordinary synchronous readers have none.
#[derive(Clone, Default)]
pub struct ReadPacing(Option<Arc<dyn ReadPacer>>);

impl ReadPacing {
    pub fn new(pacer: Arc<dyn ReadPacer>) -> Self {
        Self(Some(pacer))
    }

    pub fn checkpoint(&self, at: ReadProgress) -> Walked<()> {
        self.resume(at).map_err(|_| {
            Stop::Fail(
                std::io::Error::new(std::io::ErrorKind::Interrupted, "container read cancelled")
                    .into(),
            )
        })
    }

    fn resume(&self, at: ReadProgress) -> Result<(), ReadCancelled> {
        match &self.0 {
            Some(pacer) => pacer.checkpoint(at),
            None => Ok(()),
        }
    }

    pub fn decoder(&self) -> Option<Arc<dyn DecodeAdmission>> {
        self.0
            .as_ref()
            .map(|_| Arc::new(ScheduledDecode(self.clone())) as Arc<dyn DecodeAdmission>)
    }
}

struct ScheduledDecode(ReadPacing);

impl DecodeAdmission for ScheduledDecode {
    fn admit(&self, _bytes: usize) -> Result<(), DecodeAdmissionError> {
        self.0
            .resume(ReadProgress::Allocation)
            .map_err(|_| DecodeAdmissionError::Cancelled)
    }

    fn checkpoint(&self, at: lopdf::DecodeReadProgress) -> Result<(), DecodeAdmissionError> {
        self.0
            .resume(ReadProgress::Pdf(at))
            .map_err(|_| DecodeAdmissionError::Cancelled)
    }

    fn sequential(&self) -> bool {
        true
    }
}
