//! FIX 10100: a package's files are read to the last one, however many it
//! holds. The work goes on in 1,000-file steps under the deadline its host
//! already holds; no count of files refuses it.
use std::time::Instant;

use super::package_codec::invalid;
use crate::error::Result;

/// How many files are read between two looks at the host's deadline.
const FILES_PER_STEP: usize = 1000;

/// The files read so far by one package read, and the deadline its host
/// gave the whole read.
pub(super) struct PackageFileProgress {
    deadline: Instant,
    files: usize,
}

impl PackageFileProgress {
    pub(super) const fn new(deadline: Instant) -> Self {
        Self { deadline, files: 0 }
    }

    /// One more file read. At the end of each 1,000-file step the host's
    /// deadline is read: past it, the read stops as its host stops it.
    pub(super) fn file(&mut self) -> Result<()> {
        self.files += 1;
        if self.files % FILES_PER_STEP == 0 && Instant::now() >= self.deadline {
            return Err(invalid("package fetch deadline exceeded"));
        }
        Ok(())
    }
}
