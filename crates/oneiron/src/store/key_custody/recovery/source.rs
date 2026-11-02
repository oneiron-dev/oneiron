//! Which source a restore reads its custody from (FIX 5846): the head and
//! frames fetched from the residence home when the owner named one, else
//! the folder beside the backup. A fetched source stands alone: a head or
//! frame it lacks is missing, and the folder is never read in its place.

use crate::error::Result;

use super::super::folder::FolderTarget;
use super::super::protocol::{CustodySource, FetchedCustodySource, Lineage};
use super::CustodySourceAt;

/// The source a restore reads, as [`CustodySourceAt::reader`] picks it.
pub(super) enum CustodyReader<'a> {
    Folder(FolderTarget),
    Fetched(&'a FetchedCustodySource),
}

impl CustodySourceAt<'_> {
    /// Where the restore reads the head and its frames: the residence home's
    /// fetch when given, else the folder beside the backup.
    pub(super) fn reader(&self) -> CustodyReader<'_> {
        match self.fetched {
            Some(fetched) => CustodyReader::Fetched(fetched),
            None => CustodyReader::Folder(FolderTarget::at(self.folder.to_path_buf())),
        }
    }
}

impl CustodySource for CustodyReader<'_> {
    fn head(&self, lineage: Lineage) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Folder(folder) => folder.head(lineage),
            Self::Fetched(fetched) => fetched.head(lineage),
        }
    }

    fn frame(&self, lineage: Lineage, seq: u64) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Folder(folder) => folder.frame(lineage, seq),
            Self::Fetched(fetched) => fetched.frame(lineage, seq),
        }
    }
}
