//! A restore's custody read from the residence home in place of the folder
//! beside the backup (FIX 5846): the owner names the home, the restore's kit
//! fetches the head and frames of the backup's lineage from it, and the one
//! validator admits them as it admits the folder's. There is no implicit
//! network, and a fetch that fails fails the restore: the folder beside the
//! backup is never read in its place.

use std::path::Path;

use oneiron_crypto::backup::inspect_backup_tail;

use super::super::codec_error;
use super::CustodyRecovery;
use crate::Result;
use crate::store::custody_protocol::{
    CustodyNamespace, CustodyVaultId, FetchedCustodySource, Lineage,
};

impl CustodyRecovery<'_> {
    /// Read from `fetched`, the custody the residence home holds of the
    /// backup's lineage, in place of the folder beside the backup: a head or
    /// frame it lacks is missing, never read from the folder.
    pub fn fetched_from_home(mut self, fetched: FetchedCustodySource) -> Self {
        self.fetched = Some(fetched);
        self
    }

    /// The custody lineage the backup at `backup` names, as its commitment
    /// carries it: what a restore asks the residence home for. Read from the
    /// artifact's clear head and tail alone; `None` where the backup names no
    /// custody, whose restore reads no head anywhere. Nothing here is
    /// trusted: the restore admits only a head that covers what its opened
    /// image requires.
    ///
    /// # Errors
    ///
    /// A file that does not read, or is not a sealed artifact.
    pub fn lineage_of(backup: &Path) -> Result<Option<Lineage>> {
        let file = std::fs::File::open(backup)?;
        let tail = inspect_backup_tail(std::io::BufReader::new(file)).map_err(|_| codec_error())?;
        Ok(tail.commitment.custody_ref.map(|custody| Lineage {
            vault: CustodyVaultId::from_bytes(custody.vault),
            namespace: CustodyNamespace::from_bytes(custody.namespace),
        }))
    }
}
