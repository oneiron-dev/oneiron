//! A restore's custody read from the residence home in place of the folder
//! beside the backup (FIX 5846): the owner names the home, the restore's kit
//! fetches the head and frames of the backup's lineage from it, from the
//! first frame admission may chain through (FIX 12045), and the one
//! validator admits them as it admits the folder's. There is no implicit
//! network, and a fetch that fails fails the restore: the folder beside the
//! backup is never read in its place.

use std::path::Path;

use oneiron_crypto::backup::inspect_backup_tail;

use super::super::codec_error;
use super::CustodyRecovery;
use crate::Result;
use crate::store::custody_protocol::{
    CustodyNamespace, CustodyVaultId, FetchedCustodySource, Lineage, anchored_position,
};

impl CustodyRecovery<'_> {
    /// Read from `fetched`, the custody the residence home holds of the
    /// backup's lineage, in place of the folder beside the backup: a head or
    /// frame it lacks is missing, never read from the folder.
    pub fn fetched_from_home(mut self, fetched: FetchedCustodySource) -> Self {
        self.fetched = Some(fetched);
        self
    }

    /// What a restore of the backup at `backup` asks the residence home for:
    /// the custody lineage its commitment names, and the first log frame
    /// admission may chain through (FIX 12045). That is the frame after the
    /// backup's custody position, or after the configured anchor's where
    /// the anchor is older; the home starts there, or right after its head
    /// where that is earlier, so a frame it lacks before them ends no scan.
    /// 1, the whole log, where the anchor holds no record that reads: the
    /// restore then refuses on its own read of it. Read from the artifact's
    /// clear head and tail and the anchor's record alone; `None` where the
    /// backup names no custody, whose restore reads no head anywhere.
    /// Nothing here is trusted: the restore checks the anchor's record and
    /// admits only a head that covers what its opened image requires.
    ///
    /// # Errors
    ///
    /// A file that does not read, or is not a sealed artifact.
    pub fn custody_wanted(&self, backup: &Path) -> Result<Option<(Lineage, u64)>> {
        let file = std::fs::File::open(backup)?;
        let tail = inspect_backup_tail(std::io::BufReader::new(file)).map_err(|_| codec_error())?;
        let Some(custody) = tail.commitment.custody_ref else {
            return Ok(None);
        };
        let lineage = Lineage {
            vault: CustodyVaultId::from_bytes(custody.vault),
            namespace: CustodyNamespace::from_bytes(custody.namespace),
        };
        let chained_from = match self.anchor() {
            None => Some(custody.seq),
            Some(anchor) => anchor
                .read(lineage.vault, lineage.namespace)
                .ok()
                .flatten()
                .and_then(|record| anchored_position(&record).ok())
                .map(|anchored| anchored.seq.min(custody.seq)),
        };
        let from_seq = chained_from.map_or(1, |seq| seq.saturating_add(1));
        Ok(Some((lineage, from_seq)))
    }
}
