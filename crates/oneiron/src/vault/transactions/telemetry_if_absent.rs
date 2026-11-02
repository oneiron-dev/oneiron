//! A host's telemetry rows put only where none rests (FIX 10300, 9392): a
//! wire window's first call-volume question is kept once, read-if-absent in
//! one writer, as `observe` keeps it, on the same classed door the
//! telemetry batch takes, so a commit of telemetry alone moves no backup
//! watermark (FIX 6730).

use super::check_generic_sync_state_key;
use crate::Vault;
use crate::error::Result;
use crate::store::Callback;

impl Vault {
    /// Writes each of `rows` to `sync_state` in one write, each only when no
    /// row rests at its key: a row already there stays as it is. Classed as
    /// [`Self::sync_state_put_telemetry_batch`] classes its write: when every
    /// key is a host's telemetry the commit moves no backup watermark; any
    /// other key makes the whole write content. Refuses an undeclared key,
    /// as `sync_state_put` does. Returns how many rows it wrote.
    #[doc(hidden)]
    pub fn sync_state_put_telemetry_batch_if_absent(
        &self,
        rows: &[(&str, &[u8])],
    ) -> Result<usize> {
        for (key, _) in rows {
            check_generic_sync_state_key(key)?;
        }
        let class = crate::store::telemetry_batch_class(rows.iter().map(|(key, _)| *key));
        self.write_txn_door_classed(Callback::Audited, class, |wtxn| {
            let mut written = 0;
            for (key, value) in rows {
                if self.store.sync_state.get(wtxn, key)?.is_none() {
                    crate::side_table::host_sync_state_put(self, wtxn, key, value)?;
                    written += 1;
                }
            }
            Ok(written)
        })
    }
}
