//! A target clone its vendor holds until the voice is verified there (FIX
//! 1567): an ElevenLabs voice that answers `requires_verification` is
//! recorded as awaiting verification, not as a finished clone, and is
//! recorded verified once the vendor says it is.
use super::{TARGETS, VoiceTargetRecord, read_row, target_key};
use crate::Vault;
use crate::error::Result;

/// The provider voice a clone call made, as the bank records it.
#[derive(Debug, Clone, Copy)]
pub(super) struct VendorClone<'a> {
    pub(super) id: &'a str,
    pub(super) awaiting_verification: bool,
}

impl Vault {
    /// Records `target`'s clone of `voice_id` as verified at its vendor,
    /// while the record is still the one at `revision`: one replaced, dropped
    /// or verified meanwhile is left as it is. The record as it stands after;
    /// none when the target holds none.
    pub fn record_voice_target_verified(
        &self,
        voice_id: &str,
        target: &str,
        revision: [u8; 16],
    ) -> Result<Option<VoiceTargetRecord>> {
        let key = target_key(voice_id, target)?;
        let mut txn = self.store.env.write_txn()?;
        let Some(mut record) = read_row(
            TARGETS,
            &self.store,
            &txn,
            &key,
            "corrupt voice target clone",
        )?
        else {
            return Ok(None);
        };
        if record.revision != revision || !record.awaiting_verification {
            return Ok(Some(record));
        }
        record.awaiting_verification = false;
        TARGETS.put(&self.store, &mut txn, &key, &record)?;
        txn.commit()?;
        Ok(Some(record))
    }
}
