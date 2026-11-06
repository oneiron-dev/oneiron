//! The original signed-history export in the caller's read snapshot.

use super::*;

impl Vault {
    pub(crate) fn export_signed_authority_history_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<Vec<u8>>> {
        let mut history = history_in_txn(self, txn)?;
        if let Some(adopted) =
            crate::authority::checkpoint_adopt::cached_adopted_authority_checkpoint_in_txn(
                &self.store,
                txn,
            )?
            && let Some(refusal) = unheld_prefix(adopted.as_ref(), &history)
        {
            return Err(refusal);
        }
        history_root(&history, None)?;
        let mut emitted = BTreeSet::new();
        let mut result = Vec::with_capacity(history.len());
        while !history.is_empty() {
            let Some(hash) = history.iter().find_map(|(hash, (_, entry))| {
                entry
                    .parent_hashes
                    .iter()
                    .all(|parent| emitted.contains(parent))
                    .then_some(*hash)
            }) else {
                return Err(invalid_authority());
            };
            let (bytes, _) = history
                .remove(&hash)
                .ok_or(Error::InvariantViolation("authority export order"))?;
            emitted.insert(hash);
            result.push(bytes);
        }
        Ok(result)
    }
}
