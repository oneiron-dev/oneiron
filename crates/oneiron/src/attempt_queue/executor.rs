//! Write-once executor identity for a skill-bearing attempt's terminal receipt.

use super::encoding::encode_record;
use super::validate::{validate_lease_owner, validate_transition_lease};
use super::{AttemptId, AttemptQueue, AttemptRecord, AttemptState, decode_record};
use crate::error::{Error, Result};

impl AttemptQueue<'_> {
    /// Stamps the model id and revision that execute this attempt before it closes.
    /// Repeating the same identity is safe; swapping it on an active or closed
    /// attempt is not. An absent stamp is unknown, never the current model.
    pub fn set_executor_model(
        &self,
        id: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
        model: &str,
    ) -> Result<AttemptRecord> {
        if model.len() > 256
            || model.chars().any(char::is_control)
            || !model
                .rsplit_once('@')
                .is_some_and(|(id, revision)| !id.is_empty() && !revision.is_empty())
        {
            return Err(Error::InvalidConfig(
                "invalid attempt executor model".to_owned(),
            ));
        }
        let mut txn = self.store.env.write_txn()?;
        let record =
            self.set_executor_model_in_txn(&mut txn, id, lease_owner, attempt_count, model)?;
        txn.commit()?;
        Ok(record)
    }

    pub(crate) fn set_executor_model_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
        model: &str,
    ) -> Result<AttemptRecord> {
        if model.len() > 256
            || model.chars().any(char::is_control)
            || !model
                .rsplit_once('@')
                .is_some_and(|(id, revision)| !id.is_empty() && !revision.is_empty())
        {
            return Err(Error::InvalidConfig(
                "invalid attempt executor model".to_owned(),
            ));
        }
        let raw = self
            .store
            .attempt_records
            .get(txn, id.as_bytes())?
            .ok_or(Error::InvalidConfig("unknown attempt".to_owned()))?;
        let mut record = decode_record(&raw, id)?;
        if record.executor_model.as_deref() == Some(model) {
            // An idempotent retry after terminal is read-only. During a live
            // run a stale worker must not reuse the stamp to load another skill.
            if record.state == AttemptState::Leased {
                validate_lease_owner(lease_owner)?;
                validate_transition_lease(
                    &record,
                    lease_owner,
                    attempt_count,
                    "set_executor_model",
                )?;
            }
            return Ok(record);
        }
        if record.executor_model.is_some() {
            return Err(Error::InvalidConfig(
                "executor model cannot be rebound".to_owned(),
            ));
        }
        if record.state != AttemptState::Leased {
            return Err(Error::InvalidConfig(
                "executor model requires a live lease".to_owned(),
            ));
        }
        validate_lease_owner(lease_owner)?;
        validate_transition_lease(&record, lease_owner, attempt_count, "set_executor_model")?;
        record.executor_model = Some(model.to_owned());
        self.store
            .attempt_records
            .put(txn, id.as_bytes(), &encode_record(&record)?)?;
        Ok(record)
    }
}
