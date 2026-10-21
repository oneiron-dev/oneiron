//! Write-once executor identity for a skill-bearing attempt's terminal receipt.

use super::validate::{validate_lease_owner, validate_planned_binding, validate_transition_lease};
use super::{AttemptId, AttemptQueue, AttemptRecord, AttemptState, PlannedBinding, decode_record};
use crate::error::{Error, Result};
use crate::llm::manifest::ModelRole;

impl AttemptQueue<'_> {
    /// Binds the placed task type and team context, and appends actual-use
    /// witnesses under the same live-lease fence as a skill load. The terminal
    /// transaction freezes this context beside the accumulated pack manifest.
    pub fn set_pack_attribution(
        &self,
        id: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
        fields: &crate::receipt::PackAttributionFields,
    ) -> Result<AttemptRecord> {
        fields.validate()?;
        let mut txn = self.store.env.write_txn()?;
        self.require_skill_load_lease_in_txn(&txn, id, lease_owner, attempt_count)?;
        let record = self.set_executor_model_in_txn(
            &mut txn,
            id,
            lease_owner,
            attempt_count,
            &fields.executor,
        )?;
        crate::receipt::put_attempt_pack_attribution_in_txn(self.store, &mut txn, id, fields)?;
        txn.commit()?;
        Ok(record)
    }

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

    /// Stamps what executes this attempt (OF-541): the model its run was
    /// born on and, beside it, the template seat its host configured and the
    /// functional role it runs as (OF-578), in one write. Each part is
    /// write-once, as `set_executor_model` is: repeating the stamp is safe,
    /// swapping any part is not.
    pub fn set_executor_stamp(
        &self,
        id: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
        model: &str,
        seat: &str,
        role: ModelRole,
    ) -> Result<AttemptRecord> {
        if !valid_executor_id(model) || !valid_executor_id(seat) {
            return Err(Error::InvalidConfig(
                "invalid attempt executor stamp".to_owned(),
            ));
        }
        let mut txn = self.store.env.write_txn()?;
        let raw = self
            .store
            .attempt_records
            .get(&txn, id.as_bytes())?
            .ok_or(Error::InvalidConfig("unknown attempt".to_owned()))?;
        let mut record = decode_record(&raw, id)?;
        if record
            .executor_model
            .as_deref()
            .is_some_and(|stamped| stamped != model)
            || record
                .executor_seat
                .as_deref()
                .is_some_and(|stamped| stamped != seat)
            || record.executor_role.is_some_and(|stamped| stamped != role)
        {
            return Err(Error::InvalidConfig(
                "executor model cannot be rebound".to_owned(),
            ));
        }
        if record.executor_model.is_some()
            && record.executor_seat.is_some()
            && record.executor_role.is_some()
        {
            if matches!(record.state, AttemptState::Leased | AttemptState::Landing) {
                validate_lease_owner(lease_owner)?;
                validate_transition_lease(
                    &record,
                    lease_owner,
                    attempt_count,
                    "set_executor_stamp",
                )?;
            }
            return Ok(record);
        }
        if record.state != AttemptState::Leased {
            return Err(Error::InvalidConfig(
                "executor model requires a live lease".to_owned(),
            ));
        }
        validate_lease_owner(lease_owner)?;
        validate_transition_lease(&record, lease_owner, attempt_count, "set_executor_stamp")?;
        record.executor_model = Some(model.to_owned());
        record.executor_seat = Some(seat.to_owned());
        record.executor_role = Some(role);
        let encoded = self.encode_in_txn(&mut txn, &mut record)?;
        self.store
            .attempt_records
            .put(&mut txn, id.as_bytes(), &encoded)?;
        txn.commit()?;
        Ok(record)
    }

    /// The load door may only append bytes while this lease is live, even if
    /// the same model has already been stamped on the attempt.
    pub(crate) fn require_skill_load_lease_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
    ) -> Result<()> {
        let raw = self
            .store
            .attempt_records
            .get(txn, id.as_bytes())?
            .ok_or(Error::InvalidConfig("unknown attempt".to_owned()))?;
        let record = decode_record(&raw, id)?;
        if !matches!(record.state, AttemptState::Leased | AttemptState::Landing) {
            return Err(Error::InvalidConfig(
                "skill load requires a live execution lease".to_owned(),
            ));
        }
        validate_lease_owner(lease_owner)?;
        validate_transition_lease(&record, lease_owner, attempt_count, "load_attempt_skill")
    }

    pub(crate) fn set_executor_model_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
        model: &str,
    ) -> Result<AttemptRecord> {
        self.stamp_model_in_txn(txn, id, lease_owner, attempt_count, model, None)
    }

    /// Freezes a seatless planned child's binding (FIX 7720) in one write
    /// with the executor model it runs, under `leased`'s live lease, before
    /// any pack load stamps that model. Write-once: a row that already holds
    /// a binding answers as it stands, the first binding kept, so the caller
    /// runs what the row holds; a model already stamped otherwise cannot be
    /// rebound.
    pub fn bind_planned_executor(
        &self,
        leased: &AttemptRecord,
        model: &str,
        binding: &PlannedBinding,
    ) -> Result<AttemptRecord> {
        let lease_owner = leased.lease_owner.as_deref().ok_or(Error::InvalidConfig(
            "executor model requires a live lease".to_owned(),
        ))?;
        let mut txn = self.store.env.write_txn()?;
        let record = self.stamp_model_in_txn(
            &mut txn,
            leased.id,
            lease_owner,
            leased.attempt_count,
            model,
            Some(binding),
        )?;
        txn.commit()?;
        Ok(record)
    }

    /// The write-once, lease-fenced executor model stamp, and with
    /// `binding` the planned binding written beside it in the same write.
    /// A settled row (the same model stamped, or with `binding` a binding
    /// already held) answers as it stands, fenced while its lease is live.
    fn stamp_model_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
        model: &str,
        binding: Option<&PlannedBinding>,
    ) -> Result<AttemptRecord> {
        if !valid_executor_id(model) {
            return Err(Error::InvalidConfig(
                "invalid attempt executor model".to_owned(),
            ));
        }
        let action = match binding {
            Some(_) => "bind_planned_executor",
            None => "set_executor_model",
        };
        let raw = self
            .store
            .attempt_records
            .get(txn, id.as_bytes())?
            .ok_or(Error::InvalidConfig("unknown attempt".to_owned()))?;
        let mut record = decode_record(&raw, id)?;
        let stamped = record.executor_model.as_deref() == Some(model);
        let settled = match binding {
            Some(_) => record.planned_binding.is_some(),
            None => stamped,
        };
        if settled {
            if matches!(record.state, AttemptState::Leased | AttemptState::Landing) {
                validate_lease_owner(lease_owner)?;
                validate_transition_lease(&record, lease_owner, attempt_count, action)?;
            }
            return Ok(record);
        }
        if !stamped && record.executor_model.is_some() {
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
        validate_transition_lease(&record, lease_owner, attempt_count, action)?;
        record.executor_model = Some(model.to_owned());
        if let Some(binding) = binding {
            record.planned_binding = Some(binding.clone());
        }
        validate_planned_binding(&record)?;
        let encoded = self.encode_in_txn(txn, &mut record)?;
        self.store
            .attempt_records
            .put(txn, id.as_bytes(), &encoded)?;
        Ok(record)
    }
}

/// An executor stamp's shape: `id@revision`, at most 256 bytes, with no
/// control characters.
fn valid_executor_id(value: &str) -> bool {
    value.len() <= 256
        && !value.chars().any(char::is_control)
        && value
            .rsplit_once('@')
            .is_some_and(|(id, revision)| !id.is_empty() && !revision.is_empty())
}
