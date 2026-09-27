//! Qualification is a vault door: callers cannot submit a self-graded report.
use crate::Vault;
use crate::connector_key::qualification::{
    GroundingOracle, QualificationConnector, QualificationFailure, QualificationPlan,
    QualificationReport, qualify_connector,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::super::record::{ConnectorKeyRecord, ConnectorKeyStatus, invalid_body};
use super::super::slate::read_connector_slate_in_txn;
use super::super::txn::{
    append_connector_key_op_record, read_connector_key_in_txn, rewrite_connector_key_in_txn,
};

#[derive(Debug, thiserror::Error)]
pub enum ConnectorQualificationError {
    #[error(transparent)]
    Probe(#[from] QualificationFailure),
    #[error(transparent)]
    Vault(#[from] Error),
}

impl Vault {
    /// A revision change halts the old route immediately. A new owner slate
    /// stamp and a fresh full suite are both required before it can reactivate.
    pub fn revise_connector_protocol(
        &self,
        id: &EntityId,
        revision: &str,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.catalog.is_none()
            || record.status == ConnectorKeyStatus::Revoked
            || record.protocol_revision.as_deref() == Some(revision)
        {
            return Err(invalid_body("invalid connector protocol change"));
        }
        let consent_floor = if let Some(slate_id) = record.slate_ref {
            read_connector_slate_in_txn(self, &wtxn, slate_id)?
                .map_or(record.slate_revision.unwrap_or(0), |slate| slate.revision())
                .max(record.slate_revision.unwrap_or(0))
        } else {
            record.slate_revision.unwrap_or(0)
        };
        let pending = ConnectorKeyRecord {
            status: ConnectorKeyStatus::Pending,
            status_changed_at: Some(at),
            suspended_reason: None,
            protocol_revision: Some(revision.to_owned()),
            slate_revision: Some(consent_floor),
            ..record
        };
        pending.validate()?;
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &pending)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.revise_protocol",
            &pending,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(pending)
    }

    /// Run all ARCH-0028 probes before attempting the atomic Pending -> Active
    /// flip. The record and owner slate are re-read after probes: a concurrent
    /// revision or re-stamp cannot activate a stale qualification.
    pub fn qualify_connector_key(
        &self,
        id: &EntityId,
        expected_revision: &str,
        connector: &dyn QualificationConnector,
        plan: &QualificationPlan,
        oracle: &dyn GroundingOracle,
        at: u64,
    ) -> std::result::Result<(ConnectorKeyRecord, QualificationReport), ConnectorQualificationError>
    {
        // A probe may make sandbox writes. Never start it without a bound,
        // freshly owner-stamped slate for this exact admission revision.
        let (expected_slate_id, stamped_revision, manifest_hash) = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            let record =
                read_connector_key_in_txn(&self.store, &txn, id)?.ok_or(Error::EntityNotFound)?;
            if record.status != ConnectorKeyStatus::Pending
                || record.protocol_revision.as_deref() != Some(expected_revision)
            {
                return Err(invalid_body("connector not pending at this revision").into());
            }
            let slate_id = record
                .slate_ref
                .ok_or_else(|| invalid_body("connector slate required"))?;
            let slate = read_connector_slate_in_txn(self, &txn, slate_id)?
                .ok_or_else(|| invalid_body("connector slate missing"))?;
            if slate.owner_actor().is_none()
                || slate.revision() <= record.slate_revision.unwrap_or(0)
            {
                return Err(invalid_body("connector slate not consented for qualification").into());
            }
            (slate_id, slate.revision(), slate.manifest_hash())
        };
        let report = qualify_connector(connector, plan, oracle)?;
        let mut wtxn = self.store.env.write_txn().map_err(Error::from)?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status != ConnectorKeyStatus::Pending
            || record.protocol_revision.as_deref() != Some(expected_revision)
        {
            return Err(invalid_body("connector changed during qualification").into());
        }
        if record.slate_ref != Some(expected_slate_id) {
            return Err(invalid_body("connector slate changed during qualification").into());
        }
        let slate = read_connector_slate_in_txn(self, &wtxn, expected_slate_id)?
            .ok_or_else(|| invalid_body("connector slate missing"))?;
        if slate.owner_actor().is_none()
            || slate.revision() != stamped_revision
            || slate.manifest_hash() != manifest_hash
            || slate.tool_names() != report.tools.iter().map(|tool| tool.name.as_str()).collect()
        {
            return Err(invalid_body("connector slate changed during qualification").into());
        }
        let active = ConnectorKeyRecord {
            status: ConnectorKeyStatus::Active,
            status_changed_at: Some(at),
            slate_revision: Some(slate.revision()),
            ..record
        };
        active.validate()?;
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &active)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.qualify",
            &active,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit().map_err(Error::from)?;
        Ok((active, report))
    }
}
