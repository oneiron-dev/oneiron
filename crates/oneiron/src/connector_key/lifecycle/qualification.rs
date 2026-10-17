//! Qualification is a vault door: callers cannot submit a self-graded report.
use crate::Vault;
use crate::connector_key::qualification::{
    ConnectorQualificationReceipt, GroundingOracle, QualificationConnector, QualificationFailure,
    QualificationPlan, QualificationReport, qualify_connector_with_schemas,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::super::record::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeyRecord, ConnectorKeyStatus, invalid_body,
};
use super::super::slate::{
    bind_connector_slate_in_txn, read_connector_slate_in_txn, slate_expands,
};
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
    /// Its per-grant keys are held until then.
    pub fn revise_connector_protocol(
        &self,
        id: &EntityId,
        revision: &str,
        next_slate_ref: EntityId,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        self.revise_connector_admission(id, Some(revision), next_slate_ref, at)
    }

    /// A capability change at the same protocol revision: the connector's
    /// tools or schemas changed, so `next_slate_ref` (a delta slate) replaces
    /// its slate. Like a revision change, it halts the route until the owner
    /// stamps the new slate (when it expands) and a fresh suite passes.
    pub fn revise_connector_slate(
        &self,
        id: &EntityId,
        next_slate_ref: EntityId,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        self.revise_connector_admission(id, None, next_slate_ref, at)
    }

    /// `revision`: the new protocol revision; `None` keeps the pinned one and
    /// requires a different slate.
    fn revise_connector_admission(
        &self,
        id: &EntityId,
        revision: Option<&str>,
        next_slate_ref: EntityId,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        let (unchanged, op) = match revision {
            Some(revision) => (
                record.protocol_revision.as_deref() == Some(revision),
                "gate.connector_key.revise_protocol",
            ),
            None => (
                record.protocol_revision.is_none() || record.slate_ref == Some(next_slate_ref),
                "gate.connector_key.revise_slate",
            ),
        };
        if record.catalog.is_none() || record.status == ConnectorKeyStatus::Revoked || unchanged {
            return Err(invalid_body("invalid connector protocol change"));
        }
        let revision = match revision {
            Some(revision) => revision.to_owned(),
            None => record
                .protocol_revision
                .clone()
                .ok_or_else(|| invalid_body("invalid connector protocol change"))?,
        };
        let old_slate_id = record
            .slate_ref
            .ok_or_else(|| invalid_body("connector slate missing"))?;
        let old_slate = read_connector_slate_in_txn(self, &wtxn, old_slate_id)?
            .ok_or_else(|| invalid_body("connector slate missing"))?;
        let next_slate = read_connector_slate_in_txn(self, &wtxn, next_slate_ref)?
            .ok_or_else(|| invalid_body("connector replacement slate missing"))?;
        // A pending, not-yet-consented expansion cannot be washed away by
        // another revision that makes no further expansion.
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        let expanded = record.consent_required
            || slate_expands(&old_slate, &next_slate, &policy.connector_class_carry());
        if next_slate_ref != old_slate_id {
            bind_connector_slate_in_txn(self, &mut wtxn, next_slate_ref, id)?;
        }
        let admission_epoch = record
            .admission_epoch
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("connector admission epoch"))?;
        let pending = ConnectorKeyRecord {
            status: ConnectorKeyStatus::Pending,
            status_changed_at: Some(at),
            suspended_reason: None,
            protocol_revision: Some(revision),
            slate_ref: Some(next_slate_ref),
            admission_epoch,
            consent_required: expanded,
            qualification_receipt: None,
            ..record
        };
        pending.validate()?;
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &pending)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            op,
            &pending,
            policy.read_frontier_hash()?,
            at,
        )?;
        self.sync_derived_keys_in_txn(&mut wtxn, &pending, at)?;
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
        let (expected_slate_id, stamped_revision, manifest_hash, admission_epoch, schemas) = {
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
            if record.consent_required
                && (slate.owner_actor().is_none() || slate.revision() == 0 || !slate.stamp_holds())
            {
                return Err(invalid_body("connector slate not consented for qualification").into());
            }
            (
                slate_id,
                slate.revision(),
                slate.manifest_hash(),
                record.admission_epoch,
                slate
                    .resolved_schemas()
                    .ok_or_else(|| invalid_body("resolved connector schemas required"))?,
            )
        };
        let report = qualify_connector_with_schemas(connector, plan, oracle, Some(&schemas))?;
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status != ConnectorKeyStatus::Pending
            || record.protocol_revision.as_deref() != Some(expected_revision)
        {
            return Err(invalid_body("connector changed during qualification").into());
        }
        if record.slate_ref != Some(expected_slate_id) || record.admission_epoch != admission_epoch
        {
            return Err(invalid_body("connector slate changed during qualification").into());
        }
        let slate = read_connector_slate_in_txn(self, &wtxn, expected_slate_id)?
            .ok_or_else(|| invalid_body("connector slate missing"))?;
        if record.consent_required
            && (slate.owner_actor().is_none() || slate.revision() == 0 || !slate.stamp_holds())
            || slate.revision() != stamped_revision
            || slate.manifest_hash() != manifest_hash
            || slate.tool_names() != report.tools.iter().map(|tool| tool.name.as_str()).collect()
        {
            return Err(invalid_body("connector slate changed during qualification").into());
        }
        // A scoped-MCP catalog advertises the tools its qualified slate
        // lists, so a refresh's new tools reach search, describe and routing.
        let catalog = record.catalog.clone().map(|entry| match entry.call_class {
            ConnectorCallClass::ScopedMcp => ConnectorCatalogEntry {
                verbs: slate
                    .manifest()
                    .iter()
                    .map(|tool| tool.name.clone())
                    .collect(),
                ..entry
            },
            _ => entry,
        });
        let active = ConnectorKeyRecord {
            catalog,
            qualification_receipt: Some(ConnectorQualificationReceipt::new(
                report.report_hash.clone(),
                expected_revision.to_owned(),
                manifest_hash,
                at,
            )?),
            status: ConnectorKeyStatus::Active,
            status_changed_at: Some(at),
            slate_revision: Some(slate.revision()),
            consent_required: false,
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
        self.sync_derived_keys_in_txn(&mut wtxn, &active, at)?;
        wtxn.commit().map_err(Error::from)?;
        Ok((active, report))
    }

    /// The owner restamped an admitted catalog connector's slate: new
    /// settings or a new facet limit on the same tools. A stamp never changes
    /// the slate's tools and the suite never read the settings, so the key
    /// accepts the new stamp without a new suite. Its per-grant keys carry or
    /// retire against it; a row now `never allow` retires its grants.
    pub fn adopt_connector_slate_stamp(
        &self,
        id: &EntityId,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.catalog.is_none()
            || !matches!(
                record.status,
                ConnectorKeyStatus::Active | ConnectorKeyStatus::Suspended
            )
            || record.qualification_receipt.is_none()
        {
            return Err(invalid_body("connector not admitted"));
        }
        let slate_id = record
            .slate_ref
            .ok_or_else(|| invalid_body("connector slate missing"))?;
        let slate = read_connector_slate_in_txn(self, &wtxn, slate_id)?
            .ok_or_else(|| invalid_body("connector slate missing"))?;
        if slate.owner_actor().is_none()
            || !slate.stamp_holds()
            || record
                .slate_revision
                .is_some_and(|accepted| slate.revision() <= accepted)
        {
            return Err(invalid_body("connector slate has no newer owner stamp"));
        }
        let adopted = ConnectorKeyRecord {
            slate_revision: Some(slate.revision()),
            ..record
        };
        adopted.validate()?;
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &adopted)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.restamp",
            &adopted,
            policy.read_frontier_hash()?,
            at,
        )?;
        self.sync_derived_keys_in_txn(&mut wtxn, &adopted, at)?;
        wtxn.commit()?;
        Ok(adopted)
    }
}
