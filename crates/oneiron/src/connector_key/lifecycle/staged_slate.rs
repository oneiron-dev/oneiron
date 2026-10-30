//! A same-revision refresh that expands an admitted catalog key's slate is
//! staged beside the slate the key routes on (FIX 11677). The key keeps
//! routing on its admitted rows; the staged slate replaces them only once
//! the owner stamps it and a fresh full suite passes on it, or once the
//! owner attests it in place of the suite. Another refresh restages it, and
//! one that reaches no further than the routing slate drops it.
use crate::Vault;
use crate::connector_key::qualification::{
    ConnectorQualificationReceipt, GroundingOracle, OWNER_ATTESTED_QUALIFICATION_SUITE,
    QualificationConnector, QualificationPlan, QualificationReport, qualify_connector_with_schemas,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::super::record::{ConnectorKeyRecord, ConnectorKeyStatus, invalid_body};
use super::super::slate::{
    ConnectorGrantSlate, bind_connector_slate_in_txn, read_connector_slate_in_txn,
};
use super::super::txn::{
    append_connector_key_op_record, read_connector_key_in_txn, rewrite_connector_key_in_txn,
};
use super::qualification::{
    ConnectorQualificationError, require_pack_qualification, slate_catalog,
};

/// Whether an expansion of `record`'s slate `routing` stages beside it: the
/// key is admitted (qualified, its manifest approved, no consent owed) and
/// its slate names no pack install. A pack-bound key follows its install,
/// and the pack connector doors stamp and qualify the slate it routes on.
pub(super) fn stages_beside(record: &ConnectorKeyRecord, routing: &ConnectorGrantSlate) -> bool {
    matches!(
        record.status,
        ConnectorKeyStatus::Active | ConnectorKeyStatus::Suspended
    ) && record.catalog.is_some()
        && !record.consent_required
        && record.qualification_receipt.is_some()
        && record.retained_manifest.is_some()
        && routing.slate_manifest().pack_source.is_none()
}

impl Vault {
    /// Stages `next_slate_ref`, an expansion of admitted key `id`'s slate at
    /// its pinned revision, beside the slate it routes on, in the caller's
    /// writer. Nothing the key routes on moves, and its per-grant keys stay
    /// as they are.
    pub(super) fn stage_connector_slate_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: ConnectorKeyRecord,
        next_slate_ref: EntityId,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        if record.staged_slate_ref != Some(next_slate_ref) {
            bind_connector_slate_in_txn(self, wtxn, next_slate_ref, id)?;
        }
        let staged = ConnectorKeyRecord {
            staged_slate_ref: Some(next_slate_ref),
            ..record
        };
        staged.validate()?;
        rewrite_connector_key_in_txn(&self.store, wtxn, id, &staged)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, wtxn)?;
        append_connector_key_op_record(
            &self.store,
            wtxn,
            id,
            "gate.connector_key.stage_slate",
            &staged,
            policy.read_frontier_hash()?,
            at,
        )?;
        Ok(staged)
    }

    /// Runs all ARCH-0028 probes on the slate staged beside admitted key
    /// `id` at `expected_revision`, under the owner's current stamp on it.
    /// A pass swaps it in: the key routes on the staged slate, with its new
    /// rows, under the receipt this run earned. The key and the staged slate
    /// are re-read after the probes, so a restage or a restamp during the
    /// run swaps nothing.
    pub fn qualify_staged_connector_slate(
        &self,
        id: &EntityId,
        expected_revision: &str,
        connector: &dyn QualificationConnector,
        plan: &QualificationPlan,
        oracle: &dyn GroundingOracle,
        at: u64,
    ) -> std::result::Result<(ConnectorKeyRecord, QualificationReport), ConnectorQualificationError>
    {
        let (staged_id, stamped_revision, manifest_hash, schemas) = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            let (_, staged_id, staged) =
                self.stamped_staged_slate_in_txn(&txn, id, expected_revision)?;
            (
                staged_id,
                staged.revision(),
                staged.manifest_hash(),
                staged
                    .resolved_schemas()
                    .ok_or_else(|| invalid_body("resolved connector schemas required"))?,
            )
        };
        let report = qualify_connector_with_schemas(connector, plan, oracle, Some(&schemas))?;
        let mut wtxn = self.store.env.write_txn()?;
        let (record, current_id, staged) =
            self.stamped_staged_slate_in_txn(&wtxn, id, expected_revision)?;
        if current_id != staged_id
            || staged.revision() != stamped_revision
            || staged.manifest_hash() != manifest_hash
            || staged.tool_names() != report.tools.iter().map(|tool| tool.name.as_str()).collect()
        {
            return Err(invalid_body("connector staged slate changed during qualification").into());
        }
        let receipt = ConnectorQualificationReceipt::new(
            report.report_hash.clone(),
            expected_revision.to_owned(),
            manifest_hash,
            at,
        )?;
        let swapped = self.swap_staged_slate_in_txn(
            &mut wtxn,
            id,
            record,
            (staged_id, &staged),
            receipt,
            "gate.connector_key.qualify_staged",
            at,
        )?;
        wtxn.commit().map_err(Error::from)?;
        self.measure_connector_key_shape(&swapped);
        Ok((swapped, report))
    }

    /// CONNECTOR-QUALIFY = A on a staged slate: the owner attests the slate
    /// staged beside admitted key `id` in place of the suite, as
    /// [`Self::attest_connector_key`] attests a pending key, and it swaps in
    /// under an owner-attested receipt. His current stamp on it stands as
    /// the condition.
    pub fn attest_staged_connector_slate(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        expected_revision: &str,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &wtxn)?;
        crate::memory::verify_deletion_authority_in_txn(
            self,
            &wtxn,
            actor,
            crate::edge::EdgeActorClass::Human,
        )
        .map_err(|_| invalid_body("connector attestation needs the owner"))?;
        let (record, staged_id, staged) =
            self.stamped_staged_slate_in_txn(&wtxn, id, expected_revision)?;
        let mut digest = blake3::Hasher::new();
        digest.update(OWNER_ATTESTED_QUALIFICATION_SUITE.as_bytes());
        digest.update(owner.decision_id().to_hex().as_bytes());
        digest.update(&staged.manifest_hash());
        digest.update(&staged.grant_hash());
        let receipt = ConnectorQualificationReceipt::owner_attested(
            digest.finalize().to_hex().to_string(),
            expected_revision.to_owned(),
            staged.manifest_hash(),
            at,
        )?;
        let swapped = self.swap_staged_slate_in_txn(
            &mut wtxn,
            id,
            record,
            (staged_id, &staged),
            receipt,
            "gate.connector_key.owner_attest_staged",
            at,
        )?;
        wtxn.commit()?;
        self.measure_connector_key_shape(&swapped);
        Ok(swapped)
    }

    /// Admitted key `id` at `expected_revision`, with the slate staged
    /// beside its routing one, when the owner's stamp on that slate holds.
    fn stamped_staged_slate_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        expected_revision: &str,
    ) -> Result<(ConnectorKeyRecord, EntityId, ConnectorGrantSlate)> {
        let record =
            read_connector_key_in_txn(&self.store, txn, id)?.ok_or(Error::EntityNotFound)?;
        if !matches!(
            record.status,
            ConnectorKeyStatus::Active | ConnectorKeyStatus::Suspended
        ) || record.catalog.is_none()
            || record.protocol_revision.as_deref() != Some(expected_revision)
        {
            return Err(invalid_body("connector not admitted at this revision"));
        }
        let staged_id = record
            .staged_slate_ref
            .ok_or_else(|| invalid_body("connector has no staged slate"))?;
        let staged = read_connector_slate_in_txn(self, txn, staged_id)?
            .ok_or_else(|| invalid_body("connector staged slate missing"))?;
        require_pack_qualification(self, txn, &record, &staged, expected_revision)?;
        if staged.owner_actor().is_none() || staged.revision() == 0 || !staged.stamp_holds() {
            return Err(invalid_body("connector staged slate not stamped"));
        }
        Ok((record, staged_id, staged))
    }

    /// `staged` (stored as `staged_id`) replaces the slate admitted key `id`
    /// routes on, under `receipt`. Its per-grant keys carry or retire
    /// against it.
    #[allow(clippy::too_many_arguments)]
    fn swap_staged_slate_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: ConnectorKeyRecord,
        (staged_id, staged): (EntityId, &ConnectorGrantSlate),
        receipt: ConnectorQualificationReceipt,
        op: &'static str,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        let admission_epoch = record
            .admission_epoch
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("connector admission epoch"))?;
        let swapped = ConnectorKeyRecord {
            catalog: slate_catalog(record.catalog.clone(), staged),
            slate_ref: Some(staged_id),
            slate_revision: Some(staged.revision()),
            staged_slate_ref: None,
            admission_epoch,
            qualification_receipt: Some(receipt),
            ..record
        };
        swapped.validate()?;
        rewrite_connector_key_in_txn(&self.store, wtxn, id, &swapped)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, wtxn)?;
        append_connector_key_op_record(
            &self.store,
            wtxn,
            id,
            op,
            &swapped,
            policy.read_frontier_hash()?,
            at,
        )?;
        self.sync_derived_keys_in_txn(wtxn, &swapped, at)?;
        Ok(swapped)
    }
}
