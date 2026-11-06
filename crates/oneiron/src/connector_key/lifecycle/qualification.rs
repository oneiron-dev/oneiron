//! Qualification is a vault door: callers cannot submit a self-graded report.
use crate::Vault;
use crate::connector_key::qualification::{
    ConnectorQualificationReceipt, GroundingOracle, OWNER_ATTESTED_QUALIFICATION_SUITE,
    QualificationConnector, QualificationFailure, QualificationPlan, QualificationReport,
    qualify_connector_with_schemas,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::super::record::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeyRecord, ConnectorKeyStatus, invalid_body,
};
use super::super::slate::{
    ConnectorGrantSlate, bind_connector_slate_in_txn, put_slate_in_txn,
    read_connector_slate_in_txn, slate_expands,
};
use super::super::txn::{
    append_connector_key_op_record, read_connector_key_in_txn, rewrite_connector_key_in_txn,
};
use super::staged_slate::stages_beside;

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
    /// its slate. One that reaches no further (unchanged and narrowed rows
    /// only) keeps an admitted key routing on it, under his stamp and the
    /// suite that qualified those rows (FIX 8681). One that expands is staged
    /// beside an admitted key's slate, which keeps routing until the owner
    /// stamps the new one and a fresh suite passes
    /// ([`Self::qualify_staged_connector_slate`], FIX 11677). On a key not
    /// yet admitted, an expansion halts the route, like a revision change,
    /// until both.
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
        let same_revision = revision.is_none();
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
        if old_slate.slate_manifest().pack_source.is_some()
            && next_slate.slate_manifest().pack_source.is_none()
        {
            return Err(invalid_body(
                "a connector pack update must retain its source binding",
            ));
        }
        // A pending, not-yet-consented expansion cannot be washed away by
        // another revision that makes no further expansion.
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        let expanded = record.consent_required
            || slate_expands(&old_slate, &next_slate, &policy.connector_class_carry());
        if same_revision && !expanded && next_slate_ref != old_slate_id {
            let receipt = record.qualification_receipt.clone();
            if let Some(carried) = self.carry_connector_slate_in_txn(
                &mut wtxn,
                id,
                &record,
                (&old_slate, next_slate, next_slate_ref),
                receipt,
                op,
                at,
            )? {
                wtxn.commit()?;
                return Ok(carried);
            }
        } else if same_revision
            && next_slate_ref != old_slate_id
            && stages_beside(&record, &old_slate)
        {
            let staged =
                self.stage_connector_slate_in_txn(&mut wtxn, id, record, next_slate_ref, at)?;
            wtxn.commit()?;
            return Ok(staged);
        }
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
            staged_slate_ref: None,
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
            require_pack_qualification(self, &txn, &record, &slate, expected_revision)?;
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
        require_pack_qualification(self, &wtxn, &record, &slate, expected_revision)?;
        if record.consent_required
            && (slate.owner_actor().is_none() || slate.revision() == 0 || !slate.stamp_holds())
            || slate.revision() != stamped_revision
            || slate.manifest_hash() != manifest_hash
            || slate.tool_names() != report.tools.iter().map(|tool| tool.name.as_str()).collect()
        {
            return Err(invalid_body("connector slate changed during qualification").into());
        }
        let catalog = slate_catalog(record.catalog.clone(), &slate);
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
        self.measure_connector_key_shape(&active);
        Ok((active, report))
    }

    /// CONNECTOR-QUALIFY = A (owner ruling 2026-10-30 05:52 JST): the owner
    /// attests a pending catalog connector the probe suite cannot grade, in
    /// place of [`Self::qualify_connector_key`]. The probes stay the default;
    /// only his authenticated act activates a key this way, and its receipt
    /// names that basis ([`OWNER_ATTESTED_QUALIFICATION_SUITE`]). Every other
    /// guard stands: his current stamp on the bound slate, its per-tool
    /// settings, a pack's qualification basis, and the call-time screens.
    pub fn attest_connector_key(
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
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status != ConnectorKeyStatus::Pending
            || record.catalog.is_none()
            || record.protocol_revision.as_deref() != Some(expected_revision)
        {
            return Err(invalid_body("connector not pending at this revision"));
        }
        let slate_id = record
            .slate_ref
            .ok_or_else(|| invalid_body("connector slate required"))?;
        let slate = read_connector_slate_in_txn(self, &wtxn, slate_id)?
            .ok_or_else(|| invalid_body("connector slate missing"))?;
        require_pack_qualification(self, &wtxn, &record, &slate, expected_revision)?;
        if slate.owner_actor().is_none() || slate.revision() == 0 || !slate.stamp_holds() {
            return Err(invalid_body("connector slate not stamped for attestation"));
        }
        let mut digest = blake3::Hasher::new();
        digest.update(OWNER_ATTESTED_QUALIFICATION_SUITE.as_bytes());
        digest.update(owner.decision_id().to_hex().as_bytes());
        digest.update(&slate.manifest_hash());
        digest.update(&slate.grant_hash());
        let active = ConnectorKeyRecord {
            catalog: slate_catalog(record.catalog.clone(), &slate),
            qualification_receipt: Some(ConnectorQualificationReceipt::owner_attested(
                digest.finalize().to_hex().to_string(),
                expected_revision.to_owned(),
                slate.manifest_hash(),
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
            "gate.connector_key.owner_attest",
            &active,
            policy.read_frontier_hash()?,
            at,
        )?;
        self.sync_derived_keys_in_txn(&mut wtxn, &active, at)?;
        wtxn.commit()?;
        self.measure_connector_key_shape(&active);
        Ok(active)
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
        let adopted = self.adopt_connector_slate_stamp_in_txn(&mut wtxn, id, at)?;
        wtxn.commit()?;
        Ok(adopted)
    }

    pub(in crate::connector_key) fn adopt_connector_slate_stamp_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        let record =
            read_connector_key_in_txn(&self.store, wtxn, id)?.ok_or(Error::EntityNotFound)?;
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
        let slate = read_connector_slate_in_txn(self, wtxn, slate_id)?
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
        rewrite_connector_key_in_txn(&self.store, wtxn, id, &adopted)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, wtxn)?;
        append_connector_key_op_record(
            &self.store,
            wtxn,
            id,
            "gate.connector_key.restamp",
            &adopted,
            policy.read_frontier_hash()?,
            at,
        )?;
        self.sync_derived_keys_in_txn(wtxn, &adopted, at)?;
        Ok(adopted)
    }

    /// An admitted catalog key `id` routes on `next` (its slate `prior`
    /// revised, stored as `next_id`) without a new suite, under the owner's
    /// stamp on `prior` carried to it, with `receipt` as its qualification.
    /// A slate staged beside `prior` drops: it was drafted against `prior`.
    /// `None`, with nothing written, when the key is not admitted or the
    /// stamp does not carry: the caller's own path then runs.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn carry_connector_slate_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: &ConnectorKeyRecord,
        (prior, mut next, next_id): (&ConnectorGrantSlate, ConnectorGrantSlate, EntityId),
        receipt: Option<ConnectorQualificationReceipt>,
        op: &'static str,
        at: u64,
    ) -> Result<Option<ConnectorKeyRecord>> {
        let admitted = matches!(
            record.status,
            ConnectorKeyStatus::Active | ConnectorKeyStatus::Suspended
        ) && record.catalog.is_some()
            && !record.consent_required
            && record.qualification_receipt.is_some();
        let policy = crate::gate::resolve_policy_manifest(&self.store, wtxn)?;
        let Some(receipt) = receipt.filter(|_| admitted) else {
            return Ok(None);
        };
        if !next.carry_owner_stamp(prior, &policy.connector_class_carry()) {
            return Ok(None);
        }
        put_slate_in_txn(&self.store, wtxn, next_id, &next)?;
        bind_connector_slate_in_txn(self, wtxn, next_id, id)?;
        let admission_epoch = record
            .admission_epoch
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("connector admission epoch"))?;
        let carried = ConnectorKeyRecord {
            catalog: slate_catalog(record.catalog.clone(), &next),
            slate_ref: Some(next_id),
            slate_revision: Some(next.revision()),
            admission_epoch,
            qualification_receipt: Some(receipt),
            staged_slate_ref: None,
            ..record.clone()
        };
        carried.validate()?;
        rewrite_connector_key_in_txn(&self.store, wtxn, id, &carried)?;
        append_connector_key_op_record(
            &self.store,
            wtxn,
            id,
            op,
            &carried,
            policy.read_frontier_hash()?,
            at,
        )?;
        self.sync_derived_keys_in_txn(wtxn, &carried, at)?;
        Ok(Some(carried))
    }
}

/// A scoped-MCP catalog advertises the tools its qualified slate lists, so
/// a refresh's new tools reach search, describe and routing.
pub(super) fn slate_catalog(
    catalog: Option<ConnectorCatalogEntry>,
    slate: &ConnectorGrantSlate,
) -> Option<ConnectorCatalogEntry> {
    catalog.map(|entry| match entry.call_class {
        ConnectorCallClass::ScopedMcp => ConnectorCatalogEntry {
            verbs: slate
                .manifest()
                .iter()
                .map(|tool| tool.name.clone())
                .collect(),
            ..entry
        },
        _ => entry,
    })
}

/// A pack's catalog route cannot activate on another source's qualification.
pub(super) fn require_pack_qualification(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &ConnectorKeyRecord,
    slate: &super::super::slate::ConnectorGrantSlate,
    revision: &str,
) -> Result<()> {
    let Some(binding) = &slate.slate_manifest().pack_source else {
        return Ok(());
    };
    let source_id = EntityId::from_hex(&binding.source_ref)?;
    let source = vault
        .pack_source_in_txn(txn, &source_id)?
        .ok_or_else(|| invalid_body("connector pack source missing"))?;
    let installed = vault
        .installed_pack_in_txn(txn, &source.manifest().name)?
        .ok_or_else(|| invalid_body("connector pack has not qualified"))?;
    let qualification = installed
        .connector_qualification
        .as_ref()
        .ok_or_else(|| invalid_body("connector pack has not qualified"))?;
    let manifest = record
        .pending_manifest
        .as_ref()
        .map(|pending| &pending.manifest)
        .or(record.retained_manifest.as_ref())
        .ok_or_else(|| invalid_body("connector pack manifest has not qualified"))?;
    if source.content_hash().to_hex() != binding.content_hash
        || installed.source_id != binding.source_ref
        || installed.content_hash != binding.content_hash
        || qualification.source_hash != binding.content_hash
        || qualification.qualification.protocol_revision != revision
        || qualification.qualification.manifest_hash != manifest.hash()?
    {
        return Err(invalid_body("connector pack qualification basis changed"));
    }
    Ok(())
}
