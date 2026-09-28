//! Manifest updates: qualify immutable resolved input, retain the approved
//! snapshot, and bind an owner stamp to the exact candidate and suite report.
use super::super::manifest_drift::{
    ConnectorManifestDrift, ConnectorToolSchema, ResolvedConnectorManifest,
};
use super::super::qualification::{
    GroundingOracle, ProbeTool, QualificationConnector, QualificationPlan, qualify_connector,
};
use super::super::record::{
    ConnectorKeyRecord, ConnectorKeyStatus, PendingConnectorManifest, invalid_body,
    validate_protocol_revision,
};
use super::super::txn::{
    append_connector_key_op_record, read_connector_key_in_txn, rewrite_connector_key_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// The host's real suite runs on the resolved, immutable candidate for each
/// first admission and each drift. An empty or failing report never stages it.
pub trait ConnectorManifestQualifier {
    fn qualify(&self, manifest: &ResolvedConnectorManifest, revision: &str) -> Result<String>;
}

/// The engine suite behind [`ConnectorManifestQualifier`]: the ARCH-0028
/// probe runner. The connector's resolved declarations must equal the exact
/// candidate before any effectful probe runs, and again in the runner's own
/// listing, so a report never vouches for a different surface.
pub struct ProbeManifestQualifier<'a> {
    pub connector: &'a dyn QualificationConnector,
    pub plan: &'a QualificationPlan,
    pub oracle: &'a dyn GroundingOracle,
}

impl ConnectorManifestQualifier for ProbeManifestQualifier<'_> {
    fn qualify(&self, manifest: &ResolvedConnectorManifest, revision: &str) -> Result<String> {
        let declared = self
            .connector
            .connect()
            .and_then(|mut connection| connection.tools_list())
            .map_err(|_| probe_failure())?;
        ensure_declared(manifest, &declared)?;
        let report = qualify_connector(self.connector, self.plan, self.oracle)
            .map_err(|_| probe_failure())?;
        ensure_declared(manifest, &report.tools)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"connector-manifest-qualification-v1");
        hasher.update(&manifest.hash()?);
        hasher.update(revision.as_bytes());
        hasher.update(
            &u64::try_from(report.calls)
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        for result_type in &report.exercised_result_types {
            hasher.update(result_type.as_bytes());
            hasher.update(&[0]);
        }
        Ok(hasher.finalize().to_hex().to_string())
    }
}

fn probe_failure() -> Error {
    invalid_body("connector qualification probes failed")
}

/// Probe listings are literal declarations: compare them only after the same
/// resolution the candidate went through. Listings carry no permission rows,
/// so those come from the candidate by tool name.
fn ensure_declared(manifest: &ResolvedConnectorManifest, tools: &[ProbeTool]) -> Result<()> {
    let observed = ResolvedConnectorManifest::resolve(
        tools
            .iter()
            .map(|tool| ConnectorToolSchema {
                name: tool.name.clone(),
                permissions: manifest
                    .tools()
                    .iter()
                    .find(|candidate| candidate.name == tool.name)
                    .map(|candidate| candidate.permissions.clone())
                    .unwrap_or_default(),
                triggers: tool.trigger.iter().cloned().collect(),
                input_schema: tool.input_schema.clone(),
            })
            .collect(),
    )?;
    if observed != *manifest {
        return Err(invalid_body("connector declarations differ from candidate"));
    }
    Ok(())
}

impl Vault {
    /// Stage an exact qualified candidate without replacing the approved
    /// manifest. Revision changes return the key to Pending; other drift only
    /// marks affected tool rows for confirm-first. No-op changes do not
    /// manufacture an ask. A catalog key changes revision only through
    /// `revise_connector_protocol`, which re-binds its owner slate.
    pub fn stage_connector_manifest(
        &self,
        id: &EntityId,
        manifest: ResolvedConnectorManifest,
        revision: &str,
        suite: &dyn ConnectorManifestQualifier,
        at: u64,
    ) -> Result<Option<ConnectorManifestDrift>> {
        manifest.validate_snapshot()?;
        validate_protocol_revision(revision)?;
        let manifest_hash = manifest.hash()?;
        if serde_json::to_vec(&manifest)
            .map_err(|_| invalid_body("manifest serialization failed"))?
            .len()
            > super::super::record::MAX_CONNECTOR_MANIFEST_BYTES
        {
            return Err(invalid_body("resolved manifest exceeds aggregate bound"));
        }
        let mut txn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &txn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("revoked connector cannot update manifest"));
        }
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        if policy.is_fail_closed() {
            return Err(invalid_body("connector admission policy is unavailable"));
        }
        let holder = record.actor_entity_ref.as_ref().map(EntityId::to_hex);
        manifest.validate_admission(policy.connector_admission.effective(holder.as_deref()))?;
        let drift = match (&record.retained_manifest, &record.protocol_revision) {
            (Some(old), Some(old_revision)) => {
                ConnectorManifestDrift::between(old, &manifest, old_revision, revision)
            }
            (None, Some(pinned)) if pinned == revision => {
                ConnectorManifestDrift::first_registration(&manifest)
            }
            (None, None) => ConnectorManifestDrift::first_registration(&manifest),
            (None, Some(_)) => return Err(catalog_revision_change()),
            (Some(_), None) => return Err(invalid_body("connector manifest pin incomplete")),
        };
        if record.catalog.is_some() && drift.requires_reregistration {
            return Err(catalog_revision_change());
        }
        if !drift.has_change() {
            if let Some(previous) = record.pending_manifest.as_ref() {
                let held_revision = record.status == ConnectorKeyStatus::Pending
                    && previous.drift.requires_reregistration;
                if held_revision {
                    // A return to the approved revision is not an expansion,
                    // but it is not proof that the reconnected peer still
                    // qualifies. Keep the hold through the suite and compare
                    // the exact old candidate again before lifting it.
                    let candidate_id = previous.candidate_id;
                    drop(txn);
                    let report = suite.qualify(&manifest, revision)?;
                    if !valid_report_hash(&report) {
                        return Err(invalid_body("connector qualification report hash missing"));
                    }
                    let mut txn = self.store.env.write_txn()?;
                    let current = read_connector_key_in_txn(&self.store, &txn, id)?
                        .ok_or(Error::EntityNotFound)?;
                    if current
                        .pending_manifest
                        .as_ref()
                        .map(|candidate| candidate.candidate_id)
                        != Some(candidate_id)
                        || current.status != ConnectorKeyStatus::Pending
                        || current.retained_manifest.as_ref() != Some(&manifest)
                        || current.protocol_revision.as_deref() != Some(revision)
                    {
                        return Err(Error::ConcurrentWrite("connector manifest candidate"));
                    }
                    let reverted = ConnectorKeyRecord {
                        pending_manifest: None,
                        status: ConnectorKeyStatus::Active,
                        status_changed_at: Some(at),
                        suspended_reason: None,
                        ..current
                    };
                    rewrite_connector_key_in_txn(&self.store, &mut txn, id, &reverted)?;
                    let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
                    append_connector_key_op_record(
                        &self.store,
                        &mut txn,
                        id,
                        "gate.connector_key.manifest_requalified_revert",
                        &reverted,
                        policy.read_frontier_hash()?,
                        at,
                    )?;
                    txn.commit()?;
                } else {
                    let reverted = ConnectorKeyRecord {
                        pending_manifest: None,
                        ..record
                    };
                    rewrite_connector_key_in_txn(&self.store, &mut txn, id, &reverted)?;
                    let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
                    append_connector_key_op_record(
                        &self.store,
                        &mut txn,
                        id,
                        "gate.connector_key.manifest_revert",
                        &reverted,
                        policy.read_frontier_hash()?,
                        at,
                    )?;
                    txn.commit()?;
                }
            }
            return Ok(None);
        }
        if record.status == ConnectorKeyStatus::Pending
            && record
                .pending_manifest
                .as_ref()
                .is_some_and(|pending| pending.drift.requires_reregistration)
            && !drift.requires_reregistration
        {
            return Err(invalid_body(
                "protocol revision drift still needs re-registration",
            ));
        }
        if drift.requires_reregistration && record.status == ConnectorKeyStatus::Suspended {
            return Err(invalid_body(
                "resume an independently suspended key before revision update",
            ));
        }
        // First commit the drift hold, before invoking the external suite.
        // Failed probes or malformed reports leave this candidate non-approvable.
        let mut candidate_hasher = blake3::Hasher::new();
        candidate_hasher.update(b"connector-manifest-candidate-v1");
        candidate_hasher.update(&self.store.clock.ulid()?);
        candidate_hasher.update(&manifest_hash);
        candidate_hasher.update(revision.as_bytes());
        let candidate_id = *candidate_hasher.finalize().as_bytes();
        let first = record.retained_manifest.is_none();
        let staged = ConnectorKeyRecord {
            pending_manifest: Some(PendingConnectorManifest {
                candidate_id,
                manifest: manifest.clone(),
                protocol_revision: revision.to_owned(),
                drift: drift.clone(),
                qualification_report_hash: None,
            }),
            status: if drift.requires_reregistration || first {
                ConnectorKeyStatus::Pending
            } else {
                record.status
            },
            status_changed_at: if drift.requires_reregistration || first {
                Some(at)
            } else {
                record.status_changed_at
            },
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut txn, id, &staged)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        append_connector_key_op_record(
            &self.store,
            &mut txn,
            id,
            "gate.connector_key.manifest_stage",
            &staged,
            policy.read_frontier_hash()?,
            at,
        )?;
        txn.commit()?;

        let report_hash = suite.qualify(&manifest, revision)?;
        if !valid_report_hash(&report_hash) {
            return Err(invalid_body("connector qualification report hash missing"));
        }
        let mut txn = self.store.env.write_txn()?;
        let mut record =
            read_connector_key_in_txn(&self.store, &txn, id)?.ok_or(Error::EntityNotFound)?;
        let pending = record
            .pending_manifest
            .as_mut()
            .ok_or(Error::ConcurrentWrite("connector manifest candidate"))?;
        if pending.candidate_id != candidate_id {
            return Err(Error::ConcurrentWrite("connector manifest candidate"));
        }
        pending.qualification_report_hash = Some(report_hash);
        let auto_narrow = !pending.drift.needs_reconsent();
        if auto_narrow {
            // A strict permission subset or removed tool is a proved narrow.
            // It takes effect after successful qualification, without an
            // unnecessary owner re-consent prompt.
            record.retained_manifest = Some(pending.manifest.clone());
            record.protocol_revision = Some(pending.protocol_revision.clone());
            record.pending_manifest = None;
        }
        rewrite_connector_key_in_txn(&self.store, &mut txn, id, &record)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        append_connector_key_op_record(
            &self.store,
            &mut txn,
            id,
            if auto_narrow {
                "gate.connector_key.manifest_narrow"
            } else {
                "gate.connector_key.manifest_qualified"
            },
            &record,
            policy.read_frontier_hash()?,
            at,
        )?;
        txn.commit()?;
        Ok(Some(drift))
    }

    /// An owner explicitly accepts the exact qualified candidate. The
    /// expected report binds consent to the suite that actually ran.
    pub fn approve_connector_manifest(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        expected_candidate_id: [u8; 32],
        expected_manifest_hash: [u8; 32],
        expected_report_hash: &str,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        let mut txn = self.store.env.write_txn()?;
        crate::memory::verify_deletion_authority_in_txn(
            self,
            &txn,
            owner.actor(),
            EdgeActorClass::Human,
        )
        .map_err(|_| invalid_body("connector manifest owner binding required"))?;
        let record =
            read_connector_key_in_txn(&self.store, &txn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("revoked connector cannot approve manifest"));
        }
        let pending = record
            .pending_manifest
            .as_ref()
            .ok_or_else(|| invalid_body("no pending manifest"))?;
        if pending.candidate_id != expected_candidate_id {
            return Err(invalid_body(
                "connector manifest candidate changed since consent",
            ));
        }
        if pending.manifest.hash()? != expected_manifest_hash {
            return Err(invalid_body("connector manifest changed since consent"));
        }
        if pending.qualification_report_hash.as_deref() != Some(expected_report_hash) {
            return Err(invalid_body("connector qualification report changed"));
        }
        let approved = ConnectorKeyRecord {
            protocol_revision: Some(pending.protocol_revision.clone()),
            retained_manifest: Some(pending.manifest.clone()),
            pending_manifest: None,
            status: if pending.drift.requires_reregistration
                || record.status == ConnectorKeyStatus::Pending
            {
                ConnectorKeyStatus::Active
            } else {
                record.status
            },
            status_changed_at: if pending.drift.requires_reregistration
                || record.status == ConnectorKeyStatus::Pending
            {
                Some(at)
            } else {
                record.status_changed_at
            },
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut txn, id, &approved)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        append_connector_key_op_record(
            &self.store,
            &mut txn,
            id,
            "gate.connector_key.manifest_approve",
            &approved,
            policy.read_frontier_hash()?,
            at,
        )?;
        txn.commit()?;
        Ok(approved)
    }

    /// Tool callers must use this door before auto-fire. An unknown tool or
    /// a changed row cannot reuse the prior stamp; a revision change closes
    /// the whole key until re-registration and re-consent.
    pub fn connector_tool_requires_confirmation(&self, id: &EntityId, tool: &str) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &txn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status != ConnectorKeyStatus::Active {
            return Ok(true);
        }
        Ok(record.tool_requires_confirmation(tool))
    }
}

fn catalog_revision_change() -> Error {
    invalid_body("catalog protocol changes go through revise_connector_protocol")
}

fn valid_report_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
