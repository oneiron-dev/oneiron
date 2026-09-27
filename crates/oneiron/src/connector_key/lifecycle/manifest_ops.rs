//! Manifest updates: qualify immutable resolved input, retain the approved
//! snapshot, and bind an owner stamp to the exact candidate and suite report.
use super::super::manifest_drift::{ConnectorManifestDrift, ResolvedConnectorManifest};
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

impl Vault {
    /// Stage an exact qualified candidate without replacing the approved
    /// manifest. Revision changes suspend; other drift only marks affected
    /// tool rows for confirm-first. No-op changes do not manufacture an ask.
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
        let drift = match (
            &record.retained_manifest,
            &record.negotiated_protocol_revision,
        ) {
            (Some(old), Some(old_revision)) => {
                ConnectorManifestDrift::between(old, &manifest, old_revision, revision)
            }
            (None, None) => ConnectorManifestDrift::first_registration(&manifest),
            _ => return Err(invalid_body("connector manifest pin incomplete")),
        };
        if !drift.has_change() {
            if let Some(previous) = record.pending_manifest.as_ref() {
                let held_revision = record.status == ConnectorKeyStatus::Suspended
                    && record.suspended_reason.as_deref() == Some("protocol_revision_drift")
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
                        || current.status != ConnectorKeyStatus::Suspended
                        || current.suspended_reason.as_deref() != Some("protocol_revision_drift")
                        || current.retained_manifest.as_ref() != Some(&manifest)
                        || current.negotiated_protocol_revision.as_deref() != Some(revision)
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
        if record.status == ConnectorKeyStatus::Suspended
            && record.suspended_reason.as_deref() == Some("protocol_revision_drift")
            && !drift.requires_reregistration
        {
            return Err(invalid_body(
                "protocol revision drift still needs re-registration",
            ));
        }
        if drift.requires_reregistration
            && record.status == ConnectorKeyStatus::Suspended
            && record
                .pending_manifest
                .as_ref()
                .is_none_or(|p| !p.drift.requires_reregistration)
        {
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
            status: if drift.requires_reregistration {
                ConnectorKeyStatus::Suspended
            } else if first {
                ConnectorKeyStatus::Pending
            } else {
                record.status
            },
            status_changed_at: if drift.requires_reregistration || first {
                Some(at)
            } else {
                record.status_changed_at
            },
            suspended_reason: if drift.requires_reregistration {
                Some("protocol_revision_drift".to_owned())
            } else {
                record.suspended_reason.clone()
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
            record.negotiated_protocol_revision = Some(pending.protocol_revision.clone());
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
            negotiated_protocol_revision: Some(pending.protocol_revision.clone()),
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
            suspended_reason: if pending.drift.requires_reregistration {
                None
            } else {
                record.suspended_reason.clone()
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

fn valid_report_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
