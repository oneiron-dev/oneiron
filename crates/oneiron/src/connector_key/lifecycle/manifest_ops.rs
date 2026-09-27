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
        let report_hash = suite.qualify(&manifest, revision)?;
        if report_hash.len() != 64 || !report_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid_body("connector qualification report hash missing"));
        }
        let mut txn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &txn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("revoked connector cannot update manifest"));
        }
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
        if !drift.needs_reconsent() {
            return Ok(None);
        }
        // Do not replace a protocol-revision re-registration with an ordinary
        // candidate. Its suspension must survive until that revision's
        // qualification and owner approval, never become an unrelated hold.
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
                .is_none_or(|pending| !pending.drift.requires_reregistration)
        {
            return Err(invalid_body(
                "resume an independently suspended key before revision update",
            ));
        }
        let first = record.retained_manifest.is_none();
        let changed = ConnectorKeyRecord {
            pending_manifest: Some(PendingConnectorManifest {
                manifest,
                protocol_revision: revision.to_owned(),
                drift: drift.clone(),
                qualification_report_hash: Some(report_hash),
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
        rewrite_connector_key_in_txn(&self.store, &mut txn, id, &changed)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        append_connector_key_op_record(
            &self.store,
            &mut txn,
            id,
            "gate.connector_key.manifest_stage",
            &changed,
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
