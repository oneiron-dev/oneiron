//! Key state machine: suspend/resume, terminal revoke/remove, custody rotation and generation log.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::resolve_secret_ref_in_txn;

use super::super::record::{
    ConnectorKeyRecord, ConnectorKeyStatus, invalid_body, validate_secret_ref,
};
use super::super::txn::{
    ConnectorKeyGeneration, append_connector_key_op_record, read_connector_key_generation_in_txn,
    read_connector_key_in_txn, reject_terminal_transition, revoke_connector_key_in_txn,
    rewrite_connector_key_in_txn, suspend_connector_key_in_txn,
    write_connector_key_generation_in_txn,
};

impl Vault {
    /// Suspends an Active key (owner op).
    pub fn suspend_connector_key(
        &self,
        id: &EntityId,
        reason: &str,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status != ConnectorKeyStatus::Active {
            return Err(invalid_body("illegal status transition"));
        }
        let suspended = suspend_connector_key_in_txn(
            &self.store,
            &mut wtxn,
            id,
            &record,
            reason.to_owned(),
            at,
        )?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.suspend",
            &suspended,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(suspended)
    }
    /// Resumes a Suspended key. Deliberately does NOT clear usage rows: the
    /// window state is truth — if the window has not rolled, the next send
    /// re-exhausts and re-suspends (correct hard-cap behavior).
    pub fn resume_connector_key(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status != ConnectorKeyStatus::Suspended {
            return Err(invalid_body("illegal status transition"));
        }
        let resumed = ConnectorKeyRecord {
            status: ConnectorKeyStatus::Active,
            status_changed_at: Some(at),
            suspended_reason: None,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &resumed)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.resume",
            &resumed,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(resumed)
    }
    /// Revokes a key (terminal) from any non-revoked state.
    pub fn revoke_connector_key(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(reject_terminal_transition());
        }
        let revoked = revoke_connector_key_in_txn(&self.store, &mut wtxn, id, &record, at)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.revoke",
            &revoked,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(revoked)
    }
    /// Removes a connector from the engine catalog.
    ///
    /// Mechanically this is the SAME terminal revocation core, but it is a
    /// different OP: exactly ONE `gate.connector_key.remove` record is
    /// appended and `gate.connector_key.revoke` is never emitted, so the
    /// receipt trail distinguishes "the owner pulled this key" from "the
    /// operator retired this connector".
    ///
    /// The permanent catalog name-index row is deliberately NOT deleted:
    /// names are unique per vault ACROSS HISTORY. So after removal
    /// `search_connector_catalog` omits the connector (Active-only),
    /// `describe_connector` still resolves it as Revoked, `route_connector_call`
    /// returns `None`, and re-registering the same name fails
    /// [`Error::ConnectorKeyAlreadyExists`] rather than recycling the name
    /// onto a different connector.
    pub fn remove_connector_key(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(reject_terminal_transition());
        }
        let removed = revoke_connector_key_in_txn(&self.store, &mut wtxn, id, &record, at)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.remove",
            &removed,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(removed)
    }
    /// Re-points a key at a NEW custody record and bumps its rotation
    /// generation, receipted as `gate.connector_key.rotate`.
    ///
    /// VALUE-FREE by construction: `new_secret_ref` is a custody record NAME
    /// that must resolve to a live record BEFORE anything is written, and the
    /// secret value is never read, copied, or carried through here. Rotating
    /// the VALUE behind a custody record is SECRET-04's job; this rotates
    /// which record the connector key points AT.
    ///
    /// The generation log lazily backfills the record's CURRENT generation
    /// first, so a key whose body predates the log (a v1/v2 body, which
    /// decodes at generation 0) still leaves `0..=new` point-readable through
    /// [`Self::connector_key_generation`].
    pub fn rotate_connector_key(
        &self,
        id: &EntityId,
        new_secret_ref: &str,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        validate_secret_ref(new_secret_ref)?;
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("cannot rotate a revoked key"));
        }
        if resolve_secret_ref_in_txn(&self.store, &wtxn, new_secret_ref)?.is_none() {
            return Err(invalid_body("secret_ref does not resolve"));
        }
        let next_generation =
            record
                .key_generation
                .checked_add(1)
                .ok_or(Error::InvariantViolation(
                    "connector key generation overflow",
                ))?;
        if read_connector_key_generation_in_txn(&self.store, &wtxn, id, record.key_generation)?
            .is_none()
        {
            write_connector_key_generation_in_txn(
                &self.store,
                &mut wtxn,
                id,
                &ConnectorKeyGeneration {
                    generation: record.key_generation,
                    secret_ref: record.secret_ref.clone(),
                    rotated_at: record.registered_at,
                },
            )?;
        }
        let rotated = ConnectorKeyRecord {
            secret_ref: Some(new_secret_ref.to_owned()),
            key_generation: next_generation,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &rotated)?;
        write_connector_key_generation_in_txn(
            &self.store,
            &mut wtxn,
            id,
            &ConnectorKeyGeneration {
                generation: next_generation,
                secret_ref: rotated.secret_ref.clone(),
                rotated_at: at,
            },
        )?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.rotate",
            &rotated,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(rotated)
    }
    /// Point-reads one entry of a key's rotation-generation log: which custody
    /// record the key pointed at while that generation was current.
    pub fn connector_key_generation(
        &self,
        id: &EntityId,
        generation: u32,
    ) -> Result<Option<ConnectorKeyGeneration>> {
        let rtxn = self.store.env.read_txn()?;
        read_connector_key_generation_in_txn(&self.store, &rtxn, id, generation)
    }
}
