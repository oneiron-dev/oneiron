//! Vault row primitives (owner check, row read/write, content-addressed envelope put) and the owner-only envelope doors plus the identity-actor proof.

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity::{
    ChannelIdentityBinding, ChannelIdentityState, decode_channel_identity_body,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::codec::{
    action_from, action_value, address, array, decode, encode, id, id_value, key, number,
    read_from, read_value,
};
use super::invalid_autonomy;
use super::types::{
    CHANNEL_IDENTITY_AUTONOMY_SCHEMA_VERSION, ChannelIdentityActionEnvelope, MailboxReadEnvelope,
    PREDICATE_ACTION_ENVELOPE, PREDICATE_MAILBOX_READ_ENVELOPE,
};

impl Vault {
    pub(super) fn autonomy_owner(&self, owner: &AuthenticatedOwner) -> Result<()> {
        self.authenticate_owner(
            owner.actor(),
            owner.principal_ref(),
            true,
            owner.decision_id(),
        )
        .map(|_| ())
    }

    pub(super) fn autonomy_row(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &[u8],
    ) -> Result<(EntityId, u64, Value)> {
        let bytes = self
            .store
            .vault_meta
            .get(txn, key)?
            .ok_or_else(invalid_autonomy)?;
        let value = decode(&bytes)?;
        let v = array(&value, 4)?;
        if number(&v[0])? != CHANNEL_IDENTITY_AUTONOMY_SCHEMA_VERSION {
            return Err(invalid_autonomy());
        }
        Ok((id(&v[1])?, number(&v[2])?, v[3].clone()))
    }

    pub(super) fn write_autonomy_row(
        &self,
        txn: &mut heed::RwTxn<'_>,
        key: &[u8],
        actor: EntityId,
        at: u64,
        value: Value,
    ) -> Result<()> {
        let bytes = encode(&Value::Array(vec![
            Value::from(CHANNEL_IDENTITY_AUTONOMY_SCHEMA_VERSION),
            id_value(actor),
            Value::from(at),
            value,
        ]))?;
        self.store.vault_meta.put(txn, key, &bytes)?;
        Ok(())
    }

    pub(super) fn put_autonomy_envelope(
        &self,
        txn: &mut heed::RwTxn<'_>,
        kind: &str,
        value: Value,
        owner: &AuthenticatedOwner,
        at: u64,
    ) -> Result<EntityId> {
        let reference = address(kind, &value)?;
        let key = key(kind, &reference.to_hex());
        if self.store.vault_meta.get(txn, &key)?.is_some() {
            let (actor, _, old) = self.autonomy_row(txn, &key)?;
            if actor != owner.actor() || old != value {
                return Err(invalid_autonomy());
            }
        } else {
            self.write_autonomy_row(txn, &key, owner.actor(), at, value)?;
        }
        Ok(reference)
    }

    /// Owner-only immutable write. An exact retry returns the same handle.
    pub fn put_mailbox_read_envelope(
        &self,
        envelope: MailboxReadEnvelope,
        owner: &AuthenticatedOwner,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.autonomy_owner(owner)?;
        let value = read_value(&envelope)?;
        let mut txn = self.store.env.write_txn()?;
        self.autonomy_identity_actor(&txn, envelope.identity_ref)?;
        let id = self.put_autonomy_envelope(
            &mut txn,
            PREDICATE_MAILBOX_READ_ENVELOPE,
            value,
            owner,
            learned_at,
        )?;
        txn.commit()?;
        Ok(id)
    }

    /// Owner-only immutable action bound. This does not mint a grant.
    pub fn put_channel_identity_action_envelope(
        &self,
        envelope: ChannelIdentityActionEnvelope,
        owner: &AuthenticatedOwner,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.autonomy_owner(owner)?;
        let value = action_value(&envelope)?;
        let mut txn = self.store.env.write_txn()?;
        self.autonomy_identity_actor(&txn, envelope.identity_ref)?;
        let id = self.put_autonomy_envelope(
            &mut txn,
            PREDICATE_ACTION_ENVELOPE,
            value,
            owner,
            learned_at,
        )?;
        txn.commit()?;
        Ok(id)
    }

    pub fn get_mailbox_read_envelope(&self, reference: &EntityId) -> Result<MailboxReadEnvelope> {
        let txn = self.store.env.read_txn()?;
        read_from(
            &self
                .autonomy_row(
                    &txn,
                    &key(PREDICATE_MAILBOX_READ_ENVELOPE, &reference.to_hex()),
                )?
                .2,
        )
    }

    pub fn get_channel_identity_action_envelope(
        &self,
        reference: &EntityId,
    ) -> Result<ChannelIdentityActionEnvelope> {
        let txn = self.store.env.read_txn()?;
        self.autonomy_action_envelope(&txn, reference)
    }

    pub(crate) fn autonomy_action_envelope(
        &self,
        txn: &heed::RoTxn<'_>,
        reference: &EntityId,
    ) -> Result<ChannelIdentityActionEnvelope> {
        let value = self
            .autonomy_row(txn, &key(PREDICATE_ACTION_ENVELOPE, &reference.to_hex()))?
            .2;
        if address(PREDICATE_ACTION_ENVELOPE, &value)? != *reference {
            return Err(invalid_autonomy());
        }
        action_from(&value)
    }

    pub(crate) fn autonomy_identity_actor(
        &self,
        txn: &heed::RoTxn<'_>,
        identity: EntityId,
    ) -> Result<EntityId> {
        let raw = self
            .store
            .entities
            .get(txn, identity.as_bytes())?
            .ok_or_else(invalid_autonomy)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid_autonomy)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(invalid_autonomy());
        }
        let record = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if record.state != ChannelIdentityState::Active {
            return Err(invalid_autonomy());
        }
        if record.is_delegated() {
            crate::channel_identity::admit_channel_identity_transition_in_txn(
                &self.store,
                txn,
                &identity,
                crate::channel_identity::IdentityTransition::Step {
                    prior: &record,
                    next: &record,
                },
            )?;
        }
        match record.binding {
            ChannelIdentityBinding::Actor { actor_ref, .. } => Ok(actor_ref),
            ChannelIdentityBinding::Vault { .. } => Err(invalid_autonomy()),
        }
    }
}
