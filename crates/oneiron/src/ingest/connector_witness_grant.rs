//! The witness-read grant (FIX 10895, owner ruling WITNESS-READ). An agent
//! that witnesses a connector conversation reads that conversation's
//! witnessed MESSAGEs through its own read lane, by a durable, revocable
//! AccessGrant the engine issues on the owner's standing policy (DEC-0006:
//! consent is durable grants). The grant goes through the read lane, never
//! around it: every other check on a MESSAGE still binds.
//!
//! The grant sits at an id derived from the agent and the conversation, so
//! it is issued once. A later witness finds it, live or revoked, and never
//! issues it again: a grant the owner revoked stays revoked until the owner
//! grants again through the normal grant door. The consent registry lists
//! every witness-read grant beside the owner's other grants, with its own
//! one-tap revoke, and its receipts name the reason it was issued.

use crate::Vault;
use crate::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
    decode_live_access_grant_body,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::{
    AuthenticatedOwner, ConsentDomain, ConsentGrantStatus, ConsentRegistryRow, ConsentRevokeAction,
};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;

/// The owner's standing policy for connector conversations (CALLS `FIX
/// 10895 WITNESS-READ`): `true` issues an agent that witnesses a connector
/// conversation a read grant over its MESSAGEs.
pub(crate) const CONNECTOR_WITNESS_READ_GRANT: bool = true;

/// The reason a witness-read grant names in its receipts and its consent
/// registry row.
pub(crate) const CONNECTOR_WITNESS_READ_REASON: &str = "connector_witness_read";

/// The owner verb that revokes one witness-read grant.
pub(crate) const CONNECTOR_WITNESS_READ_REVOKE_COMMAND: &str =
    "vault.connectors.read_grants.revoke";

/// A witness-read grant. Parts: the agent, then the conversation.
const CONNECTOR_WITNESS_READ_GRANT_DOMAIN: &[u8] =
    b"oneiron.ingest.connector.witness_read_grant.v1";

impl Vault {
    /// Issues `agent` its read grant over the MESSAGEs of `conversation`,
    /// the connector conversation it just witnessed, once. A grant already
    /// at its id, live or revoked, stands as it is.
    ///
    /// # Errors
    /// The grant's id does not derive, or the vault read or write fails.
    pub(crate) fn issue_connector_witness_read_grant(
        &self,
        agent: EntityId,
        conversation: EntityId,
        now: u64,
    ) -> Result<()> {
        if !CONNECTOR_WITNESS_READ_GRANT {
            return Ok(());
        }
        let id = connector_witness_read_grant_id(agent, conversation)?;
        if self.get_access_grant(&id)?.is_some() {
            return Ok(());
        }
        let grant = AccessGrant {
            authority_scope: crate::federation::scope_codec::read_preset(),
            principal_ref: agent,
            scope: AccessGrantScope::ConversationMessages {
                conversation_ref: conversation,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: now,
            revoked_at: None,
            expires_at: None,
        };
        match self.create_access_grant(&id, &grant) {
            // A concurrent witness issued it first.
            Err(Error::Record(RecordError::AccessGrantAlreadyExists)) => Ok(()),
            issued => issued,
        }
    }

    /// Revokes the witness-read grant at `grant_ref` on `owner`'s word,
    /// through the AccessGrant revoke door. It stays revoked: its revoked
    /// row is what keeps a later witness from issuing it again, and only
    /// the owner's own grant lets the agent read the conversation once
    /// more. A grant already revoked is answered as it stands, unchanged.
    ///
    /// # Errors
    /// `owner` no longer proves the vault's owner; `EntityNotFound` when
    /// `grant_ref` names no witness-read grant; or the vault write fails.
    pub(crate) fn revoke_connector_witness_read_grant(
        &self,
        owner: &AuthenticatedOwner,
        grant_ref: &EntityId,
        revoked_at: u64,
    ) -> Result<WitnessReadGrantRevoke> {
        self.recheck_owner(owner)?;
        let (grant, conversation) = self
            .get_access_grant(grant_ref)?
            .and_then(|grant| {
                witness_read_conversation(grant_ref, &grant)
                    .map(|conversation| (grant, conversation))
            })
            .ok_or(Error::EntityNotFound)?;
        if grant.status == AccessGrantStatus::Revoked {
            return Ok(WitnessReadGrantRevoke {
                grant,
                conversation,
                changed: false,
            });
        }
        Ok(WitnessReadGrantRevoke {
            grant: self.revoke_access_grant(grant_ref, revoked_at)?,
            conversation,
            changed: true,
        })
    }

    /// The witness-read grants as `vault.consent.registry` reviews them:
    /// live ones, or every one with `include_revoked`, each with the
    /// witness-read revoke as its one-tap revoke. A grant row that does not
    /// decode is no witness-read grant and is left out.
    ///
    /// # Errors
    /// The vault's clock or its grant index does not read.
    pub(crate) fn connector_witness_read_registry_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        include_revoked: bool,
    ) -> Result<Vec<ConsentRegistryRow>> {
        let now = self.instant_in_txn(txn)?.secs();
        let mut rows = Vec::new();
        for id in EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            txn,
            ENTITY_TYPE_ACCESS_GRANT,
            None,
        )? {
            let id = id?;
            let Some((grant, conversation)) = self.connector_witness_read_grant_in(txn, &id) else {
                continue;
            };
            let live = grant.effective_status_at(now) == AccessGrantStatus::Active;
            if include_revoked || live {
                rows.push(registry_row(&id, &grant, conversation, live));
            }
        }
        Ok(rows)
    }

    /// The live witness-read grant row at `id`, with the conversation it
    /// reads; `None` for any other row, or one that does not read.
    fn connector_witness_read_grant_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Option<(AccessGrant, EntityId)> {
        if !crate::vault::live_entity_row_in_txn(&self.store, txn, id)
            .is_ok_and(|row| row.is_live())
        {
            return None;
        }
        let raw = EntityStoreRead::port_entity_raw(&self.store, txn, id)
            .ok()
            .flatten()?;
        if EntityMetadataHeader::parse(&raw)?.entity_type != ENTITY_TYPE_ACCESS_GRANT {
            return None;
        }
        let grant = decode_live_access_grant_body(raw.get(ENTITY_METADATA_HEADER_LEN..)?)
            .ok()
            .flatten()?;
        let conversation = witness_read_conversation(id, &grant)?;
        Some((grant, conversation))
    }
}

/// One witness-read grant's registry row: the agent it lets read, the
/// conversation it reads, and the witness-read revoke as its one-tap
/// revoke, never the consent grant revoke.
fn registry_row(
    id: &EntityId,
    grant: &AccessGrant,
    conversation: EntityId,
    live: bool,
) -> ConsentRegistryRow {
    let grant_ref = id.to_hex();
    ConsentRegistryRow {
        domain: ConsentDomain::Disclosure,
        subject: grant.principal_ref.to_hex(),
        class: CONNECTOR_WITNESS_READ_REASON.to_owned(),
        selectors: vec![
            format!("conversation:{}", conversation.to_hex()),
            format!("capability:{}", grant.capability.as_str()),
        ],
        scope: Some(grant.authority_scope.clone()),
        status: if live {
            ConsentGrantStatus::Active
        } else {
            ConsentGrantStatus::Revoked
        },
        created_at: grant.created_at,
        revoke_action: ConsentRevokeAction {
            command: CONNECTOR_WITNESS_READ_REVOKE_COMMAND.to_owned(),
            grant_ref: grant_ref.clone(),
        },
        grant_ref,
        bypass: None,
        delegation: None,
        agent_grant: None,
    }
}

/// What the owner's revoke of a witness-read grant did.
pub(crate) struct WitnessReadGrantRevoke {
    /// The grant as it now stands: revoked.
    pub(crate) grant: AccessGrant,
    /// The connector conversation whose MESSAGEs it let its agent read.
    pub(crate) conversation: EntityId,
    /// False when the grant was already revoked and the call changed
    /// nothing.
    pub(crate) changed: bool,
}

/// The id of `agent`'s witness-read grant over `conversation`.
fn connector_witness_read_grant_id(agent: EntityId, conversation: EntityId) -> Result<EntityId> {
    EntityId::derive(
        CONNECTOR_WITNESS_READ_GRANT_DOMAIN,
        &[
            agent.as_bytes().as_slice(),
            conversation.as_bytes().as_slice(),
        ],
    )
}

/// The reason `grant`, stored at `id`, was issued, when it is a
/// witness-read grant.
pub(crate) fn connector_witness_read_reason(
    id: &EntityId,
    grant: &AccessGrant,
) -> Option<&'static str> {
    witness_read_conversation(id, grant).map(|_| CONNECTOR_WITNESS_READ_REASON)
}

/// The conversation `grant`, stored at `id`, reads when it is a
/// witness-read grant: one over a conversation's MESSAGEs at the id its
/// agent and conversation derive.
fn witness_read_conversation(id: &EntityId, grant: &AccessGrant) -> Option<EntityId> {
    let AccessGrantScope::ConversationMessages { conversation_ref } = grant.scope else {
        return None;
    };
    connector_witness_read_grant_id(grant.principal_ref, conversation_ref)
        .is_ok_and(|derived| derived == *id)
        .then_some(conversation_ref)
}
