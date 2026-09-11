//! Vault doors for ChannelIdentity create, provision, transition, reads, and body apply.

use crate::Vault;

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};

use crate::entity_id::EntityId;

use crate::error::{Error, Result};

use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;

use crate::temporal::TimeRange;

use crate::vault::entity_id_from_type_index_key;

use super::address::{AssignmentAddress, AssignmentKey, ChannelKey};

use super::binding::ChannelIdentityFulfillment;

use super::codec::{decode_channel_identity_body, encode_channel_identity_body};

use super::custody::{DelegatedGrant, verify_delegated_custody_in_txn};

use super::lifecycle::ChannelIdentityState;

use super::record::ChannelIdentity;

use super::transition::{IdentityTransition, admit_channel_identity_transition_in_txn};

use super::transition::DelegatedProvisionRequest;

impl Vault {
    /// Creates a ChannelIdentity record through the engine maintenance door.
    ///
    /// Generic public entity puts for `ENTITY_TYPE_CHANNEL_IDENTITY` remain
    /// rejected with `MaintenanceKindNotWritable`; this method validates the
    /// CID-1 body and runs `admit_channel_identity_transition_in_txn` before
    /// writing.
    pub fn create_channel_identity(&self, id: &EntityId, identity: &ChannelIdentity) -> Result<()> {
        let data = encode_channel_identity_body(identity)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::ChannelIdentityAlreadyExists);
        }
        admit_channel_identity_transition_in_txn(
            &self.store,
            &wtxn,
            id,
            IdentityTransition::Birth { next: identity },
        )?;
        self.apply_channel_identity_body(&mut wtxn, id, identity.state_changed_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Creates the pre-provisioned own-app home-channel identity for an agent.
    pub fn create_own_app_channel_identity(
        &self,
        id: &EntityId,
        agent_ref: EntityId,
        created_at: u64,
    ) -> Result<ChannelIdentity> {
        let identity = ChannelIdentity::own_app_home(agent_ref, created_at);
        self.create_channel_identity(id, &identity)?;
        Ok(identity)
    }

    /// Stands up a requested `delegated_grant` row: THE delegated door.
    ///
    /// One call, one write transaction, and the custody proof is minted and
    /// consumed inside it. A caller cannot split this into "verify, then
    /// provision" and hold the answer across the gap: the proof borrows its
    /// transaction, so the window in which a member could revoke the grant
    /// between the check and the write is closed by construction rather than by
    /// a second check every host would have to remember to write.
    ///
    /// The adapter supplies `(channel, mailbox, binding, grant)` — NAMES — and
    /// never a proof. The row is born `Requested`; going live is the ordinary
    /// gated lifecycle road, and each step re-proves custody in its own
    /// transaction.
    ///
    /// # Errors
    ///
    /// [`Error::ChannelIdentityAlreadyExists`] when `id` is taken or the mailbox
    /// already has an occupant; [`SecretError::SecretRefNotFound`](crate::error::SecretError::SecretRefNotFound),
    /// [`SecretError::SecretCustodyNotActive`](crate::error::SecretError::SecretCustodyNotActive) or [`SecretError::SecretBindingDenied`](crate::error::SecretError::SecretBindingDenied) when
    /// the named custody record is missing, inactive, unbound for the channel's
    /// effector, or does not name this mailbox as its subject; and
    /// [`Error::InvalidChannelIdentityBody`] when the resulting row fails
    /// validation.
    pub fn provision_delegated_identity(
        &self,
        id: &EntityId,
        request: DelegatedProvisionRequest,
        requested_at: u64,
    ) -> Result<ChannelIdentity> {
        let mut wtxn = self.store.env.write_txn()?;
        let identity =
            self.provision_delegated_identity_in_txn(&mut wtxn, id, request, requested_at)?;
        wtxn.commit()?;
        Ok(identity)
    }

    /// The delegated door composed with a caller's authorization transaction.
    /// Custody proof, admission, and write all use that same transaction.
    pub(crate) fn provision_delegated_identity_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        request: DelegatedProvisionRequest,
        requested_at: u64,
    ) -> Result<ChannelIdentity> {
        if self.store.entities.get(wtxn, id.as_bytes())?.is_some() {
            return Err(Error::ChannelIdentityAlreadyExists);
        }
        // The proof borrows `wtxn`; the block ends the borrow before the write
        // takes it mutably, and the row it produced outlives it because a row
        // carries names, never evidence.
        let identity = {
            let channel_key = ChannelKey::normalize(&request.channel);
            let address =
                AssignmentAddress::normalize(channel_key.as_str(), &request.address_or_handle);
            let proof = verify_delegated_custody_in_txn(
                &self.store,
                wtxn,
                channel_key.as_str(),
                address.as_str(),
                &request.grant,
            )?;
            ChannelIdentity::requested_delegated(
                channel_key.as_str(),
                address.as_str(),
                request.binding,
                request.grant,
                &proof,
                requested_at,
            )?
        };
        let data = encode_channel_identity_body(&identity)?;
        admit_channel_identity_transition_in_txn(
            &self.store,
            wtxn,
            id,
            IdentityTransition::Birth { next: &identity },
        )?;
        self.apply_channel_identity_body(wtxn, id, requested_at, data)?;
        Ok(identity)
    }

    /// Verifies the custody record a delegated grant names for
    /// `(channel, address)`, without minting anything the caller can hold.
    ///
    /// The proof is intentionally NOT returned: it borrows the transaction that
    /// read the record, and a proof handed across a transaction boundary is
    /// exactly the stale evidence the type exists to make unspellable. Callers
    /// that want a row call [`Self::provision_delegated_identity`]; callers that
    /// only want the yes/no call this.
    ///
    /// # Errors
    ///
    /// As [`Self::provision_delegated_identity`]'s custody arms.
    pub fn verify_delegated_custody(
        &self,
        channel: &str,
        address_or_handle: &str,
        grant: &DelegatedGrant,
    ) -> Result<()> {
        let rtxn = self.store.env.read_txn()?;
        let channel_key = ChannelKey::normalize(channel);
        let address = AssignmentAddress::normalize(channel_key.as_str(), address_or_handle);
        verify_delegated_custody_in_txn(
            &self.store,
            &rtxn,
            channel_key.as_str(),
            address.as_str(),
            grant,
        )
        .map(|_| ())
    }

    /// Applies a checked ChannelIdentity lifecycle transition in place.
    pub fn transition_channel_identity(
        &self,
        id: &EntityId,
        next_state: ChannelIdentityState,
        pending_fulfillment: Option<ChannelIdentityFulfillment>,
        state_changed_at: u64,
        quarantine_until: Option<u64>,
    ) -> Result<ChannelIdentity> {
        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let current = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let next = current.transition(
            next_state,
            pending_fulfillment,
            state_changed_at,
            quarantine_until,
        )?;
        admit_channel_identity_transition_in_txn(
            &self.store,
            &wtxn,
            id,
            IdentityTransition::Step {
                prior: &current,
                next: &next,
            },
        )?;
        let data = encode_channel_identity_body(&next)?;
        self.apply_channel_identity_body(&mut wtxn, id, state_changed_at, data)?;
        wtxn.commit()?;
        Ok(next)
    }

    /// Reads and decodes a ChannelIdentity record.
    pub fn get_channel_identity(&self, id: &EntityId) -> Result<Option<ChannelIdentity>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Reads the ChannelIdentity holding a `(channel, address)` key.
    ///
    /// The lookup canonicalizes BOTH sides through [`AssignmentKey`], so a
    /// caller spelling the mailbox the way its provider did finds the row a
    /// normalizing writer stored, and a row decoded verbatim off disk is found
    /// under the key it means rather than the bytes it holds.
    ///
    /// A row that no longer OCCUPIES its key is skipped: a released or
    /// tombstoned delegated row has withdrawn its claim on a mailbox the
    /// product never owned, so it must not shadow the row a lawful re-consent
    /// stands up. Self-held rows occupy forever and are still found here in
    /// every state, which is what keeps a tombstoned address routing to its own
    /// rejection instead of looking unknown.
    pub fn channel_identity_by_assignment(
        &self,
        channel: &str,
        address_or_handle: &str,
    ) -> Result<Option<(EntityId, ChannelIdentity)>> {
        let wanted = AssignmentKey::of(channel, address_or_handle);
        let rtxn = self.store.env.read_txn()?;
        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_CHANNEL_IDENTITY])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
                return Err(Error::CorruptedIndex("type index row kind mismatch"));
            }
            let identity = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if identity.occupies_assignment_key() && identity.assignment_key() == wanted {
                return Ok(Some((id, identity)));
            }
        }
        Ok(None)
    }

    pub(crate) fn apply_channel_identity_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_CHANNEL_IDENTITY,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }
}
