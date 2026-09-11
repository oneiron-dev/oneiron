//! Vault mint, revoke, get, and apply doors plus binding handles.

use super::codec::{decode_standing_outbound_grant_body, encode_standing_outbound_grant_body};
use super::grant::{StandingOutboundGrant, StandingOutboundGrantStatus};
use super::scope::{
    BOOKING_PAGE_INVITE_ORIGIN_ACTION_ID, BOOKING_PAGE_INVITE_ORIGIN_COMPONENT_ID,
    BookingPageInviteGrantMintIntent, ScopedMcpGrantMintIntent, StandingOutboundGrantScope,
};
use super::standing_outbound_grant_principal_index_key;
use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_OUTBOUND_GRANT;
use crate::store::Store;
use crate::temporal::TimeRange;

impl Vault {
    /// Mints a standing outbound grant from an authenticated OF-336 grant intent.
    pub fn mint_standing_outbound_grant(
        &self,
        id: &EntityId,
        intent: &crate::genui::GrantMintIntent,
        created_at: u64,
    ) -> Result<StandingOutboundGrant> {
        let policy = {
            let rtxn = self.store.env.read_txn()?;
            crate::gate::resolve_policy_manifest(&self.store, &rtxn)?
        };
        let (binding_diff_handle, read_frontier_hash) =
            crate::gate::standing_outbound_grant_binding_parts(intent, &policy)?;
        let grant = StandingOutboundGrant::from_grant_mint_intent(
            intent,
            created_at,
            binding_diff_handle,
            read_frontier_hash,
        )?;
        let data = encode_standing_outbound_grant_body(&grant)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::Record(RecordError::OutboundGrantAlreadyExists));
        }
        self.apply_standing_outbound_grant_body(&mut wtxn, id, created_at, data)?;
        wtxn.commit()?;
        Ok(grant)
    }

    /// Mints a payload-aware standing grant from an authenticated grant-time
    /// decision and binds it to the current policy floor.
    pub fn mint_scoped_mcp_outbound_grant(
        &self,
        id: &EntityId,
        intent: &ScopedMcpGrantMintIntent,
        created_at: u64,
    ) -> Result<StandingOutboundGrant> {
        let policy = {
            let rtxn = self.store.env.read_txn()?;
            crate::gate::resolve_policy_manifest(&self.store, &rtxn)?
        };
        let binding_diff_handle = scoped_mcp_grant_binding_handle(intent);
        let grant = StandingOutboundGrant::from_scoped_mcp_grant_mint_intent(
            intent,
            created_at,
            binding_diff_handle,
            policy.read_frontier_hash()?,
        )?;
        let data = encode_standing_outbound_grant_body(&grant)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::Record(RecordError::OutboundGrantAlreadyExists));
        }
        self.apply_standing_outbound_grant_body(&mut wtxn, id, created_at, data)?;
        wtxn.commit()?;
        Ok(grant)
    }

    /// Mints the bounded booking-page invite grant for one published page.
    ///
    /// Same shape as the two landed mints: resolve the policy floor on a read
    /// transaction, build and validate the grant, then write it under the
    /// existing `entities.get` already-exists guard. The caller owns
    /// one-live-grant-per-page: `booking::mint_publish_page_invite_grant`
    /// looks up the principal index before it ever reaches this door, and
    /// derives `id` from the page so a second publish lands on
    /// [`RecordError::OutboundGrantAlreadyExists`](crate::error::RecordError::OutboundGrantAlreadyExists) rather than on a second grant.
    ///
    /// # Errors
    ///
    /// [`RecordError::OutboundGrantAlreadyExists`](crate::error::RecordError::OutboundGrantAlreadyExists) when `id` is already stored;
    /// [`RecordError::InvalidOutboundGrantBody`](crate::error::RecordError::InvalidOutboundGrantBody) when the grant fails validation;
    /// storage errors propagate.
    pub fn mint_booking_page_invite_outbound_grant(
        &self,
        id: &EntityId,
        intent: &BookingPageInviteGrantMintIntent,
        created_at: u64,
    ) -> Result<StandingOutboundGrant> {
        let policy = {
            let rtxn = self.store.env.read_txn()?;
            crate::gate::resolve_policy_manifest(&self.store, &rtxn)?
        };
        let grant = StandingOutboundGrant {
            principal_ref: intent.publisher_principal.to_hex(),
            origin_component_id: BOOKING_PAGE_INVITE_ORIGIN_COMPONENT_ID.to_owned(),
            origin_action_id: BOOKING_PAGE_INVITE_ORIGIN_ACTION_ID.to_owned(),
            origin_receipt_ref: None,
            scope: StandingOutboundGrantScope::BookingPageInvites {
                page_ref: intent.page_ref,
            },
            status: StandingOutboundGrantStatus::Active,
            created_at,
            revoked_at: None,
            last_used_at: None,
            binding_diff_handle: booking_page_invite_grant_binding_handle(intent),
            read_frontier_hash: policy.read_frontier_hash()?,
        };
        grant.validate()?;
        let data = encode_standing_outbound_grant_body(&grant)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::Record(RecordError::OutboundGrantAlreadyExists));
        }
        self.apply_standing_outbound_grant_body(&mut wtxn, id, created_at, data)?;
        wtxn.commit()?;
        Ok(grant)
    }

    /// Revokes a standing outbound grant by rewriting the same record as revoked.
    pub fn revoke_standing_outbound_grant(
        &self,
        id: &EntityId,
        revoked_at: u64,
    ) -> Result<StandingOutboundGrant> {
        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let grant = decode_standing_outbound_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let revoked = grant.revoked(revoked_at)?;
        let data = encode_standing_outbound_grant_body(&revoked)?;
        self.apply_standing_outbound_grant_body(&mut wtxn, id, revoked_at, data)?;
        wtxn.commit()?;
        Ok(revoked)
    }

    /// Reads and decodes a standing outbound grant record.
    pub fn get_standing_outbound_grant(
        &self,
        id: &EntityId,
    ) -> Result<Option<StandingOutboundGrant>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_standing_outbound_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    pub(crate) fn apply_standing_outbound_grant_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        let new_grant = decode_standing_outbound_grant_body(&data)?;
        let new_index_key =
            standing_outbound_grant_principal_index_key(&new_grant.principal_ref, id)?;
        let old_index_key = if let Some(raw) = self.store.entities.get(&*wtxn, id.as_bytes())? {
            let Some(header) = EntityMetadataHeader::parse(&raw) else {
                return Err(Error::CorruptedIndex("outbound grant entity header"));
            };
            if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
                return Err(Error::CorruptedIndex("outbound grant entity type"));
            }
            let old_grant = decode_standing_outbound_grant_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )?;
            Some(standing_outbound_grant_principal_index_key(
                &old_grant.principal_ref,
                id,
            )?)
        } else {
            None
        };
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_OUTBOUND_GRANT,
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
        )?;
        if let Some(old_index_key) = old_index_key.as_ref()
            && old_index_key != &new_index_key
        {
            self.store.vault_meta.delete(wtxn, old_index_key)?;
        }
        self.store.vault_meta.put(wtxn, &new_index_key, &[])?;
        Ok(())
    }
}

pub(crate) fn standing_outbound_grant_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<StandingOutboundGrant>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    decode_standing_outbound_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

fn scoped_mcp_grant_binding_handle(intent: &ScopedMcpGrantMintIntent) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    scoped_mcp_binding_hash_bytes(
        &mut hasher,
        b"oneiron.gate.standing_outbound_grant.scoped_mcp.v1",
    );
    scoped_mcp_binding_hash_str(&mut hasher, &intent.principal_ref);
    scoped_mcp_binding_hash_str(&mut hasher, &intent.origin_component_id);
    scoped_mcp_binding_hash_str(&mut hasher, &intent.origin_action_id);
    if let Some(origin_receipt_ref) = intent.origin_receipt_ref.as_deref() {
        scoped_mcp_binding_hash_str(&mut hasher, origin_receipt_ref);
    }
    scoped_mcp_binding_hash_str(&mut hasher, &intent.server);
    scoped_mcp_binding_hash_str(&mut hasher, &intent.tool);
    scoped_mcp_binding_hash_str(&mut hasher, intent.data_class_ceiling.as_str());
    for endpoint in &intent.endpoint_allowlist {
        scoped_mcp_binding_hash_str(&mut hasher, endpoint);
    }
    hasher.finalize().as_bytes().to_vec()
}

/// Content address for the page-publish decision behind one booking-page
/// grant. Its own domain tag: a booking-page handle can never be replayed as
/// an OF-336 escalator handle or as a scoped-tool one over the same bytes.
fn booking_page_invite_grant_binding_handle(intent: &BookingPageInviteGrantMintIntent) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    scoped_mcp_binding_hash_bytes(
        &mut hasher,
        b"oneiron.gate.standing_outbound_grant.booking_page_invites.v1",
    );
    scoped_mcp_binding_hash_bytes(&mut hasher, intent.publisher_principal.as_bytes());
    scoped_mcp_binding_hash_bytes(&mut hasher, intent.page_ref.as_bytes());
    hasher.finalize().as_bytes().to_vec()
}

fn scoped_mcp_binding_hash_str(hasher: &mut blake3::Hasher, value: &str) {
    scoped_mcp_binding_hash_bytes(hasher, value.as_bytes());
}

fn scoped_mcp_binding_hash_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}
