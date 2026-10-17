//! FIX 3134: an owner's own device holds a member FEDERATION_GRANT at its
//! home, so the device's residence selector names a real grant and keeps that
//! grant's ceiling. Pairing a device to a live owner provisions the owner's
//! grant (one serves every device they pair) and names it in the paired
//! slip's `grant_ref`, where the device reads it; the slip then stands only
//! while the grant does.
use super::{
    FederationGrant, FederationGrantPreset as GrantPreset, FederationGrantRole as Role,
    FederationGrantScope, decode_federation_grant_body, encode_federation_grant_body,
};
use crate::batch::{BatchOp, apply_ops};
use crate::error::Result;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, TimeRange, Vault};

/// The numeric grant scope the home's residence selector checks: its
/// single-vault selector ABI. Federation grants refuse zero, and FED-001
/// fixtures pin this value.
const OWN_DEVICE_RESIDENCE_VAULT_ID: u64 = 7;

/// The grant scope a residence selector's grant carries at the home; every
/// own-device grant is minted under it.
pub const fn own_device_residence_scope() -> FederationGrantScope {
    FederationGrantScope::vault(OWN_DEVICE_RESIDENCE_VAULT_ID)
}

/// Whether `grant` is an own-device grant: an Owner-role member grant under
/// the residence scope, neither delegated nor a guest's.
pub(crate) fn is_own_device_grant(grant: &FederationGrant) -> bool {
    grant.scope == own_device_residence_scope()
        && grant.role == Role::Owner
        && grant.delegated_by.is_none()
        && grant.guest.is_none()
}

impl Vault {
    /// For a slip being paired to `holder` (PERSON hex) with `actor_class`:
    /// when the holder is a live owner of this vault acting as a person (no
    /// class, or human), their own-device grant, ensured in the caller's
    /// writer. `None` for anyone else, and when the vault's Owner default
    /// would confer nothing.
    pub(crate) fn own_device_grant_for_holder_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        holder: &str,
        actor_class: Option<&str>,
        now: u64,
    ) -> Result<Option<EntityId>> {
        if actor_class.is_some_and(|class| class != crate::authority::ACTOR_CLASS_HUMAN) {
            return Ok(None);
        }
        let Ok(holder) = EntityId::from_hex(holder) else {
            return Ok(None);
        };
        if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &holder)? {
            return Ok(None);
        }
        if let Some(id) = self.own_device_grant_in_txn(txn, holder, now)? {
            return Ok(Some(id));
        }
        let mut grant = FederationGrant::new(
            own_device_residence_scope(),
            holder,
            Role::Owner,
            GrantPreset::Owner,
        );
        // The vault's stored Owner default, as for any membership row.
        grant.authority_scope = self.grant_default_scope_in_txn(
            txn,
            Role::Owner,
            OWN_DEVICE_RESIDENCE_VAULT_ID,
            holder,
        )?;
        if !grant.confers_at(now) {
            return Ok(None);
        }
        let id = self.store.clock.entity_id()?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data: encode_federation_grant_body(&grant)?,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(Some(id))
    }

    /// `owner`'s live own-device grant that confers at `now`, if any.
    fn own_device_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: EntityId,
        now: u64,
    ) -> Result<Option<EntityId>> {
        for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            txn,
            ENTITY_TYPE_FEDERATION_GRANT,
            None,
        )? {
            let id = id?;
            if self.own_device_grant_stands_in_txn(txn, id, &owner.to_hex(), now)? {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// Whether `grant_ref` is `member`'s (PERSON hex) own-device grant, live
    /// and conferring at `now`. A paired slip naming it stands while it does.
    pub(crate) fn own_device_grant_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant_ref: EntityId,
        member: &str,
        now: u64,
    ) -> Result<bool> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &grant_ref)?
        else {
            return Ok(false);
        };
        let grant = decode_federation_grant_body(&body)?;
        Ok(is_own_device_grant(&grant)
            && grant.member_ref.to_hex() == member
            && grant.confers_at(now))
    }
}
