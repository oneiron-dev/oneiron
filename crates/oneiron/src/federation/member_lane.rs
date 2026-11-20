//! MEMBER-SYNC D1: a shared-vault member's standing to hold a selector-only
//! sync lane at this home (H8-SHARED-ENV-LANE = B: "a slip whose grant_ref
//! names its holder's live member grant gets a selector-only socket, with no
//! root snapshot and no legacy full lane").
//!
//! The home derives the grant scope from its own shared-vault creation, never
//! from the caller, and asks the exact first-party gate
//! ([`Vault::authenticated_grant_membership_in_txn`]) about the one grant the
//! slip names. Membership opens the restricted carrier; each selector the lane
//! sends is still judged by `authorize_sync_selector` under that scope.

use super::{FederationGrantRole, FederationGrantScope, MembershipStanding, Scope};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::{EntityId, Vault};

/// What a member lane stands on at this home: the grant its slip names, the
/// PERSON holding it, the scope the home derived from its own shared-vault
/// creation, the grant's role and the grant's own authority. Fixed for the
/// lane's life; re-asked through [`Vault::member_lane_standing`] before each
/// read and flush, so a grant whose role or authority changed stops the lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberLaneStanding {
    pub grant: EntityId,
    pub holder: EntityId,
    pub scope: FederationGrantScope,
    pub role: FederationGrantRole,
    /// The grant's `authority_scope`: a member slip minted under it carries
    /// it whole, and the lane admits only a slip that does (the selector,
    /// document and body doors filter by the grant, not by the slip).
    pub authority_scope: Scope,
}

impl Vault {
    /// The standing `holder` has here to hold a member lane under `grant`, or
    /// `None`. It stands only when, in one read: `holder` names a live PERSON;
    /// this vault is an undeleted shared vault; and `grant` is a live
    /// FEDERATION_GRANT naming `holder` under this shared vault's own scope,
    /// unexpired, active under its pact, with a first-party member role
    /// ([`MembershipStanding::Member`]). A Connect or Ask guest grant, a grant
    /// of another vault, an own-device grant and an agent holder all answer
    /// `None`. Proving the credential and its transport stays the caller's.
    pub fn member_lane_standing(
        &self,
        holder: EntityId,
        grant: EntityId,
    ) -> Result<Option<MemberLaneStanding>> {
        let txn = self.store.env.read_txn()?;
        if !crate::consent::person_is_live_in_txn(self, &txn, &holder)? {
            return Ok(None);
        }
        let Some(creation) = self.shared_vault_creation_in_txn(&txn)? else {
            return Ok(None);
        };
        let scope = FederationGrantScope::vault(creation.vault_id);
        match self.authenticated_grant_membership_in_txn(&txn, scope, holder, grant)? {
            Some(MembershipStanding::Member {
                grant: standing,
                role,
            }) if standing == grant => {
                // The gate read this row live in `txn`; its body names the
                // grant's own authority.
                let Some(record) = self.store.port_entity_record(&txn, &grant)? else {
                    return Ok(None);
                };
                let raw = record.encode();
                let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
                    return Ok(None);
                };
                Ok(Some(MemberLaneStanding {
                    grant,
                    holder,
                    scope,
                    role,
                    authority_scope: super::decode_federation_grant_body(body)?.authority_scope,
                }))
            }
            _ => Ok(None),
        }
    }
}
