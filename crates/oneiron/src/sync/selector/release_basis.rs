//! What a selector answer is made under, so the socket that queued it can
//! judge it again where it leaves (SELECTOR-RELEASE-POINT = B, a lead
//! ruling, Sun 15 Nov 19:26). ARCH-0077: "Revocation is not rollback. Queued
//! work follows the current Grant decision".
//!
//! The basis is the grant decision's inputs, read in one snapshot:
//! - the grant's live stored bytes, while the grant confers read at the
//!   second they are read: a delegate past its expiry has no basis, as the
//!   selector door refuses it (ONE-1409);
//! - the authority fold the selector door reads (pacts, their bindings and
//!   ceilings), from the snapshot-bound view, so a read takes no writer;
//! - the reach the grant's member reads relationship labels with (FIX
//!   SELECTOR-RELATIONSHIP-LABELS): its live access grants and relationship
//!   memberships, or none for an Owner's member, who reads every row. An
//!   access grant is stored outside the authority log, so the fold does not
//!   show its revocation or expiry.
//!
//! A basis stands while a fresh read equals it. The rows an answer carries
//! are content, not authority, and are not compared: an unrelated write
//! never drops an answer.

use crate::Vault;
use crate::access_grant::AccessContextSnapshot;
use crate::authority::AuthorityView;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::federation::{decode_federation_grant_body, live_federation_grant_in};

/// What a selector answer under one grant was made under.
pub struct SelectorReleaseBasis {
    grant_id: EntityId,
    /// `None` when the grant was gone or conferred no read, or a read
    /// failed: such a basis never stands.
    made_under: Option<MadeUnder>,
}

impl SelectorReleaseBasis {
    /// The basis of an answer under the grant `grant_id`, read now.
    #[must_use]
    pub fn take(vault: &Vault, grant_id: EntityId) -> Self {
        Self {
            made_under: MadeUnder::read(vault, &grant_id),
            grant_id,
        }
    }

    /// The grant the answer is made under.
    #[must_use]
    pub fn grant_id(&self) -> &EntityId {
        &self.grant_id
    }

    /// Whether what the answer was made under stands now: the grant still
    /// confers read, and its bytes, the authority fold and its member's
    /// reach read as they did.
    #[must_use]
    pub fn stands(&self, vault: &Vault) -> bool {
        self.made_under.as_ref().is_some_and(|made_under| {
            MadeUnder::read(vault, &self.grant_id).is_some_and(|now| now.same(made_under))
        })
    }
}

struct MadeUnder {
    grant: Vec<u8>,
    authority: AuthorityView,
    /// `None` for an Owner's member, which reads every row.
    member: Option<AccessContextSnapshot>,
}

impl MadeUnder {
    fn read(vault: &Vault, grant_id: &EntityId) -> Option<Self> {
        // The second the selector door judges expiry at, read before its
        // snapshot as the door reads it.
        let now = vault.now_recorded_at();
        let txn = vault.store.env.read_txn().ok()?;
        let grant = live_federation_grant_in(vault, &txn, grant_id).ok()?;
        let decoded =
            decode_federation_grant_body(grant.get(ENTITY_METADATA_HEADER_LEN..)?).ok()?;
        if !decoded.confers_at(now) {
            return None;
        }
        Some(Self {
            authority: vault.authority_view_readonly_in_txn(&txn).ok()?,
            member: super::authorize::member_label_access(vault, &txn, &decoded)
                .ok()?
                .map(|access| access.snapshot().clone()),
            grant,
        })
    }

    fn same(&self, other: &Self) -> bool {
        self.grant == other.grant
            && self.authority.same_image(&other.authority)
            && match (&self.member, &other.member) {
                (None, None) => true,
                (Some(member), Some(other)) => member.same_reach(other),
                _ => false,
            }
    }
}
