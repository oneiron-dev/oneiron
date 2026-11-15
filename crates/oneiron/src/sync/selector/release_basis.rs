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
//!   show its revocation or expiry;
//! - for a forwarded search, the reach of the caller it reads for
//!   ([`SelectorReaderReach`]): the caller's own access grants decide what it
//!   reads, beside the selector's ceiling. Its credential's standing is the
//!   fold's.
//!
//! Each reach is read on the authorization clock every access decision
//! reads, observed first, so a grant past its expiry is not loaded.
//!
//! A basis stands while a fresh read equals it. The rows an answer carries
//! are content, not authority, and are not compared: an unrelated write
//! never drops an answer.

use crate::Vault;
use crate::access_grant::AccessContextSnapshot;
use crate::authority::AuthorityView;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::ScopedReadActorKey;
use crate::entity_id::EntityId;
use crate::federation::{decode_federation_grant_body, live_federation_grant_in};

/// What a selector answer under one grant was made under.
pub struct SelectorReleaseBasis {
    grant_id: EntityId,
    /// `None` when the grant was gone or conferred no read, or a read
    /// failed: such a basis never stands.
    made_under: Option<MadeUnder>,
    /// The reach of the forwarded caller the answer was read for, if any.
    reader: Option<SelectorReaderReach>,
}

impl SelectorReleaseBasis {
    /// The basis of an answer under the grant `grant_id`, read now.
    #[must_use]
    pub fn take(vault: &Vault, grant_id: EntityId) -> Self {
        Self {
            made_under: MadeUnder::read(vault, &grant_id),
            grant_id,
            reader: None,
        }
    }

    /// The basis of an answer read for the forwarded caller whose reach
    /// `reader` holds, taken before that read: the answer stands only while
    /// that reach does too.
    #[must_use]
    pub fn reading_for(mut self, reader: Option<SelectorReaderReach>) -> Self {
        self.reader = reader;
        self
    }

    /// The grant the answer is made under.
    #[must_use]
    pub fn grant_id(&self) -> &EntityId {
        &self.grant_id
    }

    /// Whether what the answer was made under stands now: the grant still
    /// confers read, and its bytes, the authority fold, its member's reach
    /// and a forwarded caller's reach read as they did.
    #[must_use]
    pub fn stands(&self, vault: &Vault) -> bool {
        self.made_under.as_ref().is_some_and(|made_under| {
            MadeUnder::read(vault, &self.grant_id).is_some_and(|now| now.same(made_under))
        }) && self
            .reader
            .as_ref()
            .is_none_or(|reader| reader.stands(vault))
    }
}

/// The reach of the caller a forwarded search reads for: its own live
/// access grants and relationship memberships, which decide what it reads
/// beside the selector's ceiling.
pub struct SelectorReaderReach {
    principal: EntityId,
    /// `None` when the read failed: such a reach never stands.
    reach: Option<AccessContextSnapshot>,
}

impl SelectorReaderReach {
    /// The reach a read under `reader` loads, read now; `None` for a reader
    /// that loads no principal's grants.
    #[must_use]
    pub fn take(vault: &Vault, reader: &ScopedReadActorKey) -> Option<Self> {
        let principal = reader.access_principal()?;
        Some(Self {
            principal,
            reach: read_reach(vault, principal),
        })
    }

    fn stands(&self, vault: &Vault) -> bool {
        self.reach.as_ref().is_some_and(|reach| {
            read_reach(vault, self.principal).is_some_and(|now| now.same_reach(reach))
        })
    }
}

/// The reach of `principal`, read now on the authorization clock, observed
/// first as [`Vault::access_context`] observes it.
fn read_reach(vault: &Vault, principal: EntityId) -> Option<AccessContextSnapshot> {
    vault.store.authorization_now().ok()?;
    let txn = vault.store.env.read_txn().ok()?;
    AccessContextSnapshot::load(vault, &txn, Some(principal)).ok()
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
        // The member's reach is read on the authorization clock, observed
        // first as every access decision observes it: a grant past its
        // expiry is not loaded once the clock's lease has lapsed.
        vault.store.authorization_now().ok()?;
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
