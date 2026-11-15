//! Moves a base reader's existing state across a worker boundary.
use super::*;

/// A base reader that owns its vault and all of its existing serving state.
/// It can lend a native reader for one operation, then return that same state.
pub struct OwnedScopedRead {
    actor_key: ScopedReadActorKey,
    audience: Option<Vec<EntityId>>,
    peer_reads: Vec<ScopedReadActorKey>,
    audience_cache: Mutex<crate::conversation::AudienceCache>,
    room_ceiling: Mutex<Option<Arc<RoomTurnCeiling>>>,
    room_ceilings_built: AtomicUsize,
    claim_status: ClaimReadStatus,
    recall_authority: Mutex<Option<crate::authority::AuthorityFold>>,
    room_peer: bool,
    own_owner_authority: bool,
    records_cover: records_cover::ArtifactRecordsCover,
    judged_at: Option<u64>,
    read_filter: Option<RetrievalFilter>,
    vault: Arc<crate::Vault>,
}

impl ScopedRead<'_> {
    /// Transfers only a base reader of this exact vault. An incompatible
    /// reader comes back unchanged; a session's overlay is never detached.
    pub fn into_owned_base(
        self,
        vault: Arc<crate::Vault>,
    ) -> std::result::Result<OwnedScopedRead, Self> {
        if self.session_view.is_some() || !std::ptr::eq(self.vault, vault.as_ref()) {
            return Err(self);
        }
        let Self {
            vault: _,
            session_view: _,
            actor_key,
            audience,
            peer_reads,
            audience_cache,
            room_ceiling,
            room_ceilings_built,
            claim_status,
            recall_authority,
            room_peer,
            own_owner_authority,
            records_cover,
            judged_at,
            read_filter,
        } = self;
        Ok(OwnedScopedRead {
            actor_key,
            audience,
            peer_reads,
            audience_cache,
            room_ceiling,
            room_ceilings_built,
            claim_status,
            recall_authority,
            room_peer,
            own_owner_authority,
            records_cover,
            judged_at,
            read_filter,
            vault,
        })
    }
}

impl OwnedScopedRead {
    /// Lends the same native base reader to one synchronous operation. Its
    /// caches and ceilings move back with the returned owner, not rebuilt.
    pub fn with_read<T>(self, operation: impl FnOnce(&ScopedRead<'_>) -> T) -> (Self, T) {
        let Self {
            actor_key,
            audience,
            peer_reads,
            audience_cache,
            room_ceiling,
            room_ceilings_built,
            claim_status,
            recall_authority,
            room_peer,
            own_owner_authority,
            records_cover,
            judged_at,
            read_filter,
            vault,
        } = self;
        let read = ScopedRead {
            vault: vault.as_ref(),
            session_view: None,
            actor_key,
            audience,
            peer_reads,
            audience_cache,
            room_ceiling,
            room_ceilings_built,
            claim_status,
            recall_authority,
            room_peer,
            own_owner_authority,
            records_cover,
            judged_at,
            read_filter,
        };
        let result = operation(&read);
        let ScopedRead {
            vault: _,
            session_view: _,
            actor_key,
            audience,
            peer_reads,
            audience_cache,
            room_ceiling,
            room_ceilings_built,
            claim_status,
            recall_authority,
            room_peer,
            own_owner_authority,
            records_cover,
            judged_at,
            read_filter,
        } = read;
        (
            Self {
                actor_key,
                audience,
                peer_reads,
                audience_cache,
                room_ceiling,
                room_ceilings_built,
                claim_status,
                recall_authority,
                room_peer,
                own_owner_authority,
                records_cover,
                judged_at,
                read_filter,
                vault,
            },
            result,
        )
    }

    /// Returns the same state to a borrowed base reader of this exact vault.
    pub fn into_borrowed<'a>(
        self,
        vault: &'a crate::Vault,
    ) -> std::result::Result<ScopedRead<'a>, Self> {
        self.into_borrowed_over(vault, None)
    }

    /// Returns the same state to a reader of this exact vault composed over
    /// `room`'s view (ARCH-0052 #e5-read-union-open, ONE-1729): the same
    /// admission and policy gates over the union the stretch can see. A
    /// room of another vault gives the owner back unchanged.
    pub fn into_borrowed_in_room<'a>(
        self,
        vault: &'a crate::Vault,
        room: &'a crate::off_record::RoomPackRead<'a>,
    ) -> std::result::Result<ScopedRead<'a>, Self> {
        if !room.is_of(vault) {
            return Err(self);
        }
        self.into_borrowed_over(vault, Some(&room.view))
    }

    fn into_borrowed_over<'a>(
        self,
        vault: &'a crate::Vault,
        session_view: Option<&'a crate::store::SessionStoreView<'a>>,
    ) -> std::result::Result<ScopedRead<'a>, Self> {
        if !std::ptr::eq(self.vault.as_ref(), vault) {
            return Err(self);
        }
        let Self {
            actor_key,
            audience,
            peer_reads,
            audience_cache,
            room_ceiling,
            room_ceilings_built,
            claim_status,
            recall_authority,
            room_peer,
            own_owner_authority,
            records_cover,
            judged_at,
            read_filter,
            vault: _,
        } = self;
        Ok(ScopedRead {
            vault,
            session_view,
            actor_key,
            audience,
            peer_reads,
            audience_cache,
            room_ceiling,
            room_ceilings_built,
            claim_status,
            recall_authority,
            room_peer,
            own_owner_authority,
            records_cover,
            judged_at,
            read_filter,
        })
    }
}
