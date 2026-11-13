//! A context pack's read of the live stretch its request names (ARCH-0052
//! #e5-read-union-open, ONE-1729): "a route that takes a room's turn should
//! bind the pack too". The stretch is bound for its reader, its write route
//! is captured once for the pack's retrieval telemetry (K10), and the pack
//! reads the stretch's composed overlay ∪ base view, as recall in a session
//! does.

use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::session_overlay::SessionWriteRoute;
use crate::store::SessionStoreView;

use super::room::{ROOM_KEY_PREFIX, is_member_in_txn};
use super::session::{OffRecordSession, OffRecordSessionVault};
use super::telemetry::SessionRetrievalTelemetry;

/// The live stretch a context pack reads beside base, bound for its reader,
/// with the one write route its retrieval telemetry lands through.
pub struct RoomPackSession<'vault> {
    session: OffRecordSession<'vault>,
    route: SessionWriteRoute,
    stretch: Option<StretchRoom>,
}

/// One pack's read of a [`RoomPackSession`]: the stretch's composed view, one
/// snapshot for the whole pack, and its retrieval telemetry door, so nothing
/// the pack derives from the room's rows lands in base.
pub struct RoomPackRead<'s> {
    pub(crate) view: SessionStoreView<'s>,
    pub(crate) telemetry: SessionRetrievalTelemetry<'s>,
    pub(crate) stretch: Option<StretchRoom>,
}

/// The room a room stretch's staged rows belong to, carried by a read
/// composed over that stretch (ARCH-0052 #e5-read-union-open = B). A stretch
/// stages every turn under one conversation shell of its own, minted at
/// entry and tied to the room by no row or edge, so a rule that finds a
/// row's room up its ancestry finds the shell, which is no room on base.
/// [`Self::room_of`] is the one point that maps the shell to its room, for
/// the grant walk, the audience walk and the own-entry windows alike: a
/// staged row meets its room's rules as a base row of that room does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StretchRoom {
    room: EntityId,
    shell: EntityId,
    member: Option<EntityId>,
}

impl StretchRoom {
    /// `conversation` as a row's room: the stretch's room for its shell,
    /// any other conversation as it is.
    pub(crate) fn room_of(&self, conversation: EntityId) -> EntityId {
        if conversation == self.shell {
            self.room
        } else {
            conversation
        }
    }

    /// The conversation shell the stretch stages its turns under.
    pub(crate) fn shell(&self) -> EntityId {
        self.shell
    }

    /// The member whose own sight bounds each row the stretch staged;
    /// `None` for the vault's owner, whom no window binds in their own
    /// vault's stretch, as the stretch's copy reads its talk.
    pub(crate) fn member(&self) -> Option<EntityId> {
        self.member
    }

    /// The same stretch read as `member` reads it: a room peer's own read.
    pub(crate) fn for_member(self, member: EntityId) -> Self {
        Self {
            member: Some(member),
            ..self
        }
    }

    /// Whether the member sees a row the stretch staged that occurred at
    /// `at` (D5, as `export_talk_for` reads the stretch's talk): on the
    /// room's roster in this snapshot and inside one of their own membership
    /// windows there, so a member who joined with no history sees nothing
    /// from before the join. The owner sees every row.
    ///
    /// # Errors
    ///
    /// The roster or the ledger not reading.
    pub(crate) fn sees_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        at: u64,
    ) -> Result<bool> {
        let Some(member) = self.member else {
            return Ok(true);
        };
        if !is_member_in_txn(vault, txn, self.room, member)? {
            return Ok(false);
        }
        Ok(vault
            .windows_in_txn(txn, self.room, member)?
            .iter()
            .any(|window| window.contains(at)))
    }
}

impl<'vault> OffRecordSessionVault<'vault> {
    /// The stretch `key` names, bound for `reader`, the vault's owner, to
    /// read a context pack in. In a room `reader` must be on its roster, at
    /// bind and in every transaction the pack reads the stretch in. `None`
    /// when the pack reads base alone, as a pack did before: a ref no stretch
    /// can carry, a stretch that is gone, closing or closed, or a room
    /// `reader` is not in. A key that names no room binds as
    /// [`Self::bind_for`] does, with no roster to check, so any other reader
    /// binds through [`Self::bind_pack_member`].
    ///
    /// # Errors
    ///
    /// Any other refusal binding the stretch or capturing its route.
    pub fn bind_pack_reader(
        &self,
        key: &str,
        reader: EntityId,
    ) -> Result<Option<RoomPackSession<'vault>>> {
        self.bind_pack(key, reader, None)
    }

    /// The stretch `key` names, bound for `member` of its room to read a
    /// context pack in (ARCH-0052 #e5-read-union-open = B, the lead's ruling
    /// 13 Nov 05:5x): a person or agent other than the owner reads a room's
    /// stretch only while on that room's roster, checked at bind and in
    /// every transaction the pack reads the stretch in, and each row is read
    /// under the member's own key, inside the member's own windows. `None`,
    /// for a base read, as [`Self::bind_pack_reader`] answers it, and also
    /// for a key that names no room: a stretch entered alone has no roster
    /// to admit a member by.
    ///
    /// # Errors
    ///
    /// As [`Self::bind_pack_reader`].
    pub fn bind_pack_member(
        &self,
        key: &str,
        member: EntityId,
    ) -> Result<Option<RoomPackSession<'vault>>> {
        if !key.starts_with(ROOM_KEY_PREFIX) {
            return Ok(None);
        }
        self.bind_pack(key, member, Some(member))
    }

    /// The stretch `key` names, bound for `reader`, with its room carried
    /// for the pack's read when it runs in one; `member` when `reader` reads
    /// as a member rather than as the owner.
    fn bind_pack(
        &self,
        key: &str,
        reader: EntityId,
        member: Option<EntityId>,
    ) -> Result<Option<RoomPackSession<'vault>>> {
        let session = match self.bind_for(key, reader) {
            Ok(session) => session,
            // Bind's one config refusal: a ref no stretch can carry.
            Err(Error::InvalidConfig(_)) => return Ok(None),
            Err(error) => return read_on_base(error),
        };
        let session = match session.for_participant(reader) {
            Ok(session) => session,
            Err(error) => return read_on_base(error),
        };
        let stretch = match stretch_room(&session, member) {
            Ok(stretch) => stretch,
            Err(error) => return read_on_base(error),
        };
        let route = session.write_route()?;
        Ok(Some(RoomPackSession {
            session,
            route,
            stretch,
        }))
    }
}

/// The room `session` runs in and the shell it stages under, for a read by
/// `member` (`None` for the owner); `None` for a stretch entered alone.
fn stretch_room(
    session: &OffRecordSession<'_>,
    member: Option<EntityId>,
) -> Result<Option<StretchRoom>> {
    let Some(room) = session.room()? else {
        return Ok(None);
    };
    Ok(Some(StretchRoom {
        room,
        shell: session.overlay_conversation_shell()?,
        member,
    }))
}

impl RoomPackRead<'_> {
    /// Whether this read composes over `vault`'s own store.
    pub(crate) fn is_of(&self, vault: &crate::Vault) -> bool {
        std::ptr::eq(self.telemetry.vault, vault)
    }
}

impl RoomPackSession<'_> {
    /// The room this stretch runs in; `None` for a stretch entered alone.
    #[must_use]
    pub fn room(&self) -> Option<EntityId> {
        self.stretch.map(|stretch| stretch.room)
    }

    /// `disclosure` bound to this room stretch, for a pack whose caller
    /// checked that every interlocutor is seated in the stretch's room
    /// (ARCH-0052 D5 rule 1; ROOM-PACK-STRETCH-TIER-A = A, from the owner's
    /// OFFRECORD-WORDS = A, ARCH-0052:18: "one-way mirror"). The stretch's
    /// own rows are then not Tier A by rule 1, so its reader reads them
    /// under the room's rules and the audience's clearance; a row of any
    /// other live room stays Tier A. A stretch entered alone has no room to
    /// seat anyone in, so its clamp stays as it was.
    #[must_use]
    pub fn bind_disclosure(
        &self,
        disclosure: crate::disclosure::DisclosureContext,
    ) -> crate::disclosure::DisclosureContext {
        if self.stretch.is_none() {
            return disclosure;
        }
        disclosure.bound_to_stretch(self.session.session_ref())
    }

    /// The pack's read of this stretch: one composed snapshot and the
    /// telemetry door over the route captured at bind.
    ///
    /// # Errors
    ///
    /// The route's revalidation (a flip or close since the bind) and the
    /// view's snapshot.
    pub fn read(&self) -> Result<RoomPackRead<'_>> {
        Ok(RoomPackRead {
            telemetry: self.session.retrieval_telemetry(&self.route)?,
            view: self.session.read_view()?,
            stretch: self.stretch,
        })
    }
}

/// `None`, for a base read, when `error` says the stretch is gone, closing
/// or closed, or that its reader is not in its room; any other error stands.
fn read_on_base<T>(error: Error) -> Result<Option<T>> {
    match error {
        Error::OffRecord(
            OffRecordError::OffRecordSessionNotFound { .. }
            | OffRecordError::OffRecordSessionClosing { .. }
            | OffRecordError::OffRecordNotInRoom { .. }
            | OffRecordError::OffRecordOverlayLeaseClosed { .. },
        ) => Ok(None),
        error => Err(error),
    }
}
