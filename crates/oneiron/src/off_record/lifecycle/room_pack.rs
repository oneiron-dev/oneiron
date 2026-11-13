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

use super::session::{OffRecordSession, OffRecordSessionVault};
use super::telemetry::SessionRetrievalTelemetry;

/// The live stretch a context pack reads beside base, bound for its reader,
/// with the one write route its retrieval telemetry lands through.
pub struct RoomPackSession<'vault> {
    session: OffRecordSession<'vault>,
    route: SessionWriteRoute,
}

/// One pack's read of a [`RoomPackSession`]: the stretch's composed view, one
/// snapshot for the whole pack, and its retrieval telemetry door, so nothing
/// the pack derives from the room's rows lands in base.
pub struct RoomPackRead<'s> {
    pub(crate) view: SessionStoreView<'s>,
    pub(crate) telemetry: SessionRetrievalTelemetry<'s>,
}

impl<'vault> OffRecordSessionVault<'vault> {
    /// The stretch `key` names, bound for `reader` to read a context pack in.
    /// In a room `reader` must be on its roster, at bind and in every
    /// transaction the pack reads the stretch in. `None` when the pack reads
    /// base alone, as a pack did before: a ref no stretch can carry, a
    /// stretch that is gone, closing or closed, or a room `reader` is not in.
    ///
    /// # Errors
    ///
    /// Any other refusal binding the stretch or capturing its route.
    pub fn bind_pack_reader(
        &self,
        key: &str,
        reader: EntityId,
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
        let route = session.write_route()?;
        Ok(Some(RoomPackSession { session, route }))
    }
}

impl RoomPackRead<'_> {
    /// Whether this read composes over `vault`'s own store.
    pub(crate) fn is_of(&self, vault: &crate::Vault) -> bool {
        std::ptr::eq(self.telemetry.vault, vault)
    }
}

impl RoomPackSession<'_> {
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
