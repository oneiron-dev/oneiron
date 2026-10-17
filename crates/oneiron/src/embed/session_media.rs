//! The session-aware media door (OF-370): a media vector written while a room is off record
//! stays in the room.
//!
//! [`Vault::put_media_vector`] writes base. A host that embeds a record an off-record room holds
//! writes here instead: the vector stages into the room's overlay as one typed, journaled
//! `BatchOp::MediaVector`, owned by a turn of the room, so session recall's media channel reads
//! it through the room's view and base never holds it. Promoting the turn replays it into base;
//! closing the room drops it. A room on record writes base, while its saver holds.

use super::space::{InputKind, media_text_hash_of};
use crate::Vault;
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::off_record::OffRecordSession;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_TURN;
use crate::session_overlay::{JournalEntry, JournalRole, JournalScope, RouteTarget};
use crate::temporal::TimeRange;

impl Vault {
    /// Stores one host-computed media vector of record `id` in `space_id` through `session`'s
    /// own write route. While the room is off record the vector stages in the room, owned by
    /// its `turn`, and promotion carries it into base with that turn; once the room is on
    /// record it lands in base as [`Self::put_media_vector`] does, while the room's saver holds.
    /// A text vector is of the record's current text as the room reads it.
    ///
    /// # Errors
    ///
    /// [`Error::InvariantViolation`] for a session of another vault; [`Error::EntityNotFound`]
    /// when the room holds no record `id` or no TURN `turn`; [`Error::InvalidConfig`] when the
    /// space is undeclared, no slot binds or moves `kind` to it, or a text record holds no text;
    /// [`Error::DimensionMismatch`] for a vector of another width. An anonymous room records
    /// nothing, so it refuses.
    pub fn put_session_media_vector(
        &self,
        session: &OffRecordSession<'_>,
        turn: &EntityId,
        space_id: &str,
        id: &EntityId,
        kind: InputKind,
        vector: &[f32],
    ) -> Result<()> {
        if session.vault_id() != self.vault_id() {
            return Err(Error::InvariantViolation(
                "a session media write names a session of another vault",
            ));
        }
        let route = session.write_route()?;
        route.require_recording(session.session_ref())?;
        if route.target() == RouteTarget::Base {
            return session.with_saver_write_txn(session.saver_check_for(&route)?, |wtxn| {
                self.put_base_media_vector_in_txn(wtxn, space_id, id, kind, vector)
            });
        }
        let conversation = session.overlay_conversation_shell()?;
        session.overlay_write_routed(&route, |wtxn, apply| {
            let text_hash = {
                let view = session.read_view()?;
                if view.port_entity_record(&*wtxn, id)?.is_none() {
                    return Err(Error::EntityNotFound);
                }
                if view
                    .port_entity_record(&*wtxn, turn)?
                    .is_none_or(|row| row.entity_type != ENTITY_TYPE_TURN)
                {
                    return Err(Error::EntityNotFound);
                }
                // A record the room holds promotes with the turn that put it,
                // so its vector rides that turn: under another one, promote
                // would replay it into base without its record.
                if view.entities.stages_row(id.as_bytes())
                    && !session
                        .overlay()
                        .snapshot()?
                        .journal_entries()
                        .iter()
                        .any(|entry| {
                            entry.scope.turn() == *turn
                                && matches!(&entry.op, BatchOp::Put { id: put, .. } if put == id)
                        })
                {
                    return Err(Error::InvalidConfig(
                        "a record the room holds takes its media vector under the turn that put it"
                            .into(),
                    ));
                }
                media_text_hash_of(self, &view, &*wtxn, id, kind)?
            };
            let at = self.store.clock.now_recorded_at();
            apply(
                wtxn,
                JournalEntry {
                    scope: JournalScope::new(conversation, *turn),
                    role: JournalRole::TurnOwnedArtifact,
                    learned_at: at,
                    occurred: TimeRange { start: at, end: at },
                    op: BatchOp::MediaVector {
                        space: space_id.to_owned(),
                        id: *id,
                        kind,
                        text_hash,
                        vector: vector.to_vec(),
                    },
                },
            )
        })
    }
}
