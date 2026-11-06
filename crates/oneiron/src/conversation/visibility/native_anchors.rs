//! Native inline rows' declared thread, room and occurred-time anchors.

use super::*;
use crate::store::GateReadAnchors;

#[derive(Clone, Copy)]
pub(super) enum AudiencePosition<'a> {
    Stored(EntityId, &'a [u8]),
    Anchors(&'a GateReadAnchors),
}

impl AudienceCache {
    /// The same audience rule as a stored row, over an inline row's own
    /// complete placement. No entity body or header is fabricated.
    pub(crate) fn anchors_readable_in(
        &mut self,
        vault: &Vault,
        dbs: &crate::store::StoreRead<'_>,
        txn: &heed::RoTxn<'_>,
        anchors: &GateReadAnchors,
        audience: &[EntityId],
        current: bool,
        personal: Option<EntityId>,
    ) -> Result<bool> {
        if !anchors.is_complete() || anchors.worlds().is_empty() {
            return Ok(false);
        }
        let Some(occurred) = anchors.occurred() else {
            return Ok(false);
        };
        for anchor in anchors.threads() {
            let allowed = if current {
                crate::workspace_roster::thread_root_readable_with_read_in(
                    vault,
                    dbs,
                    txn,
                    anchor.root,
                    audience,
                )?
            } else {
                crate::workspace_roster::thread_turn_readable_with_read_in(
                    vault,
                    dbs,
                    txn,
                    anchor.root,
                    anchor.turn,
                    audience,
                )?
            };
            if !allowed {
                return Ok(false);
            }
        }
        for root in anchors.reached() {
            if !crate::workspace_roster::thread_root_readable_with_read_in(
                vault, dbs, txn, *root, audience,
            )? {
                return Ok(false);
            }
        }
        for room in anchors.rooms() {
            if !self.room_readable_in(
                vault,
                txn,
                *room,
                occurred.start,
                audience,
                personal,
                Some(AudiencePosition::Anchors(anchors)),
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn room_readable_in(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        at: u64,
        audience: &[EntityId],
        personal: Option<EntityId>,
        record: Option<AudiencePosition<'_>>,
    ) -> Result<bool> {
        if audience.is_empty() {
            return Ok(false);
        }
        match body::body_in(vault, txn, room) {
            Ok(_) => {}
            Err(Error::EntityNotFound | Error::Record(RecordError::InvalidConversationBody(_))) => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
        if crate::workspace_roster::project_room_audience_in(vault, txn, room, &[])?.is_some() {
            if !project_audience_readable_in(vault, txn, room, audience, at, record)? {
                return Ok(false);
            }
        } else {
            let revision = membership::revision_in(&vault.store, txn, room)?;
            if !self.rows.contains_key(&(room, revision)) {
                if self.rows.len() >= 1024 {
                    self.rows.clear();
                }
                self.rows.insert(
                    (room, revision),
                    membership::rows_in(&vault.store, txn, room)?,
                );
                self.ledger_reads = self.ledger_reads.saturating_add(1);
            }
            let rows = self
                .rows
                .get(&(room, revision))
                .ok_or(Error::CorruptedIndex("audience snapshot"))?;
            // A seat's own read meets its own window alone (FIX 5667):
            // another member's join from now on never narrows it. A
            // reader with no seat here, a host or one on a Ready join,
            // meets every member's, as a held turn does.
            let mut seat = None;
            if let Some(reader) = personal
                && membership::windows_rows(rows, reader)?
                    .last()
                    .is_some_and(|window| window.to.is_none())
            {
                seat = Some(reader);
            }
            let checked = if seat.is_some() {
                seat.as_slice()
            } else {
                audience
            };
            for person in checked {
                // An unplaced speaker stays in the audience under the
                // cut its entry fact froze (ILDF2 P5): never dropped,
                // never wider than from its entry into this room. A live
                // Ready receipt for the room is current standing too
                // (OF-417); it is re-proved here, never cached, and so
                // is a private thread's Owner or Admin with no seat here
                // (FIX 5638): a seated one keeps its window (FIX 6268).
                let windows = membership::windows_rows(rows, *person)?;
                let seated = windows.last().is_some_and(|window| window.to.is_none());
                if !windows.iter().any(|w| w.contains(at))
                    && !attendee::speaker_entry_covers_in(vault, txn, room, *person, at)?
                    && !crate::workspace_roster::room_join_audience_in(vault, txn, room, *person)?
                    && (seated || !privileged_thread_reader_in(vault, txn, room, record, *person)?)
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

pub(super) fn privileged_anchor_reader_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    anchors: &GateReadAnchors,
    viewer: EntityId,
) -> Result<bool> {
    let mut placed = false;
    for root in anchors
        .threads()
        .iter()
        .map(|anchor| anchor.root)
        .chain(anchors.reached().iter().copied())
    {
        if room_for_record_in(vault, txn, root)? != Some(room) {
            continue;
        }
        placed = true;
        if !crate::workspace_roster::privileged_private_thread_reader_in(
            vault, txn, room, root, viewer,
        )? {
            return Ok(false);
        }
    }
    Ok(placed)
}
