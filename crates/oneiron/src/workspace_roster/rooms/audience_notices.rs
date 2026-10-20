//! What a private thread's members are told, and the audience its own view
//! shows them (owner ruling 2026-10-20, FIX 6381, 6383).
//!
//! # Notices
//!
//! A walk-in, an opened full history, the Owner's add with full history
//! from outside the thread and the Owner's export of the vault tell every
//! member of the thread now, the walker included: one inbox NOTIFICATION
//! each, of the existing `Finding` kind, naming the thread's root, who acted
//! and what happened, never a name, a title or a turn's words. No notice
//! attaches to the room, whose members off the thread do not learn of it.
//! A notice never fails or undoes what it tells of: the doors here tell
//! after their edit committed, in a write of their own, and a member whose
//! notice is not written is logged and skipped.
//!
//! # The member list
//!
//! `vault.rooms.get` shows a reader in a private thread's audience now
//! that audience, and each walk-in that entered and each opened history,
//! read from the thread's own edits, whatever of its talk they read.

use super::audience::{names_actor_in, root_audience_in, thread_binding};
use super::audience_events::AudienceOp;
use super::liveness::{RoomThread, RoomThreadAudienceEvent, RoomThreadAudienceOp};
use super::*;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::registry::ENTITY_TYPE_TURN;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The producer a private thread's notices are recorded under; a read
/// admits such a notice to its recipient and the thread's readers alone
/// (FIX 6473).
pub(crate) const THREAD_NOTICE_PRODUCER: &str = "rooms.private_thread";

/// What a private thread's members are told (FIX 6381, 6383; owner ruling
/// RT-EXPORT). Each names what it tells of, so a notice is written once per
/// member, however often it is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadNotice {
    /// The acting person walked in, reading from now on; `event` is the
    /// walk-in's audience edit TURN.
    WalkIn { event: EntityId },
    /// The Owner opened the thread's full history to themselves; `event` is
    /// that audience edit TURN.
    OpenFullHistory { event: EntityId },
    /// The Owner, from outside the thread, added `person` with its full
    /// history; `event` is that audience edit TURN.
    OwnerAddedFullHistory { event: EntityId, person: EntityId },
    /// The Owner exported the vault, this thread included; `export` names
    /// that export, a fresh id where it has none.
    VaultExported { export: EntityId },
}

impl ThreadNotice {
    /// The notice's op, as its NOTIFICATION names it.
    const fn op(self) -> &'static str {
        match self {
            Self::WalkIn { .. } => "walk_in",
            Self::OpenFullHistory { .. } => "open_full_history",
            Self::OwnerAddedFullHistory { .. } => "owner_added_full_history",
            Self::VaultExported { .. } => "vault_exported",
        }
    }

    /// What the notice tells of: the audience edit, or the export.
    const fn occasion(self) -> EntityId {
        match self {
            Self::WalkIn { event }
            | Self::OpenFullHistory { event }
            | Self::OwnerAddedFullHistory { event, .. } => event,
            Self::VaultExported { export } => export,
        }
    }
}

/// Tells every member of the private thread rooted at `root` now, the
/// walker included, `notice` of `actor`'s act, in the caller's `txn`: one
/// `Finding` NOTIFICATION each, for that member alone, naming the root, the
/// actor, the op and the person added, if any. Best-effort: it never fails
/// or rolls back its caller. A member whose notice is not written, or a
/// thread whose members do not read, is logged and skipped, so a caller
/// whose own write must stand tells after it commits.
pub(crate) fn notify_thread_members_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    root: EntityId,
    actor: EntityId,
    notice: ThreadNotice,
) {
    let members = match thread_members_now_in(vault, txn, root) {
        Ok(members) => members,
        Err(error) => {
            tracing::warn!(
                thread = %root.to_hex(),
                op = notice.op(),
                %error,
                "private thread notice: members not read"
            );
            return;
        }
    };
    let at = match crate::ports::recorded_at_in_txn(&vault.store, txn) {
        Ok(at) => at,
        Err(error) => {
            tracing::warn!(
                thread = %root.to_hex(),
                op = notice.op(),
                %error,
                "private thread notice: no time"
            );
            return;
        }
    };
    let mut subjects = vec![root, actor];
    if let ThreadNotice::OwnerAddedFullHistory { person, .. } = notice {
        subjects.push(person);
    }
    for member in members {
        let event = NotificationEvent {
            kind: NotificationKind::Finding,
            source: NotificationSource {
                producer: THREAD_NOTICE_PRODUCER.to_owned(),
                event: format!(
                    "{}:{}:{}:{}",
                    notice.op(),
                    root.to_hex(),
                    notice.occasion().to_hex(),
                    member.to_hex()
                ),
                result: Some(root.to_hex()),
                detail: Some(notice.op().to_owned()),
                ..NotificationSource::default()
            },
            subject_refs: subjects.clone(),
            recipient: Some(member),
            created_at: at,
            origin_conversation: None,
        };
        if let Err(error) = vault.record_notification_in_txn(txn, &event) {
            tracing::warn!(
                thread = %root.to_hex(),
                member = %member.to_hex(),
                op = notice.op(),
                %error,
                "private thread notice not written"
            );
        }
    }
}

/// [`notify_thread_members_in_txn`] in a write of its own, after the write
/// that made `notice` committed: nothing it meets undoes that write.
pub(super) fn tell_thread_members(
    vault: &Vault,
    root: EntityId,
    actor: EntityId,
    notice: ThreadNotice,
) {
    let told = vault.with_write_txn(|txn| {
        crate::workspace_roster::notify_thread_members_in_txn(vault, txn, root, actor, notice);
        Ok(())
    });
    if let Err(error) = told {
        tracing::warn!(
            thread = %root.to_hex(),
            op = notice.op(),
            %error,
            "private thread notice: write failed"
        );
    }
}

/// Everyone in the audience of the private thread rooted at `root` now; no
/// one for a root that is no live private root.
fn thread_members_now_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
) -> Result<BTreeSet<EntityId>> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_TURN,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, &root)?
    else {
        return Ok(BTreeSet::new());
    };
    let Some(binding) = thread_binding(&body)?.filter(|binding| binding.root == root) else {
        return Ok(BTreeSet::new());
    };
    match root_audience_in(vault, txn, binding.room, root) {
        Ok(folded) => Ok(folded.map_or_else(BTreeSet::new, |folded| folded.current())),
        Err(Error::EntityNotFound) => Ok(BTreeSet::new()),
        Err(error) => Err(error),
    }
}

impl Memory<'_> {
    /// `thread`, the thread rooted at `root` in `room` as `vault.rooms.get`
    /// read it, with its audience now and its walk-ins and opened histories
    /// when it is private and this actor is in its audience now (FIX 6381):
    /// a reader that view already admits. A public thread, and any other
    /// reader, gets it as it was, and so does one whose audience does not
    /// read, logged: the enrichment never fails the read.
    pub(super) fn with_thread_audience(
        &self,
        room: EntityId,
        root: EntityId,
        thread: Option<RoomThread>,
    ) -> MemoryResult<Option<RoomThread>> {
        let Some(mut thread) = thread else {
            return Ok(None);
        };
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        match self.thread_audience_view_in(&txn, room, root) {
            Ok(Some((audience, events))) => {
                thread.audience = audience;
                thread.audience_events = events;
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(
                thread = %root.to_hex(),
                %error,
                "private thread view: audience not read"
            ),
        }
        Ok(Some(thread))
    }

    /// The audience now of the private thread rooted at `root` in `room`,
    /// 32-hex each, and its walk-ins that entered and opened histories, in
    /// order; `None` for a public thread, or a reader off its audience now.
    fn thread_audience_view_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        root: EntityId,
    ) -> Result<Option<(Vec<String>, Vec<RoomThreadAudienceEvent>)>> {
        let vault = self.vault();
        let folded = match root_audience_in(vault, txn, room, root) {
            Ok(Some(folded)) => folded,
            Ok(None) | Err(Error::EntityNotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        let current = folded.current();
        if !names_actor_in(vault, txn, &current, self.actor())? {
            return Ok(None);
        }
        let mut events = Vec::new();
        for (event, op, person) in folded.entries() {
            let op = match op {
                AudienceOp::WalkIn => RoomThreadAudienceOp::WalkIn,
                AudienceOp::OpenFullHistory => RoomThreadAudienceOp::OpenFullHistory,
                AudienceOp::Add | AudienceOp::Remove => continue,
            };
            let at = vault
                .entity_header_in_txn(txn, event)?
                .map_or(0, |header| header.occurred_start);
            events.push(RoomThreadAudienceEvent {
                event_ref: event.to_hex(),
                op,
                person_ref: person.live().map(|person| person.to_hex()),
                at,
            });
        }
        Ok(Some((
            current.iter().map(EntityId::to_hex).collect(),
            events,
        )))
    }
}
