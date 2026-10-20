//! What a private thread's members are told, and the audience its own view
//! shows them (owner ruling 2026-10-20, FIX 6381, 6383).
//!
//! # Notices
//!
//! A walk-in, an opened full history, the Owner's add with full history
//! from outside the thread and the Owner's export of the vault tell every
//! member of the thread now, the walker included: one inbox NOTIFICATION
//! each, naming the thread's root, who acted and what happened, never a
//! name, a title or a turn's words. A walk-in is a `ThreadWalkIn`, an
//! opened history either way a `ThreadHistoryOpened`, and an export a
//! `Finding` (FIX 6466). A request to join asks every member, one
//! `ThreadJoinRequested` each (FIX 6381, 6384, 6466); its approval or
//! denial tells the one who asked alone, as a `Finding`, naming no member.
//! A member is everyone the thread's audience names now, and each live pen
//! it admits through its PERSON anchor, told under the pen's own id (FIX
//! 6472). No notice attaches to the room, whose members off the thread do
//! not learn of it.
//! A notice never fails or undoes what it tells of: the doors here tell
//! after their edit committed, in a write of their own, and a member whose
//! notice is not written is logged and skipped.
//!
//! A thread's members are read from its root on base, or, for a root only
//! a live off-record stretch's published overlay holds, from that overlay
//! composed with base, its audience still read on base.
//!
//! # The member list
//!
//! `vault.rooms.get` shows a reader in a private thread's audience now
//! that audience, and each walk-in that entered and each opened history,
//! read from the thread's own edits, whatever of its talk they read.

use super::audience::{names_actor_in, resolved_root_in, root_audience_in, thread_binding};
use super::audience_events::{AudienceOp, fold_audience_in};
use super::liveness::{RoomThread, RoomThreadAudienceEvent, RoomThreadAudienceOp};
use super::*;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_TURN};
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
    /// The acting person asked to join; `event` is the request's audience
    /// TURN, which a member approves or denies. Asks every member.
    JoinRequested { event: EntityId },
    /// A member approved the request `request`; `event` is the add it
    /// wrote. Tells the one who asked alone.
    JoinApproved { event: EntityId, request: EntityId },
    /// A member denied the request `request`; `event` is the denial. Tells
    /// the one who asked alone.
    JoinDenied { event: EntityId, request: EntityId },
}

impl ThreadNotice {
    /// The notice's op, as its NOTIFICATION names it.
    const fn op(self) -> &'static str {
        match self {
            Self::WalkIn { .. } => "walk_in",
            Self::OpenFullHistory { .. } => "open_full_history",
            Self::OwnerAddedFullHistory { .. } => "owner_added_full_history",
            Self::VaultExported { .. } => "vault_exported",
            Self::JoinRequested { .. } => "join_requested",
            Self::JoinApproved { .. } => "join_approved",
            Self::JoinDenied { .. } => "join_denied",
        }
    }

    /// What the notice tells of: the audience edit, or the export.
    const fn occasion(self) -> EntityId {
        match self {
            Self::WalkIn { event }
            | Self::OpenFullHistory { event }
            | Self::OwnerAddedFullHistory { event, .. }
            | Self::JoinRequested { event }
            | Self::JoinApproved { event, .. }
            | Self::JoinDenied { event, .. } => event,
            Self::VaultExported { export } => export,
        }
    }

    /// What the notice names besides the thread's root: who acted, and the
    /// person added or the request answered. An answer to a request names
    /// no member, its approver or denier included.
    fn subjects(self, root: EntityId, actor: EntityId) -> Vec<EntityId> {
        match self {
            Self::OwnerAddedFullHistory { person, .. } => vec![root, actor, person],
            Self::JoinRequested { event } => vec![root, actor, event],
            Self::JoinApproved { event, request } | Self::JoinDenied { event, request } => {
                vec![root, request, event]
            }
            Self::WalkIn { .. } | Self::OpenFullHistory { .. } | Self::VaultExported { .. } => {
                vec![root, actor]
            }
        }
    }

    /// The NOTIFICATION kind it is written as (FIX 6466): a walk-in, an
    /// opened full history and a request to join each its own thread kind;
    /// anything else tells as a finding.
    const fn kind(self) -> NotificationKind {
        match self {
            Self::WalkIn { .. } => NotificationKind::ThreadWalkIn,
            Self::OpenFullHistory { .. } | Self::OwnerAddedFullHistory { .. } => {
                NotificationKind::ThreadHistoryOpened
            }
            Self::JoinRequested { .. } => NotificationKind::ThreadJoinRequested,
            Self::VaultExported { .. } | Self::JoinApproved { .. } | Self::JoinDenied { .. } => {
                NotificationKind::Finding
            }
        }
    }
}

/// Tells every member of the private thread rooted at `root` now, the
/// walker included, `notice` of `actor`'s act, in the caller's `txn`: one
/// NOTIFICATION of the notice's kind each, for that member alone, naming
/// the root, the actor, the op and the person added, if any. A live pen
/// the audience admits through its PERSON anchor is a member too (FIX
/// 6472), told once under its own id. Best-effort: it never fails or rolls
/// back its caller. A member whose notice is not written, or a thread
/// whose members do not read, is logged and skipped, so a caller whose own
/// write must stand tells after it commits.
pub(crate) fn notify_thread_members_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    root: EntityId,
    actor: EntityId,
    notice: ThreadNotice,
) {
    let audience = match thread_members_now_in(vault, txn, root) {
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
    // A pen not read is told nothing more; the audience it names still is.
    let members = match with_anchored_pens_in(vault, txn, &audience) {
        Ok(members) => members,
        Err(error) => {
            tracing::warn!(
                thread = %root.to_hex(),
                op = notice.op(),
                %error,
                "private thread notice: pens not read"
            );
            audience
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
    for member in members {
        record_notice_in_txn(vault, txn, root, actor, notice, member, at);
    }
}

/// Writes `notice` of `actor`'s act on the thread rooted at `root` for
/// `recipient` alone, at `at`. Best-effort: a notice not written is logged.
fn record_notice_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    root: EntityId,
    actor: EntityId,
    notice: ThreadNotice,
    recipient: EntityId,
    at: u64,
) {
    let event = NotificationEvent {
        kind: notice.kind(),
        source: NotificationSource {
            producer: THREAD_NOTICE_PRODUCER.to_owned(),
            event: format!(
                "{}:{}:{}:{}",
                notice.op(),
                root.to_hex(),
                notice.occasion().to_hex(),
                recipient.to_hex()
            ),
            result: Some(root.to_hex()),
            detail: Some(notice.op().to_owned()),
            ..NotificationSource::default()
        },
        subject_refs: notice.subjects(root, actor),
        recipient: Some(recipient),
        created_at: at,
        origin_conversation: None,
    };
    if let Err(error) = vault.record_notification_in_txn(txn, &event) {
        tracing::warn!(
            thread = %root.to_hex(),
            recipient = %recipient.to_hex(),
            op = notice.op(),
            %error,
            "private thread notice not written"
        );
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

/// [`ThreadNotice`]'s answer to a request to join, `notice`, for `requester`
/// alone, in a write of its own after the answer committed: nothing it
/// meets undoes that answer.
pub(super) fn tell_requester(
    vault: &Vault,
    root: EntityId,
    actor: EntityId,
    requester: EntityId,
    notice: ThreadNotice,
) {
    let told = vault.with_write_txn(|txn| {
        match crate::ports::recorded_at_in_txn(&vault.store, txn) {
            Ok(at) => record_notice_in_txn(vault, txn, root, actor, notice, requester, at),
            Err(error) => tracing::warn!(
                thread = %root.to_hex(),
                op = notice.op(),
                %error,
                "private thread notice: no time"
            ),
        }
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

/// `audience` and each live pen it admits through the PERSON its subject
/// anchor names now ([`names_actor_in`], FIX 6472), each once: a pen is
/// told under its own id, beside its PERSON. Only a pen whose PERSON the
/// audience names is added, never anyone else of the room. Every AGENT_DEF
/// is read, however many (rule 5).
fn with_anchored_pens_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    audience: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let mut members = audience.clone();
    if audience.is_empty() {
        return Ok(members);
    }
    let agents = vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_AGENT_DEF, None)?
        .collect::<Result<Vec<_>>>()?;
    for agent in agents {
        if !members.contains(&agent)
            && live_entity_row_in_txn(&vault.store, txn, &agent)?.live_type()
                == Some(ENTITY_TYPE_AGENT_DEF)
            && names_actor_in(vault, txn, audience, agent)?
        {
            members.insert(agent);
        }
    }
    Ok(members)
}

/// Whether the audience now of the private thread rooted at `root` names
/// `person` ([`names_actor_in`]), read as [`notify_thread_members_in_txn`]
/// reads its members: on base, or in the published overlay of the live
/// off-record stretch that holds a root base does not. No one is in a public
/// thread, or a root that is no live private root. Read only; an Owner's
/// export asks it before it tells a thread (FIX 6427).
pub(crate) fn thread_has_member_now_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    person: EntityId,
) -> Result<bool> {
    let members = thread_members_now_in(vault, txn, root)?;
    names_actor_in(vault, txn, &members, person)
}

/// Everyone in the audience of the private thread rooted at `root` now; no
/// one for a root that is no live private root. A root base does not hold
/// is read in the published overlay of the live off-record stretch that
/// holds it, if any ([`overlay_thread_members_now_in`]).
fn thread_members_now_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
) -> Result<BTreeSet<EntityId>> {
    let body = match live_entity_row_in_txn(&vault.store, txn, &root)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } => body,
        LiveEntityRow::Absent => return overlay_thread_members_now_in(vault, txn, root),
        _ => return Ok(BTreeSet::new()),
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

/// Everyone in the audience of the private thread rooted at `root`, a root
/// only a live off-record stretch's published overlay holds (Engine
/// 10-20 17:4x): the stretch is found by the registry's lock-free lookup,
/// the root read strictly in its overlay composed with base, and its
/// audience folded on base, where every edit is. No one when no live
/// stretch holds it, or it is no private root there. Read only: nothing is
/// staged in the overlay.
fn overlay_thread_members_now_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
) -> Result<BTreeSet<EntityId>> {
    let Some(overlay) = vault.store.off_record_sessions.overlay_holding(&root)? else {
        return Ok(BTreeSet::new());
    };
    let view = vault.store.session_view(overlay)?;
    match resolved_root_in(&view.read(), txn, root)? {
        Some(super::audience::ThreadBinding {
            room,
            audience: Some(seed),
            ..
        }) => Ok(fold_audience_in(vault, txn, room, root, &seed)?.current()),
        _ => Ok(BTreeSet::new()),
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
                AudienceOp::Add
                | AudienceOp::Remove
                | AudienceOp::RequestJoin
                | AudienceOp::DenyJoin => continue,
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
