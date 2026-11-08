//! The `surface.inbound` source (ARCH-0080 §4 Watchers; FIX 4749): one row
//! per inbound connector SurfaceEvent (OF-247), appended in the write that
//! admits the event to its attempt queue. The sequence is drawn there, so
//! feed order is commit order, and a provider's re-delivery, which admits
//! nothing new, appends nothing; nor does an event no fact binding reads
//! (FIX 22141). A row keeps ids and tokens only, never provider text: a
//! hook that wants more reads it under its own grant. The runner and each
//! housekeeping pass prune the rows every hook binding has passed (FIX
//! 22180), and an erase leaves a row that names an erased entity at its
//! sequence with no ids or tokens in it.

use std::collections::BTreeSet;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::runtime_hooks::store::source_erased_in_txn;
use crate::side_table::{self, Named, SideTable};
use crate::surface_event::{SurfaceEvent, SurfaceEventAction, SurfaceInteractionKind};
use crate::{EntityId, Error, Result, Vault};

use super::{
    FactEntry, FactKind, FactOp, FactPosition, FactSource, SourceBatch, SurfaceInboundPosition,
};

/// The inbound feed: one row per admitted surface event, by its sequence.
const SURFACE_INBOUND: SideTable<u64, InboundFeedRow, Named> =
    SideTable::new(&side_table::HOOKS_SURFACE_INBOUND);
/// The last inbound sequence handed out.
const SURFACE_INBOUND_NEXT: SideTable<(), u64, Named> =
    SideTable::new(&side_table::HOOKS_SURFACE_INBOUND_NEXT);

/// One inbound feed row, at the sequence its admission committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InboundFeedRow {
    /// An admitted event.
    Admitted(SurfaceInboundRow),
    /// An event whose identity or actor was erased: it keeps its position,
    /// so a cursor past it neither breaks nor reads it again, and names no
    /// entity, attempt, connector or channel. No reader takes it.
    Erased,
}

/// One admitted inbound event, as the feed keeps it and its hook reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::runtime_hooks) struct SurfaceInboundRow {
    /// The attempt that carries the event to its connector wake.
    pub(in crate::runtime_hooks) attempt: [u8; 16],
    /// The normalized connector key: what a `surface.inbound:<glob>`
    /// selector reads.
    pub(in crate::runtime_hooks) connector: String,
    /// The provider channel key the event arrived on.
    pub(in crate::runtime_hooks) channel: String,
    /// `message`, or the interaction kind.
    pub(in crate::runtime_hooks) action: String,
    /// The ChannelIdentity the event addressed: the fact's entity.
    #[serde(with = "crate::serialize::entity_ref")]
    pub(in crate::runtime_hooks) receiving_identity: EntityId,
    /// The actor that identity routed the event to.
    #[serde(with = "crate::serialize::entity_ref")]
    pub(in crate::runtime_hooks) actor: EntityId,
    /// The provider's receive time, Unix seconds.
    pub(in crate::runtime_hooks) received_at: u64,
    /// When the admission committed, Unix seconds.
    pub(in crate::runtime_hooks) recorded_at: u64,
}

impl SurfaceInboundRow {
    fn input_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron.hook-surface-inbound.v1");
        hasher.update(&self.attempt);
        hasher.update(self.receiving_identity.as_bytes());
        hasher.update(self.actor.as_bytes());
        for token in [&self.connector, &self.channel, &self.action] {
            hasher.update(&(token.len() as u64).to_be_bytes());
            hasher.update(token.as_bytes());
        }
        hasher.update(&self.received_at.to_be_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Appends `event`, which `attempt` now carries, to the inbound feed in the
/// admitting write. An event whose identity or actor is no entity id is one
/// no hook's grant can place, and one admitted with no reader
/// ([`super::has_reader_in_txn`]) is one no hook reads, so either appends
/// nothing. Nor does one whose identity or actor a permanent erase fenced:
/// the erase's scrub would have emptied it (FIX 22191).
pub(crate) fn record_surface_inbound_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    event: &SurfaceEvent,
) -> Result<()> {
    let (Ok(receiving_identity), Ok(actor)) = (
        EntityId::from_hex(&event.receiving_identity_ref),
        EntityId::from_hex(&event.actor_ref),
    ) else {
        return Ok(());
    };
    if !super::has_reader_in_txn(
        vault,
        txn,
        FactSource::SurfaceInbound,
        FactKind::SurfaceInbound,
    )? {
        return Ok(());
    }
    if source_erased_in_txn(vault, txn, &receiving_identity)?
        || source_erased_in_txn(vault, txn, &actor)?
    {
        return Ok(());
    }
    let last = SURFACE_INBOUND_NEXT
        .get(&vault.store, txn, &())?
        .unwrap_or(0);
    let sequence = last
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("hook surface inbound sequence"))?;
    let row = SurfaceInboundRow {
        attempt: *attempt.as_bytes(),
        connector: crate::connector_key::normalize_connector_key(&event.channel),
        channel: event.channel.clone(),
        action: action_token(&event.action).to_owned(),
        receiving_identity,
        actor,
        received_at: event.received_at,
        recorded_at: vault.store.clock.now_recorded_at(),
    };
    SURFACE_INBOUND.put(&vault.store, txn, &sequence, &InboundFeedRow::Admitted(row))?;
    SURFACE_INBOUND_NEXT.put(&vault.store, txn, &(), &sequence)
}

/// The action token a hook's input carries.
fn action_token(action: &SurfaceEventAction) -> &'static str {
    match action {
        SurfaceEventAction::Message => "message",
        SurfaceEventAction::Interaction { interaction, .. } => match interaction {
            SurfaceInteractionKind::Reaction => "reaction",
            SurfaceInteractionKind::CardCompletion => "card_completion",
            SurfaceInteractionKind::Dwell => "dwell",
            SurfaceInteractionKind::Tap => "tap",
            SurfaceInteractionKind::OptOut => "opt_out",
        },
    }
}

/// Inbound events after `after`, at most `max_entries` rows scanned. The
/// fact's entity is the identity the event addressed, so a hook sees only
/// events whose identity its grant reads; its actor is the engine's own
/// principal, as no writer made it. An erased row is scanned past, so the
/// cursor moves over it as over a skipped fact.
pub(super) fn events_after(
    vault: &Vault,
    after: Option<SurfaceInboundPosition>,
    max_entries: usize,
) -> Result<SourceBatch> {
    let rtxn = vault.store.env.read_txn()?;
    let start = after
        .as_ref()
        .map_or(Bound::Unbounded, |position| Bound::Excluded(&position.0));
    let actor = crate::ports::storage_service_principal()?;
    let mut batch = SourceBatch::default();
    for (scanned, row) in SURFACE_INBOUND
        .iter_range(&vault.store, &rtxn, start, Bound::Unbounded)?
        .enumerate()
    {
        if scanned >= max_entries {
            batch.more = true;
            break;
        }
        let (sequence, row) = row?;
        let position = FactPosition::SurfaceInbound(SurfaceInboundPosition(sequence));
        batch.through = Some(position);
        let InboundFeedRow::Admitted(event) = row else {
            continue;
        };
        batch.entries.push(FactEntry {
            position,
            kind: FactKind::SurfaceInbound,
            entity: event.receiving_identity,
            op: FactOp::Inbound,
            actor,
            recorded_at: event.recorded_at,
            input_hash: event.input_hash(),
            body_hash: None,
            revision: None,
            settlement: None,
            predicate: None,
            tick: None,
            surface: Some(event),
        });
    }
    Ok(batch)
}

/// The newest inbound position, or `None` while the feed is empty.
pub(super) fn head_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<FactPosition>> {
    Ok(SURFACE_INBOUND
        .iter_rev_from(&vault.store, txn, &[])?
        .next()
        .transpose()?
        .map(|(sequence, _)| FactPosition::SurfaceInbound(SurfaceInboundPosition(sequence))))
}

/// The inbound rows at or before `floor`, the lowest cursor of every
/// enabled fact binding, at most `max_rows`, read in `txn` for a later
/// write to delete ([`delete_events_in_txn`]). A binding new to the feed
/// starts at its head, so no passed row is read again.
pub(super) fn passed_events_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    floor: SurfaceInboundPosition,
    max_rows: usize,
) -> Result<Vec<u64>> {
    let mut passed = Vec::new();
    for row in SURFACE_INBOUND.iter_range(
        &vault.store,
        txn,
        Bound::Unbounded,
        Bound::Included(&floor.0),
    )? {
        if passed.len() >= max_rows {
            break;
        }
        let (sequence, _) = row?;
        passed.push(sequence);
    }
    Ok(passed)
}

/// Deletes the inbound feed rows `sequences` names, in the caller's write.
pub(super) fn delete_events_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    sequences: &[u64],
) -> Result<()> {
    for sequence in sequences {
        SURFACE_INBOUND.delete(&vault.store, txn, sequence)?;
    }
    Ok(())
}

/// Erases `ids` from the inbound feed in the caller's erase write: each row
/// whose receiving identity or actor is one of them becomes
/// [`InboundFeedRow::Erased`] at its own sequence. One complete scan for
/// all of them, as the other hook carriers' scrub; a row erased already
/// stays as it is.
pub(super) fn scrub_inbound_events_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ids: &BTreeSet<EntityId>,
) -> Result<()> {
    let mut named = Vec::new();
    for row in SURFACE_INBOUND.iter_from(&vault.store, txn, &[])? {
        let (sequence, row) = row?;
        if matches!(
            &row,
            InboundFeedRow::Admitted(event)
                if ids.contains(&event.receiving_identity) || ids.contains(&event.actor)
        ) {
            named.push(sequence);
        }
    }
    for sequence in &named {
        SURFACE_INBOUND.put(&vault.store, txn, sequence, &InboundFeedRow::Erased)?;
    }
    Ok(())
}
