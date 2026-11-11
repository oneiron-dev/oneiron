//! Fact sources and their typed positions (ARCH-0080 §4 Sources and cursors).
//! A position is never a timestamp or the notify counter: an imported claim
//! can carry an old time, and the notify counter is process-local. The
//! engine's own hook feeds live in submodules: the settlement feed in
//! `settlement`, and the two watcher sources (FIX 4749) in `schedule` and
//! `surface_inbound`. Those three are the feeds the runner and each
//! housekeeping pass prune and an erase scrubs; the claim changelog is
//! neither.

mod schedule;
mod settlement;
mod surface_inbound;

use serde::{Deserialize, Serialize};

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::ports::{ChangeLogStore, ChangeLogStoreRead, ChangeOp, EntityStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::skill_hub::pack_catalog::HookPhase;
use crate::vault::RevisionRef;
use crate::{EntityId, Error, Result, Vault};

use super::{filter, store};

pub(super) use schedule::TickDetails;
pub(crate) use schedule::{
    index_task_due_in_txn, next_tick_release_at, release_due_ticks, releases_here,
};
pub(super) use settlement::{SettledRow, prepare_settlement_in_txn, settlement_fact_in_txn};
pub(crate) use settlement::{record_settlement_in_txn, record_timeout_demotion_in_txn};
pub(super) use surface_inbound::SurfaceInboundRow;
pub(crate) use surface_inbound::record_surface_inbound_in_txn;

// The claim changelog, read through `ChangeLogStoreRead`: the mutation-audit
// rows, keyed by their record id.
//
// The id is drawn from `StoreClock::ulid` inside the writer transaction that
// commits the row, and LMDB runs one writer at a time, so a later commit
// always holds a larger id. The id floor (`ports:id_floor:v1`) is persisted
// with every mutation and observed when the vault opens, so ids keep rising
// across restarts. Key order is therefore commit order: a reader that resumes
// after its last id never misses a row that commits later.

/// Rows a batch may scan for each entry it keeps, so a run of other entity
/// kinds cannot make one pass unbounded.
const SCAN_PER_ENTRY: usize = 16;
/// The binding changes read to find where a binding was last written.
const BINDING_CHANGES: usize = 4_096;

/// Where a fact comes from. Each source has its own cursor.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FactSource {
    /// Claim writes, in commit order.
    ClaimChangelog,
    /// Settled proposals, in settlement order.
    Settlement,
    /// Due TASK ticks, in release order (FIX 4749).
    Schedule,
    /// Inbound connector surface events, in admission order (FIX 4749).
    SurfaceInbound,
}

impl FactSource {
    pub const ALL: [Self; 4] = [
        Self::ClaimChangelog,
        Self::Settlement,
        Self::Schedule,
        Self::SurfaceInbound,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimChangelog => "claim_changelog",
            Self::Settlement => "settlement",
            Self::Schedule => "schedule",
            Self::SurfaceInbound => "surface_inbound",
        }
    }

    pub(super) const fn tag(self) -> u8 {
        match self {
            Self::ClaimChangelog => 0,
            Self::Settlement => 1,
            Self::Schedule => 2,
            Self::SurfaceInbound => 3,
        }
    }
}

/// A claim changelog position: the audit record id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimChangelogPosition(pub [u8; 16]);

/// A settlement position: the feed's committed sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SettlementPosition(pub u64);

/// A tick feed position: the sequence its release committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulePosition(pub u64);

/// An inbound feed position: the sequence its admission committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SurfaceInboundPosition(pub u64);

/// A position in one source. Two positions compare only within one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactPosition {
    ClaimChangelog(ClaimChangelogPosition),
    Settlement(SettlementPosition),
    Schedule(SchedulePosition),
    SurfaceInbound(SurfaceInboundPosition),
}

impl FactPosition {
    #[must_use]
    pub const fn source(self) -> FactSource {
        match self {
            Self::ClaimChangelog(_) => FactSource::ClaimChangelog,
            Self::Settlement(_) => FactSource::Settlement,
            Self::Schedule(_) => FactSource::Schedule,
            Self::SurfaceInbound(_) => FactSource::SurfaceInbound,
        }
    }

    /// The position's own bytes: the record id, or the sequence big-endian.
    #[must_use]
    pub fn bytes(self) -> Vec<u8> {
        match self {
            Self::ClaimChangelog(position) => position.0.to_vec(),
            Self::Settlement(position) => position.0.to_be_bytes().to_vec(),
            Self::Schedule(position) => position.0.to_be_bytes().to_vec(),
            Self::SurfaceInbound(position) => position.0.to_be_bytes().to_vec(),
        }
    }

    /// Lowercase hex of [`Self::bytes`], as a hook's input carries it.
    #[must_use]
    pub fn hex(self) -> String {
        crate::receipt::hex_lower(&self.bytes())
    }

    /// The source-tagged form replay takes.
    #[must_use]
    pub fn to_hex(self) -> FactPositionHex {
        FactPositionHex(format!("{}:{}", self.source().as_str(), self.hex()))
    }
}

/// A position as text: `claim_changelog:<hex32>`, or `settlement:<hex16>`,
/// `schedule:<hex16>` or `surface_inbound:<hex16>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct FactPositionHex(pub String);

impl FactPositionHex {
    /// The typed position this text names.
    pub fn parse(&self) -> Result<FactPosition> {
        let (source, hex) = self
            .0
            .split_once(':')
            .ok_or_else(|| invalid("a fact position is <source>:<hex>"))?;
        match source {
            "claim_changelog" => Ok(FactPosition::ClaimChangelog(ClaimChangelogPosition(
                decode_hex(hex)?,
            ))),
            "settlement" => Ok(FactPosition::Settlement(SettlementPosition(
                u64::from_be_bytes(decode_hex(hex)?),
            ))),
            "schedule" => Ok(FactPosition::Schedule(SchedulePosition(
                u64::from_be_bytes(decode_hex(hex)?),
            ))),
            "surface_inbound" => Ok(FactPosition::SurfaceInbound(SurfaceInboundPosition(
                u64::from_be_bytes(decode_hex(hex)?),
            ))),
            _ => Err(invalid("unknown fact source")),
        }
    }
}

/// The kinds of fact the runner follows: slice 1's, and the two watcher
/// sources (FIX 4749).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub enum FactKind {
    #[serde(rename = "claim.landed")]
    ClaimLanded,
    #[serde(rename = "claim.superseded")]
    ClaimSuperseded,
    #[serde(rename = "proposal.settled")]
    ProposalSettled,
    /// A TASK's due time passed (ARCH-0080 §4 Watchers).
    #[serde(rename = "schedule.tick")]
    ScheduleTick,
    /// A connector SurfaceEvent was admitted (OF-247).
    #[serde(rename = "surface.inbound")]
    SurfaceInbound,
}

impl FactKind {
    pub const ALL: [Self; 5] = [
        Self::ClaimLanded,
        Self::ClaimSuperseded,
        Self::ProposalSettled,
        Self::ScheduleTick,
        Self::SurfaceInbound,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimLanded => "claim.landed",
            Self::ClaimSuperseded => "claim.superseded",
            Self::ProposalSettled => "proposal.settled",
            Self::ScheduleTick => "schedule.tick",
            Self::SurfaceInbound => "surface.inbound",
        }
    }

    /// The kind `token` names, as a selector entry spells it.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == token)
    }

    /// Whether the kind is a watcher source: no write made it, so it
    /// carries no claim and no verb hook sees it (FIX 4749).
    #[must_use]
    pub const fn is_watcher_source(self) -> bool {
        matches!(self, Self::ScheduleTick | Self::SurfaceInbound)
    }
}

/// What the write that made a fact did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FactOp {
    Create,
    Update,
    Supersede,
    Settle,
    /// A due TASK's tick.
    Tick,
    /// An inbound surface event's admission.
    Inbound,
}

impl FactOp {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Supersede => "supersede",
            Self::Settle => "settle",
            Self::Tick => "tick",
            Self::Inbound => "inbound",
        }
    }
}

/// The settlement detail a proposal fact carries into its hook input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SettlementDetails {
    pub(super) kind: SettlementKind,
    pub(super) outcome: SettledOutcome,
}

/// One fact read from a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FactEntry {
    pub(super) position: FactPosition,
    pub(super) kind: FactKind,
    pub(super) entity: EntityId,
    pub(super) op: FactOp,
    pub(super) actor: EntityId,
    pub(super) recorded_at: u64,
    /// The fact's own input hash: the changelog's, or the settlement row's.
    pub(super) input_hash: [u8; 32],
    /// BLAKE3 of the entity's body as this fact left it, when known.
    pub(super) body_hash: Option<[u8; 32]>,
    /// The exact live or retained revision with that body, when it remains.
    pub(super) revision: Option<RevisionRef>,
    /// The settlement door and outcome, only for a proposal fact.
    pub(super) settlement: Option<SettlementDetails>,
    /// The claim's predicate, for block expiry only. Filters read the claim
    /// under the hook's grant instead.
    pub(super) predicate: Option<String>,
    /// The due time, only for a tick.
    pub(super) tick: Option<TickDetails>,
    /// The event's ids and tokens, only for an inbound surface event.
    pub(super) surface: Option<SurfaceInboundRow>,
}

impl FactEntry {
    /// What a selector's glob reads on a fact that is no claim: a tick's
    /// TASK id as 32 hex, an inbound event's connector key.
    pub(super) fn selector_key(&self) -> Option<String> {
        match (&self.tick, &self.surface) {
            (Some(_), _) => Some(self.entity.to_hex()),
            (None, Some(surface)) => Some(surface.connector.clone()),
            (None, None) => None,
        }
    }

    /// Whether the hook's input carries the entity's body. A tick's and an
    /// inbound event's carry only ids and tokens, so a live replay of one
    /// needs no pinned body.
    pub(super) const fn input_carries_body(&self) -> bool {
        self.tick.is_none() && self.surface.is_none()
    }
}

/// One bounded read from a source.
#[derive(Debug, Default)]
pub(super) struct SourceBatch {
    pub(super) entries: Vec<FactEntry>,
    /// The last position scanned, kept or not.
    pub(super) through: Option<FactPosition>,
    /// The batch stopped at its bound before the source's end.
    pub(super) more: bool,
}

pub use crate::consent::settlement_fact::{SettledFact, SettledOutcome, SettlementKind};

use settlement::settlements_after_in_txn;

/// Up to `max_entries` facts after `after` (exclusive) in `source`.
pub(super) fn read_after(
    vault: &Vault,
    source: FactSource,
    after: Option<FactPosition>,
    max_entries: usize,
) -> Result<SourceBatch> {
    match (source, after) {
        (FactSource::ClaimChangelog, None) => claim_changes_after(vault, None, max_entries),
        (FactSource::ClaimChangelog, Some(FactPosition::ClaimChangelog(position))) => {
            claim_changes_after(vault, Some(position), max_entries)
        }
        (FactSource::Settlement, None) => settlement::settlements_after(vault, None, max_entries),
        (FactSource::Settlement, Some(FactPosition::Settlement(position))) => {
            settlement::settlements_after(vault, Some(position), max_entries)
        }
        (FactSource::Schedule, None) => schedule::ticks_after(vault, None, max_entries),
        (FactSource::Schedule, Some(FactPosition::Schedule(position))) => {
            schedule::ticks_after(vault, Some(position), max_entries)
        }
        (FactSource::SurfaceInbound, None) => {
            surface_inbound::events_after(vault, None, max_entries)
        }
        (FactSource::SurfaceInbound, Some(FactPosition::SurfaceInbound(position))) => {
            surface_inbound::events_after(vault, Some(position), max_entries)
        }
        _ => Err(Error::InvariantViolation(
            "hook cursor names another source",
        )),
    }
}

/// [`read_after`] in the caller's snapshot.
pub(super) fn read_after_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: FactSource,
    after: Option<FactPosition>,
    max_entries: usize,
) -> Result<SourceBatch> {
    match (source, after) {
        (FactSource::ClaimChangelog, None) => {
            claim_changes_after_in_txn(vault, txn, None, max_entries)
        }
        (FactSource::ClaimChangelog, Some(FactPosition::ClaimChangelog(position))) => {
            claim_changes_after_in_txn(vault, txn, Some(position), max_entries)
        }
        (FactSource::Settlement, None) => settlements_after_in_txn(vault, txn, None, max_entries),
        (FactSource::Settlement, Some(FactPosition::Settlement(position))) => {
            settlements_after_in_txn(vault, txn, Some(position), max_entries)
        }
        _ => Err(Error::InvariantViolation(
            "hook cursor names another source",
        )),
    }
}

/// Claim writes after `after`: Create and Update land a claim, Supersede
/// closes one. Other entity kinds and other ops are scanned past.
fn claim_changes_after(
    vault: &Vault,
    after: Option<ClaimChangelogPosition>,
    max_entries: usize,
) -> Result<SourceBatch> {
    let rtxn = vault.store.env.read_txn()?;
    claim_changes_after_in_txn(vault, &rtxn, after, max_entries)
}

fn claim_changes_after_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: Option<ClaimChangelogPosition>,
    max_entries: usize,
) -> Result<SourceBatch> {
    let budget = max_entries.saturating_mul(SCAN_PER_ENTRY).max(1);
    let mut batch = SourceBatch::default();
    for (scanned, row) in vault
        .store
        .port_changelog_after(txn, after.map(|position| position.0))?
        .enumerate()
    {
        if scanned >= budget || batch.entries.len() >= max_entries {
            batch.more = true;
            break;
        }
        let (id, change) = row?;
        if change.id != id {
            return Err(Error::CorruptedIndex("hook changelog identity"));
        }
        let position = FactPosition::ClaimChangelog(ClaimChangelogPosition(id));
        batch.through = Some(position);
        if let Some(entry) = claim_fact_in_txn(vault, txn, &change)? {
            batch.entries.push(entry);
        }
    }
    Ok(batch)
}

pub(super) fn claim_fact_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    change: &crate::ports::ChangeLogRecord,
) -> Result<Option<FactEntry>> {
    let position = FactPosition::ClaimChangelog(ClaimChangelogPosition(change.id));
    let (kind, op) = match change.op {
        ChangeOp::Create => (FactKind::ClaimLanded, FactOp::Create),
        ChangeOp::Update => (FactKind::ClaimLanded, FactOp::Update),
        ChangeOp::Supersede => (FactKind::ClaimSuperseded, FactOp::Supersede),
        _ => return Ok(None),
    };
    let Some(record) = vault.store.port_entity_record(txn, &change.entity)? else {
        return Ok(None);
    };
    if record.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let revision = crate::vault::entity_revision::revision_for_body_hash_in_txn(
        vault,
        txn,
        &change.entity,
        &change.input_hash,
    )?;
    let historical = match revision {
        Some(revision) => crate::vault::entity_revision::read_entity_revision_in_txn(
            vault,
            txn,
            &change.entity,
            crate::vault::ReadMode::Pinned(revision),
        )?,
        None => None,
    };
    let predicate = historical
        .as_deref()
        .and_then(|raw| raw.get(ENTITY_METADATA_HEADER_LEN..))
        .and_then(|body| crate::claim::decode_claim_body(body, true).ok())
        .map(|body| body.predicate);
    Ok(Some(FactEntry {
        position,
        kind,
        entity: change.entity,
        op,
        actor: change.actor_principal,
        recorded_at: change.recorded_at,
        input_hash: change.input_hash,
        body_hash: Some(change.input_hash),
        revision,
        settlement: None,
        predicate,
        tick: None,
        surface: None,
    }))
}

/// The newest position in `source`, or `None` while it is empty, in the
/// caller's snapshot, including a binding lifecycle write's own settlement
/// head.
pub(crate) fn head_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: FactSource,
) -> Result<Option<FactPosition>> {
    let head = match source {
        FactSource::ClaimChangelog => vault
            .store
            .port_changelog_head(txn)?
            .map(|(id, _)| FactPosition::ClaimChangelog(ClaimChangelogPosition(id))),
        FactSource::Settlement => settlement::head_in_txn(vault, txn)?,
        FactSource::Schedule => schedule::head_in_txn(vault, txn)?,
        FactSource::SurfaceInbound => surface_inbound::head_in_txn(vault, txn)?,
    };
    Ok(head)
}

/// Whether a fact of `kind` that a write appends to `source`, one of the
/// engine's own hook feeds, has a reader in that write's `txn` (FIX 22141,
/// FIX 22154): a change feed subscription follows `source` (untangle slice
/// 6.8), or hooks are on and an enabled fact binding whose selector
/// takes `kind` follows `source` from an unpaused cursor. No other binding
/// takes the fact: one with no cursor there, or a paused one, starts past it
/// at the feed head; a disabled one takes nothing; one whose selector takes
/// no such fact skips it. While hooks are off no fact is recorded, so a
/// binding that kept its cursor reads none appended then, and a selector
/// widened to take `kind` reads none appended before. It reads the switch,
/// the cursor rows and, up to the first reader, the claims of the bindings
/// they name: no binding list scan per fact.
pub(super) fn has_reader_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: FactSource,
    kind: FactKind,
) -> Result<bool> {
    // A change feed subscription that follows `source` reads each of its
    // facts, hooks on or off (untangle slice 6.8).
    if crate::feeds::followed_in_txn(vault, txn, source)? {
        return Ok(true);
    }
    if !vault.hooks_enabled_in_txn(txn)? {
        return Ok(false);
    }
    for binding in store::unpaused_cursor_bindings_in_txn(vault, txn, source)? {
        // A binding claim that does not read counts as a reader: the runner
        // judges it on its pass, and the appending write never fails on a
        // hook's claim.
        let reads = vault
            .pack_hook_binding_in_txn(txn, &binding)
            .map_or(true, |row| {
                row.is_some_and(|row| {
                    row.enabled
                        && row.selector.phase == HookPhase::Fact
                        && filter::verbs_admit_kind(&row.selector.verbs, kind)
                })
            });
        if reads {
            return Ok(true);
        }
    }
    Ok(false)
}

/// One settled proposal as a change feed delivers it (untangle slice 6.8):
/// its position, the settled entity, who settled it and when, and the read
/// of that entity its subscriber's lane must pass, `None` once its pinned
/// history is gone.
pub(crate) struct SettledFeedFact {
    pub(crate) position: SettlementPosition,
    pub(crate) entity: EntityId,
    pub(crate) actor: EntityId,
    pub(crate) recorded_at: u64,
    pub(crate) revision: Option<RevisionRef>,
    pub(crate) point: Option<crate::claim::PointRead<'static>>,
}

/// One bounded read of the settlement feed for a change feed.
pub(crate) struct SettledFeedFacts {
    pub(crate) facts: Vec<SettledFeedFact>,
    /// The last position scanned, kept or not.
    pub(crate) through: Option<SettlementPosition>,
}

/// Up to `max_entries` settled proposals after `after` (exclusive) in the
/// caller's snapshot: the settlement feed the hooks follow, read for a change
/// feed subscription (untangle slice 6.8).
pub(crate) fn settled_feed_facts_after_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: Option<SettlementPosition>,
    max_entries: usize,
) -> Result<SettledFeedFacts> {
    let batch = read_after_in_txn(
        vault,
        txn,
        FactSource::Settlement,
        after.map(FactPosition::Settlement),
        max_entries,
    )?;
    let through = match batch.through {
        None => None,
        Some(FactPosition::Settlement(position)) => Some(position),
        Some(_) => {
            return Err(Error::InvariantViolation(
                "the settlement feed answered another source",
            ));
        }
    };
    let mut facts = Vec::with_capacity(batch.entries.len());
    for entry in batch.entries {
        let FactPosition::Settlement(position) = entry.position else {
            return Err(Error::InvariantViolation(
                "the settlement feed answered another source",
            ));
        };
        facts.push(SettledFeedFact {
            position,
            entity: entry.entity,
            actor: entry.actor,
            recorded_at: entry.recorded_at,
            revision: entry.revision,
            point: super::read::fact_point(&entry),
        });
    }
    Ok(SettledFeedFacts { facts, through })
}

/// The hook feed rows at or before `floor`, the lowest cursor of every
/// enabled fact binding, that no binding reads again, at most `max_rows`,
/// read in `txn`. The claim changelog prunes nothing.
pub(super) fn passed_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    floor: FactPosition,
    max_rows: usize,
) -> Result<Vec<u64>> {
    match floor {
        FactPosition::Settlement(floor) => {
            settlement::passed_settlements_in_txn(vault, txn, floor, max_rows)
        }
        FactPosition::Schedule(floor) => schedule::passed_ticks_in_txn(vault, txn, floor, max_rows),
        FactPosition::SurfaceInbound(floor) => {
            surface_inbound::passed_events_in_txn(vault, txn, floor, max_rows)
        }
        FactPosition::ClaimChangelog(_) => Ok(Vec::new()),
    }
}

/// Deletes `source`'s hook feed rows `rows`, in the caller's write.
pub(super) fn delete_feed_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: FactSource,
    rows: &[u64],
) -> Result<()> {
    match source {
        FactSource::Settlement => settlement::delete_settlements_in_txn(vault, txn, rows),
        FactSource::Schedule => schedule::delete_ticks_in_txn(vault, txn, rows),
        FactSource::SurfaceInbound => surface_inbound::delete_events_in_txn(vault, txn, rows),
        FactSource::ClaimChangelog => Ok(()),
    }
}

/// Erases `ids` from the three hook feeds in the caller's erase write: an
/// erased TASK's due index rows, and every settlement, tick or inbound row
/// that names one, each kept at its sequence with nothing in it. One walk
/// of each feed for all of them.
pub(super) fn scrub_hook_feeds_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ids: &std::collections::BTreeSet<EntityId>,
) -> Result<()> {
    settlement::scrub_settlements_in_txn(vault, txn, ids)?;
    schedule::scrub_task_ticks_in_txn(vault, txn, ids)?;
    surface_inbound::scrub_inbound_events_in_txn(vault, txn, ids)?;
    crate::feeds::scrub_withdrawn_types_in_txn(&vault.store, txn, ids)?;
    // Untangle slice 6.8b: the change feed's edge and redirty rows go with the same erase.
    crate::feeds::scrub_feeds_in_txn(vault, txn, ids)
}

/// The changelog position of a binding claim's latest write, in the
/// caller's snapshot: where a new or re-enabled binding starts following the
/// claim changelog.
pub(super) fn binding_written_at_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &EntityId,
) -> Result<Option<FactPosition>> {
    let changes = vault
        .store
        .port_changelog_list_by_entity(txn, binding, BINDING_CHANGES)?;
    Ok(changes
        .iter()
        .map(|change| change.id)
        .max()
        .map(|id| FactPosition::ClaimChangelog(ClaimChangelogPosition(id))))
}

/// Where an enabled binding starts in each source at its real lifecycle
/// write: its own claim write where one exists, otherwise the source head.
/// The settlement, tick and inbound feeds hold no binding's write, so a
/// binding starts at their heads, but for one `fresh` to the tick feed,
/// never bound before: it starts before the earliest tick of a TASK still
/// open (FIX 4749), so a watcher bound after its TASK ticked sees that tick.
pub(super) fn enable_start_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &EntityId,
    source: FactSource,
    fresh: bool,
) -> Result<Option<FactPosition>> {
    match source {
        FactSource::ClaimChangelog => match binding_written_at_in_txn(vault, txn, binding)? {
            Some(position) => Ok(Some(position)),
            None => head_in_txn(vault, txn, source),
        },
        FactSource::Schedule if fresh => schedule::open_tick_start_in_txn(vault, txn),
        FactSource::Settlement | FactSource::Schedule | FactSource::SurfaceInbound => {
            head_in_txn(vault, txn, source)
        }
    }
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return Err(invalid("fact position has the wrong length"));
    }
    let mut out = [0_u8; N];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        *slot = (high << 4) | low;
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid("fact position is not lowercase hex")),
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
