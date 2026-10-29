//! Dirty-TURN progress: the consolidation watermark and its working set.
//! Entry: `ConsolidationWatermark`, with `read_watermark` and `advance_watermark`.
//! Definitions are local; the wire codec lives in the codec child, the
//! turn-body decoder in the turn_body child.

use crate::ports::EntityStoreRead;

use super::support::{
    DEFAULT_MESO_ROUND_TURN_CAP, WATERMARK_SCHEMA_VERSION, invalid_consolidation, scope_byte,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::dreamer_runner::{
    DreamerConsolidationScope, DreamerTurnRole, dreamer_extraction_role_admissible,
    dreamer_turn_role,
};
use crate::dreamer_wake::read_phase::WakeStop;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TURN;
use crate::side_table::{self, Raw, SideTable};

pub(super) use super::redirty::conversation_of;
mod codec;
pub(super) use codec::{decode_watermark, encode_watermark};
mod turn_body;
pub use turn_body::entity_ref_from_value;
pub(crate) use turn_body::{TurnBodyFacts, decode_turn_body};

/// Per-scope consolidation watermark row. Key: u8 (the scope byte).
const WATERMARK: SideTable<[u8; 1], ConsolidationWatermark, Raw> =
    SideTable::new(&side_table::DREAMER_WATERMARK);

impl crate::side_table::RawValue for ConsolidationWatermark {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, crate::side_table::CodecError> {
        Ok(encode_watermark(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, crate::side_table::CodecError> {
        Ok(decode_watermark(bytes)?)
    }
}

#[cfg(test)]
mod rescan_tests;

// ---------------------------------------------------------------------------
// Phase 0 — global watermark scan (dirty-turn selection)
// ---------------------------------------------------------------------------

/// Per-scope consolidation watermark: the scan authority, as an exact POSITION
/// in the `learned_at` temporal index rather than a bare second. A round
/// resumes at the first temporal key strictly greater than this position, so a
/// cap that cuts between two turns sharing one second neither replays the
/// consumed prefix nor strands the remainder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsolidationWatermark {
    pub schema_version: u64,
    pub last_learned_at: u64,
    /// Explicit full-rescan position, before every temporal key, including zero.
    /// When true, `last_learned_at` is zero and `last_turn_id` is None.
    pub before_first: bool,
    /// Unless `before_first`, None = end-of-second; Some(id) = exact index key.
    ///
    /// The sentinel is deliberate, NOT Rust tuple ordering: outside a full
    /// rescan, `None` puts every key at `last_learned_at` behind the cursor,
    /// which is what bootstrap
    /// (`(0, None)` starts at learned-at 1) and a decoded schema-1 row
    /// ("through second X") both mean.
    pub last_turn_id: Option<EntityId>,
}

impl ConsolidationWatermark {
    /// Bootstrap: an absent row IS watermark 0 (DESIGN-PIN A1).
    #[must_use]
    pub const fn bootstrap() -> Self {
        Self {
            schema_version: WATERMARK_SCHEMA_VERSION,
            last_learned_at: 0,
            before_first: false,
            last_turn_id: None,
        }
    }
}

/// One admissible dirty turn in the working set, with its GATE-10 role for
/// extraction provenance tagging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkingSetTurn {
    pub turn_id: EntityId,
    pub role: DreamerTurnRole,
    pub learned_at: u64,
    /// The id of the re-dirty carrier this TURN was selected at, the
    /// selection key's id beside `learned_at` (then the carrier's position);
    /// `None` at the TURN's own temporal key. A complete-second settlement
    /// consumes exactly the carriers its round names.
    pub carrier: Option<EntityId>,
    /// The turn's CONVERSATION (`conversation_of(turn)`) — the consolidation
    /// grouping key. Never a SESSION entity: the canonical SESSION (type 2)
    /// is one time-bounded visit to a conversation (ONE-1685 resolved the
    /// 7-way "session" naming collision; this field was the misnomer).
    pub conversation: Option<EntityId>,
}

/// Reconstructs the full raw key a watermark row lives under, for tests that plant or inspect
/// rows through the raw `vault_meta` door directly.
#[cfg(test)]
pub(super) fn watermark_key(scope: DreamerConsolidationScope) -> Vec<u8> {
    WATERMARK.key_bytes(&[scope_byte(scope)])
}

/// Reads the per-scope watermark; absent row = bootstrap watermark 0.
pub fn read_watermark(
    vault: &Vault,
    scope: DreamerConsolidationScope,
) -> Result<ConsolidationWatermark> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(WATERMARK
        .get(&vault.store, &rtxn, &[scope_byte(scope)])?
        .unwrap_or_else(ConsolidationWatermark::bootstrap))
}

/// Admit a landed or changed TURN that any scope has already passed.
/// The put owns this transaction, so a late source and its pending carrier
/// become visible together; temporal-index position remains the authority
/// for forward writes, not a caller's arrival-time hint.
pub(crate) fn admit_turn_position_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    let row = store
        .port_entity_record(txn, turn)?
        .ok_or(Error::EntityNotFound)?;
    for scope in [
        DreamerConsolidationScope::Micro,
        DreamerConsolidationScope::Meso,
        DreamerConsolidationScope::Macro,
    ] {
        let watermark = WATERMARK
            .get(store, txn, &[scope_byte(scope)])?
            .unwrap_or_else(ConsolidationWatermark::bootstrap);
        let passed = !watermark.before_first
            && (row.learned_at < watermark.last_learned_at
                || (row.learned_at == watermark.last_learned_at
                    && watermark.last_turn_id.is_none_or(|last| *turn <= last)));
        if passed {
            super::redirty::requeue_turn_in_txn(store, txn, turn)?;
            crate::dreamer_wake::words_changed_in_txn(store, txn, turn)?;
            break;
        }
    }
    Ok(())
}

/// Reads the per-scope watermark inside a caller-owned write transaction
/// (the ONE-1685 session close re-reads it to guard its pre-planned round
/// against a concurrent planner).
pub(crate) fn read_watermark_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: DreamerConsolidationScope,
) -> Result<ConsolidationWatermark> {
    Ok(WATERMARK
        .get(&vault.store, txn, &[scope_byte(scope)])?
        .unwrap_or_else(ConsolidationWatermark::bootstrap))
}

/// Complete-second administrative adapter — writes `last_turn_id = None`,
/// treating the whole second as consumed, and consumes the re-dirty carriers
/// the `queued` round was selected at through it, by identity
/// ([`WorkingSetTurn::carrier`]): a carrier a newer change put in place of
/// one since, even in that same second, stays pending. Bounded rounds must
/// use the exact-position path.
///
/// Call ONLY after the round's attempts are enqueued+committed — a crash
/// before this re-scans, and idempotency rides the enqueue dedupe keys
/// (dedupe, never a lock).
///
/// Every deferred temporal entry the cursor passes on its way (a TURN whose
/// tagged MESSAGE is away from this replica, OF-534) is parked on the
/// carrier first, in the same commit, as the in-transaction settlement
/// parks it (FIX 3862): the first round after a promotion brings the row
/// back takes it. When the passed turns cannot be read, that is logged and
/// the cursor still moves, parking nothing, as it always did.
pub fn advance_watermark(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    last_learned_at: u64,
    queued: &[WorkingSetTurn],
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let passed = read_watermark_in_txn(vault, &wtxn, scope).and_then(|current| {
        enumerate_admissible_turns(
            vault,
            &wtxn,
            scope,
            &current,
            Some(last_learned_at),
            usize::MAX,
            WakeStop::NEVER,
        )
        // NEVER never stops, so the enumeration always yields its rows.
        .map(|rows| rows.unwrap_or_default())
    });
    match passed {
        Ok(passed) => park_deferred_in_txn(vault, &mut wtxn, &passed)?,
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            "the turns a watermark advance passes were not read; none of them is parked"
        ),
    }
    write_watermark_position_in_txn(vault, &mut wtxn, scope, last_learned_at, None)?;
    super::redirty::consume_carriers_in_txn(
        vault,
        &mut wtxn,
        scope,
        last_learned_at,
        queued
            .iter()
            .filter(|turn| turn.learned_at <= last_learned_at)
            .filter_map(|turn| Some((turn.turn_id, turn.carrier?))),
    )?;
    wtxn.commit()?;
    Ok(())
}

/// Administrative inclusive rescan, distinct from normal round settlement.
/// Zero needs a before-first position: completing second zero would skip it.
/// The re-dirty carriers the scope consumed from that second on are pending
/// again in the same commit.
pub(crate) fn reopen_watermark_from(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    from_learned_at: u64,
) -> Result<()> {
    let previous = from_learned_at.checked_sub(1);
    let watermark = ConsolidationWatermark {
        last_learned_at: previous.unwrap_or(0),
        before_first: previous.is_none(),
        ..ConsolidationWatermark::bootstrap()
    };
    let mut wtxn = vault.store.env.write_txn()?;
    write_watermark_in_txn(vault, &mut wtxn, scope, &watermark)?;
    super::redirty::reopen_carriers_in_txn(vault, &mut wtxn, scope, from_learned_at)?;
    wtxn.commit()?;
    Ok(())
}

/// Settles the watermark on the EXACT temporal-index position of the last TURN
/// a bounded round consumed — the settlement API for in-crate bounded-round
/// callers. Unlike [`advance_watermark`] it never claims a whole second
/// completed, so a round the Meso cap cut mid-second resumes at the very next
/// temporal key instead of swallowing the rest of that second.
///
/// The round is re-read from the live cursor through `last_consumed`, which
/// must still be in it: the cursor settles on the round's last temporal key,
/// and each TURN the round took at a re-dirty carrier consumes that carrier
/// (see [`settle_round_in_txn`]). The caller holds the round's fence: a
/// carrier replaced since its scan, in the same second, is read as consumed.
/// A `last_consumed` the re-read no longer reaches settles on its own key, as
/// before carriers.
// Lint shim until the first in-crate production bounded-round caller lands;
// remove with that caller. Session-close settlement composes its advance into
// the close transaction through `advance_watermark_in_txn` instead.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn advance_watermark_to_turn(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    last_consumed: &WorkingSetTurn,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let current = read_watermark_in_txn(vault, &wtxn, scope)?;
    let at = last_consumed.learned_at;
    // NEVER never stops, so the enumeration always yields its rows.
    let round = enumerate_admissible_turns(
        vault,
        &wtxn,
        scope,
        &current,
        Some(at),
        usize::MAX,
        WakeStop::NEVER,
    )?
    .unwrap_or_default();
    match round
        .iter()
        .position(|row| row.turn_id == last_consumed.turn_id)
    {
        Some(end) => settle_round_in_txn(vault, &mut wtxn, scope, &round[..=end])?,
        None => write_watermark_position_in_txn(
            vault,
            &mut wtxn,
            scope,
            at,
            Some(last_consumed.turn_id),
        )?,
    }
    wtxn.commit()?;
    Ok(())
}

/// An advance's settlement round, enumerated in a read snapshot.
pub(crate) struct WatermarkAdvance {
    current: ConsolidationWatermark,
    upper_learned_at: u64,
    round: Vec<AdmissibleTurnRow>,
}

/// The read half of [`advance_watermark_in_txn`]: the current watermark and
/// the SAME capped prefix it settles, enumerated in the caller's snapshot.
/// `None` when `stop` stopped the enumeration; nothing is settled then.
pub(crate) fn read_watermark_advance_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: DreamerConsolidationScope,
    upper_learned_at: u64,
    stop: WakeStop<'_>,
) -> Result<Option<WatermarkAdvance>> {
    let current = read_watermark_in_txn(vault, txn, scope)?;
    let Some(round) = enumerate_admissible_turns(
        vault,
        txn,
        scope,
        &current,
        Some(upper_learned_at),
        effective_dirty_turn_limit(scope, usize::MAX),
        stop,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(WatermarkAdvance {
        current,
        upper_learned_at,
        round,
    }))
}

/// The write half of [`advance_watermark_in_txn`]: settles the enumerated
/// round on its final `(learned_at, id)` through [`settle_round_in_txn`].
/// An empty round is the empty matched round: nothing was planned through
/// `upper_learned_at`, so the cursor takes that complete-second position.
/// Fail-closed on a backwards complete-second advance: rewinding the cursor
/// over consumed work would re-plan it. A round of pending carriers alone
/// may sit behind the cursor's second; it moves no cursor.
pub(crate) fn apply_watermark_advance_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    advance: &WatermarkAdvance,
) -> Result<()> {
    if advance.round.iter().any(|row| !row.deferred) {
        return settle_round_in_txn(vault, wtxn, scope, &advance.round);
    }
    if advance.upper_learned_at < advance.current.last_learned_at {
        return Err(invalid_consolidation(
            "dreamer watermark cannot settle behind its own position",
        ));
    }
    park_deferred_in_txn(vault, wtxn, &advance.round)?;
    write_watermark_position_in_txn(vault, wtxn, scope, advance.upper_learned_at, None)
}

/// Settles a fenced round inside a caller-owned write transaction: its read
/// half, then its apply half.
pub(crate) fn advance_watermark_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    upper_learned_at: u64,
) -> Result<()> {
    // NEVER never stops, so the read phase always yields its advance.
    let Some(advance) =
        read_watermark_advance_in_txn(vault, wtxn, scope, upper_learned_at, WakeStop::NEVER)?
    else {
        return Ok(());
    };
    apply_watermark_advance_in_txn(vault, wtxn, scope, &advance)
}

/// Settles a consumed round of `scope`, a prefix of the merged selection
/// order: the cursor moves to the round's last TEMPORAL key, so it only ever
/// names a TURN's own key, and each TURN taken at a re-dirty carrier consumes
/// that carrier instead. A round of carriers alone leaves the cursor where it
/// is. A passed TURN without its conversation edge is parked on a carrier,
/// and so is a passed TURN whose tagged MESSAGE is away.
fn settle_round_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    round: &[AdmissibleTurnRow],
) -> Result<()> {
    let passed = round.iter().filter(|row| !row.carried && !row.deferred);
    super::redirty::park_edgeless_in_txn(vault, wtxn, passed.map(|row| row.turn_id))?;
    park_deferred_in_txn(vault, wtxn, round)?;
    if let Some(last) = round.iter().rev().find(|row| !row.carried) {
        write_watermark_position_in_txn(vault, wtxn, scope, last.learned_at, Some(last.turn_id))?;
    }
    super::redirty::consume_carriers_in_txn(
        vault,
        wtxn,
        scope,
        u64::MAX,
        round
            .iter()
            .filter(|row| row.carried)
            .map(|row| (row.turn_id, row.key)),
    )
}

/// Parks each deferred temporal entry of `round` on the carrier as a cursor
/// settles past it. A TURN whose tagged MESSAGE is away from this replica
/// (OF-534) is pending there for every scope: selection leaves it out while
/// the MESSAGE is away, and the first round after a promotion brings the
/// row back takes it.
fn park_deferred_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    round: &[AdmissibleTurnRow],
) -> Result<()> {
    for row in round.iter().filter(|row| row.deferred) {
        super::redirty::park_turn_in_txn(vault, wtxn, &row.turn_id)?;
    }
    Ok(())
}

/// Writes the exact cursor position for `scope`. `turn_id = None` is the
/// complete-second boundary; `Some(id)` is the within-second position a capped
/// round settled on.
fn write_watermark_position_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    learned_at: u64,
    turn_id: Option<EntityId>,
) -> Result<()> {
    write_watermark_in_txn(
        vault,
        wtxn,
        scope,
        &ConsolidationWatermark {
            schema_version: WATERMARK_SCHEMA_VERSION,
            last_learned_at: learned_at,
            before_first: false,
            last_turn_id: turn_id,
        },
    )
}

fn write_watermark_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    watermark: &ConsolidationWatermark,
) -> Result<()> {
    if watermark.last_learned_at > crate::ports::job_recorded_at_in_txn(&vault.store, wtxn)? {
        return Err(invalid_consolidation(
            "dreamer watermark cannot advance into the future",
        ));
    }
    WATERMARK.put(&vault.store, wtxn, &[scope_byte(scope)], watermark)?;
    Ok(())
}

/// One admissible TURN at its exact key `(learned_at, key)` — its temporal
/// key, or its pending re-dirty carrier's (`carried`) — plus the GATE-10 role
/// the enumerator already resolved from the turn body.
#[derive(Debug, Clone, Copy)]
struct AdmissibleTurnRow {
    learned_at: u64,
    key: EntityId,
    carried: bool,
    /// A temporal entry whose tagged MESSAGE is away from this replica
    /// (OF-534): no round takes it and the cap does not count it; it is
    /// listed so the round a cursor settles past it parks it on the carrier.
    deferred: bool,
    turn_id: EntityId,
    role: DreamerTurnRole,
}

/// The round BOUND is the only scope-keyed part of selection: a Meso round is
/// capped at [`DEFAULT_MESO_ROUND_TURN_CAP`] admissible TURNs on top of the
/// caller's own limit; Micro and Macro keep the requested limit.
const fn effective_dirty_turn_limit(scope: DreamerConsolidationScope, requested: usize) -> usize {
    match scope {
        DreamerConsolidationScope::Meso => {
            if requested < DEFAULT_MESO_ROUND_TURN_CAP {
                requested
            } else {
                DEFAULT_MESO_ROUND_TURN_CAP
            }
        }
        DreamerConsolidationScope::Micro | DreamerConsolidationScope::Macro => requested,
    }
}

/// The ONE seek/filter/cap body: every admissible TURN strictly after
/// `watermark`'s compound position (unbounded below for a before-first rescan),
/// and every TURN whose re-dirty carrier is still pending for `scope`
/// (`super::redirty`), in one `(position, id)` order, through
/// `upper_inclusive_second` (unbounded above when `None`), stopping at
/// `limit`.
///
/// A TURN's position is its EFFECTIVE one, read in this same snapshot: its
/// temporal `learned_at` key, or the carrier a changed TURN took without
/// moving its row. Each TURN appears at most once; the cursor cuts only the
/// temporal entries, while the bound and cap apply to the merged order.
///
/// Selection ORDER and ADMISSIBILITY are scope-independent — type-filtered to
/// TURN (claims NEVER enter the working set, GATE-11) and role-filtered by
/// GATE-10; only the round BOUND the caller resolves is scope-keyed. Scan,
/// snapshot fence, and settlement all read through here so the capped prefix
/// they each see cannot drift.
///
/// A TURN whose tagged MESSAGE is away from this replica (OF-534) reads only
/// partly here, so no round takes it: a carried one keeps its carrier
/// pending, and a temporal one comes back marked `deferred`, outside the
/// cap, for settlement to park. Scan and fence drop those rows.
fn enumerate_admissible_turns(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: DreamerConsolidationScope,
    watermark: &ConsolidationWatermark,
    upper_inclusive_second: Option<u64>,
    limit: usize,
    stop: WakeStop<'_>,
) -> Result<Option<Vec<AdmissibleTurnRow>>> {
    let admission_time = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    let upper_inclusive_second = Some(
        upper_inclusive_second
            .unwrap_or(admission_time)
            .min(admission_time),
    );
    let query = crate::ports::TimelineQuery {
        start: if !watermark.before_first && watermark.last_turn_id.is_none() {
            std::ops::Bound::Excluded(watermark.last_learned_at)
        } else {
            std::ops::Bound::Unbounded
        },
        end: upper_inclusive_second.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Included),
        after: if watermark.before_first {
            None
        } else {
            watermark.last_turn_id.map(|id| crate::ports::EntityTime {
                timestamp: watermark.last_learned_at,
                id,
            })
        },
        ..Default::default()
    };
    let carriers = super::redirty::DirtyCarriers::read(vault, txn, scope)?;
    if stop.stopped() {
        return Ok(None);
    }
    // A bound behind the cursor's second leaves no temporal entry, only
    // pending carriers at or before it.
    let behind = upper_inclusive_second
        .is_some_and(|upper| !watermark.before_first && upper < watermark.last_learned_at);
    let timeline: crate::ports::PortRows<'_, crate::ports::EntityTime> = if behind {
        Box::new(std::iter::empty())
    } else {
        vault.store.port_entity_timeline(txn, query)?
    };
    let mut admissible = Vec::new();
    let mut taken = 0_usize;
    for entry in carriers.merge(timeline, upper_inclusive_second) {
        if stop.stopped() {
            return Ok(None);
        }
        if taken >= limit {
            break;
        }
        let candidate = entry?;
        let learned_at = candidate.position;
        let turn_id = candidate.turn;
        let raw = match vault.store.port_entity_record(txn, &turn_id) {
            Ok(Some(raw)) => raw,
            // An unreadable TURN is not an admissible member. The close fence
            // compares these IDs with the plan and defers the entire round;
            // explicit enqueue still rejects corrupt planned rows.
            Ok(None) | Err(Error::CorruptedIndex("entity header")) => continue,
            Err(error) => return Err(error),
        };

        if raw.entity_type != ENTITY_TYPE_TURN
            || raw.learned_at > admission_time
            || !carriers.stands(vault, txn, &candidate, raw.learned_at)?
        {
            continue;
        }
        let body = decode_turn_body(&raw.body);
        let role = dreamer_turn_role(
            body.speaker.as_deref(),
            &vault.config.assistant_display_names,
        );
        // A parked TURN waits on its carrier until its conversation edge lands.
        if !dreamer_extraction_role_admissible(role)
            || (candidate.carried
                && super::redirty::conversation_in_txn(vault, txn, &turn_id)?.is_none())
        {
            continue;
        }
        let deferred = crate::tagging::tagged_messages_absent_in_txn(&vault.store, txn, &turn_id)?;
        if deferred && candidate.carried {
            continue;
        }
        taken += usize::from(!deferred);
        admissible.push(AdmissibleTurnRow {
            learned_at,
            key: candidate.key,
            carried: candidate.carried,
            deferred,
            turn_id,
            role,
        });
    }
    Ok(Some(admissible))
}

/// Scans dirty turns: TURN entities (type 1) at temporal keys STRICTLY AFTER
/// the watermark's compound position `(last_learned_at, last_turn_id)` (or all
/// keys for a before-first rescan), in temporal-key order, passing the GATE-10 role
/// filter. Claims NEVER enter the working set (GATE-11 structural invariant —
/// the scan is type-filtered).
///
/// A Meso round is bounded by `min(limit, DEFAULT_MESO_ROUND_TURN_CAP)`; Micro
/// and Macro use `limit` as given. The cap may cut between two turns sharing
/// one `learned_at`: settling on the exact last consumed key
/// (`advance_watermark_to_turn`) is what lets the next round resume inside
/// that same second instead of replaying or stranding it.
pub fn scan_dirty_turns(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    watermark: &ConsolidationWatermark,
    limit: usize,
) -> Result<Vec<WorkingSetTurn>> {
    // Pass 1 under ONE read txn: temporal scan + type/role filter. Sessions
    // resolve in a second pass — LMDB allows one read txn per thread.
    let admissible = {
        let rtxn = vault.store.env.read_txn()?;
        enumerate_admissible_turns(
            vault,
            &rtxn,
            scope,
            watermark,
            None,
            effective_dirty_turn_limit(scope, limit),
            WakeStop::NEVER,
        )?
        // NEVER never stops, so the enumeration always yields its rows.
        .unwrap_or_default()
    };

    let mut out = Vec::with_capacity(admissible.len());
    for row in admissible.into_iter().filter(|row| !row.deferred) {
        out.push(WorkingSetTurn {
            turn_id: row.turn_id,
            role: row.role,
            learned_at: row.learned_at,
            carrier: row.carried.then_some(row.key),
            conversation: conversation_of(vault, &row.turn_id)?,
        });
    }
    Ok(out)
}

/// Collects the admissible dirty-turn IDs a planned round covers, through a
/// caller-owned write transaction, for snapshot fencing. It shares
/// [`enumerate_admissible_turns`] with [`scan_dirty_turns`] — same order, same
/// admissibility, same scope-keyed round cap — and drops only the conversation
/// pass, which is irrelevant to fencing.
///
/// The lower bound is the LIVE watermark read inside this transaction, not
/// `lower_exclusive` alone: enumeration starts strictly after the current
/// compound position and runs through `upper_inclusive`, so a planner that
/// advanced WITHIN the caller's second yields a different prefix here and the
/// caller's identity comparison defers the round. `lower_exclusive` is the
/// caller's claim about that position's second; when it no longer matches, the
/// round is stale and the answer is an empty set, never an error.
pub(crate) fn collect_dirty_turn_ids_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: DreamerConsolidationScope,
    lower_exclusive: u64,
    upper_inclusive: u64,
) -> Result<Vec<EntityId>> {
    // NEVER never stops, so the collection always yields its ids.
    Ok(collect_dirty_turn_ids_until(
        vault,
        txn,
        scope,
        lower_exclusive,
        upper_inclusive,
        WakeStop::NEVER,
    )?
    .unwrap_or_default())
}

/// [`collect_dirty_turn_ids_in_txn`] with a stop: `None` when `stop`
/// stopped the enumeration; nothing is fenced then.
pub(crate) fn collect_dirty_turn_ids_until(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: DreamerConsolidationScope,
    lower_exclusive: u64,
    upper_inclusive: u64,
    stop: WakeStop<'_>,
) -> Result<Option<Vec<EntityId>>> {
    // `upper_inclusive` may sit behind `lower_exclusive`: a round of pending
    // re-dirty carriers alone, which the cursor does not cut.
    let current = read_watermark_in_txn(vault, txn, scope)?;
    if current.last_learned_at != lower_exclusive {
        return Ok(Some(Vec::new()));
    }
    let Some(admissible) = enumerate_admissible_turns(
        vault,
        txn,
        scope,
        &current,
        Some(upper_inclusive),
        effective_dirty_turn_limit(scope, usize::MAX),
        stop,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(
        admissible
            .into_iter()
            .filter(|row| !row.deferred)
            .map(|row| row.turn_id)
            .collect(),
    ))
}

pub(super) fn read_turn_facts(vault: &Vault, id: &EntityId) -> Result<TurnBodyFacts> {
    let Some(raw) = vault.get_raw(id)? else {
        return Ok(TurnBodyFacts {
            speaker: None,
            text: None,
            world_ref: None,
            facet_ref: None,
            imported: false,
            import_source: None,
        });
    };
    Ok(decode_turn_body(
        &raw[ENTITY_METADATA_HEADER_LEN.min(raw.len())..],
    ))
}

/// [`read_turn_facts`] through a caller-owned write transaction. An absent row
/// decodes as the empty body (no `world_ref`/`facet_ref` signal), the same
/// fail-open-to-None the committed reader takes.
///
/// The custody seal is re-applied here BY HAND because this reader reaches the
/// row through [`Vault::get_raw_in`], which is deliberately UNSEALED for the
/// scrub/mirror passes whose whole job is to read the type byte and refuse. A
/// partition planner is not one of those passes, and `conversation_ref` is an
/// edge target that carries no type filter, so without this check the in-txn
/// twin would decode a SECRET_CUSTODY body in the clear on exactly the row the
/// committed twin refuses through the sealed [`Vault::get_raw`] — and the
/// "byte-identical partition keys" claim on [`plan_partitions_in_txn`] would be
/// false at the one row where it matters most.
pub(super) fn read_turn_facts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<TurnBodyFacts> {
    let Some(raw) = vault.get_raw_in(txn, id)? else {
        return Ok(decode_turn_body(&[]));
    };
    if EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY)
    {
        return Err(crate::secret_custody::reject_secret_custody_byte());
    }
    // A TURN whose words a deletion withdrew reads as the empty body, as the
    // committed twin reads it through `Vault::get_raw`.
    if !crate::ports::raw_readable_in_txn(&vault.store, txn, id, &raw)? {
        return Ok(decode_turn_body(&[]));
    }
    Ok(decode_turn_body(
        &raw[ENTITY_METADATA_HEADER_LEN.min(raw.len())..],
    ))
}

/// Read-only turn text for the retrieval tagger's shadow path.
pub(crate) fn turn_text_for_shadow(vault: &Vault, id: &EntityId) -> Result<String> {
    if vault.get_entity_type(id)? != Some(ENTITY_TYPE_TURN) {
        return Err(invalid_consolidation("shadow tag input must be a turn"));
    }
    super::turn_text::read_turn_text(vault, id)?
        .into_text()
        .ok_or_else(|| invalid_consolidation("turn has no text"))
}
