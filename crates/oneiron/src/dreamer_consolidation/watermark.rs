use std::io::Cursor;

use rmpv::Value;

use super::support::{
    DEFAULT_MESO_ROUND_TURN_CAP, DREAMER_PRIVATE_WATERMARK_PREFIX, KEY_LAST_LEARNED_AT,
    KEY_LAST_TURN_ID, KEY_SCHEMA_VERSION, TURN_BODY_FACET_REF_KEY, TURN_BODY_WORLD_REF_KEY,
    WATERMARK_SCHEMA_VERSION, WATERMARK_SCHEMA_VERSION_V1, decode_value, encode_value, expect_key,
    expect_map, invalid_consolidation, scope_byte,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::dreamer_runner::{
    DreamerConsolidationScope, DreamerTurnRole, dreamer_extraction_role_admissible,
    dreamer_turn_role,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TURN;

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
    /// None = end-of-second boundary; Some(id) = exact temporal-index key.
    ///
    /// The sentinel is deliberate, NOT Rust tuple ordering: `None` means every
    /// key at `last_learned_at` is behind the cursor, which is what bootstrap
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
    /// The turn's CONVERSATION (`conversation_of(turn)`) — the consolidation
    /// grouping key. Never a SESSION entity: the canonical SESSION (type 2)
    /// is one time-bounded visit to a conversation (ONE-1685 resolved the
    /// 7-way "session" naming collision; this field was the misnomer).
    pub conversation: Option<EntityId>,
}

pub(super) fn watermark_key(scope: DreamerConsolidationScope) -> Vec<u8> {
    let mut key = Vec::with_capacity(DREAMER_PRIVATE_WATERMARK_PREFIX.len() + 1);
    key.extend_from_slice(DREAMER_PRIVATE_WATERMARK_PREFIX);
    key.push(scope_byte(scope));
    key
}

/// Reads the per-scope watermark; absent row = bootstrap watermark 0.
pub fn read_watermark(
    vault: &Vault,
    scope: DreamerConsolidationScope,
) -> Result<ConsolidationWatermark> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &watermark_key(scope))? else {
        return Ok(ConsolidationWatermark::bootstrap());
    };
    decode_watermark(&raw)
}

/// Reads the per-scope watermark inside a caller-owned write transaction
/// (the ONE-1685 session close re-reads it to guard its pre-planned round
/// against a concurrent planner).
pub(crate) fn read_watermark_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
) -> Result<ConsolidationWatermark> {
    let Some(raw) = vault.store.vault_meta.get(txn, &watermark_key(scope))? else {
        return Ok(ConsolidationWatermark::bootstrap());
    };
    decode_watermark(&raw)
}

/// Complete-second administrative adapter — writes `last_turn_id = None`,
/// treating the whole second as consumed; bounded rounds must use the
/// exact-position path.
///
/// Call ONLY after the round's attempts are enqueued+committed — a crash
/// before this re-scans, and idempotency rides the enqueue dedupe keys
/// (dedupe, never a lock).
pub fn advance_watermark(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    last_learned_at: u64,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    write_watermark_position_in_txn(vault, &mut wtxn, scope, last_learned_at, None)?;
    wtxn.commit()?;
    Ok(())
}

/// Settles the watermark on the EXACT temporal-index position of the last TURN
/// a bounded round consumed — the settlement API for in-crate bounded-round
/// callers. Unlike [`advance_watermark`] it never claims a whole second
/// completed, so a round the Meso cap cut mid-second resumes at the very next
/// temporal key instead of swallowing the rest of that second.
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
    write_watermark_position_in_txn(
        vault,
        &mut wtxn,
        scope,
        last_consumed.learned_at,
        Some(last_consumed.turn_id),
    )?;
    wtxn.commit()?;
    Ok(())
}

/// Settles a fenced round inside a caller-owned write transaction: composing
/// the advance into the same commit as the round's enqueue makes
/// "enqueued+committed before the advance" structural instead of ordered.
///
/// The caller has already matched its planned round against the
/// in-transaction snapshot, so this re-enumerates that SAME capped prefix
/// — through [`enumerate_admissible_turns`], from the current compound
/// watermark through `upper_learned_at` — and settles on its final
/// `(learned_at, id)`. An empty re-enumeration is the empty matched round:
/// nothing was planned through `upper_learned_at`, so the cursor takes that
/// complete-second position. Fail-closed on a backwards advance: rewinding the
/// cursor over consumed work would re-plan it.
pub(crate) fn advance_watermark_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    upper_learned_at: u64,
) -> Result<()> {
    let current = read_watermark_in_txn(vault, wtxn, scope)?;
    if upper_learned_at < current.last_learned_at {
        return Err(invalid_consolidation(
            "dreamer watermark cannot settle behind its own position",
        ));
    }
    let round = enumerate_admissible_turns(
        vault,
        wtxn,
        &current,
        Some(upper_learned_at),
        effective_dirty_turn_limit(scope, usize::MAX),
    )?;
    match round.last() {
        Some(last) => {
            write_watermark_position_in_txn(vault, wtxn, scope, last.learned_at, Some(last.turn_id))
        }
        None => write_watermark_position_in_txn(vault, wtxn, scope, upper_learned_at, None),
    }
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
    let encoded = encode_watermark(&ConsolidationWatermark {
        schema_version: WATERMARK_SCHEMA_VERSION,
        last_learned_at: learned_at,
        last_turn_id: turn_id,
    })?;
    vault
        .store
        .vault_meta
        .put(wtxn, &watermark_key(scope), &encoded)?;
    Ok(())
}

/// Encodes a watermark row. Every emitted row is schema v2 (no bulk rewrite
/// runs: a landed v1 row upgrades on its next advance).
pub(super) fn encode_watermark(watermark: &ConsolidationWatermark) -> Result<Vec<u8>> {
    encode_value(&Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(WATERMARK_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_LAST_LEARNED_AT),
            Value::from(watermark.last_learned_at),
        ),
        (
            Value::from(KEY_LAST_TURN_ID),
            watermark
                .last_turn_id
                .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        ),
    ]))
}

pub(super) fn decode_watermark(raw: &[u8]) -> Result<ConsolidationWatermark> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value, "dreamer watermark row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut last_learned_at = None;
    // Outer Option = "the pinned key was present"; inner = the sentinel.
    let mut last_turn_id: Option<Option<EntityId>> = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => {
                if schema_version.is_some() {
                    return Err(duplicate_watermark_key());
                }
                schema_version = Some(expect_watermark_u64(value)?);
            }
            KEY_LAST_LEARNED_AT => {
                if last_learned_at.is_some() {
                    return Err(duplicate_watermark_key());
                }
                last_learned_at = Some(expect_watermark_u64(value)?);
            }
            KEY_LAST_TURN_ID => {
                if last_turn_id.is_some() {
                    return Err(duplicate_watermark_key());
                }
                last_turn_id = Some(decode_watermark_turn_id(value)?);
            }
            _ => return Err(unpinned_watermark_key()),
        }
    }
    let schema_version =
        schema_version.ok_or(invalid_consolidation("missing dreamer watermark schema"))?;
    let last_turn_id = match schema_version {
        // A v1 row carries EXACTLY the two landed keys and means "through
        // second X": `last_turn_id` on it is as unpinned as any unknown key.
        WATERMARK_SCHEMA_VERSION_V1 => {
            if last_turn_id.is_some() {
                return Err(unpinned_watermark_key());
            }
            None
        }
        WATERMARK_SCHEMA_VERSION => last_turn_id.ok_or(invalid_consolidation(
            "missing dreamer watermark turn position",
        ))?,
        _ => {
            return Err(invalid_consolidation(
                "unsupported dreamer watermark schema",
            ));
        }
    };
    Ok(ConsolidationWatermark {
        schema_version,
        last_learned_at: last_learned_at.ok_or(invalid_consolidation(
            "missing dreamer watermark learned_at",
        ))?,
        last_turn_id,
    })
}

const fn duplicate_watermark_key() -> Error {
    invalid_consolidation("duplicate dreamer watermark key")
}

const fn unpinned_watermark_key() -> Error {
    invalid_consolidation("dreamer watermark key is not pinned")
}

fn expect_watermark_u64(value: &Value) -> Result<u64> {
    value.as_u64().ok_or(invalid_consolidation(
        "dreamer watermark counters must be unsigned integers",
    ))
}

/// `nil` = the end-of-second sentinel; binary = an exact 16-byte entity id.
fn decode_watermark_turn_id(value: &Value) -> Result<Option<EntityId>> {
    match value {
        Value::Nil => Ok(None),
        Value::Binary(bytes) => {
            let raw: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
                invalid_consolidation("dreamer watermark turn id must be 16 binary bytes")
            })?;
            Ok(Some(EntityId::from_bytes(raw).map_err(|_| {
                invalid_consolidation("dreamer watermark turn id is not a valid entity id")
            })?))
        }
        _ => Err(invalid_consolidation(
            "dreamer watermark turn id must be binary or nil",
        )),
    }
}

/// One admissible temporal-index row: its exact key position plus the GATE-10
/// role the enumerator already resolved from the turn body.
#[derive(Debug, Clone, Copy)]
struct AdmissibleTurnRow {
    learned_at: u64,
    turn_id: EntityId,
    role: DreamerTurnRole,
}

/// The 24-byte `learned_at` temporal-index key: `learned_at_be || entity_id`.
fn temporal_turn_key(learned_at: u64, turn_id: &EntityId) -> [u8; 24] {
    let mut key = [0_u8; 24];
    key[..8].copy_from_slice(&learned_at.to_be_bytes());
    key[8..].copy_from_slice(turn_id.as_bytes());
    key
}

/// The EXCLUSIVE lower key a resumed round seeks past. `Some(id)` is the exact
/// consumed key; `None` is the end-of-second sentinel, whose `0xff` id tail
/// puts every key at that second behind the cursor.
fn watermark_lower_key(watermark: &ConsolidationWatermark) -> [u8; 24] {
    match watermark.last_turn_id {
        Some(turn_id) => temporal_turn_key(watermark.last_learned_at, &turn_id),
        None => {
            let mut key = [u8::MAX; 24];
            key[..8].copy_from_slice(&watermark.last_learned_at.to_be_bytes());
            key
        }
    }
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
/// `watermark`'s compound position, in temporal-key `(learned_at, id)` order,
/// through `upper_inclusive_second` (unbounded above when `None`), stopping at
/// `limit`.
///
/// Selection ORDER and ADMISSIBILITY are scope-independent — type-filtered to
/// TURN (claims NEVER enter the working set, GATE-11) and role-filtered by
/// GATE-10; only the round BOUND the caller resolves is scope-keyed. Scan,
/// snapshot fence, and settlement all read through here so the capped prefix
/// they each see cannot drift.
fn enumerate_admissible_turns(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    watermark: &ConsolidationWatermark,
    upper_inclusive_second: Option<u64>,
    limit: usize,
) -> Result<Vec<AdmissibleTurnRow>> {
    let lower = watermark_lower_key(watermark);
    let upper = upper_inclusive_second.map(|second| {
        let mut key = [u8::MAX; 24];
        key[..8].copy_from_slice(&second.to_be_bytes());
        key
    });
    let range: (std::ops::Bound<&[u8]>, std::ops::Bound<&[u8]>) = match upper.as_ref() {
        Some(upper) => (
            std::ops::Bound::Excluded(&lower[..]),
            std::ops::Bound::Included(&upper[..]),
        ),
        None => (
            std::ops::Bound::Excluded(&lower[..]),
            std::ops::Bound::Unbounded,
        ),
    };

    let mut admissible = Vec::new();
    for entry in vault.store.temporal_learned.range(txn, &range)? {
        if admissible.len() >= limit {
            break;
        }
        let (key, _) = entry?;
        if key.len() != 24 {
            continue;
        }
        let learned_at = u64::from_be_bytes(
            key[..8]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
        );
        let Ok(id_bytes) = <[u8; 16]>::try_from(&key[8..24]) else {
            continue;
        };
        let Ok(turn_id) = EntityId::from_bytes(id_bytes) else {
            continue;
        };
        let Some(raw) = vault.store.entities.get(txn, turn_id.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type != ENTITY_TYPE_TURN {
            continue;
        }
        let body = decode_turn_body(&raw[ENTITY_METADATA_HEADER_LEN..]);
        let role = dreamer_turn_role(body.speaker.as_deref());
        if !dreamer_extraction_role_admissible(role) {
            continue;
        }
        admissible.push(AdmissibleTurnRow {
            learned_at,
            turn_id,
            role,
        });
    }
    Ok(admissible)
}

/// Scans dirty turns: TURN entities (type 1) at temporal keys STRICTLY AFTER
/// the watermark's compound position `(last_learned_at, last_turn_id)`, in
/// temporal-key `(learned_at, id)` order, each passing the GATE-10 role
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
            watermark,
            None,
            effective_dirty_turn_limit(scope, limit),
        )?
    };

    let mut out = Vec::with_capacity(admissible.len());
    for row in admissible {
        out.push(WorkingSetTurn {
            turn_id: row.turn_id,
            role: row.role,
            learned_at: row.learned_at,
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
    wtxn: &heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    lower_exclusive: u64,
    upper_inclusive: u64,
) -> Result<Vec<EntityId>> {
    // Equality is NOT degenerate: with `last_turn_id = Some(id)` it is the
    // live same-second continuation round.
    if lower_exclusive > upper_inclusive {
        return Ok(Vec::new());
    }
    let current = read_watermark_in_txn(vault, wtxn, scope)?;
    if current.last_learned_at != lower_exclusive {
        return Ok(Vec::new());
    }
    let admissible = enumerate_admissible_turns(
        vault,
        wtxn,
        &current,
        Some(upper_inclusive),
        effective_dirty_turn_limit(scope, usize::MAX),
    )?;
    Ok(admissible.into_iter().map(|row| row.turn_id).collect())
}

pub(crate) struct TurnBodyFacts {
    pub(crate) speaker: Option<String>,
    pub(crate) text: Option<String>,
    pub(crate) world_ref: Option<EntityId>,
    pub(crate) facet_ref: Option<EntityId>,
}

/// The ONE turn-body decoder. In-crate planners (the ONE-1685 session-close
/// wake) share it so a turn's GATE-10 role can never be read one way by the
/// scan and another way by the planner: first-wins across the `spkr|speaker`
/// alias set, exactly as [`enumerate_admissible_turns`] admits it.
pub(crate) fn decode_turn_body(raw: &[u8]) -> TurnBodyFacts {
    let mut facts = TurnBodyFacts {
        speaker: None,
        text: None,
        world_ref: None,
        facet_ref: None,
    };
    let Ok(value) = rmpv::decode::read_value(&mut Cursor::new(raw)) else {
        return facts;
    };
    let Value::Map(entries) = value else {
        return facts;
    };
    for (key, value) in entries {
        match key.as_str() {
            Some("spkr" | "speaker") => {
                if facts.speaker.is_none() {
                    facts.speaker = value.as_str().map(str::to_owned);
                }
            }
            Some("txt" | "text") => {
                if facts.text.is_none() {
                    facts.text = value.as_str().map(str::to_owned);
                }
            }
            Some(TURN_BODY_WORLD_REF_KEY) => facts.world_ref = entity_ref_from_value(&value),
            Some(TURN_BODY_FACET_REF_KEY) => facts.facet_ref = entity_ref_from_value(&value),
            _ => {}
        }
    }
    facts
}

/// Validator for the documented opt-in `world_ref`/`facet_ref` turn-body
/// keys: exactly 16 MessagePack-binary bytes forming a valid entity id.
#[must_use]
pub fn entity_ref_from_value(value: &Value) -> Option<EntityId> {
    let Value::Binary(bytes) = value else {
        return None;
    };
    let raw: [u8; 16] = bytes.as_slice().try_into().ok()?;
    EntityId::from_bytes(raw).ok()
}

pub(super) fn conversation_of(vault: &Vault, turn_id: &EntityId) -> Result<Option<EntityId>> {
    Ok(vault
        .edges_out(turn_id)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::ChildOf)
        .map(|edge| edge.target))
}

pub(super) fn read_turn_facts(vault: &Vault, id: &EntityId) -> Result<TurnBodyFacts> {
    let Some(raw) = vault.get_raw(id)? else {
        return Ok(TurnBodyFacts {
            speaker: None,
            text: None,
            world_ref: None,
            facet_ref: None,
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
    txn: &heed::RwTxn<'_>,
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
    Ok(decode_turn_body(
        &raw[ENTITY_METADATA_HEADER_LEN.min(raw.len())..],
    ))
}
