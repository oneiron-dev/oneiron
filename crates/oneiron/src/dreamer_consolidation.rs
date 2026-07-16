//! Dreamer consolidation algorithm + reflection gap scan (ONE-1289,
//! DREAM-002; DESIGN-PIN-20260710 Part A).
//!
//! Phases: 0 — global `learned_at` watermark scan selects dirty TURN
//! entities (claims never enter the working set, GATE-11); 1 — work
//! partitions in turn vocabulary `(conversation, world, facet)`; 2 —
//! post-extraction semantic candidate buckets keyed on
//! `(subject, predicate_root, world, facet)`; 3 — mechanical BLAKE3
//! evidence collapse, then the deterministic conflict trigger on the FULL
//! predicate, with only conflicting sets entering scoped LLM merge steps;
//! 4 — the reflection gap scan with dedupe/decay and escalate-once.
//!
//! This module NEVER writes belief claims: surviving candidates go to the
//! promotion writer (`dreamer_promotion`, ONE-1290) through a
//! [`ConsolidationSink`]. The watermark is the selection authority; the
//! landed offset pager and every `ledger_revision` hint are efficiency
//! devices only, never authority (1184-D1).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, claim_consolidatable,
    claim_evidence_admissible, predicate_root,
};
use crate::dreamer_runner::{
    DreamerClaimAuthoringStrategy, DreamerConsolidationScope, DreamerRunnerStore, DreamerTurnRole,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
    dreamer_extraction_role_admissible, dreamer_turn_role,
};
use crate::dreamer_wake::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepResult, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, ModelId,
    ModelLocality, ModelTierRef, ResponseFormat, StepOutcome, TierPrecedence, call_as_step,
};
use crate::registry::ENTITY_TYPE_TURN;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

/// Domain for phase-2 candidate-bucket hashes (pinned, design D6). The
/// phase-1 partition hash keeps this domain unchanged (DESIGN-PIN A2).
pub const DREAMER_BUCKET_HASH_DOMAIN: &[u8] = b"oneiron:dreamer-bucket:v1";
/// Domain for reflection gap hashes (pinned, design D6).
pub const DREAMER_GAP_HASH_DOMAIN: &[u8] = b"oneiron:dreamer-gap:v1";
/// Domain for deterministic, write-once promotion-candidate claim ids. A
/// candidate's id is a pure function of its identity + the owning attempt so an
/// at-least-once re-run of the same durable step re-mints the SAME id.
pub const DREAMER_CLAIM_ID_HASH_DOMAIN: &[u8] = b"oneiron:dreamer-claim-id:v1";
/// Domain for swarm evidence content hashes (pinned, design D10).
pub const DREAMER_EVIDENCE_HASH_DOMAIN: &[u8] = b"oneiron:dreamer-evidence:v1";
/// A gap not re-observed within this window decays and is never re-surfaced
/// (escalate-or-let-go, never re-nag nightly).
pub const DREAMER_GAP_DECAY_MS: u64 = 14 * 24 * 60 * 60 * 1000;
/// `DreamerAttemptPayload.attempt_type` string for reflection gap-scan child
/// attempts (a payload discriminator, not a new queue kind).
pub const DREAMER_GAP_SCAN_ATTEMPT_TYPE: &str = "dreamer.reflection.gap_scan";
/// Documented OPT-IN turn-body key naming the WORLD entity this turn's
/// content belongs to (16-byte MessagePack binary; ILD D4 opt-in precedent).
pub const TURN_BODY_WORLD_REF_KEY: &str = "world_ref";
/// Documented OPT-IN turn-body key naming the active FACET at turn time
/// (16-byte MessagePack binary). Absent = "channel gave no mask signal";
/// extraction may still assign one — it does NOT force the invariant layer.
pub const TURN_BODY_FACET_REF_KEY: &str = "facet_ref";

const DREAMER_PRIVATE_WATERMARK_PREFIX: &[u8] = b"dreamer:watermark:v1:"; // + scope byte
const DREAMER_PRIVATE_CURSOR_PREFIX: &[u8] = b"dreamer:cursor:v1:"; // + scope byte + partition_hash(32)
const DREAMER_PRIVATE_GAP_PREFIX: &[u8] = b"dreamer:gap:v1:"; // + gap_hash(32)

const WATERMARK_SCHEMA_VERSION: u64 = 1;
const CURSOR_SCHEMA_VERSION: u64 = 1;
const GAP_SCHEMA_VERSION: u64 = 1;
const PARTITION_PAYLOAD_SCHEMA_VERSION: u64 = 1;

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_LAST_LEARNED_AT: &str = "last_learned_at";
const KEY_LAST_LEDGER_REVISION_HINT: &str = "last_ledger_revision_hint";
const KEY_KIND: &str = "kind";
const KEY_SUBJECT: &str = "subject";
const KEY_EVIDENCE_TURN_REFS: &str = "evidence_turn_refs";
const KEY_FIRST_SEEN: &str = "first_seen";
const KEY_LAST_SEEN: &str = "last_seen";
const KEY_ESCALATIONS: &str = "escalations";
const KEY_DECAYED: &str = "decayed";
const KEY_CONVERSATION: &str = "conversation_ref";
const KEY_WORLD: &str = "world_ref";
const KEY_FACET: &str = "facet_ref";
const KEY_WATERMARK: &str = "watermark";
const KEY_TURNS: &str = "turns";

const fn invalid_consolidation(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

fn scope_byte(scope: DreamerConsolidationScope) -> u8 {
    match scope {
        DreamerConsolidationScope::Micro => 0,
        DreamerConsolidationScope::Meso => 1,
        DreamerConsolidationScope::Macro => 2,
    }
}

// ---------------------------------------------------------------------------
// Promotion candidate (D7 shape) — DEFINED here (the producer);
// dreamer_promotion (ONE-1290) re-exports it.
// ---------------------------------------------------------------------------

/// One consolidated belief candidate handed to the promotion writer
/// (`dreamer_promotion::promote_consolidated_claims`, ONE-1290).
#[derive(Debug, Clone, PartialEq)]
pub struct PromotionCandidate {
    /// Caller-minted, write-once claim id.
    pub claim_id: EntityId,
    pub candidate: ClaimCandidate,
    /// TURN entities only (GATE-11): the writer drops refs resolving to
    /// evidence-inadmissible CLAIM entities.
    pub evidence_turn_refs: Vec<EntityId>,
    /// At most ONE prior head (multi-claim contradictions route to the gap
    /// scan, never a multi-supersede).
    pub supersedes: Option<EntityId>,
    /// Lattice meet over every source read (GATE-05); `Generated` when no
    /// external reads happened.
    pub evidence_meet: ClaimSource,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

/// Where surviving candidates go. ONE-1290's promotion writer is the real
/// implementation; tests stub it. This module never writes claims.
pub trait ConsolidationSink {
    fn accept(&mut self, candidates: Vec<PromotionCandidate>) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Phase 0 — global watermark scan (dirty-turn selection)
// ---------------------------------------------------------------------------

/// Per-scope consolidation watermark: the `learned_at` scan authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsolidationWatermark {
    pub schema_version: u64,
    pub last_learned_at: u64,
}

impl ConsolidationWatermark {
    /// Bootstrap: an absent row IS watermark 0 (DESIGN-PIN A1).
    #[must_use]
    pub const fn bootstrap() -> Self {
        Self {
            schema_version: WATERMARK_SCHEMA_VERSION,
            last_learned_at: 0,
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

fn watermark_key(scope: DreamerConsolidationScope) -> Vec<u8> {
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
    decode_watermark(raw)
}

/// Advances the per-scope watermark. Call ONLY after the round's attempts are
/// enqueued+committed — a crash before this re-scans, and idempotency rides
/// the enqueue dedupe keys (dedupe, never a lock).
pub fn advance_watermark(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    last_learned_at: u64,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    advance_watermark_in_txn(vault, &mut wtxn, scope, last_learned_at)?;
    wtxn.commit()?;
    Ok(())
}

/// [`advance_watermark`] inside a caller-owned write transaction: composing
/// the advance into the same commit as the round's enqueue makes
/// "enqueued+committed before the advance" structural instead of ordered.
pub(crate) fn advance_watermark_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    last_learned_at: u64,
) -> Result<()> {
    let encoded = encode_watermark(&ConsolidationWatermark {
        schema_version: WATERMARK_SCHEMA_VERSION,
        last_learned_at,
    })?;
    vault
        .store
        .vault_meta
        .put(wtxn, &watermark_key(scope), &encoded)?;
    Ok(())
}

fn encode_watermark(watermark: &ConsolidationWatermark) -> Result<Vec<u8>> {
    encode_value(&Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(watermark.schema_version),
        ),
        (
            Value::from(KEY_LAST_LEARNED_AT),
            Value::from(watermark.last_learned_at),
        ),
    ]))
}

fn decode_watermark(raw: &[u8]) -> Result<ConsolidationWatermark> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value, "dreamer watermark row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut last_learned_at = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => schema_version = value.as_u64(),
            KEY_LAST_LEARNED_AT => last_learned_at = value.as_u64(),
            _ => return Err(invalid_consolidation("dreamer watermark key is not pinned")),
        }
    }
    let schema_version =
        schema_version.ok_or(invalid_consolidation("missing dreamer watermark schema"))?;
    if schema_version != WATERMARK_SCHEMA_VERSION {
        return Err(invalid_consolidation(
            "unsupported dreamer watermark schema",
        ));
    }
    Ok(ConsolidationWatermark {
        schema_version,
        last_learned_at: last_learned_at.ok_or(invalid_consolidation(
            "missing dreamer watermark learned_at",
        ))?,
    })
}

/// Scans dirty turns: TURN entities (type 1) with
/// `learned_at > watermark.last_learned_at`, oldest-first, bounded by
/// `limit`, each passing the GATE-10 role filter. Claims NEVER enter the
/// working set (GATE-11 structural invariant — the scan is type-filtered).
pub fn scan_dirty_turns(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    watermark: &ConsolidationWatermark,
    limit: usize,
) -> Result<Vec<WorkingSetTurn>> {
    let _ = scope; // selection is scope-independent; scope keys the watermark row
    // Pass 1 under ONE read txn: temporal scan + type/role filter. Sessions
    // resolve in a second pass — LMDB allows one read txn per thread.
    let mut admissible: Vec<(EntityId, DreamerTurnRole, u64)> = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        let mut lower = [0_u8; 24];
        lower[..8].copy_from_slice(&watermark.last_learned_at.saturating_add(1).to_be_bytes());
        for entry in vault.store.temporal_learned.range(
            &rtxn,
            &(
                std::ops::Bound::Included(&lower[..]),
                std::ops::Bound::Unbounded,
            ),
        )? {
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
            let Some(raw) = vault.store.entities.get(&rtxn, turn_id.as_bytes())? else {
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
            admissible.push((turn_id, role, learned_at));
        }
    }

    let mut out = Vec::with_capacity(admissible.len());
    for (turn_id, role, learned_at) in admissible {
        out.push(WorkingSetTurn {
            turn_id,
            role,
            learned_at,
            conversation: conversation_of(vault, &turn_id)?,
        });
    }
    Ok(out)
}

/// Counts admissible dirty turns in a bounded learned-at window through a
/// caller-owned write transaction. This intentionally mirrors only Pass 1 of
/// [`scan_dirty_turns`]: conversation edges are irrelevant to snapshot fencing.
pub(crate) fn count_dirty_turns_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    lower_exclusive: u64,
    upper_inclusive: u64,
) -> Result<usize> {
    let _ = scope; // selection is scope-independent; scope identifies the fenced round
    if lower_exclusive >= upper_inclusive {
        return Ok(0);
    }

    let mut lower = [0_u8; 24];
    lower[..8].copy_from_slice(&(lower_exclusive + 1).to_be_bytes());
    let mut upper = [u8::MAX; 24];
    upper[..8].copy_from_slice(&upper_inclusive.to_be_bytes());

    let mut count = 0;
    for entry in vault.store.temporal_learned.range(
        wtxn,
        &(
            std::ops::Bound::Included(&lower[..]),
            std::ops::Bound::Included(&upper[..]),
        ),
    )? {
        let (key, _) = entry?;
        if key.len() != 24 {
            continue;
        }
        let Ok(id_bytes) = <[u8; 16]>::try_from(&key[8..24]) else {
            continue;
        };
        let Ok(turn_id) = EntityId::from_bytes(id_bytes) else {
            continue;
        };
        let Some(raw) = vault.store.entities.get(wtxn, turn_id.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(raw) else {
            continue;
        };
        if header.entity_type != ENTITY_TYPE_TURN {
            continue;
        }
        let body = decode_turn_body(&raw[ENTITY_METADATA_HEADER_LEN..]);
        let role = dreamer_turn_role(body.speaker.as_deref());
        if dreamer_extraction_role_admissible(role) {
            count += 1;
        }
    }
    Ok(count)
}

struct TurnBodyFacts {
    speaker: Option<String>,
    text: Option<String>,
    world_ref: Option<EntityId>,
    facet_ref: Option<EntityId>,
}

fn decode_turn_body(raw: &[u8]) -> TurnBodyFacts {
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

fn conversation_of(vault: &Vault, turn_id: &EntityId) -> Result<Option<EntityId>> {
    Ok(vault
        .edges_out(turn_id)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::ChildOf)
        .map(|edge| edge.target))
}

// ---------------------------------------------------------------------------
// Phase 1 — work partitions (turn vocabulary ONLY)
// ---------------------------------------------------------------------------

/// Phase-1 partition key: pre-extraction turn vocabulary — no subject, no
/// predicate, by design (predicates mint at extraction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsolidationPartitionKey {
    pub conversation_ref: EntityId,
    pub world_ref: Option<EntityId>,
    pub facet_ref: Option<EntityId>,
}

impl ConsolidationPartitionKey {
    /// Domain-separated BLAKE3 over the partition key (domain unchanged
    /// from D6's cursor derivation, DESIGN-PIN A2).
    #[must_use]
    pub fn partition_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DREAMER_BUCKET_HASH_DOMAIN);
        hasher.update(b"partition");
        hasher.update(self.conversation_ref.as_bytes());
        hash_optional_entity(&mut hasher, self.world_ref.as_ref());
        hash_optional_entity(&mut hasher, self.facet_ref.as_ref());
        *hasher.finalize().as_bytes()
    }
}

fn hash_optional_entity(hasher: &mut blake3::Hasher, entity: Option<&EntityId>) {
    match entity {
        Some(entity) => {
            hasher.update(&[1]);
            hasher.update(entity.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

/// Per-partition cursor row. `last_ledger_revision_hint` is an EFFICIENCY
/// HINT only — never consulted for admission decisions (1184-D1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsolidationCursor {
    pub schema_version: u64,
    pub last_learned_at: u64,
    pub last_ledger_revision_hint: u64,
}

/// One planned partition attempt over the dirty turns that fell into it.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsolidationPartitionPlan {
    pub key: ConsolidationPartitionKey,
    pub turns: Vec<WorkingSetTurn>,
    pub watermark_last_learned_at: u64,
}

fn cursor_key(scope: DreamerConsolidationScope, partition_hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(DREAMER_PRIVATE_CURSOR_PREFIX.len() + 1 + 32);
    key.extend_from_slice(DREAMER_PRIVATE_CURSOR_PREFIX);
    key.push(scope_byte(scope));
    key.extend_from_slice(partition_hash);
    key
}

/// Reads a partition cursor row.
pub fn read_cursor(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    partition_hash: &[u8; 32],
) -> Result<Option<ConsolidationCursor>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &cursor_key(scope, partition_hash))?
    else {
        return Ok(None);
    };
    decode_cursor(&raw).map(Some)
}

/// Writes a partition cursor row (advance ONLY after the bucket's promotion
/// pass completes).
pub fn write_cursor(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    partition_hash: &[u8; 32],
    cursor: &ConsolidationCursor,
) -> Result<()> {
    let encoded = encode_cursor(cursor)?;
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &cursor_key(scope, partition_hash), &encoded)?;
    wtxn.commit()?;
    Ok(())
}

fn encode_cursor(cursor: &ConsolidationCursor) -> Result<Vec<u8>> {
    encode_value(&Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(cursor.schema_version),
        ),
        (
            Value::from(KEY_LAST_LEARNED_AT),
            Value::from(cursor.last_learned_at),
        ),
        (
            Value::from(KEY_LAST_LEDGER_REVISION_HINT),
            Value::from(cursor.last_ledger_revision_hint),
        ),
    ]))
}

fn decode_cursor(raw: &[u8]) -> Result<ConsolidationCursor> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value, "dreamer cursor row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut last_learned_at = None;
    let mut hint = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => schema_version = value.as_u64(),
            KEY_LAST_LEARNED_AT => last_learned_at = value.as_u64(),
            KEY_LAST_LEDGER_REVISION_HINT => hint = value.as_u64(),
            _ => return Err(invalid_consolidation("dreamer cursor key is not pinned")),
        }
    }
    let schema_version =
        schema_version.ok_or(invalid_consolidation("missing dreamer cursor schema"))?;
    if schema_version != CURSOR_SCHEMA_VERSION {
        return Err(invalid_consolidation("unsupported dreamer cursor schema"));
    }
    Ok(ConsolidationCursor {
        schema_version,
        last_learned_at: last_learned_at
            .ok_or(invalid_consolidation("missing dreamer cursor learned_at"))?,
        last_ledger_revision_hint: hint.unwrap_or(0),
    })
}

/// Groups dirty turns into work partitions. `conversation_ref` comes from
/// the structural ChildOf edge; `world_ref`/`facet_ref` from the documented
/// opt-in body keys with the fallback chain body-key-on-turn → conversation
/// body key → None (facet None = "channel gave no mask signal"; world None
/// = base reality — the connector-level facet fallback applies at ingest
/// time, where connectors stamp the body key).
pub fn plan_partitions(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    dirty_turns: &[WorkingSetTurn],
    watermark: &ConsolidationWatermark,
) -> Result<Vec<ConsolidationPartitionPlan>> {
    let _ = scope;
    let mut plans: BTreeMap<ConsolidationPartitionKey, Vec<WorkingSetTurn>> = BTreeMap::new();
    for turn in dirty_turns {
        let Some(conversation_ref) = turn.conversation else {
            // A turn without its structural conversation edge cannot be
            // partitioned; skip fail-closed rather than invent a partition.
            continue;
        };
        let turn_facts = read_turn_facts(vault, &turn.turn_id)?;
        let conversation_facts = read_turn_facts(vault, &conversation_ref)?;
        let key = ConsolidationPartitionKey {
            conversation_ref,
            world_ref: turn_facts.world_ref.or(conversation_facts.world_ref),
            facet_ref: turn_facts.facet_ref.or(conversation_facts.facet_ref),
        };
        plans.entry(key).or_default().push(*turn);
    }
    Ok(plans
        .into_iter()
        .map(|(key, turns)| ConsolidationPartitionPlan {
            key,
            turns,
            watermark_last_learned_at: watermark.last_learned_at,
        })
        .collect())
}

fn read_turn_facts(vault: &Vault, id: &EntityId) -> Result<TurnBodyFacts> {
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

/// One partition plan as its production enqueue input: the executor-
/// decodable payload ([`encode_partition_payload`]) plus the advisory
/// dedupe key `hex(partition_hash):watermark`.
fn partition_attempt_input(
    scope: DreamerConsolidationScope,
    plan: &ConsolidationPartitionPlan,
    run_id: Option<String>,
    now: u64,
) -> EnqueueDreamerConsolidationAttempt {
    let dedupe_key = format!(
        "{}:{}",
        bytes_to_hex_lower(&plan.key.partition_hash()),
        plan.watermark_last_learned_at
    );
    EnqueueDreamerConsolidationAttempt {
        scope,
        input: encode_partition_payload(plan),
        parent_attempt: None,
        dedupe_key: Some(dedupe_key),
        run_id,
        now,
    }
}

/// Enqueues one consolidation attempt per partition plan with the advisory
/// dedupe key `hex(partition_hash):watermark` (idempotency floor — two
/// devices planning the same partition coalesce, never lock).
pub fn enqueue_partition_attempts(
    store: &DreamerRunnerStore<'_>,
    scope: DreamerConsolidationScope,
    plans: &[ConsolidationPartitionPlan],
    run_id: &str,
    now: u64,
) -> Result<Vec<EnqueueDreamerAttemptOutcome>> {
    let mut outcomes = Vec::with_capacity(plans.len());
    for plan in plans {
        outcomes.push(store.enqueue_consolidation(partition_attempt_input(
            scope,
            plan,
            Some(run_id.to_owned()),
            now,
        ))?);
    }
    Ok(outcomes)
}

/// [`enqueue_partition_attempts`] inside a caller-owned write transaction —
/// the ONE-1685 session close enqueues its SessionEnd → Meso round in the
/// SAME transaction that stamps `ended_at`, so an attempt row exists exactly
/// when the end committed.
pub(crate) fn enqueue_partition_attempts_in_txn(
    store: &DreamerRunnerStore<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    plans: &[ConsolidationPartitionPlan],
    run_id: Option<&str>,
    now: u64,
) -> Result<Vec<EnqueueDreamerAttemptOutcome>> {
    let mut outcomes = Vec::with_capacity(plans.len());
    for plan in plans {
        outcomes.push(store.enqueue_consolidation_in_txn(
            wtxn,
            partition_attempt_input(scope, plan, run_id.map(str::to_owned), now),
        )?);
    }
    Ok(outcomes)
}

fn encode_partition_payload(plan: &ConsolidationPartitionPlan) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(PARTITION_PAYLOAD_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_CONVERSATION),
            Value::Binary(plan.key.conversation_ref.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_WORLD),
            plan.key
                .world_ref
                .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        ),
        (
            Value::from(KEY_FACET),
            plan.key
                .facet_ref
                .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        ),
        (
            Value::from(KEY_WATERMARK),
            Value::from(plan.watermark_last_learned_at),
        ),
        (
            Value::from(KEY_TURNS),
            Value::Array(
                plan.turns
                    .iter()
                    .map(|turn| Value::Binary(turn.turn_id.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
    ])
}

/// Decodes a partition attempt payload back into its plan facts.
pub fn decode_partition_payload(
    value: &Value,
) -> Result<(ConsolidationPartitionKey, Vec<EntityId>, u64)> {
    let entries = expect_map(value, "dreamer partition payload must be a MessagePack map")?;
    let mut conversation = None;
    let mut world = None;
    let mut facet = None;
    let mut watermark = None;
    let mut turns = Vec::new();
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => {}
            KEY_CONVERSATION => conversation = entity_ref_from_value(value),
            KEY_WORLD => world = entity_ref_from_value(value),
            KEY_FACET => facet = entity_ref_from_value(value),
            KEY_WATERMARK => watermark = value.as_u64(),
            KEY_TURNS => {
                let Value::Array(items) = value else {
                    return Err(invalid_consolidation(
                        "partition payload turns must be an array",
                    ));
                };
                for item in items {
                    turns.push(entity_ref_from_value(item).ok_or(invalid_consolidation(
                        "partition payload turn refs must be 16-byte binary",
                    ))?);
                }
            }
            _ => return Err(invalid_consolidation("partition payload key is not pinned")),
        }
    }
    Ok((
        ConsolidationPartitionKey {
            conversation_ref: conversation.ok_or(invalid_consolidation(
                "partition payload missing conversation_ref",
            ))?,
            world_ref: world,
            facet_ref: facet,
        },
        turns,
        watermark.ok_or(invalid_consolidation("partition payload missing watermark"))?,
    ))
}

// ---------------------------------------------------------------------------
// Phase 2 — candidate buckets (post-extraction, semantic)
// ---------------------------------------------------------------------------

/// Phase-2 semantic bucket key. Facet stays in the key BY CANON (ARCH-0022:
/// same Person + different Facets must NOT merge behavioral profiles).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsolidationBucketKey {
    pub subject: EntityId,
    pub predicate_root: String,
    pub world: Option<EntityId>,
    pub facet: Option<EntityId>,
}

impl ConsolidationBucketKey {
    /// Domain-separated BLAKE3 over the bucket key (pinned domain
    /// `oneiron:dreamer-bucket:v1`, design D6).
    #[must_use]
    pub fn bucket_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DREAMER_BUCKET_HASH_DOMAIN);
        hasher.update(b"bucket");
        hasher.update(self.subject.as_bytes());
        hasher.update(&(self.predicate_root.len() as u64).to_be_bytes());
        hasher.update(self.predicate_root.as_bytes());
        hash_optional_entity(&mut hasher, self.world.as_ref());
        hash_optional_entity(&mut hasher, self.facet.as_ref());
        *hasher.finalize().as_bytes()
    }
}

/// One phase-2 bucket over candidate indexes into the caller's slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsolidationBucketPlan {
    pub key: ConsolidationBucketKey,
    pub candidate_indexes: Vec<usize>,
}

/// Semantic identity facts of one candidate, derived through the envelope
/// stamping path (`ClaimCandidate` keeps its fields private by design).
struct CandidateFacts {
    subject: EntityId,
    predicate: String,
    value: Value,
    world: Option<EntityId>,
    facet: Option<EntityId>,
}

fn candidate_facts(candidate: &ClaimCandidate) -> Result<CandidateFacts> {
    // A throwaway envelope: into_claim_body only stamps envelope-owned
    // metadata; the identity fields we read are candidate-owned.
    let envelope = WriteEnvelope::new(
        WriteActor::new(candidate_probe_actor(), crate::edge::EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::from("dreamer-consolidation-probe"))?,
        ClaimApprovalStatus::Proposed,
    );
    let body = candidate.clone().into_claim_body(&envelope);
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(invalid_consolidation(
            "consolidation candidates must have entity subjects",
        ));
    };
    Ok(CandidateFacts {
        subject,
        predicate: body.predicate,
        value: body.value,
        world: body.world,
        facet: facet_from_scope(body.scope.as_ref()),
    })
}

fn candidate_probe_actor() -> EntityId {
    EntityId::from_bytes([0x11; 16]).unwrap_or_else(|_| unreachable!("constant id is valid"))
}

/// Reads the facet scope entry (engine-owned scope-map pattern; the same
/// idiom as `federated_original_source`).
fn facet_from_scope(scope: Option<&Value>) -> Option<EntityId> {
    let Some(Value::Map(entries)) = scope else {
        return None;
    };
    entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some(TURN_BODY_FACET_REF_KEY))
            .then(|| entity_ref_from_value(value))
            .flatten()
    })
}

/// Groups candidates into semantic buckets on
/// `(subject, predicate_root, world, facet)`.
pub fn plan_candidate_buckets(
    candidates: &[PromotionCandidate],
) -> Result<Vec<ConsolidationBucketPlan>> {
    let mut buckets: BTreeMap<ConsolidationBucketKey, Vec<usize>> = BTreeMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let facts = candidate_facts(&candidate.candidate)?;
        let key = ConsolidationBucketKey {
            subject: facts.subject,
            predicate_root: predicate_root(&facts.predicate).to_owned(),
            world: facts.world,
            facet: facts.facet,
        };
        buckets.entry(key).or_default().push(index);
    }
    Ok(buckets
        .into_iter()
        .map(|(key, candidate_indexes)| ConsolidationBucketPlan {
            key,
            candidate_indexes,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Phase 3 — mechanical evidence collapse + deterministic conflict trigger
// ---------------------------------------------------------------------------

/// Swarm evidence reference — the HASH-ONLY boundary (GATE-05): a child
/// return structurally cannot carry source bytes; identity is
/// `(source_id, content_hash)` and comparisons use exactly those two
/// fields (trust ties resolve to the most restrictive at collapse time).
#[derive(Debug, Clone, Copy)]
pub struct SwarmEvidenceRef {
    pub source_id: EntityId,
    pub content_hash: [u8; 32],
    pub trust_class: ClaimSource,
}

impl SwarmEvidenceRef {
    const fn identity(&self) -> (EntityId, [u8; 32]) {
        (self.source_id, self.content_hash)
    }
}

impl PartialEq for SwarmEvidenceRef {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl Eq for SwarmEvidenceRef {}

impl PartialOrd for SwarmEvidenceRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SwarmEvidenceRef {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.identity().cmp(&other.identity())
    }
}

/// One swarm child's return: evidence hashes ONLY (raw content never
/// crosses the boundary — no field can carry it), candidate claims AS
/// DATA, and the weave's read pin.
#[derive(Debug, Clone, PartialEq)]
pub struct SwarmChildReturn {
    /// Evidence hashes as a `Vec`, deliberately NOT a set keyed on
    /// identity: two refs sharing one `(source_id, content_hash)` but
    /// differing in `trust_class` must BOTH reach
    /// `collapse_sibling_evidence`, the single authority that melts a
    /// same-identity tie to the most-restrictive class. A set would drop
    /// the stricter tie at insertion (identity-only `Ord`), silently
    /// inflating trust before the meet ever runs.
    pub evidence: Vec<SwarmEvidenceRef>,
    pub candidates: Vec<PromotionCandidate>,
    /// The max `learned_at` watermark captured ONCE at weave start and
    /// stamped into every child payload.
    pub read_pin: u64,
}

/// Mechanically collapsed evidence: N siblings citing one
/// `(source_id, content_hash)` are ONE independent signal.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CollapsedEvidence {
    pub independent: Vec<SwarmEvidenceRef>,
    pub duplicates_collapsed: u32,
}

/// Content hash over the entity's stored body bytes AFTER the metadata
/// header (`raw[ENTITY_METADATA_HEADER_LEN..]`) — byte-identical across
/// devices by storage construction. Domain-separated BLAKE3.
#[must_use]
pub fn swarm_evidence_content_hash(entity_body_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DREAMER_EVIDENCE_HASH_DOMAIN);
    hasher.update(entity_body_bytes);
    *hasher.finalize().as_bytes()
}

/// BLAKE3 identity collapse across sibling children (GATE-05): dedupe by
/// `(source_id, content_hash)`; trust ties on one identity resolve to the
/// MOST restrictive class.
pub fn collapse_sibling_evidence(children: &[SwarmChildReturn]) -> Result<CollapsedEvidence> {
    let mut independent: BTreeMap<(EntityId, [u8; 32]), SwarmEvidenceRef> = BTreeMap::new();
    let mut duplicates_collapsed = 0_u32;
    for child in children {
        for entry in &child.evidence {
            match independent.entry(entry.identity()) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(*entry);
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    duplicates_collapsed += 1;
                    let kept = slot.get_mut();
                    kept.trust_class = source_meet(kept.trust_class, entry.trust_class);
                }
            }
        }
    }
    Ok(CollapsedEvidence {
        independent: independent.into_values().collect(),
        duplicates_collapsed,
    })
}

/// Most-restrictive trust meet over every source read (GATE-05). Lattice
/// order, high→low: `UserStated > Observed > Inferred = Generated >
/// ToolOutput > Imported`. Empty input = `Generated`, the Dreamer's own
/// floor. Feeds `PromotionCandidate::evidence_meet` (ONE-1290 consumes:
/// meet at/below ToolOutput forces Proposed + `scope.evidence_taint`).
#[allow(single_use_lifetimes)] // pinned public signature (brief ONE-1385); anonymous impl-Trait lifetimes are unstable on this toolchain
pub fn evidence_trust_meet<'a>(refs: impl Iterator<Item = &'a SwarmEvidenceRef>) -> ClaimSource {
    refs.fold(ClaimSource::Generated, |meet, entry| {
        source_meet(meet, entry.trust_class)
    })
}

/// Rejects a child return whose `read_pin` differs from the weave's pin —
/// the result is discarded and counted by the caller, never merged.
pub fn validate_child_read_pin(expected: u64, child: &SwarmChildReturn) -> Result<()> {
    if child.read_pin != expected {
        return Err(invalid_consolidation(
            "dreamer swarm child read pin mismatch",
        ));
    }
    Ok(())
}

/// Turn → trust_class derivation (DESIGN-PIN Part B1, ratified R4):
/// native User → `UserStated`; native Assistant → `Generated` (never
/// Observed — two assistant turns must not corroborate each other above
/// the Proposed-forcing floor); imported-transcript turns → `Imported`
/// regardless of role; every other role is never classified (GATE-10
/// excludes it). The reachable working-set meet space is therefore
/// {UserStated, Generated, Imported}.
#[must_use]
pub const fn turn_trust_class(
    role: DreamerTurnRole,
    imported_transcript: bool,
) -> Option<ClaimSource> {
    if !dreamer_extraction_role_admissible(role) {
        return None;
    }
    if imported_transcript {
        return Some(ClaimSource::Imported);
    }
    match role {
        DreamerTurnRole::User => Some(ClaimSource::UserStated),
        DreamerTurnRole::Assistant => Some(ClaimSource::Generated),
        _ => None,
    }
}

/// A prior head consulted as merge context. Admission REQUIRES
/// `claim_consolidatable`; corroboration additionally requires
/// `claim_evidence_admissible` (GATE-11 — Generated-origin priors are
/// merge-eligible but contribute ZERO corroboration).
#[derive(Debug, Clone, PartialEq)]
pub struct PriorHead {
    pub claim_id: EntityId,
    pub body: ClaimBody,
}

/// Full-identity conflict key (A4): the FULL predicate — not the root —
/// refines identity WITHIN a bucket.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConflictIdentity {
    pub subject: EntityId,
    pub predicate: String,
    pub world: Option<EntityId>,
    pub facet: Option<EntityId>,
}

/// One conflicting set: same full identity, non-equal canonical values.
#[derive(Debug, Clone, PartialEq)]
pub struct ConflictSet {
    pub identity: ConflictIdentity,
    pub candidate_indexes: Vec<usize>,
    /// The consolidatable prior head with the same identity, when present.
    pub prior_head: Option<EntityId>,
}

/// Deterministic conflict trigger (DESIGN-PIN A4):
/// `CONFLICT(a,b) ⇔ same (subject, FULL predicate, world, facet) AND
/// canonical_value(a) != canonical_value(b)`. `b` ranges over sibling
/// candidates AND the prior head admitted via `claim_consolidatable`.
/// By key construction: facet-local, null-shadow, world-local.
pub fn detect_conflicts(
    candidates: &[PromotionCandidate],
    prior_heads: &[PriorHead],
) -> Result<Vec<ConflictSet>> {
    let mut groups: BTreeMap<ConflictIdentity, Vec<(usize, Vec<u8>)>> = BTreeMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let facts = candidate_facts(&candidate.candidate)?;
        let identity = ConflictIdentity {
            subject: facts.subject,
            predicate: facts.predicate,
            world: facts.world,
            facet: facts.facet,
        };
        groups
            .entry(identity)
            .or_default()
            .push((index, canonical_value_bytes(&facts.value)?));
    }

    let mut conflicts = Vec::new();
    for (identity, members) in groups {
        let prior = prior_heads.iter().find(|prior| {
            claim_consolidatable(&prior.body) && prior_matches_identity(&prior.body, &identity)
        });
        let mut values: BTreeSet<&[u8]> =
            members.iter().map(|(_, bytes)| bytes.as_slice()).collect();
        let mut prior_value = None;
        if let Some(prior) = prior {
            let bytes = canonical_value_bytes(&prior.body.value)?;
            prior_value = Some(bytes);
        }
        if let Some(bytes) = &prior_value {
            values.insert(bytes.as_slice());
        }
        if values.len() > 1 {
            conflicts.push(ConflictSet {
                identity,
                candidate_indexes: members.into_iter().map(|(index, _)| index).collect(),
                prior_head: prior.map(|prior| prior.claim_id),
            });
        }
    }
    Ok(conflicts)
}

fn prior_matches_identity(body: &ClaimBody, identity: &ConflictIdentity) -> bool {
    let ClaimSubject::Entity(subject) = body.subject else {
        return false;
    };
    subject == identity.subject
        && body.predicate == identity.predicate
        && body.world == identity.world
        && facet_from_scope(body.scope.as_ref()) == identity.facet
}

fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>> {
    encode_value(&canonicalize_value(value))
}

/// Derives a [`PromotionCandidate`]'s write-once claim id DETERMINISTICALLY
/// from its identity (owning attempt, subject, predicate, canonical value, world,
/// facet).
///
/// `EntityId::now()` mints a fresh id on every call, so under the wake
/// driver's at-least-once re-execution (a crash after `sink.accept` but before
/// the attempt completes) a memoized step re-run would hand the promotion writer
/// NEW ids for the same beliefs — DUPLICATE claims. A content-addressed id is
/// stable across re-runs (and independent of `now`), so promotion stays
/// idempotent (#485-3).
fn deterministic_claim_id(
    attempt_id: crate::attempt_queue::AttemptId,
    subject: EntityId,
    predicate: &str,
    value: &Value,
    world: Option<EntityId>,
    facet: Option<EntityId>,
) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DREAMER_CLAIM_ID_HASH_DOMAIN);
    hasher.update(attempt_id.as_bytes());
    hasher.update(subject.as_bytes());
    hasher.update(&(predicate.len() as u64).to_le_bytes());
    hasher.update(predicate.as_bytes());
    let value_bytes = canonical_value_bytes(value).unwrap_or_default();
    hasher.update(&(value_bytes.len() as u64).to_le_bytes());
    hasher.update(&value_bytes);
    hasher.update(&[u8::from(world.is_some())]);
    if let Some(world) = world {
        hasher.update(world.as_bytes());
    }
    hasher.update(&[u8::from(facet.is_some())]);
    if let Some(facet) = facet {
        hasher.update(facet.as_bytes());
    }
    let digest = hasher.finalize();
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&digest.as_bytes()[..16]);
    // A blake3 prefix colliding with a reserved id is ~2^-120; perturb
    // deterministically rather than fall back to a non-deterministic id.
    EntityId::from_bytes(raw).unwrap_or_else(|_| {
        raw[0] ^= 0x01;
        raw[15] ^= 0x01;
        EntityId::from_bytes(raw).expect("perturbed derived claim id is non-reserved")
    })
}

/// Recursively sorts every `Value::Map`'s entries by their MessagePack-encoded
/// key so canonical bytes are independent of map key order.
///
/// `json_to_rmpv` preserves serde_json object order and the workspace enables
/// serde_json `preserve_order`, so the LLM's key order flows verbatim into the
/// candidate value. Without this, two semantically identical objects that
/// differ only in key order encode differently and `detect_conflicts` sees a
/// FALSE conflict — spurious merge LLM calls, escalations, and gap writes
/// (#485-4).
fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_value).collect()),
        Value::Map(entries) => {
            let mut canon: Vec<(Vec<u8>, Value, Value)> = entries
                .iter()
                .map(|(key, val)| {
                    let key = canonicalize_value(key);
                    let val = canonicalize_value(val);
                    // Encoding a Value into a Vec never fails; a deterministic
                    // total order over encoded keys is all that is required.
                    let mut sort_key = Vec::new();
                    let _ = rmpv::encode::write_value(&mut sort_key, &key);
                    (sort_key, key, val)
                })
                .collect();
            canon.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Map(canon.into_iter().map(|(_, key, val)| (key, val)).collect())
        }
        other => other.clone(),
    }
}

/// Independent corroboration for one candidate: collapsed turn evidence
/// counts once per source; prior CLAIM refs count ONLY when
/// `claim_evidence_admissible` (GATE-11: Generated-origin priors add zero).
#[must_use]
pub fn corroboration_count(collapsed: &CollapsedEvidence, prior_heads: &[PriorHead]) -> usize {
    let prior_signals = prior_heads
        .iter()
        .filter(|prior| claim_evidence_admissible(&prior.body))
        .count();
    collapsed.independent.len() + prior_signals
}

// ---------------------------------------------------------------------------
// Phase 4 — reflection gap scan
// ---------------------------------------------------------------------------

/// The pinned gap taxonomy — exactly these four kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReflectionGapKind {
    MissingFollowUp,
    UnresolvedThread,
    StatedIntentWithoutAction,
    ContradictionLeftStanding,
}

impl ReflectionGapKind {
    /// Stable kind string for gap rows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingFollowUp => "missing_follow_up",
            Self::UnresolvedThread => "unresolved_thread",
            Self::StatedIntentWithoutAction => "stated_intent_without_action",
            Self::ContradictionLeftStanding => "contradiction_left_standing",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "missing_follow_up" => Some(Self::MissingFollowUp),
            "unresolved_thread" => Some(Self::UnresolvedThread),
            "stated_intent_without_action" => Some(Self::StatedIntentWithoutAction),
            "contradiction_left_standing" => Some(Self::ContradictionLeftStanding),
            _ => None,
        }
    }

    const fn byte(self) -> u8 {
        match self {
            Self::MissingFollowUp => 0,
            Self::UnresolvedThread => 1,
            Self::StatedIntentWithoutAction => 2,
            Self::ContradictionLeftStanding => 3,
        }
    }
}

/// One observed reflection gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectionGap {
    pub kind: ReflectionGapKind,
    pub subject: EntityId,
    pub evidence_turn_refs: Vec<EntityId>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub escalations: u32,
    pub decayed: bool,
}

/// Gap identity hash: BLAKE3 over domain + kind byte + subject bytes +
/// normalized description.
#[must_use]
pub fn gap_hash(kind: ReflectionGapKind, subject: &EntityId, description: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DREAMER_GAP_HASH_DOMAIN);
    hasher.update(&[kind.byte()]);
    hasher.update(subject.as_bytes());
    hasher.update(description.trim().to_ascii_lowercase().as_bytes());
    *hasher.finalize().as_bytes()
}

/// Outcome of one gap-queue upsert pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GapQueueDelta {
    pub created: u32,
    pub refreshed: u32,
    pub decayed: u32,
    /// Gaps due their ONE escalation per lifetime (the caller routes these
    /// through the promotion writer as Proposed inbox claims — ONE-1290).
    pub escalations: Vec<ReflectionGap>,
}

/// v1 deterministic gap detectors over the working set (taxonomy + queue
/// mechanics are the deliverable; detector quality iterates post-ship):
/// a user turn ending the conversation unanswered → `UnresolvedThread`;
/// a user turn asking a question with no later assistant turn in the set →
/// `MissingFollowUp`; a user turn declaring intent ("i will"/"i'll") →
/// `StatedIntentWithoutAction`. `ContradictionLeftStanding` gaps are fed by
/// the reducer's escalate outcomes, not this scan.
pub fn scan_reflection_gaps(
    vault: &Vault,
    working_set: &[WorkingSetTurn],
    now: u64,
) -> Result<Vec<ReflectionGap>> {
    let mut by_conversation: BTreeMap<EntityId, Vec<&WorkingSetTurn>> = BTreeMap::new();
    for turn in working_set {
        if let Some(conversation) = turn.conversation {
            by_conversation.entry(conversation).or_default().push(turn);
        }
    }

    let mut gaps = Vec::new();
    for (conversation, mut turns) in by_conversation {
        turns.sort_by_key(|turn| turn.learned_at);
        let Some(last) = turns.last() else {
            continue;
        };
        if last.role == DreamerTurnRole::User {
            gaps.push(ReflectionGap {
                kind: ReflectionGapKind::UnresolvedThread,
                subject: conversation,
                evidence_turn_refs: vec![last.turn_id],
                first_seen: now,
                last_seen: now,
                escalations: 0,
                decayed: false,
            });
        }
        for (position, turn) in turns.iter().enumerate() {
            if turn.role != DreamerTurnRole::User {
                continue;
            }
            let text = read_turn_facts(vault, &turn.turn_id)?
                .text
                .unwrap_or_default()
                .to_ascii_lowercase();
            let answered = turns[position + 1..]
                .iter()
                .any(|later| later.role == DreamerTurnRole::Assistant);
            if text.contains('?') && !answered {
                gaps.push(ReflectionGap {
                    kind: ReflectionGapKind::MissingFollowUp,
                    subject: conversation,
                    evidence_turn_refs: vec![turn.turn_id],
                    first_seen: now,
                    last_seen: now,
                    escalations: 0,
                    decayed: false,
                });
            }
            if text.contains("i will ") || text.contains("i'll ") {
                gaps.push(ReflectionGap {
                    kind: ReflectionGapKind::StatedIntentWithoutAction,
                    subject: conversation,
                    evidence_turn_refs: vec![turn.turn_id],
                    first_seen: now,
                    last_seen: now,
                    escalations: 0,
                    decayed: false,
                });
            }
        }
    }
    Ok(gaps)
}

fn gap_row_key(hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(DREAMER_PRIVATE_GAP_PREFIX.len() + 32);
    key.extend_from_slice(DREAMER_PRIVATE_GAP_PREFIX);
    key.extend_from_slice(hash);
    key
}

/// Upserts observed gaps into the private gap queue: re-observation
/// refreshes `last_seen`; a stored gap not re-observed within
/// [`DREAMER_GAP_DECAY_MS`] decays and is never re-surfaced; the FIRST
/// insertion of a gap earns its single per-lifetime escalation.
pub fn upsert_gap_queue(
    vault: &Vault,
    gaps: Vec<ReflectionGap>,
    now: u64,
) -> Result<GapQueueDelta> {
    let mut delta = GapQueueDelta::default();
    let mut observed: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut wtxn = vault.store.env.write_txn()?;

    for gap in gaps {
        let hash = gap_hash(gap.kind, &gap.subject, "");
        let key = gap_row_key(&hash);
        observed.insert(key.clone());
        match vault.store.vault_meta.get(&wtxn, &key)? {
            Some(raw) => {
                let mut stored = decode_gap_row(&raw)?;
                if stored.decayed {
                    // Decayed gaps are let go — never re-surfaced.
                    continue;
                }
                stored.last_seen = now;
                stored.evidence_turn_refs = gap.evidence_turn_refs;
                let encoded = encode_gap_row(&stored)?;
                vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
                delta.refreshed += 1;
            }
            None => {
                let stored = ReflectionGap {
                    first_seen: now,
                    last_seen: now,
                    escalations: 1,
                    decayed: false,
                    ..gap
                };
                let encoded = encode_gap_row(&stored)?;
                vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
                delta.created += 1;
                delta.escalations.push(stored);
            }
        }
    }

    // Decay pass over stored gaps that were NOT re-observed this round.
    let stale: Vec<(Vec<u8>, ReflectionGap)> = {
        let mut stale = Vec::new();
        for row in vault
            .store
            .vault_meta
            .prefix_iter(&wtxn, DREAMER_PRIVATE_GAP_PREFIX)?
        {
            let (key, raw) = row?;
            if observed.contains(key.as_ref()) {
                continue;
            }
            let stored = decode_gap_row(&raw)?;
            if !stored.decayed && now.saturating_sub(stored.last_seen) >= DREAMER_GAP_DECAY_MS {
                stale.push((key.to_vec(), stored));
            }
        }
        stale
    };
    for (key, mut stored) in stale {
        stored.decayed = true;
        let encoded = encode_gap_row(&stored)?;
        vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        delta.decayed += 1;
    }

    wtxn.commit()?;
    Ok(delta)
}

fn encode_gap_row(gap: &ReflectionGap) -> Result<Vec<u8>> {
    encode_value(&Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(GAP_SCHEMA_VERSION),
        ),
        (Value::from(KEY_KIND), Value::from(gap.kind.as_str())),
        (
            Value::from(KEY_SUBJECT),
            Value::Binary(gap.subject.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_EVIDENCE_TURN_REFS),
            Value::Array(
                gap.evidence_turn_refs
                    .iter()
                    .map(|id| Value::Binary(id.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (Value::from(KEY_FIRST_SEEN), Value::from(gap.first_seen)),
        (Value::from(KEY_LAST_SEEN), Value::from(gap.last_seen)),
        (Value::from(KEY_ESCALATIONS), Value::from(gap.escalations)),
        (Value::from(KEY_DECAYED), Value::from(gap.decayed)),
    ]))
}

fn decode_gap_row(raw: &[u8]) -> Result<ReflectionGap> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value, "dreamer gap row must be a MessagePack map")?;
    let mut kind = None;
    let mut subject = None;
    let mut evidence = Vec::new();
    let mut first_seen = None;
    let mut last_seen = None;
    let mut escalations = None;
    let mut decayed = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => {}
            KEY_KIND => {
                kind = value.as_str().and_then(ReflectionGapKind::parse);
            }
            KEY_SUBJECT => subject = entity_ref_from_value(value),
            KEY_EVIDENCE_TURN_REFS => {
                if let Value::Array(items) = value {
                    for item in items {
                        if let Some(id) = entity_ref_from_value(item) {
                            evidence.push(id);
                        }
                    }
                }
            }
            KEY_FIRST_SEEN => first_seen = value.as_u64(),
            KEY_LAST_SEEN => last_seen = value.as_u64(),
            KEY_ESCALATIONS => escalations = value.as_u64(),
            KEY_DECAYED => decayed = value.as_bool(),
            _ => return Err(invalid_consolidation("dreamer gap row key is not pinned")),
        }
    }
    Ok(ReflectionGap {
        kind: kind.ok_or(invalid_consolidation("missing dreamer gap kind"))?,
        subject: subject.ok_or(invalid_consolidation("missing dreamer gap subject"))?,
        evidence_turn_refs: evidence,
        first_seen: first_seen.ok_or(invalid_consolidation("missing dreamer gap first_seen"))?,
        last_seen: last_seen.ok_or(invalid_consolidation("missing dreamer gap last_seen"))?,
        escalations: u32::try_from(escalations.unwrap_or(0))
            .map_err(|_| invalid_consolidation("dreamer gap escalations out of range"))?,
        decayed: decayed.unwrap_or(false),
    })
}

// ---------------------------------------------------------------------------
// Phase 3 executor — bucket attempts over the step layer
// ---------------------------------------------------------------------------

/// Extraction/merge executor for partition attempts. Implements ONE-1288's
/// [`DreamerAttemptExecutor`]: decodes the partition payload, extracts
/// candidates AS DATA through `call_as_step` (single-pass strategy),
/// resolves conflicts, and hands survivors to the [`ConsolidationSink`].
/// The tournament strategy routes through the landed `dreamer_tournament`
/// machinery under its admission gate (steps still via `call_as_step`).
pub struct ConsolidationExecutor<'a> {
    pub backend: &'a dyn LlmBackend,
    pub guard: &'a BudgetGuard,
    pub strategy: DreamerClaimAuthoringStrategy,
    pub actor: WriteActor,
    pub model: ModelId,
    pub sink: &'a mut dyn ConsolidationSink,
}

/// Outcome of the (possibly multi-step) LLM work inside one consolidation
/// partition attempt.
///
/// `Trapped` means a durable `call_as_step` suspended the attempt — the step layer
/// has ALREADY parked it for resume. A trapped attempt must therefore Park, never
/// Complete: no candidates are accepted (the work is not silently dropped-as-
/// done) and no `ContradictionLeftStanding` gap is written from a merge that
/// never decided. On resume the memoized steps replay and the attempt re-runs to a
/// real decision (#485-1, #485-2).
enum PartitionRun {
    Completed {
        candidates: Vec<PromotionCandidate>,
        spent: u64,
    },
    Trapped,
}

impl ConsolidationExecutor<'_> {
    fn extraction_request(
        &self,
        partition: &ConsolidationPartitionKey,
        transcript: &str,
    ) -> LlmRequest {
        let system = "Extract durable memory claims from the conversation transcript. \
             Respond with JSON: {\"candidates\": [{\"subject\": \"<32-hex entity id>\", \
             \"predicate\": \"<dotted.predicate>\", \"value\": <json>, \"confidence\": <0..1>, \
             \"evidence_turn_refs\": [\"<32-hex turn id>\"]}]}. Only claims stated by the \
             user or assistant; never invent evidence refs.";
        LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                purpose: CallPurpose::Extraction,
                class: CallClass::BestEffort,
                tier: TierPrecedence {
                    per_call: None,
                    vault_policy: None,
                    purpose_default: None,
                    global_default: ModelTierRef("consolidation".to_owned()),
                },
                response_format: ResponseFormat::Json {
                    schema: serde_json::json!({"type": "object"}),
                },
                locality: ModelLocality::OwnServer,
            },
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: system.to_owned(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text {
                        text: format!(
                            "conversation {}\n{transcript}",
                            bytes_to_hex_lower(partition.conversation_ref.as_bytes())
                        ),
                    }],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        }
    }

    fn decode_candidates(
        &self,
        partition: &ConsolidationPartitionKey,
        response: &LlmResponse,
        attempt_id: crate::attempt_queue::AttemptId,
        now_ms: u64,
    ) -> Result<Vec<PromotionCandidate>> {
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        let parsed: serde_json::Value = serde_json::from_str(text.trim())
            .map_err(|_| invalid_consolidation("extraction response must be JSON"))?;
        let Some(items) = parsed.get("candidates").and_then(|value| value.as_array()) else {
            return Ok(Vec::new());
        };

        let mut candidates = Vec::new();
        for item in items {
            let Some(subject) = item
                .get("subject")
                .and_then(|value| value.as_str())
                .and_then(entity_id_from_hex)
            else {
                continue;
            };
            let Some(predicate) = item.get("predicate").and_then(|value| value.as_str()) else {
                continue;
            };
            let confidence = item
                .get("confidence")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.5) as f32;
            let value = json_to_rmpv(item.get("value").unwrap_or(&serde_json::Value::Null));
            let claim_id = deterministic_claim_id(
                attempt_id,
                subject,
                predicate,
                &value,
                partition.world_ref,
                partition.facet_ref,
            );
            let evidence_turn_refs: Vec<EntityId> = item
                .get("evidence_turn_refs")
                .and_then(|value| value.as_array())
                .map(|refs| {
                    refs.iter()
                        .filter_map(|entry| entry.as_str().and_then(entity_id_from_hex))
                        .collect()
                })
                .unwrap_or_default();

            let mut candidate =
                ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, confidence);
            if let Some(world) = partition.world_ref {
                candidate = candidate.with_world(world);
            }
            if let Some(facet) = partition.facet_ref {
                candidate = candidate.with_scope(Value::Map(vec![(
                    Value::from(TURN_BODY_FACET_REF_KEY),
                    Value::Binary(facet.as_bytes().to_vec()),
                )]));
            }
            candidates.push(PromotionCandidate {
                claim_id,
                candidate,
                evidence_turn_refs,
                supersedes: None,
                evidence_meet: ClaimSource::Generated,
                occurred: TimeRange {
                    start: now_ms,
                    end: now_ms,
                },
                learned_at: now_ms,
            });
        }
        Ok(candidates)
    }

    async fn run_partition_attempt(
        &mut self,
        payload_input: &Value,
        ctx: &WakeAttemptContext<'_>,
        attempt_id: crate::attempt_queue::AttemptId,
        run_id: Option<String>,
    ) -> DurableStepResult<PartitionRun> {
        let run_id_ref = run_id.as_ref();
        let (partition, turn_ids, _watermark) = decode_partition_payload(payload_input)?;

        let mut transcript = String::new();
        for turn_id in &turn_ids {
            let facts = read_turn_facts(ctx.vault, turn_id)?;
            let speaker = facts.speaker.unwrap_or_else(|| "unknown".to_owned());
            let text = facts.text.unwrap_or_default();
            transcript.push_str(&format!(
                "[{} {}] {}\n",
                bytes_to_hex_lower(turn_id.as_bytes()),
                speaker,
                text
            ));
        }

        let step_ctx = DurableStepContext {
            vault: ctx.vault,
            attempt_id,
            run_id: run_id_ref.cloned(),
            envelope_actor: self.actor,
            subject: partition.conversation_ref,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        let request = self.extraction_request(&partition, &transcript);
        let outcome = call_as_step(&step_ctx, self.backend, self.guard, request).await?;
        let (response, spent) = match outcome {
            StepOutcome::Finished { response, .. } => {
                let spent = response
                    .usage
                    .input
                    .total
                    .saturating_add(response.usage.output.total);
                (response, spent)
            }
            // The extraction step suspended: the attempt is parked. Surface the
            // trap so `execute` parks it for resume instead of completing an
            // empty extraction (#485-1).
            StepOutcome::Trapped(_) => return Ok(PartitionRun::Trapped),
        };
        let candidates = self.decode_candidates(&partition, &response, attempt_id, ctx.now_ms)?;
        match self
            .resolve_conflicts(
                candidates,
                ctx,
                attempt_id_for_steps(attempt_id, run_id_ref),
            )
            .await?
        {
            PartitionRun::Completed {
                candidates,
                spent: merge_spent,
            } => Ok(PartitionRun::Completed {
                candidates,
                spent: spent.saturating_add(merge_spent),
            }),
            PartitionRun::Trapped => Ok(PartitionRun::Trapped),
        }
    }

    /// Scoped LLM merge over conflicting sets — ONLY conflicting sets. One
    /// `call_as_step` per set with the pinned outcome vocabulary:
    /// `merge` (one merged value) | `supersede` (single prior head — with no
    /// prior in scope it degrades to merge) | `accumulate` (multi-value
    /// predicates keep all) | `escalate` (drop the set to the gap queue as
    /// `ContradictionLeftStanding`; contradictions never land silently).
    async fn resolve_conflicts(
        &mut self,
        candidates: Vec<PromotionCandidate>,
        ctx: &WakeAttemptContext<'_>,
        step_identity: (crate::attempt_queue::AttemptId, Option<String>),
    ) -> DurableStepResult<PartitionRun> {
        let conflicts = detect_conflicts(&candidates, &[])?;
        if conflicts.is_empty() {
            return Ok(PartitionRun::Completed {
                candidates,
                spent: 0,
            });
        }

        let mut dropped: BTreeSet<usize> = BTreeSet::new();
        let mut merged: Vec<PromotionCandidate> = Vec::new();
        let mut escalated: Vec<ReflectionGap> = Vec::new();
        let mut spent = 0_u64;

        for conflict in &conflicts {
            let members: Vec<&PromotionCandidate> = conflict
                .candidate_indexes
                .iter()
                .map(|index| &candidates[*index])
                .collect();
            let request = self.merge_request(&conflict.identity, &members)?;
            let step_ctx = DurableStepContext {
                vault: ctx.vault,
                attempt_id: step_identity.0,
                run_id: step_identity.1.clone(),
                envelope_actor: self.actor,
                subject: conflict.identity.subject,
                deadline: Some(ctx.deadline),
                now_ms: ctx.now_ms,
            };
            let outcome = call_as_step(&step_ctx, self.backend, self.guard, request).await?;
            let response = match outcome {
                StepOutcome::Finished { response, .. } => {
                    spent = spent.saturating_add(
                        response
                            .usage
                            .input
                            .total
                            .saturating_add(response.usage.output.total),
                    );
                    response
                }
                StepOutcome::Trapped(_) => {
                    // Suspended mid-merge: the attempt is parked. STOP and surface
                    // the trap. Writing a contradiction gap here would fabricate
                    // a `ContradictionLeftStanding` for a merge that never
                    // decided (#485-2); accepting partial survivors would drop
                    // the rest as done. On resume the memoized steps replay and
                    // this merge re-runs to a real resolution.
                    return Ok(PartitionRun::Trapped);
                }
            };

            match decode_merge_resolution(&response)? {
                MergeResolution::Accumulate => {} // keep every member
                MergeResolution::Merge { value } => {
                    dropped.extend(conflict.candidate_indexes.iter().copied());
                    merged.push(merged_candidate(
                        conflict,
                        &members,
                        value,
                        step_identity.0,
                        ctx.now_ms,
                    ));
                }
                MergeResolution::Escalate => {
                    dropped.extend(conflict.candidate_indexes.iter().copied());
                    escalated.push(contradiction_gap(conflict, &members, ctx.now_ms));
                }
            }
        }

        if !escalated.is_empty() {
            upsert_gap_queue(ctx.vault, escalated, ctx.now_ms)?;
        }

        let mut surviving: Vec<PromotionCandidate> = candidates
            .into_iter()
            .enumerate()
            .filter_map(|(index, candidate)| (!dropped.contains(&index)).then_some(candidate))
            .collect();
        surviving.extend(merged);
        Ok(PartitionRun::Completed {
            candidates: surviving,
            spent,
        })
    }

    fn merge_request(
        &self,
        identity: &ConflictIdentity,
        members: &[&PromotionCandidate],
    ) -> Result<LlmRequest> {
        let mut lines = String::new();
        for member in members {
            let facts = candidate_facts(&member.candidate)?;
            lines.push_str(&format!(
                "- value: {}\n",
                serde_json::to_string(&rmpv_to_json(&facts.value)).unwrap_or_default()
            ));
        }
        let system = "Conflicting values were extracted for one claim identity. Respond \
             with JSON: {\"resolution\": \"merge\"|\"accumulate\"|\"escalate\", \
             \"value\": <json when resolution is merge>}. Choose accumulate only for \
             genuinely multi-valued predicates; escalate real contradictions.";
        Ok(LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                purpose: CallPurpose::Consolidation,
                class: CallClass::BestEffort,
                tier: TierPrecedence {
                    per_call: None,
                    vault_policy: None,
                    purpose_default: None,
                    global_default: ModelTierRef("consolidation".to_owned()),
                },
                response_format: ResponseFormat::Json {
                    schema: serde_json::json!({"type": "object"}),
                },
                locality: ModelLocality::OwnServer,
            },
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: system.to_owned(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text {
                        text: format!("predicate {}\n{lines}", identity.predicate),
                    }],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        })
    }
}

enum MergeResolution {
    Merge { value: Value },
    Accumulate,
    Escalate,
}

fn decode_merge_resolution(response: &LlmResponse) -> Result<MergeResolution> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let parsed: serde_json::Value = serde_json::from_str(text.trim())
        .map_err(|_| invalid_consolidation("merge response must be JSON"))?;
    match parsed.get("resolution").and_then(|value| value.as_str()) {
        // With no prior head in scope, supersede degrades to merge (D7: at
        // most one prior head; the promotion writer owns the supersession).
        Some("merge" | "supersede") => Ok(MergeResolution::Merge {
            value: json_to_rmpv(parsed.get("value").unwrap_or(&serde_json::Value::Null)),
        }),
        Some("accumulate") => Ok(MergeResolution::Accumulate),
        Some("escalate") => Ok(MergeResolution::Escalate),
        _ => Err(invalid_consolidation("unknown merge resolution")),
    }
}

fn merged_candidate(
    conflict: &ConflictSet,
    members: &[&PromotionCandidate],
    value: Value,
    attempt_id: crate::attempt_queue::AttemptId,
    now_ms: u64,
) -> PromotionCandidate {
    let mut evidence: Vec<EntityId> = Vec::new();
    let mut meet = ClaimSource::UserStated;
    let mut confidence = 0.0_f32;
    for member in members {
        for turn in &member.evidence_turn_refs {
            if !evidence.contains(turn) {
                evidence.push(*turn);
            }
        }
        meet = source_meet(meet, member.evidence_meet);
        confidence = confidence.max(0.5);
    }
    let claim_id = deterministic_claim_id(
        attempt_id,
        conflict.identity.subject,
        &conflict.identity.predicate,
        &value,
        conflict.identity.world,
        conflict.identity.facet,
    );
    let mut candidate = ClaimCandidate::new(
        conflict.identity.predicate.clone(),
        ClaimSubject::Entity(conflict.identity.subject),
        value,
        confidence,
    );
    if let Some(world) = conflict.identity.world {
        candidate = candidate.with_world(world);
    }
    if let Some(facet) = conflict.identity.facet {
        candidate = candidate.with_scope(Value::Map(vec![(
            Value::from(TURN_BODY_FACET_REF_KEY),
            Value::Binary(facet.as_bytes().to_vec()),
        )]));
    }
    PromotionCandidate {
        claim_id,
        candidate,
        evidence_turn_refs: evidence,
        supersedes: conflict.prior_head,
        evidence_meet: meet,
        occurred: TimeRange {
            start: now_ms,
            end: now_ms,
        },
        learned_at: now_ms,
    }
}

/// Lattice meet (most restrictive wins) over the D10 order
/// `UserStated > Observed > Inferred = Generated > ToolOutput > Imported`.
/// ONE-1385 hardens/pins this as the boundary contract.
fn source_meet(left: ClaimSource, right: ClaimSource) -> ClaimSource {
    const fn rank(source: ClaimSource) -> u8 {
        match source {
            ClaimSource::UserStated => 4,
            ClaimSource::Observed => 3,
            ClaimSource::Inferred | ClaimSource::Generated => 2,
            ClaimSource::ToolOutput => 1,
            ClaimSource::Imported => 0,
        }
    }
    if rank(right) < rank(left) {
        right
    } else {
        left
    }
}

fn contradiction_gap(
    conflict: &ConflictSet,
    members: &[&PromotionCandidate],
    now_ms: u64,
) -> ReflectionGap {
    let mut evidence: Vec<EntityId> = Vec::new();
    for member in members {
        for turn in &member.evidence_turn_refs {
            if !evidence.contains(turn) {
                evidence.push(*turn);
            }
        }
    }
    ReflectionGap {
        kind: ReflectionGapKind::ContradictionLeftStanding,
        subject: conflict.identity.subject,
        evidence_turn_refs: evidence,
        first_seen: now_ms,
        last_seen: now_ms,
        escalations: 0,
        decayed: false,
    }
}

fn rmpv_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Nil => serde_json::Value::Null,
        Value::Boolean(flag) => serde_json::Value::Bool(*flag),
        Value::Integer(number) => number
            .as_u64()
            .map(serde_json::Value::from)
            .or_else(|| number.as_i64().map(serde_json::Value::from))
            .unwrap_or(serde_json::Value::Null),
        Value::F32(number) => serde_json::Value::from(f64::from(*number)),
        Value::F64(number) => serde_json::Value::from(*number),
        Value::String(text) => text
            .as_str()
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
        Value::Array(items) => serde_json::Value::Array(items.iter().map(rmpv_to_json).collect()),
        Value::Map(entries) => serde_json::Value::Object(
            entries
                .iter()
                .filter_map(|(key, value)| {
                    key.as_str()
                        .map(|key| (key.to_owned(), rmpv_to_json(value)))
                })
                .collect(),
        ),
        _ => serde_json::Value::Null,
    }
}

fn attempt_id_for_steps(
    attempt_id: crate::attempt_queue::AttemptId,
    run_id: Option<&String>,
) -> (crate::attempt_queue::AttemptId, Option<String>) {
    (attempt_id, run_id.cloned())
}

impl DreamerAttemptExecutor for ConsolidationExecutor<'_> {
    async fn execute(
        &mut self,
        attempt: &crate::dreamer_runner::DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if attempt.status.payload.attempt_type == DREAMER_GAP_SCAN_ATTEMPT_TYPE {
            // Gap-scan child attempt: deterministic detectors + queue upsert.
            let (_, turn_ids, _) = decode_partition_payload(&attempt.status.payload.input)?;
            let mut working_set = Vec::new();
            for turn_id in &turn_ids {
                let facts = read_turn_facts(ctx.vault, turn_id)?;
                let role = dreamer_turn_role(facts.speaker.as_deref());
                working_set.push(WorkingSetTurn {
                    turn_id: *turn_id,
                    role,
                    learned_at: 0,
                    conversation: conversation_of(ctx.vault, turn_id)?,
                });
            }
            let gaps = scan_reflection_gaps(ctx.vault, &working_set, ctx.now_ms)?;
            upsert_gap_queue(ctx.vault, gaps, ctx.now_ms)?;
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        }

        let run_id = attempt.status.attempt.run_id.clone();
        match self
            .run_partition_attempt(
                &attempt.status.payload.input,
                ctx,
                attempt.status.attempt.id,
                run_id,
            )
            .await
        {
            Ok(PartitionRun::Completed { candidates, spent }) => {
                self.sink.accept(candidates)?;
                Ok(DreamerAttemptExecution::Completed {
                    completed_units: spent,
                })
            }
            // The step layer already parked the trapped attempt; Park it for resume
            // WITHOUT accepting candidates or completing it (#485-1, #485-2).
            Ok(PartitionRun::Trapped) => Ok(DreamerAttemptExecution::Park {
                reason: "durable step trapped for resume".to_owned(),
            }),
            Err(crate::llm::DurableStepError::DeadlineHardCut) => {
                Ok(DreamerAttemptExecution::Park {
                    reason: crate::dreamer_wake::DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                })
            }
            Err(crate::llm::DurableStepError::FinalizeRefused) => {
                Ok(DreamerAttemptExecution::Park {
                    reason: "wake pass finalize window".to_owned(),
                })
            }
            Err(crate::llm::DurableStepError::Engine(error)) => Err(error),
            Err(other) => Ok(DreamerAttemptExecution::Park {
                reason: other.to_string(),
            }),
        }
    }
}

fn entity_id_from_hex(hex: &str) -> Option<EntityId> {
    let hex = hex.trim();
    if hex.len() != 32 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut raw = [0_u8; 16];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        raw[index] = (high << 4) | low;
    }
    EntityId::from_bytes(raw).ok()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn json_to_rmpv(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(flag) => Value::from(*flag),
        serde_json::Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                Value::from(unsigned)
            } else if let Some(signed) = number.as_i64() {
                Value::from(signed)
            } else {
                Value::from(number.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(text) => Value::from(text.as_str()),
        serde_json::Value::Array(items) => Value::Array(items.iter().map(json_to_rmpv).collect()),
        serde_json::Value::Object(entries) => Value::Map(
            entries
                .iter()
                .map(|(key, value)| (Value::from(key.as_str()), json_to_rmpv(value)))
                .collect(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Codec helpers
// ---------------------------------------------------------------------------

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value)
        .map_err(|_| invalid_consolidation("dreamer consolidation MessagePack encode failed"))?;
    Ok(encoded)
}

fn decode_value(raw: &[u8]) -> Result<Value> {
    rmpv::decode::read_value(&mut Cursor::new(raw))
        .map_err(|_| invalid_consolidation("dreamer consolidation MessagePack decode failed"))
}

fn expect_map<'v>(value: &'v Value, context: &'static str) -> Result<&'v Vec<(Value, Value)>> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid_consolidation(context)),
    }
}

fn expect_key(key: &Value) -> Result<&str> {
    key.as_str().ok_or(invalid_consolidation(
        "dreamer consolidation keys must be strings",
    ))
}

#[cfg(test)]
mod tests;

/// Count of type-0 CLAIM entities in the vault — test seam for the
/// no-fabricated-writes invariant.
#[cfg(test)]
pub(crate) fn claim_predicates_in_store(vault: &Vault) -> Result<Vec<String>> {
    let claim_ids: Vec<EntityId> = {
        let rtxn = vault.store.env.read_txn()?;
        let mut ids = Vec::new();
        for row in vault.store.entities.iter(&rtxn)? {
            let (key, raw) = row?;
            let Some(header) = EntityMetadataHeader::parse(&raw) else {
                continue;
            };
            if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
                continue;
            }
            let Ok(id_bytes) = <[u8; 16]>::try_from(key.as_ref()) else {
                continue;
            };
            if let Ok(id) = EntityId::from_bytes(id_bytes) {
                ids.push(id);
            }
        }
        ids
    };
    let mut predicates = Vec::new();
    for id in claim_ids {
        if let Some(body) = vault.get_claim(&id)? {
            predicates.push(body.predicate);
        }
    }
    Ok(predicates)
}
