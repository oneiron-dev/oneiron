use std::collections::BTreeMap;

use rmpv::Value;

use super::support::{
    CURSOR_SCHEMA_VERSION, DREAMER_BUCKET_HASH_DOMAIN, DREAMER_PARTITION_ROUND_HASH_DOMAIN,
    DREAMER_PRIVATE_CURSOR_PREFIX, DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE, KEY_CONVERSATION,
    KEY_FACET, KEY_LAST_LEARNED_AT, KEY_LAST_LEDGER_REVISION_HINT, KEY_SCHEMA_VERSION, KEY_TURNS,
    KEY_WATERMARK, KEY_WORLD, PARTITION_PAYLOAD_SCHEMA_VERSION, decode_value, encode_value,
    expect_key, expect_map, hash_optional_entity, invalid_consolidation, scope_byte,
};
use super::watermark::{
    ConsolidationWatermark, WorkingSetTurn, entity_ref_from_value, read_turn_facts,
    read_turn_facts_in_txn,
};
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt};
use crate::dreamer_prefilter::{
    prefilter_partition_input, prefilter_partition_input_in_txn, write_prefilter_receipts_in_txn,
};
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
    encode_dreamer_attempt_payload,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;

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
///
/// The OF-361 statistical screen (ONE-1525) runs FIRST, over the whole input:
/// the scan's GATE-10 role gate has already ruled on which turns MAY be
/// extracted, and `prefilter_partition_input` rules on which of those are
/// worth the budget. The order is not interchangeable — eligibility, then
/// value. This API is a preview only. [`enqueue_partition_attempts`] rebuilds
/// the plans and their screening receipts together in its write transaction;
/// it takes the original pre-screen input rather than these lossy plans.
///
/// The screen NEVER reaches the selection authority: `dirty_turns` was chosen
/// by the watermark scan, the caller's `planned_turn_ids` and watermark
/// advance are taken from that same pre-screen list, and a skipped turn is
/// therefore consumed by this round exactly as a kept one is. A screened-out
/// turn loses its extraction, not its place in the log.
pub fn plan_partitions(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    dirty_turns: &[WorkingSetTurn],
    watermark: &ConsolidationWatermark,
) -> Result<Vec<ConsolidationPartitionPlan>> {
    let _ = scope;
    let screened = prefilter_partition_input(vault, dirty_turns)?;
    let mut plans: BTreeMap<ConsolidationPartitionKey, Vec<WorkingSetTurn>> = BTreeMap::new();
    for turn in &screened.kept {
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

/// [`plan_partitions`] over a caller-owned write transaction — the ONE-1685
/// session close plans its SessionEnd → Meso round from rows it has staged but
/// not yet committed. Same grouping and the SAME `world_ref`/`facet_ref`
/// fallback chain (turn body key → conversation body key → None): only the read
/// transaction differs, so an in-transaction plan and a committed-state plan of
/// the same turns produce byte-identical partition keys.
///
/// The OF-361 screen composes the same way: same policy row, same pure
/// arithmetic, only the read transaction differs, so the two twins keep or
/// skip the same turns.
pub(crate) fn plan_partitions_in_txn(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    txn: &heed::RwTxn<'_>,
    dirty_turns: &[WorkingSetTurn],
    watermark: &ConsolidationWatermark,
) -> Result<Vec<ConsolidationPartitionPlan>> {
    let _ = scope;
    let screened = prefilter_partition_input_in_txn(vault, txn, dirty_turns)?;
    partition_screened_turns_in_txn(vault, txn, &screened.kept, watermark)
}

fn partition_screened_turns_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    kept: &[WorkingSetTurn],
    watermark: &ConsolidationWatermark,
) -> Result<Vec<ConsolidationPartitionPlan>> {
    let mut plans: BTreeMap<ConsolidationPartitionKey, Vec<WorkingSetTurn>> = BTreeMap::new();
    for turn in kept {
        let Some(conversation_ref) = turn.conversation else {
            // A turn without its structural conversation edge cannot be
            // partitioned; skip fail-closed rather than invent a partition.
            continue;
        };
        let turn_facts = read_turn_facts_in_txn(vault, txn, &turn.turn_id)?;
        let conversation_facts = read_turn_facts_in_txn(vault, txn, &conversation_ref)?;
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

/// Domain-separated BLAKE3 over the EXACT ordered TURN batch of one round:
/// `domain || u64_be(count) || repeated(u64_be(learned_at) || turn_id)`. The
/// count is hashed so a batch can never be a prefix-ambiguous concatenation of
/// another.
pub(crate) fn partition_round_hash(turns: &[WorkingSetTurn]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DREAMER_PARTITION_ROUND_HASH_DOMAIN);
    hasher.update(&(turns.len() as u64).to_be_bytes());
    for turn in turns {
        hasher.update(&turn.learned_at.to_be_bytes());
        hasher.update(turn.turn_id.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// One partition plan as its production enqueue input: the executor-
/// decodable payload ([`encode_partition_payload`]) plus the advisory dedupe
/// key `hex(partition_hash):hex(partition_round_hash)`.
///
/// The round component is derived from the exact ordered TURN batch, not the
/// round's watermark second: successive capped batches inside ONE second would
/// otherwise share a key and coalesce, silently dropping the later batch's
/// round. The accepted trade-off is that only an EXACT replay of the same
/// batch coalesces — two planners whose local turn sets differ (superset or
/// partial overlap) enqueue distinct advisory attempts, and the overlapping
/// re-consolidation is best-effort cost. Consolidation attempts are advisory
/// identity, never a lock.
fn partition_attempt_input(
    scope: DreamerConsolidationScope,
    plan: &ConsolidationPartitionPlan,
    run_id: Option<String>,
    now: u64,
) -> EnqueueDreamerConsolidationAttempt {
    let dedupe_key = format!(
        "{}:{}",
        bytes_to_hex_lower(&plan.key.partition_hash()),
        bytes_to_hex_lower(&partition_round_hash(&plan.turns)),
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

/// Screens and enqueues a complete PRE-screen batch in one transaction, with
/// its skip receipts and rollup. Pass the original scan, not turns flattened
/// from [`plan_partitions`]: those preview plans have already lost the skips.
/// Current rows and policy are read again inside this commit, so a preview is
/// never authority for either extraction or its audit records.
///
/// The caller still owns watermark settlement. Exact partition-batch replays
/// coalesce on advisory dedupe keys; overlapping batches remain distinct.
/// Missing, malformed, or no-longer-admissible turn rows abort the whole round.
pub fn enqueue_partition_attempts(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    dirty_turns: &[WorkingSetTurn],
    watermark: &ConsolidationWatermark,
    run_id: &str,
    now: u64,
) -> Result<Vec<EnqueueDreamerAttemptOutcome>> {
    let turn_ids: Vec<_> = dirty_turns.iter().map(|turn| turn.turn_id).collect();
    vault.with_write_txn(|wtxn| {
        enqueue_partition_attempts_in_txn(
            vault,
            wtxn,
            scope,
            &turn_ids,
            watermark,
            Some(run_id),
            now,
        )
    })
}

/// Transaction-composable form of [`enqueue_partition_attempts`]. Session close
/// supplies its fence-matched PRE-screen IDs, not its stale preview plans.
pub(crate) fn enqueue_partition_attempts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    planned_turn_ids: &[EntityId],
    watermark: &ConsolidationWatermark,
    run_id: Option<&str>,
    now: u64,
) -> Result<Vec<EnqueueDreamerAttemptOutcome>> {
    if planned_turn_ids.is_empty() {
        return Ok(Vec::new());
    }
    let turns = read_partition_turns_in_txn(vault, wtxn, planned_turn_ids)?;
    if turns.iter().any(|turn| turn.conversation.is_none()) {
        return Err(invalid_consolidation(
            "dreamer planned turn has no conversation",
        ));
    }
    let screen = prefilter_partition_input_in_txn(vault, wtxn, &turns)?;
    let plans = partition_screened_turns_in_txn(vault, wtxn, &screen.kept, watermark)?;
    let store = DreamerRunnerStore::new(vault);
    let mut outcomes = Vec::with_capacity(plans.len());
    for plan in &plans {
        outcomes.push(store.enqueue_consolidation_in_txn(
            wtxn,
            partition_attempt_input(scope, plan, run_id.map(str::to_owned), now),
        )?);
    }
    write_prefilter_receipts_in_txn(vault, wtxn, scope, &turns, &screen, now)?;
    Ok(outcomes)
}

/// Reconstructs complete planning input before any lossy commit. An unreadable
/// text field can still pass unscored, but a missing/non-TURN row cannot stand
/// in for a planned turn. Resolve roles and structural membership from this
/// transaction, never from caller-supplied working-set metadata.
pub(crate) fn read_partition_turns_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    turn_ids: &[EntityId],
) -> Result<Vec<WorkingSetTurn>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut turns = Vec::with_capacity(turn_ids.len());
    for turn_id in turn_ids {
        if !seen.insert(*turn_id) {
            return Err(invalid_consolidation("duplicate dreamer partition turn"));
        }
        let raw = vault
            .get_raw_in(txn, turn_id)?
            .ok_or(crate::error::Error::CorruptedIndex(
                "dreamer planned turn is missing",
            ))?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .filter(|header| header.entity_type == crate::registry::ENTITY_TYPE_TURN)
            .ok_or(crate::error::Error::CorruptedIndex(
                "dreamer planned turn header is invalid",
            ))?;
        let facts =
            super::watermark::decode_turn_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]);
        let role = crate::dreamer_runner::dreamer_turn_role(facts.speaker.as_deref());
        if !crate::dreamer_runner::dreamer_extraction_role_admissible(role) {
            return Err(invalid_consolidation(
                "dreamer planned turn is not admissible",
            ));
        }
        let prefix = crate::vault::edge_kind_prefix(turn_id, crate::edge::EdgeKind::ChildOf);
        let conversation = vault
            .store
            .edges_out
            .prefix_iter(txn, &prefix)?
            .next()
            .transpose()?
            .map(|(key, _)| {
                crate::edge::parse_strict_edge_record_key(&key).map(|(_, _, target)| target)
            })
            .transpose()?;
        turns.push(WorkingSetTurn {
            turn_id: *turn_id,
            role,
            learned_at: header.learned_at,
            conversation,
        });
    }
    Ok(turns)
}

/// Registers ED-04's recurring-substitution miner (ONE-1760) for a sitting that
/// just closed, inside the CALLER'S close transaction.
///
/// Same commit as the close, for the reason the distill job is: "this sitting
/// ended and its corrections have not been mined" is a durable fact or it is a
/// live process's intention, and the second one does not survive a crash.
///
/// The attempt rides the Meso consolidation queue the SessionEnd wake already
/// drains — this is a payload discriminator on the landed wake, never a second
/// wake mechanism — and its dedupe key is the sitting, so re-ending an
/// already-ended session can never queue a second pass. It carries no run id:
/// the miner derives its inbox group from the sitting when the queue row has
/// none, exactly as the session-end partition attempts run without one.
pub(crate) fn register_substitution_mine_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    session: &EntityId,
    now: u64,
) -> Result<()> {
    let payload = encode_dreamer_attempt_payload(&DreamerAttemptPayload {
        attempt_type: DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE.to_owned(),
        input: crate::edit_distance::miner::miner_attempt_input(session),
        parent_attempt: None,
    })?;
    AttemptQueue::new(vault).enqueue_in_txn(
        wtxn,
        EnqueueAttempt {
            kind: DreamerConsolidationScope::Meso.attempt_kind().to_owned(),
            payload,
            dedupe_key: Some(format!(
                "{DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE}:{}",
                session.to_hex()
            )),
            run_id: None,
            now,
        },
    )?;
    Ok(())
}

pub(super) fn encode_partition_payload(plan: &ConsolidationPartitionPlan) -> Value {
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
