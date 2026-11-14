//! Bounded pages of one queued extraction attempt's reachable TURNs and effective policy.
//!
//! Rows follow the payload's part and TURN order. Unread TURNs or partition entities
//! are absent whole, counted nowhere and never named by a cursor. Words read only
//! through `vault.evidence.spans`, using the source versions served here.

use serde::{Deserialize, Serialize};

use super::source_version::{SourceVersion, source_version_in_txn};
use super::strength_observations::{
    observation_reader_scope_for_actor_in_txn, observed_claim_reads_in_txn,
};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadResult};
use crate::dreamer_consolidation::routing::PredicateKeyRules;
use crate::dreamer_consolidation::selection::SelectionConfig;
use crate::dreamer_consolidation::{
    ConsolidationBranchPlan, ConsolidationPartitionKey, decode_partition_payload,
    read_partition_turns_in_txn,
};
use crate::dreamer_prefilter::PrefilterConfig;
use crate::dreamer_runner::{
    DreamerAttemptBinding, DreamerConsolidationScope, decode_dreamer_attempt_payload,
};
use crate::federation::Scope;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EntityId, Error, Result, Vault};

/// The cursor prefix naming the last TURN a page served.
const EXTRACTION_TURNS_CURSOR_PREFIX: &str = "extraction-turns:";

/// The next page of one queued extraction attempt's reachable TURNs.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtractionInputsPageRequest {
    /// The queued attempt's identifier, encoded as 32 lowercase hexadecimal characters.
    pub attempt: String,
    /// The preceding page's cursor, absent on the first page.
    pub cursor: Option<String>,
    /// The most TURNs served, capped at the effective page row bound.
    pub limit: Option<u32>,
}

/// One page of queued TURNs with the effective extraction policy and its pin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionInputsPage {
    /// The extraction attempt this page reads.
    pub attempt: String,
    /// The attempt's consolidation scope.
    pub scope: String,
    /// The effective extraction policy read in this page's transaction.
    pub policy: ExtractionPolicy,
    /// The domain-separated hexadecimal BLAKE3 pin of the effective policy.
    pub policy_pin: String,
    /// The reachable TURNs in queued order, without their words.
    pub turns: Vec<ExtractionTurn>,
    /// The cursor after the last served TURN, only when a later TURN would be served.
    pub next: Option<String>,
}

/// The effective screening, selection and predicate key policies for extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionPolicy {
    /// The effective statistical screening policy.
    pub prefilter: PrefilterConfig,
    /// The effective candidate selection policy.
    pub selection: SelectionConfig,
    /// The effective predicate key rules.
    pub key_rules: PredicateKeyRules,
}

/// One queued TURN whose source and partition entities all read for the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionTurn {
    /// The queued TURN's identifier.
    pub turn: String,
    /// The conversation named by this TURN's queued part.
    pub conversation: String,
    /// The queued branch's world, when present.
    pub world: Option<String>,
    /// The queued branch's facet, when present.
    pub facet: Option<String>,
    /// The lowercase hexadecimal partition hash of this TURN's queued part.
    pub partition: String,
    /// The speaker role resolved by the production partition reader.
    pub role: String,
    /// The learned time resolved by the production partition reader.
    pub learned_at: u64,
    /// The source version served under the caller's live scoped read.
    pub version: SourceVersion,
}

/// Pages one extraction attempt through the caller's live reach and scoped read.
///
/// The byte bound counts encoded TURN rows, not the envelope. A TURN too large
/// for an empty page is refused rather than served partially.
///
/// # Errors
///
/// No owner proof or live Steward read grant, an invalid attempt or cursor,
/// a TURN larger than the page byte bound, and storage failures.
pub fn extraction_inputs_page(
    memory: &Memory<'_>,
    input: &ExtractionInputsPageRequest,
) -> MemoryResult<ScopedReadResult<ExtractionInputsPage>> {
    bound_extraction_inputs_page(memory, input, None)
}

/// Proves the extraction binding in the page's own transaction before reading rows.
///
/// # Errors
///
/// As [`extraction_inputs_page`], and a stale binding or a request for another attempt.
pub(crate) fn extraction_inputs_page_bound(
    memory: &Memory<'_>,
    input: &ExtractionInputsPageRequest,
    binding: &DreamerAttemptBinding,
) -> MemoryResult<ScopedReadResult<ExtractionInputsPage>> {
    bound_extraction_inputs_page(memory, input, Some(binding))
}

/// Serves the public and bound page through one transaction and one reader.
fn bound_extraction_inputs_page(
    memory: &Memory<'_>,
    input: &ExtractionInputsPageRequest,
    binding: Option<&DreamerAttemptBinding>,
) -> MemoryResult<ScopedReadResult<ExtractionInputsPage>> {
    let vault = memory.vault();
    let owner = memory
        .embedded_owner("vault.consolidation.extraction.inputs.page")
        .ok();
    let bounds = vault.snapshot_read_settings()?;
    let limit = input
        .limit
        .unwrap_or(bounds.page_rows)
        .min(bounds.page_rows)
        .max(1);
    let attempt = extraction_attempt_key(&input.attempt)?;
    let after = extraction_turn_cursor_key(input.cursor.as_deref())?;
    let read = memory.read_lane(ClaimReadStatus::Recorded)?;
    let _pins = read.prepare_point_read::<MemoryError>()?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    memory.prove_read_authority_in_txn(&txn)?;
    if let Some(binding) = binding {
        binding.check_in_txn(&txn)?;
        if attempt != binding.attempt() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "an extraction binding reads its own attempt's inputs only",
                &[],
            ));
        }
    }
    let reader_scope = extraction_reader_scope_in_txn(memory, &txn, owner.as_ref())?;
    read.read_projected_in_txn(&txn, &[], None, |txn, _| {
        let (scope, branch) = queued_extraction_branch_in_txn(vault, txn, attempt)?;
        let queued: Vec<_> = branch
            .parts
            .iter()
            .flat_map(|part| {
                let key = branch.part_key(part.conversation_ref);
                part.turns.iter().map(move |turn| (key, *turn))
            })
            .collect();
        let start = match after {
            Some(after) => queued
                .iter()
                .position(|(_, turn)| *turn == after)
                .map(|position| position + 1)
                .ok_or_else(|| MemoryError::bad_request("invalid extraction TURN cursor"))?,
            None => 0,
        };
        let policy = ExtractionPolicy {
            prefilter: vault.prefilter_config_in_txn(txn)?,
            selection: vault.consolidation_selection_in_txn(txn)?,
            key_rules: vault.consolidation_key_rules_in_txn(txn)?,
        };
        let mut page = ExtractionInputsPage {
            attempt: attempt.to_hex(),
            scope: scope.as_str().to_owned(),
            policy_pin: extraction_policy_pin(&policy)?,
            policy,
            turns: Vec::new(),
            next: None,
        };
        let mut rows = queued.into_iter().skip(start);
        let mut bytes = 0u64;
        let mut shown = None;
        while let Some((key, turn)) = rows.next() {
            let Some(row) = extraction_turn_in_txn(
                vault,
                txn,
                &read,
                reader_scope.as_ref(),
                scope,
                &key,
                turn,
            )?
            else {
                continue;
            };
            let size = serde_json::to_vec(&row)
                .map_err(|error| MemoryError::bad_request(error.to_string()))?
                .len() as u64;
            if page.turns.is_empty() && size > bounds.page_bytes {
                return Err(MemoryError::bad_request(
                    "the snapshot page byte bound cannot hold the extraction TURN",
                ));
            }
            if bytes.saturating_add(size) > bounds.page_bytes {
                page.next = shown.map(extraction_turn_cursor);
                break;
            }
            bytes = bytes.saturating_add(size);
            page.turns.push(row);
            shown = Some(turn);
            if page.turns.len() as u64 >= u64::from(limit) {
                for (later_key, later_turn) in rows.by_ref() {
                    if extraction_turn_in_txn(
                        vault,
                        txn,
                        &read,
                        reader_scope.as_ref(),
                        scope,
                        &later_key,
                        later_turn,
                    )?
                    .is_some()
                    {
                        page.next = Some(extraction_turn_cursor(turn));
                        break;
                    }
                }
                break;
            }
        }
        Ok(page)
    })
}

/// Resolves the proven owner's whole-vault read or a live Steward reader's scope.
pub(crate) fn extraction_reader_scope_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    owner: Option<&crate::consent::AuthenticatedOwner>,
) -> MemoryResult<Option<Scope>> {
    let vault = memory.vault();
    if let Some(owner) = owner {
        owner.revalidate_as_vault_owner_in_txn(vault, txn)?;
        return Ok(None);
    }
    match observation_reader_scope_for_actor_in_txn(vault, txn, memory.actor())? {
        Some(scope) => Ok(scope),
        None => Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "extraction inputs read for the owner under its proof or a live Steward reader",
            &[],
        )),
    }
}

/// Reads only an extraction attempt still present in the queue, without distinguishing refusals.
pub(crate) fn queued_extraction_branch_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: EntityId,
) -> MemoryResult<(DreamerConsolidationScope, ConsolidationBranchPlan<EntityId>)> {
    let record = AttemptQueue::new(vault)
        .get_in_txn(txn, AttemptId::from_bytes(attempt.as_bytes())?)?
        .ok_or_else(invalid_extraction_attempt)?;
    let payload = decode_dreamer_attempt_payload(&record.payload)
        .map_err(|_| invalid_extraction_attempt())?;
    let scope = [
        DreamerConsolidationScope::Micro,
        DreamerConsolidationScope::Meso,
        DreamerConsolidationScope::Macro,
    ]
    .into_iter()
    .find(|scope| record.kind == scope.attempt_kind() && payload.attempt_type == scope.as_str())
    .ok_or_else(invalid_extraction_attempt)?;
    let branch =
        decode_partition_payload(&payload.input).map_err(|_| invalid_extraction_attempt())?;
    Ok((scope, branch))
}

/// Serves one queued TURN only when its source and every named partition entity read.
pub(crate) fn extraction_turn_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    reader_scope: Option<&Scope>,
    scope: DreamerConsolidationScope,
    key: &ConsolidationPartitionKey,
    turn: EntityId,
) -> MemoryResult<Option<ExtractionTurn>> {
    for entity in [
        Some(turn),
        Some(key.conversation_ref),
        key.world_ref,
        key.facet_ref,
    ]
    .into_iter()
    .flatten()
    {
        if !observed_claim_reads_in_txn(vault, txn, read, reader_scope, entity)? {
            return Ok(None);
        }
    }
    let Some((version, _)) = source_version_in_txn(read, txn, &turn)? else {
        return Ok(None);
    };
    let facts = read_partition_turns_in_txn(vault, txn, scope, &[turn])?
        .pop()
        .ok_or_else(invalid_extraction_attempt)?;
    Ok(Some(ExtractionTurn {
        turn: turn.to_hex(),
        conversation: key.conversation_ref.to_hex(),
        world: key.world_ref.map(|world| world.to_hex()),
        facet: key.facet_ref.map(|facet| facet.to_hex()),
        partition: blake3::Hash::from(key.partition_hash())
            .to_hex()
            .to_string(),
        role: facts.role.as_str().to_owned(),
        learned_at: facts.learned_at,
        version,
    }))
}

/// Pins the effective policy with its extraction-specific domain and canonical JSON bytes.
fn extraction_policy_pin(policy: &ExtractionPolicy) -> Result<String> {
    let encoded =
        serde_json::to_vec(policy).map_err(|error| Error::InvalidConfig(error.to_string()))?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.dreamer.extraction.policy.v1");
    hash.update(&encoded);
    Ok(hash.finalize().to_hex().to_string())
}

/// Decodes the attempt identifier in its one lowercase hexadecimal spelling.
fn extraction_attempt_key(attempt: &str) -> MemoryResult<EntityId> {
    let id = EntityId::from_hex(attempt).map_err(|_| invalid_extraction_attempt())?;
    if id.to_hex() != attempt {
        return Err(invalid_extraction_attempt());
    }
    Ok(id)
}

/// Returns the same bad request for an unknown attempt and any other queued kind.
fn invalid_extraction_attempt() -> MemoryError {
    MemoryError::bad_request("the attempt must name a queued extraction attempt")
}

/// Encodes the last served TURN as the next page's cursor.
fn extraction_turn_cursor(turn: EntityId) -> String {
    format!("{EXTRACTION_TURNS_CURSOR_PREFIX}{}", turn.to_hex())
}

/// Decodes a cursor naming one queued TURN in its lowercase hexadecimal spelling.
fn extraction_turn_cursor_key(cursor: Option<&str>) -> MemoryResult<Option<EntityId>> {
    cursor
        .map(|cursor| {
            let hex = cursor
                .strip_prefix(EXTRACTION_TURNS_CURSOR_PREFIX)
                .ok_or_else(|| MemoryError::bad_request("invalid extraction TURN cursor"))?;
            let turn = EntityId::from_hex(hex)
                .map_err(|_| MemoryError::bad_request("invalid extraction TURN cursor"))?;
            if turn.to_hex() != hex {
                return Err(MemoryError::bad_request("invalid extraction TURN cursor"));
            }
            Ok(turn)
        })
        .transpose()
}
