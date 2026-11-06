//! A caller's correction of one callable call's answer (FIX 12214). The
//! call's own caller, never the skill's author, names the call by its
//! receipt and step seq and records the answer the call should have given.
//! The call's case is frozen again with that answer as its `answer`, so the
//! helper gate scores both arms against it: the amendment wins over the kept
//! answer (lead ruling 01:12). Its key, its index entries and its skill's
//! kept cases stay as they are.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::super::invalid;
use super::{CASES, CaseCaller, FrozenCall, index};
use crate::error::{ClaimError, Error, Result};
use crate::limit_ask::EngineLimit;
use crate::store::Store;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// Where a case key's step seq sits: after id16 + u64be at.
const CASE_KEY_SEQ_AT: usize = 24;
/// Where a case key's receipt starts: after the step seq.
const CASE_KEY_RECEIPT_AT: usize = 32;

/// `vault.skills.callable.amend`: the caller of one callable call records
/// the answer the call should have given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallableAmendRequest {
    /// The attempt pack receipt of the run that made the call.
    pub receipt: String,
    /// The call's step seq in that run.
    pub seq: u64,
    /// The corrected answer, as the skill's contract returns it.
    pub answer: JsonValue,
}

/// What an amendment came to. None of these is a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CallableAmendOutcome {
    /// The call's case now expects the corrected answer.
    Refrozen,
    /// The call has no frozen case: it did not pass its contract, was too
    /// long to keep, was trimmed or erased since, or never ran. Nothing is
    /// stored.
    NoCase,
    /// The corrected answer is longer than the `[limits]
    /// maintenance_text_bytes` row: the row asked, and nothing is stored.
    OverLimit,
}

/// The answer of `vault.skills.callable.amend`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CallableAmendReceipt {
    pub outcome: CallableAmendOutcome,
    /// The skill entity whose case it is, hex; `None` with no case.
    pub skill: Option<String>,
}

impl CallableAmendReceipt {
    fn no_case() -> Self {
        Self {
            outcome: CallableAmendOutcome::NoCase,
            skill: None,
        }
    }
}

/// Records `input.answer` in place of the answer of the call that the run
/// under `input.receipt` made at step `input.seq`, as `by`, that call's
/// caller. The case is found and `by` checked on one snapshot. The answer is
/// measured against the `[limits] maintenance_text_bytes` row, as at
/// capture. Then one writer freezes the case again: the correction becomes
/// its `answer` through the side-row wall, stamped with when, and a later
/// correction replaces an earlier one. A call with no case stores nothing.
///
/// # Errors
///
/// The write-actor check's refusals. The not-allowed refusal when `by` is
/// not the call's caller or is the skill's author. Storage errors.
pub fn amend_callable_case(
    vault: &Vault,
    by: &WriteActor,
    input: &CallableAmendRequest,
) -> Result<CallableAmendReceipt> {
    let answer = serde_json::to_string(&input.answer)
        .map_err(|_| invalid("an amended answer cannot be encoded"))?;
    let (key, row) = {
        let rtxn = vault.store.env.read_txn()?;
        vault.verify_write_actor_in_txn(&rtxn, by)?;
        let Some((key, row)) = case_in_txn(&vault.store, &rtxn, &input.receipt, input.seq)? else {
            return Ok(CallableAmendReceipt::no_case());
        };
        check_amender_in_txn(vault, &rtxn, by, &key, &row)?;
        (key, row)
    };
    let skill = case_skill(&key)?;
    let longest = answer.len().max(row.arguments.len()) as u64;
    if vault
        .measure_limit(EngineLimit::MaintenanceTextBytes, longest)
        .is_some()
    {
        return Ok(CallableAmendReceipt {
            outcome: CallableAmendOutcome::OverLimit,
            skill: Some(skill.to_hex()),
        });
    }
    let at = vault.now_recorded_at();
    let refrozen = vault.with_write_txn_grouped(|txn| {
        // A trim or an erase since the snapshot leaves no case, and an actor
        // erase leaves one that names no caller.
        let Some(mut row) = CASES.get(&vault.store, txn, &key)? else {
            return Ok(false);
        };
        if row.caller != CaseCaller::Actor(by.entity_ref()) {
            return Err(not_allowed("only a call's caller amends its answer"));
        }
        row.answer = answer;
        row.amended_at = Some(at);
        // The side-row wall admits the corrected text as it admitted the
        // answer at capture.
        CASES.put(&vault.store, txn, &key, &row)?;
        Ok(true)
    })?;
    if !refrozen {
        return Ok(CallableAmendReceipt::no_case());
    }
    Ok(CallableAmendReceipt {
        outcome: CallableAmendOutcome::Refrozen,
        skill: Some(skill.to_hex()),
    })
}

/// The case of the call the run under `receipt` made at step `seq`, with its
/// key. Its receipt's index entries find it while its sources are unknown;
/// a case whose sources are known is indexed under them, so the case keys
/// are read for it then.
fn case_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    receipt: &str,
    seq: u64,
) -> Result<Option<(Vec<u8>, FrozenCall)>> {
    let names_call = |key: &Vec<u8>| {
        key.get(CASE_KEY_SEQ_AT..CASE_KEY_RECEIPT_AT) == Some(&seq.to_be_bytes()[..])
            && key.get(CASE_KEY_RECEIPT_AT..) == Some(receipt.as_bytes())
    };
    let key = match index::receipt_case_keys_in_txn(store, txn, receipt)?
        .into_iter()
        .find(&names_call)
    {
        Some(key) => Some(key),
        None => CASES
            .scan_keys(store, txn, &[])?
            .into_iter()
            .find(&names_call),
    };
    let Some(key) = key else {
        return Ok(None);
    };
    Ok(CASES.get(store, txn, &key)?.map(|row| (key, row)))
}

/// `by` may amend the case `row` under `key` only as the call's caller, the
/// principal the case was frozen for, and never as the author of the skill
/// that ran: a case its author made never scores its skill's helpers.
fn check_amender_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    by: &WriteActor,
    key: &[u8],
    row: &FrozenCall,
) -> Result<()> {
    let actor = by.entity_ref();
    if row.caller != CaseCaller::Actor(actor) {
        return Err(not_allowed("only a call's caller amends its answer"));
    }
    let skill = case_skill(key)?;
    let author = match vault.get_skill_record_in_txn(txn, &skill)? {
        Some(record) => crate::memory::skill_author_in_txn(vault, txn, &skill, &record)?,
        None => None,
    };
    if author == Some(actor) {
        return Err(not_allowed("a skill's author never amends its cases"));
    }
    Ok(())
}

/// The skill a case key names: its first 16 bytes.
fn case_skill(key: &[u8]) -> Result<EntityId> {
    let bytes = key
        .first_chunk::<16>()
        .ok_or(Error::CorruptedIndex("frozen callable case key"))?;
    EntityId::from_bytes(*bytes)
}

/// The not-allowed refusal the write doors give an actor without the
/// standing a write needs.
fn not_allowed(reason: &'static str) -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority { reason })
}
