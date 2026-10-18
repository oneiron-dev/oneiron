//! The parked run's side of a code consent wait (DOOR-079 1b). The step
//! that parks on the wait seals it in its replay commit, and the replay
//! commit that takes the settled reply consumes it, once. Both run inside
//! the executor's own compare-and-put writer, after the record's put, so
//! neither the seal nor the consumption exists without the replay row it
//! describes, and a refused one commits no replay row either.
//!
//! The wait is picked by its control row, never by its reason or prompt.
//! The answer, the settlement and the consumption stay three facts: only the
//! replay writer fills the consumption, and neither an answer retry, a
//! settle nor the cleanup of the wait's delivery rows touches it. Nothing
//! here asks again, settles again, dispatches the effect again or asks for a
//! fresh grant: the settled reply is the completed effect's.

use crate::Vault;
use crate::code_run::{CodeRunReplayRecord, WaitKey};
use crate::consent::{CodeWaitReceiptLinks, ConsentReceipt};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::store::GateDecisionId;

use super::binding::{
    put_code_consent_wait_in_txn, read_code_consent_wait_in_txn, seal_code_consent_wait_in_txn,
};
use super::types::{
    CodeConsentBinding, CodeConsentCheckpoint, CodeConsentConsumption, CodeConsentSettleOutcome,
    CodeConsentSettlement, CodeConsentWaitRow,
};

/// The hash domain of a consumption's facts digest.
const CODE_CONSENT_CONSUMED_DOMAIN: &[u8] = b"oneiron:code-consent-consumed:v1";

/// Why the resume of a bound wait refuses when no reply was delivered to its
/// key (CALLS: a bound wait's missing delivery is an error). An ordinary
/// wait with none commits its record as before; a bound one never consumes a
/// settlement its run was not delivered.
const CODE_WAIT_RESUME_UNDELIVERED: &str = "a code consent wait resumed with no delivered reply";

/// The wait a step's checkpoint parks its run on, as the step's replay
/// writer sees it: the wait's key and the step's first bridge position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ParkedWait {
    pub(crate) key: WaitKey,
    pub(crate) step_start: u64,
}

/// One resume of a parked run from its wait: the run's record, the wait's
/// key at the generation the run resumed from, the parked step's checkpoint
/// index and the resumed result's path in the record.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CodeConsentResume<'a> {
    pub(crate) record: &'a CodeRunReplayRecord,
    pub(crate) key: WaitKey,
    pub(crate) step_seq: u64,
    pub(crate) resumed_path: &'a str,
}

/// Seals the code consent wait `parked` names, when a control row binds it,
/// in the step's replay commit (`txn`): the wait generation, the parked
/// step's checkpoint hash and the replay generation the commit writes. A
/// wait no row binds is left to its own path. A row bound to another run,
/// step or call refuses the commit.
pub(crate) fn seal_parked_code_consent_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &CodeRunReplayRecord,
    parked: &ParkedWait,
) -> Result<()> {
    let Some(row) = read_code_consent_wait_in_txn(vault, txn, parked.key.wait_id)? else {
        return Ok(());
    };
    let binding = &row.binding;
    let parked_call = record
        .bridge_calls
        .iter()
        .any(|call| call.seq >= parked.step_start && call.seq == binding.bridge_seq);
    if parked.key.run != record.run_id
        || binding.run_id != record.run_id
        || binding.step_start != parked.step_start
        || !parked_call
    {
        return Err(Error::InvariantViolation(
            "a step parked on a code consent wait another call bound",
        ));
    }
    let step = record
        .step_checkpoints
        .last()
        .ok_or(Error::InvariantViolation(
            "a code consent wait parked with no step",
        ))?;
    let generation = record.generation()?;
    seal_code_consent_wait_in_txn(
        vault,
        txn,
        parked.key.wait_id,
        CodeConsentCheckpoint {
            wait_generation: parked.key.generation,
            step_hash: step.state_hash,
            bridge_call_count: generation.bridge_call_count,
            step_checkpoint_count: generation.step_checkpoint_count,
            output_count: generation.output_count,
            last_state_hash: generation.last_state_hash,
        },
    )
}

/// Checks a bound wait before its run parks on `key`: the row binds this run
/// and was sealed by the run's last step, the one that parked, at this
/// generation. `Ok` for a wait no row binds. An unsealed or mismatched
/// binding refuses, so no run parks on a wait its step never sealed.
pub(crate) fn verify_parked_code_consent(
    vault: &Vault,
    record: &CodeRunReplayRecord,
    key: &WaitKey,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    let Some(row) = read_code_consent_wait_in_txn(vault, &txn, key.wait_id)? else {
        return Ok(());
    };
    let parked_step = u64::try_from(record.step_checkpoints.len())
        .ok()
        .and_then(|count| count.checked_sub(1))
        .ok_or(Error::CorruptedIndex(
            "a code consent wait parked with no step",
        ))?;
    own_sealed_step(&row, record, key, parked_step).map(drop)
}

/// The consent evidence a resumed result carries, once the bound wait's seal
/// and its settlement's own delivered reply verify: the binding, the
/// person's word, the answer's act and the settlement, by reference. `None`
/// for a wait no row binds. The consumption is not in it: a reader joins
/// that from the row (CALLS: the result carries the settlement, never its
/// own consumption), so the result's digest never feeds its own receipt.
///
/// # Errors
///
/// A seal, settlement or delivered reply that does not verify.
pub(crate) fn code_consent_resume_evidence(
    vault: &Vault,
    resume: &CodeConsentResume<'_>,
    delivered: &str,
) -> Result<Option<serde_json::Value>> {
    let txn = vault.store.env.read_txn()?;
    let Some(row) = read_code_consent_wait_in_txn(vault, &txn, resume.key.wait_id)? else {
        return Ok(None);
    };
    let (_, settlement) = settled_delivery(&row, resume, delivered)?;
    let answer = row.answer.as_ref();
    Ok(Some(serde_json::json!({
        "binding": row.binding.wait_id.to_hex(),
        "binding_digest": bytes_to_hex_lower(&row.binding.binding_digest),
        "effect_digest": bytes_to_hex_lower(&row.binding.effect_digest),
        "word": answer.map(|answer| answer.word_ref.to_hex()),
        "answer": answer.map(|answer| format!("gate:{}", answer.decision.to_hex())),
        "choice": answer.map(|answer| answer.choice.as_str()),
        "settlement": format!("gate:{}", settlement.receipt.to_hex()),
        "outcome": settlement.outcome.as_str(),
    })))
}

/// Consumes a bound wait's settlement into the replay commit that takes its
/// reply, in that commit's writer (`txn`), after the record's put. `false`
/// for a wait no row binds: its own path goes on. For a bound one the reply
/// must have been delivered (`delivered`) and be the settlement's own, to
/// this run's sealed parked step at this generation, and the record must
/// hold the resumed result at `resume.resumed_path` under a result name.
/// Then ONE consumption receipt joins the consent Gate family and the row
/// keeps its pointer. The same consumption again is a no-op; another path,
/// result, step or generation refuses, and nothing clears it.
///
/// The original caller's current authority is not asked again here: the
/// reply is the completed effect's, and the durable result stays. Releasing
/// the run's result later is its own read gate's call, under the authority
/// current then (CALLS: revoked authority refuses release, never the
/// durable result).
///
/// # Errors
///
/// No delivered reply, a seal, settlement, reply or result that does not
/// verify, or a consumption by another resume.
pub(crate) fn consume_code_consent_wait_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    resume: &CodeConsentResume<'_>,
    delivered: Option<&str>,
) -> Result<bool> {
    let Some(mut row) = read_code_consent_wait_in_txn(vault, txn, resume.key.wait_id)? else {
        return Ok(false);
    };
    let delivered = delivered.ok_or(Error::InvariantViolation(CODE_WAIT_RESUME_UNDELIVERED))?;
    let (sealed, settlement) = settled_delivery(&row, resume, delivered)?;
    let resumed = resumed_result(resume, sealed, settlement)?;
    if !resume
        .record
        .bindings
        .iter()
        .any(|binding| binding.handle == resumed.result_handle)
    {
        return Err(Error::InvariantViolation(
            "a code consent wait resumed into a result no name binds",
        ));
    }
    if let Some(consumed) = &row.consumption {
        if resumed.is(consumed) {
            return Ok(true);
        }
        return Err(Error::ConcurrentWrite(
            "a code consent wait was consumed by another resume",
        ));
    }
    let receipt_id = GateDecisionId::from_bytes(vault.store.clock.ulid()?);
    let receipt = ConsentReceipt::CodeWaitConsumed {
        decision_id: receipt_id,
        links: CodeWaitReceiptLinks {
            wait_id: resume.key.wait_id,
            word_ref: row.answer.as_ref().map(|answer| answer.word_ref),
            prior_receipt: Some(resumed.settlement_receipt),
            facts_digest: resumed.facts_digest(&row.binding),
        },
    };
    // The run's own replay consumed it: the engine's act, whose provenance
    // is the settlement it names (CALLS: a consumption's actor class).
    vault.append_code_wait_receipt_in_txn(txn, &receipt, None)?;
    row.consumption = Some(resumed.consumption(receipt_id));
    put_code_consent_wait_in_txn(vault, txn, &mut row)?;
    Ok(true)
}

/// Verifies that the resumed result a run's record holds for its wait stands
/// on the bound wait's committed consumption; a wait no row binds passes. A
/// bound wait never consumed, consumed by another result, step or
/// generation, or whose settlement changed refuses as corruption, never as a
/// wait to ask again. A run forked from the consuming one (a continuation)
/// holds the same resumed result in the history it inherited: the same step
/// hash, path, handle and digest verify it, whatever its own run id.
///
/// # Errors
///
/// Any of those mismatches, or storage errors.
pub(crate) fn verify_code_consent_consumed(
    vault: &Vault,
    resume: &CodeConsentResume<'_>,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    let Some(row) = read_code_consent_wait_in_txn(vault, &txn, resume.key.wait_id)? else {
        return Ok(());
    };
    let sealed = sealed_step(&row, resume.record, &resume.key, resume.step_seq)?;
    let settlement = row.settlement.as_ref().ok_or(Error::CorruptedIndex(
        "a resumed code consent wait never settled",
    ))?;
    let consumed = row.consumption.as_ref().ok_or(Error::CorruptedIndex(
        "a resumed code consent wait was never consumed",
    ))?;
    if !resumed_result(resume, sealed, settlement)?.is(consumed) {
        return Err(Error::CorruptedIndex(
            "a code consent wait was consumed by another result",
        ));
    }
    Ok(())
}

/// The seal of `row`, checked against a record's history: it was sealed by
/// the step at `step_seq` (that step's checkpoint hash, which chains every
/// step before it, with that step the last one then) at the key's
/// generation.
fn sealed_step<'r>(
    row: &'r CodeConsentWaitRow,
    record: &CodeRunReplayRecord,
    key: &WaitKey,
    step_seq: u64,
) -> Result<&'r CodeConsentCheckpoint> {
    let sealed = row.checkpoint.as_ref().ok_or(Error::CorruptedIndex(
        "a parked code consent wait was never sealed",
    ))?;
    let step = usize::try_from(step_seq)
        .ok()
        .and_then(|index| record.step_checkpoints.get(index));
    if sealed.wait_generation != key.generation
        || sealed.step_checkpoint_count != step_seq.saturating_add(1)
        || step.is_none_or(|step| step.state_hash != sealed.step_hash)
    {
        return Err(Error::CorruptedIndex(
            "a code consent wait was sealed with another parked step",
        ));
    }
    Ok(sealed)
}

/// [`sealed_step`] for the run the row binds, parked or resuming now: the
/// record and the key are that run's own.
fn own_sealed_step<'r>(
    row: &'r CodeConsentWaitRow,
    record: &CodeRunReplayRecord,
    key: &WaitKey,
    step_seq: u64,
) -> Result<&'r CodeConsentCheckpoint> {
    if row.binding.run_id != record.run_id || key.run != record.run_id {
        return Err(Error::CorruptedIndex(
            "a code consent wait is bound to another run",
        ));
    }
    sealed_step(row, record, key, step_seq)
}

/// The seal and the settlement a resume takes: the row is sealed by this
/// run's parked step at this generation, it settled, the reply delivered to
/// the run is the settlement's own, and a denial settled as refused.
fn settled_delivery<'r>(
    row: &'r CodeConsentWaitRow,
    resume: &CodeConsentResume<'_>,
    delivered: &str,
) -> Result<(&'r CodeConsentCheckpoint, &'r CodeConsentSettlement)> {
    let sealed = own_sealed_step(row, resume.record, &resume.key, resume.step_seq)?;
    let settlement = row.settlement.as_ref().ok_or(Error::CorruptedIndex(
        "a code consent wait delivered a reply it never settled",
    ))?;
    if *blake3::hash(delivered.as_bytes()).as_bytes() != settlement.reply_digest {
        return Err(Error::CorruptedIndex(
            "a code consent wait delivered another reply than its settlement",
        ));
    }
    if row
        .answer
        .as_ref()
        .is_some_and(|answer| !answer.choice.approves())
        && settlement.outcome != CodeConsentSettleOutcome::Refused
    {
        return Err(Error::CorruptedIndex(
            "a denied code consent wait settled as sent",
        ));
    }
    Ok((sealed, settlement))
}

/// What one resume took the settled reply into: the settlement and its
/// reply, the parked step and the result the record holds for it.
struct Resumed<'a> {
    settlement_receipt: GateDecisionId,
    reply_digest: [u8; 32],
    step_seq: u64,
    step_hash: [u8; 32],
    wait_generation: u64,
    resumed_path: &'a str,
    result_handle: &'a str,
    result_digest: [u8; 32],
}

/// The resume's facts, from the record's result at its resumed path.
fn resumed_result<'a>(
    resume: &CodeConsentResume<'a>,
    sealed: &CodeConsentCheckpoint,
    settlement: &CodeConsentSettlement,
) -> Result<Resumed<'a>> {
    let record: &'a CodeRunReplayRecord = resume.record;
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == resume.resumed_path)
        .ok_or(Error::CorruptedIndex(
            "a code consent wait resumed with no result",
        ))?;
    Ok(Resumed {
        settlement_receipt: settlement.receipt,
        reply_digest: settlement.reply_digest,
        step_seq: resume.step_seq,
        step_hash: sealed.step_hash,
        wait_generation: resume.key.generation,
        resumed_path: resume.resumed_path,
        result_handle: &output.handle,
        result_digest: output.raw_blake3,
    })
}

impl Resumed<'_> {
    /// Whether `consumed` recorded this very resume.
    fn is(&self, consumed: &CodeConsentConsumption) -> bool {
        consumed.settlement_receipt == self.settlement_receipt
            && consumed.reply_digest == self.reply_digest
            && consumed.step_seq == self.step_seq
            && consumed.step_hash == self.step_hash
            && consumed.wait_generation == self.wait_generation
            && consumed.resumed_path == self.resumed_path
            && consumed.result_handle == self.result_handle
            && consumed.result_digest == self.result_digest
    }

    /// The consumption this resume records under `receipt`.
    fn consumption(&self, receipt: GateDecisionId) -> CodeConsentConsumption {
        CodeConsentConsumption {
            receipt,
            settlement_receipt: self.settlement_receipt,
            reply_digest: self.reply_digest,
            step_seq: self.step_seq,
            step_hash: self.step_hash,
            wait_generation: self.wait_generation,
            resumed_path: self.resumed_path.to_owned(),
            result_handle: self.result_handle.to_owned(),
            result_digest: self.result_digest,
            consumed_at_ms: super::settle::now_ms(),
        }
    }

    /// BLAKE3 of the immutable facts a consumption closes: the binding, the
    /// settlement it consumed and its reply, the run, the parked step and its
    /// hash, the wait generation and the resumed result's path, handle and
    /// digest.
    fn facts_digest(&self, binding: &CodeConsentBinding) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        let mut field = |bytes: &[u8]| {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        field(CODE_CONSENT_CONSUMED_DOMAIN);
        field(&binding.binding_digest);
        field(&binding.effect_digest);
        field(binding.run_id.as_bytes());
        field(&self.settlement_receipt.as_bytes());
        field(&self.reply_digest);
        field(&self.step_seq.to_le_bytes());
        field(&self.step_hash);
        field(&self.wait_generation.to_le_bytes());
        field(self.resumed_path.as_bytes());
        field(self.result_handle.as_bytes());
        field(&self.result_digest);
        *hasher.finalize().as_bytes()
    }
}
