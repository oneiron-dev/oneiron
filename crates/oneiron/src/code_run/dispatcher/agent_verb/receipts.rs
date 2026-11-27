//! A verb write's receipt: its identity, its read, and how a step's write
//! rows are compared with it. A continuation also asks here whether a
//! receipt past its cut may have run (FIX 4199).

use crate::batch::secret_scan::{MapOrder, held_row_meets};
use crate::code_run::CompareKnown;
use crate::code_run::payload::{
    agent_verb_call_identity as call_identity, decode_self_dispatch_outcome,
    self_call_request_value,
};
use crate::code_run::replay::{CodeRunBridgeCall, CodeRunReplayGeneration, CodeRunReplayRecord};
use crate::code_run::storage::derived_executor_id;
use crate::code_run::types::{
    SelfAgentVerbCall, SelfCall, SelfDeniedResult, SelfDispatchOutcome, SelfEffect,
};
use crate::error::{Error, Result};
use crate::task_verb::sdk::AgentVerb;
use crate::{EntityId, Vault};
use oneiron_store::batch::secret_scan::mask::wipe::PlanTree;

use super::super::{ExecutorCallSite, HostSelfDispatcher};

const AGENT_VERB_RECEIPT_DOMAIN: &[u8] =
    crate::entity_id::derived_domains::EXECUTOR_AGENT_VERB_RECEIPT;

/// The reason a receipt's refusal row carries, so that no row read back from
/// the receipt's answer, a refusal or not, is ever taken for one.
pub(super) const KEPT_ANSWER_REFUSED: &str = "kept_answer_refused";

/// The mark a receipt keeps when a verb hook stopped its write before the
/// write ran (ARCH-0080 §3): nothing was written, so a replay of the step
/// asks the door again.
pub(super) const VERB_HOOK_STOPPED: &str = "verb_hook_stopped";

/// The answer a write's receipt keeps when a verb hook hid its result after
/// the write ran: kept, so a replay never writes again.
pub(super) const VERB_HOOK_HIDDEN: &str = "verb_hook_hidden";

/// The mark a receipt keeps when no provider answered the write's model call
/// (FIX 3194): nothing was written, so the run parks, and a replay of the
/// step asks the door again.
pub(super) const PROVIDER_UNAVAILABLE: &str = "provider_unavailable";

/// A media call's admission trapped before its physical effect ran.
pub(super) const MEDIA_STEP_TRAPPED: &str = "media_step_trapped";

/// The mark an erased row's identity starts with: no verb is named so.
const ERASED_ROW_IDENTITY: &[u8] = b"erased\0";

impl HostSelfDispatcher<'_> {
    /// The receipt of the step's write at `site`, keyed by the write's place
    /// in its step (the step's first position and how many writes the step
    /// made before it; reads do not count), and how it stands: the write's
    /// ordinal, the receipt's id, and what the receipt kept.
    pub(super) fn write_receipt(
        &self,
        site: ExecutorCallSite<'_>,
    ) -> Result<(u64, EntityId, KeptWrite)> {
        let ordinal = site.earlier.iter().filter(is_write).count() as u64;
        let receipt_id = self.write_receipt_id(site.run_id, site.step_start, ordinal)?;
        let kept = match self.storage.get_code_run_replay_record(&receipt_id)? {
            // A hook stopped this write before it ran, or no provider
            // answered it, so nothing was written: the write is made again,
            // under a fresh reservation.
            Some(receipt) if receipt.bridge_calls.first().is_some_and(never_ran) => {
                KeptWrite::Fresh(Some(receipt.generation()?))
            }
            Some(receipt) => KeptWrite::Ran(Box::new(receipt)),
            None => KeptWrite::Fresh(None),
        };
        Ok((ordinal, receipt_id, kept))
    }

    /// Refuses to close a step that left out a write an earlier attempt of it
    /// made. A resumed step makes the step's writes again in order, each
    /// answered from its receipt: the step's writes, in order, must be the
    /// receipts' calls with the receipts' answers. A receipt the step did not
    /// meet so (a write left out, one the bridge recorded after halting and
    /// never dispatched, or one whose kept answer stands refused) means the
    /// step would checkpoint without that write, and a later step could make
    /// it again under a fresh receipt. A receipt the side-row wall placed a
    /// value of base custody in is read with base custody's values (FIX
    /// RECEIPT-RECORDS-CALL-HELD-INPUT).
    pub(crate) fn refuse_a_step_that_dropped_a_write(
        &self,
        run_id: EntityId,
        step_start: u64,
        calls: &[CodeRunBridgeCall],
    ) -> Result<()> {
        let base_known = || self.base_known_values();
        let known = CompareKnown::new(Some(&base_known));
        let mut made = calls.iter().filter(is_write);
        let mut ordinal = 0;
        while let Some(receipt) = self
            .storage
            .get_code_run_replay_record(&self.write_receipt_id(run_id, step_start, ordinal)?)?
        {
            let met = match made.next() {
                Some(made) => meets(&receipt, made, &known)?,
                None => false,
            };
            if !met {
                return Err(Error::InvariantViolation(
                    "a resumed step left out a write it already made",
                ));
            }
            ordinal += 1;
        }
        Ok(())
    }

    /// The receipt of the step's write at `ordinal`: the run, the step's first
    /// bridge position, and how many verb writes the step made before it.
    pub(super) fn write_receipt_id(
        &self,
        run_id: EntityId,
        step_start: u64,
        ordinal: u64,
    ) -> Result<EntityId> {
        derive_write_receipt_id(&self.run_ref, run_id, step_start, ordinal)
    }
}

/// The id of a write receipt: the run reference `run_ref` the run's
/// dispatcher holds, the run, the step's first bridge position, and how many
/// verb writes the step made before the write. The dispatcher and
/// [`write_receipt_may_have_run`] both derive it here.
fn derive_write_receipt_id(
    run_ref: &str,
    run_id: EntityId,
    step_start: u64,
    ordinal: u64,
) -> Result<EntityId> {
    derived_executor_id(
        AGENT_VERB_RECEIPT_DOMAIN,
        &[
            run_ref.as_bytes(),
            run_id.as_bytes(),
            &step_start.to_le_bytes(),
            &ordinal.to_le_bytes(),
        ],
    )
}

/// Whether a write receipt of a step, from the write at `ordinal` on, may
/// have run (FIX 4199). `run_ref` is the run reference the run's dispatcher
/// held. `run_id`, `step_start` and `ordinal` place the write as the
/// dispatcher keyed its receipt. The read is in `rtxn` and writes nothing.
///
/// A step keeps a write's answer on its receipt before the run's row keeps
/// the write's bridge call. A crash between the two leaves a receipt with no
/// bridge call, so the row alone does not show that write.
///
/// The receipts are read in order until one is absent. A write refused
/// before its door ran keeps no receipt and halts the bridge, so no later
/// write of the step keeps one. Only a never-ran mark on a receipt's first
/// row shows that its write did not run. An empty reservation, a kept answer
/// and a receipt that does not read may each have run. This query never
/// says that a write committed or did not commit: that positive commit
/// marker is the work of FIX 12507 and FIX 11887.
pub(crate) fn write_receipt_may_have_run(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    run_ref: &str,
    run_id: EntityId,
    step_start: u64,
    mut ordinal: u64,
) -> Result<bool> {
    loop {
        let receipt_id = derive_write_receipt_id(run_ref, run_id, step_start, ordinal)?;
        match vault.get_code_run_replay_record_in_txn(rtxn, &receipt_id) {
            Ok(None) => return Ok(false),
            Ok(Some(receipt)) if receipt.bridge_calls.first().is_some_and(never_ran) => {}
            Ok(Some(_)) | Err(_) => return Ok(true),
        }
        ordinal += 1;
    }
}

/// How a write's receipt stands when the step makes the write.
pub(super) enum KeptWrite {
    /// The write ran: its receipt answers it (`kept_write_answer`).
    Ran(Box<CodeRunReplayRecord>),
    /// No receipt, or one whose write never ran (a hook stopped it, or no
    /// provider answered it), under that receipt's generation: the write is
    /// made now.
    Fresh(Option<CodeRunReplayGeneration>),
}

/// The refusal a write's kept answer stands under, if any. A receipt's first
/// row is its call's answer; the rows after it are the rulings on reading that
/// answer back, each a refusal or the admitted read that reconciled one, so
/// the answer stands refused while the last of them is a refusal. A refusal
/// is the ruling whose reason codes start with the receipt's marker; the
/// door's own codes follow it (FIX CODE-MODE-DENIAL-REASONS), and a ruling
/// written before them holds the marker alone.
pub(super) fn standing_refusal(receipt: &CodeRunReplayRecord) -> Option<&CodeRunBridgeCall> {
    let ruling = receipt.bridge_calls.get(1..)?.last()?;
    let Ok(SelfDispatchOutcome::Denied(refused)) = decode_self_dispatch_outcome(&ruling.outcome)
    else {
        return None;
    };
    refused
        .reason_codes
        .first()
        .is_some_and(|code| code == KEPT_ANSWER_REFUSED)
        .then_some(ruling)
}

/// Whether a write row met its receipt: it is the receipt's call with the
/// answer the receipt kept, and no refusal of that answer stands. A write a
/// hook stopped before it ran, or no provider answered, meets its mark
/// whatever the run made of it. The receipt's call is read as the side-row
/// wall stored it ([`held_input_meets`]).
///
/// # Errors
///
/// A request the side-row wall cannot read, or the read of base custody's
/// values.
pub(super) fn meets(
    receipt: &CodeRunReplayRecord,
    made: &CodeRunBridgeCall,
    known: &CompareKnown<'_>,
) -> Result<bool> {
    if standing_refusal(receipt).is_some() {
        return Ok(false);
    }
    let Some(kept) = receipt.bridge_calls.first() else {
        return Ok(false);
    };
    let same_call = row_identity(kept) == row_identity(made)
        || (made.effect == SelfEffect::AgentVerb && held_input_meets(kept, &made.request, known)?);
    Ok(same_call && (never_ran(kept) || answered_as_kept(kept, made)))
}

/// The mark a write's receipt keeps when it never ran: a verb hook stopped it
/// ([`VERB_HOOK_STOPPED`]), no provider answered it ([`PROVIDER_UNAVAILABLE`]),
/// or its media admission trapped ([`MEDIA_STEP_TRAPPED`]).
pub(super) fn never_ran_mark(why: &str) -> SelfDispatchOutcome {
    SelfDispatchOutcome::Denied(SelfDeniedResult {
        hook_notice: None,
        effect: SelfEffect::AgentVerb,
        outcome: why.to_owned(),
        reason_codes: vec![why.to_owned()],
    })
}

/// Whether a receipt's row is a [`never_ran_mark`]: the write never ran.
fn never_ran(row: &CodeRunBridgeCall) -> bool {
    matches!(
        decode_self_dispatch_outcome(&row.outcome),
        Ok(SelfDispatchOutcome::Denied(refused))
            if refused.reason_codes == [VERB_HOOK_STOPPED]
                || refused.reason_codes == [PROVIDER_UNAVAILABLE]
                || refused.reason_codes == [MEDIA_STEP_TRAPPED]
    )
}

/// The identity of the verb call a receipt row recorded, if the row is one.
/// A row an erase took the request words of keeps its request identity
/// alone (FIX 6534): only another erased row of the same request meets it,
/// never a live call's reading and never an absent one.
pub(super) fn row_identity(row: &CodeRunBridgeCall) -> Option<Vec<u8>> {
    if row.request_erased() {
        let identity = row.request_identity().ok()?;
        return (row.effect == SelfEffect::AgentVerb)
            .then(|| [ERASED_ROW_IDENTITY, identity.as_slice()].concat());
    }
    let (verb, input) = recorded_call(row)?;
    if crate::task_verb::sdk::CUSTODY_VALUE_ROWS.contains(&verb) {
        if !input.is_empty() {
            return None;
        }
        let rmpv::Value::Map(fields) = &row.request else {
            return None;
        };
        let (_, rmpv::Value::Binary(digest)) = fields
            .iter()
            .find(|(key, _)| key.as_str() == Some("input_identity"))?
        else {
            return None;
        };
        if digest.len() != 32 {
            return None;
        }
        let mut identity = verb.as_bytes().to_vec();
        identity.push(0);
        identity.extend_from_slice(digest);
        return Some(identity);
    }
    Some(call_identity(verb, &serde_json::from_str(input).ok()?))
}

/// Whether a write's receipt row recorded this live call: the row's input,
/// read back from the JSON text the receipt keeps, has the live input's
/// identity. A float in the input must read back exactly, so the crate's
/// serde_json parses with `float_roundtrip` (census L1-06). The side-row
/// wall stored the row, so a live input it placed a handle in meets the row
/// in the wall's planned form ([`held_input_meets`]).
///
/// # Errors
///
/// A request the side-row wall cannot read, or the read of base custody's
/// values.
pub(super) fn records_call(
    row: &CodeRunBridgeCall,
    call: &SelfAgentVerbCall,
    known: &CompareKnown<'_>,
) -> Result<bool> {
    if row_identity(row) == Some(call_identity(call.verb.as_str(), &call.input)) {
        return Ok(true);
    }
    let again = self_call_request_value(&SelfCall::AgentVerb(call.clone()))?;
    held_input_meets(row, &again, known)
}

/// Whether `kept`, a live write row the side-row wall admitted, holds the
/// verb call `offered` spells (FIX RECEIPT-RECORDS-CALL-HELD-INPUT). The two
/// verb names are read first, as written, and must be one verb; only the
/// JSON inputs are read for custody's values. The wall placed each shaped
/// secret, as the handle of a record it minted for it, and each value base
/// custody held, as its record's handle, in the input text the row keeps.
/// While base custody knows a value, read through `known`, both inputs are
/// read as JSON and the row's is a template ([`held_row_meets`]): each
/// handle it holds that names a record custody knows meets the same handle
/// offered again, or one value of that record at any generation, whose
/// length lets the row's text after it match; every other byte meets only
/// itself. So a value another record holds, another token of a shape, or a
/// longer value another record took since, is another write (FIX
/// REPLAY-COMPARE-KNOWN-OTHER-CALLERS); a key the wall kept as written with
/// its switch off, and a value the row holds as written, meet only
/// themselves, also after custody took that value (a rotation into it
/// included). A handle no record custody knows names (literal text, or an
/// erased record's) reads only as written, so two such handles are two
/// writes, and a custody that knows no value leaves the two to meet as
/// written, by [`row_identity`] alone. An input's object keys may come in
/// any order, as a receipt reads them. A row an erase took the words of and
/// a custody value row (its input is a digest) meet only by
/// [`row_identity`].
fn held_input_meets(
    kept: &CodeRunBridgeCall,
    offered: &rmpv::Value,
    known: &CompareKnown<'_>,
) -> Result<bool> {
    let (Some((verb, input)), Some((again_verb, again_input))) =
        (recorded_call(kept), request_call(offered))
    else {
        return Ok(false);
    };
    if verb != again_verb || crate::task_verb::sdk::CUSTODY_VALUE_ROWS.contains(&verb) {
        return Ok(false);
    }
    let Some(known) = known.get()? else {
        return Ok(false);
    };
    let tree = |input: &str| {
        serde_json::from_str::<serde_json::Value>(input)
            .ok()
            .map(|input| json_tree(&input))
    };
    let (Some(held), Some(again)) = (tree(input), tree(again_input)) else {
        return Ok(false);
    };
    held_row_meets(&PlanTree(held).0, &PlanTree(again).0, &known, MapOrder::Any)
}

/// `value` as a MessagePack tree, each object's members in the order the
/// JSON holds them: a number as an integer when it is one, else as a
/// 64-bit float.
fn json_tree(value: &serde_json::Value) -> rmpv::Value {
    match value {
        serde_json::Value::Null => rmpv::Value::Nil,
        serde_json::Value::Bool(flag) => rmpv::Value::Boolean(*flag),
        serde_json::Value::Number(number) => number
            .as_i64()
            .map(rmpv::Value::from)
            .or_else(|| number.as_u64().map(rmpv::Value::from))
            .unwrap_or_else(|| rmpv::Value::F64(number.as_f64().unwrap_or(f64::NAN))),
        serde_json::Value::String(text) => rmpv::Value::from(text.as_str()),
        serde_json::Value::Array(items) => {
            rmpv::Value::Array(items.iter().map(json_tree).collect())
        }
        serde_json::Value::Object(fields) => rmpv::Value::Map(
            fields
                .iter()
                .map(|(key, member)| (rmpv::Value::from(key.as_str()), json_tree(member)))
                .collect(),
        ),
    }
}

/// Whether a write row carries the answer its receipt kept: a verb's answer,
/// which only this door gives a write (fresh, or read back from the
/// receipt), or the same refusal. A row the bridge recorded without
/// dispatching it carries neither. A verb's answer is matched by kind: its
/// JSON text need not survive a decode exactly, as a float may move by one
/// unit in the last place.
fn answered_as_kept(kept: &CodeRunBridgeCall, made: &CodeRunBridgeCall) -> bool {
    match (
        decode_self_dispatch_outcome(&kept.outcome),
        decode_self_dispatch_outcome(&made.outcome),
    ) {
        (Ok(SelfDispatchOutcome::AgentVerb(_)), Ok(SelfDispatchOutcome::AgentVerb(_))) => true,
        (Ok(SelfDispatchOutcome::Denied(kept)), Ok(SelfDispatchOutcome::Denied(made))) => {
            kept == made
        }
        // A held connector call's park (ONE-2510).
        (
            Ok(SelfDispatchOutcome::DurableWait(kept)),
            Ok(SelfDispatchOutcome::DurableWait(made)),
        ) => kept == made,
        _ => false,
    }
}

/// Whether a recorded call is a verb write: by the catalog verb its row
/// keeps, its request words kept or erased (FIX 6534), so an erase never
/// moves a later write's place among the step's writes.
pub(super) fn is_write(row: &&CodeRunBridgeCall) -> bool {
    row.recorded_verb()
        .is_some_and(|verb| AgentVerb::from_name(verb).is_some_and(AgentVerb::writes))
}

/// The verb name and JSON input of a recorded verb call, if the row is one.
pub(crate) fn recorded_call(row: &CodeRunBridgeCall) -> Option<(&str, &str)> {
    if row.effect != SelfEffect::AgentVerb {
        return None;
    }
    request_call(&row.request)
}

/// The verb name and JSON input a verb call's request spells.
fn request_call(request: &rmpv::Value) -> Option<(&str, &str)> {
    let rmpv::Value::Map(fields) = request else {
        return None;
    };
    let field = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .and_then(|(_, value)| value.as_str())
    };
    Some((field("verb")?, field("input")?))
}
