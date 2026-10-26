//! A widen's context reads (FIX 9438, 10543): an attempt's live recursive
//! slice, a parent's effective slice and the board its lineage records. Each
//! reads in the caller's transaction, so a writer that proposes, approves
//! or declines reads in its own view and opens no snapshot beside it.

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::context_projection::{
    ContextResolutionRequest, ContextSpec, MemoryProjection, ResolvedContextProjection,
    resolve_context_spec_in_txn,
};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::super::codec::record_dispatch_input;
use super::super::widen_record::{SLICE, invalid};
use super::super::{AgentDispatchInput, AgentDispatcher};

impl AgentDispatcher<'_> {
    /// Re-resolves an attempt's live recursive slice, including approved widening.
    /// Executors must use this door rather than resolve a payload standalone.
    /// Reads in one snapshot of its own.
    pub fn resolve_attempt_context(&self, attempt: AttemptId) -> Result<ResolvedContextProjection> {
        let txn = self.vault.store.env.read_txn()?;
        self.resolve_attempt_context_in_txn(&txn, attempt)
    }

    /// [`Self::resolve_attempt_context`] in the caller's transaction.
    pub(super) fn resolve_attempt_context_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
    ) -> Result<ResolvedContextProjection> {
        let mut projection = self
            .resolve_ancestor_projection_in_txn(txn, attempt)?
            .ok_or_else(|| invalid("attempt has no provable context lineage"))?;
        let row = AttemptQueue::new(self.vault)
            .get_in_txn(txn, attempt)?
            .ok_or_else(|| invalid("context attempt is missing"))?;
        let input =
            record_dispatch_input(&row).ok_or_else(|| invalid("context input is malformed"))?;
        let parent = decode_dreamer_attempt_payload(&row.payload)?.parent_attempt;
        self.require_sibling_result_lineage_in_txn(
            txn,
            parent,
            row.run_id.as_deref(),
            &input.context_from,
        )?;
        projection.sibling_result_refs = resolve_context_spec_in_txn(
            self.vault,
            txn,
            ContextResolutionRequest {
                spec: ContextSpec::excluded(),
                parent: None,
                context_from: input.context_from,
                world_scope: None,
            },
        )?
        .sibling_result_refs;
        projection.workflow_output_refs =
            self.workflow_output_refs_for_attempt_in_txn(txn, attempt, parent)?;
        Ok(projection)
    }

    /// The slice `attempt` reads: an approved widening's, replayed on its
    /// board act and its landed proposal, else its own descriptor. Read in
    /// the caller's transaction.
    pub(in crate::agent_dispatch) fn effective_context_spec_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
        input: &AgentDispatchInput,
    ) -> Result<ContextSpec> {
        let Some(slice) = SLICE.get(&self.vault.store, txn, &attempt)? else {
            return Ok(input.context_spec.clone().unwrap_or_default());
        };
        self.replay_board_act_in_txn(
            txn,
            slice.board,
            EntityId::from_hex(&slice.actor)?,
            slice.proof,
        )?;
        let (_, record) = self.stored_widen_proposal(txn, &slice.proposal_id)?;
        if self.recorded_parent_in_txn(txn, attempt)? != slice.board {
            return Err(invalid("approved slice has a different board lineage"));
        }
        if record.landed.is_none() || record.request.intent.parent != attempt {
            return Err(invalid("slice has no matching landed board decision"));
        }
        if record.request.widened_spec == slice.spec {
            return Ok(slice.spec);
        }
        // SLICE keeps a layer or domain equal to a custody value as its
        // handle; the intent row keeps the same slice's references as written
        // (FIX 6665), so those are the ones every read resolves.
        if masked_slice_of(&slice.spec, &record.request.widened_spec) {
            return Ok(record.request.widened_spec);
        }
        Err(invalid("slice has no matching landed board decision"))
    }

    /// The board `attempt`'s lineage records above it, read in the caller's
    /// transaction: its parent, a wrapper crossed to its real parent.
    pub(super) fn recorded_parent_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
    ) -> Result<Option<AttemptId>> {
        let row = AttemptQueue::new(self.vault)
            .get_in_txn(txn, attempt)?
            .ok_or_else(|| invalid("widen lineage attempt is missing"))?;
        self.workflow_authority_parent_in_txn(
            txn,
            decode_dreamer_attempt_payload(&row.payload)?.parent_attempt,
        )
    }
}

/// Whether `slice`, an approved slice as SLICE keeps it, is `widened`, the
/// intent row's copy written beside it (FIX 6665). SLICE masks known values in
/// every field, while the intent row keeps the slice's layers and memory
/// domains raw, so a layer or domain may hold a custody handle where
/// `widened` holds bytes; every other field reads the same in both.
fn masked_slice_of(slice: &ContextSpec, widened: &ContextSpec) -> bool {
    let refs_match = |masked: &[String], raw: &[String]| {
        masked.len() == raw.len()
            && masked
                .iter()
                .zip(raw)
                .all(|(masked, raw)| masked == raw || handles_stand_in(masked, raw))
    };
    if !refs_match(&slice.layers, &widened.layers) {
        return false;
    }
    let mut aligned = slice.clone();
    aligned.layers.clone_from(&widened.layers);
    if let MemoryProjection::Scoped { domains, .. } = &mut aligned.memory
        && let MemoryProjection::Scoped { domains: raw, .. } = &widened.memory
    {
        if !refs_match(domains, raw) {
            return false;
        }
        domains.clone_from(raw);
    }
    aligned == *widened
}

/// Whether `masked` is `raw` with spans the side-row wall replaced by custody
/// handles: all of it as one handle, or each span as the text form
/// `[secret sc12]` between the bytes the wall kept. Each replaced span held at
/// least one character.
fn handles_stand_in(masked: &str, raw: &str) -> bool {
    const HANDLE_OPEN: &str = "[secret ";
    if raw.is_empty() {
        return false;
    }
    if crate::secret_custody::parse_secret_handle(masked).is_ok() {
        return true;
    }
    let mut kept = Vec::new();
    let mut from = 0;
    let mut at = 0;
    while let Some(open) = masked[at..].find(HANDLE_OPEN).map(|found| at + found) {
        let Some(close) = masked[open..].find(']').map(|found| open + found + 1) else {
            break;
        };
        if crate::secret_custody::parse_secret_handle(&masked[open..close]).is_ok() {
            kept.push(&masked[from..open]);
            from = close;
            at = close;
        } else {
            at = open + HANDLE_OPEN.len();
        }
    }
    if kept.is_empty() {
        return false;
    }
    kept.push(&masked[from..]);
    let [first, middle @ .., last] = kept.as_slice() else {
        return false;
    };
    if !raw.starts_with(*first) {
        return false;
    }
    let mut cursor = first.len();
    for segment in middle {
        let Some((found, _)) = raw[cursor..]
            .match_indices(*segment)
            .find(|(found, _)| *found > 0)
        else {
            return false;
        };
        cursor += found + segment.len();
    }
    raw.ends_with(*last) && raw.len() - last.len() > cursor
}
