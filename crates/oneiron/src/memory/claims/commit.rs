//! Claim commits: the batch, single and guarded commit doors, and the claim-envelope actor read.
//! `Memory::commit_one_guarded` and `claim_envelope_actor` are its call surface.
//! `memory::claims` defines the claim inputs and receipts these commit.

use super::*;

mod preferences;
mod write;

impl Memory<'_> {
    // ── internals ───────────────────────────────────────────────────────

    /// Commits each of `claims` as its own gated write, through `row`. The
    /// batch is not atomic: each element's write is its own transaction
    /// ([`Self::commit_one`]), so a refused element rolls back alone and
    /// sinks no other. Each answers its landed receipt or its typed refusal
    /// (OF-063, Engine ruling 1221); a refusal is receipted on a write of its
    /// own once the element's write has rolled back, so the receipt
    /// survives it, and names the element's pointer, never what it held.
    pub(in crate::memory) fn commit_all(
        &self,
        row: &'static str,
        claims: &[ClaimInput],
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
    ) -> Vec<CommitOutcome> {
        let mut outcomes = Vec::with_capacity(claims.len());
        for (index, input) in claims.iter().enumerate() {
            match self.commit_one(input, auto_supersede, forced_approval) {
                Ok(receipt) => outcomes.push(CommitOutcome::Landed(receipt)),
                Err(err) => {
                    let refusal = RecordRefusal::from_error(&err, format!("/claims/{index}"));
                    let receipt_ref = refusal.receipt(self, row);
                    outcomes.push(CommitOutcome::Refused {
                        refusal,
                        receipt_ref,
                    });
                }
            }
        }
        outcomes
    }

    pub(super) fn commit_one(
        &self,
        input: &ClaimInput,
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
    ) -> MemoryResult<CommitReceipt> {
        self.commit_one_with_before_txn(input, auto_supersede, forced_approval, || {})
    }

    /// Upserts one claim, running `before_txn` in the window between the
    /// ADVISORY prior-claim lookup and the write transaction.
    ///
    /// That window is the race the in-txn guard closes: the prior discovered
    /// outside the transaction may have moved by the time the transaction
    /// runs. The seam exists so a test can move it deliberately; production
    /// callers pass a no-op.
    pub(super) fn commit_one_with_before_txn(
        &self,
        input: &ClaimInput,
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
        before_txn: impl FnOnce(),
    ) -> MemoryResult<CommitReceipt> {
        self.commit_one_guarded(
            input,
            auto_supersede,
            forced_approval,
            before_txn,
            &|_: &heed::RoTxn<'_>| Ok(()),
        )
    }

    /// [`Self::commit_one_with_before_txn`], with `in_writer` run first in
    /// the content writer that commits the claim: a door whose authority must
    /// still hold when the claim lands rechecks it there (FIX 1400).
    pub(in crate::memory) fn commit_one_guarded(
        &self,
        input: &ClaimInput,
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
        before_txn: impl FnOnce(),
        in_writer: &dyn Fn(&heed::RoTxn<'_>) -> Result<(), Error>,
    ) -> MemoryResult<CommitReceipt> {
        self.commit_one_guarded_with_birth(
            input,
            auto_supersede,
            forced_approval,
            before_txn,
            in_writer,
            None,
        )
    }
}

/// The memory key a prior claim shares with an incoming one: subject,
/// predicate, world, relationship and exact scope, extended with
/// `value.question_id` for declared multi-cardinality predicates (B1c).
struct MemoryKey<'a> {
    subject: EntityId,
    input: &'a ClaimInput,
    world: Option<EntityId>,
    relationship: Option<EntityId>,
}

impl MemoryKey<'_> {
    /// Whether `body` is a standing head on this key: Active, and Auto or
    /// Approved. The caller enumerates `subject`'s claims.
    fn stands(&self, body: &ClaimBody) -> bool {
        if body.lifecycle != ClaimLifecycleStatus::Active
            || !matches!(
                body.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
            || body.predicate != self.input.predicate
            || body.world != self.world
            || body.rel != self.relationship
            || body.scope.as_ref().map(msgpack_value_to_json) != self.input.scope
        {
            return false;
        }
        if !MULTI_CARDINALITY_PREDICATES.contains(&self.input.predicate.as_str()) {
            return true;
        }
        let question = |value: &serde_json::Value| value.get(MULTI_CARDINALITY_VALUE_KEY).cloned();
        question(&msgpack_value_to_json(&body.value)) == question(&self.input.value)
    }
}

/// Extracts the write-envelope actor stamped into a claim's evidence
/// (gated candidate path). `None` for claims written without an envelope.
pub(super) fn claim_envelope_actor(body: &ClaimBody) -> Option<EntityId> {
    let Value::Map(entries) = body.evidence.as_ref()? else {
        return None;
    };
    for (key, value) in entries {
        if key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)
            && let Value::Binary(bytes) = value
        {
            let raw: [u8; 16] = bytes.as_slice().try_into().ok()?;
            return EntityId::from_bytes(raw).ok();
        }
    }
    None
}
