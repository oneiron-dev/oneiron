use sha2::{Digest, Sha256};

use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{GateDecisionId, GateDecisionRecord};

use super::tombstone::{DeleteReason, TombstoneReason};

/// Owner-authority evidence evaluated before a facade deletion starts.
///
/// The actor identity is intentionally recorded at today's strength: a
/// store-verified actor entity plus asserted class. Stronger identity minting
/// remains ONE-1604 and is not implied by this record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeletionGateContext {
    actor: EntityId,
    actor_class: EdgeActorClass,
    policy_manifest_version: String,
    read_frontier_hash: [u8; 32],
}

/// The facade's gated-deletion carrier: the evaluated decision record PLUS the
/// authority re-check the transactions BEFORE the delete's linearization point
/// re-run.
///
/// The two halves are deliberately separate. [`DeletionGateContext`] is a
/// RECORD — the evidence minted once, before TXN1, and written verbatim into
/// the gate ledger. `reverify` is a DECISION, and a decision made against a
/// dropped read snapshot is worthless the instant the snapshot is stale: a
/// `RevokeActor` (or any binding change) committed between gate evaluation and
/// the first destructive commit would never be observed, and the delete would
/// tear on authority that no longer exists. Re-running the fold INSIDE that
/// transaction makes the two atomic under LMDB's single writer, matching what
/// the sibling owner verbs already do (`claim_retract` and the structural arm
/// fold inside their own write txns).
///
/// LINEARIZATION (fix-leg 7, refined by fix-leg 8): the re-check is NOT re-run
/// forever — but only because a publish commit exists to settle it. That commit
/// is the delete's linearization point, and after it the answer is settled; when
/// this delete publishes NOTHING there is no such point, and every destructive
/// transaction is still pre-publication. See
/// [`reverify_deletion_authority_before_publication`] and
/// [`reverify_deletion_authority_when_unpublished`].
pub(crate) struct GatedDeletion<'a> {
    pub(super) context: DeletionGateContext,
    reverify: &'a dyn Fn(&heed::RoTxn<'_>) -> Result<()>,
}

impl<'a> GatedDeletion<'a> {
    pub(crate) fn new(
        context: DeletionGateContext,
        reverify: &'a dyn Fn(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Self {
        Self { context, reverify }
    }
}

/// Re-runs `gate`'s authority check against `txn`, or passes when the delete is
/// ungated (the engine-internal `delete_entity_with_reason` door, which carries
/// no owner claim to re-prove).
///
/// CALL SITES ARE PRE-PUBLICATION ONLY (fix-leg 7 linearization ruling). Every
/// caller must run STRICTLY BEFORE the transaction that publishes the tombstone
/// commits — the entry folds and the publish txn itself. The publish commit is
/// the delete's linearization point: a `RevokeActor` LMDB-ordered after it did
/// not race the delete, it simply follows an operation that was authorized when
/// it committed, and no linearizable history lets a later revocation
/// retroactively un-authorize an earlier committed op. Re-checking authority at
/// a post-publication step could only produce a FORBIDDEN for a deletion that
/// already reached peers — a lie the caller cannot act on, and one sync replay
/// undoes anyway (the published tombstone comes back and purges locally
/// regardless). The name says PRE-publication so a future edit that reaches for
/// this helper below the publish txn reads as the mistake it would be.
pub(super) fn reverify_deletion_authority_before_publication(
    gate: Option<&GatedDeletion<'_>>,
    txn: &heed::RoTxn<'_>,
) -> Result<()> {
    match gate {
        Some(gate) => (gate.reverify)(txn),
        None => Ok(()),
    }
}

/// Re-runs the authority check IF AND ONLY IF this delete published nothing —
/// the fix-leg 8 refinement of the linearization ruling.
///
/// `crdt_persisted` is the whole condition, and it is deliberately NOT the
/// `sync` cargo flag. The rule above settles authority at the publish COMMIT,
/// and a delete with no publish commit has no such point: nothing became
/// remote-visible, no peer can be tearing, and the local purge is still the
/// FIRST irreversible act rather than a committed operation finishing. Refusing
/// there is therefore actionable and true — the exact opposite of the
/// post-publication refusal fix-7 removed.
///
/// Two distinct build/runtime shapes reach this with `crdt_persisted == false`:
/// the sync-DISABLED build, where [`Vault::write_crdt_tombstone`] is a no-op by
/// construction, and any future sync-enabled path that declines to publish. Both
/// must obey the same rule, which is why the flag is the wrong key — a `#[cfg]`
/// here would silently re-open the hole for the second shape.
///
/// The caller runs this INSIDE its destructive transaction, so the check and the
/// tear (and the `pt:` marker that carries the deletion's propagation intent to
/// a later sync-enabled boot) are atomic under LMDB's single writer. A
/// `RevokeActor` is thus ordered strictly before the check — seen, nothing torn,
/// no replayable marker — or strictly after the commit, where it follows a
/// deletion that WAS authorized when it committed.
pub(super) fn reverify_deletion_authority_when_unpublished(
    gate: Option<&GatedDeletion<'_>>,
    crdt_persisted: bool,
    txn: &heed::RoTxn<'_>,
) -> Result<()> {
    if crdt_persisted {
        return Ok(());
    }
    reverify_deletion_authority_before_publication(gate, txn)
}

impl DeletionGateContext {
    pub(crate) fn new(
        actor: EntityId,
        actor_class: EdgeActorClass,
        policy_manifest_version: String,
        read_frontier_hash: [u8; 32],
    ) -> Self {
        Self {
            actor,
            actor_class,
            policy_manifest_version,
            read_frontier_hash,
        }
    }

    pub(super) fn decision_record(
        &self,
        request_id: [u8; 16],
        target: &EntityId,
        reason: DeleteReason,
        created_at: u64,
    ) -> GateDecisionRecord {
        let mut diff = Sha256::new();
        diff.update(b"oneiron.gate.deletion.v0");
        diff.update(self.actor.as_bytes());
        diff.update(target.as_bytes());
        diff.update([TombstoneReason::from(reason).wire_byte()]);
        GateDecisionRecord {
            version: 0,
            // The ledger key is the deletion request id, so recovery and
            // REDACTION_AUDIT correlation never need a second identifier.
            decision_id: GateDecisionId::from_bytes(request_id),
            created_at,
            outcome: "allow".to_owned(),
            reason_codes: vec!["gate.allow.owner_delete".to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: self.actor_class.gate_actor_class().to_owned(),
            actor_ref: Some(self.actor.to_hex()),
            content_kind: "deletion".to_owned(),
            policy_manifest_version: self.policy_manifest_version.clone(),
            claim_id: None,
            grant_ref: None,
            diff_handle: diff.finalize().to_vec(),
            read_frontier_hash: self.read_frontier_hash,
            redacted_at: None,
        }
    }
}
