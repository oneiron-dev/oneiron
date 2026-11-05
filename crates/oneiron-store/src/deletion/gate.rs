use sha2::{Digest, Sha256};
use std::cell::Cell;

use crate::gate_decision::types::GateDecisionId;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

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
pub type DeletionCheck<'a> = &'a dyn Fn(&heed::RoTxn<'_>) -> Result<()>;

/// A write a `user_hard_delete` makes in its own linearizing transaction (its
/// tombstone publication, or with nothing published its purge), given its
/// request id: the claim on what authorized it, refused when that is already
/// spent. The purge transaction calls it again with the delete's receipt.
pub type DeletionClaimWrite<'a> =
    &'a dyn Fn(&mut heed::RwTxn<'_>, &[u8; 16], Option<&EntityId>) -> Result<()>;

/// The original authority act beside its ordinary in-transaction claim. The
/// staged deletion sidecar keeps that identity if publication rolls back after
/// the shared document changed; recovery never infers it from a request id.
#[derive(Clone, Copy)]
pub struct DeletionClaim<'a> {
    pub authority_act: EntityId,
    pub apply: DeletionClaimWrite<'a>,
}

impl<'a> DeletionClaim<'a> {
    pub fn new(authority_act: EntityId, apply: DeletionClaimWrite<'a>) -> Self {
        Self {
            authority_act,
            apply,
        }
    }
}
