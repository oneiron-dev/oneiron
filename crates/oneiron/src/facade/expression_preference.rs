//! Typed `companion.expression.*` doors on the [`Memory`] surface.
//! Surface half of the write guards in `claim/`; re-exported by [`super`].
//!
//! # Why this file exists
//!
//! The expression-preference family owns its own supersession semantics: a
//! write closes the head that the family's precedence rules pick (source rank,
//! then validity, then recency), and a retraction closes the head AND restores
//! the predecessor it superseded. The generic claim doors cannot honour either
//! half — a generic upsert supersedes on `subject+scope+predicate` alone, and
//! a generic retraction performs only the closing half — so all of them refuse
//! the family and point the caller at "the typed door".
//!
//! Until now that door was a `Vault` method taking a raw `WriteActor`, which
//! an app-tier caller holding a [`Memory`] could not reach. The refusal named
//! somewhere the refused caller could not go. These three verbs are that
//! somewhere, on the surface the refusal is raised from.
//!
//! # What they add over the vault doors
//!
//! Nothing about the semantics — those stay where they are, in the engine.
//! What is added is the facade's own contract: the actor comes from the
//! BINDING rather than an argument, subjects arrive as refs rather than ids,
//! and results come back in short-ref terms. The engine's own rules ride
//! through untouched, including the one that matters most here: an
//! [`ExpressionPreferenceOrigin::ExplicitUser`] write requires a human-class
//! actor, so an agent cannot put words in the owner's mouth by routing through
//! a friendlier surface.

use super::*;

use crate::claim::{
    ExpressionPreferenceChange, ExpressionPreferenceOrigin, ExpressionPreferenceSet,
    ExpressionPreferenceValue,
};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// One typed expression-preference write.
///
/// The subject is a REF, not an id, because that is the facade's vocabulary.
/// There is deliberately no actor field: the writing actor is the bound one,
/// so there is no payload key an untrusted caller could use to write as
/// somebody else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressionPreferenceInput {
    /// Subject entity ref (short-id ref or 32-hex).
    pub subject_ref: String,
    /// Which preference, and its value.
    pub value: ExpressionPreferenceValue,
    /// Whether the person said this or the system inferred it.
    /// `ExplicitUser` requires a human-class bound actor.
    pub origin: ExpressionPreferenceOrigin,
    /// When the preference takes effect (Unix seconds).
    pub valid_from: u64,
}

/// Receipt for one typed expression-preference write.
///
/// Deliberately NOT [`CommitReceipt`]. A preference write can close SEVERAL
/// prior heads at once, and `CommitReceipt` carries a single
/// `superseded_short_id` — folding a set into it would silently drop
/// supersessions, which is precisely the chain damage the typed door exists to
/// prevent. A receipt that under-reports what it closed would be worse than no
/// receipt, because it reads as complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressionPreferenceReceipt {
    /// Short-id ref of the written preference claim.
    pub claim_short_id: String,
    /// Final approval as stored.
    pub approval: String,
    /// Short-id refs of EVERY claim this write superseded, in the order the
    /// engine closed them. Empty when the write started a fresh chain.
    ///
    /// These are resolved AFTER the supersession, and a short ref carries a
    /// content hash — so a closed claim's ref here will NOT equal the
    /// `claim_short_id` its own write receipt returned while it was active.
    /// Same property [`CommitReceipt::superseded_short_id`] already has, named
    /// here because a caller correlating two receipts would otherwise read the
    /// difference as two different claims rather than one claim in two states.
    pub superseded_short_ids: Vec<String>,
    /// Gate decision ref (`gate:<hex>`), when the write left one.
    pub receipt_ref: Option<String>,
}

impl Memory<'_> {
    /// Writes one expression preference, superseding whichever head the
    /// family's precedence rules say it replaces.
    ///
    /// This is the door the generic claim-write refusals point at. It is the
    /// ONLY way to write `companion.expression.*` through this surface;
    /// `commit`, `claim_upsert` and `seed_claims` all refuse the family.
    ///
    /// # Errors
    ///
    /// The bound actor must resolve and match its class. An
    /// [`ExpressionPreferenceOrigin::ExplicitUser`] write from a non-human
    /// actor is refused by the engine, as is a value outside the family's
    /// vocabulary.
    pub fn set_expression_preference(
        &self,
        input: &ExpressionPreferenceInput,
        occurred_at: u64,
    ) -> FacadeResult<ExpressionPreferenceReceipt> {
        // Claim doors verify the class here and let the claim write
        // transaction revalidate the binding, rather than opening a second
        // transaction around one the engine already owns (the DA-0 split
        // recorded in `support`).
        self.verified_actor_class()?;
        let subject = self.resolve_ref(&input.subject_ref)?;
        let actor = WriteActor::new(self.actor, self.actor_class);
        let claim_id = EntityId::now();
        let written = self.vault.set_expression_preference(
            &actor,
            claim_id,
            ExpressionPreferenceChange {
                subject,
                value: input.value.clone(),
                origin: input.origin,
                valid_from: input.valid_from,
            },
            TimeRange {
                start: occurred_at,
                end: occurred_at,
            },
            occurred_at,
        )?;

        let mut superseded_short_ids = Vec::with_capacity(written.superseded_claim_ids.len());
        for old_id in &written.superseded_claim_ids {
            superseded_short_ids.push(self.short_ref_or_hex(old_id)?);
        }
        Ok(ExpressionPreferenceReceipt {
            claim_short_id: self.short_ref_or_hex(&written.claim_id)?,
            approval: written.approval.as_str().to_owned(),
            superseded_short_ids,
            receipt_ref: self.latest_decision_ref_for(&written.claim_id)?,
        })
    }

    /// Retracts an expression preference, restoring the predecessor it had
    /// superseded.
    ///
    /// Both halves, which is what makes this different from
    /// [`Memory::claim_retract`] — that door refuses this family precisely
    /// because it performs only the closing half and would leave the chain
    /// headless.
    ///
    /// # Errors
    ///
    /// The ref must resolve to an ACTIVE claim of this family that the bound
    /// actor is allowed to close; the engine decides that, unchanged.
    pub fn retract_expression_preference(&self, claim_ref: &str) -> FacadeResult<()> {
        self.verified_actor_class()?;
        let claim_id = self.resolve_ref(claim_ref)?;
        let actor = WriteActor::new(self.actor, self.actor_class);
        self.vault
            .retract_expression_preference(&actor, &claim_id, crate::unix_seconds_now())?;
        Ok(())
    }

    /// The preferences in force for a subject at `at`, one winner per kind.
    ///
    /// A read, so it neither writes nor gates — but it takes the same binding
    /// check as the writes beside it, so a caller cannot read a subject's
    /// preferences from an actor the store never admitted.
    ///
    /// # Errors
    ///
    /// The bound actor must resolve and match its class, and the subject ref
    /// must resolve.
    pub fn expression_preferences(
        &self,
        subject_ref: &str,
        at: u64,
    ) -> FacadeResult<ExpressionPreferenceSet> {
        self.verified_actor_class()?;
        let subject = self.resolve_ref(subject_ref)?;
        Ok(self.vault.expression_preferences(&subject, at)?)
    }
}
