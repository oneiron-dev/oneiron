//! A claim commit's request, resolved before its write: the typed families it refuses, its
//! references, its value and clock, and the prior head it would replace.

use super::*;

/// A claim commit resolved before its write transaction opens; each write
/// attempt reads it.
pub(super) struct ClaimWrite<'a> {
    pub(super) input: &'a ClaimInput,
    pub(super) id: EntityId,
    pub(super) subject: EntityId,
    pub(super) source: crate::claim::ClaimSource,
    pub(super) value: rmpv::Value,
    pub(super) world: Option<EntityId>,
    pub(super) relationship: Option<EntityId>,
    pub(super) scope_rmpv: Option<rmpv::Value>,
    pub(super) now: u64,
    pub(super) occurred_at: u64,
    pub(super) learned_at: u64,
    pub(super) key: MemoryKey<'a>,
    pub(super) beside_stated: bool,
    pub(super) prior: Option<EntityId>,
    pub(super) in_writer: &'a dyn Fn(&heed::RoTxn<'_>) -> Result<(), Error>,
    pub(super) birth: Option<&'a crate::provenance::birth::RowBirth>,
    /// Preserves the owner's typed refusal across the engine transaction
    /// closure, whose error type is the storage API's rather than MemoryError.
    pub(super) publication_refusal: std::cell::RefCell<Option<MemoryError>>,
}

/// This door does not own `companion.expression.*` any more than
/// `claim_retract` does, and for the mirror-image reason. Writing a new
/// head of that family means superseding the CURRENT head under the
/// family's own precedence rules — source rank, then validity, then
/// recency — and the generic upsert below supersedes on
/// `subject+scope+predicate` alone. Those disagree: a new `Inferred`
/// revision written here closes a `UserStated` head the typed door
/// would have left standing, and the supersession chain the typed
/// retraction walks back is silently wrong from then on. Asked before
/// anything is resolved, because it is not an authorization question —
/// an authorized caller breaks the chain exactly as thoroughly.
///
/// Every generic claim-write door routes through here (`vault.commit`,
/// `vault.claims.upsert`, `vault.claims.seed` via `commit_all`), so one
/// guard covers all three.
/// Keyed facts bind subject, envelope actor/class, worldless scope,
/// exact address, and replay identity together. A generic upsert's
/// subject+scope match must not supersede another actor's keyed fact.
pub(super) fn refuse_typed_claim_family(input: &ClaimInput) -> MemoryResult<()> {
    if input.predicate == super::super::key_value::PREDICATE {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "keyed memory is written through vault.kv.put",
            &["Use the actor-bound keyed-memory door; generic claims cannot replace keyed facts."],
        ));
    }
    if crate::claim::is_expression_preference_predicate(&input.predicate) {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "an expression preference is written through its own door, not the general one",
            &[
                "Write the preference through the vault's typed expression-preference door.",
                "That door supersedes the head this family's own precedence rules pick; a general write does not.",
            ],
        ));
    }
    Ok(())
}

impl Memory<'_> {
    /// Resolves the claim's references, value and clock, and finds the prior
    /// head an auto-superseding write would replace.
    pub(super) fn resolve_claim_write<'a>(
        &self,
        input: &'a ClaimInput,
        auto_supersede: bool,
        in_writer: &'a dyn Fn(&heed::RoTxn<'_>) -> Result<(), Error>,
        birth: Option<&'a crate::provenance::birth::RowBirth>,
    ) -> MemoryResult<ClaimWrite<'a>> {
        self.verified_actor_class()?;
        let id = id_from_optional_hex(self.vault, input.id.as_deref())?;
        let subject = self.resolve_ref(&input.subject_ref)?;
        if self.vault.get_entity_type(&subject)?.is_none() {
            return Err(MemoryError::not_found(format!(
                "claim subject {} does not exist",
                subject.to_hex()
            )));
        }
        let source = self.claim_source(&input.source)?;
        // The publisher sponsors the page's anonymous parses (FIX 5288):
        // stamped here, where the publish door already holds the publishing
        // principal as this write's actor.
        let value = if input.predicate == crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE {
            let mut claimed = input.value.clone();
            crate::booking::publication::stamp_publication_sponsor(&mut claimed, self.actor);
            json_to_rmpv(&claimed)
        } else {
            json_to_rmpv(&input.value)
        };
        let world = match &input.world_ref {
            Some(world_ref) => Some(self.resolve_ref(world_ref)?),
            None => None,
        };
        let relationship = input
            .relationship_ref
            .as_deref()
            .map(|r| self.resolve_ref(r))
            .transpose()?;
        let scope_rmpv = input.scope.as_ref().map(json_to_rmpv);
        let now = self.vault.store.clock.now_recorded_at();
        let occurred_at = input.occurred_at.unwrap_or(now);
        let learned_at = input.learned_at.unwrap_or(now);
        let key = MemoryKey {
            subject,
            input,
            world,
            relationship,
        };
        // OF-023: a want derived from behaviour is minted beside the stated
        // one, never over it. Only the replacing doors (commit, upsert) take
        // this path; the seed and proposal doors replace nothing.
        let beside_stated =
            auto_supersede && crate::claim::is_observed_preference(Some(source), &input.predicate);

        // ADVISORY only (ONE-1936): this lookup runs outside the transaction,
        // so the prior it names may already be closed by the time the write
        // txn opens. The authority is `supersede_claim_in_txn`'s guard, inside
        // that txn — and a refusal there rolls the staged replacement back
        // with it.
        let prior = if auto_supersede {
            self.find_prior_claim(&key, &id, beside_stated)?
        } else {
            None
        };
        Ok(ClaimWrite {
            input,
            id,
            subject,
            source,
            value,
            world,
            relationship,
            scope_rmpv,
            now,
            occurred_at,
            learned_at,
            key,
            beside_stated,
            prior,
            in_writer,
            birth,
            publication_refusal: std::cell::RefCell::new(None),
        })
    }
}
