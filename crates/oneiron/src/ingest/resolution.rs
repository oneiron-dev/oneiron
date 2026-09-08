//! ARCH-0024 entity-resolution waterfall: candidate scoring, routing, and canonical subject.

use crate::claim::ClaimSubject;
use crate::entity_id::EntityId;

// ===========================================================================
// ARCH-0024 candidate scoring / ranking / routing waterfall
//
// The scoring input is EFFECTIVE confidence — stored claim confidence composed
// with the provider's `actor.confidence_prior` — never the stored column. That
// is the whole point of the leg: a provider the vault has learned to distrust
// must not out-rank a modest claim from one it trusts, and reading
// `ClaimBody::confidence` directly here would silently restore the old,
// provider-blind ordering.
//
// The five ARCH-0024 signal producers and the mention-side wiring are NOT in
// this wave, so this function has NO production call site yet. It is complete
// and testable on its own terms: candidates in, a routed decision out, no
// writes of any kind.
// ===========================================================================

/// One entity-resolution candidate: a subject, plus the provider-attributed
/// confidence CLAIM that argues for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntityResolutionCandidate {
    /// The entity this candidate proposes the mention resolves to.
    pub subject: EntityId,
    /// The `provider.enrichment` CLAIM whose effective confidence scores it.
    pub confidence_claim_ref: EntityId,
}

/// The ARCH-0024 routing bands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntityResolutionRoute {
    /// `>= 0.90` — link outright.
    HardLink,
    /// `[0.70, 0.90)` — link, but verify asynchronously.
    SoftLink,
    /// `[0.50, 0.70)` — link weakly, verify asynchronously.
    SoftLinkLow,
    /// `< 0.50`, or no candidates at all — resolve to nothing here.
    ProvisionalEntity,
}

/// A candidate with the effective confidence the waterfall scored it at.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScoredEntityResolutionCandidate {
    /// The candidate with its subject projected to the canonical Active head.
    pub candidate: EntityResolutionCandidate,
    /// Stored confidence composed with the provider's active prior.
    pub effective_confidence: f32,
}

/// The waterfall's verdict for one mention.
#[derive(Clone, Debug, PartialEq)]
pub struct EntityResolutionWaterfallDecision {
    /// Every authority-admissible candidate, scored and ranked best-first.
    pub ranked: Vec<ScoredEntityResolutionCandidate>,
    /// Surfaceable claims excluded by the stricter `claim_consolidatable` gate.
    pub claims_suppressed: usize,
    /// The chosen subject; `None` for [`EntityResolutionRoute::ProvisionalEntity`].
    pub selected: Option<EntityId>,
    /// The top effective confidence; `None` for the provisional route.
    pub selected_effective_confidence: Option<f32>,
    /// Which band the top score fell in.
    pub route: EntityResolutionRoute,
    /// Whether the route demands asynchronous verification.
    pub requires_async_verification: bool,
}

/// Scores, ranks, and routes entity-resolution candidates for one mention.
///
/// Opens exactly ONE write transaction for the whole batch — a write
/// transaction because scoring may repair a provider-confidence shortcut (see
/// [`crate::provider_confidence`]), and exactly one because a per-candidate
/// transaction would serialize N writer-lock acquisitions per mention and let
/// the ranking span N different views of the vault. Nothing is minted: the
/// provisional route selects nothing, creates no entity, and performs no
/// topology merge.
///
/// # Errors
///
/// * [`Error::InvalidClaimBody`] when a candidate's confidence CLAIM does not
///   have that candidate as its subject, when the CLAIM is not currently
///   effective, when either subject lacks exactly one canonical Active head,
///   or when it fails the shared `provider.enrichment` structural validator.
///   Surfaceable claims that fail `claim_consolidatable` are excluded and counted,
///   not errors.
/// * The underlying read error otherwise.
///
/// [`Error::InvalidClaimBody`]: crate::error::Error::InvalidClaimBody
pub fn evaluate_entity_resolution_waterfall(
    vault: &crate::Vault,
    candidates: &[EntityResolutionCandidate],
    high_collision_mention: bool,
) -> crate::Result<EntityResolutionWaterfallDecision> {
    let (mut ranked, claims_suppressed) = vault.with_write_txn(|wtxn| {
        // Topology cannot change during scoring. Fold the zero-head-shell
        // witness once, not once for each candidate and claim subject.
        let zero_head_shells = vault.zero_head_split_shells_in_txn(&*wtxn)?;
        // Prior truth cannot change during scoring. Reuse each provider's
        // resolution (including absence) only for this transaction.
        let mut prior_memo = crate::provider_confidence::ProviderPriorMemo::default();
        let mut scored = Vec::with_capacity(candidates.len());
        let mut claims_suppressed = 0;
        for candidate in candidates {
            let body = vault
                .get_claim_in_txn(&*wtxn, &candidate.confidence_claim_ref)?
                .ok_or(crate::error::Error::EntityNotFound)?;
            // The candidate and its evidence must be the same assertion.
            // A claim about some OTHER subject scoring this one would let a
            // caller borrow an unrelated provider's confidence.
            let subject = canonical_waterfall_subject_in_txn(
                vault,
                &*wtxn,
                &candidate.subject,
                &zero_head_shells,
            )?;
            let claim_subject = match body.subject {
                ClaimSubject::Entity(id) => {
                    canonical_waterfall_subject_in_txn(vault, &*wtxn, &id, &zero_head_shells)?
                }
                _ => {
                    return Err(crate::error::Error::InvalidClaimBody(
                        "waterfall candidate subject does not match confidence claim subject",
                    ));
                }
            };
            if subject != claim_subject {
                return Err(crate::error::Error::InvalidClaimBody(
                    "waterfall candidate subject does not match confidence claim subject",
                ));
            }
            // Same surfaceability the claim read path uses: rejected,
            // retracted/superseded, and stale claims are CLOSED history and
            // may not route a live mention.
            if !crate::claim::claim_surfaceable(&body) {
                return Err(crate::error::Error::InvalidClaimBody(
                    "waterfall confidence claim is not active",
                ));
            }
            crate::provider_confidence::validate_provider_enrichment_claim_structure(&body)?;
            if !crate::claim::claim_consolidatable(&body) {
                claims_suppressed += 1;
                continue;
            }
            // The EFFECTIVE confidence, never the stored column: a claim's
            // own number says how sure its provider was, not how much this
            // vault has learned to trust that provider.
            let effective_confidence = crate::provider_confidence::effective_confidence_in_txn(
                vault,
                wtxn,
                &candidate.confidence_claim_ref,
                &mut prior_memo,
            )?;
            scored.push(ScoredEntityResolutionCandidate {
                candidate: EntityResolutionCandidate {
                    subject,
                    confidence_claim_ref: candidate.confidence_claim_ref,
                },
                effective_confidence,
            });
        }
        Ok((scored, claims_suppressed))
    })?;

    // Total and deterministic: effective confidence descending, then subject
    // ascending, then claim id ascending. The tiebreakers are what make two
    // devices ranking the same set agree.
    ranked.sort_by(|left, right| {
        right
            .effective_confidence
            .total_cmp(&left.effective_confidence)
            .then_with(|| left.candidate.subject.cmp(&right.candidate.subject))
            .then_with(|| {
                left.candidate
                    .confidence_claim_ref
                    .cmp(&right.candidate.confidence_claim_ref)
            })
    });

    let top = ranked.first().copied();
    let top_effective = top.map_or(0.0, |scored| scored.effective_confidence);
    let route = if top.is_none() || top_effective < 0.50 {
        EntityResolutionRoute::ProvisionalEntity
    } else if top_effective < 0.70 {
        EntityResolutionRoute::SoftLinkLow
    } else if top_effective < 0.90 {
        EntityResolutionRoute::SoftLink
    } else {
        EntityResolutionRoute::HardLink
    };
    let requires_async_verification = match route {
        // A hard link is confident enough to stand alone — EXCEPT over a
        // high-collision mention, where the score is confident about a surface
        // form many referents share.
        EntityResolutionRoute::HardLink => high_collision_mention,
        EntityResolutionRoute::SoftLink | EntityResolutionRoute::SoftLinkLow => true,
        EntityResolutionRoute::ProvisionalEntity => false,
    };
    let (selected, selected_effective_confidence) = match route {
        EntityResolutionRoute::ProvisionalEntity => (None, None),
        _ => (
            top.map(|scored| scored.candidate.subject),
            Some(top_effective),
        ),
    };

    Ok(EntityResolutionWaterfallDecision {
        ranked,
        claims_suppressed,
        selected,
        selected_effective_confidence,
        route,
        requires_async_verification,
    })
}

fn canonical_waterfall_subject_in_txn(
    vault: &crate::Vault,
    rtxn: &heed::RoTxn<'_>,
    subject: &EntityId,
    zero_head_shells: &std::collections::BTreeSet<EntityId>,
) -> crate::Result<EntityId> {
    let heads = vault.resolve_entity_in_txn(rtxn, subject)?;
    if let [head] = heads.as_slice()
        && vault.get_entity_type_in_txn(rtxn, head)?.is_some()
        && vault.entity_lifecycle_state_with_zero_head_shells_in_txn(
            rtxn,
            head,
            Some(zero_head_shells),
        )? == crate::identity_topology::EntityLifecycleState::Active
    {
        return Ok(*head);
    }
    Err(crate::error::Error::InvalidClaimBody(
        "waterfall candidate subject is not a canonical active entity",
    ))
}
