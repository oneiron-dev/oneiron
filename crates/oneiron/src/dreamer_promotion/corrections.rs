//! A correction the Dreamer stages, settled in the pass that staged it.
//!
//! A replacement takes its Auto grant through the deferred door when the
//! vault's policy allows it; the grant closes its named prior in the same
//! transaction. One the policy protects (a class a manifest rule declares
//! critical, attributed truth, a Gate that pends, the Generated-over-UserStated
//! guard) is never applied here: it stays Proposed in the owner's run review. Once the prior is closed, each
//! open conflict that named it closes through the conflict-close door.
use std::collections::BTreeSet;

use super::*;
use crate::claim::{ClaimLifecycleStatus, PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED};
use crate::dreamer_consolidation::resources::{ConsolidationFence, RowRevision};
use crate::dreamer_consolidation::{conflict_close_candidate, marker_ids as ids_at};
use crate::edge::EdgeKind;
use crate::registry::ENTITY_TYPE_CLAIM;

/// Grants `replacement` when the policy allows it, returning the prior the
/// grant closed. Anything else leaves it Proposed for the owner.
pub(super) fn grant_allowed_replacement(
    vault: &Vault,
    run: &DreamerRunContext,
    fence: &ConsolidationFence,
    replacement: EntityId,
    checker: Option<&BoundedAutoChecker>,
) -> Option<EntityId> {
    let prior = match vault.pending_claim_supersession(&replacement) {
        Ok(prior) => prior?,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), replacement = %replacement.to_hex(), "a staged replacement could not be read");
            return None;
        }
    };
    // The prior as the grant left it, read in the grant's own transaction:
    // the handoff's later writes hold it to that revision.
    let mut closed_at = None;
    let original = std::cell::Cell::new(None);
    match vault.grant_deferred_claim_auto_after(
        &replacement,
        run.now_ms,
        checker,
        |txn| {
            fence.validate_in_txn(vault, txn)?;
            original.set(fence.root_close_revision(vault, txn, prior)?);
            Ok(())
        },
        |txn| {
            fence.record_root_close_in_txn(vault, txn, prior, replacement, original.take())?;
            closed_at = RowRevision::read_in(vault, txn, &prior)?;
            Ok(())
        },
    ) {
        Ok(()) => {
            if let Some(revision) = closed_at {
                fence.closed_by_this_write(prior, revision);
            }
            Some(prior)
        }
        // The policy protects it; the owner's run review holds it.
        Err(error @ Error::Gate(_)) => {
            tracing::info!(target: "oneiron::dreamer", kind = ?error.kind(), replacement = %replacement.to_hex(), "a staged replacement is held for the owner");
            None
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), replacement = %replacement.to_hex(), "a staged replacement was not granted; it stays in the owner's review");
            None
        }
    }
}

/// The prior this attempt's own correction closed, when an earlier pass
/// already landed it with its grant and died before the attempt completed:
/// the claim at the candidate's id says what the candidate says, is Auto,
/// and supersedes a prior. A replay meets it again with no prior left to
/// route to, so it is not written twice.
pub(super) fn granted_correction(
    vault: &Vault,
    candidate: &PromotionCandidate,
) -> Result<Option<EntityId>> {
    if vault.get_entity_type(&candidate.claim_id)? != Some(ENTITY_TYPE_CLAIM) {
        return Ok(None);
    }
    let Some(stored) = vault.get_claim(&candidate.claim_id)? else {
        return Ok(None);
    };
    if stored.approval != ClaimApprovalStatus::Auto
        || !crate::dreamer_consolidation::reviewed::names_candidate(candidate, &stored)?
    {
        return Ok(None);
    }
    superseded_prior(vault, candidate.claim_id)
}

/// The prior `head` closed, when `head` is a granted replacement.
pub(super) fn superseded_prior(vault: &Vault, head: EntityId) -> Result<Option<EntityId>> {
    Ok(vault
        .edges_out(&head)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Supersedes)
        .map(|edge| edge.target))
}

/// Closes each open conflict on `replacement`'s subject that named `prior`
/// on `replacement`'s own world, facet, relationship and project, citing
/// `evidence` and recording `replacement` as its resolution. Each close is
/// written under the handoff's `fence`. A marker a standing resolution
/// already answers is left as it is, so a replay closes nothing twice; a
/// proposed, refused, closed or stale one answers nothing. A replacement that
/// no longer stands (retracted, closed or stale since it landed, as a replay
/// meets it) answers nothing either.
pub(super) fn close_conflicts_naming(
    vault: &Vault,
    run: &DreamerRunContext,
    fence: &ConsolidationFence,
    replacement: EntityId,
    prior: EntityId,
    evidence: &[EntityId],
) -> Result<()> {
    // One snapshot where the scan took several: the standing, the revision
    // and the subject sweep all read in the one read below. The read ends
    // with the scan: each close below opens its own read and then a write,
    // and this store allows one read transaction a thread.
    let scan = {
        let txn = vault.store.env.read_txn()?;
        open_markers_naming_in_txn(vault, &txn, replacement, prior)?
    };
    let Some((revision, open)) = scan else {
        return Ok(());
    };
    let resolution = Value::Map(vec![(
        Value::from("superseded_by"),
        Value::Binary(replacement.as_bytes().to_vec()),
    )]);
    fence.relies_on(replacement, revision);
    for marker in open {
        // A marker this close cannot land stays open, and in the owner's
        // view; the correction itself has landed.
        // Logged by a closed name and its error's kind, never its text: a
        // refusal's text can quote the vault (FIX 7368).
        let refused = match conflict_close_candidate(
            vault,
            run,
            marker,
            resolution.clone(),
            evidence.to_vec(),
        ) {
            Ok(close) => match promote_one(vault, run, close, None, Some(fence), None) {
                Ok(ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed) => None,
                Ok(other) => Some((other.as_str(), None)),
                Err(rejection) => Some(("promotion_refused", rejection.kind)),
            },
            Err(error) => Some(("no_close_candidate", Some(error.kind()))),
        };
        if let Some((reason, kind)) = refused {
            tracing::warn!(reason, error_kind = ?kind, marker = %marker.to_hex(), "an open conflict the correction answered stayed open");
        }
    }
    // The handoff's later writes do not stand on it.
    fence.released(replacement);
    Ok(())
}

/// The replacement's revision with the open markers a standing resolution
/// does not answer, in the caller's read `txn`: the standing and revision
/// from one read, then the subject sweep for open markers on the
/// replacement's axes that name `prior`, minus the markers a standing
/// `conflict.resolved` already answers. `None` when the replacement does not
/// stand (missing, unrevised, unsurfaced, or of no entity subject).
fn open_markers_naming_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    replacement: EntityId,
    prior: EntityId,
) -> Result<Option<(RowRevision, Vec<EntityId>)>> {
    // Its standing and revision come from one read; each close's fence then
    // refuses once the replacement changes or no longer reads. (A replacement
    // that does not stand would be refused by that fence too; this skips the
    // attempts.)
    let body = vault.get_claim_for_effect_in_txn(txn, &replacement)?;
    let revision = RowRevision::read_in(vault, txn, &replacement)?;
    let (Some(body), Some(revision)) = (body, revision) else {
        return Ok(None);
    };
    if !crate::claim::claim_surfaceable(&body) {
        return Ok(None);
    }
    let crate::claim::ClaimSubject::Entity(subject) = body.subject else {
        return Ok(None);
    };
    let mut open = Vec::new();
    let mut resolved = BTreeSet::new();
    for id in vault.claims_for_subject_in_txn(txn, &subject)? {
        let Some(claim) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if claim.predicate == PREDICATE_CONFLICT_RESOLVED {
            if crate::claim::claim_surfaceable(&claim) {
                resolved.extend(ids_at(&claim.value, "open_marker"));
            }
        } else if claim.predicate == PREDICATE_CONFLICT_OPEN
            && claim.lifecycle == ClaimLifecycleStatus::Active
            && same_axes(&claim, &body)
            && ids_at(&claim.value, "prior_head")
                .chain(ids_at(&claim.value, "prior_heads"))
                .any(|named| named == prior)
        {
            open.push(id);
        }
    }
    open.retain(|marker| !resolved.contains(marker));
    Ok(Some((revision, open)))
}

/// Grants `replacement` when the policy allows it, in the caller's write
/// `txn`, returning the prior the grant closed with the two gate receipts
/// for the caller to count after its write commits. Anything else leaves it
/// Proposed for the owner. Three differences from [`grant_allowed_replacement`]:
/// the caller's transaction with a nested savepoint for the grant alone; a
/// store error aborts the commit instead of holding; no checker (the stager
/// passes `None`, as the ordinary owner-less auto grant does).
///
/// # Errors
///
/// The store's. A gate refusal or a claim-domain error aborts only the
/// nested grant savepoint and answers `(None, [])`, with the replacement
/// staying Proposed with its staged supersession for the owner, as native
/// holds it.
pub(crate) fn grant_allowed_replacement_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &DreamerRunContext,
    fence: &ConsolidationFence,
    replacement: EntityId,
) -> Result<(
    Option<EntityId>,
    Vec<crate::gate::RecordedClaimGateDecision>,
)> {
    let prior = vault.pending_claim_supersession_in_txn(txn, &replacement)?;
    let Some(prior) = prior else {
        return Ok((None, Vec::new()));
    };
    // The prior as the grant left it, read in the grant's own savepoint:
    // the handoff's later writes hold it to that revision.
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let granted: Result<(
        Option<crate::gate::RecordedClaimGateDecision>,
        Option<crate::gate::RecordedClaimGateDecision>,
        Option<RowRevision>,
    )> = (|| {
        fence.validate_in_txn(vault, &savepoint)?;
        let original = fence.root_close_revision(vault, &savepoint, prior)?;
        // The own-rate read as the e2g.2 G7 settled it for `prepare_promotion`:
        // inside, on the grouped thread, as the Evidence stager does.
        let auto_write_rate = crate::own_rate::auto_write_rate();
        let (decision, closure) = vault.grant_deferred_claim_auto_after_in_txn(
            &mut savepoint,
            &replacement,
            run.now_ms,
            None,
            auto_write_rate,
        )?;
        fence.record_root_close_in_txn(vault, &mut savepoint, prior, replacement, original)?;
        let closed_at = RowRevision::read_in(vault, &savepoint, &prior)?;
        Ok((decision, closure, closed_at))
    })();
    match granted {
        Ok((decision, closure, closed_at)) => {
            savepoint.commit()?;
            if let Some(revision) = closed_at {
                fence.closed_by_this_write(prior, revision);
            }
            let receipts = [decision, closure].into_iter().flatten().collect();
            Ok((Some(prior), receipts))
        }
        Err(error @ (Error::Gate(_) | Error::Claim(_) | Error::InvalidClaimBody(_))) => {
            savepoint.abort();
            tracing::info!(target: "oneiron::dreamer", kind = ?error.kind(), replacement = %replacement.to_hex(), "a staged replacement is held for the owner");
            Ok((None, Vec::new()))
        }
        Err(error) => {
            savepoint.abort();
            Err(error)
        }
    }
}

/// What [`close_conflicts_naming_in_txn`] closes: the run, the fence, the
/// granted replacement with the prior it closed, the cited evidence and the
/// provenance the closes carry.
pub(crate) struct CloseConflictsRequest<'a> {
    /// The run the closes land under.
    pub(crate) run: &'a DreamerRunContext,
    /// The handoff fence the closes land under.
    pub(crate) fence: &'a ConsolidationFence,
    /// The granted replacement the closes cite as their resolution.
    pub(crate) replacement: EntityId,
    /// The prior the grant closed, which the closed markers named.
    pub(crate) prior: EntityId,
    /// The replacement candidate's cited evidence, which the closes cite.
    pub(crate) evidence: &'a [EntityId],
    /// The provenance the closes carry (derive's, for a derive item).
    pub(crate) provenance: Value,
}

/// Closes each open conflict the scan names, in the caller's write `txn`,
/// each close in its own nested savepoint: the scan on this transaction,
/// `relies_on`, then per marker the in-transaction close builder, the shared
/// preparation with `None` evidence and the caller's provenance, and the
/// shared landing under the fence. A close that is refused aborts its own
/// savepoint, is logged with native's closed reason and the error's kind,
/// never its text, and the loop goes on; a store error aborts the commit.
///
/// What `promote_one` does around the preparation and the landing: the blank
/// run guard is left out (the stager's run id is never blank: the stamp's run
/// or the attempt's hex); the `reviewed_output` early-Proposed check is left
/// out (the scan's resolved filter already skips answered markers, and a
/// derive batch commits once); the own read for the preparation is replaced
/// by the caller's transaction; the checker admission is left out (no
/// checker); the post-commit `verify_landed` is repeated as a read back with
/// `verify_landed_body` inside the savepoint, so a mismatch aborts that
/// close alone instead of rejecting after commit; the stage-line hold is left
/// out (derive keeps no stage line).
///
/// # Errors
///
/// The store's. A refused close never errors: it is logged and skipped.
pub(crate) fn close_conflicts_naming_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &CloseConflictsRequest<'_>,
) -> Result<()> {
    let read_txn: &heed::RoTxn<'_> = txn;
    let Some((revision, open)) =
        open_markers_naming_in_txn(vault, read_txn, request.replacement, request.prior)?
    else {
        return Ok(());
    };
    let resolution = Value::Map(vec![(
        Value::from("superseded_by"),
        Value::Binary(request.replacement.as_bytes().to_vec()),
    )]);
    request.fence.relies_on(request.replacement, revision);
    for marker in open {
        let close = {
            let read_txn: &heed::RoTxn<'_> = txn;
            match crate::dreamer_consolidation::conflict_close_candidate_in_txn(
                vault,
                read_txn,
                request.run,
                marker,
                resolution.clone(),
                request.evidence.to_vec(),
            ) {
                Ok(close) => close,
                Err(error @ (Error::Gate(_) | Error::Claim(_) | Error::InvalidClaimBody(_))) => {
                    tracing::warn!(reason = "no_close_candidate", error_kind = ?error.kind(), marker = %marker.to_hex(), "an open conflict the correction answered stayed open");
                    continue;
                }
                Err(error) => {
                    request.fence.released(request.replacement);
                    return Err(error);
                }
            }
        };
        let mut savepoint = vault.store.env.nested_write_txn(txn)?;
        let (prepared, claim_candidate) = {
            let read_txn: &heed::RoTxn<'_> = &savepoint;
            match super::prepare_promotion(
                vault,
                read_txn,
                request.run,
                close,
                None,
                &[],
                Some(request.provenance.clone()),
            ) {
                Ok(prepared) => prepared,
                Err(rejection) => {
                    savepoint.abort();
                    if rejection.gate.is_some() || rejection.claim_domain {
                        tracing::warn!(reason = "promotion_refused", error_kind = ?rejection.kind, marker = %marker.to_hex(), "an open conflict the correction answered stayed open");
                        continue;
                    }
                    request.fence.released(request.replacement);
                    return Err(Error::Io(std::io::Error::other(format!(
                        "close preparation failed: {:?}",
                        rejection.kind
                    ))));
                }
            }
        };
        if let Err(error) = super::land_prepared_promotion_in_txn(
            vault,
            request.run,
            &prepared,
            claim_candidate,
            Some(request.fence),
            false,
            &mut savepoint,
        ) {
            savepoint.abort();
            match error {
                error @ (Error::Gate(_) | Error::Claim(_) | Error::InvalidClaimBody(_)) => {
                    tracing::warn!(reason = "promotion_refused", error_kind = ?error.kind(), marker = %marker.to_hex(), "an open conflict the correction answered stayed open");
                    continue;
                }
                error => {
                    request.fence.released(request.replacement);
                    return Err(error);
                }
            }
        }
        let stored = {
            let save_read: &heed::RoTxn<'_> = &savepoint;
            vault.get_claim_in_txn(save_read, &prepared.claim_id)?
        };
        let landed = stored.as_ref().and_then(|stored| {
            super::verify_landed_body(stored, &prepared.predicate, prepared.source).ok()
        });
        match landed {
            Some(ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed) => {
                savepoint.commit()?;
            }
            Some(other) => {
                savepoint.abort();
                tracing::warn!(reason = other.as_str(), marker = %marker.to_hex(), "an open conflict the correction answered stayed open");
            }
            None => {
                savepoint.abort();
                tracing::warn!(reason = "promotion_refused", marker = %marker.to_hex(), "an open conflict the correction answered stayed open");
            }
        }
    }
    request.fence.released(request.replacement);
    Ok(())
}

/// Whether `marker` asks its question on `replacement`'s axes. A marker in
/// another world, facet, relationship or project is another branch's, and a
/// facet that does not read is no match.
fn same_axes(marker: &crate::ClaimBody, replacement: &crate::ClaimBody) -> bool {
    let facet = |body: &crate::ClaimBody| {
        crate::dreamer_consolidation::resources::claim_facet(body.scope.as_ref())
    };
    marker.world == replacement.world
        && marker.rel == replacement.rel
        && marker.scope_project == replacement.scope_project
        && matches!((facet(marker), facet(replacement)), (Ok(a), Ok(b)) if a == b)
}
