//! The one-candidate promotion writer and its landed re-read. A refusal
//! keeps the reason text its outcome has always carried, and the kind of
//! the engine error behind it when one refused it (FIX 7271), so the scoped
//! sink logs a kind and never the text. A gate's refusal also keeps the
//! gate's own outcome and reason codes (FIX 10355), so the sink's one error
//! and the log name why the gate refused.

use super::*;
use crate::dreamer_consolidation::evidence::ResolvedConflictOutput;
use crate::error::{ErrorKind, GateError};

/// A gate refusal's outcome and reason codes, as the gate wrote them: static
/// codes, never the candidate's text (FIX 10355).
pub(super) type GateCodes = (&'static str, Vec<&'static str>);

/// The outcome and reason codes of `error` when the gate refused the write.
pub(super) fn gate_codes(error: &Error) -> Option<GateCodes> {
    match error {
        Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => Some((*outcome, reason_codes.clone())),
        _ => None,
    }
}

/// Why one candidate was not written: the reason its outcome keeps, the
/// kind of the engine error that refused it, and the gate's codes when the
/// gate refused it. A structural guard's refusal has no kind; none is read
/// back out of text.
#[derive(Debug)]
pub(super) struct PromotionRejection {
    pub(super) reason: String,
    pub(super) kind: Option<ErrorKind>,
    pub(super) gate: Option<GateCodes>,
}

impl PromotionRejection {
    /// A structural guard's refusal: its text only.
    fn guard(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            kind: None,
            gate: None,
        }
    }

    /// An engine error's refusal, its text as the outcome carried it.
    pub(super) fn engine(error: Error) -> Self {
        Self {
            kind: Some(error.kind()),
            gate: gate_codes(&error),
            reason: error.to_string(),
        }
    }

    /// An engine error's refusal behind `context`: `"{context}: {error}"`.
    fn engine_in(context: &str, error: Error) -> Self {
        Self {
            kind: Some(error.kind()),
            gate: gate_codes(&error),
            reason: format!("{context}: {error}"),
        }
    }

    /// A read transaction the store did not open: the store's own text, and
    /// the kind the engine error it converts to carries.
    fn store(error: heed::Error) -> Self {
        let reason = error.to_string();
        Self {
            reason,
            kind: Some(Error::from(error).kind()),
            gate: None,
        }
    }

    /// Records this refusal of `id` in `outcome`: its kind and gate codes
    /// when it carries them, then its reason.
    pub(super) fn record(self, id: EntityId, outcome: &mut PromotionOutcome) {
        if let Some(kind) = self.kind {
            outcome.rejected_kinds.push((id, kind));
        }
        if let Some((gate_outcome, reason_codes)) = self.gate {
            outcome.rejected_gates.push((id, gate_outcome, reason_codes));
        }
        outcome.rejected.push((id, self.reason));
    }
}

/// One candidate: evidence admission → envelope → taint (incl. E1 fold) →
/// one wtxn (claim + optional supersession) → landed verification.
/// Returns the landed approval lane, or a typed rejection reason.
pub(super) fn promote_one(
    vault: &Vault,
    run: &DreamerRunContext,
    candidate: PromotionCandidate,
    checker: Option<&BoundedAutoChecker>,
    fence: Option<&crate::dreamer_consolidation::resources::ConsolidationFence>,
    verified: Option<&VerifiedEvidenceSet>,
) -> std::result::Result<ClaimApprovalStatus, PromotionRejection> {
    promote_one_answering(vault, run, candidate, checker, fence, verified, &[])
}

/// [`promote_one`] for an output that answers the open markers `answers`
/// name: its provenance keeps each binding, so a replay that meets it again
/// still closes them (FIX 7325). With none, its provenance is as before.
pub(super) fn promote_one_answering(
    vault: &Vault,
    run: &DreamerRunContext,
    candidate: PromotionCandidate,
    checker: Option<&BoundedAutoChecker>,
    fence: Option<&crate::dreamer_consolidation::resources::ConsolidationFence>,
    verified: Option<&VerifiedEvidenceSet>,
    answers: &[&ResolvedConflictOutput],
) -> std::result::Result<ClaimApprovalStatus, PromotionRejection> {
    // A blank run would hide the write from every Dreamer-run reader: the
    // gate's imported floor and the owner's review grouping among them.
    if run.run_id.trim().is_empty() {
        return Err(PromotionRejection::guard("promotion run id is blank"));
    }
    // An earlier pass of this attempt committed this claim into the owner's
    // review: a crash before the attempt completed, or a held selection's
    // retry. It stays as the review holds it or the owner left it; writing it
    // again would refuse the attempt.
    if crate::dreamer_consolidation::reviewed::reviewed_output(vault, &candidate)
        .map_err(|error| PromotionRejection::engine_in("committed output read failed", error))?
    {
        return Ok(ClaimApprovalStatus::Proposed);
    }
    let public_refs = public_evidence_refs(candidate.candidate.evidence())
        .map_err(|error| PromotionRejection::engine_in("invalid document evidence", error))?;
    let pinned_sources = {
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(PromotionRejection::store)?;
        public_refs
            .iter()
            .map(|reference| {
                crate::entity_doc::promotion_evidence_source_in_txn(vault, &txn, reference)
            })
            .collect::<Result<Vec<_>>>()
            .map_err(|error| PromotionRejection::engine_in("document evidence refused", error))?
    };
    let default_facet = vault
        .default_facet()
        .map_err(|error| PromotionRejection::engine_in("default facet read failed", error))?;
    // 1. Evidence admission (GATE-11 write-path consumption): drop refs
    // resolving to evidence-inadmissible CLAIM entities and refs that do
    // not resolve at all; zero survivors is a typed rejection.
    let mut surviving: Vec<EntityId> = Vec::new();
    let mut dropped: Vec<EntityId> = Vec::new();
    for entry in &candidate.evidence_turn_refs {
        match evidence_ref_admissible(vault, entry) {
            Ok(true) => surviving.push(*entry),
            Ok(false) => dropped.push(*entry),
            Err(error) => {
                return Err(PromotionRejection::engine_in(
                    "evidence resolution failed",
                    error,
                ));
            }
        }
    }
    if verified.is_some_and(|evidence| evidence.refs() != surviving) {
        return Err(PromotionRejection::guard(
            "scoped evidence differs from verified parent refs",
        ));
    }
    if pinned_sources
        .iter()
        .any(|source| !surviving.contains(source))
    {
        return Err(PromotionRejection::guard(
            "document citation has no admissible source ref",
        ));
    }
    if surviving.is_empty() {
        let mut reason = "no admissible evidence refs".to_owned();
        if !dropped.is_empty() {
            reason.push_str(&format!(
                " (dropped {} inadmissible/unresolvable refs)",
                dropped.len()
            ));
        }
        return Err(PromotionRejection::guard(reason));
    }

    // 2. Source (§3) — COMPUTED, never chosen. The candidate's evidence meet
    // folds with any superseded head's taint (the E1 supersession fold: a
    // tainted head superseded by a clean candidate keeps its taint — no
    // laundering), and the result becomes BOTH the envelope source and the
    // engine-owned taint stamp.
    let old_head_taint = match candidate.supersedes.as_ref() {
        Some(old_id) => vault
            .get_claim(old_id)
            .map_err(|error| PromotionRejection::engine_in("supersedes head read failed", error))?
            .as_ref()
            .and_then(claim_evidence_taint),
        None => None,
    };
    // ARCH-0027 trust tier: imported material never auto-approves. Evidence
    // on an imported TURN makes the claim `Imported` whatever meet a caller
    // computed, and its claim lands Proposed in the review of the import its
    // cited words came from.
    let import = {
        let cited = verified.map(VerifiedEvidenceSet::cited_messages);
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(PromotionRejection::store)?;
        crate::ingest::history::imported_evidence_in_txn(
            vault,
            &txn,
            &surviving,
            cited.as_deref().unwrap_or_default(),
        )
        .map_err(|error| PromotionRejection::engine_in("imported evidence read failed", error))?
    };
    let computed_meet = effective_evidence_source(
        verified.map_or(candidate.evidence_meet, VerifiedEvidenceSet::meet),
        old_head_taint,
    );
    let computed_meet = if import.imported {
        ClaimSource::Imported
    } else {
        computed_meet
    };
    let source = computed_meet;
    let imported = source == ClaimSource::Imported;
    let import_review = import.review.filter(|_| imported);

    // 3. Envelope — constructed HERE; callers cannot pass one. Provenance
    // keeps exactly the shape dreamer_run_id_from_provenance parses and
    // gains the typed lineage only when there is one, so a candidate with no
    // external chain writes byte-identical provenance to before.
    // ONE-1314: the consolidation writer KNOWS its own history — a Dreamer run
    // generated this claim, and the computed meet says what the evidence under
    // it was tainted by. A tainted meet therefore rides as lineage alongside
    // the generative hop, so the auto lane sees the whole history rather than
    // the single folded label. An untainted candidate's meet is `Generated`
    // (the consolidation lattice only ever meets DOWN from it), so its lineage
    // is trivial and its evidence is byte-identical to before.
    let lineage = match source {
        ClaimSource::ToolOutput | ClaimSource::Imported => {
            SourceLineage::of(ClaimSource::Generated).with(source)
        }
        _ => SourceLineage::of(ClaimSource::Generated),
    };
    let mut envelope = WriteEnvelope::with_lineage(
        run.agent_actor,
        source,
        WriteProvenance::new(super::resolved_outputs::with_answers(
            promotion_provenance(
                run,
                &candidate.provenance_chain,
                import_review.as_deref(),
                &candidate.decisions,
            )
            .map_err(PromotionRejection::engine)?,
            answers,
        ))
        .map_err(PromotionRejection::engine)?,
        // Auto for every native candidate (ARCH-0067 §7). The gate may still
        // refuse; it may never turn this into an owner-review row.
        ClaimApprovalStatus::Auto,
        lineage,
    );

    let is_conflict_marker =
        candidate.candidate.predicate() == crate::claim::PREDICATE_CONFLICT_OPEN;
    if candidate.supersedes.is_some() || is_conflict_marker || imported {
        envelope = WriteEnvelope::with_lineage(
            envelope.actor(),
            source,
            envelope.provenance().clone(),
            ClaimApprovalStatus::Proposed,
            envelope.lineage().clone(),
        );
    }

    // Rule A: the claim is concluded from the evidence that survived
    // admission, the head it supersedes and the MESSAGEs its evidence cites,
    // every one of them, taken before `surviving` moves.
    let birth = {
        let cited = verified
            .map(VerifiedEvidenceSet::cited_messages)
            .unwrap_or_default();
        let inputs: Vec<EntityId> = surviving
            .iter()
            .chain(&candidate.supersedes)
            .chain(&cited)
            .copied()
            .collect();
        RowBirth::written(
            run.agent_actor,
            MadeByClass::Concluded,
            "dreamer.promotion",
            &inputs,
            &[],
            candidate.learned_at,
        )
    };

    // Surviving evidence + the typed chain + the computed meet ride the
    // candidate's structured evidence payload: the envelope evidence map's
    // candidate_evidence entry that GATE-12's evidence floor reads, and the
    // machine-readable record of WHICH answer TURN and consult TASK the
    // claim descends from. `refs` is exactly the post-admission survivors.
    let mut evidence_value = if let Some(verified) = verified {
        verified
            .clone()
            .restrict(source)
            .envelope(candidate.provenance_chain.clone())
    } else {
        encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
            refs: surviving,
            chain: candidate.provenance_chain.clone(),
            source_meet: source,
        })
    };

    if !public_refs.is_empty() {
        let Value::Map(fields) = &mut evidence_value else {
            return Err(PromotionRejection::guard("promotion evidence is not a map"));
        };
        fields.push((
            Value::from("evidence_refs"),
            public_evidence_value(&public_refs).map_err(PromotionRejection::engine)?,
        ));
    }

    // `ClaimCandidate` exposes no scope accessor, so the probe body is how
    // the writer reads the candidate's own scope before re-stamping it.
    let probe_body = candidate
        .candidate
        .clone()
        .into_claim_body(&envelope, default_facet)
        .map_err(PromotionRejection::engine)?;
    let mut scope = scope_with_taint(probe_body.scope.clone(), source);
    // OF-492: a claim from a later import of a topic the owner answered is
    // born into the audience they chose, before it is signed. Conflict
    // bookkeeping keeps its marker's project.
    if let Some(review) = import_review.as_deref().filter(|_| {
        !is_conflict_marker && probe_body.predicate != crate::claim::PREDICATE_CONFLICT_RESOLVED
    }) {
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(PromotionRejection::store)?;
        scope = crate::federation::record_scope::stamp_import_audience_birth(
            vault, &txn, scope, review,
        )
        .map_err(|error| PromotionRejection::engine_in("import audience read failed", error))?;
    }
    let prospective_queries = candidate.candidate.lexical_hints().to_vec();
    let claim_candidate = candidate
        .candidate
        .with_evidence(evidence_value)
        // Stamped for EVERY consolidation claim, not only the tainted
        // classes (§4): the central lineage guard compares src against this
        // key, so leaving it absent would leave a claim whose lineage
        // nothing can check.
        .with_scope(scope);

    // Defence in depth (§5): the runtime validator at the write chokepoint
    // is authoritative; this catches an internal regression that lets the
    // encoded source drift above the computed meet in debug/test builds.
    debug_assert!(!claim_source_widens_beyond(
        claim_candidate
            .clone()
            .into_claim_body(&envelope, default_facet)
            .map_err(PromotionRejection::engine)?
            .source
            .expect("consolidation envelope must stamp a source"),
        computed_meet
    ));
    // The Dreamer is a MACHINE writer: its host-held key signs the exact
    // candidate the write door below admits.
    {
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(PromotionRejection::store)?;
        vault
            .sign_retained_machine_claim_in_txn(
                &txn,
                &candidate.claim_id,
                &claim_candidate,
                &mut envelope,
            )
            .map_err(PromotionRejection::engine)?;
    }

    // 4. ONE wtxn: the proposed claim and its deferred closure binding
    // commit or roll back together; the prior stays active until later grant.
    // GATE-007 (Generated over UserStated) is rechecked on closure.
    // Read on the calling thread: a grouped commit may run the closure elsewhere.
    let auto_write_rate = crate::own_rate::auto_write_rate();
    // The claim's bytes before this write, read in its own transaction: an
    // exact replay of a claim that already stands Auto lands nothing new, so
    // it counts nothing.
    let prior = std::cell::RefCell::new(None);
    let read_prior = |txn: &heed::RoTxn<'_>| -> crate::Result<()> {
        *prior.borrow_mut() =
            crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &candidate.claim_id)?;
        Ok(())
    };
    let finish_promotion = |wtxn: &mut heed::RwTxn<'_>| {
        crate::entity_doc::verify_promotion_evidence_in_txn(vault, wtxn, &public_refs)?;
        if let Some(fence) = fence {
            fence.validate_in_txn(vault, wtxn)?;
        }
        if let Some(old_id) = candidate.supersedes.as_ref() {
            vault.stage_claim_supersession_in_txn(
                wtxn,
                &candidate.claim_id,
                old_id,
                &envelope,
                run.now_ms,
            )?;
        }
        // Failed apply or stage rolls back the claim, binding and gate receipt.
        // Checker refusals never reach this callback: preflight commits only
        // the rejection receipt, with no claim or pending-consent row.
        // The already-stored answer TURN never shared this transaction.
        let landed =
            vault
                .get_claim_in_txn(&*wtxn, &candidate.claim_id)?
                .ok_or(Error::InvalidClaimBody(
                    "consolidation claim is missing inside its own write transaction",
                ))?;
        // Never Auto, and never Proposed where no review holds it.
        if imported
            && (landed.approval == ClaimApprovalStatus::Auto
                || store_pending_group(vault, wtxn, &candidate.claim_id)?.is_none())
        {
            return Err(Error::InvalidClaimBody(
                "a claim from imported evidence lands only in an owner review",
            ));
        }
        if landed.approval != ClaimApprovalStatus::Auto
            && candidate.supersedes.is_none()
            && !is_conflict_marker
            && !imported
        {
            return Err(Error::InvalidClaimBody(
                "consolidation write was not granted Auto; no approval queue is created",
            ));
        }
        // An Auto write counts on the agent's own-rate window. Its first
        // crossing leaves a typed check; the write itself stays Auto.
        let replayed = match prior.borrow().as_deref() {
            Some(before) => {
                crate::ports::EntityStoreRead::port_entity_raw(
                    &vault.store,
                    wtxn,
                    &candidate.claim_id,
                )?
                .as_deref()
                    == Some(before)
            }
            None => false,
        };
        if landed.approval == ClaimApprovalStatus::Auto && !replayed {
            crate::own_rate::count_in_txn(
                &vault.store,
                wtxn,
                crate::own_rate::OwnRateKind::AutoWrite,
                run.agent_actor.entity_ref(),
                vault.store.clock.now_recorded_at(),
                auto_write_rate,
            )?;
            #[cfg(test)]
            crate::own_rate::counted_auto_write(crate::own_rate::AutoWriteDoor::Promotion);
            // A landed finding reaches its owner's inbox in the same
            // transaction; a pended or refused one never does.
            if let crate::claim::ClaimSubject::Entity(subject) = landed.subject {
                vault.record_finding_notification_in_txn(
                    wtxn,
                    candidate.claim_id,
                    subject,
                    run.now_ms,
                )?;
            }
        }
        // Both write paths reach here; a replayed attempt keeps the claim's
        // first birth.
        if let Some(birth) = &birth {
            crate::provenance::birth::stamp_birth_if_absent_in_txn(
                &vault.store,
                wtxn,
                &candidate.claim_id,
                birth,
            )?;
        }
        // The MESSAGE words the evidence names become this claim's
        // dependencies in the claim's own transaction.
        match verified {
            Some(evidence) => {
                evidence.record_message_dependencies_in_txn(vault, wtxn, &candidate.claim_id)?;
                crate::dreamer_consolidation::strength::record_verified_in_txn(
                    vault,
                    wtxn,
                    candidate.claim_id,
                    evidence,
                    run.now_ms,
                )
            }
            None => Ok(()),
        }
    };
    // A signed (MACHINE) promotion carries no lexical query hints (FIX 11356):
    // a hint is a stale side CLAIM, and a machine claim birth refuses every
    // stale birth (claim/machine_birth.rs), so a hint would fail the whole
    // candidate. The belief itself still lands.
    let hints: Vec<&str> = if envelope.machine_signature().is_some() {
        Vec::new()
    } else {
        prospective_queries.iter().map(String::as_str).collect()
    };
    // The checker's turn, waited for here, before the batch announces its
    // write (FIX 8751, 8701): the gate inside never waits for capacity.
    let checker = checker
        .map(|checker| checker.admit_for_writes(&vault.store, run.agent_actor.entity_ref()))
        .transpose()
        .map_err(|error| PromotionRejection::engine_in("checker admission failed", error))?;
    let write = if let Some(checker) = checker.as_ref() {
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &candidate.claim_id,
                claim_candidate,
                &envelope,
                candidate.occurred,
                candidate.learned_at,
                &hints,
            )
            .commit_with_checker_guard_and_then(checker, read_prior, finish_promotion)
    } else {
        // Preserve the original single-pass transaction for every None caller.
        vault.with_write_txn_grouped(|wtxn| {
            read_prior(wtxn)?;
            vault
                .batch_in()
                .claim_candidate_with_lexical_hints(
                    &candidate.claim_id,
                    claim_candidate,
                    &envelope,
                    candidate.occurred,
                    candidate.learned_at,
                    &hints,
                )
                .apply_recording_gate_decisions(wtxn)?;
            finish_promotion(wtxn)
        })
    };
    if let Err(error) = write {
        return Err(PromotionRejection::engine_in("gated write rejected", error));
    }

    // 5. Post-commit landed verification (Hermes gate 9c): re-read and check
    // predicate, source, and taint. A failure cannot roll back the committed
    // writes; it rejects the candidate, and the caller must not complete the attempt.
    verify_landed(vault, &candidate.claim_id, &probe_body.predicate, source)
}

/// Re-reads a landed claim and checks it is the claim we wrote. A missing
/// or mismatched read moves the candidate to `rejected`. The source is
/// compared against the COMPUTED meet the writer stamped — never a
/// hardcoded class.
pub(super) fn verify_landed(
    vault: &Vault,
    claim_id: &EntityId,
    expected_predicate: &str,
    expected_source: ClaimSource,
) -> std::result::Result<ClaimApprovalStatus, PromotionRejection> {
    let Some(body) = vault
        .get_claim(claim_id)
        .map_err(|error| PromotionRejection::engine_in("landed verification read failed", error))?
    else {
        return Err(PromotionRejection::guard(
            "landed verification failed: claim missing after commit",
        ));
    };
    if body.predicate != expected_predicate {
        return Err(PromotionRejection::guard(
            "landed verification failed: predicate mismatch",
        ));
    }
    if body.source != Some(expected_source) {
        return Err(PromotionRejection::guard(
            "landed verification failed: source stamp mismatch",
        ));
    }
    if claim_evidence_taint(&body) != Some(expected_source) {
        return Err(PromotionRejection::guard(
            "landed verification failed: evidence taint stamp mismatch",
        ));
    }
    Ok(body.approval)
}
