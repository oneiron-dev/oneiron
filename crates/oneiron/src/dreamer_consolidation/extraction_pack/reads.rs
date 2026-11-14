//! The bound-only rebuild orchestration behind
//! [`rebuild_checked_pack`](super::rebuild_checked_pack): checked candidate rows, native
//! grouping, paging, and the five read plans.
//!
//! Nothing here asks a model or writes a row. Question specs, key parts,
//! state rendering, paging measures and the paging branch all come from the
//! shared builders in their original modules; this module feeds them checked
//! plain rows. Conflict grouping runs the native nomination and the bound
//! route mirror; correction paging labels Claim and Entity rows through a
//! real call map in native order, while question labels stay positional, so
//! both measure the same bytes without any question id.

use std::collections::BTreeMap;

use super::super::branch::BranchAxes;
use super::super::call_labels::{CallLabelMap, LabelKind};
use super::super::conflict::{
    ConflictIdentity, PriorHead, candidate_facts, conflict_open_marker_id, route_bound_priors,
};
use super::super::executor::extraction::corrections::{
    NumberedCorrectionCandidate, NumberedListedClaim, correction_candidate_bytes,
    correction_choice_specs, correction_frame_bytes, correction_listed_bytes,
    group_correction_asks, render_correction_state,
};
use super::super::executor::extraction::{
    CandidateAssemblyInput, ChoiceSpec, ConflictRows, CorrectsPrior, DecisionKeyPart,
    PackRelationship, PartMark, assemble_identity_candidate, claim_id_for_identity,
    conflict_identity_specs, key_part_bytes, key_part_text, page_or_whole, resolution_choice_spec,
    resolution_spans_predicates,
};
use super::super::provenance::PromotionCandidate;
use super::super::routing::judge_queue;
use super::super::settle::decision_pages::{json_len, split_pages};
use super::super::support::invalid_consolidation;
use super::super::value_projection::rmpv_to_json;
use super::BoundBranchRead;
use crate::attempt_queue::AttemptId;
use crate::claim::{ClaimSource, ScopedRead, validate_predicate};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::verbs::{ExtractionPack, ExtractionPart, PackQuestion};
use crate::write_envelope::ClaimCandidate;

/// One pack candidate as the rebuild checked it: its native id, the flat
/// facts correction states read, and the assembled proposal grouping reads.
pub(super) struct CheckedCandidate {
    /// The native deterministic id derived for its operand.
    pub(super) claim_id: EntityId,
    /// The operand subject correction states read.
    pub(super) subject: EntityId,
    /// The operand predicate correction states read.
    pub(super) predicate: String,
    /// The proposed value as JSON text, as correction states show it.
    pub(super) value_text: String,
    /// The branch project its sources share, as the native build stamps it.
    pub(super) project: EntityId,
    /// The assembled proposal with its native id, as nomination routes it.
    pub(super) proposal: PromotionCandidate,
}

/// One listed claim as the rebuild holds it: its id and subject with its
/// predicate and value as the listing writes them.
pub(super) struct CorrectionListed {
    /// The listed claim id.
    pub(super) claim: EntityId,
    /// The subject the listing shows it about.
    pub(super) subject: EntityId,
    /// The predicate as the listing writes it.
    pub(super) predicate: String,
    /// The value as JSON text, as the listing writes it.
    pub(super) value_text: String,
}

/// The pack candidates checked with their eligible pairs and listing: every
/// plan below rebuilds from this projection, never from the job's claims.
pub(super) struct CheckedPack {
    /// The checked candidates, in pack order.
    pub(super) rows: Vec<CheckedCandidate>,
    /// The eligible (candidate position, listed index) pairs, in native order.
    pub(super) pairs: Vec<(usize, usize)>,
    /// The rebuilt listing, in native first-seen order.
    pub(super) listed: Vec<CorrectionListed>,
}

impl CheckedPack {
    /// The derived candidate ids, in pack order.
    pub(super) fn candidate_ids(&self) -> Vec<EntityId> {
        self.rows.iter().map(|row| row.claim_id).collect()
    }

    /// The rebuilt listed claims, in native order.
    pub(super) fn listed_ids(&self) -> Vec<EntityId> {
        self.listed.iter().map(|row| row.claim).collect()
    }
}

/// One conflict as a resolution rebuild reads it: its rows for reads, its
/// routed heads, whether its members span predicates, the pack-ordered
/// candidate ids alias mapping resolves, and the retained set identity with
/// its native evidence and ask correlation for the lent execution.
pub(super) struct BuiltConflict {
    /// The conflict rows native reads page and render.
    pub(super) rows: ConflictRows,
    /// The routed prior heads, in native id order.
    pub(super) priors: Vec<EntityId>,
    /// Whether any member predicate differs from the identity one.
    pub(super) across: bool,
    /// The derived candidate ids in pack order, for alias mapping.
    pub(super) candidate_ids: Vec<EntityId>,
    /// The retained conflict identity, for the execution subject and project.
    pub(super) identity: ConflictIdentity,
    /// The native evidence in native order: the routed heads, then the member
    /// source TURNs sorted and deduped.
    pub(super) evidence: Vec<EntityId>,
    /// The ask correlation of the rebuilt set in this attempt.
    pub(super) correlation: EntityId,
}

impl BuiltConflict {
    /// The rebuilt prior heads, in native id order.
    pub(super) fn prior_ids(&self) -> Vec<EntityId> {
        self.priors.clone()
    }
}

/// `reference` as the id it names: 32 lowercase hex digits that round-trip.
/// The bound handler pins subjects, turns and claims, but not corrected
/// claims or relationships, so every id parses here, canonically.
fn parse_reference(reference: &str) -> Result<EntityId> {
    let id = EntityId::from_hex(reference).map_err(|_| {
        invalid_consolidation("extraction references must be 32 lowercase hex digits")
    })?;
    if id.to_hex() != reference {
        return Err(invalid_consolidation(
            "extraction references must be 32 lowercase hex digits",
        ));
    }
    Ok(id)
}

/// The eligible (candidate position, listed index) pairs over `subjects` with
/// the listing in native first-seen order: every claim the bound listing
/// shows about each subject that its read may correct. Operand evidence is
/// turn-only, so no candidate restates a listed claim through a claim
/// locator and every correctable pair is asked, as native asks it.
pub(super) fn correction_sets(
    subjects: &[EntityId],
    bound: &BoundBranchRead,
) -> Result<(Vec<(usize, usize)>, Vec<CorrectionListed>)> {
    let mut entries: Vec<(usize, usize)> = Vec::new();
    let mut listed: Vec<CorrectionListed> = Vec::new();
    for (position, subject) in subjects.iter().enumerate() {
        for (claim, predicate, value) in bound.correctable(*subject, bound.scope()) {
            let at = match listed.iter().position(|row| row.claim == claim) {
                Some(at) => at,
                None => {
                    listed.push(CorrectionListed {
                        claim,
                        subject: *subject,
                        predicate,
                        value_text: value,
                    });
                    listed.len() - 1
                }
            };
            entries.push((position, at));
        }
    }
    Ok((entries, listed))
}

/// The native correction evidence over `checked`: every rebuilt listed claim
/// in native order, then the asked candidates' source TURNs sorted and
/// deduped, excluding any TURN already listed. This mirrors the native
/// correction pack's one evidence set across all its pages.
pub(super) fn correction_evidence(checked: &CheckedPack) -> Vec<EntityId> {
    let mut evidence: Vec<EntityId> = checked.listed_ids();
    let mut turns: Vec<EntityId> = checked
        .pairs
        .iter()
        .filter_map(|(position, _)| checked.rows.get(*position))
        .flat_map(|row| row.proposal.evidence_turn_refs.iter().copied())
        .filter(|turn| !evidence.contains(turn))
        .collect();
    turns.sort_unstable();
    turns.dedup();
    evidence.extend(turns);
    evidence
}

/// The native correction route project over `checked`: the one project every
/// asked candidate shares, or none when they span projects or none is asked.
/// This mirrors the native correction pack's unanimous project.
pub(super) fn correction_project(checked: &CheckedPack) -> Option<EntityId> {
    let mut asked = checked
        .pairs
        .iter()
        .filter_map(|(position, _)| checked.rows.get(*position))
        .map(|row| row.project);
    let first = asked.next()?;
    if asked.all(|project| project == first) {
        Some(first)
    } else {
        None
    }
}

/// Every pack candidate checked with the listing its pairs need: each subject
/// parsed, each predicate grammar checked, each value non-null with turn
/// evidence, each corrected claim a listed head it repeats, each relationship
/// inside the bound set, each project the common one of its turns, and each
/// id derived with the native deterministic id.
pub(super) fn check_pack_candidates(
    pack: &ExtractionPack,
    bound: &BoundBranchRead,
    attempt: AttemptId,
    axes: &BranchAxes,
) -> Result<CheckedPack> {
    let mut subjects = Vec::with_capacity(pack.candidates.len());
    for operand in &pack.candidates {
        subjects.push(parse_reference(&operand.subject)?);
    }
    let (pairs, listed) = correction_sets(&subjects, bound)?;
    let mut rows = Vec::with_capacity(pack.candidates.len());
    for (position, (operand, subject)) in pack.candidates.iter().zip(&subjects).enumerate() {
        validate_predicate(&operand.predicate, false).map_err(|_| {
            invalid_consolidation("extracted candidate's predicate breaks the claim grammar")
        })?;
        if operand.value.is_null() {
            return Err(invalid_consolidation("extracted candidate names no value"));
        }
        if operand.evidence.is_empty() {
            return Err(invalid_consolidation(
                "extracted candidate needs TURN evidence",
            ));
        }
        let mut turn_refs: Vec<EntityId> = operand
            .evidence
            .iter()
            .map(|evidence| parse_reference(&evidence.turn))
            .collect::<Result<Vec<_>>>()?;
        turn_refs.sort_unstable();
        turn_refs.dedup();
        let corrects_id = operand
            .corrects
            .as_ref()
            .map(|corrects| parse_reference(corrects.as_str()))
            .transpose()?;
        if let Some(id) = corrects_id {
            let asked = pairs.iter().any(|(at, listed_at)| {
                *at == position && listed.get(*listed_at).is_some_and(|row| row.claim == id)
            });
            if !asked {
                return Err(invalid_consolidation(
                    "extracted correction names an unlisted claim",
                ));
            }
        }
        let corrects = corrects_id
            .map(|id| {
                bound
                    .prior(id)
                    .ok_or_else(|| {
                        invalid_consolidation("extracted correction names an unknown prior head")
                    })
                    .and_then(|prior| CorrectsPrior::from_head(prior))
            })
            .transpose()?;
        let rel = match operand.rel.as_ref() {
            None => PackRelationship::Inherit,
            Some(ids) => PackRelationship::Set(
                ids.iter()
                    .map(|id| parse_reference(id))
                    .collect::<Result<Vec<_>>>()?,
            ),
        };
        // A proposed relationship stays inside the bound set even while the
        // candidate corrects: shared assembly intentionally ignores it then.
        if let PackRelationship::Set(ids) = &rel
            && let Some(allowed) = bound.relationship()
            && !ids.iter().all(|id| allowed.contains(id))
        {
            return Err(invalid_consolidation(
                "extraction relationship crossed branch scope",
            ));
        }
        let project = bound.evidence_project(&turn_refs)?.ok_or_else(|| {
            invalid_consolidation("extracted candidate's sources share no one branch project")
        })?;
        let input = CandidateAssemblyInput {
            subject: *subject,
            predicate: Some(operand.predicate.as_str()),
            value: &operand.value,
            rel,
            topic: operand.topic.as_ref(),
            corrects,
            confidence: 0.0,
            lexical_hints: Vec::new(),
            project,
            world: axes.world_ref,
            facet: axes.facet_ref,
            scope_relationship: bound.relationship(),
        };
        let candidate = assemble_identity_candidate(&input)?;
        let claim_id = claim_id_for_identity(attempt, &candidate)?;
        let facts = candidate_facts(&candidate)?;
        rows.push(CheckedCandidate {
            claim_id,
            subject: *subject,
            predicate: operand.predicate.clone(),
            value_text: operand.value.to_string(),
            project: facts.project,
            proposal: PromotionCandidate {
                claim_id,
                candidate,
                evidence_turn_refs: turn_refs,
                provenance_chain: Vec::new(),
                supersedes: None,
                evidence_meet: ClaimSource::Generated,
                occurred: crate::TimeRange { start: 0, end: 0 },
                learned_at: 0,
                decisions: Vec::new(),
            },
        });
    }
    Ok(CheckedPack {
        rows,
        pairs,
        listed,
    })
}

/// The shared key parts of `parts` as wire text through the one key mapping.
pub(super) fn key_texts(parts: &[DecisionKeyPart]) -> Vec<String> {
    parts
        .iter()
        .map(|part| key_part_text(&key_part_bytes(part), false))
        .collect()
}

/// The numbered rows of the correction read over its asked positions: each
/// asked candidate with its question labels and each listed claim it shows.
/// Claim and Entity labels come from a real call map in native order, so
/// repeats dedupe exactly as native; question labels run positionally, since
/// native labels every question before the state names any and a read's own
/// questions always take `Q1` onward however many suffix labels follow.
fn numbered_correction_read(
    prepared: &[(usize, Vec<ChoiceSpec>)],
    rows: &[CheckedCandidate],
    listed: &[CorrectionListed],
    shown: &[usize],
    labels: &mut CallLabelMap,
) -> (Vec<NumberedCorrectionCandidate>, Vec<NumberedListedClaim>) {
    let mut candidates = Vec::new();
    let mut counter = 0_usize;
    for (position, specs) in prepared {
        let mut refs = Vec::new();
        for _ in specs {
            counter += 1;
            refs.push(format!("Q{counter}"));
        }
        let Some(row) = rows.get(*position) else {
            continue;
        };
        candidates.push(NumberedCorrectionCandidate {
            questions: refs,
            subject: labels.assign(LabelKind::Entity, row.subject).to_string(),
            predicate: Some(row.predicate.clone()),
            value_text: row.value_text.clone(),
        });
    }
    let mut listed_rows = Vec::new();
    for at in shown {
        let Some(row) = listed.get(*at) else {
            continue;
        };
        listed_rows.push(NumberedListedClaim {
            claim: labels.assign(LabelKind::Claim, row.claim).to_string(),
            subject: labels.assign(LabelKind::Entity, row.subject).to_string(),
            predicate: row.predicate.clone(),
            value_text: row.value_text.clone(),
        });
    }
    (candidates, listed_rows)
}

/// The eligible pairs in native pages: all on one when the whole state fits
/// the ladder's bound, else split in order through the shared measures and
/// branch. This mirrors the native correction paging decision exactly.
pub(super) fn correction_page_entries(
    rows: &[CheckedCandidate],
    pairs: &[(usize, usize)],
    listed: &[CorrectionListed],
) -> Vec<Vec<(usize, usize)>> {
    let listed_ids: Vec<EntityId> = listed.iter().map(|row| row.claim).collect();
    let (asked, shown) = group_correction_asks(pairs, &listed_ids);
    let mut labels = CallLabelMap::default();
    let prepared = correction_choice_specs(&asked, None, &mut labels);
    let (candidates, listed_rows) =
        numbered_correction_read(&prepared, rows, listed, &shown, &mut labels);
    let whole_len = json_len(&render_correction_state(
        candidates,
        listed_rows,
        PartMark::Whole,
    ));
    page_or_whole(whole_len, pairs, || {
        split_pages(
            correction_frame_bytes(),
            pairs,
            |page, (position, at)| {
                let candidate = if page.iter().any(|entry| entry.0 == position) {
                    0
                } else {
                    rows.get(position).map_or(0, |row| {
                        correction_candidate_bytes(
                            &row.subject.to_hex(),
                            Some(row.predicate.as_str()),
                            &row.value_text,
                        )
                    })
                };
                let claim = if page.iter().any(|entry| entry.1 == at) {
                    0
                } else {
                    listed.get(at).map_or(0, |row| {
                        correction_listed_bytes(
                            &row.claim.to_hex(),
                            &row.subject.to_hex(),
                            &row.predicate,
                            &row.value_text,
                        )
                    })
                };
                candidate.saturating_add(claim)
            },
            |_, _| true,
        )
    })
}

/// The one native conflict the pack candidates form: nomination through
/// the native [`judge_queue`] over stored vectors with the bound key rules
/// and threshold, then [`route_bound_priors`] over the bound heads. The pack
/// is one conflict exactly when routing leaves a single set covering every
/// candidate, exactly-restated members aside. Returns its rows for reads,
/// its heads, whether members span predicates, and the retained set identity
/// with its native evidence and ask correlation for the lent execution.
pub(super) fn resolution_conflict(
    rows: &[CheckedCandidate],
    bound: &BoundBranchRead,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<BuiltConflict> {
    let proposals: Vec<PromotionCandidate> = rows.iter().map(|row| row.proposal.clone()).collect();
    let mut embeddings: BTreeMap<EntityId, Vec<f32>> = BTreeMap::new();
    for proposal in &proposals {
        if let Some(vector) =
            bound.candidate_vector_in_txn(read, txn, proposal.claim_id, &proposal.candidate)?
        {
            embeddings.insert(proposal.claim_id, vector);
        }
    }
    let nominated = judge_queue(
        &proposals,
        &embeddings,
        bound.key_rules(),
        bound.cosine_threshold(),
    )?;
    let heads: Vec<PriorHead> = bound.priors().values().cloned().collect();
    let (routed, exact) =
        route_bound_priors(&proposals, &heads, nominated, bound.key_rules(), |id| {
            bound.require_prior_write(id)
        })?;
    if routed.len() != 1 {
        return Err(invalid_consolidation(if routed.is_empty() {
            "extraction candidates form no native conflict"
        } else {
            "extraction candidates span more than one conflict"
        }));
    }
    let set = &routed[0];
    let mut covered: Vec<usize> = set.candidate_indexes.clone();
    covered.extend(exact.iter().copied());
    covered.sort_unstable();
    if covered != (0..proposals.len()).collect::<Vec<_>>() {
        return Err(invalid_consolidation(
            "extraction candidates are not one native conflict",
        ));
    }
    let mut members = Vec::with_capacity(set.candidate_indexes.len());
    for index in &set.candidate_indexes {
        let Some(proposal) = proposals.get(*index) else {
            return Err(invalid_consolidation(
                "extraction candidates are not one native conflict",
            ));
        };
        let facts = candidate_facts(&proposal.candidate)?;
        members.push((
            proposal.claim_id,
            facts.predicate,
            rmpv_to_json(&facts.value),
        ));
    }
    let mut shown = Vec::with_capacity(set.prior_heads.len());
    for id in &set.prior_heads {
        let Some(head) = bound.prior(*id) else {
            return Err(invalid_consolidation(
                "extraction conflict names an unknown prior head",
            ));
        };
        shown.push(head.clone());
    }
    let member_candidates: Vec<&ClaimCandidate> = set
        .candidate_indexes
        .iter()
        .filter_map(|index| proposals.get(*index))
        .map(|proposal| &proposal.candidate)
        .collect();
    let across = resolution_spans_predicates(&set.identity, &member_candidates);
    let mut evidence: Vec<EntityId> = set.prior_heads.clone();
    let mut turns: Vec<EntityId> = set
        .candidate_indexes
        .iter()
        .filter_map(|index| rows.get(*index))
        .flat_map(|row| row.proposal.evidence_turn_refs.iter().copied())
        .filter(|turn| !evidence.contains(turn))
        .collect();
    turns.sort_unstable();
    turns.dedup();
    evidence.extend(turns);
    let correlation = conflict_open_marker_id(set, attempt)?;
    Ok(BuiltConflict {
        rows: ConflictRows::from_rows(&set.identity, &members, &shown),
        priors: set.prior_heads.clone(),
        across,
        candidate_ids: rows.iter().map(|row| row.claim_id).collect(),
        identity: set.identity.clone(),
        evidence,
        correlation,
    })
}

/// The questions of the correction read over `checked`'s `part`: every
/// candidate's groups over its listed claims, in native order. A whole part
/// needs the single rebuilt page; a page part needs its page of the rebuilt
/// count.
pub(super) fn correction_plan_questions(
    checked: &CheckedPack,
    part: ExtractionPart,
) -> Result<Vec<PackQuestion>> {
    let pages = correction_page_entries(&checked.rows, &checked.pairs, &checked.listed);
    let entries: &[(usize, usize)];
    let page: Option<usize>;
    match part {
        ExtractionPart::Whole => {
            if pages.len() != 1 {
                return Err(invalid_consolidation(
                    "extraction pack part does not match its read",
                ));
            }
            entries = pages
                .first()
                .ok_or_else(|| {
                    invalid_consolidation("extraction pack part does not match its read")
                })?
                .as_slice();
            page = None;
        }
        ExtractionPart::Page {
            page: at,
            pages: count,
        } => {
            if count < 2 || pages.len() != count {
                return Err(invalid_consolidation(
                    "extraction pack part does not match its read",
                ));
            }
            entries = pages
                .get(at)
                .ok_or_else(|| {
                    invalid_consolidation("extraction pack part does not match its read")
                })?
                .as_slice();
            page = Some(at);
        }
        ExtractionPart::Final { .. } => {
            return Err(invalid_consolidation(
                "extraction pack part does not match its read",
            ));
        }
    }
    let listed_ids: Vec<EntityId> = checked.listed.iter().map(|row| row.claim).collect();
    let (asked, _) = group_correction_asks(entries, &listed_ids);
    let mut labels = CallLabelMap::default();
    let mut questions = Vec::new();
    for (_, specs) in correction_choice_specs(&asked, page, &mut labels) {
        for spec in specs {
            questions.push(PackQuestion {
                key: key_texts(&spec.key),
                options: spec.options,
            });
        }
    }
    Ok(questions)
}

/// The questions of the resolution read over `built`'s `part`: how the
/// conflict resolves, then which members a merge keeps, in native order. A
/// whole part needs the single rebuilt page; a page part needs its page of
/// the rebuilt count.
pub(super) fn resolution_plan_questions(
    built: &BuiltConflict,
    part: ExtractionPart,
) -> Result<Vec<PackQuestion>> {
    let pages = built.rows.pages();
    let shown: &[usize];
    let page: Option<usize>;
    match part {
        ExtractionPart::Whole => {
            if pages.len() != 1 {
                return Err(invalid_consolidation(
                    "extraction pack part does not match its read",
                ));
            }
            shown = pages
                .first()
                .ok_or_else(|| {
                    invalid_consolidation("extraction pack part does not match its read")
                })?
                .as_slice();
            page = None;
        }
        ExtractionPart::Page {
            page: at,
            pages: count,
        } => {
            if count < 2 || pages.len() != count {
                return Err(invalid_consolidation(
                    "extraction pack part does not match its read",
                ));
            }
            shown = pages
                .get(at)
                .ok_or_else(|| {
                    invalid_consolidation("extraction pack part does not match its read")
                })?
                .as_slice();
            page = Some(at);
        }
        ExtractionPart::Final { .. } => {
            return Err(invalid_consolidation(
                "extraction pack part does not match its read",
            ));
        }
    }
    let ids = built.rows.ids(shown);
    let mut labels = CallLabelMap::default();
    let resolution = resolution_choice_spec(page);
    let mut questions = vec![PackQuestion {
        key: key_texts(&resolution.key),
        options: resolution.options,
    }];
    let paged = page.is_some();
    for spec in conflict_identity_specs(&ids, !built.across || paged, page, &mut labels) {
        questions.push(PackQuestion {
            key: key_texts(&spec.key),
            options: spec.options,
        });
    }
    Ok(questions)
}
