//! The typed pack that decides which listed claim each extracted candidate
//! corrects: per candidate, one question per option group, over `none` and
//! the claims the listing shows about its subject. Its call shows every
//! question, subject and claim by a call-local label (FIX 7506 P2), field by
//! field, never by rewriting inside a value; its decisions keep the
//! canonical options. A candidate that restates a listed claim unchanged
//! reinforces it and is never asked whether it corrects it (FIX 8295).
//!
//! Every value rides whole (Rule 5, FIX 7637): a pack whose state does not
//! fit one read is asked in pages, in its own order, each page holding some
//! candidates and some of the claims listed for them, every candidate with
//! its own groups over the claims on that page. A candidate whose groups
//! name more than one claim gets one final choice over those claims (FIX
//! 8693).

use super::super::decisions::{
    ChoiceSpec, DecisionKeyPart, FinalChoice, PartMark, StatePart, id_options, key_part_bytes,
    page_or_whole,
};
use super::*;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::evidence::EvidenceLocator;
use crate::dreamer_consolidation::settle::decision_pages::{json_len, measure_state, split_pages};
use crate::dreamer_consolidation::value_projection::rmpv_to_json;
use crate::error::Result;
use crate::model_decision::catalogue::CORRECTION;
use crate::model_decision::{AnswerContract, DecisionQuestion};

/// One claim the listing shows that a candidate may correct: its id, its
/// subject, and its predicate and value as the listing writes them.
type Listed<'r> = (EntityId, EntityId, &'r str, &'r str);

/// The shared key parts of one correction group question: the candidate
/// position with its group number, then the page marker and number on a paged
/// read.
pub(in crate::dreamer_consolidation) fn correction_key_parts(
    position: usize,
    group: usize,
    page: Option<usize>,
) -> Vec<DecisionKeyPart> {
    let mut parts = vec![
        DecisionKeyPart::Number(position),
        DecisionKeyPart::Number(group),
    ];
    if let Some(page) = page {
        parts.extend([DecisionKeyPart::Text("page"), DecisionKeyPart::Number(page)]);
    }
    parts
}

/// The asks over `entries` against `listed_ids`: each asked candidate
/// position with the listed ids it pairs, both in first-seen entry order,
/// with the shown listed indexes. Native correction reads and the bound
/// rebuild group their pairs here.
pub(in crate::dreamer_consolidation) fn group_correction_asks(
    entries: &[(usize, usize)],
    listed_ids: &[EntityId],
) -> (Vec<(usize, Vec<EntityId>)>, Vec<usize>) {
    let mut asked: Vec<(usize, Vec<EntityId>)> = Vec::new();
    let mut shown: Vec<usize> = Vec::new();
    for &(position, at) in entries {
        if !shown.contains(&at) {
            shown.push(at);
        }
        let Some(id) = listed_ids.get(at).copied() else {
            continue;
        };
        match asked.iter_mut().find(|row| row.0 == position) {
            Some(row) => row.1.push(id),
            None => asked.push((position, vec![id])),
        }
    }
    (asked, shown)
}

/// One read's prepared correction choices: each asked position with one
/// choice per option group over its listed ids, keyed by position and group
/// (and page, on a paged read), each group with the shown texts its
/// question registers. Every group offers `none`, as native always did.
pub(in crate::dreamer_consolidation) fn correction_choice_specs(
    asked: &[(usize, Vec<EntityId>)],
    page: Option<usize>,
    labels: &mut CallLabelMap,
) -> Vec<(usize, Vec<ChoiceSpec>)> {
    asked
        .iter()
        .map(|(position, ids)| {
            let specs = id_options(ids, true, labels)
                .into_iter()
                .enumerate()
                .map(|(group, (options, shown))| ChoiceSpec {
                    key: correction_key_parts(*position, group, page),
                    options,
                    shown: Some(shown),
                })
                .collect();
            (*position, specs)
        })
        .collect()
}

/// One asked candidate as a shared state render takes it: its question labels
/// already assigned, with its subject label, predicate and value text.
#[derive(Debug, Clone)]
pub(in crate::dreamer_consolidation) struct NumberedCorrectionCandidate {
    /// The question labels of its groups, such as `Q1`.
    pub(in crate::dreamer_consolidation) questions: Vec<String>,
    /// The subject label the read assigned, such as `P1`.
    pub(in crate::dreamer_consolidation) subject: String,
    /// The candidate predicate, when it meets the claim grammar.
    pub(in crate::dreamer_consolidation) predicate: Option<String>,
    /// The candidate value as JSON text.
    pub(in crate::dreamer_consolidation) value_text: String,
}

/// One listed claim as a shared state render takes it: its claim and subject
/// labels already assigned, with its predicate and value text.
#[derive(Debug, Clone)]
pub(in crate::dreamer_consolidation) struct NumberedListedClaim {
    /// The claim label the read assigned, such as `C1`.
    pub(in crate::dreamer_consolidation) claim: String,
    /// The subject label the read assigned, such as `P2`.
    pub(in crate::dreamer_consolidation) subject: String,
    /// The listed predicate.
    pub(in crate::dreamer_consolidation) predicate: String,
    /// The listed value as JSON text.
    pub(in crate::dreamer_consolidation) value_text: String,
}

/// The correction state over `candidates` and `listed`: each asked candidate
/// with its questions, subject, predicate and value, and each listed claim,
/// every value whole as its JSON text, marked as `mark`'s. Native correction
/// reads and the bound rebuild render through this function with the same
/// label order, so both measure the same bytes.
pub(in crate::dreamer_consolidation) fn render_correction_state(
    candidates: Vec<NumberedCorrectionCandidate>,
    listed: Vec<NumberedListedClaim>,
    mark: PartMark,
) -> serde_json::Value {
    let candidates: Vec<serde_json::Value> = candidates
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "questions": row.questions,
                "subject": row.subject,
                "predicate": row.predicate,
                "value": row.value_text,
            })
        })
        .collect();
    let listed: Vec<serde_json::Value> = listed
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "claim": row.claim,
                "subject": row.subject,
                "predicate": row.predicate,
                "value": row.value_text,
            })
        })
        .collect();
    mark.apply(serde_json::json!({
        "candidates": candidates,
        "listed": listed,
    }))
}

/// The bytes one asked candidate adds to a correction page: its row with its
/// full subject id, plus one separator byte. Native paging and the bound
/// rebuild share this measure.
pub(in crate::dreamer_consolidation) fn correction_candidate_bytes(
    subject_hex: &str,
    predicate: Option<&str>,
    value_text: &str,
) -> usize {
    json_len(&serde_json::json!({
        "questions": ["Q0000"],
        "subject": subject_hex,
        "predicate": predicate,
        "value": value_text,
    }))
    .saturating_add(1)
}

/// The bytes one listed claim adds to a correction page: its row with full
/// ids, plus one separator byte. Native paging and the bound rebuild share
/// this measure.
pub(in crate::dreamer_consolidation) fn correction_listed_bytes(
    claim_hex: &str,
    subject_hex: &str,
    predicate: &str,
    value_text: &str,
) -> usize {
    json_len(&serde_json::json!({
        "claim": claim_hex,
        "subject": subject_hex,
        "predicate": predicate,
        "value": value_text,
    }))
    .saturating_add(1)
}

/// The bytes a correction page carries beside its rows: the empty state
/// marked as page one of two. Native paging and the bound rebuild share this
/// frame.
pub(in crate::dreamer_consolidation) fn correction_frame_bytes() -> usize {
    json_len(&render_correction_state(
        Vec::new(),
        Vec::new(),
        PartMark::Page { page: 0, pages: 2 },
    ))
}

/// One read of the correction pack: its questions, the candidate each asks
/// about by position, the call's labels and the state it reads.
struct CorrectionRead {
    questions: Vec<DecisionQuestion>,
    owners: Vec<usize>,
    labels: CallLabelMap,
    state: serde_json::Value,
}

impl ConsolidationExecutor<'_> {
    /// Which listed claim each parsed candidate corrects, in order. A
    /// candidate whose subject the listing shows claims about, that its child
    /// may read and write, gets one question per option group over `none` and
    /// those claims' ids, all candidates in one pack, or in its pages; one
    /// with no such claim, or no answer, corrects none. The pack's ask goes
    /// to its candidates' project's route, or to the owners when they span
    /// projects. None when the step trapped.
    pub(in crate::dreamer_consolidation) async fn decide_corrections(
        &self,
        step_ctx: &DurableStepContext<'_>,
        pass: &crate::dreamer_wake::WakePassDeadline,
        parsed: &[ParsedCandidate<'_>],
        resources: &BranchResources<'_>,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<Option<Vec<Correction>>> {
        // Each (candidate position, listed claim) pair asked, and every
        // listed claim asked about, once.
        let mut entries: Vec<(usize, usize)> = Vec::new();
        let mut listed: Vec<Listed<'_>> = Vec::new();
        let pins = resources.pins();
        for (position, candidate) in parsed.iter().enumerate() {
            let shown = pins
                .correctable(candidate.subject, candidate.scope)
                .filter(|(claim, ..)| !reinforces(candidate, resources, *claim));
            for (claim, predicate, value) in shown {
                let at = match listed.iter().position(|row| row.0 == claim) {
                    Some(at) => at,
                    None => {
                        listed.push((claim, candidate.subject, predicate, value));
                        listed.len() - 1
                    }
                };
                entries.push((position, at));
            }
        }
        if entries.is_empty() {
            return Ok(Some(parsed.iter().map(|_| Correction::none()).collect()));
        }
        let reads = self.correction_reads(parsed, &entries, &listed)?;
        let asked: Vec<&ParsedCandidate<'_>> = parsed
            .iter()
            .enumerate()
            .filter(|(position, _)| entries.iter().any(|entry| entry.0 == *position))
            .map(|(_, candidate)| candidate)
            .collect();
        // The pack reads the listed claims and candidates drawn from these
        // turns. The turns also keep one extraction's asks apart from
        // another's over the same listing.
        let mut evidence: Vec<EntityId> = listed.iter().map(|row| row.0).collect();
        let mut turns: Vec<EntityId> = asked
            .iter()
            .flat_map(|candidate| candidate.evidence_turn_refs.iter().copied())
            .filter(|turn| !evidence.contains(turn))
            .collect();
        turns.sort_unstable();
        turns.dedup();
        evidence.extend(turns);
        let project = asked
            .first()
            .map(|candidate| candidate.project)
            .filter(|project| asked.iter().all(|candidate| candidate.project == *project));
        let to = self.ask_route(step_ctx.vault, project)?;
        // The pack is the attempt's one correction read: the attempt names it.
        let key =
            EntityId::from_bytes(*step_ctx.attempt_id.as_bytes()).map_err(crate::Error::from)?;
        let mut groups: Vec<Vec<KeptDecision>> = vec![Vec::new(); parsed.len()];
        for read in &reads {
            measure_state(step_ctx.vault, &read.state);
            let sources = Some(correction_sources(
                parsed,
                &read.owners,
                &evidence,
                &read.labels,
            ));
            let Some(decided) = self
                .decide(
                    step_ctx,
                    pass,
                    resources,
                    &to,
                    key,
                    &read.questions,
                    &evidence,
                    &read.state,
                    &read.labels,
                    sources,
                    charges,
                )
                .await?
            else {
                return Ok(None);
            };
            for (decision, position) in decided.into_iter().zip(&read.owners) {
                if let Some(kept) = groups.get_mut(*position) {
                    kept.push(decision);
                }
            }
        }
        let mut corrections = Vec::with_capacity(parsed.len());
        for (position, mut decisions) in groups.into_iter().enumerate() {
            if decisions.is_empty() {
                corrections.push(Correction::none());
                continue;
            }
            let base = [DecisionKeyPart::Number(position)];
            let choice = FinalChoice {
                family: &CORRECTION,
                base: &base,
                wording: &self.decisions.correction_wording,
                none: true,
            };
            let state = |shortlist: &[EntityId],
                         questions: &[DecisionQuestion],
                         labels: &mut CallLabelMap| {
                let rows: Vec<Listed<'_>> = shortlist
                    .iter()
                    .filter_map(|id| listed.iter().find(|row| row.0 == *id).copied())
                    .collect();
                let asks: [(usize, Vec<usize>); 1] = [(position, (0..questions.len()).collect())];
                correction_state(parsed, &asks, questions, &rows, StatePart::Final, labels)
            };
            let sources_for = |_: &[EntityId], labels: &CallLabelMap| {
                Some(correction_sources(parsed, &[position], &evidence, labels))
            };
            let Some((corrects, finals)) = self
                .choose_identity(
                    step_ctx,
                    pass,
                    resources,
                    &to,
                    key,
                    &evidence,
                    &choice,
                    &decisions,
                    &state,
                    &sources_for,
                    charges,
                )
                .await?
            else {
                return Ok(None);
            };
            decisions.extend(finals);
            corrections.push(Correction {
                corrects,
                decisions,
            });
        }
        // Every decided candidate is kept at the attempt before the branch
        // builds, filters or selects it (FIX 2425).
        super::decided::record_decided_candidates(
            step_ctx.vault,
            step_ctx.attempt_id,
            parsed,
            &corrections,
        )?;
        Ok(Some(corrections))
    }

    /// The pack's reads over `entries`: one whole read when its state fits
    /// the ladder's bound, else pages in order. A page takes the next pair
    /// while its candidate's row (once per page) and its listed claim's row
    /// (once per page), each measured with full ids, keep the page within
    /// the bound; a pair wider than a page has a page of its own.
    fn correction_reads(
        &self,
        parsed: &[ParsedCandidate<'_>],
        entries: &[(usize, usize)],
        listed: &[Listed<'_>],
    ) -> Result<Vec<CorrectionRead>> {
        let whole = self.correction_read(parsed, entries, listed, StatePart::Whole)?;
        let candidate_bytes = |position: usize| {
            parsed.get(position).map_or(0, |candidate| {
                correction_candidate_bytes(
                    &candidate.subject.to_hex(),
                    candidate.predicate.as_deref(),
                    &candidate.value.to_string(),
                )
            })
        };
        let listed_bytes = |at: usize| {
            listed.get(at).map_or(0, |row| {
                correction_listed_bytes(&row.0.to_hex(), &row.1.to_hex(), row.2, row.3)
            })
        };
        let frame = correction_frame_bytes();
        let pages = page_or_whole(json_len(&whole.state), entries, || {
            split_pages(
                frame,
                entries,
                |page, (position, at)| {
                    let candidate = if page.iter().any(|entry| entry.0 == position) {
                        0
                    } else {
                        candidate_bytes(position)
                    };
                    let claim = if page.iter().any(|entry| entry.1 == at) {
                        0
                    } else {
                        listed_bytes(at)
                    };
                    candidate.saturating_add(claim)
                },
                |_, _| true,
            )
        });
        if pages.len() == 1 {
            return Ok(vec![whole]);
        }
        let count = pages.len();
        pages
            .iter()
            .enumerate()
            .map(|(page, entries)| {
                self.correction_read(
                    parsed,
                    entries,
                    listed,
                    StatePart::Page { page, pages: count },
                )
            })
            .collect()
    }

    /// One read over `entries`: each candidate they name, in order, with one
    /// question per option group over the listed claims they pair it with,
    /// keyed by its position and group (and page, on a paged read), and the
    /// state over those candidates and claims.
    fn correction_read(
        &self,
        parsed: &[ParsedCandidate<'_>],
        entries: &[(usize, usize)],
        listed: &[Listed<'_>],
        part: StatePart,
    ) -> Result<CorrectionRead> {
        let page = match part {
            StatePart::Page { page, .. } => Some(page),
            StatePart::Whole | StatePart::Final => None,
        };
        let listed_ids: Vec<EntityId> = listed.iter().map(|row| row.0).collect();
        let (asked, shown) = group_correction_asks(entries, &listed_ids);
        let mut labels = CallLabelMap::default();
        let mut questions = Vec::new();
        let mut owners = Vec::new();
        let mut asks: Vec<(usize, Vec<usize>)> = Vec::new();
        for (position, specs) in correction_choice_specs(&asked, page, &mut labels) {
            let mut questioned = Vec::new();
            for spec in specs {
                let owned: Vec<Vec<u8>> = spec.key.iter().map(key_part_bytes).collect();
                let key: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
                let question = CORRECTION.question(
                    &key,
                    self.decisions.correction_wording.clone(),
                    AnswerContract::Choice {
                        options: spec.options,
                    },
                )?;
                if let Some(shown) = spec.shown {
                    labels.show_choices(question.id, shown);
                }
                questioned.push(questions.len());
                owners.push(position);
                questions.push(question);
            }
            asks.push((position, questioned));
        }
        // Every question is labelled before the state names any, so each
        // request the read splits into reads the same labels.
        self.label_questions(&mut labels, &questions);
        let rows: Vec<Listed<'_>> = shown
            .iter()
            .filter_map(|at| listed.get(*at).copied())
            .collect();
        let state = correction_state(parsed, &asks, &questions, &rows, part, &mut labels);
        Ok(CorrectionRead {
            questions,
            owners,
            labels,
            state,
        })
    }
}

/// Whether `candidate` restates listed `claim` unchanged: it cites the claim
/// and carries the claim's own predicate and value (its subject is the
/// claim's, as the listing shows it about that subject). It reinforces the
/// claim, so that pair is never asked and corrects none.
fn reinforces(
    candidate: &ParsedCandidate<'_>,
    resources: &BranchResources<'_>,
    claim: EntityId,
) -> bool {
    candidate.locators.iter().any(
        |locator| matches!(locator, EvidenceLocator::Claim { claim_id, .. } if *claim_id == claim),
    ) && resources.prior(claim).is_ok_and(|prior| {
        candidate.predicate.as_deref() == Some(prior.body.predicate.as_str())
            && rmpv_to_json(&prior.body.value) == candidate.value
    })
}

/// What the correction pack decided for one parsed candidate: the listed
/// claim it corrects, if any, and its questions' decisions.
pub(in crate::dreamer_consolidation) struct Correction {
    pub(super) corrects: Option<EntityId>,
    pub(super) decisions: Vec<KeptDecision>,
}

impl Correction {
    /// A candidate the pack asked nothing about: it corrects none.
    fn none() -> Self {
        Self {
            corrects: None,
            decisions: Vec::new(),
        }
    }

    /// Whether one of its questions waits on a role's answer.
    pub(super) fn waiting(&self) -> bool {
        self.decisions.iter().any(KeptDecision::waiting)
    }
}

/// The rows one correction read sends under (FIX 11526): its candidates'
/// extraction rows, the pack's evidence, and the rows its labels name.
fn correction_sources(
    parsed: &[ParsedCandidate<'_>],
    owners: &[usize],
    evidence: &[EntityId],
    labels: &CallLabelMap,
) -> Vec<EntityId> {
    let row_sources: Vec<&[EntityId]> = parsed.iter().map(ParsedCandidate::sources).collect();
    let label_rows: Vec<EntityId> = labels.rows().collect();
    correction_source_rows(&row_sources, owners, evidence, &label_rows)
}

/// The rows one correction read sends under (FIX 11526) over plain rows:
/// the `owners`' extraction rows from `row_sources`, the pack's evidence,
/// and the stored `label_rows`, sorted and deduped. The bound rebuild sends
/// no sources, so only native calls this; it stays a shared plain helper so
/// wording-free preparation never needs the parsed type.
pub(in crate::dreamer_consolidation) fn correction_source_rows(
    row_sources: &[&[EntityId]],
    owners: &[usize],
    evidence: &[EntityId],
    label_rows: &[EntityId],
) -> Vec<EntityId> {
    let mut set: Vec<EntityId> = Vec::new();
    for position in owners {
        if let Some(sources) = row_sources.get(*position) {
            set.extend(sources.iter().copied());
        }
    }
    set.extend(evidence.iter().copied());
    set.extend(label_rows.iter().copied());
    set.sort_unstable();
    set.dedup();
    set
}

/// The candidates and the listed claims as one read of the correction pack
/// takes them: each candidate `asks` names with its questions, subject,
/// predicate and value, and each of `listed`, every value whole as its JSON
/// text, marked as `part`'s. Each question, subject and claim goes by its
/// label in `labels`.
fn correction_state(
    parsed: &[ParsedCandidate<'_>],
    asks: &[(usize, Vec<usize>)],
    questions: &[DecisionQuestion],
    listed: &[Listed<'_>],
    part: StatePart,
    labels: &mut CallLabelMap,
) -> serde_json::Value {
    let mut candidates = Vec::new();
    for (position, asked) in asks {
        let Some(candidate) = parsed.get(*position) else {
            continue;
        };
        let refs: Vec<String> = asked
            .iter()
            .filter_map(|at| questions.get(*at))
            .map(|question| labels.assign(LabelKind::Question, question.id).to_string())
            .collect();
        let subject = labels
            .assign(LabelKind::Entity, candidate.subject)
            .to_string();
        candidates.push(NumberedCorrectionCandidate {
            questions: refs,
            subject,
            predicate: candidate.predicate.clone(),
            value_text: candidate.value.to_string(),
        });
    }
    let listed: Vec<NumberedListedClaim> = listed
        .iter()
        .map(|(claim, subject, predicate, value)| NumberedListedClaim {
            claim: labels.assign(LabelKind::Claim, *claim).to_string(),
            subject: labels.assign(LabelKind::Entity, *subject).to_string(),
            predicate: (*predicate).to_owned(),
            value_text: (*value).to_owned(),
        })
        .collect();
    render_correction_state(candidates, listed, PartMark::from(part))
}
