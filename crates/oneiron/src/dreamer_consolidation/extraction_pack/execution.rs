//! Runs one checked extraction pack read through the native typed read with the lent wording.
//!
//! [`rebuild_checked_pack`](super::rebuild_checked_pack) checks every operand and rebuilds
//! every question key and canonical option without wording or question identifiers. This
//! module carries the checked owned rows out of that one validation transaction and, once
//! the attempt's lender lends its pass resources, runs the whole pack through the shared
//! native shell, seal and [`decide_pack_with_charges`](super::super::executor::decide_pack_with_charges)
//! with the held native wording. No second transaction opens here, no proposal writes,
//! and no value the job offered is trusted as a fact.
//!
//! The split stays strict. The rebuild owns live read reach, source pins, operand shape,
//! native grouping, paging validation and earlier answer checks. The execution owns only
//! the native question, label and state build over the already checked rows, with the
//! lent wording applied exactly as native applies it. Evidence versions come from the
//! rows the rebuild already pinned, in native evidence order, through the shared plain
//! body hash. The bound read sends unsourced, since the extraction call source rows are
//! unknown.

use super::super::ConsolidationDecisions;
use super::super::KeptDecision;
use super::super::call_labels::{CallLabelMap, LabelKind};
use super::super::executor::extraction::corrections::{
    NumberedCorrectionCandidate, NumberedListedClaim, correction_choice_specs,
    group_correction_asks, render_correction_state,
};
use super::super::executor::extraction::{
    ConflictRows, DecisionKeyPart, PartMark, conflict_identity_specs, identity_round_specs,
    key_part_bytes, resolution_choice_spec, resolution_final_prep,
};
use super::super::executor::{
    ChargeSink, Decider, StatePart, VerdictRead, ask_route_for, decide_pack_with_charges,
    label_questions_with,
};
use super::super::support::invalid_consolidation;
use super::reads::{
    BuiltConflict, CheckedCandidate, CheckedPack, CorrectionListed, correction_evidence,
    correction_page_entries, correction_project,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::ExtractionDecisionLoan;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::model_decision::catalogue::{CONFLICT_RESOLUTION, CORRECTION};
use crate::model_decision::{AnswerContract, DecisionQuestion, DecisionRung, EvidenceVersion};
use crate::model_step_context::DurableStepContext;
use crate::model_step_error::DurableStepResult;
use crate::verbs::ExtractionPart;
use crate::write_envelope::WriteActor;
use oneiron_model::llm::Scope;

/// Carries one checked extraction read's owned execution rows: the native evidence, subject,
/// scope, route project and ask correlation, with the read specific plain rows the
/// lent execution renders. Every row below was checked in the one validation
/// transaction, and no row here is read again.
pub(crate) struct CheckedExtractionRead {
    /// Lists the native evidence in native order.
    evidence: Vec<EntityId>,
    /// Names the read subject. Resolution reads use the rebuilt conflict subject, while
    /// correction reads use the queued branch subject the caller supplies.
    subject: EntityId,
    /// Holds the engine's rebuilt native scope for the attempt.
    scope: Scope,
    /// Names the derived route project, or none when the read asks the owners.
    project: Option<EntityId>,
    /// Names the ask correlation of this read in this attempt.
    correlation: EntityId,
    /// Holds the read specific owned rows the lent execution renders.
    kind: CheckedReadKind,
}

/// Names the read specific owned rows one checked execution renders.
enum CheckedReadKind {
    /// Carries a correction whole or page read over its checked pairs and listing.
    Correction {
        /// Holds the checked candidates in pack order.
        rows: Vec<CheckedCandidate>,
        /// Holds the eligible candidate and listed index pairs in native order.
        pairs: Vec<(usize, usize)>,
        /// Holds the rebuilt listing in native first seen order.
        listed: Vec<CorrectionListed>,
        /// Names the whole or page part this read asks.
        part: ExtractionPart,
    },
    /// Carries a correction final round over its checked rows and target shortlist.
    CorrectionFinal {
        /// Holds the checked candidates in pack order.
        rows: Vec<CheckedCandidate>,
        /// Holds the rebuilt listing in native first seen order.
        listed: Vec<CorrectionListed>,
        /// Names the candidate position this final choice belongs to.
        position: usize,
        /// Lists the target round shortlist in native order.
        shortlist: Vec<EntityId>,
        /// Names the requested one based target round.
        round: usize,
    },
    /// Carries a resolution whole or page read over its conflict rows.
    Resolution {
        /// Holds the conflict rows native reads page and render.
        rows: ConflictRows,
        /// Tracks whether any member predicate differs from the identity one.
        across: bool,
        /// Names the whole or page part this read asks.
        part: ExtractionPart,
    },
    /// Carries a resolution final choice over its conflict rows and page answers.
    ResolutionFinal {
        /// Holds the conflict rows native reads page and render.
        rows: ConflictRows,
        /// Holds the checked page answers in page order.
        page_answers: Vec<Option<String>>,
    },
    /// Carries a conflict identity final round over its conflict rows and shortlist.
    IdentityFinal {
        /// Holds the conflict rows native reads page and render.
        rows: ConflictRows,
        /// Tracks whether any member predicate differs from the identity one.
        across: bool,
        /// Lists the target round shortlist in native order.
        shortlist: Vec<EntityId>,
        /// Names the requested one based target round.
        round: usize,
    },
}

impl CheckedExtractionRead {
    /// Builds the correction execution over `checked` and its `part` with the
    /// rebuilt `scope`, the queued branch `subject` and the attempt `correlation`.
    pub(super) fn correction(
        checked: CheckedPack,
        part: ExtractionPart,
        scope: Scope,
        subject: EntityId,
        correlation: EntityId,
    ) -> Self {
        let evidence = correction_evidence(&checked);
        let project = correction_project(&checked);
        Self {
            evidence,
            subject,
            scope,
            project,
            correlation,
            kind: CheckedReadKind::Correction {
                rows: checked.rows,
                pairs: checked.pairs,
                listed: checked.listed,
                part,
            },
        }
    }

    /// Builds the correction final execution over `checked` with the checked
    /// `position`, the target `shortlist` and `round`, the rebuilt `scope`,
    /// the queued branch `subject` and the attempt `correlation`.
    pub(super) fn correction_final(
        checked: CheckedPack,
        position: usize,
        shortlist: Vec<EntityId>,
        round: usize,
        scope: Scope,
        subject: EntityId,
        correlation: EntityId,
    ) -> Self {
        let evidence = correction_evidence(&checked);
        let project = correction_project(&checked);
        Self {
            evidence,
            subject,
            scope,
            project,
            correlation,
            kind: CheckedReadKind::CorrectionFinal {
                rows: checked.rows,
                listed: checked.listed,
                position,
                shortlist,
                round,
            },
        }
    }

    /// Builds the resolution execution over `built` and its `part` with the
    /// rebuilt `scope`.
    pub(super) fn resolution(built: BuiltConflict, part: ExtractionPart, scope: Scope) -> Self {
        let subject = built.identity.subject;
        let project = Some(built.identity.project);
        Self {
            evidence: built.evidence,
            subject,
            scope,
            project,
            correlation: built.correlation,
            kind: CheckedReadKind::Resolution {
                rows: built.rows,
                across: built.across,
                part,
            },
        }
    }

    /// Builds the resolution final execution over `built` with the checked
    /// `page_answers` and the rebuilt `scope`.
    pub(super) fn resolution_final(
        built: BuiltConflict,
        page_answers: Vec<Option<String>>,
        scope: Scope,
    ) -> Self {
        let subject = built.identity.subject;
        let project = Some(built.identity.project);
        Self {
            evidence: built.evidence,
            subject,
            scope,
            project,
            correlation: built.correlation,
            kind: CheckedReadKind::ResolutionFinal {
                rows: built.rows,
                page_answers,
            },
        }
    }

    /// Builds the identity final execution over `built` with the target
    /// `shortlist` and `round` and the rebuilt `scope`.
    pub(super) fn identity_final(
        built: BuiltConflict,
        shortlist: Vec<EntityId>,
        round: usize,
        scope: Scope,
    ) -> Self {
        let subject = built.identity.subject;
        let project = Some(built.identity.project);
        Self {
            evidence: built.evidence,
            subject,
            scope,
            project,
            correlation: built.correlation,
            kind: CheckedReadKind::IdentityFinal {
                rows: built.rows,
                across: built.across,
                shortlist,
                round,
            },
        }
    }

    /// Returns the native evidence in native order.
    pub(crate) fn evidence(&self) -> &[EntityId] {
        &self.evidence
    }

    /// Returns the read subject.
    pub(crate) fn subject(&self) -> EntityId {
        self.subject
    }

    /// Returns the engine's rebuilt native scope for the attempt.
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Returns the derived route project, or none when the read asks the owners.
    pub(crate) fn project(&self) -> Option<EntityId> {
        self.project
    }

    /// Returns the ask correlation of this read in this attempt.
    pub(crate) fn correlation(&self) -> EntityId {
        self.correlation
    }

    /// Builds this read's native questions, call labels and state with the held
    /// native wording.
    fn build_read(
        &self,
        decisions: &ConsolidationDecisions,
    ) -> Result<(Vec<DecisionQuestion>, CallLabelMap, serde_json::Value)> {
        match &self.kind {
            CheckedReadKind::Correction {
                rows,
                pairs,
                listed,
                part,
            } => build_correction_read(rows, pairs, listed, *part, decisions),
            CheckedReadKind::CorrectionFinal {
                rows,
                listed,
                position,
                shortlist,
                round,
            } => build_correction_final_read(rows, listed, *position, shortlist, *round, decisions),
            CheckedReadKind::Resolution { rows, across, part } => {
                build_resolution_read(rows, *across, *part, decisions)
            }
            CheckedReadKind::ResolutionFinal { rows, page_answers } => {
                build_resolution_final_read(rows, page_answers, decisions)
            }
            CheckedReadKind::IdentityFinal {
                rows,
                across,
                shortlist,
                round,
            } => build_identity_final_read(rows, *across, shortlist, *round, decisions),
        }
    }
}

/// Groups the execution context one checked read runs with.
pub(crate) struct ExtractionReadExecution<'a> {
    /// Borrows the vault the read runs in.
    pub(crate) vault: &'a Vault,
    /// Names the admitted attempt the read runs for.
    pub(crate) attempt: AttemptId,
    /// Holds the attempt recorded run, when it has one.
    pub(crate) run: Option<String>,
    /// Holds the Dreamer actor the read runs as.
    pub(crate) actor: WriteActor,
    /// Borrows the checked owned execution rows.
    pub(crate) execution: &'a CheckedExtractionRead,
    /// Borrows the native evidence versions in native evidence order.
    pub(crate) versions: &'a [EvidenceVersion],
    /// Holds the borrowed pass loan.
    pub(crate) loan: &'a ExtractionDecisionLoan<'a>,
    /// Holds the request deadline lowering in milliseconds, when it lowers the pass deadline.
    pub(crate) deadline_ms: Option<u64>,
    /// Holds the request ceiling lowering, when it lowers the native ceiling.
    pub(crate) ceiling: Option<DecisionRung>,
}

/// Runs one checked extraction read through the shared native pack read with the
/// lent wording, scope, route and evidence versions. The durable step uses the
/// admitted attempt, its recorded run, the caller actor and execution subject, the lent
/// pass deadline and frozen clock, no spend scope, and the pass bound guard.
/// The read sends unsourced, since the extraction call source rows are unknown.
pub(crate) async fn execute_checked_read(
    ctx: ExtractionReadExecution<'_>,
) -> DurableStepResult<Option<Vec<KeptDecision>>> {
    let step = DurableStepContext {
        vault: ctx.vault,
        attempt_id: ctx.attempt,
        run_id: ctx.run,
        envelope_actor: ctx.actor,
        subject: ctx.execution.subject(),
        deadline: Some(ctx.loan.deadline),
        now_ms: ctx.loan.now_ms,
        spend_scope: None,
        wake_pass_bound: true,
    };
    let (questions, labels, state) = ctx.execution.build_read(ctx.loan.decisions)?;
    let to = ask_route_for(ctx.vault, ctx.actor.entity_ref(), ctx.execution.project())?;
    let read = VerdictRead {
        step: &step,
        pass: ctx.loan.deadline,
        decider: Decider {
            decisions: ctx.loan.decisions,
            actor: ctx.actor,
            guard: ctx.loan.guard,
        },
        call: &ctx.loan.call,
        scope: ctx.execution.scope(),
        versions: ctx.versions,
        to: &to,
        correlation: ctx.execution.correlation(),
        evidence: ctx.execution.evidence(),
        state: &state,
        labels: &labels,
        sources: None,
        deadline_ms: ctx.deadline_ms,
        ceiling: ctx.ceiling,
    };
    decide_pack_with_charges(read, &questions, ChargeSink::Shared(ctx.loan.charges)).await
}

/// Builds the correction whole or page read over its checked rows: every asked
/// candidate with one question per option group, in native order, with the
/// native labels and state.
fn build_correction_read(
    rows: &[CheckedCandidate],
    pairs: &[(usize, usize)],
    listed: &[CorrectionListed],
    part: ExtractionPart,
    decisions: &ConsolidationDecisions,
) -> Result<(Vec<DecisionQuestion>, CallLabelMap, serde_json::Value)> {
    let pages = correction_page_entries(rows, pairs, listed);
    let (entries, page, mark) = match part {
        ExtractionPart::Whole => {
            let Some(first) = pages.first() else {
                return Err(invalid_consolidation(
                    "extraction pack part does not match its read",
                ));
            };
            if pages.len() != 1 {
                return Err(invalid_consolidation(
                    "extraction pack part does not match its read",
                ));
            }
            (first.as_slice(), None, PartMark::Whole)
        }
        ExtractionPart::Page { page, pages: count } => {
            if count < 2 || pages.len() != count {
                return Err(invalid_consolidation(
                    "extraction pack part does not match its read",
                ));
            }
            let Some(entries) = pages.get(page) else {
                return Err(invalid_consolidation(
                    "extraction pack part does not match its read",
                ));
            };
            (
                entries.as_slice(),
                Some(page),
                PartMark::Page { page, pages: count },
            )
        }
        ExtractionPart::Final { .. } => {
            return Err(invalid_consolidation(
                "extraction pack part does not match its read",
            ));
        }
    };
    let listed_ids: Vec<EntityId> = listed.iter().map(|row| row.claim).collect();
    let (asked, shown) = group_correction_asks(entries, &listed_ids);
    let mut labels = CallLabelMap::default();
    let mut questions = Vec::new();
    let mut asks: Vec<(usize, Vec<usize>)> = Vec::new();
    for (position, specs) in correction_choice_specs(&asked, page, &mut labels) {
        let mut questioned = Vec::new();
        for spec in specs {
            let owned: Vec<Vec<u8>> = spec.key.iter().map(key_part_bytes).collect();
            let key: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
            let question = CORRECTION.question(
                &key,
                decisions.correction_wording.clone(),
                AnswerContract::Choice {
                    options: spec.options,
                },
            )?;
            if let Some(shown) = spec.shown {
                labels.show_choices(question.id, shown);
            }
            questioned.push(questions.len());
            questions.push(question);
        }
        asks.push((position, questioned));
    }
    label_questions_with(
        decisions.ladder.paired.as_ref(),
        decisions.ladder.person.as_ref(),
        &mut labels,
        &questions,
    );
    let state =
        correction_execution_state(rows, listed, &asks, &questions, &shown, mark, &mut labels);
    Ok((questions, labels, state))
}

/// Builds the correction final target round over its checked rows: the one based
/// `round` over the checked `shortlist` for `position`, with the native labels
/// and state.
fn build_correction_final_read(
    rows: &[CheckedCandidate],
    listed: &[CorrectionListed],
    position: usize,
    shortlist: &[EntityId],
    round: usize,
    decisions: &ConsolidationDecisions,
) -> Result<(Vec<DecisionQuestion>, CallLabelMap, serde_json::Value)> {
    let base = [DecisionKeyPart::Number(position)];
    let mut labels = CallLabelMap::default();
    let mut questions = Vec::new();
    for spec in identity_round_specs(&base, true, shortlist, round, &mut labels) {
        let owned: Vec<Vec<u8>> = spec.key.iter().map(key_part_bytes).collect();
        let key: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        let question = CORRECTION.question(
            &key,
            decisions.correction_wording.clone(),
            AnswerContract::Choice {
                options: spec.options,
            },
        )?;
        if let Some(shown) = spec.shown {
            labels.show_choices(question.id, shown);
        }
        questions.push(question);
    }
    label_questions_with(
        decisions.ladder.paired.as_ref(),
        decisions.ladder.person.as_ref(),
        &mut labels,
        &questions,
    );
    let shown: Vec<usize> = shortlist
        .iter()
        .filter_map(|id| listed.iter().position(|row| row.claim == *id))
        .collect();
    let asks = [(position, (0..questions.len()).collect())];
    let state = correction_execution_state(
        rows,
        listed,
        &asks,
        &questions,
        &shown,
        PartMark::Final,
        &mut labels,
    );
    Ok((questions, labels, state))
}

/// Renders the correction state over its asked candidates and shown listed claims
/// with the already assigned call labels.
fn correction_execution_state(
    rows: &[CheckedCandidate],
    listed: &[CorrectionListed],
    asks: &[(usize, Vec<usize>)],
    questions: &[DecisionQuestion],
    shown: &[usize],
    mark: PartMark,
    labels: &mut CallLabelMap,
) -> serde_json::Value {
    let mut candidates = Vec::new();
    for (position, asked) in asks {
        let Some(row) = rows.get(*position) else {
            continue;
        };
        let refs: Vec<String> = asked
            .iter()
            .filter_map(|at| questions.get(*at))
            .map(|question| labels.assign(LabelKind::Question, question.id).to_string())
            .collect();
        let subject = labels.assign(LabelKind::Entity, row.subject).to_string();
        candidates.push(NumberedCorrectionCandidate {
            questions: refs,
            subject,
            predicate: Some(row.predicate.clone()),
            value_text: row.value_text.clone(),
        });
    }
    let listed_rows: Vec<NumberedListedClaim> = shown
        .iter()
        .filter_map(|at| listed.get(*at))
        .map(|row| NumberedListedClaim {
            claim: labels.assign(LabelKind::Claim, row.claim).to_string(),
            subject: labels.assign(LabelKind::Entity, row.subject).to_string(),
            predicate: row.predicate.clone(),
            value_text: row.value_text.clone(),
        })
        .collect();
    render_correction_state(candidates, listed_rows, mark)
}

/// Builds the resolution whole or page read over its conflict rows: how the
/// conflict resolves, then which members a merge keeps, in native order, with
/// the native labels and state.
fn build_resolution_read(
    rows: &ConflictRows,
    across: bool,
    part: ExtractionPart,
    decisions: &ConsolidationDecisions,
) -> Result<(Vec<DecisionQuestion>, CallLabelMap, serde_json::Value)> {
    let pages = rows.pages();
    let (shown, page, state_part) = match part {
        ExtractionPart::Whole => {
            let Some(first) = pages.first() else {
                return Err(invalid_consolidation(
                    "extraction pack part does not match its read",
                ));
            };
            if pages.len() != 1 {
                return Err(invalid_consolidation(
                    "extraction pack part does not match its read",
                ));
            }
            (first.as_slice(), None, StatePart::Whole)
        }
        ExtractionPart::Page { page, pages: count } => {
            if count < 2 || pages.len() != count {
                return Err(invalid_consolidation(
                    "extraction pack part does not match its read",
                ));
            }
            let Some(shown) = pages.get(page) else {
                return Err(invalid_consolidation(
                    "extraction pack part does not match its read",
                ));
            };
            (
                shown.as_slice(),
                Some(page),
                StatePart::Page { page, pages: count },
            )
        }
        ExtractionPart::Final { .. } => {
            return Err(invalid_consolidation(
                "extraction pack part does not match its read",
            ));
        }
    };
    let ids = rows.ids(shown);
    let mut labels = CallLabelMap::default();
    let resolution = resolution_choice_spec(page);
    let mut questions = vec![{
        let owned: Vec<Vec<u8>> = resolution.key.iter().map(key_part_bytes).collect();
        let key: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        CONFLICT_RESOLUTION.question(
            &key,
            decisions.resolution_wording.clone(),
            AnswerContract::Choice {
                options: resolution.options,
            },
        )?
    }];
    for spec in conflict_identity_specs(&ids, !across || page.is_some(), page, &mut labels) {
        let owned: Vec<Vec<u8>> = spec.key.iter().map(key_part_bytes).collect();
        let key: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        let question = CONFLICT_RESOLUTION.question(
            &key,
            decisions.identity_wording.clone(),
            AnswerContract::Choice {
                options: spec.options,
            },
        )?;
        if let Some(shown) = spec.shown {
            labels.show_choices(question.id, shown);
        }
        questions.push(question);
    }
    label_questions_with(
        decisions.ladder.paired.as_ref(),
        decisions.ladder.person.as_ref(),
        &mut labels,
        &questions,
    );
    let state = rows.state(shown, state_part, &mut labels);
    Ok((questions, labels, state))
}

/// Builds the resolution final choice over its conflict rows with the checked page
/// answers beside every member whole.
fn build_resolution_final_read(
    rows: &ConflictRows,
    page_answers: &[Option<String>],
    decisions: &ConsolidationDecisions,
) -> Result<(Vec<DecisionQuestion>, CallLabelMap, serde_json::Value)> {
    let spec = resolution_final_prep(page_answers);
    let owned: Vec<Vec<u8>> = spec.key.iter().map(key_part_bytes).collect();
    let key: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    let question = CONFLICT_RESOLUTION.question(
        &key,
        decisions.resolution_wording.clone(),
        AnswerContract::Choice {
            options: spec.options,
        },
    )?;
    let questions = vec![question];
    let mut labels = CallLabelMap::default();
    label_questions_with(
        decisions.ladder.paired.as_ref(),
        decisions.ladder.person.as_ref(),
        &mut labels,
        &questions,
    );
    let mut state = rows.state(&rows.all(), StatePart::Final, &mut labels);
    if let serde_json::Value::Object(fields) = &mut state {
        fields.insert("page_answers".to_owned(), serde_json::json!(page_answers));
    }
    Ok((questions, labels, state))
}

/// Builds the conflict identity final target round over its conflict rows: the one
/// based `round` over the checked `shortlist`, with the native labels and state.
fn build_identity_final_read(
    rows: &ConflictRows,
    across: bool,
    shortlist: &[EntityId],
    round: usize,
    decisions: &ConsolidationDecisions,
) -> Result<(Vec<DecisionQuestion>, CallLabelMap, serde_json::Value)> {
    let base = [DecisionKeyPart::Text("identity")];
    let mut labels = CallLabelMap::default();
    let mut questions = Vec::new();
    for spec in identity_round_specs(&base, !across, shortlist, round, &mut labels) {
        let owned: Vec<Vec<u8>> = spec.key.iter().map(key_part_bytes).collect();
        let key: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        let question = CONFLICT_RESOLUTION.question(
            &key,
            decisions.identity_wording.clone(),
            AnswerContract::Choice {
                options: spec.options,
            },
        )?;
        if let Some(shown) = spec.shown {
            labels.show_choices(question.id, shown);
        }
        questions.push(question);
    }
    label_questions_with(
        decisions.ladder.paired.as_ref(),
        decisions.ladder.person.as_ref(),
        &mut labels,
        &questions,
    );
    let state = rows.state(&rows.indexes(shortlist), StatePart::Final, &mut labels);
    Ok((questions, labels, state))
}
