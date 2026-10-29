//! A conflict set's resolution: the typed pack (how it resolves, and which candidate's
//! identity a merge keeps), then the resolved value as generation beside the decision.
//!
//! Every value rides whole (Rule 5, FIX 7637). A pack whose state does not fit one read is
//! asked in pages, each with every prior head and some of the candidates: each page reads
//! the resolution and its own candidates' identity groups. A page that escalates or reads
//! no resolution leaves the contradiction standing, as one read's escalation does; pages
//! that all read one resolution give it; pages that read different ones get one final
//! choice over the resolutions they read, every member whole and each page's answer beside
//! them, and its answer is the pack's. The identity a merge or supersede keeps is the one
//! final choice over the ids the groups named (FIX 8693).

use super::decisions::{ConflictRows, FinalChoice, StatePart, id_options};
use super::*;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::provenance::KeptDecision;
use crate::dreamer_consolidation::settle::decision_pages::measure_state;
use crate::dreamer_wake::WakePassDeadline;
use crate::llm::decision::catalogue::CONFLICT_RESOLUTION;
use crate::llm::decision::{AnswerContract, AskTo, DecisionAnswer, DecisionQuestion};

/// A conflict's resolutions. With no prior head in scope, supersede degrades to merge (D7:
/// at most one prior head; the promotion writer owns the supersession).
const RESOLUTIONS: [&str; 4] = ["merge", "supersede", "accumulate", ESCALATE];
/// The resolution that leaves the contradiction standing.
const ESCALATE: &str = "escalate";

/// The resolution a final choice reads, if any, and its decisions.
type FinalResolution = (Option<String>, Vec<KeptDecision>);

pub(super) enum MergeResolution {
    Merge {
        value: Value,
        candidate_ref: Option<EntityId>,
    },
    Accumulate,
    Escalate,
}

/// What a conflict's pack decided: its resolution, when one was read, the listed
/// candidate whose identity a merge keeps, and every decision as the write keeps it.
pub(super) struct ConflictAnswers {
    pub(super) resolution: Option<String>,
    pub(super) identity: Option<EntityId>,
    pub(super) decisions: Vec<KeptDecision>,
}

impl ConflictAnswers {
    /// Whether a question went up the role chain and waits on its answer: the
    /// conflict waits with it, neither resolved nor left standing.
    pub(super) fn waiting(&self) -> bool {
        self.decisions.iter().any(KeptDecision::waiting)
    }
}

impl ConsolidationExecutor<'_> {
    /// The conflict's typed pack: how it resolves, and which listed candidate's identity a
    /// merge keeps (a merge across predicates must name one). An ask goes to the route of
    /// the conflict's project. None when the step trapped. Each read shows its questions,
    /// claims and identity options by its own call's labels (FIX 7506).
    #[expect(
        clippy::too_many_arguments,
        reason = "the step, its pass clock and branch join the conflict and the charge tally"
    )]
    pub(super) async fn decide_conflict(
        &self,
        step_ctx: &DurableStepContext<'_>,
        pass: &WakePassDeadline,
        conflict: &ConflictSet,
        members: &[&super::super::evidence::VerifiedCandidate],
        prior_heads: &[super::super::PriorHead],
        resources: &BranchResources<'_>,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<Option<ConflictAnswers>> {
        let across = members.iter().any(|member| {
            candidate_facts(&member.candidate)
                .is_ok_and(|facts| facts.predicate != conflict.identity.predicate)
        });
        // The pack reads the prior heads and candidates drawn from these turns. The
        // turns also keep one conflict's ask apart from another's on the same heads.
        let mut evidence: Vec<EntityId> = prior_heads.iter().map(|prior| prior.claim_id).collect();
        let mut turns: Vec<EntityId> = members
            .iter()
            .flat_map(|member| member.evidence_turn_refs.iter().copied())
            .filter(|turn| !evidence.contains(turn))
            .collect();
        turns.sort_unstable();
        turns.dedup();
        evidence.extend(turns);
        let to = self.ask_route(step_ctx.vault, Some(conflict.identity.project))?;
        // The ask is this conflict's in this attempt: its open-marker id.
        let key =
            crate::dreamer_consolidation::conflict_open_marker_id(conflict, step_ctx.attempt_id)?;
        let rows = ConflictRows::of(&conflict.identity, members, prior_heads)?;
        let pages = rows.pages();
        let mut resolutions = Vec::with_capacity(pages.len());
        let mut page_sources: Vec<Option<Vec<EntityId>>> = Vec::with_capacity(pages.len());
        let mut groups = Vec::new();
        let mut decisions = Vec::new();
        for (page, shown) in pages.iter().enumerate() {
            let part = if pages.len() > 1 {
                StatePart::Page {
                    page,
                    pages: pages.len(),
                }
            } else {
                StatePart::Whole
            };
            let mut labels = CallLabelMap::default();
            let questions = self.conflict_questions(&rows.ids(shown), across, part, &mut labels)?;
            let state = rows.state(shown, part, &mut labels);
            measure_state(step_ctx.vault, &state);
            let sources = conflict_sources(members, &evidence, &labels);
            page_sources.push(sources.clone());
            let Some(decided) = self
                .decide(
                    step_ctx, pass, resources, &to, key, &questions, &evidence, &state, &labels,
                    sources, charges,
                )
                .await?
            else {
                return Ok(None);
            };
            resolutions.push(match decided.first().and_then(KeptDecision::answer) {
                Some(DecisionAnswer::Choice(label)) => Some(label.clone()),
                _ => None,
            });
            groups.extend(decided.iter().skip(1).cloned());
            decisions.extend(decided);
        }
        let resolution = match resolutions.as_slice() {
            [only] => only.clone(),
            // A page that escalates or reads none leaves the contradiction standing.
            paged
                if paged
                    .iter()
                    .any(|read| read.as_deref().is_none_or(|label| label == ESCALATE)) =>
            {
                None
            }
            [first, rest @ ..] if rest.iter().all(|other| other == first) => first.clone(),
            paged => {
                let Some((chosen, finals)) = self
                    .final_resolution(
                        step_ctx,
                        pass,
                        resources,
                        &to,
                        key,
                        &evidence,
                        &rows,
                        members,
                        paged,
                        &page_sources,
                        charges,
                    )
                    .await?
                else {
                    return Ok(None);
                };
                decisions.extend(finals);
                chosen
            }
        };
        // Only a merge or supersede keeps an identity, so only one asks the final choice.
        let mut identity = None;
        if matches!(resolution.as_deref(), Some("merge" | "supersede")) {
            let identity_key: [&[u8]; 1] = [b"identity"];
            let choice = FinalChoice {
                family: &CONFLICT_RESOLUTION,
                key: &identity_key,
                wording: &self.decisions.identity_wording,
                none: !across,
            };
            let state =
                |shortlist: &[EntityId], _: &[DecisionQuestion], labels: &mut CallLabelMap| {
                    rows.state(&rows.indexes(shortlist), StatePart::Final, labels)
                };
            let sources_for = |_: &[EntityId], labels: &CallLabelMap| {
                conflict_sources(members, &evidence, labels)
            };
            let Some((chosen, finals)) = self
                .choose_identity(
                    step_ctx,
                    pass,
                    resources,
                    &to,
                    key,
                    &evidence,
                    &choice,
                    &groups,
                    &state,
                    &sources_for,
                    charges,
                )
                .await?
            else {
                return Ok(None);
            };
            identity = chosen;
            decisions.extend(finals);
        }
        Ok(Some(ConflictAnswers {
            resolution,
            identity,
            decisions,
        }))
    }

    /// The one final resolution of a paged pack whose pages read different ones (the
    /// module's rule): a choice over the resolutions `read` gives, in page order, every
    /// member whole and each page's answer beside them, with its decisions. None when the
    /// step trapped.
    #[expect(
        clippy::too_many_arguments,
        reason = "the pack's step, clock, branch, route and evidence join its rows and pages"
    )]
    async fn final_resolution(
        &self,
        step_ctx: &DurableStepContext<'_>,
        pass: &WakePassDeadline,
        resources: &BranchResources<'_>,
        to: &AskTo,
        key: EntityId,
        evidence: &[EntityId],
        rows: &ConflictRows,
        members: &[&super::super::evidence::VerifiedCandidate],
        read: &[Option<String>],
        page_sources: &[Option<Vec<EntityId>>],
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<Option<FinalResolution>> {
        let mut options: Vec<String> = Vec::new();
        for label in read.iter().flatten() {
            if !options.contains(label) {
                options.push(label.clone());
            }
        }
        let question = CONFLICT_RESOLUTION.question(
            &[b"resolution".as_slice(), b"final".as_slice()],
            self.decisions.resolution_wording.clone(),
            AnswerContract::Choice { options },
        )?;
        let questions = vec![question];
        let mut labels = CallLabelMap::default();
        self.label_questions(&mut labels, &questions);
        let mut state = rows.state(&rows.all(), StatePart::Final, &mut labels);
        if let serde_json::Value::Object(fields) = &mut state {
            fields.insert("page_answers".to_owned(), serde_json::json!(read));
        }
        measure_state(step_ctx.vault, &state);
        // The final read renders earlier pages' answers: each was read
        // from its page's rows, so the read sends under their union too.
        let sources = crate::skill_optimize::union_source_rows(
            std::iter::once(conflict_sources(members, evidence, &labels))
                .chain(page_sources.iter().cloned()),
        );
        let Some(decided) = self
            .decide(
                step_ctx, pass, resources, to, key, &questions, evidence, &state, &labels, sources,
                charges,
            )
            .await?
        else {
            return Ok(None);
        };
        let chosen = match decided.first().and_then(KeptDecision::answer) {
            Some(DecisionAnswer::Choice(label)) => Some(label.clone()),
            _ => None,
        };
        Ok(Some((chosen, decided)))
    }

    /// One read's questions over the candidates `ids`: how the conflict resolves, then
    /// which of them a merge keeps, in option groups, each group's options shown by
    /// `labels`. A paged read offers `none` in every group, since the
    /// identity may be on another page, and keys its questions by its page.
    fn conflict_questions(
        &self,
        ids: &[EntityId],
        across: bool,
        part: StatePart,
        labels: &mut CallLabelMap,
    ) -> Result<Vec<DecisionQuestion>> {
        let page = match part {
            StatePart::Page { page, .. } => Some(page.to_string()),
            StatePart::Whole | StatePart::Final => None,
        };
        let paging: Vec<&[u8]> = page
            .iter()
            .flat_map(|page| [b"page".as_slice(), page.as_bytes()])
            .collect();
        let mut key: Vec<&[u8]> = vec![b"resolution".as_slice()];
        key.extend(&paging);
        let mut questions = vec![
            CONFLICT_RESOLUTION.question(
                &key,
                self.decisions.resolution_wording.clone(),
                AnswerContract::Choice {
                    options: RESOLUTIONS
                        .iter()
                        .map(|label| (*label).to_owned())
                        .collect(),
                },
            )?,
        ];
        for (group, (options, shown)) in id_options(ids, !across || page.is_some(), labels)
            .into_iter()
            .enumerate()
        {
            let group = group.to_string();
            let mut key: Vec<&[u8]> = vec![b"identity".as_slice(), group.as_bytes()];
            key.extend(&paging);
            let question = CONFLICT_RESOLUTION.question(
                &key,
                self.decisions.identity_wording.clone(),
                AnswerContract::Choice { options },
            )?;
            labels.show_choices(question.id, shown);
            questions.push(question);
        }
        self.label_questions(labels, &questions);
        Ok(questions)
    }

    /// The value a decided merge or supersede writes, generated beside the decision under
    /// the rules in force at that moment (H398); a reply that names none escalates. None
    /// when the step trapped.
    #[expect(
        clippy::too_many_arguments,
        reason = "the decided resolution and identity join the conflict and the charge tally"
    )]
    pub(super) async fn merged_value(
        &self,
        step_ctx: &DurableStepContext<'_>,
        resolution: &str,
        identity: Option<EntityId>,
        conflict: &ConflictSet,
        members: &[&PromotionCandidate],
        prior_heads: &[super::super::PriorHead],
        scope: &crate::llm::Scope,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<Option<MergeResolution>> {
        let call = self.role(DREAMER_VERDICT_ROLE);
        let mut request = Self::value_request(
            &call,
            resolution,
            identity,
            &conflict.identity,
            members,
            prior_heads,
            scope,
        )?;
        if let Some(rules) = failure_rules::load(step_ctx.vault)? {
            rules.bind(Stage::Conflict, &mut request);
        }
        let mut request = step_ctx
            .vault
            .authorize_model_role(DREAMER_VERDICT_ROLE, request, &call.inference)?
            .into_request();
        super::super::roles::bind_reasoning(step_ctx.vault, call.backend, &mut request)?;
        let step_hash = request.canonical_hash()?;
        let outcome = call_as_step(step_ctx, call.backend, self.guard, request).await;
        let response = match outcome? {
            StepOutcome::Finished { response, .. } => response,
            StepOutcome::Trapped { .. } => return Ok(None),
        };
        charges.record_terminal(
            step_ctx.vault,
            step_ctx.attempt_id,
            step_hash,
            &response.usage,
        )?;
        let rules = failure_rules::load(step_ctx.vault)?;
        if rules.is_some_and(|rules| !rules.accepts(Stage::Conflict, &response)) {
            return Ok(Some(MergeResolution::Escalate));
        }
        // A decision that names no value writes no claim: it parks as an open conflict.
        Ok(Some(match decode_merged_value(&response) {
            Some(value) => MergeResolution::Merge {
                value,
                candidate_ref: identity,
            },
            None => MergeResolution::Escalate,
        }))
    }

    /// The resolved-value request: each claim by its call-local label
    /// (FIX 7506), the map bound into the request's identity.
    fn value_request(
        call: &RoleCall<'_>,
        resolution: &str,
        kept: Option<EntityId>,
        identity: &ConflictIdentity,
        members: &[&PromotionCandidate],
        prior_heads: &[super::super::PriorHead],
        scope: &crate::llm::Scope,
    ) -> Result<LlmRequest> {
        let mut labels = CallLabelMap::default();
        let mut lines = format!("resolution {resolution}\n");
        if let Some(kept) = kept {
            lines.push_str(&format!(
                "keeps candidate_ref {}\n",
                labels.assign(LabelKind::Claim, kept)
            ));
        }
        lines.push_str(&format!("predicate {}\n", identity.predicate));
        for prior in prior_heads {
            let claim = labels.assign(LabelKind::Claim, prior.claim_id).to_string();
            lines.push_str(
                &serde_json::json!({"prior_head": claim,
                "predicate": prior.body.predicate,
                "source": prior.body.source.map(crate::claim::ClaimSource::as_str),
                "value": rmpv_to_json(&prior.body.value)})
                .to_string(),
            );
            lines.push('\n');
        }
        for member in members {
            let facts = candidate_facts(&member.candidate)?;
            lines.push_str(&format!(
                "- candidate_ref: {} predicate: {} value: {}\n",
                labels.assign(LabelKind::Claim, member.claim_id),
                facts.predicate,
                serde_json::to_string(&rmpv_to_json(&facts.value)).unwrap_or_default()
            ));
        }
        let system = "Conflicting values were extracted for one claim identity, and they \
             resolve into one claim. Respond with JSON: {\"value\": <the resolved claim's \
             value as JSON>}. On supersede the value is the newest one stated; on merge it is \
             one value that holds what the candidates state.";
        let mut request = LlmRequest {
            model: call.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: scope.clone(),
                purpose: CallPurpose::Consolidation,
                class: CallClass::Durable {
                    fallback: crate::llm::DeterministicFallback {
                        name: "json_rules_v1".into(),
                        config: Some(
                            serde_json::json!({"version":1,"rows":[{"failure":"fatal","value":{"value":null}}]}),
                        ),
                    },
                },
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Consolidation,
                    ModelTierRef("consolidation".into()),
                ),
                response_format: ResponseFormat::Json {
                    schema: serde_json::json!({"type": "object", "properties": {"value": {}}}),
                },
                locality: call.inference.selected_locality().ok_or_else(||
                    crate::Error::InvalidConfig("consolidation host binding needs locality".into()))?,
            }.with_purpose_defaults(),
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: system.to_owned(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text { text: lines }],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        labels.bind_request(&mut request, None);
        Ok(request)
    }
}

/// The rows one conflict read sends under (FIX 11526): every member's
/// extraction rows (a superset of the members a page shows), the pack's
/// evidence, and the stored rows its labels name, never a candidate's
/// unwritten claim id. `None` when a member's rows are not known.
fn conflict_sources(
    members: &[&super::super::evidence::VerifiedCandidate],
    evidence: &[EntityId],
    labels: &CallLabelMap,
) -> Option<Vec<EntityId>> {
    let stored: Vec<EntityId> = evidence
        .iter()
        .copied()
        .chain(
            labels
                .rows()
                .filter(|id| !members.iter().any(|member| member.claim_id == *id)),
        )
        .collect();
    crate::skill_optimize::union_source_rows(
        members
            .iter()
            .map(|member| member.sources.clone())
            .chain(std::iter::once(Some(stored))),
    )
}

/// The non-null `value` a resolved-value reply names, if any.
fn decode_merged_value(response: &LlmResponse) -> Option<Value> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let parsed: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    parsed
        .get("value")
        .filter(|value| !value.is_null())
        .map(json_to_rmpv)
}
