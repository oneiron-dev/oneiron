//! The consolidation's typed questions through the host's ladder: how a conflict set
//! resolves and which candidate's identity a merge keeps, and which listed claim an
//! extracted candidate corrects. The verdict role's generation is each pack's first read.

use serde_json::json;

use super::*;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::provenance::KeptDecision;
use crate::dreamer_consolidation::settle::decision_pages::{json_len, split_pages};
use crate::dreamer_wake::WakePassDeadline;
use crate::llm::BoundedAutoChecker;
use crate::llm::decision::{AskRole, AskTo, DecisionAsk, HeldLadder, TypedDecision};
use crate::model_decision::AnswerActor;
use crate::model_decision::{
    AskAct, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionQuestion, DecisionRung,
    HumanAskReason, MAX_DECISION_STATE_BYTES, RoleRank,
};

pub(in crate::dreamer_consolidation) mod identity_choice;
#[cfg(oneiron_test_support)]
mod native_parity;
mod read;
pub(super) use identity_choice::FinalChoice;
#[cfg(oneiron_test_support)]
pub(crate) use native_parity::{
    NativeFixtureMember, NativePackOutcome, NativeResolutionFixture,
    native_resolution_snapshot_for_test,
};
pub(in crate::dreamer_consolidation) use read::{Decider, ScopedRead};

/// The answer that names no listed id.
pub(in crate::dreamer_consolidation) const NONE: &str = "none";
/// The most ids one choice offers beside [`NONE`]; the contract allows 64 options.
const IDS_PER_QUESTION: usize = 63;
/// How long work waiting on a role's answer sits before the attempt reads
/// the ask again (CALLS: Dreamer ask recheck).
pub(super) const ASK_RECHECK_MS: u64 = 15 * 60 * 1_000;
/// The highest rung a Dreamer verdict reads at. The Dreamer applies its own
/// verdict and the owner reverts it (owner ruling 10-18, "autoapply + revert
/// rather than holdout"), so no verdict goes up to a role and holds its
/// work: one still in band at this rung escalates, and its pair parks as an
/// open conflict the Dreamer's own review settles.
const VERDICT_CEILING: DecisionRung = DecisionRung::Big;
/// The highest role a Dreamer verdict's ask climbs to, and what its answer
/// authorises (CALLS: Dreamer ask route), were [`VERDICT_CEILING`] the person
/// rung.
const ASK_CEILING: RoleRank = RoleRank::Owner;
const ASK_ACT: AskAct = AskAct::Judgment;

/// The host's ladder for the Dreamer's typed questions, the dial and learned bands they
/// route under, and its wording of each question. The verdict role's generated read sits at
/// the dial's first rung, in place of that slot's provider.
#[derive(Clone)]
pub struct ConsolidationDecisions {
    pub ladder: HeldLadder,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    /// How a conflict set resolves.
    pub resolution_wording: String,
    /// Which candidate's identity a merge keeps.
    pub identity_wording: String,
    /// Which listed claim an extracted candidate corrects.
    pub correction_wording: String,
    /// Whether a sieve span's mention is new information (OF-498a).
    pub sieve_novelty_wording: String,
    /// Which span kind a sieve span is.
    pub sieve_kind_wording: String,
    /// Which supplied candidate, if any, a sieve span names.
    pub sieve_entity_wording: String,
    /// How sure a sieve reading is, as an integer percent.
    pub sieve_confidence_wording: String,
    /// Whether two claims different children of one night proposed state the
    /// same thing (OF-498d): same_as, no_link or unresolved.
    pub nightly_link_wording: String,
    /// Whether an Arc's cited TURN should be opened beside the current claims.
    pub arc_open_wording: String,
    /// The host's write-gate auto check, when it runs one. `None` promotes
    /// without a check, as before.
    pub checker: Option<BoundedAutoChecker>,
}

impl ConsolidationDecisions {
    /// The shipped wording on an unstaffed ladder: the verdict role's read, at the big
    /// rung, is the one rung, and every band starts in shadow.
    pub fn shipped() -> Result<Self> {
        let wording: Wording = serde_json::from_str(include_str!("decision_wording.json"))
            .map_err(|_| invalid_consolidation("shipped decision wording is not readable"))?;
        Ok(Self {
            ladder: HeldLadder::unstaffed(),
            dial: DecisionDial {
                first: DecisionRung::Big,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            bands: DecisionBandPolicy::default(),
            resolution_wording: wording.resolution,
            identity_wording: wording.identity,
            correction_wording: wording.correction,
            sieve_novelty_wording: wording.sieve_novelty,
            sieve_kind_wording: wording.sieve_kind,
            sieve_entity_wording: wording.sieve_entity,
            sieve_confidence_wording: wording.sieve_confidence,
            nightly_link_wording: wording.nightly_link,
            arc_open_wording: wording.arc_open,
            checker: None,
        })
    }

    /// The decisions, each NOTE review promotion through `checker`'s auto
    /// check.
    #[must_use]
    pub fn with_checker(mut self, checker: Option<BoundedAutoChecker>) -> Self {
        self.checker = checker;
        self
    }
}

/// The shipped wording, as data.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Wording {
    resolution: String,
    identity: String,
    correction: String,
    sieve_novelty: String,
    sieve_kind: String,
    sieve_entity: String,
    sieve_confidence: String,
    nightly_link: String,
    arc_open: String,
}

/// `ids` as a choice's option groups, each of at most [`IDS_PER_QUESTION`] ids, with
/// [`NONE`] first when `none` holds or there is more than one group. Each group comes with
/// the same options as its call shows them (FIX 7506): every id by its claim label in
/// `labels`, [`NONE`] as it is. The canonical options are the question's; the shown ones
/// go on the wire only.
pub(super) fn id_options(
    ids: &[EntityId],
    none: bool,
    labels: &mut CallLabelMap,
) -> Vec<(Vec<String>, Vec<String>)> {
    choice_groups(ids.len(), none)
        .into_iter()
        .map(|group| {
            let options: Vec<String> = group
                .iter()
                .map(|slot| match slot {
                    None => NONE.to_owned(),
                    Some(at) => ids[*at].to_hex(),
                })
                .collect();
            let shown: Vec<String> = group
                .iter()
                .map(|slot| match slot {
                    None => NONE.to_owned(),
                    Some(at) => labels.assign(LabelKind::Claim, ids[*at]).to_string(),
                })
                .collect();
            (options, shown)
        })
        .collect()
}

/// One typed key part shared by every extraction question builder: native text
/// verbatim, or a number in decimal. Both paths build the same parts while
/// native projects them to question key bytes and the bound path maps them to
/// wire text, so the two can never drift on values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dreamer_consolidation) enum DecisionKeyPart {
    /// Native text, rendered verbatim.
    Text(&'static str),
    /// A number, rendered in decimal.
    Number(usize),
}

/// `part` as question key bytes: text verbatim, a number in decimal. Native
/// question building projects every shared part through this function, so a
/// rebuilt key and its native question carry the same bytes.
pub(in crate::dreamer_consolidation) fn key_part_bytes(part: &DecisionKeyPart) -> Vec<u8> {
    match part {
        DecisionKeyPart::Text(text) => text.as_bytes().to_vec(),
        DecisionKeyPart::Number(number) => number.to_string().into_bytes(),
    }
}

/// `raw` as one wire key part: native text and decimal verbatim, a binary part
/// in lowercase hexadecimal. The binary arm is caller-directed through
/// `binary`, never a sniff of the bytes; every current call site passes text
/// or decimal with `binary` false, and a future binary part passes true.
pub(in crate::dreamer_consolidation) fn key_part_text(raw: &[u8], binary: bool) -> String {
    if binary {
        return hex_lower(raw);
    }
    match std::str::from_utf8(raw) {
        Ok(text) => text.to_owned(),
        Err(_) => hex_lower(raw),
    }
}

/// `bytes` in lowercase hexadecimal.
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    text
}

/// `total` option slots as choice groups: each group holds at most
/// [`IDS_PER_QUESTION`] indexes with [`NONE`] first when `none` holds or
/// there is more than one group. `None` renders [`NONE`]; `Some` renders the
/// id at its index. Native option building and the bound rebuild share this
/// grouping, so both lay out the same groups.
pub(in crate::dreamer_consolidation) fn choice_groups(
    total: usize,
    none: bool,
) -> Vec<Vec<Option<usize>>> {
    let none = none || total > IDS_PER_QUESTION;
    let mut groups = Vec::new();
    let mut start = 0;
    while start < total {
        let end = (start + IDS_PER_QUESTION).min(total);
        let mut group = Vec::with_capacity(end - start + usize::from(none));
        if none {
            group.push(None);
        }
        group.extend((start..end).map(Some));
        groups.push(group);
        start = end;
    }
    groups
}

/// One prepared Choice question: its shared key parts with its canonical
/// options, and the shown texts native registers, if it shows any. Native
/// applies its lent wording to each spec afterwards; the bound rebuild maps
/// the keys to wire text and checks the options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::dreamer_consolidation) struct ChoiceSpec {
    /// The shared key parts of the question, in order.
    pub(in crate::dreamer_consolidation) key: Vec<DecisionKeyPart>,
    /// The canonical options in native order.
    pub(in crate::dreamer_consolidation) options: Vec<String>,
    /// The shown texts native registers with the question, or `None` where
    /// native shows the options as they are.
    pub(in crate::dreamer_consolidation) shown: Option<Vec<String>>,
}

/// Which part mark a rendered state carries: the whole pack, one page of it,
/// or a final choice. This mirrors [`StatePart`] for callers outside the
/// executor, which cannot name that type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dreamer_consolidation) enum PartMark {
    /// The whole pack in one read.
    Whole,
    /// One page of a paged pack, zero-based below the page count.
    Page { page: usize, pages: usize },
    /// A final choice.
    Final,
}

impl From<StatePart> for PartMark {
    /// `part` as the mark a shared renderer applies.
    fn from(part: StatePart) -> Self {
        match part {
            StatePart::Whole => Self::Whole,
            StatePart::Page { page, pages } => Self::Page { page, pages },
            StatePart::Final => Self::Final,
        }
    }
}

impl PartMark {
    /// `state` marked as this part's: a page says which of how many, a final
    /// choice says it is one. This is the one marking both native states and
    /// the bound rebuild apply.
    pub(in crate::dreamer_consolidation) fn apply(
        self,
        mut state: serde_json::Value,
    ) -> serde_json::Value {
        if let serde_json::Value::Object(fields) = &mut state {
            match self {
                Self::Whole => {}
                Self::Page { page, pages } => {
                    fields.insert("page".to_owned(), json!(page + 1));
                    fields.insert("pages".to_owned(), json!(pages));
                }
                Self::Final => {
                    fields.insert("final_choice".to_owned(), json!(true));
                }
            }
        }
        state
    }
}

/// One conflict candidate as a shared state render takes it: its claim label
/// already assigned, with its predicate and whole value.
#[derive(Debug, Clone)]
pub(in crate::dreamer_consolidation) struct NumberedConflictCandidate {
    /// The claim label the read assigned, such as `C1`.
    pub(in crate::dreamer_consolidation) claim: String,
    /// The candidate predicate.
    pub(in crate::dreamer_consolidation) predicate: String,
    /// The whole candidate value.
    pub(in crate::dreamer_consolidation) value: serde_json::Value,
}

/// One prior head as a shared state render takes it: its claim label already
/// assigned, with its predicate, source name and whole value.
#[derive(Debug, Clone)]
pub(in crate::dreamer_consolidation) struct NumberedPriorHead {
    /// The claim label the read assigned, such as `C2`.
    pub(in crate::dreamer_consolidation) claim: String,
    /// The head predicate.
    pub(in crate::dreamer_consolidation) predicate: String,
    /// The head source name, when it has one.
    pub(in crate::dreamer_consolidation) source: Option<String>,
    /// The whole head value.
    pub(in crate::dreamer_consolidation) value: serde_json::Value,
}

/// The conflict state over `priors` and `candidates`: the predicate, every
/// prior head and each candidate whole, marked as `mark`'s. Native conflict
/// reads and the bound rebuild render through this function with the same
/// label order, so both measure the same bytes.
pub(in crate::dreamer_consolidation) fn render_conflict_state(
    predicate: &str,
    priors: Vec<NumberedPriorHead>,
    candidates: Vec<NumberedConflictCandidate>,
    mark: PartMark,
) -> serde_json::Value {
    let candidates: Vec<serde_json::Value> = candidates
        .into_iter()
        .map(|row| json!({"claim": row.claim, "predicate": row.predicate, "value": row.value}))
        .collect();
    let priors: Vec<serde_json::Value> = priors
        .into_iter()
        .map(|row| {
            json!({"claim": row.claim, "predicate": row.predicate, "source": row.source, "value": row.value})
        })
        .collect();
    PartMark::apply(
        mark,
        json!({
            "predicate": predicate,
            "prior_heads": priors,
            "candidates": candidates,
        }),
    )
}

/// The bytes one conflict candidate adds to a page: its row with its full id,
/// plus one separator byte. Native paging and the bound rebuild share this
/// measure.
pub(in crate::dreamer_consolidation) fn conflict_member_bytes(
    claim_hex: &str,
    predicate: &str,
    value: &serde_json::Value,
) -> usize {
    json_len(&json!({"claim": claim_hex, "predicate": predicate, "value": value})).saturating_add(1)
}

/// The bytes a conflict page carries beside its candidates: the state over
/// `priors` with no candidate, marked as page one of two. Native paging and
/// the bound rebuild share this frame with the same prior labels.
pub(in crate::dreamer_consolidation) fn conflict_frame_bytes(
    predicate: &str,
    priors: Vec<NumberedPriorHead>,
) -> usize {
    json_len(&render_conflict_state(
        predicate,
        priors,
        Vec::new(),
        PartMark::Page { page: 0, pages: 2 },
    ))
}

/// The pages `all` reads in: all on one when `whole_len` fits the ladder's
/// bound; else the `split` pages, or all on one again when the split keeps
/// them together. Native paging and the bound rebuild share this branch, so
/// both page alike from the same measured length.
pub(in crate::dreamer_consolidation) fn page_or_whole<T: Copy>(
    whole_len: usize,
    all: &[T],
    split: impl FnOnce() -> Vec<Vec<T>>,
) -> Vec<Vec<T>> {
    if whole_len <= MAX_DECISION_STATE_BYTES {
        return vec![all.to_vec()];
    }
    let pages = split();
    if pages.len() == 1 {
        return vec![all.to_vec()];
    }
    pages
}

/// Whether the ladder put this decision to a role: its last pin is the person rung's.
fn went_up(decision: &TypedDecision) -> bool {
    decision
        .receipt
        .providers
        .last()
        .is_some_and(|pin| pin.rung == DecisionRung::Human)
}

/// Whether an ask holds the work it decides: an answered one always does,
/// and an open one unless the ladder only asked because the read ran out of
/// time; that pass checkpoints, and its resume reads again.
fn holds(ask: &DecisionAsk) -> bool {
    ask.answer.is_some() || ask.reason != HumanAskReason::Deadline
}

/// Labels `questions` `Q1`, `Q2`, in order, then the ladder's paired and
/// person questions, so every request a pack splits into shows the same
/// labels. A read's own questions always take the first numbers however many
/// suffix questions follow, and only those numbers ever render into a state.
fn label_questions_with(
    paired: Option<&DecisionQuestion>,
    person: Option<&DecisionQuestion>,
    labels: &mut CallLabelMap,
    questions: &[DecisionQuestion],
) {
    for question in questions.iter().chain(paired).chain(person) {
        labels.assign(LabelKind::Question, question.id);
    }
}

/// Who a verdict over `project`'s claims asks when it goes up, read as the
/// Dreamer `dreamer`: the project's leader as the responsible actor, then its
/// boards and the owners; its boards when it has no leader but the Dreamer
/// itself; the owners when the vault folds no such project. Never the
/// Dreamer: a system actor holds no role.
fn ask_route_for(
    vault: &crate::Vault,
    dreamer: EntityId,
    project: Option<EntityId>,
) -> Result<AskTo> {
    let Some(project) = project else {
        return Ok(AskTo::owner());
    };
    let effective = {
        let txn = vault.store.env.read_txn()?;
        vault.effective_project_in_txn(&txn, project)?
    };
    let Some((_, effective)) = effective else {
        return Ok(AskTo::owner());
    };
    let role = match EntityId::from_hex(&effective.leader)
        .ok()
        .filter(|leader| *leader != dreamer)
    {
        Some(actor) => AskRole::Responsible {
            actor: AnswerActor::Actor(actor),
            project: Some(project),
        },
        None => AskRole::Board { project },
    };
    Ok(AskTo {
        role,
        ceiling: ASK_CEILING,
        act: ASK_ACT,
    })
}

impl ConsolidationExecutor<'_> {
    /// Labels `questions` `Q1`, `Q2`, in order, then the ladder's paired and
    /// person questions (FIX 7506), before the pack's state renders: every
    /// request the pack splits into shows the same labels, and its state
    /// names its questions by them.
    pub(in crate::dreamer_consolidation) fn label_questions(
        &self,
        labels: &mut CallLabelMap,
        questions: &[DecisionQuestion],
    ) {
        let held = &self.decisions.ladder;
        label_questions_with(
            held.paired.as_ref(),
            held.person.as_ref(),
            labels,
            questions,
        );
    }

    /// Who a verdict over `project`'s claims asks when it goes up: the
    /// project's leader as the responsible actor, then its boards and the
    /// owners; its boards when it has no leader but the Dreamer itself; the
    /// owners when the vault folds no such project. Never the Dreamer: a
    /// system actor holds no role.
    pub(super) fn ask_route(
        &self,
        vault: &crate::Vault,
        project: Option<EntityId>,
    ) -> Result<AskTo> {
        ask_route_for(vault, self.actor.entity_ref(), project)
    }

    /// `questions` over `state` through the host's ladder, the verdict role's generation
    /// the dial's first read, on the time the pass has left, any ask going to `to` for
    /// the work `correlation` names. Each generation that finished joins `charges`, even
    /// when a later one traps or fails. None when the step trapped: the attempt is parked.
    ///
    /// Every read shows the pack through `labels` (FIX 7506): the generation's
    /// questions by their labels and its choices as registered, every rung
    /// past it the same choices, and each answer reads back canonical. The map
    /// binds into each generation's identity.
    ///
    /// A question already put to `to` for this work is not put again: an open ask
    /// still holds its work, and an answered one is the answer, so the read stops below
    /// the person rung. Each decision keeps its ask, and its receipt names the version
    /// of every evidence body the branch pinned.
    #[expect(
        clippy::too_many_arguments,
        reason = "the step, its pass clock, branch and route join the pack and the charge tally"
    )]
    pub(super) async fn decide(
        &self,
        step_ctx: &DurableStepContext<'_>,
        pass: &WakePassDeadline,
        resources: &BranchResources<'_>,
        to: &AskTo,
        correlation: EntityId,
        questions: &[DecisionQuestion],
        evidence: &[EntityId],
        state: &serde_json::Value,
        labels: &CallLabelMap,
        sources: Option<Vec<EntityId>>,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<Option<Vec<KeptDecision>>> {
        let vault = step_ctx.vault;
        let call = self.role(DREAMER_VERDICT_ROLE);
        let seal = |request: LlmRequest| -> Result<LlmRequest> {
            let mut request = vault
                .authorize_model_role(DREAMER_VERDICT_ROLE, request, &call.inference)?
                .into_request();
            super::super::roles::bind_reasoning(vault, call.backend, &mut request)?;
            Ok(request)
        };
        // Every decision's receipt names the version of each evidence body
        // the branch pinned.
        let versions = resources.evidence_versions(evidence);
        let mut spent = Vec::new();
        let decided = self
            .decider()
            .decide_scoped(
                ScopedRead {
                    step: step_ctx,
                    pass,
                    call: &call,
                    shell: verdict_shell(&call, resources.scope())?,
                    seal: &seal,
                    versions: &versions,
                    to,
                    correlation,
                    evidence,
                    state,
                    ceiling: VERDICT_CEILING,
                    // Each pack passes the rows it rendered (FIX 11526).
                    sources,
                },
                questions,
                labels,
                &mut spent,
            )
            .await;
        // Every generation that finished is spent, whatever the pack's outcome: a later
        // step that traps or fails leaves the prefix on the tally.
        for (index, (_, usage, binding, _)) in spent.iter().enumerate() {
            if let Some(binding) = binding {
                if let Err(error) =
                    charges.record_terminal(vault, binding.attempt_id, binding.step_hash, usage)
                {
                    for (_, usage, _, memoized) in &spent[index..] {
                        if !*memoized {
                            charges.record_usage(usage);
                        }
                    }
                    if let Some(usage) = decided
                        .as_ref()
                        .err()
                        .and_then(DurableStepError::spent_usage)
                    {
                        charges.record_usage(usage);
                    }
                    return Err(error.into());
                }
            } else {
                charges.record_usage(usage);
            }
        }
        decided
    }
}

/// The verdict role's request for a typed read: its model, scope and binding, with no
/// messages yet.
fn verdict_shell(call: &RoleCall<'_>, scope: &oneiron_model::llm::Scope) -> Result<LlmRequest> {
    let keyless = call.inference.selected_keyless();
    let paid = call.inference.selected_paid();
    Ok(LlmRequest {
        model: call.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: scope.clone(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::Durable {
                fallback: oneiron_model::llm::DeterministicFallback {
                    name: "json_rules_v1".into(),
                    config: None,
                },
            },
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: call.inference.selected_locality().ok_or_else(|| {
                crate::Error::InvalidConfig("consolidation host binding needs locality".into())
            })?,
            host_keyless: keyless,
            host_paid: paid,
        }
        .with_purpose_defaults(),
        messages: Vec::new(),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    })
}

/// Which read of a pack one state is for: the whole pack, one of its pages,
/// or a final identity choice (FIX 8693).
#[derive(Debug, Clone, Copy)]
pub(super) enum StatePart {
    Whole,
    Page { page: usize, pages: usize },
    Final,
}

/// A conflict as its pack reads it, every value whole (Rule 5, FIX 7637):
/// the predicate and the prior heads every read shows, and each candidate.
/// Each claim goes by its label in the read's map (FIX 7506).
pub(in crate::dreamer_consolidation) struct ConflictRows {
    predicate: String,
    priors: Vec<(EntityId, String, Option<&'static str>, serde_json::Value)>,
    candidates: Vec<(EntityId, String, serde_json::Value)>,
}

impl ConflictRows {
    pub(super) fn of(
        identity: &ConflictIdentity,
        members: &[&super::super::evidence::VerifiedCandidate],
        priors: &[super::super::PriorHead],
    ) -> Result<Self> {
        let members = members
            .iter()
            .map(|member| {
                let facts = candidate_facts(&member.candidate)?;
                Ok((member.claim_id, facts.predicate, rmpv_to_json(&facts.value)))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self::from_rows(identity, &members, priors))
    }

    /// The rows over plain member rows: `members` as already projected
    /// (id, predicate, value) triples with the `priors` every read shows.
    /// Native [`ConflictRows::of`] projects its verified members once, then
    /// builds here, and the bound rebuild projects its checked candidates
    /// the same way.
    pub(in crate::dreamer_consolidation) fn from_rows(
        identity: &ConflictIdentity,
        members: &[(EntityId, String, serde_json::Value)],
        priors: &[super::super::PriorHead],
    ) -> Self {
        let priors = priors
            .iter()
            .map(|prior| {
                (
                    prior.claim_id,
                    prior.body.predicate.clone(),
                    prior.body.source.map(ClaimSource::as_str),
                    rmpv_to_json(&prior.body.value),
                )
            })
            .collect();
        Self {
            predicate: identity.predicate.clone(),
            priors,
            candidates: members.to_vec(),
        }
    }

    /// Every candidate's index, in order.
    pub(super) fn all(&self) -> Vec<usize> {
        (0..self.candidates.len()).collect()
    }

    /// The indexes of the candidates `ids` name, in their order.
    pub(super) fn indexes(&self, ids: &[EntityId]) -> Vec<usize> {
        ids.iter()
            .filter_map(|id| self.candidates.iter().position(|row| row.0 == *id))
            .collect()
    }

    /// The candidate ids at `shown`, in order.
    pub(in crate::dreamer_consolidation) fn ids(&self, shown: &[usize]) -> Vec<EntityId> {
        shown
            .iter()
            .filter_map(|at| self.candidates.get(*at).map(|row| row.0))
            .collect()
    }

    /// The state one read of the pack takes: the predicate, every prior head
    /// and the candidates at `shown`, each whole, marked as `part`'s.
    pub(super) fn state(
        &self,
        shown: &[usize],
        part: StatePart,
        labels: &mut CallLabelMap,
    ) -> serde_json::Value {
        let candidates: Vec<NumberedConflictCandidate> = shown
            .iter()
            .filter_map(|at| self.candidates.get(*at))
            .map(|(claim, predicate, value)| NumberedConflictCandidate {
                claim: labels.assign(LabelKind::Claim, *claim).to_string(),
                predicate: predicate.clone(),
                value: value.clone(),
            })
            .collect();
        let priors: Vec<NumberedPriorHead> = self
            .priors
            .iter()
            .map(|(claim, predicate, source, value)| NumberedPriorHead {
                claim: labels.assign(LabelKind::Claim, *claim).to_string(),
                predicate: predicate.clone(),
                source: (*source).map(str::to_owned),
                value: value.clone(),
            })
            .collect();
        render_conflict_state(&self.predicate, priors, candidates, PartMark::from(part))
    }

    /// The candidates' indexes in pages: all on one when the whole state fits
    /// the ladder's bound; else split in order, each page beside every prior
    /// head, a candidate wider than a page on a page of its own. Each is
    /// measured with its full id.
    pub(in crate::dreamer_consolidation) fn pages(&self) -> Vec<Vec<usize>> {
        let all = self.all();
        let whole = self.state(&all, StatePart::Whole, &mut CallLabelMap::default());
        page_or_whole(json_len(&whole), &all, || {
            let priors: Vec<NumberedPriorHead> = self
                .priors
                .iter()
                .enumerate()
                .map(|(at, (_, predicate, source, value))| NumberedPriorHead {
                    claim: format!("C{}", at + 1),
                    predicate: predicate.clone(),
                    source: (*source).map(str::to_owned),
                    value: value.clone(),
                })
                .collect();
            let frame = conflict_frame_bytes(&self.predicate, priors);
            split_pages(
                frame,
                &all,
                |_, at| {
                    self.candidates
                        .get(at)
                        .map_or(0, |(claim, predicate, value)| {
                            conflict_member_bytes(&claim.to_hex(), predicate, value)
                        })
                },
                |_, _| true,
            )
        })
    }
}
