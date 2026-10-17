//! Routed placement (OF-543, OF-541): a task is placed once, at spawn.
//!
//! Placement is a routed typed-judgment skill ([`PLACEMENT_SKILL_ID`]): it
//! runs through decide() as one [`PLACEMENT_QUESTION`] whose options are the
//! live nodes of the tree in force. Its executor is whichever rung of the
//! host's ladder answers, chosen by the dial and the bands learned on the
//! question, and the receipt's pins name it, so it is scored like any skill's;
//! Jev is one candidate among the host's rungs. The deterministic keyword
//! reader is the skill's rule rung, the first a dial starting at the rule
//! reads. Where no host ladder is in hand (inside a write transaction, where
//! no model call may hold it), the rule rung reads alone. Whatever answers,
//! the law is the same: unsure uses the root, and a stamp is always produced
//! — missing is invalid, never untyped.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::llm::decision::catalogue::QuestionFamily;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionCall, DecisionClass, DecisionDial,
    DecisionLadder, DecisionProvider, DecisionRung, ProviderDecision, ProviderPin, Reversibility,
    cut_text, fit_state,
};
use crate::retrieval_depth::RetrievalDeadline;

use super::{
    ROOT_NODE_ID, SeedTaskType, TaskTypeNode, TaskTypeRef, TaskTypeTree, invalid_type_ref,
};

/// The routed skill that owns placement.
pub const PLACEMENT_SKILL_ID: &str = "task_type.placement";

/// Which live node of the tree in force is this task? The options are the
/// tree's live node ids, so an answer can only name a node the tree holds.
/// The wording is the host's.
pub const PLACEMENT_QUESTION: QuestionFamily = QuestionFamily {
    name: PLACEMENT_SKILL_ID,
    version: 1,
    class: DecisionClass::Judgment,
};

/// The rule rung's model name on its pin.
pub const HEURISTIC_PLACEMENT_EXECUTOR: &str = "heuristic";

/// The rule rung's revision on its pin; bumped when its reading changes.
pub const HEURISTIC_PLACEMENT_VERSION: &str = "1";

/// The most options one choice question offers (the decision contract's).
const MAX_PLACEMENT_OPTIONS: usize = 64;

/// The rule rung's reading of a kind hint with no keyword evidence: a weak
/// prior, inside the seed band, so an enforced band asks the next rung.
const HINT_PROBABILITY: f64 = 0.5;

/// What a placer may look at: the task as the spawner described it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_text: Option<String>,
    /// A seed hint from a typed surface (for example the TASK body's shape
    /// discriminator). A hint is a weak prior, never the placement itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind_hint: Option<SeedTaskType>,
    /// Lower-hex project entity id, when the task belongs to a project
    /// whose forked tree should be placed against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_ref: Option<String>,
}

impl PlacementRequest {
    #[must_use]
    pub fn new(label: Option<String>, spec_text: Option<String>) -> Self {
        Self {
            label,
            spec_text,
            kind_hint: None,
            project_ref: None,
        }
    }

    #[must_use]
    pub const fn with_kind_hint(mut self, hint: SeedTaskType) -> Self {
        self.kind_hint = Some(hint);
        self
    }

    #[must_use]
    pub fn with_project(mut self, project_ref: String) -> Self {
        self.project_ref = Some(project_ref);
        self
    }

    fn haystack(&self) -> String {
        let mut text = String::new();
        if let Some(label) = &self.label {
            text.push_str(label);
            text.push(' ');
        }
        if let Some(spec) = &self.spec_text {
            text.push_str(spec);
        }
        text.to_ascii_lowercase()
    }
}

/// The host's placement ladder: its rungs (the rule slot is the skill's own
/// keyword reader), the principal the answer is for, its dial and learned
/// bands, its wording of [`PLACEMENT_QUESTION`], and the call's clock. The
/// engine bundles no model and no prompt text.
pub struct PlacementDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub deadline: &'a RetrievalDeadline,
}

/// The placement verdict: the stamp, who placed it, how sure it was, and
/// every rung that read it (the answering one last), for scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementOutcome {
    pub type_ref: TaskTypeRef,
    pub confident: bool,
    /// `model@revision` of the answering rung; the skill id when none
    /// answered and the law placed the root.
    pub executor: String,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<ProviderPin>,
}

impl PlacementOutcome {
    /// The unsure verdict: the root, placed by the skill's law.
    #[must_use]
    pub fn unsure(
        tree: &TaskTypeTree,
        providers: Vec<ProviderPin>,
        rationale: impl Into<String>,
    ) -> Self {
        Self {
            type_ref: tree.root_ref(),
            confident: false,
            executor: PLACEMENT_SKILL_ID.to_owned(),
            rationale: rationale.into(),
            providers,
        }
    }
}

const SEED_KEYWORDS: [(SeedTaskType, &[&str]); 7] = [
    (
        SeedTaskType::Generate,
        &[
            "generate",
            "draft",
            "write",
            "create",
            "compose",
            "brainstorm",
        ],
    ),
    (
        SeedTaskType::Refine,
        &["refine", "improve", "polish", "edit", "revise", "rewrite"],
    ),
    (
        SeedTaskType::Solve,
        &["solve", "fix", "debug", "diagnose", "repair", "resolve"],
    ),
    (
        SeedTaskType::Research,
        &[
            "research",
            "investigate",
            "explore",
            "survey",
            "find",
            "search",
        ],
    ),
    (
        SeedTaskType::Judge,
        &["judge", "review", "evaluate", "assess", "critique", "score"],
    ),
    (
        SeedTaskType::Build,
        &["build", "implement", "ship", "develop", "code", "construct"],
    ),
    (
        SeedTaskType::Negotiate,
        &[
            "negotiate",
            "persuade",
            "agree",
            "settle",
            "bargain",
            "convince",
        ],
    ),
];

/// What the rule rung read: an offered node, and whether keyword evidence
/// (not only a kind hint) put it there.
struct RuleRead {
    node_id: String,
    evidence: bool,
    rationale: String,
}

/// The rule rung's reading: keyword evidence over the label and spec text,
/// refined into decision-split children when the winning seed has been
/// split; else a live kind hint; no evidence, or a tie, reads nothing.
fn rule_read(
    tree: &TaskTypeTree,
    request: &PlacementRequest,
    options: &[String],
) -> Option<RuleRead> {
    let haystack = request.haystack();
    let mut best: Option<(SeedTaskType, usize)> = None;
    let mut tied = false;
    for (seed, keywords) in SEED_KEYWORDS {
        let score = keywords
            .iter()
            .filter(|keyword| contains_word(&haystack, keyword))
            .count();
        match best {
            Some((_, best_score)) if score == best_score && score > 0 => tied = true,
            Some((_, best_score)) if score <= best_score => {}
            _ if score > 0 => {
                best = Some((seed, score));
                tied = false;
            }
            _ => {}
        }
    }
    if let Some((seed, _)) = best.filter(|_| !tied) {
        let node_id = descend(tree, seed.node_id(), &haystack);
        return Some(RuleRead {
            node_id: offered(tree, node_id, options),
            evidence: true,
            rationale: format!("keyword evidence for {seed}"),
        });
    }
    if let Some(hint) = request.kind_hint
        && tree.node(hint.node_id()).is_some_and(TaskTypeNode::is_live)
    {
        return Some(RuleRead {
            node_id: offered(tree, hint.node_id(), options),
            evidence: false,
            rationale: format!("kind hint {hint}, no keyword evidence"),
        });
    }
    None
}

fn descend<'a>(tree: &'a TaskTypeTree, seed_node: &'a str, haystack: &str) -> &'a str {
    let mut current = seed_node;
    loop {
        let next = tree
            .children(current)
            .into_iter()
            .filter_map(|child| {
                child
                    .split_winner
                    .as_ref()
                    .filter(|winner| contains_word(haystack, &winner.to_ascii_lowercase()))
                    .map(|_| child.node_id.as_str())
            })
            .next();
        match next {
            Some(child_id) => current = child_id,
            None => return current,
        }
    }
}

fn contains_word(haystack: &str, word: &str) -> bool {
    haystack
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| token == word)
}

/// The question's options: the live nodes, root first and each node after
/// its parent, up to the contract's limit.
fn placement_options(tree: &TaskTypeTree) -> Vec<String> {
    let mut options = vec![ROOT_NODE_ID.to_owned()];
    let mut next = 0;
    while next < options.len() && options.len() < MAX_PLACEMENT_OPTIONS {
        let children: Vec<String> = tree
            .children(&options[next])
            .into_iter()
            .map(|child| child.node_id.clone())
            .filter(|id| id.len() <= 256 && !options.contains(id))
            .collect();
        for child in children {
            if options.len() == MAX_PLACEMENT_OPTIONS {
                break;
            }
            options.push(child);
        }
        next += 1;
    }
    options
}

/// `node_id` as an offered option: a merged-away node reads as the node it
/// merged into, and a node past the offered set as its nearest offered
/// ancestor; the root when nothing on the chain is offered.
fn offered(tree: &TaskTypeTree, node_id: &str, options: &[String]) -> String {
    let mut seen = BTreeSet::new();
    let mut cursor = tree
        .resolve_ref(&TaskTypeRef::new(node_id, tree.version))
        .map(|node| node.node_id.as_str());
    while let Some(id) = cursor {
        if options.iter().any(|option| option == id) {
            return id.to_owned();
        }
        if !seen.insert(id) {
            break;
        }
        cursor = tree.node(id).and_then(|node| node.parent.as_deref());
    }
    ROOT_NODE_ID.to_owned()
}

/// The bounded state every rung reads: the task as described, and the
/// offered nodes with their parents, names and split winners.
fn placement_state(
    tree: &TaskTypeTree,
    request: &PlacementRequest,
    options: &[String],
) -> serde_json::Value {
    let longest = request
        .label
        .as_ref()
        .map_or(0, String::len)
        .max(request.spec_text.as_ref().map_or(0, String::len));
    fit_state(longest, |cut| {
        serde_json::json!({
            "label": request.label.as_deref().map(|label| cut_text(label, cut)),
            "spec_text": request.spec_text.as_deref().map(|text| cut_text(text, cut)),
            "kind_hint": request.kind_hint.map(SeedTaskType::as_str),
            "project_ref": request.project_ref,
            "tree_version": tree.version,
            "types": options
                .iter()
                .filter_map(|id| tree.node(id))
                .map(|node| serde_json::json!({
                    "node_id": node.node_id,
                    "parent": node.parent,
                    "name": node.name,
                    "split_winner": node.split_winner,
                }))
                .collect::<Vec<_>>(),
            "cut_at_bytes": cut,
        })
    })
}

fn heuristic_pin() -> ProviderPin {
    ProviderPin {
        rung: DecisionRung::Rule,
        model: HEURISTIC_PLACEMENT_EXECUTOR.to_owned(),
        version: HEURISTIC_PLACEMENT_VERSION.to_owned(),
    }
}

fn executor_of(pin: &ProviderPin) -> String {
    format!("{}@{}", pin.model, pin.version)
}

/// The skill's rule rung for one call, over the reading taken from the same
/// tree and request the call's state is built from.
struct HeuristicRung<'r> {
    read: Option<&'r RuleRead>,
}

impl DecisionProvider for HeuristicRung<'_> {
    fn pin(&self) -> ProviderPin {
        heuristic_pin()
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let answer = self
            .read
            .map(|read| {
                (
                    DecisionAnswer::Choice(read.node_id.clone()),
                    if read.evidence { 1.0 } else { HINT_PROBABILITY },
                )
            })
            .filter(|(answer, _)| call.question.contract.accepts(answer));
        Ok(match answer {
            Some((answer, probability)) => ProviderDecision {
                answer,
                probability: Some(probability),
                paired: None,
                person: None,
            },
            None => ProviderDecision {
                answer: DecisionAnswer::Abstain,
                probability: None,
                paired: None,
                person: None,
            },
        })
    }
}

/// The rule rung's reading as the verdict.
fn rule_outcome(tree: &TaskTypeTree, read: Option<&RuleRead>) -> PlacementOutcome {
    let pin = heuristic_pin();
    match read {
        Some(read) => PlacementOutcome {
            type_ref: tree.type_ref(&read.node_id),
            confident: read.evidence,
            executor: executor_of(&pin),
            rationale: read.rationale.clone(),
            providers: vec![pin],
        },
        None => PlacementOutcome::unsure(tree, vec![pin], "no placement evidence"),
    }
}

/// Places a task once against `tree` through the placement skill's ladder.
/// With the host's `decisions`, the dial routes [`PLACEMENT_QUESTION`] from
/// the rule rung up through the host's rungs, never to a person; an
/// abstention is the root, and a failed run keeps the rule rung's reading.
/// Without them, the rule rung reads alone.
#[must_use]
pub fn place_task(
    tree: &TaskTypeTree,
    request: &PlacementRequest,
    decisions: Option<&PlacementDecisions<'_>>,
) -> PlacementOutcome {
    let options = placement_options(tree);
    let read = rule_read(tree, request, &options);
    let Some(decisions) = decisions else {
        return rule_outcome(tree, read.as_ref());
    };
    let Ok(question) = PLACEMENT_QUESTION.question(
        &[],
        decisions.wording.clone(),
        AnswerContract::Choice {
            options: options.clone(),
        },
    ) else {
        return rule_outcome(tree, read.as_ref());
    };
    let rung = HeuristicRung {
        read: read.as_ref(),
    };
    let ladder = DecisionLadder {
        rule: Some(&rung),
        local: decisions.ladder.local,
        system_one: decisions.ladder.system_one,
        escalation: decisions.ladder.escalation,
        big: decisions.ladder.big,
        human: decisions.ladder.human,
        human_pin: decisions.ladder.human_pin.clone(),
        ask_to: decisions.ladder.ask_to,
        paired: decisions.ladder.paired,
        person: decisions.ladder.person,
        presence: decisions.ladder.presence,
        correlation: decisions.ladder.correlation,
    };
    // Unsure is the root, so a placement never queues a person.
    let dial = DecisionDial {
        first: decisions.dial.first.min(DecisionRung::Big),
        ceiling: decisions.dial.ceiling.min(DecisionRung::Big),
        band: decisions.dial.band,
    };
    let state = placement_state(tree, request, &options);
    let Ok(decision) = ladder.run(
        &question,
        decisions.principal,
        &[],
        &state,
        dial,
        &decisions.bands,
        Reversibility::ReversibleRead,
        decisions.deadline,
    ) else {
        return rule_outcome(tree, read.as_ref());
    };
    let providers = decision.receipt.providers;
    match decision.answer {
        DecisionAnswer::Choice(node_id)
            if tree.node(&node_id).is_some_and(TaskTypeNode::is_live) =>
        {
            let answering = providers.last().cloned().unwrap_or_else(heuristic_pin);
            let rationale = match &read {
                Some(read) if answering == heuristic_pin() => read.rationale.clone(),
                _ => format!("placed by {}", executor_of(&answering)),
            };
            PlacementOutcome {
                type_ref: tree.type_ref(&node_id),
                confident: !decision.in_band,
                executor: executor_of(&answering),
                rationale,
                providers,
            }
        }
        _ => PlacementOutcome::unsure(tree, providers, "no rung placed it"),
    }
}

/// The spawn law in one call: a caller-supplied ref that validates against
/// the current tree is kept; anything else is placed, and an unsure
/// placement is the root. The result always validates.
#[must_use]
pub fn ensure_type_ref(
    tree: &TaskTypeTree,
    requested: Option<&TaskTypeRef>,
    request: &PlacementRequest,
    decisions: Option<&PlacementDecisions<'_>>,
) -> TaskTypeRef {
    if let Some(requested) = requested
        && tree.validate_current_ref(requested).is_ok()
    {
        return requested.clone();
    }
    place_task(tree, request, decisions).type_ref
}

/// The receipt law in one call: a spawn/task receipt without a `typeRef`
/// is invalid. Callers that merely may omit it route through
/// [`ensure_type_ref`] first; this is the refusing reader.
pub fn require_type_ref(requested: Option<&TaskTypeRef>) -> Result<TaskTypeRef> {
    match requested {
        Some(type_ref) if !type_ref.node_id.is_empty() => Ok(type_ref.clone()),
        Some(_) => Err(invalid_type_ref("typeRef node_id must not be empty")),
        None => Err(Error::Record(RecordError::InvalidTaskBody(
            "tasks.body.type_ref",
        ))),
    }
}
