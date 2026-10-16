//! Routed placement (OF-543): a task is placed once, at spawn.
//!
//! Placement is a routed typed-judgment skill — its executor is chosen and
//! scored like any skill's, and Jev is one executor candidate. This module
//! is the placement contract plus the deterministic heuristic executor that
//! runs until a judged executor is routed in. Whatever the executor, the
//! law is the same: unsure uses the root, and a stamp is always produced —
//! missing is invalid, never untyped.

use serde::{Deserialize, Serialize};

use crate::error::{Error, RecordError, Result};

use super::{SeedTaskType, TaskTypeRef, TaskTypeTree, invalid_type_ref};

/// The routed skill that owns placement.
pub const PLACEMENT_SKILL_ID: &str = "task_type.placement";

/// One executor candidate for the placement skill (ARCH-0079: "Jev is one
/// candidate"). Recorded on the outcome so receipts can score executors.
pub const JEV_PLACEMENT_EXECUTOR: &str = "jev";

/// The heuristic executor's recorded name.
pub const HEURISTIC_PLACEMENT_EXECUTOR: &str = "heuristic";

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

/// The placement verdict: the stamp plus who placed it and how sure it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementOutcome {
    pub type_ref: TaskTypeRef,
    pub confident: bool,
    pub executor: String,
    pub rationale: String,
}

impl PlacementOutcome {
    /// The unsure verdict every executor must be able to return: the root.
    #[must_use]
    pub fn unsure(tree: &TaskTypeTree, executor: &str, rationale: impl Into<String>) -> Self {
        Self {
            type_ref: tree.root_ref(),
            confident: false,
            executor: executor.to_owned(),
            rationale: rationale.into(),
        }
    }
}

/// One placement executor. Routed executors (a judged skill run, Jev, …)
/// implement this; the engine routes [`PLACEMENT_SKILL_ID`] to one of them.
pub trait TaskTypePlacer {
    /// The executor name receipts record for scoring.
    fn executor(&self) -> &str;

    /// Places the task once against `tree`. Implementations return the
    /// root rather than guessing when unsure.
    fn place(&self, tree: &TaskTypeTree, request: &PlacementRequest) -> PlacementOutcome;
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

/// The deterministic placement executor: keyword evidence over the label
/// and spec text, refined one level into decision-split children when the
/// winning seed has been split. No evidence, or a tie, reads unsure.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeuristicPlacer;

impl HeuristicPlacer {
    fn descend<'a>(&self, tree: &'a TaskTypeTree, seed_node: &'a str, haystack: &str) -> &'a str {
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
}

impl TaskTypePlacer for HeuristicPlacer {
    fn executor(&self) -> &str {
        HEURISTIC_PLACEMENT_EXECUTOR
    }

    fn place(&self, tree: &TaskTypeTree, request: &PlacementRequest) -> PlacementOutcome {
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
            let node_id = self.descend(tree, seed.node_id(), &haystack);
            return PlacementOutcome {
                type_ref: tree.type_ref(node_id),
                confident: true,
                executor: self.executor().to_owned(),
                rationale: format!("keyword evidence for {seed}"),
            };
        }
        if let Some(hint) = request.kind_hint
            && tree.node(hint.node_id()).is_some_and(|node| node.is_live())
        {
            return PlacementOutcome {
                type_ref: tree.type_ref(hint.node_id()),
                confident: false,
                executor: self.executor().to_owned(),
                rationale: format!("kind hint {hint}, no keyword evidence"),
            };
        }
        PlacementOutcome::unsure(tree, self.executor(), "no placement evidence")
    }
}

fn contains_word(haystack: &str, word: &str) -> bool {
    haystack
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| token == word)
}

/// Places a task with the heuristic executor — the spawn-time default
/// until the router seats a judged executor for [`PLACEMENT_SKILL_ID`].
#[must_use]
pub fn place_task(tree: &TaskTypeTree, request: &PlacementRequest) -> PlacementOutcome {
    HeuristicPlacer.place(tree, request)
}

/// The spawn law in one call: a caller-supplied ref that validates against
/// the current tree is kept; anything else is placed, and an unsure
/// placement is the root. The result always validates.
#[must_use]
pub fn ensure_type_ref(
    tree: &TaskTypeTree,
    requested: Option<&TaskTypeRef>,
    request: &PlacementRequest,
) -> TaskTypeRef {
    if let Some(requested) = requested
        && tree.validate_current_ref(requested).is_ok()
    {
        return requested.clone();
    }
    place_task(tree, request).type_ref
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
