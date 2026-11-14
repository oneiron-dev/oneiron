//! The tasks file (v1) and the trace check every follow-up passes before a
//! run starts (ARCH-0053 #eval-trace-task: world, intent, tools and a grader,
//! and an answer not leaked to the reader).
//!
//! Histories and follow-ups sit apart: a history is the frozen past a vault
//! is built from; a follow-up is held out and reaches the reader only as its
//! prompt and its tools. Its rubric reaches the scorer only.
//!
//! A history may hold worlds besides base reality (a claim names its world;
//! a follow-up acts in one), and the user may delete a turn or a claim before
//! the freeze: the vault then holds it no longer.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    path::Path,
};

use serde::{Deserialize, Serialize};

use super::super::{BeamError, BeamResult};

/// The only tasks-file version this bench reads.
const TASKS_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TaskFile {
    pub(super) version: u32,
    pub(super) histories: Vec<History>,
    pub(super) follow_ups: Vec<FollowUp>,
}

impl TaskFile {
    pub(super) fn follow_ups_of<'a>(
        &'a self,
        history: &'a str,
    ) -> impl Iterator<Item = &'a FollowUp> {
        self.follow_ups
            .iter()
            .filter(move |follow_up| follow_up.history == history)
    }
}

/// One synthetic user's past. Only what happened before `frozen_at` enters
/// the vault; anything later is the held-out future.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct History {
    pub(super) id: String,
    pub(super) frozen_at: u64,
    /// The worlds the history's vault holds besides base reality, by name.
    #[serde(default)]
    pub(super) worlds: Vec<String>,
    pub(super) turns: Vec<Turn>,
    /// The derived memory, held fixed across the memory arms: the claims an
    /// extraction of these turns stands for. A later claim on the same
    /// predicate supersedes an earlier one.
    pub(super) claims: Vec<DerivedClaim>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Turn {
    pub(super) at: u64,
    pub(super) author: TurnAuthor,
    pub(super) text: String,
    /// When the user deleted the turn: after `at`, before the freeze.
    pub(super) deleted_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TurnAuthor {
    User,
    Companion,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DerivedClaim {
    pub(super) at: u64,
    /// A `profile.*` predicate about the vault owner.
    pub(super) predicate: String,
    pub(super) value: String,
    /// The world the claim holds in, one of the history's; none is base
    /// reality. One predicate may hold a value of its own in each world.
    pub(super) world: Option<String>,
    /// When the user deleted the claim: after `at`, before the freeze.
    pub(super) deleted_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TaskKind {
    CorrectedSource,
    StableDefinition,
    RepeatedWorkflow,
    /// A preference that differs by world; the follow-up acts in one.
    ScopedPreference,
    /// A memory the user deleted before the freeze.
    DeletedMemory,
}

/// A held-out follow-up: what the reader is asked to do, the tools it may
/// act through, the gold memory the gold arm hands it, and the rubric.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FollowUp {
    pub(super) id: String,
    pub(super) history: String,
    pub(super) kind: TaskKind,
    /// The world the follow-up acts in, one of its history's; none is base
    /// reality. Its reads see that world and base, never another world.
    pub(super) world: Option<String>,
    pub(super) prompt: String,
    pub(super) tools: Vec<Tool>,
    pub(super) gold_memory: Vec<String>,
    pub(super) rubric: Rubric,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tool {
    pub(super) name: String,
    pub(super) description: String,
    /// Each field and the options the reader picks one of.
    pub(super) fields: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rubric {
    /// The tool the right action uses.
    pub(super) action: String,
    /// Field values the right action sets.
    pub(super) expect: BTreeMap<String, String>,
    /// Superseded values per field: giving one fails correction persistence.
    #[serde(default)]
    pub(super) stale: BTreeMap<String, Vec<String>>,
    /// Standing values per field: giving another is an unsupported change.
    #[serde(default)]
    pub(super) keep: BTreeMap<String, String>,
    /// Another world's values per field: giving one is cross-scope leakage.
    #[serde(default)]
    pub(super) other_scope: BTreeMap<String, Vec<String>>,
    /// Deleted values per field: giving one is reappearance after deletion.
    #[serde(default)]
    pub(super) deleted: BTreeMap<String, Vec<String>>,
}

impl FollowUp {
    pub(super) fn tool(&self, name: &str) -> Option<&Tool> {
        self.tools.iter().find(|tool| tool.name == name)
    }
}

/// Reads and checks a tasks file; a follow-up that fails the trace check
/// stops the run with its id and the part it lacks.
pub(super) fn load(path: &Path) -> BeamResult<TaskFile> {
    let file: TaskFile = serde_json::from_slice(&std::fs::read(path)?)?;
    check(&file)?;
    Ok(file)
}

fn check(file: &TaskFile) -> BeamResult<()> {
    if file.version != TASKS_VERSION {
        return Err(BeamError::UnsupportedSchemaVersion {
            expected: TASKS_VERSION,
            actual: file.version,
        });
    }
    let mut history_ids = BTreeSet::new();
    for history in &file.histories {
        if !history_ids.insert(history.id.as_str()) {
            return Err(invalid(&history.id, "world", "the history id repeats"));
        }
        check_history(history)?;
    }
    let mut follow_up_ids = BTreeSet::new();
    for follow_up in &file.follow_ups {
        if !follow_up_ids.insert(follow_up.id.as_str()) {
            return Err(invalid(&follow_up.id, "intent", "the follow-up id repeats"));
        }
        let history = file
            .histories
            .iter()
            .find(|history| history.id == follow_up.history)
            .ok_or_else(|| invalid(&follow_up.id, "world", "it names no history"))?;
        check_follow_up(history, follow_up)?;
    }
    Ok(())
}

/// A history's worlds and deletions: distinct named worlds, every claim's
/// world declared, and each deletion after its item and before the freeze.
fn check_history(history: &History) -> BeamResult<()> {
    let id = history.id.as_str();
    let mut worlds = BTreeSet::new();
    for world in &history.worlds {
        if world.trim().is_empty() || !worlds.insert(world.as_str()) {
            return Err(invalid(id, "world", "a world name is blank or repeats"));
        }
    }
    if history.claims.iter().any(|claim| {
        claim
            .world
            .as_ref()
            .is_some_and(|world| !worlds.contains(world.as_str()))
    }) {
        return Err(invalid(
            id,
            "world",
            "a claim names a world its history does not declare",
        ));
    }
    let lives = history
        .turns
        .iter()
        .map(|turn| (turn.at, turn.deleted_at))
        .chain(
            history
                .claims
                .iter()
                .map(|claim| (claim.at, claim.deleted_at)),
        );
    for (at, deleted_at) in lives {
        if deleted_at.is_some_and(|deleted_at| deleted_at <= at || deleted_at >= history.frozen_at)
        {
            return Err(invalid(
                id,
                "world",
                "a deletion falls outside its item's life before the freeze",
            ));
        }
    }
    Ok(())
}

/// The four parts (world, intent, tools, grader), then the leak clause.
fn check_follow_up(history: &History, follow_up: &FollowUp) -> BeamResult<()> {
    let id = follow_up.id.as_str();
    let frozen = frozen_text(history);
    if history.frozen_at == 0 || frozen.is_empty() {
        return Err(invalid(
            id,
            "world",
            "the history holds nothing before its freeze",
        ));
    }
    if let Some(world) = &follow_up.world
        && !history.worlds.contains(world)
    {
        return Err(invalid(
            id,
            "world",
            "the follow-up's world is not one of its history's",
        ));
    }
    if follow_up.prompt.trim().is_empty() {
        return Err(invalid(id, "intent", "the prompt is blank"));
    }
    check_tools(follow_up)?;
    check_grader(follow_up)?;
    check_leak(history, follow_up, &frozen)
}

/// The grader: the rubric's tool, its expected fields, every value it names
/// offered by that tool, and the values its kind is scored on.
fn check_grader(follow_up: &FollowUp) -> BeamResult<()> {
    let id = follow_up.id.as_str();
    let rubric = &follow_up.rubric;
    let Some(tool) = follow_up.tool(&rubric.action) else {
        return Err(invalid(
            id,
            "grader",
            "the rubric's action is not one of its tools",
        ));
    };
    if rubric.expect.is_empty() {
        return Err(invalid(id, "grader", "the rubric expects no field"));
    }
    let named = rubric
        .expect
        .iter()
        .chain(&rubric.keep)
        .map(|(field, value)| (field, std::slice::from_ref(value)))
        .chain(
            [&rubric.stale, &rubric.other_scope, &rubric.deleted]
                .into_iter()
                .flatten()
                .map(|(field, values)| (field, values.as_slice())),
        );
    for (field, values) in named {
        let options = tool.fields.get(field);
        if values
            .iter()
            .any(|value| options.is_none_or(|options| !options.contains(value)))
        {
            return Err(invalid(
                id,
                "grader",
                &format!("field `{field}` names a value its tool does not offer"),
            ));
        }
    }
    let lacking = match follow_up.kind {
        TaskKind::CorrectedSource => rubric
            .stale
            .is_empty()
            .then_some("a corrected source names no superseded value"),
        TaskKind::ScopedPreference => (follow_up.world.is_none() || rubric.other_scope.is_empty())
            .then_some("a scoped preference names no world or no other world's value"),
        TaskKind::DeletedMemory => rubric
            .deleted
            .is_empty()
            .then_some("a deleted memory names no deleted value"),
        TaskKind::StableDefinition | TaskKind::RepeatedWorkflow => None,
    };
    match lacking {
        Some(detail) => Err(invalid(id, "grader", detail)),
        None => Ok(()),
    }
}

/// The leak clause, RULING L9-34-TRACE-LEAK = A (Engine 14 Nov 09:31): the
/// workspace is the follow-up's own inputs (its prompt and tool
/// descriptions; an option list may name the answer among others), and each
/// expected value is stated in what the vault holds at the freeze and in the
/// gold memory, else memory cannot answer. Each other world's value is
/// stated in a claim of another world, and each deleted value only in a
/// deleted item, so leakage and reappearance can come from memory alone; the
/// gold memory states neither.
fn check_leak(history: &History, follow_up: &FollowUp, frozen: &str) -> BeamResult<()> {
    let id = follow_up.id.as_str();
    let rubric = &follow_up.rubric;
    let workspace =
        follow_up
            .tools
            .iter()
            .fold(follow_up.prompt.to_lowercase(), |mut text, tool| {
                text.push('\n');
                text.push_str(&tool.description.to_lowercase());
                text
            });
    let gold = follow_up.gold_memory.join("\n").to_lowercase();
    for value in rubric.expect.values().map(|value| value.to_lowercase()) {
        if workspace.contains(&value) {
            return Err(invalid(
                id,
                "leak",
                "an expected value is in the prompt or a tool description",
            ));
        }
        if !frozen.contains(&value) {
            return Err(invalid(
                id,
                "world",
                "an expected value is stated nowhere the vault holds at the freeze",
            ));
        }
        if !gold.contains(&value) {
            return Err(invalid(
                id,
                "grader",
                "the gold memory does not state an expected value",
            ));
        }
    }
    let elsewhere = text_of(
        history,
        |_| false,
        |claim| claim.world.is_some() && claim.world != follow_up.world,
    );
    for value in values_of(&rubric.other_scope) {
        if !elsewhere.contains(&value) {
            return Err(invalid(
                id,
                "world",
                "another world's value is stated in no claim of another world",
            ));
        }
        if gold.contains(&value) {
            return Err(invalid(
                id,
                "grader",
                "the gold memory states another world's value",
            ));
        }
    }
    let deleted = deleted_text(history);
    for value in values_of(&rubric.deleted) {
        if !deleted.contains(&value) || frozen.contains(&value) {
            return Err(invalid(
                id,
                "world",
                "a deleted value is stated in no deleted item, or still in an item the vault holds",
            ));
        }
        if gold.contains(&value) {
            return Err(invalid(
                id,
                "grader",
                "the gold memory states a deleted value",
            ));
        }
    }
    Ok(())
}

fn values_of(named: &BTreeMap<String, Vec<String>>) -> impl Iterator<Item = String> {
    named.values().flatten().map(|value| value.to_lowercase())
}

fn check_tools(follow_up: &FollowUp) -> BeamResult<()> {
    let id = follow_up.id.as_str();
    if follow_up.tools.is_empty() {
        return Err(invalid(id, "tools", "the follow-up offers no tool"));
    }
    let mut names = BTreeSet::new();
    for tool in &follow_up.tools {
        if tool.name.trim().is_empty() || !names.insert(tool.name.as_str()) {
            return Err(invalid(id, "tools", "a tool name is blank or repeats"));
        }
        if tool.fields.is_empty() {
            return Err(invalid(id, "tools", "a tool has no field"));
        }
        for options in tool.fields.values() {
            let distinct: BTreeSet<_> =
                options.iter().map(|option| option.to_lowercase()).collect();
            if options.len() < 2 || distinct.len() != options.len() {
                return Err(invalid(
                    id,
                    "tools",
                    "a field offers fewer than two distinct options",
                ));
            }
        }
    }
    Ok(())
}

/// What the vault holds at the freeze: every turn and claim from before
/// it that the user did not delete, lower-cased, one per line.
fn frozen_text(history: &History) -> String {
    text_of(history, |_| true, |_| true)
}

/// Every turn and claim the user deleted before the freeze, lower-cased.
fn deleted_text(history: &History) -> String {
    let turns = history
        .turns
        .iter()
        .filter(|turn| turn.at < history.frozen_at && turn.deleted_at.is_some())
        .map(|turn| turn.text.as_str());
    let claims = history
        .claims
        .iter()
        .filter(|claim| claim.at < history.frozen_at && claim.deleted_at.is_some())
        .map(|claim| claim.value.as_str());
    lines(turns.chain(claims))
}

/// The held items `turn` and `claim` admit (from before the freeze, not
/// deleted), lower-cased, one per line.
fn text_of(
    history: &History,
    turn: impl Fn(&Turn) -> bool,
    claim: impl Fn(&DerivedClaim) -> bool,
) -> String {
    let turns = history
        .turns
        .iter()
        .filter(|item| item.at < history.frozen_at && item.deleted_at.is_none() && turn(item))
        .map(|item| item.text.as_str());
    let claims = history
        .claims
        .iter()
        .filter(|item| item.at < history.frozen_at && item.deleted_at.is_none() && claim(item))
        .map(|item| item.value.as_str());
    lines(turns.chain(claims))
}

fn lines<S: AsRef<str>>(items: impl Iterator<Item = S>) -> String {
    items.fold(String::new(), |mut text, line| {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&line.as_ref().to_lowercase());
        text
    })
}

/// When the history's correction happened, as an extraction arm probes it
/// (ARCH-0042 #action-bench, "probed right after a correction"): the time of
/// the first claim before the freeze whose slot (predicate and world) an
/// earlier claim already holds, when a user turn was said at that time. That
/// turn is the correcting turn. An extraction arm needs one: with none, the
/// history fails the trace check's world part.
pub(super) fn correction_point(history: &History) -> BeamResult<u64> {
    let mut held: Vec<&DerivedClaim> = history
        .claims
        .iter()
        .filter(|claim| claim.at < history.frozen_at)
        .collect();
    held.sort_by_key(|claim| claim.at);
    let mut slots = BTreeSet::new();
    for claim in held {
        let fresh = slots.insert((claim.predicate.as_str(), claim.world.as_deref()));
        if !fresh
            && history
                .turns
                .iter()
                .any(|turn| turn.at == claim.at && matches!(turn.author, TurnAuthor::User))
        {
            return Ok(claim.at);
        }
    }
    Err(invalid(
        &history.id,
        "world",
        "an extraction arm needs a correction: a later claim on a slot an earlier claim holds, said in a user turn",
    ))
}

/// The question the reader sees: the follow-up's prompt and its tools, each
/// field with its options, and nothing else of the follow-up.
pub(super) fn question(follow_up: &FollowUp) -> String {
    let mut text = format!("{}\n\nTools:", follow_up.prompt);
    for tool in &follow_up.tools {
        let _ = write!(text, "\n- {}: {}", tool.name, tool.description);
        for (field, options) in &tool.fields {
            let _ = write!(text, "\n  {field}: {}", options.join(" | "));
        }
    }
    text
}

fn invalid(id: &str, part: &str, detail: &str) -> BeamError {
    BeamError::InvalidFixture {
        fixture_id: id.to_owned(),
        reason: format!("action bench trace check, {part}: {detail}"),
    }
}
