//! The catalogue keys the Setting primitive's tests set (DESIGN 15-setting-primitive, stage 0.1).
//! They exist only under `--cfg oneiron_test_support`; no engine code reads them.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::check_in::ActClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::EngineControlClass;
use crate::setting::{
    ItemDomain, Kind, ReadBy, ScopeKind, SetBy, SettingChange, SettingSync, SettingValue,
};

/// `test.bounds`'s value: a struct whose every part names its order.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct TestBounds {
    /// The most handles open at once: lower is stricter.
    pub max_open: u64,
    /// The least wait between two reads, in seconds: higher is stricter.
    pub floor_secs: u64,
}

impl SettingValue for TestBounds {}

oneiron_setting_contract::each_order!(TestBounds {
    max_open: lower,
    floor_secs: higher,
});

fn default_bounds() -> TestBounds {
    TestBounds {
        max_open: 8,
        floor_secs: 10,
    }
}

fn strictest_bounds() -> TestBounds {
    TestBounds {
        max_open: 0,
        floor_secs: u64::MAX,
    }
}

fn every_permit() -> Vec<String> {
    ["read", "send", "share"].map(str::to_owned).to_vec()
}

fn no_permit() -> Vec<String> {
    Vec::new()
}

fn plain_label() -> String {
    "plain".to_owned()
}

/// `test.custom_window`'s comparator: a window is no wider when it is no longer.
fn window_no_wider(a: &u64, b: &u64) -> bool {
    a <= b
}

/// How many changes `test.hooked` has seen.
static HOOKED_CHANGES: AtomicU64 = AtomicU64::new(0);

/// How many times `test.after_commit`'s after-commit hook has run.
static AFTER_COMMITS: AtomicU64 = AtomicU64::new(0);

/// The value of `test.after_commit` a fresh read saw when its hook last ran.
static AFTER_COMMIT_SEEN: AtomicU64 = AtomicU64::new(u64::MAX);

fn seven() -> u64 {
    7
}

fn ten() -> u64 {
    10
}

fn zero() -> u64 {
    0
}

fn learned_rate_seed() -> f64 {
    0.05
}

fn quiet_default() -> bool {
    false
}

fn quietest() -> bool {
    true
}

fn empty_banner() -> String {
    String::new()
}

fn no_mode() -> Option<u64> {
    None
}

fn no_ids() -> Vec<String> {
    Vec::new()
}

/// `test.mentioned_ids`'s erase: the list without the erased entity's 32 hex, when it names it.
#[allow(clippy::ptr_arg)] // the hook's type is `fn(&T, EntityId)` with `T = Vec<String>`
fn drop_mention(ids: &Vec<String>, erased: EntityId) -> Option<Vec<String>> {
    let hex = erased.to_hex();
    ids.contains(&hex)
        .then(|| ids.iter().filter(|id| **id != hex).cloned().collect())
}

fn channel(item: &str) -> bool {
    matches!(item, "mail" | "chat")
}

fn count_change(
    _vault: &crate::Vault,
    _txn: &mut heed::RwTxn<'_>,
    _change: &SettingChange,
) -> Result<()> {
    HOOKED_CHANGES.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

/// How many changes `test.hooked`'s hook has run for.
#[must_use]
pub fn hooked_changes() -> u64 {
    HOOKED_CHANGES.load(Ordering::SeqCst)
}

/// `test.after_commit`'s after-commit hook: it reads the key in a read of its own, which sees
/// only committed writes, and counts its run.
fn note_after_commit(vault: &crate::Vault) {
    let seen = vault
        .store
        .env
        .read_txn()
        .ok()
        .and_then(|txn| TEST_AFTER_COMMIT.read_in_txn(vault, &txn, &[], None).ok())
        .map_or(u64::MAX, |resolved| resolved.value);
    AFTER_COMMIT_SEEN.store(seen, Ordering::SeqCst);
    AFTER_COMMITS.fetch_add(1, Ordering::SeqCst);
}

/// How many times `test.after_commit`'s after-commit hook has run.
#[must_use]
pub fn after_commits() -> u64 {
    AFTER_COMMITS.load(Ordering::SeqCst)
}

/// The value of `test.after_commit` its hook's own read saw on its last run.
#[must_use]
pub fn after_commit_seen() -> u64 {
    AFTER_COMMIT_SEEN.load(Ordering::SeqCst)
}

crate::setting::setting_keys! {
    /// A number only the owner sets, at the vault, a world or a project.
    pub TEST_OWNER_NUMBER: u64 = "test.owner_number" {
        kind: Kind::new(seven).strictest(zero),
        scopes: &[ScopeKind::Vault, ScopeKind::World, ScopeKind::Project],
    };
    /// A work budget a holder of the work-budget class tunes inside the owner's cap.
    pub TEST_WORK_BUDGET: u64 = "test.work_budget" {
        kind: Kind::new(ten).strictest(zero).lower(),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        set_by: SetBy::Class(EngineControlClass::WorkBudget),
    };
    /// Whether an agent keeps quiet: the agent tightens its own row; loosening asks.
    pub TEST_AGENT_QUIET: bool = "test.agent_quiet" {
        kind: Kind::new(quiet_default).strictest(quietest).higher(),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        set_by: SetBy::Subject,
    };
    /// A wait per outbound channel: a family key.
    pub TEST_CHANNEL_WAIT: u64 = "test.channel_wait" {
        kind: Kind::new(zero),
        item: Some(ItemDomain { name: "outbound channels", admits: channel }),
    };
    /// A banner every member of the vault reads.
    pub TEST_MEMBER_BANNER: String = "test.member_banner" {
        kind: Kind::new(empty_banner),
        read_by: ReadBy::Members,
        act: ActClass::ReversibleWork,
    };
    /// A key whose hook counts its changes.
    pub TEST_HOOKED: u64 = "test.hooked" {
        kind: Kind::new(zero),
        on_change: Some(count_change),
    };
    /// A mode that is off until the owner sets one: an optional value.
    pub TEST_OPTIONAL_MODE: Option<u64> = "test.optional_mode" {
        kind: Kind::new(no_mode),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
    };
    /// A choice about this machine: a leave keeps its rows.
    pub TEST_INSTALL_MODE: u64 = "test.install_mode" {
        kind: Kind::new(zero),
        sync: SettingSync::Install,
    };
    /// Whether a person keeps quiet: the person tightens their own row.
    pub TEST_PERSON_QUIET: bool = "test.person_quiet" {
        kind: Kind::new(quiet_default).strictest(quietest).higher(),
        scopes: &[ScopeKind::Vault, ScopeKind::Person],
        set_by: SetBy::Subject,
    };
    /// A key whose after-commit hook reads it and counts its runs.
    pub TEST_AFTER_COMMIT: u64 = "test.after_commit" {
        kind: Kind::new(zero),
        after_commit: Some(note_after_commit),
    };
    /// A dial: the owner sets it, and a whole-vault Steward grant naming any `engine.controls`
    /// class reads it.
    pub TEST_DIAL_NUMBER: u64 = "test.dial_number" {
        kind: Kind::new(zero),
        read_by: ReadBy::Dials,
    };
    /// A list of entities, 32 hex each: an erase takes the erased one out of the value.
    pub TEST_MENTIONED_IDS: Vec<String> = "test.mentioned_ids" {
        kind: Kind::new(no_ids).erase_mentions(drop_mention),
    };
    /// A learned rate in [0, 1]: a fit learns it under its seeds, at the goal, project, task
    /// type and vault scopes.
    pub TEST_LEARNED_RATE: f64 = "test.learned_rate" {
        kind: Kind::new(learned_rate_seed).learned(0.0, 1.0),
        scopes: &crate::setting::LEARNED_SCOPES,
    };
    /// A cap whose rows meet (stage 6.0): lower is stricter, at the vault, a world or a project;
    /// a holder of the work-budget class moves it.
    pub TEST_ORDERED_CAP: u64 = "test.ordered_cap" {
        kind: Kind::new(ten).strictest(zero).lower(),
        scopes: &[ScopeKind::Vault, ScopeKind::World, ScopeKind::Project],
        set_by: SetBy::Class(EngineControlClass::WorkBudget),
    };
    /// A permit list whose rows meet to their intersection.
    pub TEST_PERMIT_LIST: Vec<String> = "test.permit_list" {
        kind: Kind::new(every_permit).strictest(no_permit).subset(),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        set_by: SetBy::Class(EngineControlClass::WorkBudget),
    };
    /// Bounds whose rows meet part by part.
    pub TEST_BOUNDS: TestBounds = "test.bounds" {
        kind: Kind::new(default_bounds).strictest(strictest_bounds).each(),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        set_by: SetBy::Class(EngineControlClass::WorkBudget),
    };
    /// A label that guards nothing: every move is neutral.
    pub TEST_NEUTRAL_LABEL: String = "test.neutral_label" {
        kind: Kind::new(plain_label).neutral(),
        set_by: SetBy::Class(EngineControlClass::WorkBudget),
    };
    /// A number with no order that a holder of the work-budget class moves.
    pub TEST_CLASS_NUMBER: u64 = "test.class_number" {
        kind: Kind::new(seven),
        set_by: SetBy::Class(EngineControlClass::WorkBudget),
    };
    /// A window judged by its own comparator: one slot, at the vault.
    pub TEST_CUSTOM_WINDOW: u64 = "test.custom_window" {
        kind: Kind::new(ten).custom(window_no_wider),
        set_by: SetBy::Class(EngineControlClass::WorkBudget),
    };
    /// A cap the owner sets, whose rows meet, with a row at an agent's own scope: the agent is
    /// that row's subject, not a holder.
    pub TEST_AGENT_CAP: u64 = "test.agent_cap" {
        kind: Kind::new(ten).strictest(zero).lower(),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
    };
}
