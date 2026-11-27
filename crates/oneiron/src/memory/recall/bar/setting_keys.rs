//! The `recall.bar.*` rows (their value and item domain: the parent module). They sit in a
//! file named `setting_keys.rs`, the only name build.rs reads catalogue rows from.

use super::{ExcludedPredicates, RecallBar, is_harness_item};
use crate::setting::{ItemDomain, Kind, ScopeKind, SettingSync};

crate::setting::setting_keys! {
    /// The relevance bar for the lines a session is given at its start, keyed on the task's
    /// words (RECALL-CARRIER-THRESHOLD; owner 26 Nov 18:53 and 18:59). A start keyed on the
    /// folder's name asks none: no bar separates true lines from traps there. `measured`
    /// (the default): the bar the host measured for the vault's embedding space, which only a
    /// host running that exact model revision on its measured profile states (a cosine of
    /// 0.52 for pplx-embed-v1-0.6b); a direct match on a vault with no embedder; and no line
    /// anywhere else, such as an endpoint that names no profile. `open`: no relevance cut.
    /// `quiet`: no line. `direct_match`: a rare term of the query, or every term of it.
    /// `{"cosine": {"floor", "model"}}`:
    /// a raw cosine of at least `floor` in `model`'s space, and no line in another space. A
    /// line is judged before the result is cut, so one under the bar takes no slot, and a
    /// start gets at most 3 lines, only from the session's project. Item: the harness
    /// (`claude-code`, `codex`, `prime-agent`); a row with no item judges every harness with
    /// no row of its own. A project's row overrides the vault's. Only the owner sets it.
    pub(crate) RECALL_BAR_START: RecallBar = "recall.bar.start" {
        kind: Kind::new(RecallBar::measured).strictest(RecallBar::quiet),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        item: Some(ItemDomain { name: "harnesses", admits: is_harness_item }),
        sync: SettingSync::Vault,
        standing_approval: false,
    };
    /// Claim predicates to leave out of pushed recall. An entry matches that predicate and
    /// its dot-separated descendants. A project's list replaces the vault's; an empty list
    /// excludes none. Pulls ignore this list. Only the owner sets it.
    pub(crate) RECALL_BAR_EXCLUDED_PREDICATES: ExcludedPredicates = "recall.bar.excluded_predicates" {
        kind: Kind::new(ExcludedPredicates::bookkeeping),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        item: None,
        sync: SettingSync::Vault,
        standing_approval: false,
    };
    /// The relevance bar for the lines that ride with a session's work: beside a tool
    /// result, or on the user's prompt. The values, the item and the scopes are
    /// `recall.bar.start`'s; the default is `measured`, at most 3 lines, only from the
    /// session's project. Only the owner sets it.
    pub(crate) RECALL_BAR_CARRIER: RecallBar = "recall.bar.carrier" {
        kind: Kind::new(RecallBar::measured).strictest(RecallBar::quiet),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        item: Some(ItemDomain { name: "harnesses", admits: is_harness_item }),
        sync: SettingSync::Vault,
        standing_approval: false,
    };
    /// The relevance bar for a read a session asks for itself, when it asks to be judged by
    /// one. The values, the item and the scopes are `recall.bar.start`'s; the default is
    /// `open`: a session that asks gets every line it may read. Only the owner sets it.
    pub(crate) RECALL_BAR_PULL: RecallBar = "recall.bar.pull" {
        kind: Kind::new(RecallBar::open).strictest(RecallBar::quiet),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        item: Some(ItemDomain { name: "harnesses", admits: is_harness_item }),
        sync: SettingSync::Vault,
        standing_approval: false,
    };
    /// Whether a harness says so in one line when no line cleared the bar
    /// (RECALL-EMPTY-RECEIPT, the owner's to decide). Default false: it says nothing, as the
    /// owner's "skip the recall if nothing useful" asks (26 Nov 18:53). Item: the harness; a
    /// project's row overrides the vault's. Only the owner sets it.
    pub(crate) RECALL_BAR_EMPTY_RECEIPT: bool = "recall.bar.empty_receipt" {
        kind: Kind::new(no_receipt),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        item: Some(ItemDomain { name: "harnesses", admits: is_harness_item }),
        sync: SettingSync::Vault,
        standing_approval: false,
    };
}

fn no_receipt() -> bool {
    false
}
