//! The verbs' owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue reads
//! from this file.

use super::files::MAX_FILES_PAGE_LIMIT;
use super::tree::setting_values::{ViewBudgetTok, ViewPaths};
use crate::setting::{Kind, PageMax};
use crate::setting::{ScopeKind, SettingSync};

/// 1,000 files: a Files listing's maximum page before it became a key (FIX 10247).
fn files_page_max_default() -> PageMax {
    PageMax(u32::try_from(MAX_FILES_PAGE_LIMIT).unwrap_or(u32::MAX))
}

/// The default `code_mode.view.base`: the 10 base paths of the design in order
/// (DESIGN 7). The one hand-written list of verb names in Rust: it is the
/// setting's default value.
const CODE_MODE_VIEW_BASE_DEFAULT: &[&str] = &[
    "vault.recall",
    "vault.hydrate",
    "vault.remember",
    "vault.claims.retract",
    "vault.notes.create",
    "vault.writes.pending",
    "self.actor",
    "self.focus.refresh",
    "verbs.expand",
    "verbs.search",
];

/// The design's 10 base paths in order: `code_mode.view.base`'s default.
fn code_mode_view_base_default() -> ViewPaths {
    ViewPaths::from_strs(CODE_MODE_VIEW_BASE_DEFAULT)
}

crate::setting::setting_keys! {
    /// The most files one `vault.files.sources.files` page holds (default 1,000). An ask for more
    /// is served this many, with a cursor to the rest; an ask that names no limit is still served
    /// 200, and an ask of zero is served one file. A maximum of zero is refused. A larger value
    /// is looser, so only the owner raises it; an agent's raise waits on the owner's answer.
    pub(crate) FILES_PAGE_MAX: PageMax = "verbs.files.max_page_limit" {
        kind: Kind::new(files_page_max_default)
            .strictest(files_page_max_default)
            .lower(),
    };
    /// The verb-tree view's base: the paths shown at full with their authored text, in order
    /// (DESIGN 7; the default is the 10 base verbs). Each entry is a dotted lowercase path; one
    /// the tree does not hold is reported by the view, not refused here. Only the owner sets it.
    pub(crate) CODE_MODE_VIEW_BASE: ViewPaths = "code_mode.view.base" {
        kind: Kind::new(code_mode_view_base_default),
        scopes: &[ScopeKind::Vault],
        sync: SettingSync::Vault,
        standing_approval: false,
    };
    /// The verb-tree view's expansions: paths shown one level deeper than names, in order (a
    /// branch at lines, a verb at full; default none). Entries read as `code_mode.view.base`'s.
    /// Only the owner sets it.
    pub(crate) CODE_MODE_VIEW_EXPANDED: ViewPaths = "code_mode.view.expanded" {
        kind: Kind::new(ViewPaths::empty),
        scopes: &[ScopeKind::Vault],
        sync: SettingSync::Vault,
        standing_approval: false,
    };
    /// The verb-tree view's token budget (default 4,000; zero refused). Over it, expanded
    /// entries fall back to names last-first and the view says so; the base is never dropped.
    /// Only the owner sets it.
    pub(crate) CODE_MODE_VIEW_BUDGET_TOK: ViewBudgetTok = "code_mode.view.budget_tok" {
        kind: Kind::new(ViewBudgetTok::default_budget),
        scopes: &[ScopeKind::Vault],
        sync: SettingSync::Vault,
        standing_approval: false,
    };
}
