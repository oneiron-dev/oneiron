//! Principal-bound preference compilation choices recorded by inbox decisions.

use serde::{Deserialize, Serialize};

/// An explicit compilation decision supplied by the authenticated human host.
/// These are proposals, not installed bans, charter edits or expression heads.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "text", rename_all = "snake_case")]
pub enum CompilationTarget {
    /// Preserve the existing lexical-claim/content-skill-edit chooser.
    #[default]
    Fallback,
    /// Propose a prohibition. Does not install an enforcement rule.
    Ban(String),
    /// Propose an OF-332 style token. Does not supersede an expression head.
    StyleRule(String),
    /// Propose a line for the acting charter. Does not change its authority.
    CharterLine(String),
    /// Propose a brief update. Does not mutate a brief.
    BriefUpdate(String),
}

impl CompilationTarget {
    pub(crate) fn predicate(&self) -> Option<&'static str> {
        match self {
            Self::Fallback => None,
            Self::Ban(_) => Some("preference.ban"),
            Self::StyleRule(_) => Some("preference.style_rule"),
            Self::CharterLine(_) => Some("charter.line"),
            Self::BriefUpdate(_) => Some("brief.preference"),
        }
    }

    pub(crate) fn text(&self) -> Option<&str> {
        match self {
            Self::Fallback => None,
            Self::Ban(text)
            | Self::StyleRule(text)
            | Self::CharterLine(text)
            | Self::BriefUpdate(text) => Some(text),
        }
    }
}
