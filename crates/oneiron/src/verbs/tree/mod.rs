//! A read-only view of the code-mode verb tree, from the base kit to on-demand types.
//!
//! The view depends only on the verb table, the view setting, the registered NOTE
//! kinds, and the hidden map. The same inputs give the same bytes. The catalogue
//! revision travels beside the text, not in it.

mod index;
mod render;
mod search;
pub(crate) mod setting_values;
mod vault_view;
mod view;

use std::collections::BTreeMap;

use oneiron_store::note_kind::RetentionDefault;

use self::index::{Index, Node};
pub use self::vault_view::OwnedViewOptions;

/// The code-mode catalogue, with a node for each path segment.
#[derive(Debug)]
pub struct VerbTree {
    index: Index,
    root: Node,
}

/// All caller- and vault-specific inputs to the verb tree.
#[derive(Debug)]
pub struct ViewOptions<'a> {
    /// Base entries, in display order.
    pub base: &'a [String],
    /// Paths to show one level deeper than names, in display order.
    pub expanded: &'a [String],
    /// Token budget for the whole default view.
    pub budget_tok: u32,
    /// NOTE kinds to list in the authored create-note entry.
    pub note_kinds: &'a [NoteKindLine],
    /// Omitted verb paths and the grants they need.
    pub hidden: &'a BTreeMap<String, String>,
}

/// A NOTE kind and its retention information for the base text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteKindLine {
    /// Registered kind name.
    pub kind: String,
    /// Default retention for the kind.
    pub retention: RetentionDefault,
    /// Retention period for a kind that archives after a set number of days.
    pub archive_after_days: Option<u32>,
}

/// Text and size information for a rendered default view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedView {
    /// The complete view, ending in a newline.
    pub text: String,
    /// Estimated context-pack tokens in the complete text.
    pub tokens: usize,
    /// Expanded entries dropped for size, in setting order.
    pub not_expanded: Vec<String>,
}

/// Stable codes for verb tree refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeRefusalCode {
    /// No matching verb, branch or type.
    UnknownPath,
    /// The requested verb or branch is outside the caller's grant.
    OutsideGrant,
}

impl TreeRefusalCode {
    /// The stable wire spelling of this code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownPath => "UNKNOWN_PATH",
            Self::OutsideGrant => "OUTSIDE_GRANT",
        }
    }
}

/// A verb tree lookup that could not be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeRefusal {
    /// Machine-readable reason.
    pub code: TreeRefusalCode,
    /// Human-readable reason.
    pub message: String,
    /// Nearby visible matches for an unknown path or type.
    pub nearest: Vec<String>,
    /// The required grants, sorted and joined by commas, for an outside-grant refusal.
    pub needs: Option<String>,
}

impl VerbTree {
    /// The embedded catalogue, parsed on each call: the caller keeps the tree (one per host).
    pub fn shipped() -> crate::Result<Self> {
        Self::parse_index(include_str!(concat!(
            env!("OUT_DIR"),
            "/verb_tree_index.json"
        )))
        .map_err(crate::Error::InvalidConfig)
    }

    /// Build a tree from a JSON index in the generator's format.
    pub fn from_index_json(json: &str) -> crate::Result<Self> {
        Self::parse_index(json).map_err(crate::Error::InvalidConfig)
    }

    /// Revision of the code-mode fragment that supplied the types.
    pub fn revision(&self) -> &str {
        &self.index.revision
    }

    /// Render the base kit, configured expansions, and coarse tree.
    pub fn default_view(&self, options: &ViewOptions<'_>) -> RenderedView {
        self.render_view(options)
    }

    /// Expand a branch, verb or type. An empty path returns the default view.
    pub fn expand(&self, path: &str, options: &ViewOptions<'_>) -> Result<String, TreeRefusal> {
        if path.is_empty() {
            return Ok(self.default_view(options).text);
        }
        if render::is_type_name(path) {
            return self.expand_type(path).ok_or_else(|| TreeRefusal {
                code: TreeRefusalCode::UnknownPath,
                message: format!("no type named {path}"),
                nearest: self.nearest_types(path),
                needs: None,
            });
        }
        let node = self.node_at(path).ok_or_else(|| TreeRefusal {
            code: TreeRefusalCode::UnknownPath,
            message: format!("no branch or verb at \"{path}\""),
            nearest: self.nearest_paths(path, options),
            needs: None,
        })?;
        if let Some(refusal) = node.outside_grant(options.hidden) {
            return Err(refusal);
        }
        Ok(self.expand_node(node, options.hidden))
    }

    /// Search visible verbs by words, optionally under a branch and with a hit limit.
    /// The default limit is ten.
    pub fn search(
        &self,
        query: &str,
        under: Option<&str>,
        limit: Option<usize>,
        options: &ViewOptions<'_>,
    ) -> Result<String, TreeRefusal> {
        self.search_query(query, under.unwrap_or(""), limit.unwrap_or(10), options)
    }

    /// Render one verb at `lines` detail, with its short field list and first sentence.
    pub fn verb_line(&self, path: &str) -> Option<String> {
        self.line(path)
    }

    /// Render a verb's input with every field and type for a refusal's `takes:` line.
    pub fn verb_takes(&self, path: &str) -> Option<String> {
        self.takes(path)
    }

    /// Return the row's example, or generate one from its input.
    pub fn verb_example(&self, path: &str) -> Option<String> {
        self.example(path)
    }
}
