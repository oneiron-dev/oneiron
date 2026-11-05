//! The call context a verb-hook selector can narrow to.

use serde::{Deserialize, Serialize};

/// Known scope names for one logical call. A single name keeps the hook
/// input's string form; independent model-call axes share one array.
/// These names select hooks, not the rows their grants let them read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerbCallScope {
    Named(String),
    Multiple(Vec<String>),
}

impl VerbCallScope {
    /// All hook axes actually set on the model call, without choosing a
    /// primary axis. Relationship and resource bounds are not hook axes.
    #[must_use]
    pub fn from_model_scope(scope: &crate::llm::Scope) -> Option<Self> {
        let mut names = Vec::new();
        for (axis, id) in [
            ("world", scope.world),
            ("facet", scope.facet),
            ("project", scope.project),
        ] {
            if let Some(id) = id {
                names.push(format!("{axis}:{}", id.to_hex()));
            }
        }
        match names.len() {
            0 => None,
            1 => names.pop().map(Self::Named),
            _ => Some(Self::Multiple(names)),
        }
    }

    pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
        let names = match self {
            Self::Named(name) => std::slice::from_ref(name),
            Self::Multiple(names) => names.as_slice(),
        };
        names.iter().map(String::as_str)
    }

    pub(crate) fn receipt_text(&self) -> String {
        match self {
            Self::Named(name) => name.clone(),
            Self::Multiple(names) => {
                serde_json::to_string(names).expect("scope names serialize as JSON")
            }
        }
    }
}
