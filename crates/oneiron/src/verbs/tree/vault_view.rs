//! The vault's verb-tree view inputs: the `code_mode.view.*` settings in force and
//! the NOTE kinds the view lists, as one owned value.

use std::collections::BTreeMap;

use oneiron_store::note_kind::ContextDefault;

use super::super::setting_keys::{
    CODE_MODE_VIEW_BASE, CODE_MODE_VIEW_BUDGET_TOK, CODE_MODE_VIEW_EXPANDED,
};
use super::{NoteKindLine, ViewOptions};
use crate::Vault;
use crate::error::Result;

/// The vault's verb-tree view inputs, owned: the three `code_mode.view.*`
/// settings in force, the NOTE kinds the view lists, and the hidden map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedViewOptions {
    base: Vec<String>,
    expanded: Vec<String>,
    budget_tok: u32,
    note_kinds: Vec<NoteKindLine>,
    hidden: BTreeMap<String, String>,
}

impl OwnedViewOptions {
    /// This, hiding `hidden`: omitted verb paths and the grants they need.
    pub fn with_hidden(mut self, hidden: BTreeMap<String, String>) -> Self {
        self.hidden = hidden;
        self
    }

    /// This as the tree's borrowed options.
    pub fn as_options(&self) -> ViewOptions<'_> {
        ViewOptions {
            base: &self.base,
            expanded: &self.expanded,
            budget_tok: self.budget_tok,
            note_kinds: &self.note_kinds,
            hidden: &self.hidden,
        }
    }
}

impl Vault {
    /// The vault's verb-tree view options: the `code_mode.view.*` settings in
    /// force and the registered NOTE kinds the view lists (every kind whose
    /// context default is not explicit-only, in kind order), with nothing
    /// hidden. The caller hides grant-withheld paths with
    /// [`OwnedViewOptions::with_hidden`].
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn verb_view_options(&self) -> Result<OwnedViewOptions> {
        // The three settings read in one read txn, closed before the NOTE
        // registry read below opens its own.
        let (base, expanded, budget_tok) = {
            let txn = self.store.env.read_txn()?;
            (
                CODE_MODE_VIEW_BASE
                    .read_in_txn(self, &txn, &[], None)?
                    .value
                    .0,
                CODE_MODE_VIEW_EXPANDED
                    .read_in_txn(self, &txn, &[], None)?
                    .value
                    .0,
                CODE_MODE_VIEW_BUDGET_TOK
                    .read_in_txn(self, &txn, &[], None)?
                    .value
                    .0,
            )
        };
        let note_kinds = self
            .note_kind_descriptors()?
            .into_iter()
            .filter(|descriptor| descriptor.context != ContextDefault::ExplicitOnly)
            .map(|descriptor| NoteKindLine {
                kind: descriptor.kind,
                retention: descriptor.retention,
                archive_after_days: descriptor.archive_after_days,
            })
            .collect();
        Ok(OwnedViewOptions {
            base,
            expanded,
            budget_tok,
            note_kinds,
            hidden: BTreeMap::new(),
        })
    }
}
