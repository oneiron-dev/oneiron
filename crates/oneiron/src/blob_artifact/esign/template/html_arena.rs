//! Native DOM node storage on the caller's reservation. Transitive node heap,
//! tokenizer buffers and parse-error/attribute storage are separate allocations.

use super::budget::{Backing, Budget};
use super::{ContentTemplateError, Result};
use dom_query::{ArenaReserveError, Document, NodeData, NodeId, Tree};
#[allow(unused_imports)]
use html5ever::namespace_url;
use html5ever::tendril::TendrilSink;
use html5ever::tree_builder::{NodeOrText, TreeSinkOperation};
use std::cell::{Cell, RefCell};
use std::ops::Deref;
use std::sync::{Arc, Mutex, PoisonError};

/// The arena is freed before its remaining reservation is returned.
pub(super) struct HtmlDocument {
    document: Document,
    _arena: Arc<Mutex<Backing>>,
}

impl Deref for HtmlDocument {
    type Target = Document;
    fn deref(&self) -> &Document {
        &self.document
    }
}

pub(super) fn parse_document(html: &str, budget: &Budget) -> Result<HtmlDocument> {
    let (document, backing) = if budget.admits_memory() {
        let (tree, backing) = Tree::try_new_with_reservation(
            NodeData::Document,
            |bytes| reserve(budget, bytes),
            Backing::resize,
        )
        .map_err(arena_error)?;
        (
            Document {
                tree,
                errors: RefCell::new(Vec::new()),
                quirks_mode: Cell::new(html5ever::tree_builder::NoQuirks),
            },
            backing,
        )
    } else {
        (Document::default(), Backing::new(budget.clone()))
    };
    let backing = Arc::new(Mutex::new(backing));
    let parser = html5ever::parse_document_with_checkpoint(
        document,
        html5ever::ParseOpts {
            tree_builder: html5ever::tree_builder::TreeBuilderOpts {
                scripting_enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        || budget.checkpoint(),
    );
    let document = if budget.admits_memory() {
        let budget = budget.clone();
        let current = Arc::clone(&backing);
        parser
            .with_tree_sink_checkpoint(move |document, operation| {
                budget.checkpoint()?;
                let additional = arena_slots(document, operation);
                if additional != 0 {
                    if let Some(replacement) = document
                        .tree
                        .try_reserve_nodes(
                            additional,
                            |bytes| reserve(&budget, bytes),
                            Backing::resize,
                        )
                        .map_err(arena_error)?
                    {
                        // Native replacement freed the old block before returning.
                        *current.lock().unwrap_or_else(PoisonError::into_inner) = replacement;
                    }
                }
                Ok(())
            })
            .one(html)?
    } else {
        parser.one(html)?
    };
    Ok(HtmlDocument {
        document,
        _arena: backing,
    })
}

fn reserve(budget: &Budget, bytes: usize) -> Result<Backing> {
    let mut backing = Backing::new(budget.clone());
    backing.resize(bytes)?;
    Ok(backing)
}

fn arena_error(error: ArenaReserveError<ContentTemplateError>) -> ContentTemplateError {
    match error {
        ArenaReserveError::Refused(error) => error,
        ArenaReserveError::CapacityOverflow | ArenaReserveError::Allocation(_) => {
            ContentTemplateError::Overflow
        }
    }
}

fn arena_slots(document: &Document, operation: TreeSinkOperation<'_, NodeId>) -> usize {
    match operation {
        TreeSinkOperation::CreateElement(name) => {
            1 + usize::from(
                name.ns == html5ever::ns!(html) && name.local == html5ever::local_name!("template"),
            )
        }
        TreeSinkOperation::CreateComment | TreeSinkOperation::Doctype => 1,
        TreeSinkOperation::Append(parent, child) => append_slots(document, parent, child),
        TreeSinkOperation::BeforeSibling(sibling, child) => sibling_slots(document, sibling, child),
        TreeSinkOperation::BasedOnParent(element, previous, child) => {
            if document.tree.parent_of(element).is_some() {
                sibling_slots(document, element, child)
            } else {
                append_slots(document, previous, child)
            }
        }
    }
}

fn append_slots(document: &Document, parent: &NodeId, child: &NodeOrText<NodeId>) -> usize {
    usize::from(
        matches!(child, NodeOrText::AppendText(_))
            && !document
                .tree
                .last_child_of(parent)
                .is_some_and(|node| node.is_text()),
    )
}

fn sibling_slots(document: &Document, sibling: &NodeId, child: &NodeOrText<NodeId>) -> usize {
    usize::from(
        matches!(child, NodeOrText::AppendText(_))
            && !document
                .tree
                .prev_sibling_of(sibling)
                .is_some_and(|node| node.is_text()),
    )
}
