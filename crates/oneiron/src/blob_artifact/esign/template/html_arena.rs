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
    _backing: Arc<Mutex<DomBacking>>,
}

struct DomBacking {
    nodes: Backing,
    errors: Backing,
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
    let backing = Arc::new(Mutex::new(DomBacking {
        nodes: backing,
        errors: Backing::new(budget.clone()),
    }));
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
        let open_elements = Mutex::new(Backing::new(budget.clone()));
        let temporary_buffer = Mutex::new(Backing::new(budget.clone()));
        let tag_name = Mutex::new(Backing::new(budget.clone()));
        let attribute_name = Mutex::new(Backing::new(budget.clone()));
        let comment_budget = budget.clone();
        parser
            .with_open_elements_reservation(move |elements, additional| {
                open_elements
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .reserve_vec(elements, additional)
            })
            .with_temporary_buffer_reservation(move |text, additional| {
                temporary_buffer
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .reserve_string(text, additional)
            })
            .with_tag_name_reservation(move |text, additional| {
                tag_name
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .reserve_string(text, additional)
            })
            .with_attribute_name_reservation(move |text, additional| {
                attribute_name
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .reserve_string(text, additional)
            })
            .with_comment_reservation(move |comment, additional| {
                let additional =
                    u32::try_from(additional).map_err(|_| ContentTemplateError::Overflow)?;
                comment
                    .try_reserve_with_reservation(
                        additional,
                        |bytes| reserve(&comment_budget, bytes),
                        Backing::resize,
                    )
                    .map_err(tendril_error)
            })
            .with_tree_sink_checkpoint(move |document, operation| {
                budget.checkpoint()?;
                if matches!(operation, TreeSinkOperation::ParseError) {
                    let mut backing = current.lock().unwrap_or_else(PoisonError::into_inner);
                    backing
                        .errors
                        .reserve_vec(&mut document.errors.borrow_mut(), 1)?;
                    return Ok(());
                }
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
                        current.lock().unwrap_or_else(PoisonError::into_inner).nodes = replacement;
                    }
                }
                Ok(())
            })
            .one_str(html)?
    } else {
        parser.one(html)?
    };
    Ok(HtmlDocument {
        document,
        _backing: backing,
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

fn tendril_error(
    error: html5ever::tendril::ReserveError<ContentTemplateError>,
) -> ContentTemplateError {
    match error {
        html5ever::tendril::ReserveError::Refused(error) => error,
        html5ever::tendril::ReserveError::CapacityOverflow
        | html5ever::tendril::ReserveError::Allocation(_) => ContentTemplateError::Overflow,
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
        TreeSinkOperation::ParseError => 0,
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
