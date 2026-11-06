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
    let (mut document, backing) = if budget.admits_memory() {
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
    let text_error = budget
        .admits_memory()
        .then(|| Arc::new(Mutex::new(None::<ContentTemplateError>)));
    if let Some(error) = &text_error {
        let create_error = Arc::clone(error);
        let append_error = Arc::clone(error);
        let create_budget = budget.clone();
        let append_budget = budget.clone();
        document.tree = document.tree.with_parser_text_reservation(
            move |text| {
                let mut error = create_error.lock().unwrap_or_else(PoisonError::into_inner);
                if error.is_some() {
                    return None;
                }
                match html5ever::tendril::Tendril::try_from_slice_with_reservation(
                    text,
                    |bytes| reserve(&create_budget, bytes),
                    Backing::resize,
                )
                .map_err(tendril_error)
                {
                    Ok(text) => Some(text),
                    Err(refusal) => {
                        error.get_or_insert(refusal);
                        None
                    }
                }
            },
            move |text, additional| {
                let mut error = append_error.lock().unwrap_or_else(PoisonError::into_inner);
                if error.is_some() {
                    return false;
                }
                let result = u32::try_from(additional)
                    .map_err(|_| ContentTemplateError::Overflow)
                    .and_then(|additional| {
                        text.try_reserve_with_reservation(
                            additional,
                            |bytes| reserve(&append_budget, bytes),
                            Backing::resize,
                        )
                        .map_err(tendril_error)
                    });
                match result {
                    Ok(()) => true,
                    Err(refusal) => {
                        error.get_or_insert(refusal);
                        false
                    }
                }
            },
        );
    }
    let parser = html5ever::parse_document_with_checkpoint(
        document,
        html5ever::ParseOpts {
            tree_builder: html5ever::tree_builder::TreeBuilderOpts {
                scripting_enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        || text_checkpoint(text_error.as_deref(), budget),
    );
    let document = if budget.admits_memory() {
        let budget = budget.clone();
        let current = Arc::clone(&backing);
        let native_text_error = text_error.clone();
        let open_elements = Mutex::new(Backing::new(budget.clone()));
        let temporary_buffer = Mutex::new(Backing::new(budget.clone()));
        let tag_name = Mutex::new(Backing::new(budget.clone()));
        let attribute_name = Mutex::new(Backing::new(budget.clone()));
        let attribute_storage_budget = budget.clone();
        let attribute_value_budget = budget.clone();
        let attribute_atomic_budget = budget.clone();
        let comment_budget = budget.clone();
        let doctype_budget = budget.clone();
        let pending_table_budget = budget.clone();
        let pending_table_storage_budget = budget.clone();
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
            .with_tag_attributes_reservation(
                move |bytes| reserve(&attribute_storage_budget, bytes),
                Backing::resize,
                tendril_error,
                move |document, name, attrs, flags| {
                    document
                        .create_element_with_tag_attributes(
                            name,
                            attrs,
                            flags,
                            |bytes| reserve(&attribute_atomic_budget, bytes),
                            Backing::resize,
                        )
                        .map_err(arena_error)
                },
                Document::add_tag_attributes_if_missing,
            )
            .with_attribute_value_reservation(move |value, additional| {
                let additional =
                    u32::try_from(additional).map_err(|_| ContentTemplateError::Overflow)?;
                value
                    .try_reserve_with_reservation(
                        additional,
                        |bytes| reserve(&attribute_value_budget, bytes),
                        Backing::resize,
                    )
                    .map_err(tendril_error)
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
            .with_doctype_reservation(move |text, additional| {
                let additional =
                    u32::try_from(additional).map_err(|_| ContentTemplateError::Overflow)?;
                text.try_reserve_with_reservation(
                    additional,
                    |bytes| reserve(&doctype_budget, bytes),
                    Backing::resize,
                )
                .map_err(tendril_error)
            })
            .with_pending_table_storage_reservation(
                move |bytes| reserve(&pending_table_storage_budget, bytes),
                Backing::resize,
                tendril_error,
            )
            .with_pending_table_text_reservation(move |text, additional| {
                let additional =
                    u32::try_from(additional).map_err(|_| ContentTemplateError::Overflow)?;
                text.try_reserve_with_reservation(
                    additional,
                    |bytes| reserve(&pending_table_budget, bytes),
                    Backing::resize,
                )
                .map_err(tendril_error)
            })
            .with_tree_sink_checkpoint(move |document, operation| {
                text_checkpoint(native_text_error.as_deref(), &budget)?;
                if matches!(operation, TreeSinkOperation::ParseError) {
                    let mut backing = current.lock().unwrap_or_else(PoisonError::into_inner);
                    backing
                        .errors
                        .reserve_vec(&mut document.errors.borrow_mut(), 1)?;
                    return Ok(());
                }
                let additional = arena_slots(document, &operation);
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
                match operation {
                    TreeSinkOperation::CreateElement(_, count) => document
                        .tree
                        .try_prepare_parser_attributes(
                            count,
                            |bytes| reserve(&budget, bytes),
                            Backing::resize,
                        )
                        .map_err(arena_error)?,
                    TreeSinkOperation::AddAttributes(target, attrs) => document
                        .tree
                        .try_reserve_parser_added_attributes(
                            target,
                            attrs,
                            |bytes| reserve(&budget, bytes),
                            Backing::resize,
                        )
                        .map_err(arena_error)?,
                    _ => {}
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

fn text_checkpoint(
    error: Option<&Mutex<Option<ContentTemplateError>>>,
    budget: &Budget,
) -> Result<()> {
    if let Some(error) =
        error.and_then(|state| state.lock().unwrap_or_else(PoisonError::into_inner).clone())
    {
        return Err(error);
    }
    budget.checkpoint()
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

fn arena_slots(document: &Document, operation: &TreeSinkOperation<'_, NodeId>) -> usize {
    match operation {
        TreeSinkOperation::CreateElement(name, _) => {
            1 + usize::from(
                name.ns == html5ever::ns!(html) && name.local == html5ever::local_name!("template"),
            )
        }
        TreeSinkOperation::CreateComment | TreeSinkOperation::Doctype => 1,
        TreeSinkOperation::ParseError | TreeSinkOperation::AddAttributes(_, _) => 0,
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
