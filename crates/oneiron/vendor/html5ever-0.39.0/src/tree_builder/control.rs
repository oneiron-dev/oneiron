//! Admission before native tree-sink operations that may grow a node arena.

use super::{pending_table_text::PendingTableText, TreeBuilder};
use crate::tendril::StrTendril;
use crate::{tree_builder::NodeOrText, Attribute, QualName};

/// A pending sink operation. No handle has been created by this operation yet.
/// Text may coalesce with an existing node; the sink decides whether a slot is needed.
pub enum TreeSinkOperation<'a, Handle> {
    /// Create an element, including its template fragment when applicable.
    CreateElement(&'a QualName, usize),
    /// Merge attributes into an existing element.
    AddAttributes(&'a Handle, &'a [Attribute]),
    /// Create a comment node.
    CreateComment,
    /// Append a node or text to a parent.
    Append(&'a Handle, &'a NodeOrText<Handle>),
    /// Insert before a sibling, possibly coalescing with its previous sibling.
    BeforeSibling(&'a Handle, &'a NodeOrText<Handle>),
    /// Select between sibling insertion and appending based on the element's parent.
    BasedOnParent(&'a Handle, &'a Handle, &'a NodeOrText<Handle>),
    /// Append a document type node.
    Doctype,
    /// Record a parse error in the sink's error collection.
    ParseError,
}


pub(crate) struct TagAttributesHooks<Handle, Sink> {
    pub(crate) reserve: crate::tokenizer::TagAttributesReservation,
    pub(crate) create: Box<
        dyn Fn(&Sink, QualName, crate::tokenizer::TagAttributes, super::ElementFlags) -> Option<Handle>
            + Send,
    >,
    pub(crate) add: Box<dyn Fn(&Sink, &Handle, crate::tokenizer::TagAttributes) -> bool + Send>,
}

pub(super) type SinkCheckpoint<Handle, Sink> =
    Box<dyn Fn(&Sink, TreeSinkOperation<'_, Handle>) -> bool + Send>;

pub(super) type PendingTableStorageReservation =
    Box<dyn Fn(&mut PendingTableText, usize) -> bool + Send>;

pub(super) type PendingTableTextReservation = Box<dyn Fn(&mut StrTendril, usize) -> bool + Send>;

pub(super) type OpenElementsReservation<Handle> =
    Box<dyn Fn(&mut Vec<Handle>, usize) -> bool + Send>;

pub(super) type ActiveFormattingReservation<Handle> =
    Box<dyn Fn(&mut super::active_formatting::ActiveFormatting<Handle>, usize) -> bool + Send>;

impl<Handle, Sink> TreeBuilder<Handle, Sink> {
    pub(crate) fn set_tag_attributes_hooks(&mut self, hooks: TagAttributesHooks<Handle, Sink>) {
        self.tag_attributes_hooks = Some(hooks);
    }

    pub(super) fn clone_tag_attributes(
        &self,
        attrs: &crate::tokenizer::TagAttributes,
    ) -> Option<crate::tokenizer::TagAttributes> {
        match &self.tag_attributes_hooks {
            Some(hooks) => attrs.try_clone(&hooks.reserve),
            None => Some(attrs.clone()),
        }
    }

    pub(super) fn clone_tag(&self, tag: &crate::tokenizer::Tag) -> Option<crate::tokenizer::Tag> {
        Some(crate::tokenizer::Tag {
            kind: tag.kind,
            name: tag.name.clone(),
            self_closing: tag.self_closing,
            attrs: self.clone_tag_attributes(&tag.attrs)?,
            had_duplicate_attributes: tag.had_duplicate_attributes,
        })
    }

    pub(super) fn equivalent_tags(
        &self,
        tag: &crate::tokenizer::Tag,
        other: &crate::tokenizer::Tag,
    ) -> Option<bool> {
        if self.tag_attributes_hooks.is_none() {
            return Some(tag.equiv_modulo_attr_order(other));
        }
        if tag.kind != other.kind || tag.name != other.name {
            return Some(false);
        }
        let mut attrs = self.clone_tag_attributes(&tag.attrs)?;
        let mut other_attrs = self.clone_tag_attributes(&other.attrs)?;
        attrs.sort_unstable();
        other_attrs.sort_unstable();
        Some(attrs == other_attrs)
    }

    pub(crate) fn coalesce_table_text(&mut self) {
        self.coalesce_table_text = true;
    }

    pub(crate) fn set_pending_table_storage_reservation(
        &mut self,
        reservation: PendingTableStorageReservation,
    ) {
        self.pending_table_storage_reservation = Some(reservation);
    }

    pub(super) fn reserve_pending_table_storage(
        &self,
        pending: &mut PendingTableText,
        additional: usize,
    ) -> bool {
        self.pending_table_storage_reservation
            .as_ref()
            .is_none_or(|reservation| reservation(pending, additional))
    }

    pub(crate) fn set_pending_table_text_reservation(
        &mut self,
        reservation: PendingTableTextReservation,
    ) {
        self.pending_table_text_reservation = Some(reservation);
    }

    pub(super) fn append_pending_table_text(
        &self,
        destination: &mut StrTendril,
        text: &StrTendril,
    ) -> bool {
        if let Some(reservation) = &self.pending_table_text_reservation {
            if !reservation(destination, text.len()) {
                return false;
            }
            destination.push_slice(text);
        } else {
            destination.push_tendril(text);
        }
        true
    }

    pub(super) fn prepare_pending_table_text(&self, text: StrTendril) -> Option<StrTendril> {
        if self.pending_table_text_reservation.is_none() {
            return Some(text);
        }
        let mut destination = StrTendril::new();
        self.append_pending_table_text(&mut destination, &text)
            .then_some(destination)
    }

    pub(crate) fn set_active_formatting_reservation(
        &mut self,
        reservation: ActiveFormattingReservation<Handle>,
    ) {
        self.active_formatting_reservation = Some(reservation);
    }

    pub(super) fn reserve_active_formatting(&self, additional: usize) -> Option<()> {
        self.active_formatting_reservation
            .as_ref()
            .is_none_or(|reservation| {
                reservation(&mut self.active_formatting.borrow_mut(), additional)
            })
            .then_some(())
    }

    pub(crate) fn set_open_elements_reservation(
        &mut self,
        reservation: OpenElementsReservation<Handle>,
    ) {
        self.open_elements_reservation = Some(reservation);
    }

    pub(super) fn reserve_open_elements(
        &self,
        elements: &mut Vec<Handle>,
        additional: usize,
    ) -> Option<()> {
        self.open_elements_reservation
            .as_ref()
            .is_none_or(|reservation| reservation(elements, additional))
            .then_some(())
    }

    pub(crate) fn set_tree_sink_checkpoint(&mut self, checkpoint: SinkCheckpoint<Handle, Sink>) {
        self.tree_sink_checkpoint = Some(checkpoint);
    }

    pub(super) fn before_tree_sink_operation(
        &self,
        operation: TreeSinkOperation<'_, Handle>,
    ) -> bool {
        self.tree_sink_checkpoint
            .as_ref()
            .is_none_or(|checkpoint| checkpoint(&self.sink, operation))
    }
}

impl<Handle, Sink> TreeBuilder<Handle, Sink>
where
    Handle: Clone,
    Sink: super::TreeSink<Handle = Handle>,
{
    pub(super) fn add_tag_attributes(
        &self,
        target: &Handle,
        attrs: crate::tokenizer::TagAttributes,
    ) -> Option<()> {
        match &self.tag_attributes_hooks {
            Some(hooks) => (hooks.add)(&self.sink, target, attrs).then_some(()),
            None => {
                self.sink.add_attrs_if_missing(
                    target,
                    attrs
                        .into_unreserved()
                        .expect("guarded attributes require a native sink"),
                );
                Some(())
            }
        }
    }

    pub(crate) fn report_parse_error(&self, error: std::borrow::Cow<'static, str>) {
        if self.before_tree_sink_operation(TreeSinkOperation::ParseError) {
            self.sink.parse_error(error);
        }
    }
}
