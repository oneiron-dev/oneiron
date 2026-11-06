//! Admission before native tree-sink operations that may grow a node arena.

use super::TreeBuilder;
use crate::{tree_builder::NodeOrText, QualName};

/// A pending sink operation. No handle has been created by this operation yet.
/// Text may coalesce with an existing node; the sink decides whether a slot is needed.
pub enum TreeSinkOperation<'a, Handle> {
    /// Create an element, including its template fragment when applicable.
    CreateElement(&'a QualName),
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
}

pub(super) type SinkCheckpoint<Handle, Sink> =
    Box<dyn Fn(&Sink, TreeSinkOperation<'_, Handle>) -> bool + Send>;

impl<Handle, Sink> TreeBuilder<Handle, Sink> {
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
