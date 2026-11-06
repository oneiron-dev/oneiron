//! Caller checkpoints for the existing tokenizer and tree builder.

use super::{loop_until_done, ParseOpts};
use crate::buffer_queue::BufferQueue;
use crate::tendril::stream::{TendrilSink, Utf8LossyDecoder};
use crate::tendril::{fmt::UTF8, ReserveError, StrTendril};
use crate::tokenizer::{Token, TokenSink, TokenSinkResult, Tokenizer};
use crate::tree_builder::{TreeBuilder, TreeSink, TreeSinkOperation};
use std::borrow::Cow;
use std::sync::{Arc, Mutex, PoisonError};

/// Parse a document, returning the first caller checkpoint failure instead of
/// a partial document. The callback is polled between tokenizer steps and
/// before tokens, parse errors and EOF are delivered to the tree builder.
/// A single tokenizer step or tree-builder call remains non-preemptible.
pub fn parse_document_with_checkpoint<Sink, F, E>(
    sink: Sink,
    opts: ParseOpts,
    checkpoint: F,
) -> CheckedParser<Sink, F, E>
where
    Sink: TreeSink,
    F: Fn() -> Result<(), E>,
{
    let sink = CheckpointSink {
        sink: TreeBuilder::new(sink, opts.tree_builder),
        checkpoint,
        error: Arc::new(Mutex::new(None)),
    };
    CheckedParser {
        tokenizer: Tokenizer::new(sink, opts.tokenizer),
        input_buffer: BufferQueue::default(),
    }
}

/// A one-shot or incremental document parser with a caller-owned checkpoint.
/// Its successful output is the same sink output as the ordinary parser.
pub struct CheckedParser<Sink, F, E>
where
    Sink: TreeSink,
{
    tokenizer: Tokenizer<CheckpointSink<TreeBuilder<Sink::Handle, Sink>, F, E>>,
    input_buffer: BufferQueue,
}

impl<Sink, F, E> CheckedParser<Sink, F, E>
where
    Sink: TreeSink,
    F: Fn() -> Result<(), E>,
{
    /// Admit native sink operations before they can allocate or create handles.
    /// A refusal stores the first error in this parser and stops the current
    /// tree-builder operation, so finish drops the partial sink before Err.
    pub fn with_tree_sink_checkpoint<G>(mut self, checkpoint: G) -> Self
    where
        E: Send + 'static,
        G: Fn(&Sink, TreeSinkOperation<'_, Sink::Handle>) -> Result<(), E> + Send + 'static,
    {
        let error = Arc::clone(&self.tokenizer.sink.error);
        self.tokenizer.sink.sink.set_tree_sink_checkpoint(Box::new(move |sink, operation| {
            if error.lock().unwrap_or_else(PoisonError::into_inner).is_some() {
                return false;
            }
            match checkpoint(sink, operation) {
                Ok(()) => true,
                Err(refusal) => {
                    error.lock().unwrap_or_else(PoisonError::into_inner).get_or_insert(refusal);
                    false
                }
            }
        }));
        self
    }

    /// Install before feeding input to reserve the actual native open-element
    /// vector before its push or insert.
    /// The callback is dropped after that vector on success and failure, so an
    /// owned reservation can be released when parsing ends, before rendering.
    /// A refusal uses the same first-error channel as the other checkpoints.
    pub fn with_open_elements_reservation<G>(mut self, reservation: G) -> Self
    where
        E: Send + 'static,
        G: Fn(&mut Vec<Sink::Handle>, usize) -> Result<(), E> + Send + 'static,
    {
        let error = Arc::clone(&self.tokenizer.sink.error);
        self.tokenizer
            .sink
            .sink
            .set_open_elements_reservation(Box::new(move |elements, additional| {
                if error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some()
                {
                    return false;
                }
                match reservation(elements, additional) {
                    Ok(()) => true,
                    Err(refusal) => {
                        error
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get_or_insert(refusal);
                        false
                    }
                }
            }));
        self
    }

    /// Reserve the spec temporary buffer's UTF-8 String before growth.
    /// The callback owns its admission and is dropped after the live String.
    /// Copies emitted as native tendrils have separate, unadmitted backing.
    pub fn with_temporary_buffer_reservation<G>(mut self, reservation: G) -> Self
    where
        E: Send + 'static,
        G: Fn(&mut String, usize) -> Result<(), E> + Send + 'static,
    {
        let error = Arc::clone(&self.tokenizer.sink.error);
        self.tokenizer
            .set_temporary_buffer_reservation(Box::new(move |text, additional| {
                if error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some()
                {
                    return false;
                }
                match reservation(text, additional) {
                    Ok(()) => true,
                    Err(refusal) => {
                        error
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get_or_insert(refusal);
                        false
                    }
                }
            }));
        self
    }

    /// Reserve the current tag name's UTF-8 String before growth.
    /// The callback owns its admission and is dropped after the live String.
    /// Interned LocalName values have separate, unadmitted backing.
    pub fn with_tag_name_reservation<G>(mut self, reservation: G) -> Self
    where
        E: Send + 'static,
        G: Fn(&mut String, usize) -> Result<(), E> + Send + 'static,
    {
        let error = Arc::clone(&self.tokenizer.sink.error);
        self.tokenizer
            .set_tag_name_reservation(Box::new(move |text, additional| {
                if error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some()
                {
                    return false;
                }
                match reservation(text, additional) {
                    Ok(()) => true,
                    Err(refusal) => {
                        error
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get_or_insert(refusal);
                        false
                    }
                }
            }));
        self
    }

    /// Reserve the current attribute name's UTF-8 String before growth.
    /// The callback owns its admission and is dropped after the live String.
    /// Interned LocalName values have separate, unadmitted backing.
    pub fn with_attribute_name_reservation<G>(mut self, reservation: G) -> Self
    where
        E: Send + 'static,
        G: Fn(&mut String, usize) -> Result<(), E> + Send + 'static,
    {
        let error = Arc::clone(&self.tokenizer.sink.error);
        self.tokenizer
            .set_attribute_name_reservation(Box::new(move |text, additional| {
                if error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some()
                {
                    return false;
                }
                match reservation(text, additional) {
                    Ok(()) => true,
                    Err(refusal) => {
                        error
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get_or_insert(refusal);
                        false
                    }
                }
            }));
        self
    }

    /// Reserve the actual attribute-value tendril before each append, including
    /// decoded character references. Moves retain its allocation; allocating
    /// copies have separate backing and need their own reservation.
    /// A refusal uses the same first-error channel as the other checkpoints.
    pub fn with_attribute_value_reservation<G>(mut self, reservation: G) -> Self
    where
        E: Send + 'static,
        G: Fn(&mut StrTendril, usize) -> Result<(), E> + Send + 'static,
    {
        let error = Arc::clone(&self.tokenizer.sink.error);
        self.tokenizer
            .set_attribute_value_reservation(Box::new(move |value, additional| {
                if error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some()
                {
                    return false;
                }
                match reservation(value, additional) {
                    Ok(()) => true,
                    Err(refusal) => {
                        error
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get_or_insert(refusal);
                        false
                    }
                }
            }));
        self
    }

    /// Reserve the actual comment tendril before append. Its allocation can
    /// retain the reservation through token moves and native DOM ownership.
    /// A refusal uses the same first-error channel as the other checkpoints.
    pub fn with_comment_reservation<G>(mut self, reservation: G) -> Self
    where
        E: Send + 'static,
        G: Fn(&mut StrTendril, usize) -> Result<(), E> + Send + 'static,
    {
        let error = Arc::clone(&self.tokenizer.sink.error);
        self.tokenizer
            .set_comment_reservation(Box::new(move |comment, additional| {
                if error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some()
                {
                    return false;
                }
                match reservation(comment, additional) {
                    Ok(()) => true,
                    Err(refusal) => {
                        error
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get_or_insert(refusal);
                        false
                    }
                }
            }));
        self
    }

    /// Reserve the actual doctype name and identifiers before each character.
    /// Their allocation headers retain admission through token and DOM moves.
    /// A refusal uses the same first-error channel as the other checkpoints.
    pub fn with_doctype_reservation<G>(mut self, reservation: G) -> Self
    where
        E: Send + 'static,
        G: Fn(&mut StrTendril, usize) -> Result<(), E> + Send + 'static,
    {
        let error = Arc::clone(&self.tokenizer.sink.error);
        self.tokenizer
            .set_doctype_reservation(Box::new(move |text, additional| {
                if error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some()
                {
                    return false;
                }
                match reservation(text, additional) {
                    Ok(()) => true,
                    Err(refusal) => {
                        error
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get_or_insert(refusal);
                        false
                    }
                }
            }));
        self
    }

    /// Install before input to admit input attribute vectors and every checked
    /// parser clone. Sink callbacks receive the whole owning carrier and must
    /// retain its guard until the input allocation is freed or transferred.
    /// Destination storage and attribute payload copies need separate admission.
    pub fn with_tag_attributes_reservation<R, G, S, M, C, A>(
        mut self,
        reserve: G,
        settle: S,
        map_error: M,
        create_element: C,
        add_attributes: A,
    ) -> Self
    where
        E: Send + 'static,
        R: Send + Sync + 'static,
        G: Fn(usize) -> Result<R, E> + Send + Sync + 'static,
        S: Fn(&mut R, usize) -> Result<(), E> + Send + Sync + 'static,
        M: Fn(ReserveError<E>) -> E + Send + Sync + 'static,
        C: Fn(
                &Sink,
                crate::QualName,
                crate::tokenizer::TagAttributes,
                crate::tree_builder::ElementFlags,
            ) -> Result<Sink::Handle, E>
            + Send
            + 'static,
        A: Fn(&Sink, &Sink::Handle, crate::tokenizer::TagAttributes) -> Result<(), E> + Send + 'static,
    {
        let error = Arc::clone(&self.tokenizer.sink.error);
        let create_error = Arc::clone(&error);
        let add_error = Arc::clone(&error);
        let reservation: crate::tokenizer::TagAttributesReservation =
            Arc::new(move |attrs, additional| {
                if error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some()
                {
                    return false;
                }
                match attrs.try_reserve(additional, &reserve, &settle) {
                    Ok(()) => true,
                    Err(refusal) => {
                        error
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get_or_insert_with(|| map_error(refusal));
                        false
                    }
                }
            });
        self.tokenizer
            .set_tag_attributes_reservation(Arc::clone(&reservation));
        self.tokenizer.sink.sink.set_tag_attributes_hooks(
            crate::tree_builder::TagAttributesHooks {
                reserve: reservation,
                create: Box::new(move |sink, name, attrs, flags| {
                    if create_error
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .is_some()
                    {
                        return None;
                    }
                    match create_element(sink, name, attrs, flags) {
                        Ok(handle) => Some(handle),
                        Err(refusal) => {
                            create_error
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .get_or_insert(refusal);
                            None
                        }
                    }
                }),
                add: Box::new(move |sink, target, attrs| {
                    if add_error
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .is_some()
                    {
                        return false;
                    }
                    match add_attributes(sink, target, attrs) {
                        Ok(()) => true,
                        Err(refusal) => {
                            add_error
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .get_or_insert(refusal);
                            false
                        }
                    }
                }),
            },
        );
        self
    }

    /// Install before input to reserve native pending-table vector storage.
    /// Native capacity is measured and its reservation moves with the vector
    /// through take and flush. The iterator frees before returning admission.
    /// Native capacity/allocation failures use the caller's typed mapper and
    /// this parser's existing first-error channel.
    pub fn with_pending_table_storage_reservation<R, G, S, M>(
        mut self,
        reserve: G,
        settle: S,
        map_error: M,
    ) -> Self
    where
        E: Send + 'static,
        R: Send + Sync + 'static,
        G: Fn(usize) -> Result<R, E> + Send + 'static,
        S: Fn(&mut R, usize) -> Result<(), E> + Send + 'static,
        M: Fn(ReserveError<E>) -> E + Send + 'static,
    {
        let error = Arc::clone(&self.tokenizer.sink.error);
        self.tokenizer
            .sink
            .sink
            .set_pending_table_storage_reservation(Box::new(move |pending, additional| {
                if error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some()
                {
                    return false;
                }
                match pending.try_reserve(additional, &reserve, &settle) {
                    Ok(()) => true,
                    Err(refusal) => {
                        error
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get_or_insert_with(|| map_error(refusal));
                        false
                    }
                }
            }));
        self
    }

    /// Reserve actual pending table-text payload before storing or coalescing
    /// UTF-8. The first payload is built in a fresh native destination; existing
    /// input storage is not retrospectively admitted. The native header keeps
    /// its reservation through flush and drop. Pending vector storage is separate.
    /// A refusal uses this parser's existing first-error channel.
    pub fn with_pending_table_text_reservation<G>(mut self, reservation: G) -> Self
    where
        E: Send + 'static,
        G: Fn(&mut StrTendril, usize) -> Result<(), E> + Send + 'static,
    {
        let error = Arc::clone(&self.tokenizer.sink.error);
        self.tokenizer
            .sink
            .sink
            .set_pending_table_text_reservation(Box::new(move |text, additional| {
                if error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some()
                {
                    return false;
                }
                match reservation(text, additional) {
                    Ok(()) => true,
                    Err(refusal) => {
                        error
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get_or_insert(refusal);
                        false
                    }
                }
            }));
        self
    }

    /// Parse borrowed UTF-8 without copying the whole input into a heap tendril.
    /// Each input tendril contains one Unicode scalar and fits in tendril's
    /// inline storage. Tokenizer and sink allocations remain separate.
    /// Character-token batching follows the scalar stream, not whole-input runs.
    /// The first checkpoint failure stops further input production.
    pub fn one_str(mut self, input: &str) -> Result<Sink::Output, E> {
        self.tokenizer.sink.sink.coalesce_table_text();
        for character in input.chars() {
            if !self.tokenizer.checkpoint() {
                break;
            }
            self.input_buffer
                .push_back(StrTendril::from_char(character));
            loop_until_done(&self.tokenizer, &self.input_buffer);
        }
        self.finish()
    }

    /// Accept UTF-8 bytes with the ordinary parser's lossy decoder.
    #[allow(clippy::wrong_self_convention)]
    pub fn from_utf8(self) -> Utf8LossyDecoder<Self> {
        Utf8LossyDecoder::new(self)
    }
}

impl<Sink, F, E> TendrilSink<UTF8> for CheckedParser<Sink, F, E>
where
    Sink: TreeSink,
    F: Fn() -> Result<(), E>,
{
    type Output = Result<Sink::Output, E>;

    fn process(&mut self, text: StrTendril) {
        if self.tokenizer.checkpoint() {
            self.input_buffer.push_back(text);
            loop_until_done(&self.tokenizer, &self.input_buffer);
        }
    }

    fn error(&mut self, description: Cow<'static, str>) {
        if self.tokenizer.checkpoint() {
            self.tokenizer.sink.sink.report_parse_error(description);
        }
    }

    fn finish(self) -> Self::Output {
        loop_until_done(&self.tokenizer, &self.input_buffer);
        if self.tokenizer.checkpoint() {
            assert!(
                self.input_buffer.is_empty(),
                "parser finished with remaining input"
            );
            self.tokenizer.end();
            self.tokenizer.checkpoint();
        }
        let CheckpointSink { sink, error, .. } = self.tokenizer.into_sink();
        let refused = error.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(error) = refused {
            drop(sink);
            drop(self.input_buffer);
            return Err(error);
        }
        Ok(sink.sink.finish())
    }
}

struct CheckpointSink<Sink, F, E> {
    sink: Sink,
    checkpoint: F,
    error: Arc<Mutex<Option<E>>>,
}

impl<Sink, F, E> TokenSink for CheckpointSink<Sink, F, E>
where
    Sink: TokenSink,
    F: Fn() -> Result<(), E>,
{
    type Handle = Sink::Handle;

    fn checkpoint(&self) -> bool {
        if self.error.lock().unwrap_or_else(PoisonError::into_inner).is_some() {
            return false;
        }
        match (self.checkpoint)() {
            Ok(()) => true,
            Err(error) => {
                self.error.lock().unwrap_or_else(PoisonError::into_inner).get_or_insert(error);
                false
            }
        }
    }

    fn process_token(&self, token: Token, line_number: u64) -> TokenSinkResult<Self::Handle> {
        self.sink.process_token(token, line_number)
    }

    fn process_token_with_checkpoint(
        &self,
        token: Token,
        line_number: u64,
        checkpoint: &dyn Fn() -> bool,
    ) -> TokenSinkResult<Self::Handle> {
        self.sink.process_token_with_checkpoint(token, line_number, checkpoint)
    }

    fn end(&self) {
        self.sink.end();
    }

    fn adjusted_current_node_present_but_not_in_html_namespace(&self) -> bool {
        self.sink
            .adjusted_current_node_present_but_not_in_html_namespace()
    }
}
