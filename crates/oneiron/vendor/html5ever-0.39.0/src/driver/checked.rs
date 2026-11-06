//! Caller checkpoints for the existing tokenizer and tree builder.

use super::{loop_until_done, ParseOpts};
use crate::buffer_queue::BufferQueue;
use crate::tendril::stream::{TendrilSink, Utf8LossyDecoder};
use crate::tendril::{fmt::UTF8, StrTendril};
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
            self.tokenizer.sink.sink.sink.parse_error(description);
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
