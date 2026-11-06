//! Caller checkpoints for the existing tokenizer and tree builder.

use super::{loop_until_done, ParseOpts};
use crate::buffer_queue::BufferQueue;
use crate::tendril::stream::{TendrilSink, Utf8LossyDecoder};
use crate::tendril::{fmt::UTF8, StrTendril};
use crate::tokenizer::{Token, TokenSink, TokenSinkResult, Tokenizer};
use crate::tree_builder::{TreeBuilder, TreeSink};
use std::borrow::Cow;
use std::cell::RefCell;

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
        error: RefCell::new(None),
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
        if let Some(error) = error.into_inner() {
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
    error: RefCell<Option<E>>,
}

impl<Sink, F, E> TokenSink for CheckpointSink<Sink, F, E>
where
    Sink: TokenSink,
    F: Fn() -> Result<(), E>,
{
    type Handle = Sink::Handle;

    fn checkpoint(&self) -> bool {
        if self.error.borrow().is_some() {
            return false;
        }
        match (self.checkpoint)() {
            Ok(()) => true,
            Err(error) => {
                *self.error.borrow_mut() = Some(error);
                false
            }
        }
    }

    fn process_token(&self, token: Token, line_number: u64) -> TokenSinkResult<Self::Handle> {
        self.sink.process_token(token, line_number)
    }

    fn end(&self) {
        self.sink.end();
    }

    fn adjusted_current_node_present_but_not_in_html_namespace(&self) -> bool {
        self.sink
            .adjusted_current_node_present_but_not_in_html_namespace()
    }
}
