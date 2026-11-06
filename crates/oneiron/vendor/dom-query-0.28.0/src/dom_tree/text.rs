//! Parser-only text allocation callbacks. Other DOM mutations remain ordinary.

use super::Tree;
use crate::entities::{wrap_tendril, StrWrap};
use std::sync::Arc;
use tendril::StrTendril;

pub(super) struct ParserTextReservation {
    create: Box<dyn Fn(&str) -> Option<StrWrap> + Send + Sync>,
    append: Box<dyn Fn(&mut StrWrap, usize) -> bool + Send + Sync>,
}

impl Tree {
    /// Install before parsing to construct the final native text payload and
    /// reserve its actual mutable destination before coalescing more UTF-8.
    /// The caller must retain the first failure and expose it to the checked
    /// parser's checkpoints; None/false stops this sink call, not the driver.
    /// Clones share these callbacks, but ordinary cloning and other mutations
    /// do not acquire admission for any new payload they allocate.
    pub fn with_parser_text_reservation<C, A>(mut self, create: C, append: A) -> Self
    where
        C: Fn(&str) -> Option<StrWrap> + Send + Sync + 'static,
        A: Fn(&mut StrWrap, usize) -> bool + Send + Sync + 'static,
    {
        self.parser_text = Some(Arc::new(ParserTextReservation {
            create: Box::new(create),
            append: Box::new(append),
        }));
        self
    }

    pub(crate) fn create_parser_text(&self, text: StrTendril) -> Option<StrWrap> {
        match &self.parser_text {
            Some(reservation) => (reservation.create)(&text),
            None => Some(wrap_tendril(text)),
        }
    }

    pub(crate) fn append_parser_text(&self, contents: &mut StrWrap, text: &StrTendril) -> bool {
        if let Some(reservation) = &self.parser_text {
            if !(reservation.append)(contents, text.len()) {
                return false;
            }
            contents.push_slice(text);
        } else {
            #[cfg(not(feature = "atomic"))]
            contents.push_tendril(text);
            #[cfg(feature = "atomic")]
            contents.push_slice(text);
        }
        true
    }
}
