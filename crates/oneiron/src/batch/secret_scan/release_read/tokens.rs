//! The release provider-key rule as a body's text streams (FIX 7200, FIX 5392
//! Rule 5). It reads what [`classify_token`] reads in each token, one
//! character at a time. No length bounds a token, so the reader does not
//! keep one whole. It reads each start in a token over at most
//! [`KEY_WINDOW`] bytes, the most any provider rule reads, and keeps only
//! that window. Starts are read in their order: the token's own start as a
//! token, each later one as a key inside it, and at each start the rules in
//! their order. The first key found names the reason, and nothing after it
//! is read.
//!
//! [`classify_token`]: super::super::provider_tokens::classify_token

use super::super::provider_tokens::{KEY_WINDOW, credential_at, token_char};

/// The provider rule over a text's tokens as the text streams.
#[derive(Default)]
pub(super) struct ProviderTokens {
    /// The current token's text, from a start already read on. The starts
    /// from `next` on are not read yet.
    window: String,
    /// Where in `window` the first start not read yet is.
    next: usize,
    /// That start lies past the token's first byte.
    embedded: bool,
    /// The first key's reason.
    found: Option<&'static str>,
}

impl ProviderTokens {
    /// Reads `ch` on: a token character extends the current token, and any
    /// other character ends it.
    pub(super) fn feed(&mut self, ch: char) {
        if self.found.is_some() {
            return;
        }
        if !token_char(ch) {
            self.end_token();
            return;
        }
        self.window.push(ch);
        if self.window.len() - self.next < KEY_WINDOW {
            return;
        }
        // The first start not read has its whole window now: no later byte
        // changes what the rules read there.
        self.read_start();
        if self.next >= KEY_WINDOW {
            self.window.replace_range(..self.next, "");
            self.next = 0;
        }
    }

    /// Ends the current token: each start not read yet is read over what
    /// the token has left after it.
    pub(super) fn end_token(&mut self) {
        while self.found.is_none() && self.next < self.window.len() {
            self.read_start();
        }
        self.window.clear();
        self.next = 0;
        self.embedded = false;
    }

    /// The reason of the first key found, once there is one.
    pub(super) fn found(&self) -> Option<&'static str> {
        self.found
    }

    /// Reads the first start not read yet. Token bytes are ASCII, so every
    /// offset in `window` is a char boundary.
    fn read_start(&mut self) {
        let end = self.window.len().min(self.next + KEY_WINDOW);
        self.found = credential_at(&self.window[self.next..end], !self.embedded);
        self.next += 1;
        self.embedded = true;
    }
}
