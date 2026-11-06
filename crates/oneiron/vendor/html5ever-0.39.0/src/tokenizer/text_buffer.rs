//! Parser text scratch, optionally backed by a caller reservation.

use crate::tendril::StrTendril;
use std::mem;

type Reservation = Box<dyn Fn(&mut String, usize) -> bool + Send>;

pub(super) enum TextBuffer {
    Native(StrTendril),
    Reserved {
        // Drop the bytes before the callback returns their admission.
        text: String,
        reservation: Reservation,
    },
}

impl TextBuffer {
    pub(super) fn new() -> Self {
        Self::Native(StrTendril::new())
    }

    pub(super) fn install(&mut self, reservation: Reservation) -> bool {
        let mut replacement = Self::Reserved {
            text: String::new(),
            reservation,
        };
        if !replacement.push_str(self.as_str()) {
            return false;
        }
        *self = replacement;
        true
    }

    pub(super) fn push_char(&mut self, character: char) -> bool {
        match self {
            Self::Native(text) => {
                text.push_char(character);
                true
            }
            Self::Reserved { .. } => self.push_str(character.encode_utf8(&mut [0; 4])),
        }
    }

    fn push_str(&mut self, value: &str) -> bool {
        match self {
            Self::Native(text) => text.push_slice(value),
            Self::Reserved { text, reservation } => {
                if !reservation(text, value.len()) {
                    return false;
                }
                text.push_str(value);
            }
        }
        true
    }

    pub(super) fn as_str(&self) -> &str {
        match self {
            Self::Native(text) => text,
            Self::Reserved { text, .. } => text,
        }
    }

    pub(super) fn clear(&mut self) {
        match self {
            Self::Native(text) => text.clear(),
            Self::Reserved { text, .. } => text.clear(),
        }
    }

    pub(super) fn take(&mut self) -> StrTendril {
        match self {
            Self::Native(text) => mem::take(text),
            Self::Reserved { text, .. } => {
                // Native output has separate backing. Keep this scratch's
                // capacity admitted until the tokenizer drops it.
                let output = StrTendril::from_slice(text);
                text.clear();
                output
            }
        }
    }
}
