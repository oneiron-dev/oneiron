//! The exchange a call proposes back (FIX 8188, 8192): the newest user text,
//! every answer the caller got and the model, with the rows recall put in the
//! prompt and the memory block as the model read it, for the claim's birth.

use oneiron::EntityId;
use serde_json::{Value, json};

/// One answered call, as its exchange claim records it.
pub(super) struct Exchange<'a> {
    pub(super) user: &'a str,
    /// Every answer, in choice order; never empty.
    pub(super) answers: &'a [String],
    pub(super) model: &'a str,
    /// The rows recall put in the prompt; empty when nothing went in.
    pub(super) producers: &'a [EntityId],
    /// The memory block's bytes as the model read it, when one went in.
    pub(super) read: &'a [&'a [u8]],
}

impl Exchange<'_> {
    /// The claim's value: `{user, assistant, model}`, the answer choice 0's.
    /// A call answered with more than one choice also keeps each answer, in
    /// choice order, under `choices`, so one claim holds them all.
    pub(super) fn value(&self) -> Value {
        let first = self.answers.first().map_or("", String::as_str);
        let mut value = json!({"user": self.user, "assistant": first, "model": self.model});
        if self.answers.len() > 1 {
            value["choices"] = json!(self.answers);
        }
        value
    }
}
