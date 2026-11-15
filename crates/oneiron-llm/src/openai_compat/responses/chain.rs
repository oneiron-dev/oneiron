//! Responses socket-chain operations and item digests.
//! Entry: OpenAiResponsesChain::plan.
//! OpenAiResponsesChain and item_digest stay in the parent; this module owns the moved impl and function.

use super::{
    JsonValue, OpenAiResponsesChain, item_digest, openai_responses_items,
    parse_openai_responses_output,
};

impl OpenAiResponsesChain {
    /// What `items` sends on this socket: the chained response and only the
    /// items past it when `items` extends this chain, else no response and
    /// every item.
    #[must_use]
    pub fn plan<'t>(&self, items: &'t [JsonValue]) -> (Option<&str>, &'t [JsonValue]) {
        match &self.response_id {
            Some(id) if self.extended_by(items) => {
                (Some(id.as_str()), &items[self.digests.len()..])
            }
            _ => (None, items),
        }
    }

    /// Whether `items` is this chain plus at least one new item.
    #[must_use]
    pub fn extended_by(&self, items: &[JsonValue]) -> bool {
        self.response_id.is_some()
            && items.len() > self.digests.len()
            && items
                .iter()
                .zip(&self.digests)
                .all(|(item, digest)| item_digest(item) == *digest)
    }

    /// Records the turn that sent `items` and completed as `response` (the
    /// `response` object of `response.completed`). A response this codec
    /// cannot read leaves the chain empty, so the next turn sends everything.
    pub fn record(&mut self, items: &[JsonValue], response: &JsonValue) {
        let id = response.get("id").and_then(JsonValue::as_str);
        match (id, parse_openai_responses_output(response)) {
            (Some(id), Ok(reply)) => {
                self.response_id = Some(id.to_owned());
                self.digests = items
                    .iter()
                    .chain(&openai_responses_items(&reply.message))
                    .map(item_digest)
                    .collect();
            }
            _ => self.clear(),
        }
    }

    pub fn clear(&mut self) {
        self.response_id = None;
        self.digests.clear();
    }

    /// The response this chain ends at.
    #[must_use]
    pub fn response_id(&self) -> Option<&str> {
        self.response_id.as_deref()
    }

    /// The digest of each item the chain covers, oldest first.
    #[must_use]
    pub fn digests(&self) -> &[u64] {
        &self.digests
    }

    /// The chain that ends at `response_id` and covers `items`: a
    /// conversation's stored chain, taken up on another socket.
    #[must_use]
    pub fn resumed(items: &[JsonValue], response_id: String) -> Self {
        Self {
            response_id: Some(response_id),
            digests: responses_item_digests(items),
        }
    }
}

/// The digest of each of `items`, as a chain keeps them.
#[must_use]
pub fn responses_item_digests(items: &[JsonValue]) -> Vec<u64> {
    items.iter().map(item_digest).collect()
}
