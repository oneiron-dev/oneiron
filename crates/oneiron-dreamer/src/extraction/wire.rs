//! Shared calls and commit decoding for the extraction job.

use oneiron_remote::OneironClient;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{Error, ItemResult};

/// Names the attempt-bound derive commit.
pub(super) const COMMIT: &str = "vault.derive.commit";

/// Calls one verb, preserving the refusal code and unread message.
pub(super) fn call(
    client: &OneironClient,
    verb: &'static str,
    request: Value,
) -> Result<Value, Error> {
    client
        .agent_verb(verb, request)
        .map_err(|error| Error::Client {
            verb,
            code: error.code,
            message: error.message,
        })
}

/// Decodes one answer under its stage's verb.
pub(super) fn decode<T: DeserializeOwned>(verb: &'static str, answer: Value) -> Result<T, Error> {
    serde_json::from_value(answer).map_err(|error| Error::Decode {
        verb,
        message: error.to_string(),
    })
}

/// Commits the supplied request and adds its batch id to every item view.
pub(super) fn commit(
    client: &OneironClient,
    request: Value,
    expected: usize,
) -> Result<Vec<ItemResult>, Error> {
    let answer = call(client, COMMIT, request)?;
    let mut view: CommitView = decode(COMMIT, answer)?;
    if view.items.len() != expected {
        return Err(Error::Decode {
            verb: COMMIT,
            message: "the commit did not answer one view per submitted item".to_owned(),
        });
    }
    for item in &mut view.items {
        item.batch.clone_from(&view.batch);
    }
    Ok(view.items)
}

/// Mirrors only the commit view fields this job reports.
#[derive(Deserialize)]
struct CommitView {
    /// Names the engine's derive batch.
    batch: String,
    /// Holds item results in batch order.
    items: Vec<ItemResult>,
}
