//! Who answered a quota question (restriction wave 11, census C17; RULING
//! WAVE11-QUOTA-CANON 13:25 and ANSWER WAVE11-DUPLICATE-BUILDER 14:29): the
//! owner, or the agent his key `models.quota.agent_may_answer` lets give that
//! answer. The answer's row is written in the write that closes the question,
//! beside the questions in the same table, so a question an answer closed
//! always has one: its own answer, or the top-up that put its account back
//! in rotation. A question that lapses at its reset was not answered and has
//! none. Question ids are offer ids, so the table keeps the last answer per
//! offer.

use oneiron::{EntityId, Vault};
use serde::{Deserialize, Serialize};

use super::QuotaChoice;

/// The answer rows, beside the offers' rests and the owner's questions.
const ANSWER_PREFIX: &str = "models:offer-cooldown:v1:answer:";

/// Who gave a quota question's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaAnswerer {
    /// The owner, at `POST /v1/ai/quota/{id}`.
    Owner,
    /// An agent the owner's key let give that answer.
    Agent(EntityId),
}

/// The answer one quota question got: which choice, the fallback a
/// `use_fallback` named, who gave it and when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaAnswerRecord {
    /// The question's id: the offer it asked about.
    pub question: String,
    pub choice: QuotaChoice,
    /// The model a `use_fallback` named; `None` for the other choices.
    pub fallback: Option<String>,
    pub answered_by: QuotaAnswerer,
    /// When, on the vault's recorded clock.
    pub answered_at: u64,
}

impl QuotaAnswerRecord {
    /// The last answer the question `id` got, if one is kept.
    ///
    /// # Errors
    ///
    /// A storage error, or a kept row that does not decode.
    pub fn read(vault: &Vault, id: &str) -> oneiron::Result<Option<Self>> {
        vault
            .sync_state_get(&row(id))?
            .map(|bytes| {
                rmp_serde::from_slice(&bytes)
                    .map_err(|_| oneiron::Error::InvariantViolation("decode a quota answer"))
            })
            .transpose()
    }

    /// Keeps this answer in `txn`, in place of the question's last one.
    pub(super) fn put_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
    ) -> oneiron::Result<()> {
        let bytes = rmp_serde::to_vec_named(self)
            .map_err(|_| oneiron::Error::InvariantViolation("encode a quota answer"))?;
        vault.sync_state_put_in_write_txn(txn, &row(&self.question), &bytes)
    }
}

/// Where the answer to question `id` is kept.
fn row(id: &str) -> String {
    format!("{ANSWER_PREFIX}{id}")
}
