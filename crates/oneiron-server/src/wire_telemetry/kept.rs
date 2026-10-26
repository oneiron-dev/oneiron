//! The kept questions as the health check reads them (OF-520): the
//! call-volume questions past its cursor, a page at a time (FIX 10863), and
//! the limit questions.
use oneiron::Result;

use super::{LIMIT_QUESTION, QUESTION_SEQ, WireLimitQuestion, WireQuestion, WireTelemetry, decode};

/// How many kept questions one page of the cursor read takes.
const KEPT_PAGE: usize = 256;

impl WireTelemetry {
    /// The call-volume questions kept after the one under `after`, from the
    /// first with `None`, by key, in the order they were kept: what the
    /// health check reads past its cursor. Each page starts after the last
    /// key the one before it read, so the family is never read whole and no
    /// count bounds it (FIX 10863); the page door deletes nothing here.
    pub(crate) fn kept_questions_after(
        &self,
        after: Option<&str>,
    ) -> Result<Vec<(String, WireQuestion)>> {
        let mut kept = Vec::new();
        let mut after = after.map(str::to_owned);
        loop {
            let next = self.vault.sync_state_reclaim_prefix_page(
                QUESTION_SEQ,
                after.as_deref(),
                KEPT_PAGE,
                |bytes| {
                    let question: WireQuestion = decode(bytes)?;
                    kept.push((format!("{QUESTION_SEQ}{:020}", question.seq), question));
                    Ok(false)
                },
            )?;
            match next {
                Some(next) => after = Some(next),
                None => return Ok(kept),
            }
        }
    }

    /// Every limit question kept, by key: each row's windows, oldest first.
    pub(crate) fn kept_limit_questions(&self) -> Result<Vec<(String, WireLimitQuestion)>> {
        let mut kept = Vec::new();
        for key in self.vault.sync_state_keys_with_prefix(LIMIT_QUESTION)? {
            if let Some(bytes) = self.vault.sync_state_get(&key)? {
                kept.push((key, decode(&bytes)?));
            }
        }
        Ok(kept)
    }
}
