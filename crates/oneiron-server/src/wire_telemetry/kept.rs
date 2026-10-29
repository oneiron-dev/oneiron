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
    /// health check reads past its cursor. Each page is one read
    /// transaction, starting after the last key the one before it read, so
    /// the family is never read whole, no count bounds it and the writer is
    /// never taken (FIX 10863).
    pub(crate) fn kept_questions_after(
        &self,
        after: Option<&str>,
    ) -> Result<Vec<(String, WireQuestion)>> {
        let mut kept: Vec<(String, WireQuestion)> = Vec::new();
        let mut after = after.map(str::to_owned);
        loop {
            let next = self.vault.sync_state_prefix_page(
                QUESTION_SEQ,
                after.as_deref(),
                KEPT_PAGE,
                |key, bytes| {
                    kept.push((key.to_owned(), decode(bytes)?));
                    Ok(())
                },
            )?;
            match next {
                Some(next) => after = Some(next),
                None => return Ok(kept),
            }
        }
    }

    /// The last call-volume question sequence kept, if any. Pages the whole
    /// family (FIX 11013) and keeps only the last key, so no count bounds it;
    /// a key that does not parse is skipped.
    pub(crate) fn last_kept_question_seq(&self) -> Result<Option<u64>> {
        let mut last = None;
        let mut after: Option<String> = None;
        loop {
            let mut page_last = None;
            let next = self.vault.sync_state_prefix_page(
                QUESTION_SEQ,
                after.as_deref(),
                KEPT_PAGE,
                |key, _| {
                    if let Some(seq) = key
                        .strip_prefix(QUESTION_SEQ)
                        .and_then(|seq| seq.parse::<u64>().ok())
                    {
                        page_last = Some(seq);
                    }
                    Ok(())
                },
            )?;
            if page_last.is_some() {
                last = page_last;
            }
            match next {
                Some(next) => after = Some(next),
                None => return Ok(last),
            }
        }
    }

    /// Every limit question kept, by key: each row's windows, oldest first.
    /// Pages the family (FIX 11013) as `kept_questions_after` does, so no
    /// count bounds it.
    pub(crate) fn kept_limit_questions(&self) -> Result<Vec<(String, WireLimitQuestion)>> {
        let mut kept: Vec<(String, WireLimitQuestion)> = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let next = self.vault.sync_state_prefix_page(
                LIMIT_QUESTION,
                after.as_deref(),
                KEPT_PAGE,
                |key, bytes| {
                    kept.push((key.to_owned(), decode(bytes)?));
                    Ok(())
                },
            )?;
            match next {
                Some(next) => after = Some(next),
                None => return Ok(kept),
            }
        }
    }
}
