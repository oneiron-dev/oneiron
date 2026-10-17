//! The READERS board block (ARCH-0067 #inbox-section, ARCH-0032
//! #private-reads): an agent sees who may read its diary and its sealed
//! scratchpads, and who did, with the reason each read stated. There are no
//! secret readers.
//!
//! Pinned: whether the agent reviews each read first, and the ruled readers
//! of its sealed pads. Detail: each reader a `diary.read` Grant admits, then
//! the newest logged reads and the review asks not yet spent. The rows read
//! the engine's own reader list and read log
//! ([`Memory::diary_reader_list`], [`Memory::diary_reads`]).

use super::scratchpad::clip;
use super::{BoardSection, SectionPolicy, ShedRank, quoted_leaf};
use crate::memory::{
    DiaryReadsRequest, DiaryReviewState, MEMORY_CODE_INTERNAL, Memory, MemoryError, MemoryResult,
    SealedPadReader,
};

/// The newest logged reads the block shows; the rest are counted.
const READS_SHOWN: u32 = 4;
/// The review asks the block shows, newest first.
const ASKS_SHOWN: u32 = 4;
/// Longest stated reason a row quotes, in bytes.
const REASON_SHOWN_BYTES: usize = 160;

/// The `pads:` token of each ruled sealed-pad reader.
fn pad_reader_token(reader: SealedPadReader) -> &'static str {
    match reader {
        SealedPadReader::Owner => "owner",
        SealedPadReader::Coach => "coach",
    }
}

/// The SCRATCHPAD block's reader line: who may read the pad once sealed.
pub(super) fn sealed_pad_readers_line(readers: &[SealedPadReader]) -> String {
    let readers: Vec<&str> = readers
        .iter()
        .map(|reader| pad_reader_token(*reader))
        .collect();
    format!("readers: {} (after seal)", readers.join(" "))
}

fn state_token(state: DiaryReviewState) -> &'static str {
    match state {
        DiaryReviewState::Pending => "pending",
        DiaryReviewState::Approved => "approved",
        DiaryReviewState::Declined => "declined",
        DiaryReviewState::Used => "used",
    }
}

impl Memory<'_> {
    /// The READERS block of this agent's board.
    pub fn board_readers_section(&self) -> MemoryResult<BoardSection> {
        let list = self.diary_reader_list()?;
        let log = self.diary_reads(&DiaryReadsRequest {
            limit: Some(READS_SHOWN.max(ASKS_SHOWN)),
        })?;
        let pinned = vec![
            format!("review: {}", if log.review { "on" } else { "off" }),
            format!(
                "pads: {}",
                list.sealed_pads
                    .iter()
                    .map(|reader| pad_reader_token(*reader))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        ];
        let mut rows: Vec<String> = list
            .diary
            .iter()
            .map(|reader| {
                let class = reader.actor_class.as_deref().unwrap_or("any");
                let reach = if reader.whole {
                    "whole".to_owned()
                } else {
                    format!("entries={}", reader.entries)
                };
                format!(
                    "diary: {} class={class} {reach}",
                    quoted_leaf(&reader.actor_ref)
                )
            })
            .collect();
        rows.extend(log.reads.iter().take(READS_SHOWN as usize).map(|read| {
            format!(
                "read: {} class={} at={} {}",
                read.reader.to_hex(),
                read.reader_class,
                read.at,
                quoted_leaf(clip(&read.reason, REASON_SHOWN_BYTES))
            )
        }));
        rows.extend(log.requests.iter().take(ASKS_SHOWN as usize).map(|ask| {
            format!(
                "ask: {} {} {} {}",
                ask.request.to_hex(),
                state_token(ask.state),
                ask.reader.to_hex(),
                quoted_leaf(clip(&ask.reason, REASON_SHOWN_BYTES))
            )
        }));
        BoardSection::new(
            "READERS",
            pinned,
            rows,
            vec![format!("count: {} diary readers", list.diary.len())],
            SectionPolicy {
                pinned: false,
                shed_rank: Some(ShedRank::PluginSections),
            },
        )
        .map_err(|error| {
            MemoryError::new(
                MEMORY_CODE_INTERNAL,
                error.to_string(),
                &["Report this readers render."],
            )
        })
    }
}
