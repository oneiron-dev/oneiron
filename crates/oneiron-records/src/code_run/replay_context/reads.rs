//! Moved from `crates/oneiron/src/code_run/replay_context/reads.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The verdict the door's row check gave one read of another run's result
/// (FIX 6352): the rows it was served from may reach the door's caller,
/// they stay on this device, or the door refused the read with the code it
/// named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainedReadVerdict {
    Admitted,
    Withheld,
    Refused(String),
}

impl RetainedReadVerdict {
    /// The verdict a row check's answer gives: `Ok(withheld)`, or the code
    /// of the refusal the door named.
    pub fn of(answer: std::result::Result<bool, &str>) -> Self {
        match answer {
            Ok(false) => Self::Admitted,
            Ok(true) => Self::Withheld,
            Err(code) => Self::Refused(code.to_owned()),
        }
    }
}

/// The answer the reads `seen` establish at bridge position `cut`, each
/// answer with the first and last position it was seen at, where `settled`
/// says an answer is final once seen: a final answer seen before the cut, an
/// answer that is not final seen after it, else the one answer every read at
/// the cut saw. `None` when they establish none.
pub fn established_at<T: Copy + PartialEq>(
    seen: impl Iterator<Item = (u64, u64, T)>,
    cut: u64,
    settled: impl Fn(&T) -> bool,
) -> Option<T> {
    let mut at_cut = None;
    let mut agree = true;
    for (first, last, answer) in seen {
        if (settled(&answer) && first < cut) || (!settled(&answer) && last > cut) {
            return Some(answer);
        }
        if first <= cut && cut <= last {
            agree &= at_cut.is_none_or(|held| held == answer);
            at_cut = Some(answer);
        }
    }
    at_cut.filter(|_| agree)
}
