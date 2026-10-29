//! One judge-conversion chain, resolved whole: an old score follows the
//! swap maps to the current judge, and a cyclic lineage is explicitly
//! invalid, so the row folds as unknown.

use std::collections::{BTreeMap, BTreeSet};

/// Where a score's conversion chain ends.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Resolved {
    /// No swap map names this judge; the score is already current.
    Current,
    /// The score on the current judge's scale, after at least one hop.
    Converted(f64),
    /// The chain loops back on itself; the lineage is unusable.
    Invalid,
}

/// Follows `judge`'s score `x` through every accepted swap map to the
/// terminal judge. A repeated judge is a cycle, not a longer chain.
pub(super) fn resolve(
    judge: &str,
    mut x: f64,
    conversions: &BTreeMap<String, super::judge::JudgeConversion>,
) -> Resolved {
    let mut visited: BTreeSet<&str> = BTreeSet::from([judge]);
    let mut current = judge;
    let mut converted = false;
    loop {
        let Some(conversion) = conversions.get(current) else {
            if converted {
                return Resolved::Converted(x);
            }
            return Resolved::Current;
        };
        if !visited.insert(conversion.to_judge.as_str()) {
            return Resolved::Invalid;
        }
        x = conversion.map(x);
        converted = true;
        current = &conversion.to_judge;
    }
}
