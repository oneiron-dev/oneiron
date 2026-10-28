//! Per-hunk mining of a partly unclear amendment (FIX 9808).
//!
//! The judgment keeps each changed hunk's label beside the identities of the
//! substitutions that hunk made, at the miner's own extraction granularity. A
//! judgment with an unclear share then mines only what its clear hunks made;
//! the unclear hunks stay held in the unclear ledger, and nothing of theirs is
//! taken, not even a substitution a clear hunk also made.

use std::collections::BTreeSet;

use super::model::Substitution;
use crate::edit_distance::attribution::{AmendmentClass, AmendmentJudgment};
use crate::entity_id::bytes_to_hex_lower;

/// Domain for a hunk's substitution identity, so it can never be read as a
/// cluster handle or another unit's hash.
const HUNK_SUBSTITUTION_DOMAIN: &[u8] = b"oneiron:edit-distance-hunk-substitution:v1";

/// The identities of the substitutions one changed hunk made, at the miner's
/// own extraction granularity: the hunk's whole changed run, as a recorded
/// change is read, and each line it replaced one for one, as a reconstructed
/// re-diff is read. Empty when the hunk makes no substitution. The judge
/// records them beside the hunk's label; they are digests, never the hunk's
/// text.
pub(in crate::edit_distance) fn hunk_substitution_refs(before: &str, after: &str) -> Vec<String> {
    let mut refs: Vec<String> = super::mining::substitution_pair(before, after)
        .into_iter()
        .chain(super::mining::line_substitutions(before, after))
        .map(|pair| substitution_ref(&pair))
        .collect();
    refs.sort();
    refs.dedup();
    refs
}

fn substitution_ref(substitution: &Substitution) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HUNK_SUBSTITUTION_DOMAIN);
    hasher.update(substitution.from.as_bytes());
    hasher.update(&[0]);
    hasher.update(substitution.to.as_bytes());
    bytes_to_hex_lower(hasher.finalize().as_bytes())
}

/// The substitution identities the clear hunks of `judgment` made, or with
/// `clear` false its unclear hunks.
fn refs_where(judgment: &AmendmentJudgment, clear: bool) -> BTreeSet<&str> {
    judgment
        .hunks
        .iter()
        .filter(|hunk| (hunk.class != AmendmentClass::Unclear) == clear)
        .flat_map(|hunk| hunk.substitution_refs.iter().map(String::as_str))
        .collect()
}

/// Which of a judged amendment's substitutions the miner may take.
pub(super) enum MinableHunks {
    /// No share is unclear: every substitution the amendment shows.
    Whole,
    /// A share is unclear: only the substitutions a clear hunk made and no
    /// unclear hunk did.
    Clear(BTreeSet<String>),
}

impl MinableHunks {
    /// What `judgment` lets the miner take, or `None` when it is held whole:
    /// every hunk unclear, or no clear hunk made a substitution of its own.
    pub(super) fn of(judgment: &AmendmentJudgment) -> Option<Self> {
        if judgment.share_of(AmendmentClass::Unclear) > 0.0 {
            let held = refs_where(judgment, false);
            let clear: BTreeSet<String> = refs_where(judgment, true)
                .into_iter()
                .filter(|reference| !held.contains(reference))
                .map(str::to_owned)
                .collect();
            (!clear.is_empty()).then_some(Self::Clear(clear))
        } else {
            Some(Self::Whole)
        }
    }

    /// Whether `substitution` is one this judgment lets the miner take.
    pub(super) fn admits(&self, substitution: &Substitution) -> bool {
        match self {
            Self::Whole => true,
            Self::Clear(refs) => refs.contains(&substitution_ref(substitution)),
        }
    }
}
