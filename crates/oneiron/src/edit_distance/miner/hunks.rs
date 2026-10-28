//! Per-hunk mining of a partly unclear amendment (FIX 9808).
//!
//! The judgment keeps each changed hunk's label beside the identity of the
//! substitution that hunk made. A judgment with an unclear share then mines
//! only what its clear hunks made; the unclear hunks stay held in the unclear
//! ledger, and nothing of theirs is taken.

use std::collections::BTreeSet;

use super::model::Substitution;
use crate::edit_distance::attribution::{AmendmentClass, AmendmentJudgment};
use crate::entity_id::bytes_to_hex_lower;

/// Domain for a hunk's substitution identity, so it can never be read as a
/// cluster handle or another unit's hash.
const HUNK_SUBSTITUTION_DOMAIN: &[u8] = b"oneiron:edit-distance-hunk-substitution:v1";

/// The identity of the substitution one changed hunk made, or `None` when the
/// hunk is not a substitution. The judge records it beside the hunk's label,
/// and the miner meets it through the same normalization; it is a digest,
/// never the hunk's text.
pub(in crate::edit_distance) fn hunk_substitution_ref(before: &str, after: &str) -> Option<String> {
    super::mining::substitution_pair(before, after).map(|pair| substitution_ref(&pair))
}

fn substitution_ref(substitution: &Substitution) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HUNK_SUBSTITUTION_DOMAIN);
    hasher.update(substitution.from.as_bytes());
    hasher.update(&[0]);
    hasher.update(substitution.to.as_bytes());
    bytes_to_hex_lower(hasher.finalize().as_bytes())
}

/// Which of a judged amendment's substitutions the miner may take.
pub(super) enum MinableHunks {
    /// No share is unclear: every substitution the amendment shows.
    Whole,
    /// A share is unclear: only the substitutions a clear hunk made.
    Clear(BTreeSet<String>),
}

impl MinableHunks {
    /// What `judgment` lets the miner take, or `None` when it is held whole:
    /// every hunk unclear, or no clear hunk made a substitution.
    pub(super) fn of(judgment: &AmendmentJudgment) -> Option<Self> {
        if judgment.share_of(AmendmentClass::Unclear) > 0.0 {
            let clear: BTreeSet<String> = judgment
                .hunks
                .iter()
                .filter(|hunk| hunk.class != AmendmentClass::Unclear)
                .filter_map(|hunk| hunk.substitution_ref.clone())
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
