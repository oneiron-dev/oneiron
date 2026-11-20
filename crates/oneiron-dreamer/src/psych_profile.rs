//! Chooses a Psych Mirror profile's source claims and scores its confidence
//! as pure policy (untangle 6.9i; canon ARCH-0025).
//!
//! The engine ranks the claims about one person and serves them in rank
//! order, best first. This module keeps the restricted bands out, groups the
//! rest by predicate, fills the profile's source slots round robin across
//! the groups, and scores the chosen set's confidence. It makes no client
//! calls or writes and measures nothing: the engine renders the model's input
//! and judges its reply.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How many claims one profile reads: canon's claim density saturates at 50
/// claims (ARCH-0025 #conf), past which more claims add no confidence.
pub const SOURCE_SLOTS: usize = 50;

/// The lowest sensitivity band the Dreamer never reads into a profile, the
/// consolidation neighbourhood's own floor: a profile's prose cannot be cut
/// by band, so it reads only the bands below this one.
pub const RESTRICTED_BAND: u8 = 3;

/// Where a claim came from, as the engine serves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSource {
    /// The person said it.
    UserStated,
    /// Read from what the person did.
    Observed,
    /// Concluded by an earlier pass.
    Inferred,
    /// Came in from another source.
    Imported,
    /// A tool's output.
    ToolOutput,
    /// Generated.
    Generated,
}

/// One candidate claim about the person, as the engine serves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// The claim's predicate: the groups the slots fill across.
    pub predicate: String,
    /// The claim's sensitivity band, or `None` when it carries none.
    pub band: Option<u8>,
    /// Where the claim came from, or `None` when it names no source.
    pub source: Option<ClaimSource>,
}

/// Whether a claim in `band` may be read into a profile: only a band below
/// [`RESTRICTED_BAND`]. A claim that carries no band is kept out.
#[must_use]
pub fn admits_band(band: Option<u8>) -> bool {
    band.is_some_and(|band| band < RESTRICTED_BAND)
}

/// The candidates one profile reads, as positions in `ranked`, in slot order.
///
/// `ranked` is the engine's rank order, best first. A candidate whose band
/// [`admits_band`] refuses is skipped. The rest are grouped by predicate, the
/// groups ordered by their best-ranked member, and the [`SOURCE_SLOTS`] slots
/// filled round robin: the best of each group in group order, then the second
/// of each, and so on, passing over a group that has run out. When every
/// predicate differs, this is rank order.
#[must_use]
pub fn fill_slots(ranked: &[Candidate]) -> Vec<usize> {
    let mut group_of: BTreeMap<&str, usize> = BTreeMap::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (position, candidate) in ranked.iter().enumerate() {
        if !admits_band(candidate.band) {
            continue;
        }
        let group = *group_of
            .entry(candidate.predicate.as_str())
            .or_insert_with(|| {
                groups.push(Vec::new());
                groups.len() - 1
            });
        groups[group].push(position);
    }
    let mut slots = Vec::with_capacity(SOURCE_SLOTS.min(ranked.len()));
    let mut round = 0;
    while slots.len() < SOURCE_SLOTS {
        let filled = slots.len();
        for members in &groups {
            if slots.len() == SOURCE_SLOTS {
                break;
            }
            if let Some(&position) = members.get(round) {
                slots.push(position);
            }
        }
        if slots.len() == filled {
            break;
        }
        round += 1;
    }
    slots
}

/// The weight canon gives a claim's source (ARCH-0025 #conf): stated 1.0,
/// observed 0.8, imported 0.7, and 0.5 for inferred or any other source.
#[must_use]
pub fn source_weight(source: Option<ClaimSource>) -> f64 {
    match source {
        Some(ClaimSource::UserStated) => 1.0,
        Some(ClaimSource::Observed) => 0.8,
        Some(ClaimSource::Imported) => 0.7,
        Some(ClaimSource::Inferred | ClaimSource::ToolOutput | ClaimSource::Generated) | None => {
            0.5
        }
    }
}

/// A profile's confidence from the sources of the claims it read (ARCH-0025
/// #conf): claim density saturating at [`SOURCE_SLOTS`] claims, blended 60/40
/// with the sources' mean [`source_weight`], rounded to two decimals. A
/// profile that read no claim scores 0. Each tier carries the same value.
#[must_use]
pub fn confidence(sources: impl IntoIterator<Item = Option<ClaimSource>>) -> f32 {
    let (count, weight) = sources
        .into_iter()
        .fold((0_usize, 0.0_f64), |(count, weight), source| {
            (count + 1, weight + source_weight(source))
        });
    if count == 0 {
        return 0.0;
    }
    let count = count as f64;
    let density = (count / SOURCE_SLOTS as f64).min(1.0);
    let quality = weight / count;
    (((density * 0.6 + quality * 0.4) * 100.0).round() / 100.0) as f32
}
