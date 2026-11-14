//! The phonetic channel's sound-match rung (CROSS-ARCH-0013 `#ladder` rung
//! 1, G2P → IPA → NPD): a query code `ipa:<lang>:<ipa>` is not looked up as a
//! posting; it is compared with every entity's stored `ipa:` keys by
//! Normalized Phonetic Distance.
//!
//! An entity scores its best distance over its keys and the query's keys.
//! Entities further than the threshold are no match; of the rest, those
//! within the keep ratio of the best distance are kept, nearest first, up to
//! the cap (CROSS-ARCH-0013 `#problem`). A kept match adds `1 - distance` to
//! the entity's channel score as one more match, so an exact code (1.0)
//! always outscores a sound alone, and the channel's agreement boost rewards
//! code and sound agreeing (`#flow`: a phonetic match only boosts).

use std::collections::HashMap;

use crate::EntityId;
use crate::batch::phonetic_codes::{Segment, ipa_segments, npd};
use crate::pipeline::RetrievalParams;

/// The prefix of a sound key.
pub(crate) const SOUND_KEY_PREFIX: &str = "ipa:";

/// Whether `code` is a sound key, compared by distance rather than looked
/// up as a posting.
pub(crate) fn is_sound_key(code: &str) -> bool {
    code.starts_with(SOUND_KEY_PREFIX)
}

/// The segments of a sound key `ipa:<lang>:<ipa>`; `None` for any other
/// code or one whose IPA does not parse.
fn sound_key_segments(code: &str) -> Option<Vec<Segment>> {
    let (_lang, ipa) = code.strip_prefix(SOUND_KEY_PREFIX)?.split_once(':')?;
    ipa_segments(ipa)
}

/// One sound-match scan: the query's keys, offered every candidate key in
/// turn.
pub(crate) struct SoundScan {
    queries: Vec<Vec<Segment>>,
    threshold: f32,
    keep_ratio: f32,
    cap: usize,
    best: HashMap<EntityId, f32>,
}

impl SoundScan {
    /// The scan for the sound keys among `codes`; `None` when there are
    /// none, so the caller reads no candidate.
    pub(crate) fn new(codes: &[String], params: &RetrievalParams) -> Option<Self> {
        let mut queries: Vec<Vec<Segment>> = Vec::new();
        for segments in codes
            .iter()
            .map(String::as_str)
            .filter_map(sound_key_segments)
        {
            if !queries.contains(&segments) {
                queries.push(segments);
            }
        }
        (!queries.is_empty()).then(|| Self {
            queries,
            threshold: params.phonetic_npd_threshold,
            keep_ratio: params.phonetic_npd_keep_ratio,
            cap: params.phonetic_npd_cap,
            best: HashMap::new(),
        })
    }

    /// Compares `id`'s stored code with the query; any code other than a
    /// parsable sound key is passed over.
    pub(crate) fn offer(&mut self, id: EntityId, code: &str) {
        let Some(candidate) = sound_key_segments(code) else {
            return;
        };
        for query in &self.queries {
            // An insertion or deletion costs 1, so a length gap alone puts
            // a candidate this far away; skip it unread.
            let length_gap = query.len().abs_diff(candidate.len()) as f32;
            if length_gap / query.len() as f32 > self.threshold {
                continue;
            }
            let distance = npd(query, &candidate);
            if distance <= self.threshold {
                let best = self.best.entry(id).or_insert(distance);
                *best = best.min(distance);
            }
        }
    }

    /// The kept matches, nearest first: within the threshold, within the
    /// keep ratio of the best distance, at most the cap. Equal distances
    /// keep id order, so a cut is the same on every run.
    pub(crate) fn finish(self) -> Vec<(EntityId, f32)> {
        let mut matches: Vec<(EntityId, f32)> = self.best.into_iter().collect();
        matches.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        let Some(&(_, nearest)) = matches.first() else {
            return matches;
        };
        let bound = nearest * self.keep_ratio;
        matches.retain(|(_, distance)| *distance <= bound);
        matches.truncate(self.cap);
        matches
    }
}

/// The score a kept sound match adds to its entity: 1 at distance 0, less
/// as the sounds part.
pub(crate) fn sound_match_score(distance: f32) -> f32 {
    1.0 - distance
}
