//! The full decode of a bundle with a character head
//! (`oneironer-decode-v1`): BIO, the DATE snap, character refinement. That
//! decode counts in Unicode scalars, as the model project's does, from the
//! same encoding the byte offsets come from; spans return to UTF-8 bytes
//! before they leave this module.

use std::collections::{BTreeMap, HashMap};

use super::{Span, Window, best_probability, decode};

/// The decode a bundle's `characters.decode_revision` must name. The
/// refinement constants and the DATE particle tables below are this
/// revision's; none of them is a bundle field.
pub(in crate::oneironer) const ONEIRONER_DECODE_REVISION: &str = "oneironer-decode-v1";

/// How many characters refinement may move a span edge. A platform worker's
/// handshake must declare it.
pub(in crate::oneironer) const CHAR_REFINE_K: usize = 3;

/// The edge probability a moved edge must strictly exceed. A platform
/// worker's handshake must declare it.
pub(in crate::oneironer) const CHAR_REFINE_TAU: f32 = 0.5;

/// Whether a call without `EncoderInput.language` runs the DATE snap. The
/// snap's tables are keyed by language and no language source reaches the
/// live callers yet (FIX 6713), so such a call skips it; character
/// refinement runs either way.
const DATE_SNAP_WITHOUT_LANGUAGE: bool = false;

/// The character vocabulary's id for a character outside it.
const UNKNOWN_CHARACTER: u32 = 1;

/// Which side of a character the head scores: its probability of starting
/// a span, and of being a span's last character.
const START_EDGE: usize = 0;
const END_EDGE: usize = 1;

/// The stages after BIO when the bundle has a character head. Both snap DATE
/// ends before refinement; the served runtime snaps them again after it, as
/// refinement can regrow a particle, and E4's frozen baseline does not.
#[derive(Clone, Copy, Debug)]
pub(in crate::oneironer) struct DecodeLayers {
    pub(in super::super) final_date_snap: bool,
}

impl DecodeLayers {
    /// What the slot serves, on every runtime that decodes here.
    pub(in crate::oneironer) const SERVED: Self = Self {
        final_date_snap: true,
    };
    /// E4's baseline, which `oneironer qualify` compares against.
    pub(in super::super) const E4: Self = Self {
        final_date_snap: false,
    };
}

/// The window's text as Unicode scalars, the unit the character head and
/// its decode count in, beside the UTF-8 byte offsets every output keeps.
pub(in crate::oneironer) struct Characters {
    scalars: Vec<char>,
    /// The byte each scalar starts at, then the text's length.
    bytes: Vec<usize>,
    /// Each token's half-open scalar range, from the window's one encoding.
    tokens: Vec<(usize, usize)>,
}

impl Characters {
    pub(in crate::oneironer) fn new(window: &Window<'_>) -> Self {
        let (mut bytes, scalars): (Vec<usize>, Vec<char>) = window.text.char_indices().unzip();
        bytes.push(window.text.len());
        let tokens = window
            .encoding
            .get_offsets()
            .iter()
            .map(|&(start, end)| (scalar_at(&bytes, start), scalar_at(&bytes, end)))
            .collect();
        Self {
            scalars,
            bytes,
            tokens,
        }
    }

    /// The scalar a byte offset into the window's text falls in.
    fn scalar(&self, byte: usize) -> usize {
        scalar_at(&self.bytes, byte)
    }
}

/// The scalar holding a UTF-8 byte offset, counted as the tokenizer counts
/// its own char offsets: a byte inside a character falls in that character,
/// and the text's length is its scalar count. `bytes` ends with that length.
fn scalar_at(bytes: &[usize], byte: usize) -> usize {
    bytes
        .partition_point(|&start| start <= byte)
        .saturating_sub(1)
}

/// The character head's inputs over the observed window: every scalar up to
/// the furthest token end, prefixes, context and uncovered gaps included, so
/// its convolutions see the characters around each one.
pub(in crate::oneironer) struct CharacterFeatures {
    /// Vocabulary ids; `UNKNOWN_CHARACTER` for one outside the vocabulary.
    pub(in super::super) ids: Vec<u32>,
    /// The first token covering each character; none for a gap.
    pub(in super::super) tokens: Vec<Option<u32>>,
    /// The character's offset in that token over the token's width less one
    /// (at least one), and the token's width over 32.
    pub(in super::super) positions: Vec<[f32; 2]>,
}

impl CharacterFeatures {
    pub(in crate::oneironer) fn new(characters: &Characters, vocab: &HashMap<char, u32>) -> Self {
        let length = characters
            .tokens
            .iter()
            .map(|&(_, end)| end)
            .max()
            .unwrap_or(0);
        let mut tokens = vec![None; length];
        let mut positions = vec![[0.0; 2]; length];
        for (index, &(start, end)) in characters.tokens.iter().enumerate() {
            let width = end.saturating_sub(start);
            let scale = width.saturating_sub(1).max(1) as f64;
            let extent = (width as f64 / 32.0) as f32;
            for character in start..end {
                if tokens[character].is_none() {
                    tokens[character] = Some(index as u32);
                    positions[character] = [((character - start) as f64 / scale) as f32, extent];
                }
            }
        }
        let ids = characters.scalars[..length]
            .iter()
            .map(|scalar| vocab.get(scalar).copied().unwrap_or(UNKNOWN_CHARACTER))
            .collect();
        Self {
            ids,
            tokens,
            positions,
        }
    }
}

/// A decoded name, with the byte coordinates BIO gave it before the DATE
/// snap and refinement moved them: a mention proposed there is this name.
pub(in crate::oneironer) struct Named {
    pub(in super::super) span: Span,
    pub(in super::super) decoded: (usize, usize),
}

impl From<Span> for Named {
    fn from(span: Span) -> Self {
        Self {
            decoded: (span.start, span.end),
            span,
        }
    }
}

/// The full decode of `oneironer-decode-v1` for the NER head: BIO, the DATE
/// snap, character refinement, then the DATE snap again when `layers` asks.
/// Every stage counts in Unicode scalars, as the reference does. Confidence
/// is the mean winning probability over the tokens a refined span overlaps,
/// as the served runtime scores it. The Core ML worker decodes its own
/// logits and character probabilities here too (FIX 6755 slice 2c).
pub(in crate::oneironer) fn decode_ner(
    window: &Window<'_>,
    characters: &Characters,
    logits: &[Vec<f32>],
    labels: &[String],
    probabilities: &[[f32; 2]],
    language: Option<&str>,
    layers: DecodeLayers,
) -> anyhow::Result<Vec<Named>> {
    let spans = decode(window, logits, labels, 0.0)?;
    let winners = logits
        .iter()
        .map(|scores| best_probability(scores).map(|(_, winner)| winner))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut edges: Vec<(usize, usize)> = spans
        .iter()
        .map(|span| (characters.scalar(span.start), characters.scalar(span.end)))
        .collect();
    let snap = language.is_some() || DATE_SNAP_WITHOUT_LANGUAGE;
    let language = language.unwrap_or_default();
    if snap {
        snap_dates(&spans, &mut edges, &characters.scalars, language);
    }
    refine(window, characters, &spans, &mut edges, probabilities);
    let covers: Vec<_> = edges
        .iter()
        .map(|&(start, end)| cover(characters, &winners, start, end))
        .collect();
    if snap && layers.final_date_snap {
        snap_dates(&spans, &mut edges, &characters.scalars, language);
    }
    Ok(spans
        .into_iter()
        .zip(edges)
        .zip(covers)
        .map(|((mut span, (start, end)), (confidence, tokens))| {
            let decoded = (span.start, span.end);
            span.start = characters.bytes[start];
            span.end = characters.bytes[end];
            span.confidence = confidence;
            if let Some((first, last)) = tokens {
                span.first_token = first;
                span.last_token = last;
            }
            Named { span, decoded }
        })
        .collect())
}

/// Trims trailing particles off every DATE-base span, in place. A span is
/// never trimmed to nothing and its start never moves.
fn snap_dates(spans: &[Span], edges: &mut [(usize, usize)], scalars: &[char], language: &str) {
    for (span, (start, end)) in spans.iter().zip(edges) {
        if span.label.split('/').next() == Some("DATE") {
            *end -= snap_date_end(&scalars[*start..*end], language);
        }
    }
}

/// Character refinement, turn by turn. A turn whose spans overlap after the
/// snap (repeated tokenizer offsets do that), or run past the observed
/// characters, keeps every span where it is: a skipped refinement, never a
/// failed call or a dropped span. A span moves only within its own message.
fn refine(
    window: &Window<'_>,
    characters: &Characters,
    spans: &[Span],
    edges: &mut [(usize, usize)],
    probabilities: &[[f32; 2]],
) {
    let observed = probabilities.len();
    let same_segment = |a: &usize, b: &usize| spans[*a].segment == spans[*b].segment;
    let mut turns: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, span) in spans.iter().enumerate() {
        turns
            .entry(window.segments[span.segment].turn_index)
            .or_default()
            .push(index);
    }
    for mut members in turns.into_values() {
        members.sort_by_key(|&index| edges[index]);
        let overlapping = members
            .windows(2)
            .any(|pair| edges[pair[0]].1 > edges[pair[1]].0);
        let outside = members.iter().any(|&index| edges[index].1 > observed);
        if overlapping || outside {
            continue;
        }
        for group in members.chunk_by(same_segment) {
            let segment = &window.segments[spans[group[0]].segment];
            let low = characters.scalar(segment.base);
            let high = characters.scalar(segment.end).min(observed);
            refine_message(group, edges, probabilities, low, high);
        }
    }
}

/// Refines one message's spans, sorted and disjoint, within `[low, high)`.
/// Each edge may move to the likeliest character within `CHAR_REFINE_K`
/// that neither the previous span, as decoded or as refined, nor the next
/// span's decoded start rules out. A proposal whose start would not precede
/// its end leaves the span as it was.
fn refine_message(
    members: &[usize],
    edges: &mut [(usize, usize)],
    probabilities: &[[f32; 2]],
    low: usize,
    high: usize,
) {
    if low >= high {
        return;
    }
    let mut previous = low;
    for (rank, &index) in members.iter().enumerate() {
        let (start, end) = edges[index];
        let following = members.get(rank + 1).map_or(high, |&next| edges[next].0);
        let moved_start = pick(probabilities, START_EDGE, start, previous, following - 1);
        let moved_end = pick(probabilities, END_EDGE, end - 1, previous, following - 1) + 1;
        if moved_start < moved_end {
            edges[index] = (moved_start, moved_end);
        }
        previous = end.max(edges[index].1);
    }
}

/// The candidate within `CHAR_REFINE_K` of `old` and inside `[low, high]`
/// with the highest edge probability, ties going to the smaller move and
/// then the earlier character. The edge moves there only when that
/// probability is strictly above `CHAR_REFINE_TAU`.
fn pick(probabilities: &[[f32; 2]], edge: usize, old: usize, low: usize, high: usize) -> usize {
    let first = low.max(old.saturating_sub(CHAR_REFINE_K));
    let mut best = first;
    for candidate in first + 1..=high.min(old + CHAR_REFINE_K) {
        let probability = probabilities[candidate][edge];
        let held = probabilities[best][edge];
        let closer = candidate.abs_diff(old) < best.abs_diff(old);
        if probability > held || (probability == held && closer) {
            best = candidate;
        }
    }
    if probabilities[best][edge] > CHAR_REFINE_TAU {
        best
    } else {
        old
    }
}

/// The mean winning probability over the tokens overlapping `[start, end)`,
/// with the first and last of those tokens.
fn cover(
    characters: &Characters,
    winners: &[f32],
    start: usize,
    end: usize,
) -> (f32, Option<(usize, usize)>) {
    let mut total = 0.0_f64;
    let mut count = 0_u32;
    let mut tokens: Option<(usize, usize)> = None;
    for (index, (&(low, high), &winner)) in characters.tokens.iter().zip(winners).enumerate() {
        if high > low && low < end && high > start {
            total += f64::from(winner);
            count += 1;
            let first = tokens.map_or(index, |(first, _)| first);
            tokens = Some((first, index));
        }
    }
    let confidence = if count == 0 {
        0.0
    } else {
        (total / f64::from(count)) as f32
    };
    (confidence, tokens)
}

/// The particles a DATE end sheds in one language.
struct DateParticles {
    /// Tried in order before single characters, so a two-character particle
    /// is never half trimmed.
    multi: &'static [&'static str],
    single: &'static [char],
    /// Content words ending in a particle lookalike: trimming stops at them.
    protected: &'static [&'static str],
}

/// Range connectors (から, まで, ごろ) and で are deliberately absent: gold
/// range spans end in them.
static JA_DATE_PARTICLES: DateParticles = DateParticles {
    multi: &[],
    single: &['に', 'の', 'は', 'が', 'を', 'へ', 'と', 'も'],
    protected: &[],
};

/// Range connectors (부터, 까지) are deliberately absent.
static KO_DATE_PARTICLES: DateParticles = DateParticles {
    multi: &["에는", "에도", "에서", "으로"],
    single: &['에', '은', '는', '이', '가', '을', '를', '의', '도', '로'],
    protected: &["가을"],
};

/// The DATE particle table for an exact language key; none for any other.
fn date_particles(language: &str) -> Option<&'static DateParticles> {
    match language {
        "ja" => Some(&JA_DATE_PARTICLES),
        "ko" => Some(&KO_DATE_PARTICLES),
        _ => None,
    }
}

/// How many trailing characters to trim from a predicted DATE surface.
/// Particles come off one at a time until a protected word ends the head,
/// no particle is left, or one character remains.
fn snap_date_end(surface: &[char], language: &str) -> usize {
    let Some(table) = date_particles(language) else {
        return 0;
    };
    let mut end = surface.len();
    while end > 1 {
        let head = &surface[..end];
        if table.protected.iter().any(|word| ends_with(head, word)) {
            break;
        }
        let multi = table
            .multi
            .iter()
            .find(|suffix| ends_with(head, suffix) && end > suffix.chars().count());
        if let Some(suffix) = multi {
            end -= suffix.chars().count();
        } else if table.single.contains(&head[end - 1]) {
            end -= 1;
        } else {
            break;
        }
    }
    surface.len() - end
}

/// Whether `head` ends with the characters of `word`.
fn ends_with(head: &[char], word: &str) -> bool {
    head.ends_with(&word.chars().collect::<Vec<_>>())
}
