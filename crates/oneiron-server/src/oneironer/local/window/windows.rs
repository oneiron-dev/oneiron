//! Every byte of a turn, in windows a runtime can hold (FIX 9518, 9520).
//!
//! A call whose current turn fits its window is one window, as it always
//! was, and its answer passes through untouched. A current turn longer than
//! `max_input_tokens` is never refused: its text is cut at token boundaries
//! into overlapping parts, each a call of its own that every runtime runs as
//! it runs any call (Candle, Core ML, MLX: each builds the same
//! [`super::Window`] of it), with the turn's earlier and later context
//! beside it as its window's room allows. The token cap is a physical
//! capability of a batch, never a reason a turn goes untagged.
//!
//! Each part owns the stretch of the turn between the middles of its
//! overlaps; a span is kept from the part that owns where it starts, moved
//! back into its message's own byte offsets, and spans found twice at the
//! same coordinates are one. Links are remapped through the merged spans'
//! coordinates, each span keeping one link. A turn read in one part keeps
//! the model's own mood; read in several, it has none of the whole turn —
//! no mean is made up — and each part's measured mood is returned beside
//! the spans ([`MoodPart`]).

use std::collections::{BTreeMap, BTreeSet};

use oneiron::memory::extraction::{
    ContextLink, CorefLink, EncoderInput, EncoderMessage, EncoderOutput, MoodPart, NerSpan,
    SpeakerLink, SpeakerRole,
};

use super::super::{WindowCounter, extraction_failed};
use super::encode;

/// The most times a part plan is shrunk to fit before the call fails as an
/// infer that cannot build its window would.
const SHRINKS: usize = 6;

/// The most tokens two neighbouring parts both read: a quarter of a part
/// otherwise. A span that starts in a part's own stretch is whole in that
/// part when it is at most half the overlap long, and coreference between
/// parts reaches only as far as the overlap. It bounds the text read twice
/// (FIX 10704).
const MAX_PART_OVERLAP_TOKENS: usize = 128;

/// One call's windows: its parts, each a call a runtime runs whole.
pub(crate) struct InferenceWindows {
    parts: Vec<WindowPart>,
    /// The longest part's window in tokens with specials: which workers may
    /// run the call. 0 in a slot that counts none.
    tokens: usize,
    /// Each message's place in the turn's joined text, for a call read in
    /// parts.
    bases: Vec<usize>,
}

/// One part of a call.
struct WindowPart {
    input: EncoderInput,
    /// For each of the part's messages: the call's message it is a piece
    /// of, and where in that message's text the piece starts.
    origins: Vec<(usize, usize)>,
    /// The bytes of the turn's joined text this part owns: a span that
    /// starts there is this part's.
    own: std::ops::Range<usize>,
}

impl InferenceWindows {
    /// A call that is one window: `input` as it came.
    pub(crate) fn whole(input: EncoderInput, tokens: usize) -> Self {
        let origins = (0..input.messages.len()).map(|index| (index, 0)).collect();
        Self {
            parts: vec![WindowPart {
                input,
                origins,
                own: 0..usize::MAX,
            }],
            tokens,
            bases: Vec::new(),
        }
    }

    /// `input`'s windows under `counter`: one when its live window builds,
    /// else, for a current turn longer than the cap, parts that each build
    /// one. Any other window that cannot be built fails as the call's infer
    /// would.
    pub(crate) fn plan(counter: &WindowCounter, input: EncoderInput) -> oneiron::Result<Self> {
        match counter.window(&input).map(|window| window.tokens()) {
            Ok(tokens) => return Ok(Self::whole(input, tokens)),
            Err(error) if !turn_overflows(counter, &input) => return Err(error),
            Err(_) => {}
        }
        let specials = encode(&counter.tokenizer, "", true)
            .map_err(|_| extraction_failed())?
            .len();
        // Room for the specials, a role prefix and the joins, and a quarter
        // of the window for the turn's context.
        let mut piece = counter.cap.saturating_sub(specials + 8).saturating_mul(3) / 4;
        for _ in 0..SHRINKS {
            let planned = split(counter, &input, piece.max(1))?;
            if let Some(windows) = planned {
                return Ok(windows);
            }
            piece /= 2;
        }
        Err(extraction_failed())
    }

    /// Each part's input, in turn order: what the worker runs.
    pub(crate) fn inputs(&self) -> impl Iterator<Item = &EncoderInput> {
        self.parts.iter().map(|part| &part.input)
    }

    /// How many parts the call runs as.
    pub(crate) fn len(&self) -> usize {
        self.parts.len()
    }

    /// The longest part's window in tokens with specials.
    pub(crate) const fn tokens(&self) -> usize {
        self.tokens
    }

    /// The call's one answer from its parts' answers, in part order
    /// ([`merge_window_outputs`]).
    pub(crate) fn merge(&self, outputs: Vec<EncoderOutput>) -> oneiron::Result<EncoderOutput> {
        merge_window_outputs(self, outputs)
    }
}

/// Whether `input`'s current turn alone, as its window writes it, is longer
/// than the counter's cap.
fn turn_overflows(counter: &WindowCounter, input: &EncoderInput) -> bool {
    let (text, _) = joined(input);
    // A window ends its turn with a newline.
    let prefixed = format!("{}{text}\n", prefix(input.speaker));
    encode(&counter.tokenizer, &prefixed, true).is_ok_and(|encoding| encoding.len() > counter.cap)
}

/// The role prefix a window writes before a turn.
fn prefix(speaker: Option<SpeakerRole>) -> &'static str {
    match speaker {
        Some(SpeakerRole::User) => "A: ",
        Some(SpeakerRole::Companion) => "B: ",
        None => "",
    }
}

/// The turn's messages joined by a newline, as a window writes them, and
/// each message's place in that text.
fn joined(input: &EncoderInput) -> (String, Vec<usize>) {
    let mut text = String::new();
    let mut bases = Vec::with_capacity(input.messages.len());
    for (index, message) in input.messages.iter().enumerate() {
        if index > 0 {
            text.push('\n');
        }
        bases.push(text.len());
        text.push_str(&message.text);
    }
    (text, bases)
}

/// `input` cut into parts of at most `piece` tokens of its turn's text,
/// overlapping by a quarter of a part, and [`MAX_PART_OVERLAP_TOKENS`], at
/// most; `None` when a part still builds no window, for a smaller piece to
/// try.
fn split(
    counter: &WindowCounter,
    input: &EncoderInput,
    piece: usize,
) -> oneiron::Result<Option<InferenceWindows>> {
    let (text, bases) = joined(input);
    let encoding = encode(&counter.tokenizer, &text, false).map_err(|_| extraction_failed())?;
    let offsets: Vec<(usize, usize)> = encoding
        .get_offsets()
        .iter()
        .copied()
        .filter(|(start, end)| end > start)
        .collect();
    if offsets.is_empty() {
        return Ok(None);
    }
    let overlap = (piece / 4).min(MAX_PART_OVERLAP_TOKENS);
    // Token ranges of each part.
    let mut ranges = Vec::new();
    let mut first = 0;
    loop {
        let last = offsets.len().min(first + piece);
        ranges.push(first..last);
        if last == offsets.len() {
            break;
        }
        first = last.saturating_sub(overlap).max(first + 1);
    }
    // Where each part's ownership starts: the middle of its overlap.
    let mut bounds = vec![0];
    for pair in ranges.windows(2) {
        let shared = pair[1].start..pair[0].end;
        let middle = shared.start + shared.len() / 2;
        bounds.push(offsets[middle.min(offsets.len() - 1)].0);
    }
    bounds.push(usize::MAX);
    let mut parts = Vec::with_capacity(ranges.len());
    let mut tokens = 0;
    for (place, range) in ranges.iter().enumerate() {
        let from = if place == 0 {
            0
        } else {
            offsets[range.start].0
        };
        let to = if range.end == offsets.len() {
            text.len()
        } else {
            offsets[range.end - 1].1
        };
        let mut messages = Vec::new();
        let mut origins = Vec::new();
        for (index, message) in input.messages.iter().enumerate() {
            let base = bases[index];
            let start = from.max(base).saturating_sub(base);
            let end = to.min(base + message.text.len()).saturating_sub(base);
            let start = floor_boundary(&message.text, start);
            let end = ceil_boundary(&message.text, end);
            if start >= end {
                continue;
            }
            messages.push(EncoderMessage {
                id: message.id.clone(),
                text: message.text[start..end].to_owned(),
            });
            origins.push((index, start));
        }
        let part = EncoderInput {
            messages,
            ..input.clone()
        };
        let Ok(fits) = counter.window(&part).map(|window| window.tokens()) else {
            return Ok(None);
        };
        tokens = tokens.max(fits);
        parts.push(WindowPart {
            input: part,
            origins,
            own: bounds[place]..bounds[place + 1],
        });
    }
    Ok(Some(InferenceWindows {
        parts,
        tokens,
        bases,
    }))
}

fn floor_boundary(text: &str, mut at: usize) -> usize {
    while at > 0 && !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

fn ceil_boundary(text: &str, mut at: usize) -> usize {
    while at < text.len() && !text.is_char_boundary(at) {
        at += 1;
    }
    at
}

/// A span's coordinates in the call: its message, start and end bytes.
type Place = (usize, usize, usize);

/// The call's one answer from its parts' answers, in part order. One part's
/// answer is the answer. Several are merged: every span from the part that
/// owns where it starts, in its call message's own offsets and in
/// (message, start, end) order, one per coordinates; each link remapped
/// through the merged coordinates, kept from the part that owns its span,
/// one per span; no whole-turn mood, and each part's mood beside the spans.
/// Parts that name different stacks are no answer.
pub(crate) fn merge_window_outputs(
    windows: &InferenceWindows,
    outputs: Vec<EncoderOutput>,
) -> oneiron::Result<EncoderOutput> {
    if outputs.len() != windows.parts.len() {
        return Err(extraction_failed());
    }
    if windows.parts.len() == 1 {
        return outputs.into_iter().next().ok_or_else(extraction_failed);
    }
    let stack = outputs
        .first()
        .and_then(|output| output.stack_sha16.clone());
    if outputs.iter().any(|output| output.stack_sha16 != stack) {
        return Err(extraction_failed());
    }
    // Every part span's call coordinates, and whether its part owns it.
    let mut places: Vec<Vec<(Place, bool)>> = Vec::with_capacity(outputs.len());
    let mut kept: BTreeMap<Place, NerSpan> = BTreeMap::new();
    for (part, output) in windows.parts.iter().zip(&outputs) {
        let mut placed = Vec::with_capacity(output.spans.len());
        for span in &output.spans {
            let &(message, offset) = part
                .origins
                .get(span.message)
                .ok_or_else(extraction_failed)?;
            let place = (message, span.start + offset, span.end + offset);
            let at = windows.bases.get(message).copied().unwrap_or(0) + place.1;
            let owned = part.own.contains(&at);
            if owned {
                kept.entry(place).or_insert_with(|| NerSpan {
                    message,
                    start: place.1,
                    end: place.2,
                    label: span.label.clone(),
                    confidence: span.confidence,
                });
            }
            placed.push((place, owned));
        }
        places.push(placed);
    }
    let index: BTreeMap<Place, usize> = kept
        .keys()
        .enumerate()
        .map(|(place, key)| (*key, place))
        .collect();
    let mut merged = EncoderOutput {
        spans: kept.into_values().collect(),
        links: Vec::new(),
        vad: None,
        context_links: Vec::new(),
        speaker_links: Vec::new(),
        mood_parts: Vec::new(),
        stack_sha16: stack,
    };
    let mut linked = BTreeSet::new();
    for ((part, output), placed) in windows.parts.iter().zip(&outputs).zip(&places) {
        // A span this part owns, by its merged index.
        let owned = |span: usize| {
            placed
                .get(span)
                .filter(|(_, owned)| *owned)
                .and_then(|(place, _)| index.get(place).copied())
        };
        let any = |span: usize| {
            placed
                .get(span)
                .and_then(|(place, _)| index.get(place).copied())
        };
        for link in &output.links {
            if let (Some(span), Some(antecedent)) = (owned(link.span), any(link.antecedent))
                && antecedent < span
                && linked.insert(span)
            {
                merged.links.push(CorefLink {
                    span,
                    antecedent,
                    confidence: link.confidence,
                });
            }
        }
        for link in &output.context_links {
            if let Some(span) = owned(link.span)
                && linked.insert(span)
            {
                merged.context_links.push(ContextLink {
                    span,
                    ..link.clone()
                });
            }
        }
        for link in &output.speaker_links {
            if let Some(span) = owned(link.span)
                && linked.insert(span)
            {
                merged.speaker_links.push(SpeakerLink {
                    span,
                    ..link.clone()
                });
            }
        }
        if let (Some(vad), Some(&(message, start)), Some(&(end_message, last))) =
            (output.vad, part.origins.first(), part.origins.last())
        {
            let end = part
                .input
                .messages
                .last()
                .map_or(last, |piece| last + piece.text.len());
            merged.mood_parts.push(MoodPart {
                message,
                start,
                end_message,
                end,
                vad,
            });
        }
    }
    Ok(merged)
}
