//! One causal window with byte-accurate message coordinates. Tokenization
//! never truncates the current turn and never changes the stored text.

use oneiron::memory::extraction::{EncoderInput, EncoderMessage, SpeakerRole};
use tokenizers::{Encoding, Tokenizer};

pub(super) struct Segment<'a> {
    pub(super) turn: &'a str,
    pub(super) message: &'a EncoderMessage,
    pub(super) message_index: usize,
    pub(super) turn_index: usize,
    pub(super) speaker: Option<SpeakerRole>,
    pub(super) current: bool,
    pub(super) base: usize,
    pub(super) end: usize,
    pub(super) source_offset: usize,
}

pub(super) struct Window<'a> {
    pub(super) text: String,
    pub(super) segments: Vec<Segment<'a>>,
    pub(super) encoding: Encoding,
}

fn encode(tokenizer: &Tokenizer, text: &str, special: bool) -> anyhow::Result<Encoding> {
    tokenizer
        .encode(text, special)
        .map_err(|_| anyhow::anyhow!("local extraction tokenization failed"))
}

impl<'a> Window<'a> {
    pub(super) fn new(
        input: &'a EncoderInput,
        tokenizer: &Tokenizer,
        cap: usize,
        live: usize,
    ) -> anyhow::Result<Self> {
        let mut text = String::new();
        let mut segments = Vec::new();
        for (index, turn) in input.context.iter().enumerate() {
            append(
                &mut text,
                &mut segments,
                &turn.turn,
                &turn.messages,
                index,
                turn.speaker,
                false,
            );
        }
        let context_end = text.len();
        append(
            &mut text,
            &mut segments,
            &input.turn,
            &input.messages,
            input.context.len(),
            input.speaker,
            true,
        );
        let current = encode(tokenizer, &text[context_end..], true)?;
        anyhow::ensure!(
            current.len() <= cap,
            "current extraction turn exceeds oneironer.max_input_tokens"
        );
        let budget = live.min(cap.saturating_sub(current.len()));
        let context = encode(tokenizer, &text[..context_end], false)?;
        let mut cut = if context.len() > budget {
            if budget == 0 {
                context_end
            } else {
                context.get_offsets()[context.len() - budget].0
            }
        } else {
            0
        };
        let encoding = loop {
            let encoding = encode(tokenizer, &text[cut..], true)?;
            if encoding.len() <= cap {
                break encoding;
            }
            // The join may tokenize differently from its two pieces. Drop
            // another context token rather than ever truncate current text.
            let next = encoding.get_offsets().iter().find_map(|&(start, end)| {
                (end > start && cut + end <= context_end).then_some(cut + end)
            });
            cut = next.filter(|next| *next > cut).unwrap_or(context_end);
            if cut == context_end {
                break current;
            }
        };
        segments.retain_mut(|segment| {
            if segment.end <= cut {
                return false;
            }
            if segment.base < cut {
                segment.source_offset = cut - segment.base;
                segment.base = cut;
            }
            segment.base -= cut;
            segment.end -= cut;
            true
        });
        Ok(Self {
            text: text[cut..].to_owned(),
            segments,
            encoding,
        })
    }

    pub(super) fn segment(&self, start: usize, end: usize) -> Option<(usize, &Segment<'a>)> {
        self.segments.iter().enumerate().find(|(_, segment)| {
            segment.base <= start
                && start < end
                && end <= segment.end
                && self.text.is_char_boundary(start)
                && self.text.is_char_boundary(end)
        })
    }
}

fn append<'a>(
    text: &mut String,
    segments: &mut Vec<Segment<'a>>,
    turn: &'a str,
    messages: &'a [EncoderMessage],
    turn_index: usize,
    speaker: Option<SpeakerRole>,
    current: bool,
) {
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    // Unknown authors get no invented A/B side.
    match speaker {
        Some(SpeakerRole::User) => text.push_str("A: "),
        Some(SpeakerRole::Companion) => text.push_str("B: "),
        None => {}
    }
    for (message_index, message) in messages.iter().enumerate() {
        if message_index > 0 {
            text.push('\n');
        }
        let base = text.len();
        text.push_str(&message.text);
        segments.push(Segment {
            turn,
            message,
            message_index,
            turn_index,
            speaker,
            current,
            base,
            end: text.len(),
            source_offset: 0,
        });
    }
    text.push('\n');
}

pub(super) struct Span {
    pub(super) segment: usize,
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) first_token: usize,
    pub(super) last_token: usize,
    pub(super) label: String,
    pub(super) confidence: f32,
}

/// BIO decoding repairs an orphan I into a new span, as the reference does.
/// A span crossing a message or speaker prefix is never emitted.
pub(super) fn decode(
    window: &Window<'_>,
    logits: &[Vec<f32>],
    labels: &[String],
    o_bias: f32,
) -> anyhow::Result<Vec<Span>> {
    anyhow::ensure!(
        logits.len() == window.encoding.len(),
        "extraction classifier length mismatch"
    );
    let mut spans = Vec::new();
    let mut active: Option<Span> = None;
    let mut count = 0usize;
    let finish = |active: &mut Option<Span>, count: &mut usize, spans: &mut Vec<Span>| {
        if let Some(mut span) = active.take() {
            span.confidence /= *count as f32;
            spans.push(span);
        }
        *count = 0;
    };
    for (token, (&(start, end), scores)) in
        window.encoding.get_offsets().iter().zip(logits).enumerate()
    {
        anyhow::ensure!(
            scores.len() == labels.len(),
            "extraction classifier label mismatch"
        );
        let mut scores = scores.clone();
        scores[0] += o_bias;
        let (choice, probability) = best_probability(&scores)?;
        let label = labels[choice].split_once('-');
        let location = window.segment(start, end);
        let (Some((prefix, label)), Some((segment, _))) = (label, location) else {
            finish(&mut active, &mut count, &mut spans);
            continue;
        };
        let continues = prefix == "I"
            && active
                .as_ref()
                .is_some_and(|span| span.segment == segment && span.label == label);
        if !continues {
            finish(&mut active, &mut count, &mut spans);
            active = Some(Span {
                segment,
                start,
                end,
                first_token: token,
                last_token: token,
                label: label.to_owned(),
                confidence: 0.0,
            });
        }
        if let Some(span) = active.as_mut() {
            span.end = end;
            span.last_token = token;
            span.confidence += probability;
            count += 1;
        }
    }
    finish(&mut active, &mut count, &mut spans);
    Ok(spans)
}

pub(super) fn best_probability(scores: &[f32]) -> anyhow::Result<(usize, f32)> {
    anyhow::ensure!(
        !scores.is_empty() && scores.iter().all(|value| value.is_finite()),
        "non-finite extraction logits"
    );
    let choice = (1..scores.len()).fold(0, |best, index| {
        if scores[index] > scores[best] {
            index
        } else {
            best
        }
    });
    let total: f32 = scores
        .iter()
        .map(|value| (value - scores[choice]).exp())
        .sum();
    Ok((choice, 1.0 / total))
}
