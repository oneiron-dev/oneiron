//! The Core ML worker's answer from its outputs (FIX 6755 slice 2c,
//! contract rev 3 B2), on every target.
//!
//! Both outputs read are float16 `[1, C, 1, L]`: `logits`, `C` the label
//! table's length, and `proj`, `C` the character head's width. Each is read
//! by its own strides, widened to f32, cut to the window's first `n`
//! columns and turned to `[n, C]`; a wrong shape, a stride past its buffer
//! or a value that is not finite fails the call. `pooled` is not read: this
//! bundle has no affect head.
//!
//! The logits feed BIO as Candle's do. `proj` is the character head's
//! projection, already applied by the model, so the head's tail goes on
//! from it on the CPU, in F32, and it is never projected again. Then the
//! decode is Candle's own: `oneironer-decode-v1` as the slot serves it (BIO,
//! the DATE snaps, character refinement), and the current turn's names by
//! Candle's own assembly of the current messages' spans.

use candle_core::{Device, Tensor};
use half::f16;
use oneiron::memory::extraction::NerSpan;

use super::super::local::{
    CharacterFeatures, CharacterModel, Characters, DecodeLayers, Window, current_message_spans,
    decode_ner,
};

/// One float16 output, copied off the model on the worker's thread: its
/// shape, its strides in elements, and its values' bits in buffer order.
pub(super) struct HalfArray {
    pub(super) shape: Vec<usize>,
    pub(super) strides: Vec<usize>,
    pub(super) bits: Vec<u16>,
}

/// The two outputs an answer reads, refilled by each prediction.
pub(super) struct Outputs {
    pub(super) logits: HalfArray,
    pub(super) proj: HalfArray,
}

impl Outputs {
    /// Empty outputs, for a worker's first prediction to fill.
    pub(super) const fn new() -> Self {
        Self {
            logits: HalfArray::new(),
            proj: HalfArray::new(),
        }
    }
}

impl HalfArray {
    const fn new() -> Self {
        Self {
            shape: Vec::new(),
            strides: Vec::new(),
            bits: Vec::new(),
        }
    }

    /// Columns `..n` of this `[1, width, 1, tokens]` output as `n` rows of
    /// `width` widened values: element `(c, j)` at its strides.
    fn columns(&self, width: usize, tokens: usize, n: usize) -> anyhow::Result<Vec<Vec<f32>>> {
        anyhow::ensure!(
            self.shape == [1, width, 1, tokens] && self.strides.len() == 4 && n <= tokens,
            "a core ml output is not [1, {width}, 1, {tokens}]"
        );
        let (channel, column) = (self.strides[1], self.strides[3]);
        let last = reach(width, channel).zip(reach(tokens, column));
        let last = last.and_then(|(across, along)| across.checked_add(along));
        anyhow::ensure!(
            last.is_some_and(|last| last < self.bits.len()),
            "a core ml output's strides run past its buffer"
        );
        let mut rows = Vec::with_capacity(n);
        for token in 0..n {
            let mut row = Vec::with_capacity(width);
            for at in 0..width {
                let value = f16::from_bits(self.bits[at * channel + token * column]).to_f32();
                anyhow::ensure!(value.is_finite(), "a core ml output is not finite");
                row.push(value);
            }
            rows.push(row);
        }
        Ok(rows)
    }
}

/// How far past the first of `count` elements `stride` apart the last one
/// sits: `None` for no element, or past `usize`.
fn reach(count: usize, stride: usize) -> Option<usize> {
    count.checked_sub(1)?.checked_mul(stride)
}

/// The current turn's spans from a prediction of `tokens` columns over
/// `window`, as the module says.
pub(super) fn decode(
    window: &Window<'_>,
    outputs: &Outputs,
    tokens: usize,
    head: &CharacterModel,
    labels: &[String],
    language: Option<&str>,
) -> anyhow::Result<Vec<NerSpan>> {
    let n = window.ids().len();
    let logits = outputs.logits.columns(labels.len(), tokens, n)?;
    let projected: Vec<f32> = outputs.proj.columns(head.width, tokens, n)?.concat();
    let projected = Tensor::from_vec(projected, (n, head.width), &Device::Cpu)?;
    let characters = Characters::new(window);
    let features = CharacterFeatures::new(&characters, &head.vocab);
    let boundary = &head.boundary;
    let probabilities = boundary.probabilities_from_projected(&projected, &features)?;
    let named = decode_ner(
        window,
        &characters,
        &logits,
        labels,
        &probabilities,
        language,
        DecodeLayers::SERVED,
    )?;
    Ok(current_message_spans(window, &named))
}
