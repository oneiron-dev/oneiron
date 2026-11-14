//! Myanmar Zawgyi detection and conversion (ONE-ZAWGYI, ARCH-0031 `#deferred`).
//!
//! Zawgyi is a font-hack encoding of Burmese that reuses Myanmar code points
//! in other orders and meanings: a note written in Unicode Burmese and a query
//! typed in Zawgyi share no tokens, so search must convert detected Zawgyi to
//! Unicode before NFKC, the way Khmer syllables are put in canonical order.
//!
//! Canon (ARCH-0031 `#deferred`): "Myanmar Zawgyi Bayesian detector + Unicode
//! conversion | ONE-ZAWGYI".
//!
//! The detector is a port of google/myanmar-tools' Markov model
//! (`ZawgyiUnicodeMarkovModel`, Copyright 2017 Google LLC, Apache-2.0): the
//! model bytes are embedded with `include_bytes!` from
//! `vendor/myanmar-tools/zawgyiUnicodeModel.dat` (header in `LICENSE.md` there,
//! full text in the repo root `LICENSE`, entry in `THIRD-PARTY-NOTICES.md`), and
//! [`zawgyi_probability`] follows the upstream `Predict` step. The conversion is
//! Rabbit's zg2uni rule list (Rabbit-Converter/Rabbit `rabbit.js`, WTFPL v2),
//! applied in order by [`to_unicode`] via `rules::STEPS`.
//!
//! Conversion runs only on input the detector puts above [`ZAWGYI_THRESHOLD`]
//! (P(Zawgyi) > 0.95, myanmar-tools' suggested cut). It runs per Myanmar run (a
//! maximal run of graphemes that start with a Myanmar-block character), so `^`
//! and `$` in Rabbit's rules mean the run's ends, and Rabbit's space / ZWSP
//! rules never see a space or ZWSP (they are not run characters). A run boundary
//! therefore makes rule 69 (`([^U+1040-U+1049])U+1040$`, a word-final zero read
//! as WA) fire at the end of every run, which Rabbit applied to a whole text
//! would do only at the text's end; it is the intended reading for search.

mod rules;

#[cfg(test)]
mod tests;

use std::borrow::Cow;

/// myanmar-tools' suggested cut; strictly greater converts.
pub(crate) const ZAWGYI_THRESHOLD: f64 = 0.95;

/// Whether `c` is in a Myanmar block: `U+1000..=U+109F | U+AA60..=U+AA7F |
/// U+A9E0..=U+A9FF`.
pub(crate) fn is_myanmar(c: char) -> bool {
    matches!(
        u32::from(c),
        0x1000..=0x109F | 0xAA60..=0xAA7F | 0xA9E0..=0xA9FF
    )
}

const MODEL_BYTES: &[u8] = include_bytes!("../../vendor/myanmar-tools/zawgyiUnicodeModel.dat");

/// Markov parameters: `size` states, whether the space range is scored, and
/// the `size * size` transition log-odds in row-major order.
struct Model {
    size: usize,
    spaces: bool,
    params: Vec<f32>,
}

/// Tiny big-endian reader for the model bytes; every read gives `None` when
/// fewer bytes remain than it needs.
struct Reader<'a> {
    rest: &'a [u8],
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (chunk, rest) = self.rest.split_first_chunk::<N>()?;
        self.rest = rest;
        Some(*chunk)
    }

    fn tag(&mut self, expected: &[u8; 8]) -> Option<()> {
        (self.take::<8>()? == *expected).then_some(())
    }

    fn i16(&mut self) -> Option<i16> {
        self.take().map(i16::from_be_bytes)
    }

    fn i32(&mut self) -> Option<i32> {
        self.take().map(i32::from_be_bytes)
    }

    fn f32(&mut self) -> Option<f32> {
        self.take().map(f32::from_be_bytes)
    }
}

/// Strict port of the C++ `ZawgyiUnicodeMarkovModel` reader: big-endian; tag
/// `b"UZMODEL "`; i32 version 1 (ssv 0) or 2 (then an i32 ssv, 0 or 1); tag
/// `b"BMARKOV "`; i32 version 0; i16 size, which must equal the state count for
/// the ssv (227 for ssv 0, 215 for ssv 1); per row: i16 count (>= 0); when
/// non-zero an f32 row default fills the row, then `count` pairs of (i16
/// column in `0..size`, f32 value); every byte consumed. Any violation gives
/// `None`.
fn parse_model(bytes: &[u8]) -> Option<Model> {
    let mut reader = Reader { rest: bytes };
    reader.tag(b"UZMODEL ")?;
    let ssv = match reader.i32()? {
        1 => 0,
        2 => match reader.i32()? {
            ssv @ (0 | 1) => ssv,
            _ => return None,
        },
        _ => return None,
    };
    reader.tag(b"BMARKOV ")?;
    if reader.i32()? != 0 {
        return None;
    }
    let expected = if ssv == 0 { 227 } else { 215 };
    if reader.i16()? != expected {
        return None;
    }
    let size = usize::from(expected.unsigned_abs());
    // `size` is 227 or 215, so `size * size` (at most 51529) cannot overflow.
    let mut params = vec![0.0f32; size * size];
    for row in params.chunks_exact_mut(size) {
        // A negative count or column fails `usize::try_from`.
        let count = usize::try_from(reader.i16()?).ok()?;
        if count > 0 {
            row.fill(reader.f32()?);
        }
        for _ in 0..count {
            let col = usize::try_from(reader.i16()?)
                .ok()
                .filter(|&col| col < size)?;
            row[col] = reader.f32()?;
        }
    }
    if !reader.rest.is_empty() {
        return None;
    }
    Some(Model {
        size,
        spaces: ssv == 0,
        params,
    })
}

static MODEL: std::sync::LazyLock<Option<Model>> =
    std::sync::LazyLock::new(|| parse_model(MODEL_BYTES));

const STD_START: u32 = 0x1000;
const STD_END: u32 = 0x103F;
const AFT_START: u32 = 0x104A;
const AFT_END: u32 = 0x109F;
const EXA_START: u32 = 0xAA60;
const EXA_END: u32 = 0xAA7F;
const EXB_START: u32 = 0xA9E0;
const EXB_END: u32 = 0xA9FF;
const SPC_START: u32 = 0x2000;
const SPC_END: u32 = 0x200B;

const STD_LEN: usize = 0x103F - 0x1000 + 1;
const AFT_LEN: usize = 0x109F - 0x104A + 1;
const EXA_LEN: usize = 0xAA7F - 0xAA60 + 1;
const EXB_LEN: usize = 0xA9FF - 0xA9E0 + 1;

const STD_BASE: usize = 1;
const AFT_BASE: usize = STD_BASE + STD_LEN;
const EXA_BASE: usize = AFT_BASE + AFT_LEN;
const EXB_BASE: usize = EXA_BASE + EXA_LEN;
const SPC_BASE: usize = EXB_BASE + EXB_LEN;

/// The C++ `GetIndexForCodePoint`: the Markov state for `c`, or 0 when `c`
/// is outside the scored ranges. Offsets come from the range lengths above,
/// not magic numbers.
fn state(model: &Model, c: char) -> usize {
    let cp = u32::from(c);
    // Each difference is bounded by its range length (at most 86), so the
    // `u32 -> usize` conversion fits on any target.
    if (STD_START..=STD_END).contains(&cp) {
        (cp - STD_START) as usize + STD_BASE
    } else if (AFT_START..=AFT_END).contains(&cp) {
        (cp - AFT_START) as usize + AFT_BASE
    } else if (EXA_START..=EXA_END).contains(&cp) {
        (cp - EXA_START) as usize + EXA_BASE
    } else if (EXB_START..=EXB_END).contains(&cp) {
        (cp - EXB_START) as usize + EXB_BASE
    } else if model.spaces && (SPC_START..=SPC_END).contains(&cp) {
        (cp - SPC_START) as usize + SPC_BASE
    } else {
        0
    }
}

/// The C++ `Predict`: the Zawgyi probability of `text`. Starts in state 0,
/// walks every char then one final state 0, skipping 0 -> 0 transitions and
/// adding each transition's parameter; with no transition at all, or when the
/// model failed to parse, gives `f64::NEG_INFINITY` (never converts).
pub(crate) fn zawgyi_probability(text: &str) -> f64 {
    let Some(model) = &*MODEL else {
        return f64::NEG_INFINITY;
    };
    let mut prev = 0;
    let mut total = 0.0;
    let mut seen = false;
    for c in text.chars() {
        let cur = state(model, c);
        if prev != 0 || cur != 0 {
            total += f64::from(model.params[prev * model.size + cur]);
            seen = true;
        }
        prev = cur;
    }
    if prev != 0 {
        total += f64::from(model.params[prev * model.size]);
        seen = true;
    }
    if !seen {
        return f64::NEG_INFINITY;
    }
    1.0 / (1.0 + total.exp())
}

/// Whether `text` reads as Zawgyi: false at once when no char [`is_myanmar`],
/// else whether [`zawgyi_probability`] clears [`ZAWGYI_THRESHOLD`].
pub(crate) fn is_zawgyi(text: &str) -> bool {
    if !text.chars().any(is_myanmar) {
        return false;
    }
    zawgyi_probability(text) > ZAWGYI_THRESHOLD
}

/// Rabbit's zg2uni rules in order; borrowed when no step changes anything.
/// Fails closed (borrowed) when the rule table failed to compile.
pub(crate) fn to_unicode(text: &str) -> Cow<'_, str> {
    let Some(steps) = &*rules::STEPS else {
        return Cow::Borrowed(text);
    };
    let mut current = Cow::Borrowed(text);
    for step in steps {
        if let Some(next) = step.apply(&current) {
            current = Cow::Owned(next);
        }
    }
    current
}
