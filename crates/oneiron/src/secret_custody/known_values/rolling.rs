//! The keyed rolling prefilter (FIX 12209): each entry keeps a 2-byte keyed
//! rolling value of its first window, and a match runs the keyed BLAKE3 tag
//! and fingerprint only at the offsets where some window length's rolling
//! value is one the index holds.
//!
//! A window's state is the polynomial `sum (x_i + offset) * base^(w-1-i)`
//! over its `w` bytes, mod 2^32, with a keyed odd `base` and a keyed
//! `offset`; its value is the high half of `state * mix`, mod 2^32, with a
//! keyed odd `mix`. Every step is wrapping `u32` arithmetic, which is exact
//! in the ring of integers mod 2^32, so the state rolled one byte on,
//! `state * base - (x_out + offset) * base^w + (x_in + offset)`, is the state
//! Horner's rule gives over the same `w` bytes: the value a text's window
//! has at any offset is the value remembered from the same bytes.
//!
//! The rolling value only picks offsets. A value the index matches starts
//! with its first window, whose rolling value its entry holds, so its
//! offset is always picked; each picked offset is confirmed by the full
//! keyed tag and fingerprint compare, as every offset was before. Matches
//! and spans stay the same.
//!
//! The key derives from the index's master under its own label and keys
//! nothing else. The key, each set and each scan's states are wiped when
//! they drop, and none of them is ever printed.

use zeroize::Zeroize;

const ROLLING_CONTEXT: &str = "oneiron secret_custody known-value rolling v1";

/// How many 64-bit words a set of 16-bit values takes: 65,536 bits.
const SET_WORDS: usize = 1 << 10;

// A scan's hits keep one bit per window length, and there are at most
// `TAG_WINDOW` of them.
const _: () = assert!(super::TAG_WINDOW <= 32);

/// The keyed parameters of the rolling value, derived from the index's
/// master. Wiped when dropped, and never printed.
pub(super) struct RollingKey {
    /// The polynomial's base: odd, so each byte's weight is a unit mod 2^32.
    base: u32,
    /// Added to each byte before it is weighed.
    offset: u32,
    /// Odd: folds a window's state into its 16-bit value.
    mix: u32,
}

impl RollingKey {
    /// The rolling key of the index whose master is `master`.
    pub(super) fn derive(master: &[u8; 32]) -> Self {
        let key = crate::world_keys::derive_guarded(ROLLING_CONTEXT, &[&master[..]]);
        let word_at = |at: usize| {
            let mut bytes = [0; 4];
            bytes.copy_from_slice(&key[at..at + 4]);
            let word = u32::from_le_bytes(bytes);
            bytes.zeroize();
            word
        };
        Self {
            base: word_at(0) | 1,
            offset: word_at(4),
            mix: word_at(8) | 1,
        }
    }

    /// The rolling value of `window`, as an entry keeps it: the window the
    /// tag keys, a value's first [`super::TAG_WINDOW`] bytes or all of a
    /// shorter one.
    pub(super) fn value(&self, window: &[u8]) -> u16 {
        self.fold(self.state(window))
    }

    /// One byte's term.
    fn term(&self, byte: u8) -> u32 {
        u32::from(byte).wrapping_add(self.offset)
    }

    /// The state of `window` by Horner's rule: `sum (x_i + offset) *
    /// base^(w-1-i)`, mod 2^32.
    fn state(&self, window: &[u8]) -> u32 {
        window.iter().fold(0, |state: u32, &byte| {
            state.wrapping_mul(self.base).wrapping_add(self.term(byte))
        })
    }

    /// A state's 16-bit value: the high half of `state * mix`, mod 2^32.
    fn fold(&self, state: u32) -> u16 {
        let [high, low, _, _] = state.wrapping_mul(self.mix).to_be_bytes();
        u16::from_be_bytes([high, low])
    }

    /// `base^window`, mod 2^32: the weight of the byte that leaves a
    /// window of that length once its state is multiplied by `base`.
    fn leaving(&self, window: usize) -> u32 {
        (0..window).fold(1, |power: u32, _| power.wrapping_mul(self.base))
    }
}

impl Drop for RollingKey {
    fn drop(&mut self) {
        self.base.zeroize();
        self.offset.zeroize();
        self.mix.zeroize();
    }
}

/// The rolling values of one window length's entries, as a 65,536-bit map.
/// Wiped when dropped.
struct RollingSet(Box<[u64; SET_WORDS]>);

impl RollingSet {
    fn new() -> Self {
        Self(Box::new([0; SET_WORDS]))
    }

    fn insert(&mut self, value: u16) {
        let value = usize::from(value);
        self.0[value >> 6] |= 1 << (value & 63);
    }

    fn contains(&self, value: u16) -> bool {
        let value = usize::from(value);
        (self.0[value >> 6] >> (value & 63)) & 1 != 0
    }
}

impl Drop for RollingSet {
    fn drop(&mut self) {
        let words: &mut [u64; SET_WORDS] = &mut self.0;
        words.zeroize();
    }
}

/// Each window length the index's entries have, ascending, with the set of
/// their entries' rolling values.
#[derive(Default)]
pub(super) struct RollingSets(Vec<(usize, RollingSet)>);

impl RollingSets {
    /// Adds an entry whose first window is `window` bytes long and whose
    /// rolling value is `value`.
    pub(super) fn insert(&mut self, window: usize, value: u16) {
        let at = match self.0.binary_search_by_key(&window, |(held, _)| *held) {
            Ok(at) => at,
            Err(at) => {
                self.0.insert(at, (window, RollingSet::new()));
                at
            }
        };
        self.0[at].1.insert(value);
    }

    /// Each window length, ascending: the n-th is bit n of a scan's hits.
    pub(super) fn windows(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().map(|(window, _)| *window)
    }
}

/// One window length's rolling state over a text.
struct Lane<'k> {
    window: usize,
    /// `base^window`, mod 2^32.
    leaving: u32,
    /// The state of the window at the scan's offset, while it fits the text.
    state: u32,
    set: &'k RollingSet,
}

/// The rolling values of every window length over one text, read at
/// ascending offsets: one pass of rolling updates per window length.
pub(super) struct RollingScan<'k, 'd> {
    key: &'k RollingKey,
    data: &'d [u8],
    /// The offset every lane's state is at.
    at: usize,
    /// One per window length, ascending.
    lanes: Vec<Lane<'k>>,
}

impl<'k, 'd> RollingScan<'k, 'd> {
    /// A scan of `data` at offset 0 under `key`, over the window lengths in
    /// `sets`.
    pub(super) fn new(key: &'k RollingKey, sets: &'k RollingSets, data: &'d [u8]) -> Self {
        let lanes = sets
            .0
            .iter()
            .map(|(window, set)| Lane {
                window: *window,
                leaving: key.leaving(*window),
                // A window longer than the text is never read.
                state: data.get(..*window).map_or(0, |first| key.state(first)),
                set,
            })
            .collect();
        Self {
            key,
            data,
            at: 0,
            lanes,
        }
    }

    /// Which window lengths have, at `at`, a rolling value their set holds:
    /// bit n for the n-th length ascending. A window that runs past the end
    /// is never a hit. `at` never goes back.
    pub(super) fn hits(&mut self, at: usize) -> u32 {
        while self.at < at {
            self.step();
        }
        let mut hits = 0;
        for (lane_at, lane) in self.lanes.iter().enumerate() {
            // The lanes ascend: every later window is longer.
            if self.at + lane.window > self.data.len() {
                break;
            }
            if lane.set.contains(self.key.fold(lane.state)) {
                hits |= 1 << lane_at;
            }
        }
        hits
    }

    /// Moves every lane that still fits the text one byte on.
    fn step(&mut self) {
        let at = self.at;
        for lane in &mut self.lanes {
            // The lanes ascend: every later window is past the end too.
            let Some(&entering) = self.data.get(at + lane.window) else {
                break;
            };
            lane.state = lane
                .state
                .wrapping_mul(self.key.base)
                .wrapping_sub(self.key.term(self.data[at]).wrapping_mul(lane.leaving))
                .wrapping_add(self.key.term(entering));
        }
        self.at += 1;
    }
}

impl Drop for RollingScan<'_, '_> {
    fn drop(&mut self) {
        for lane in &mut self.lanes {
            lane.leaving.zeroize();
            lane.state.zeroize();
        }
    }
}
