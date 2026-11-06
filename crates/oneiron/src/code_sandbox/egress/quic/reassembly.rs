//! The CRYPTO stream of one QUIC connection's Initials, reassembled by
//! offset until the ClientHello it opens with is whole (FIX 8991).
//!
//! Fragments may come in any order and may overlap. Where two carry bytes
//! for one offset, the bytes must agree. Only bytes a fragment carried are
//! kept, and each byte kept is held on the host-net byte floor.

use super::super::name_gate::CLIENT_HELLO;
use oneiron_container::{HostNetFloor, HostNetPermit};
use std::collections::BTreeMap;

/// The longest handshake message a 24-bit length frames, with its 4-byte
/// header (RFC 8446 4): no ClientHello reaches past it.
const LONGEST_MESSAGE: usize = 4 + 0xff_ffff;

/// Why CRYPTO reaches past the ClientHello.
pub(super) const PAST_HELLO: &str = "the Initials carry CRYPTO data past the ClientHello";
/// Why two fragments disagree.
pub(super) const CONFLICT: &str = "two CRYPTO frames carry different bytes for one offset";
/// Why the floor refused to hold a fragment or a datagram.
pub(super) const BEYOND_FLOOR: &str = "the host-net byte floor cannot hold the ClientHello";

/// One connection's Initial CRYPTO stream so far.
#[derive(Default)]
pub(super) struct CryptoStream {
    /// The bytes fragments carried, as runs by their start offset. Runs are
    /// apart: none overlaps or touches another.
    runs: BTreeMap<usize, Vec<u8>>,
    /// The floor room the runs hold.
    room: Vec<HostNetPermit>,
}

impl CryptoStream {
    /// Adds `data`, carried at `offset`, holding its new bytes on `floor`.
    pub(super) fn insert(
        &mut self,
        offset: u64,
        data: &[u8],
        floor: &dyn HostNetFloor,
    ) -> Result<(), &'static str> {
        if data.is_empty() {
            return Ok(());
        }
        let limit = self.header().map_or(LONGEST_MESSAGE, |(_, size)| 4 + size);
        let start = usize::try_from(offset).map_err(|_| PAST_HELLO)?;
        let end = start
            .checked_add(data.len())
            .filter(|end| *end <= limit)
            .ok_or(PAST_HELLO)?;
        // The runs it overlaps or touches, in order: the one that starts at
        // or before it, then those that start inside it.
        let before = self
            .runs
            .range(..=start)
            .next_back()
            .filter(|(at, run)| **at + run.len() >= start)
            .map(|(at, _)| *at);
        let touched: Vec<usize> = before
            .into_iter()
            .chain(self.runs.range(start + 1..=end).map(|(at, _)| *at))
            .collect();
        let (mut first, mut last, mut kept) = (start, end, 0);
        for &at in &touched {
            let run = &self.runs[&at];
            let run_end = at + run.len();
            let (from, to) = (at.max(start), run_end.min(end));
            if from < to && run[from - at..to - at] != data[from - start..to - start] {
                return Err(CONFLICT);
            }
            first = first.min(at);
            last = last.max(run_end);
            kept += run.len();
        }
        let growth = last - first - kept;
        if growth > 0 {
            let bytes = u64::try_from(growth).map_err(|_| BEYOND_FLOOR)?;
            let room = floor.acquire_bytes(bytes).map_err(|_| BEYOND_FLOOR)?;
            self.room.push(room);
        }
        // One run from `first` to `last`: the run before it, then its bytes
        // past that run, then each later run's bytes past what is there.
        let mut later = touched.iter();
        let mut merged = match before {
            Some(at) => {
                later.next();
                self.runs.remove(&at).unwrap_or_default()
            }
            None => Vec::new(),
        };
        let mut cursor = first + merged.len();
        if end > cursor {
            merged.extend_from_slice(&data[cursor - start..]);
            cursor = end;
        }
        for at in later {
            let run = self.runs.remove(at).unwrap_or_default();
            if at + run.len() > cursor {
                merged.extend_from_slice(&run[cursor - at..]);
                cursor = at + run.len();
            }
        }
        self.runs.insert(first, merged);
        Ok(())
    }

    /// Whether the first handshake message is whole: its bytes from offset
    /// 0 are in, and no byte lies past it. The message must be a
    /// ClientHello.
    pub(super) fn whole(&self) -> Result<bool, &'static str> {
        let Some((kind, size)) = self.header() else {
            return Ok(false);
        };
        if kind != CLIENT_HELLO {
            return Err("the first handshake message is no ClientHello");
        }
        let whole = 4 + size;
        if self
            .runs
            .last_key_value()
            .is_some_and(|(at, run)| at + run.len() > whole)
        {
            return Err(PAST_HELLO);
        }
        Ok(self.runs.get(&0).is_some_and(|run| run.len() == whole))
    }

    /// The whole ClientHello handshake message and the floor room it holds,
    /// once [`Self::whole`] is true.
    pub(super) fn into_hello(mut self) -> (Vec<u8>, Vec<HostNetPermit>) {
        (self.runs.remove(&0).unwrap_or_default(), self.room)
    }

    /// The first handshake message's type and body length, once the
    /// stream's first four bytes are in.
    fn header(&self) -> Option<(u8, usize)> {
        let &[kind, a, b, c] = self.runs.get(&0)?.first_chunk::<4>()?;
        Some((
            kind,
            (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c),
        ))
    }
}

/// Whether `data`, carried at `offset`, agrees with `hello`, a ClientHello
/// already admitted: it lies inside it and carries its bytes.
pub(super) fn agrees(hello: &[u8], offset: u64, data: &[u8]) -> Result<(), &'static str> {
    let start = usize::try_from(offset).map_err(|_| PAST_HELLO)?;
    let end = start.checked_add(data.len()).ok_or(PAST_HELLO)?;
    match hello.get(start..end) {
        None => Err(PAST_HELLO),
        Some(bytes) if bytes != data => Err(CONFLICT),
        Some(_) => Ok(()),
    }
}
