//! A tracker response decoded on the host's memory line by the memory its
//! value takes, not its wire bytes (FIX 8610, FIX 9383). A first pass counts
//! what serde_json allocates for the value: a slot per value at the capacity
//! its array or object grows to, each string's and key's bytes, and the
//! strings and read buffer the parser stages beside them. It runs under a
//! hold of the response's raw length, since it keeps one string at a time.
//! The decode then holds that count, at once while the line has room, else
//! at its turn, and the hold stays with the value until the value is
//! dropped, so a reader consumes it under the same hold. A count larger than
//! the whole line waits to run alone, as a decode did; none is refused for
//! its size. Allocator rounding is not counted.

use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;

use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use super::{GraphQlTransportError, LinearBodyLine};

/// The buffer a decode reads its response through.
const READ_BUFFER: u64 = 8 * 1024;

/// A decoded tracker response, with the hold on the host's memory line that
/// covers it while it lives. It reads as its value.
pub struct GraphQlValue {
    value: Value,
    hold: Option<Box<dyn Send>>,
}

impl GraphQlValue {
    /// `value` with no hold, for a transport that decodes off the line.
    #[must_use]
    pub fn unheld(value: Value) -> Self {
        Self { value, hold: None }
    }

    /// The value alone; its hold ends here.
    #[must_use]
    pub fn into_value(self) -> Value {
        drop(self.hold);
        self.value
    }
}

impl From<Value> for GraphQlValue {
    fn from(value: Value) -> Self {
        Self::unheld(value)
    }
}

impl std::ops::Deref for GraphQlValue {
    type Target = Value;

    fn deref(&self) -> &Value {
        &self.value
    }
}

impl fmt::Debug for GraphQlValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

/// Decodes the whole spooled response `file`, `len` bytes read from its
/// start, holding on `line` first what its value takes.
pub(crate) fn decode_spooled(
    line: Option<&dyn LinearBodyLine>,
    len: u64,
    mut file: std::fs::File,
) -> Result<GraphQlValue, GraphQlTransportError> {
    let size = decoded_size(line, len, &mut file)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| GraphQlTransportError::Uncertain)?;
    decode_sized(line, size, file)
}

/// The bytes the value of `reader`, a JSON document `len` bytes long, takes
/// once decoded, with what its decode stages beside it; never less than
/// `len`. Counted under a hold of `len` on `line`.
pub(crate) fn decoded_size(
    line: Option<&dyn LinearBodyLine>,
    len: u64,
    reader: impl Read,
) -> Result<u64, GraphQlTransportError> {
    let _held = hold(line, len)?;
    let mut tally = Tally::default();
    let mut json = serde_json::Deserializer::from_reader(std::io::BufReader::new(reader));
    Footprint(&mut tally)
        .deserialize(&mut json)
        .and_then(|()| json.end())
        .map_err(|_| GraphQlTransportError::Uncertain)?;
    let staged = tally.longest.saturating_mul(2).saturating_add(READ_BUFFER);
    Ok(bytes_of::<Value>(1)
        .saturating_add(tally.bytes)
        .saturating_add(staged)
        .max(len))
}

/// Decodes `reader` under a hold of `size` bytes on `line`, kept with the
/// value.
pub(crate) fn decode_sized(
    line: Option<&dyn LinearBodyLine>,
    size: u64,
    reader: impl Read,
) -> Result<GraphQlValue, GraphQlTransportError> {
    let hold = hold(line, size)?;
    let value = serde_json::from_reader(std::io::BufReader::new(reader))
        .map_err(|_| GraphQlTransportError::Uncertain)?;
    Ok(GraphQlValue { value, hold })
}

/// A hold of `bytes` on `line`; [`GraphQlTransportError::Waiting`] when the
/// host's wait ran out first.
fn hold(
    line: Option<&dyn LinearBodyLine>,
    bytes: u64,
) -> Result<Option<Box<dyn Send>>, GraphQlTransportError> {
    match line {
        Some(line) => line
            .hold(bytes)
            .map(Some)
            .ok_or(GraphQlTransportError::Waiting),
        None => Ok(None),
    }
}

/// What a decoded value takes beyond its own slot, and the longest string
/// the parser stages for it.
#[derive(Default)]
struct Tally {
    bytes: u64,
    longest: u64,
}

impl Tally {
    fn string(&mut self, len: usize) {
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        self.bytes = self.bytes.saturating_add(len);
        self.longest = self.longest.max(len);
    }

    fn add(&mut self, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

/// `count` values of `T`, in bytes.
fn bytes_of<T>(count: u64) -> u64 {
    count.saturating_mul(u64::try_from(size_of::<T>()).unwrap_or(u64::MAX))
}

/// The heap an array of `len` values takes, grown one push at a time: no
/// allocation while empty, then four slots, then doubling.
fn array_bytes(len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    bytes_of::<Value>(len.max(4).checked_next_power_of_two().unwrap_or(u64::MAX))
}

/// The heap an object of `len` entries takes, grown one insert at a time:
/// its entries, at the capacity of its hash index (index map entries: a
/// hash, a key and a value each), and that index's buckets with their
/// control bytes and one group of padding.
fn object_bytes(len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let usable = |buckets: u64| {
        if buckets < 8 {
            buckets - 1
        } else {
            buckets / 8 * 7
        }
    };
    let mut buckets: u64 = 4;
    while usable(buckets) < len {
        buckets = buckets.saturating_mul(2);
    }
    bytes_of::<(usize, String, Value)>(usable(buckets))
        .saturating_add(bytes_of::<usize>(buckets))
        .saturating_add(buckets)
        .saturating_add(16)
}

/// Counts one value into its tally.
struct Footprint<'t>(&'t mut Tally);

impl<'de> DeserializeSeed<'de> for Footprint<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Footprint<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<(), E> {
        self.0.string(value.len());
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let mut len: u64 = 0;
        while seq.next_element_seed(Footprint(&mut *self.0))?.is_some() {
            len = len.saturating_add(1);
        }
        self.0.add(array_bytes(len));
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut len: u64 = 0;
        while map.next_key_seed(Footprint(&mut *self.0))?.is_some() {
            map.next_value_seed(Footprint(&mut *self.0))?;
            len = len.saturating_add(1);
        }
        self.0.add(object_bytes(len));
        Ok(())
    }
}
