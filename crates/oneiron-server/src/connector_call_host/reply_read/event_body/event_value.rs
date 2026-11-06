//! Drops ordinary SSE arrays without retaining a whole batch Value.

use std::fmt;
use std::io::{BufRead, Read};

use oneiron::outbound_consent::{ZeroizingBufReader, zeroize_json};
use serde::Deserializer;
use serde::de::{SeqAccess, Visitor};
use serde_json::Value;

pub(super) fn read(reader: impl Read) -> Result<Option<Value>, serde_json::Error> {
    let mut reader = ZeroizingBufReader::new(reader);
    let array = loop {
        let bytes = match reader.fill_buf() {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            other => other.map_err(serde_json::Error::io)?,
        };
        if bytes.is_empty() {
            break false;
        }
        if let Some(at) = bytes
            .iter()
            .position(|byte| !matches!(*byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            break bytes[at] == b'[';
        }
        let count = bytes.len();
        reader.consume(count);
    };
    if !array {
        // Keep native special-map decoding, including maps that yield arrays.
        return serde_json::from_reader(reader).map(Some);
    }
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    deserializer.deserialize_seq(DiscardArray)?;
    deserializer.end()?;
    Ok(None)
}

struct DiscardArray;

impl<'de> Visitor<'de> for DiscardArray {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON event array")
    }

    fn visit_seq<A>(self, mut array: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        // An SSE array is not a batch reply: even nested answers are dropped.
        while let Some(message) = array.next_element::<Value>()? {
            zeroize_json(message);
        }
        Ok(())
    }
}
