//! Selects the first answering message without retaining a whole batch.

use std::fmt;

use serde::de::{MapAccess, SeqAccess, Visitor, value::MapAccessDeserializer};
use serde::{Deserialize, Deserializer};

use super::{Value, ZeroizingBufReader, answers, zeroize_json};

pub(super) fn read(reader: impl std::io::Read, id: u64) -> Result<Option<Value>, ()> {
    let mut found = None;
    let mut deserializer = serde_json::Deserializer::from_reader(ZeroizingBufReader::new(reader));
    let parsed = deserializer
        .deserialize_any(Selection {
            id,
            found: &mut found,
        })
        .and_then(|()| deserializer.end());
    if parsed.is_err() {
        if let Some(message) = found.take() {
            zeroize_json(message);
        }
        return Err(());
    }
    Ok(found)
}

struct Selection<'a> {
    id: u64,
    found: &'a mut Option<Value>,
}

impl Selection<'_> {
    fn message(&mut self, message: Value) {
        if self.found.is_none() && answers(&message, self.id) {
            *self.found = Some(message);
        } else {
            zeroize_json(message);
        }
    }
}

impl<'de> Visitor<'de> for Selection<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON reply or reply batch")
    }

    fn visit_seq<A>(mut self, mut batch: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(message) = batch.next_element::<Value>()? {
            self.message(message);
        }
        Ok(())
    }

    fn visit_map<A>(mut self, map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        // Value's special-map decoding can itself return a top-level array.
        match Value::deserialize(MapAccessDeserializer::new(map))? {
            Value::Array(batch) => {
                for message in batch {
                    self.message(message);
                }
            }
            message => self.message(message),
        }
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> Result<(), E> {
        zeroize_json(Value::String(value.to_owned()));
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
}
