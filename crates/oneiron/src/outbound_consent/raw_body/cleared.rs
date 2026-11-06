//! File-backed clearing keeps an ordinary JSON batch one message at a time.

use std::fmt;
use std::fs::File;
use std::io::{self, Seek};
use std::sync::{Arc, Mutex};

use serde::de::{Error as _, MapAccess, SeqAccess, Visitor, value::MapAccessDeserializer};
use serde::ser::{SerializeSeq, Serializer as _};
use serde::{Deserialize, Deserializer as _};
use serde_json::Value;

use super::{RawOutboundBody, Storage};
use crate::outbound_consent::{ZeroizingBufReader, zeroize_json};
use crate::secret_custody::SentValue;
use crate::{Result, Vault};

pub(super) fn clear(
    body: RawOutboundBody,
    vault: &Vault,
    value: &SentValue<'_>,
) -> Result<RawOutboundBody> {
    let mut decoder = serde_json::Deserializer::from_reader(ZeroizingBufReader::new(body.reader()));
    let inspected = decoder
        .deserialize_any(Inspect { value })
        .map_err(io::Error::other)?;
    if let Err(error) = decoder.end() {
        if let Inspected::Whole(parsed) = inspected {
            zeroize_json(parsed);
        }
        return Err(io::Error::other(error).into());
    }
    drop(decoder);
    match inspected {
        Inspected::Array(false) => Ok(body),
        Inspected::Array(true) => write_array(&body, vault, value),
        Inspected::Whole(mut parsed) => {
            let changed = value.clear_json_changed(&mut parsed);
            if !changed {
                zeroize_json(parsed);
                return Ok(body);
            }
            let cleared = (|| {
                let mut file = vault.archive_spool_file()?;
                serde_json::to_writer(&mut file, &parsed).map_err(io::Error::other)?;
                from_file(file)
            })();
            zeroize_json(parsed);
            cleared
        }
    }
}

enum Inspected {
    Array(bool),
    Whole(Value),
}

struct Inspect<'a, 'secret> {
    value: &'a SentValue<'secret>,
}

impl<'de> Visitor<'de> for Inspect<'_, '_> {
    type Value = Inspected;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_unit<E>(self) -> std::result::Result<Inspected, E> {
        Ok(Inspected::Whole(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Inspected, E> {
        Ok(Inspected::Whole(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Inspected, E> {
        Ok(Inspected::Whole(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Inspected, E> {
        Ok(Inspected::Whole(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Inspected, E> {
        Ok(Inspected::Whole(
            serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number),
        ))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Inspected, E> {
        Ok(Inspected::Whole(Value::String(value.to_owned())))
    }

    fn visit_map<A>(self, map: A) -> std::result::Result<Inspected, A::Error>
    where
        A: MapAccess<'de>,
    {
        // Keep Value's special-map handling, including a map that yields an array.
        Value::deserialize(MapAccessDeserializer::new(map)).map(Inspected::Whole)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Inspected, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut changed = false;
        while let Some(mut element) = sequence.next_element::<Value>()? {
            changed |= self.value.clear_json_changed(&mut element);
            zeroize_json(element);
        }
        Ok(Inspected::Array(changed))
    }
}

fn write_array(
    body: &RawOutboundBody,
    vault: &Vault,
    value: &SentValue<'_>,
) -> Result<RawOutboundBody> {
    let mut file = vault.archive_spool_file()?;
    {
        let mut encoder = serde_json::Serializer::new(&mut file);
        let mut sequence = encoder.serialize_seq(None).map_err(io::Error::other)?;
        let mut encode_error = None;
        let mut decoder =
            serde_json::Deserializer::from_reader(ZeroizingBufReader::new(body.reader()));
        let decoded = decoder.deserialize_seq(WriteArray {
            value,
            sequence: &mut sequence,
            encode_error: &mut encode_error,
        });
        // A serializer error stopped the visitor; return that original error,
        // not the synthetic deserializer error used to stop reading.
        if let Some(error) = encode_error {
            return Err(io::Error::other(error).into());
        }
        decoded.map_err(io::Error::other)?;
        decoder.end().map_err(io::Error::other)?;
        sequence.end().map_err(io::Error::other)?;
    }
    from_file(file)
}

struct WriteArray<'a, 'secret, S: SerializeSeq> {
    value: &'a SentValue<'secret>,
    sequence: &'a mut S,
    encode_error: &'a mut Option<S::Error>,
}

impl<'de, S: SerializeSeq> Visitor<'de> for WriteArray<'_, '_, S> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the validated JSON array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(mut element) = sequence.next_element::<Value>()? {
            self.value.clear_json_changed(&mut element);
            let encoded = self.sequence.serialize_element(&element);
            zeroize_json(element);
            if let Err(error) = encoded {
                *self.encode_error = Some(error);
                return Err(A::Error::custom("could not write the cleared JSON array"));
            }
        }
        Ok(())
    }
}

fn from_file(mut file: File) -> Result<RawOutboundBody> {
    let len = file.stream_position()?;
    Ok(RawOutboundBody {
        storage: Arc::new(Storage::File(Mutex::new(file))),
        start: 0,
        len,
    })
}
