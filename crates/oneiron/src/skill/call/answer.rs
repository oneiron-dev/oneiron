//! A callable skill's answer, spooled as it streams and checked against its
//! return contract as it is read, with no value tree built.

use std::io::{Read, Seek, Write};

use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

/// A callable skill's answer: in memory up to the inline reply size, a
/// temporary file past it, gone when this drops. Nothing refuses it for size.
pub struct CallableSkillAnswer {
    body: tempfile::SpooledTempFile,
    len: u64,
}

impl CallableSkillAnswer {
    pub(super) fn spool() -> Self {
        Self {
            body: tempfile::SpooledTempFile::new(crate::engine_executor::RESULT_REPLY_INLINE_BYTES),
            len: 0,
        }
    }

    /// Starts the answer over: a later `finish` replaces an earlier one.
    pub(super) fn restart(&mut self) -> crate::Result<()> {
        self.body.set_len(0)?;
        self.body.rewind()?;
        self.len = 0;
        Ok(())
    }

    pub(super) fn write(&mut self, frame: &[u8]) -> crate::Result<()> {
        self.body.write_all(frame)?;
        self.len = self.len.saturating_add(frame.len() as u64);
        Ok(())
    }

    /// The answer's length in bytes.
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.len
    }

    /// The answer, read from its first byte.
    pub fn reader(&mut self) -> crate::Result<&mut impl Read> {
        self.body.rewind()?;
        Ok(&mut self.body)
    }

    /// Reads the answer once, judging it against `shape` as the contract
    /// judges a parsed value: its SHA-256 when it is JSON within the
    /// contract, `None` when it is JSON outside it. Bytes that are no JSON
    /// are an error.
    pub(super) fn check(&mut self, shape: &JsonValue) -> crate::Result<Option<[u8; 32]>> {
        self.body.rewind()?;
        let mut hashed = Hashed {
            inner: &mut self.body,
            digest: Sha256::new(),
        };
        let matched = {
            let mut json =
                serde_json::Deserializer::from_reader(std::io::BufReader::new(&mut hashed));
            Shape(shape)
                .deserialize(&mut json)
                .and_then(|matched| json.end().map(|()| matched))
        };
        match matched {
            Ok(true) => Ok(Some(hashed.digest.finalize().into())),
            Ok(false) => Ok(None),
            Err(error) if error.is_io() => Err(std::io::Error::from(error).into()),
            Err(_) => Err(super::invalid("callable skill returned non-JSON output")),
        }
    }
}

/// A reader that digests what it reads.
struct Hashed<R> {
    inner: R,
    digest: Sha256,
}

impl<R: Read> Read for Hashed<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.digest.update(&buf[..read]);
        Ok(read)
    }
}

/// One value judged against its contract shape as it is read, as
/// `matches_shape` judges a parsed one. A value outside it is still read to
/// its end, so bytes that are no JSON are found wherever they sit.
struct Shape<'s>(&'s JsonValue);

impl Shape<'_> {
    fn kind(&self, name: &str) -> bool {
        matches!(self.0, JsonValue::String(kind) if kind == name)
    }
}

impl<'de> DeserializeSeed<'de> for Shape<'_> {
    type Value = bool;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Shape<'_> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<bool, E> {
        Ok(self.kind("boolean"))
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<bool, E> {
        Ok(self.kind("number") || self.kind("integer"))
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<bool, E> {
        Ok(self.kind("number") || self.kind("integer"))
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<bool, E> {
        Ok(self.kind("number"))
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<bool, E> {
        Ok(self.kind("string"))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<bool, E> {
        Ok(self.kind("null"))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<bool, A::Error> {
        let item = match self.0 {
            JsonValue::Array(items) if items.len() == 1 => Some(&items[0]),
            _ => None,
        };
        let mut matched = item.is_some() || self.kind("array");
        loop {
            let next = match item {
                Some(item) => seq.next_element_seed(Shape(item))?,
                None => seq.next_element::<IgnoredAny>()?.map(|_| true),
            };
            match next {
                Some(element) => matched &= element,
                None => return Ok(matched),
            }
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        let fields = match self.0 {
            JsonValue::Object(fields) => Some(fields),
            _ => None,
        };
        let mut matched = fields.is_some() || self.kind("object");
        let mut seen = std::collections::BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            match fields.and_then(|fields| fields.get_key_value(&name)) {
                Some((name, kind)) => {
                    matched &= map.next_value_seed(Shape(kind))?;
                    seen.insert(name);
                }
                None => {
                    map.next_value::<IgnoredAny>()?;
                    matched &= fields.is_none();
                }
            }
        }
        Ok(matched && fields.is_none_or(|fields| seen.len() == fields.len()))
    }
}
