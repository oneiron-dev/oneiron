//! The staged version boundary every generated-UI envelope crosses first
//! (FIX 7967; CALLS "FIX 7967 7970 fallback outcome"): the protocol version
//! and the whole-card fallback are read before any typed tree or catalog
//! decoding. That first pass reads those two members alone and skips every
//! other value unread, at any depth. A version this build does not know
//! yields its fallback text alone, its body never interpreted; a supported
//! one is decoded from the same original text by its own typed decoder,
//! with every structural error it had before.

use std::fmt;

use serde::de::{self, DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Deserializer};

use super::{GENERATED_UI_WIRE_VERSION, GeneratedUiCard, GeneratedUiRender};
use crate::lens::atom::LensText;
use crate::lens::validate::validate_required_lens_text;
use crate::{Error, Result};

/// The whole card as text, from an envelope whose `protocolVersion` this
/// build does not know. It is not a card: it carries no tree, action or
/// backing ref, and nothing on it can be acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedUiFallback {
    pub protocol_version: u64,
    pub fallback_text: LensText,
}

/// What an envelope decodes to: the typed value of a supported protocol
/// version, or only the fallback text of an unsupported one.
#[derive(Debug, Clone, PartialEq)]
pub enum GeneratedUiDecoded<T> {
    Supported(T),
    Fallback(GeneratedUiFallback),
}

impl GeneratedUiCard {
    /// One card envelope from JSON text, version first.
    pub fn decode_json(text: &str) -> Result<GeneratedUiDecoded<Self>> {
        decode_staged(text, "card")
    }
}

impl GeneratedUiRender {
    /// One flat render envelope from JSON text, version first.
    pub fn decode_json(text: &str) -> Result<GeneratedUiDecoded<Self>> {
        decode_staged(text, "render")
    }
}

/// Decode `text` as `T` when its `protocolVersion` is this build's, else
/// return its whole-card fallback.
fn decode_staged<T: DeserializeOwned>(text: &str, kind: &str) -> Result<GeneratedUiDecoded<T>> {
    let head = serde_json::from_str::<GeneratedUiEnvelopeHead>(text)
        .map_err(|error| Error::InvalidConfig(format!("generated-ui {kind}: {error}")))?;
    if let Some(fallback) = head.unsupported_fallback(kind)? {
        return Ok(GeneratedUiDecoded::Fallback(fallback));
    }
    serde_json::from_str(text)
        .map(GeneratedUiDecoded::Supported)
        .map_err(|error| Error::InvalidConfig(format!("generated-ui {kind}: {error}")))
}

/// What the first pass reads of an envelope: its `protocolVersion` and its
/// whole-card `fallbackText`. Every other member is skipped unread. A member
/// of another shape, a repeated one, or a value that is no object reads as
/// naming nothing more, for the typed decode to judge.
#[derive(Debug, Default)]
pub(super) struct GeneratedUiEnvelopeHead {
    protocol_version: Option<u64>,
    fallback_text: Option<String>,
}

impl GeneratedUiEnvelopeHead {
    pub(super) fn protocol_version(&self) -> Option<u64> {
        self.protocol_version
    }

    /// The fallback of an envelope that names a protocol version other than
    /// this build's; `None` when it names this build's, or none.
    pub(super) fn unsupported_fallback(&self, kind: &str) -> Result<Option<GeneratedUiFallback>> {
        let Some(protocol_version) = self.protocol_version else {
            return Ok(None);
        };
        if protocol_version == u64::from(GENERATED_UI_WIRE_VERSION) {
            return Ok(None);
        }
        let fallback_text = self
            .fallback_text
            .clone()
            .map(LensText::new)
            .transpose()?
            .ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "generated-ui {kind} of unsupported wire version {protocol_version} must carry its whole-card fallbackText"
                ))
            })?;
        validate_required_lens_text("generated-ui unsupported-version fallbackText", &fallback_text)?;
        Ok(Some(GeneratedUiFallback {
            protocol_version,
            fallback_text,
        }))
    }
}

impl<'de> Deserialize<'de> for GeneratedUiEnvelopeHead {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            ProtocolVersion,
            FallbackText,
            #[serde(other)]
            Other,
        }

        struct HeadVisitor;

        impl<'de> de::Visitor<'de> for HeadVisitor {
            type Value = GeneratedUiEnvelopeHead;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("generated-ui envelope")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut head = GeneratedUiEnvelopeHead::default();
                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::ProtocolVersion => {
                            let value = map.next_value::<HeadScalar>()?;
                            if let HeadScalar::Number(version) = value {
                                head.protocol_version.get_or_insert(version);
                            }
                        }
                        Field::FallbackText => {
                            let value = map.next_value::<HeadScalar>()?;
                            if let HeadScalar::Text(text) = value {
                                head.fallback_text.get_or_insert(text);
                            }
                        }
                        Field::Other => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(head)
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(GeneratedUiEnvelopeHead::default())
            }

            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(GeneratedUiEnvelopeHead::default())
            }

            fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<Self::Value, E> {
                Ok(GeneratedUiEnvelopeHead::default())
            }

            fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<Self::Value, E> {
                Ok(GeneratedUiEnvelopeHead::default())
            }

            fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<Self::Value, E> {
                Ok(GeneratedUiEnvelopeHead::default())
            }

            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Self::Value, E> {
                Ok(GeneratedUiEnvelopeHead::default())
            }

            fn visit_str<E: de::Error>(self, _: &str) -> std::result::Result<Self::Value, E> {
                Ok(GeneratedUiEnvelopeHead::default())
            }
        }

        deserializer.deserialize_any(HeadVisitor)
    }
}

/// What the first pass reads of one stream line: its `segment` name, when
/// it is a string, and the head of its `payload`. Every other member is
/// skipped unread.
#[derive(Debug, Default)]
pub(super) struct GeneratedUiSegmentHead {
    pub(super) segment: Option<String>,
    pub(super) payload: GeneratedUiEnvelopeHead,
}

impl<'de> Deserialize<'de> for GeneratedUiSegmentHead {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            Segment,
            Payload,
            #[serde(other)]
            Other,
        }

        struct SegmentHeadVisitor;

        impl<'de> de::Visitor<'de> for SegmentHeadVisitor {
            type Value = GeneratedUiSegmentHead;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("generated-ui segment")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut head = GeneratedUiSegmentHead::default();
                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::Segment => {
                            if let HeadScalar::Text(segment) = map.next_value::<HeadScalar>()? {
                                head.segment.get_or_insert(segment);
                            }
                        }
                        Field::Payload => head.payload = map.next_value()?,
                        Field::Other => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(head)
            }
        }

        deserializer.deserialize_map(SegmentHeadVisitor)
    }
}

/// One head member as the first pass reads it: a non-negative integer, a
/// string, or anything else, which is skipped unread.
enum HeadScalar {
    Number(u64),
    Text(String),
    Other,
}

impl<'de> Deserialize<'de> for HeadScalar {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScalarVisitor;

        impl<'de> de::Visitor<'de> for ScalarVisitor {
            type Value = HeadScalar;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("any JSON value")
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(HeadScalar::Number(value))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(u64::try_from(value).map_or(HeadScalar::Other, HeadScalar::Number))
            }

            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Self::Value, E> {
                Ok(HeadScalar::Other)
            }

            fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<Self::Value, E> {
                Ok(HeadScalar::Other)
            }

            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(HeadScalar::Other)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(HeadScalar::Text(value.to_owned()))
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(HeadScalar::Other)
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(HeadScalar::Other)
            }
        }

        deserializer.deserialize_any(ScalarVisitor)
    }
}
