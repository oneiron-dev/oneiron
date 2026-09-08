//! Validated provider/name@revision model identifier with segment checks and shared constructors.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Validated `provider/name@revision` model identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModelId(String);

impl ModelId {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, ModelIdError> {
        value.into().parse()
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        self.0
            .split_once('/')
            .expect("validated model id has provider separator")
            .0
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.0
            .split_once('/')
            .expect("validated model id has provider separator")
            .1
            .rsplit_once('@')
            .expect("validated model id has revision separator")
            .0
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        self.0
            .rsplit_once('@')
            .expect("validated model id has revision separator")
            .1
    }
}

impl fmt::Display for ModelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ModelId {
    type Err = ModelIdError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (provider, remainder) = value
            .split_once('/')
            .ok_or(ModelIdError::MissingProviderSeparator)?;
        let (name, revision) = remainder
            .rsplit_once('@')
            .ok_or(ModelIdError::MissingRevisionSeparator)?;

        validate_model_id_segment(provider, ModelIdSegment::Provider)?;
        validate_model_id_segment(name, ModelIdSegment::Name)?;
        validate_model_id_segment(revision, ModelIdSegment::Revision)?;

        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for ModelId {
    type Error = ModelIdError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for ModelId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ModelId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ModelIdVisitor;

        impl Visitor<'_> for ModelIdVisitor {
            type Value = ModelId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a provider/name@revision model identifier")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ModelIdVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelIdError {
    #[error("model id must contain provider/name")]
    MissingProviderSeparator,
    #[error("model id must contain @revision")]
    MissingRevisionSeparator,
    #[error("model id {segment} segment is empty")]
    EmptySegment { segment: &'static str },
    #[error("model id contains an invalid character in {segment}")]
    InvalidCharacter { segment: &'static str },
}

#[derive(Debug, Clone, Copy)]
enum ModelIdSegment {
    Provider,
    Name,
    Revision,
}

impl ModelIdSegment {
    fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Name => "name",
            Self::Revision => "revision",
        }
    }
}

fn validate_model_id_segment(
    value: &str,
    segment: ModelIdSegment,
) -> std::result::Result<(), ModelIdError> {
    if value.is_empty() {
        return Err(ModelIdError::EmptySegment {
            segment: segment.as_str(),
        });
    }

    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(ModelIdError::InvalidCharacter {
            segment: segment.as_str(),
        })
    }
}

pub(super) fn validated_static_model_id(value: &'static str) -> ModelId {
    ModelId::new(value)
        .unwrap_or_else(|error| unreachable!("hard-coded model id {value:?} is invalid: {error}"))
}

pub(super) fn dynamic_model_id(provider: &str, name: String, revision: &str) -> ModelId {
    ModelId::new(format!("{provider}/{name}@{revision}"))
        .expect("sanitized safeguard model binding produces a valid model id")
}

pub(super) fn sanitize_model_id_segment(value: &str) -> String {
    let sanitized = value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
                byte as char
            } else {
                '.'
            }
        })
        .collect::<String>()
        .trim_matches('.')
        .to_owned();
    if sanitized.is_empty() {
        "configured".to_owned()
    } else {
        sanitized
    }
}

pub(super) fn endpoint_model_identity(url: &str) -> String {
    let without_scheme = url
        .split_once("://")
        .map_or(url, |(_, remainder)| remainder);
    let without_fragment = without_scheme
        .split_once('#')
        .map_or(without_scheme, |(head, _)| head);
    let without_query = without_fragment
        .split_once('?')
        .map_or(without_fragment, |(head, _)| head);
    let slash_index = without_query.find('/').unwrap_or(without_query.len());
    let (authority, path) = without_query.split_at(slash_index);
    let authority_without_credentials = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!("{authority_without_credentials}{path}")
}
