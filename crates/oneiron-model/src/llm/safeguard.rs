//! Safeguard-classifier binding selector with parsing, display, serde, and tier/model projections.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::model_id::{
    dynamic_model_id, endpoint_model_identity, sanitize_model_id_segment, validated_static_model_id,
};
use super::{ModelId, ModelLocality, ModelTierRef};

pub const DEFAULT_SAFEGUARD_MODEL_BINDING: &str = "gpt-oss-safeguard-20b";

pub const DEFAULT_ON_DEVICE_SAFEGUARD_TIER: &str = "qwen3guard-stream-0.6b";

/// Config selector for OF-333 safeguard-class classifiers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum SafeguardModelBinding {
    #[default]
    GptOssSafeguard20b,
    OpenRouter {
        model: String,
    },
    Endpoint {
        url: String,
    },
    OnDevice {
        tier: String,
    },
}

impl SafeguardModelBinding {
    pub fn parse(value: &str) -> std::result::Result<Self, SafeguardModelBindingError> {
        value.parse()
    }

    #[must_use]
    pub fn selector(&self) -> String {
        match self {
            Self::GptOssSafeguard20b => DEFAULT_SAFEGUARD_MODEL_BINDING.to_owned(),
            Self::OpenRouter { model } => format!("openrouter:{model}"),
            Self::Endpoint { url } => format!("endpoint:{url}"),
            Self::OnDevice { tier } => format!("on-device:{tier}"),
        }
    }

    #[must_use]
    pub fn locality(&self) -> ModelLocality {
        match self {
            Self::GptOssSafeguard20b | Self::OpenRouter { .. } => ModelLocality::ThirdParty,
            Self::Endpoint { .. } => ModelLocality::OwnServer,
            Self::OnDevice { .. } => ModelLocality::OnDevice,
        }
    }

    #[must_use]
    pub fn tier_ref(&self) -> ModelTierRef {
        ModelTierRef(self.selector())
    }

    #[must_use]
    pub fn llm_model_id(&self) -> ModelId {
        match self {
            Self::GptOssSafeguard20b => {
                validated_static_model_id("oneiron/gpt-oss-safeguard-20b@default")
            }
            Self::OpenRouter { model } => {
                dynamic_model_id("openrouter", sanitize_model_id_segment(model), "configured")
            }
            Self::Endpoint { url } => dynamic_model_id(
                "endpoint",
                sanitize_model_id_segment(&endpoint_model_identity(url)),
                "configured",
            ),
            Self::OnDevice { tier } => {
                dynamic_model_id("on-device", sanitize_model_id_segment(tier), "configured")
            }
        }
    }
}

impl fmt::Display for SafeguardModelBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.selector())
    }
}

impl FromStr for SafeguardModelBinding {
    type Err = SafeguardModelBindingError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let trimmed = value.trim();
        if trimmed == DEFAULT_SAFEGUARD_MODEL_BINDING {
            return Ok(Self::GptOssSafeguard20b);
        }
        if let Some(model) = trimmed.strip_prefix("openrouter:") {
            if model.trim().is_empty() {
                return Err(SafeguardModelBindingError::EmptySelector {
                    prefix: "openrouter",
                });
            }
            return Ok(Self::OpenRouter {
                model: model.trim().to_owned(),
            });
        }
        if let Some(url) = trimmed.strip_prefix("endpoint:") {
            if url.trim().is_empty() {
                return Err(SafeguardModelBindingError::EmptySelector { prefix: "endpoint" });
            }
            return Ok(Self::Endpoint {
                url: url.trim().to_owned(),
            });
        }
        if trimmed == "on-device" {
            return Ok(Self::OnDevice {
                tier: DEFAULT_ON_DEVICE_SAFEGUARD_TIER.to_owned(),
            });
        }
        if let Some(tier) = trimmed.strip_prefix("on-device:") {
            if tier.trim().is_empty() {
                return Err(SafeguardModelBindingError::EmptySelector {
                    prefix: "on-device",
                });
            }
            return Ok(Self::OnDevice {
                tier: tier.trim().to_owned(),
            });
        }
        Err(SafeguardModelBindingError::UnknownSelector)
    }
}

impl Serialize for SafeguardModelBinding {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.selector())
    }
}

impl<'de> Deserialize<'de> for SafeguardModelBinding {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BindingVisitor;

        impl Visitor<'_> for BindingVisitor {
            type Value = SafeguardModelBinding;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a safeguard binding selector")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(BindingVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafeguardModelBindingError {
    #[error("unknown safeguard model binding selector")]
    UnknownSelector,
    #[error("{prefix} safeguard model binding selector is empty")]
    EmptySelector { prefix: &'static str },
}
