//! Versioned default model stack settings.
//!
//! A stack is the tested bundle of models behind the product-facing "Default"
//! choice. Users either follow the current default stack or pin an older stack
//! while that stack is still served.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};

use crate::llm::{ModelId, ModelIdError};

pub const DEFAULT_MODEL_STACK_CURRENT_ID: &str = "default-v2";
pub const DEFAULT_MODEL_STACK_V1_ID: &str = "default-v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ModelStackId(String);

impl ModelStackId {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, ModelStackIdError> {
        value.into().parse()
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ModelStackId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ModelStackId {
    type Err = ModelStackIdError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err(ModelStackIdError::Empty);
        }
        if value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            Ok(Self(value.to_owned()))
        } else {
            Err(ModelStackIdError::InvalidCharacter)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelStackIdError {
    #[error("model stack id is empty")]
    Empty,
    #[error("model stack id contains an invalid character")]
    InvalidCharacter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelStackModel {
    pub role: String,
    pub model: ModelId,
}

impl ModelStackModel {
    #[must_use]
    pub fn new(role: impl Into<String>, model: ModelId) -> Self {
        Self {
            role: role.into(),
            model,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelStack {
    pub id: ModelStackId,
    pub display_name: String,
    pub generation: u32,
    pub models: Vec<ModelStackModel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecation: Option<ModelStackDeprecation>,
}

impl ModelStack {
    pub fn new(
        id: ModelStackId,
        display_name: impl Into<String>,
        generation: u32,
        models: Vec<ModelStackModel>,
    ) -> std::result::Result<Self, ModelStackRegistryError> {
        let stack = Self {
            id,
            display_name: display_name.into(),
            generation,
            models,
            deprecation: None,
        };
        stack.validate()?;
        Ok(stack)
    }

    pub fn with_deprecation(mut self, deprecation: ModelStackDeprecation) -> Self {
        self.deprecation = Some(deprecation);
        self
    }

    pub fn disclosure(&self, as_of_epoch_day: u32) -> ModelStackDisclosure {
        ModelStackDisclosure {
            id: self.id.clone(),
            display_name: self.display_name.clone(),
            generation: self.generation,
            models: self.models.clone(),
            deprecation: self
                .deprecation
                .map(|deprecation| deprecation.status(as_of_epoch_day)),
        }
    }

    #[must_use]
    pub fn model_for_role(&self, role: &str) -> Option<&ModelId> {
        self.models
            .iter()
            .find(|entry| entry.role == role)
            .map(|entry| &entry.model)
    }

    #[must_use]
    pub fn is_served_on(&self, as_of_epoch_day: u32) -> bool {
        self.deprecation
            .is_none_or(|deprecation| !deprecation.is_retired(as_of_epoch_day))
    }

    fn validate(&self) -> std::result::Result<(), ModelStackRegistryError> {
        if self.display_name.trim().is_empty() {
            return Err(ModelStackRegistryError::EmptyDisplayName {
                stack: self.id.clone(),
            });
        }
        if self.models.is_empty() {
            return Err(ModelStackRegistryError::EmptyModelList {
                stack: self.id.clone(),
            });
        }

        let mut roles = BTreeSet::new();
        for entry in &self.models {
            let role = entry.role.trim();
            if role.is_empty() {
                return Err(ModelStackRegistryError::EmptyModelRole {
                    stack: self.id.clone(),
                });
            }
            if role != entry.role.as_str() {
                return Err(ModelStackRegistryError::UnnormalizedModelRole {
                    stack: self.id.clone(),
                    role: entry.role.clone(),
                });
            }
            if !roles.insert(role.to_owned()) {
                return Err(ModelStackRegistryError::DuplicateModelRole {
                    stack: self.id.clone(),
                    role: role.to_owned(),
                });
            }
        }
        if let Some(deprecation) = self.deprecation {
            deprecation.validate()?;
        }

        Ok(())
    }
}

impl<'de> Deserialize<'de> for ModelStack {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawModelStack {
            id: ModelStackId,
            display_name: String,
            generation: u32,
            models: Vec<ModelStackModel>,
            #[serde(default)]
            deprecation: Option<ModelStackDeprecation>,
        }

        let raw = RawModelStack::deserialize(deserializer)?;
        let stack = Self {
            id: raw.id,
            display_name: raw.display_name,
            generation: raw.generation,
            models: raw.models,
            deprecation: raw.deprecation,
        };
        stack.validate().map_err(serde::de::Error::custom)?;
        Ok(stack)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ModelStackDeprecation {
    pub notice_starts_epoch_day: u32,
    pub retires_epoch_day: u32,
}

impl ModelStackDeprecation {
    pub fn new(
        notice_starts_epoch_day: u32,
        retires_epoch_day: u32,
    ) -> std::result::Result<Self, ModelStackRegistryError> {
        if notice_starts_epoch_day >= retires_epoch_day {
            return Err(ModelStackRegistryError::InvalidDeprecationWindow {
                notice_starts_epoch_day,
                retires_epoch_day,
            });
        }
        Ok(Self {
            notice_starts_epoch_day,
            retires_epoch_day,
        })
    }

    fn validate(self) -> std::result::Result<(), ModelStackRegistryError> {
        if self.notice_starts_epoch_day >= self.retires_epoch_day {
            return Err(ModelStackRegistryError::InvalidDeprecationWindow {
                notice_starts_epoch_day: self.notice_starts_epoch_day,
                retires_epoch_day: self.retires_epoch_day,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn status(self, as_of_epoch_day: u32) -> ModelStackDeprecationStatus {
        let stage = if as_of_epoch_day >= self.retires_epoch_day {
            ModelStackDeprecationStage::Retired
        } else if as_of_epoch_day >= self.notice_starts_epoch_day {
            ModelStackDeprecationStage::Countdown
        } else {
            ModelStackDeprecationStage::Scheduled
        };

        ModelStackDeprecationStatus {
            stage,
            notice_starts_epoch_day: self.notice_starts_epoch_day,
            retires_epoch_day: self.retires_epoch_day,
            days_until_notice: if stage == ModelStackDeprecationStage::Scheduled {
                self.notice_starts_epoch_day.checked_sub(as_of_epoch_day)
            } else {
                None
            },
            days_until_retirement: if stage != ModelStackDeprecationStage::Retired {
                self.retires_epoch_day.checked_sub(as_of_epoch_day)
            } else {
                None
            },
        }
    }

    #[must_use]
    pub fn is_retired(self, as_of_epoch_day: u32) -> bool {
        as_of_epoch_day >= self.retires_epoch_day
    }
}

impl<'de> Deserialize<'de> for ModelStackDeprecation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawModelStackDeprecation {
            notice_starts_epoch_day: u32,
            retires_epoch_day: u32,
        }

        let raw = RawModelStackDeprecation::deserialize(deserializer)?;
        Self::new(raw.notice_starts_epoch_day, raw.retires_epoch_day)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelStackDeprecationStage {
    Scheduled,
    Countdown,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelStackDeprecationStatus {
    pub stage: ModelStackDeprecationStage,
    pub notice_starts_epoch_day: u32,
    pub retires_epoch_day: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_until_notice: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_until_retirement: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ModelStackPreference {
    #[default]
    AutoUpgrade,
    Pinned {
        stack: ModelStackId,
    },
}

impl ModelStackPreference {
    #[must_use]
    pub fn pinned(stack: ModelStackId) -> Self {
        Self::Pinned { stack }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelStackRegistry {
    pub current_default: ModelStackId,
    pub stacks: BTreeMap<ModelStackId, ModelStack>,
}

impl ModelStackRegistry {
    pub fn new(
        current_default: ModelStackId,
        stacks: impl IntoIterator<Item = ModelStack>,
    ) -> std::result::Result<Self, ModelStackRegistryError> {
        let mut by_id = BTreeMap::new();
        for stack in stacks {
            stack.validate()?;
            let stack_id = stack.id.clone();
            if by_id.insert(stack_id.clone(), stack).is_some() {
                return Err(ModelStackRegistryError::DuplicateStack { stack: stack_id });
            }
        }

        if by_id.is_empty() {
            return Err(ModelStackRegistryError::EmptyRegistry);
        }
        if !by_id.contains_key(&current_default) {
            return Err(ModelStackRegistryError::UnknownDefault {
                stack: current_default,
            });
        }

        Ok(Self {
            current_default,
            stacks: by_id,
        })
    }

    #[must_use]
    pub fn current_default(&self) -> &ModelStack {
        self.stacks
            .get(&self.current_default)
            .expect("registry construction validates current default")
    }

    #[must_use]
    pub fn get(&self, stack: &ModelStackId) -> Option<&ModelStack> {
        self.stacks.get(stack)
    }

    pub fn resolve(
        &self,
        preference: &ModelStackPreference,
        as_of_epoch_day: u32,
    ) -> std::result::Result<ModelStackResolution, ModelStackRegistryError> {
        let requested = match preference {
            ModelStackPreference::AutoUpgrade => &self.current_default,
            ModelStackPreference::Pinned { stack } => stack,
        };
        let stack = self
            .get(requested)
            .ok_or_else(|| ModelStackRegistryError::UnknownStack {
                stack: requested.clone(),
            })?;
        if !stack.is_served_on(as_of_epoch_day) {
            let retires_epoch_day = stack
                .deprecation
                .expect("unserved stack has deprecation")
                .retires_epoch_day;
            return Err(ModelStackRegistryError::StackRetired {
                stack: requested.clone(),
                as_of_epoch_day,
                retires_epoch_day,
            });
        }

        Ok(ModelStackResolution {
            preference: preference.clone(),
            stack: stack.disclosure(as_of_epoch_day),
        })
    }

    pub fn disclose_stack(
        &self,
        stack: &ModelStackId,
        as_of_epoch_day: u32,
    ) -> std::result::Result<ModelStackDisclosure, ModelStackRegistryError> {
        self.get(stack)
            .map(|stack| stack.disclosure(as_of_epoch_day))
            .ok_or_else(|| ModelStackRegistryError::UnknownStack {
                stack: stack.clone(),
            })
    }
}

impl<'de> Deserialize<'de> for ModelStackRegistry {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawModelStackRegistry {
            current_default: ModelStackId,
            stacks: BTreeMap<ModelStackId, ModelStack>,
        }

        let raw = RawModelStackRegistry::deserialize(deserializer)?;
        let mut stacks = Vec::with_capacity(raw.stacks.len());
        for (key, stack) in raw.stacks {
            if key != stack.id {
                return Err(serde::de::Error::custom(format_args!(
                    "model stack registry key {key} does not match stack id {}",
                    stack.id
                )));
            }
            stacks.push(stack);
        }
        Self::new(raw.current_default, stacks).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelStackResolution {
    pub preference: ModelStackPreference,
    pub stack: ModelStackDisclosure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelStackDisclosure {
    pub id: ModelStackId,
    pub display_name: String,
    pub generation: u32,
    pub models: Vec<ModelStackModel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecation: Option<ModelStackDeprecationStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelStackRegistryError {
    #[error("model stack registry is empty")]
    EmptyRegistry,
    #[error("current default model stack {stack} is not registered")]
    UnknownDefault { stack: ModelStackId },
    #[error("model stack {stack} is not registered")]
    UnknownStack { stack: ModelStackId },
    #[error("model stack {stack} is registered more than once")]
    DuplicateStack { stack: ModelStackId },
    #[error("model stack {stack} display name is empty")]
    EmptyDisplayName { stack: ModelStackId },
    #[error("model stack {stack} has no constituent models")]
    EmptyModelList { stack: ModelStackId },
    #[error("model stack {stack} has an empty model role")]
    EmptyModelRole { stack: ModelStackId },
    #[error("model stack {stack} has unnormalized model role {role:?}")]
    UnnormalizedModelRole { stack: ModelStackId, role: String },
    #[error("model stack {stack} repeats model role {role}")]
    DuplicateModelRole { stack: ModelStackId, role: String },
    #[error(
        "model stack deprecation window must start before retirement, got notice {notice_starts_epoch_day} and retirement {retires_epoch_day}"
    )]
    InvalidDeprecationWindow {
        notice_starts_epoch_day: u32,
        retires_epoch_day: u32,
    },
    #[error(
        "model stack {stack} retired on epoch day {retires_epoch_day} and cannot be served on epoch day {as_of_epoch_day}"
    )]
    StackRetired {
        stack: ModelStackId,
        as_of_epoch_day: u32,
        retires_epoch_day: u32,
    },
    #[error("compiled model stack id {id} is invalid: {source}")]
    InvalidCompiledStackId {
        id: String,
        source: ModelStackIdError,
    },
    #[error("compiled model id {model} is invalid: {source}")]
    InvalidCompiledModelId { model: String, source: ModelIdError },
}

#[must_use]
pub fn default_model_stack_registry() -> ModelStackRegistry {
    try_default_model_stack_registry().expect("compiled default model stack registry is valid")
}

pub fn try_default_model_stack_registry()
-> std::result::Result<ModelStackRegistry, ModelStackRegistryError> {
    let current = default_stack(DEFAULT_MODEL_STACK_CURRENT_ID, "Default", 2, "2026-07-06")?;
    let v1 = default_stack(DEFAULT_MODEL_STACK_V1_ID, "Default v1", 1, "2026-06-01")?
        .with_deprecation(ModelStackDeprecation::new(20_640, 20_730)?);

    ModelStackRegistry::new(
        compiled_stack_id(DEFAULT_MODEL_STACK_CURRENT_ID)?,
        [current, v1],
    )
}

fn default_stack(
    id: &str,
    display_name: &str,
    generation: u32,
    revision: &str,
) -> std::result::Result<ModelStack, ModelStackRegistryError> {
    ModelStack::new(
        compiled_stack_id(id)?,
        display_name,
        generation,
        [
            ("orchestrator", "orchestrator-default"),
            ("subagent", "subagent-default"),
            ("summarizer", "summarizer-default"),
        ]
        .into_iter()
        .map(|(role, name)| {
            let model = format!("oneiron/{name}@{revision}");
            Ok(ModelStackModel::new(
                role,
                ModelId::new(model.clone()).map_err(|source| {
                    ModelStackRegistryError::InvalidCompiledModelId { model, source }
                })?,
            ))
        })
        .collect::<std::result::Result<Vec<_>, ModelStackRegistryError>>()?,
    )
}

fn compiled_stack_id(id: &str) -> std::result::Result<ModelStackId, ModelStackRegistryError> {
    ModelStackId::new(id).map_err(|source| ModelStackRegistryError::InvalidCompiledStackId {
        id: id.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests;
