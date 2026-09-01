//! Bounded wire tokens shared by every other lens concern.
//!
//! `lens_token_type!` and the nine newtypes it generates stay in this one file:
//! the macro is only ever invoked here, so the generated surface is readable in
//! place. [`LensHandleRef`]/[`LensHandleRole`] live here too because lens nodes
//! ([`super::atom`], [`super::generated_ui`]) and the host mediation chokepoint
//! ([`super::mediation`]) all name them.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{Error, Result};

use super::validate::{validate_lens_capability_name, validate_lens_token};

pub(super) const MAX_LENS_TREE_DEPTH: usize = 64;
pub(super) const MAX_LENS_COLLECTION_ITEMS: usize = 4096;

macro_rules! lens_token_type {
    ($name:ident, $context:literal) => {
        lens_token_type!($name, $context, false);
    };

    ($name:ident, $context:literal, $reject_forbidden_capability:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_lens_token($context, &value)?;
                if $reject_forbidden_capability {
                    validate_lens_capability_name($context, &value)?;
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = Error;

            fn try_from(value: String) -> Result<Self> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = Error;

            fn try_from(value: &str) -> Result<Self> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

lens_token_type!(LensAtomId, "lens atom id");
lens_token_type!(LensHandleName, "lens handle name");
lens_token_type!(LensRenderId, "lens render id");
lens_token_type!(LensBackingRefId, "lens backing ref id");
lens_token_type!(LensMediaHandle, "lens media handle");
lens_token_type!(LensResultSetRowId, "lens result set row id");
lens_token_type!(SelfUiControlId, "self.ui control id");
lens_token_type!(SelfUiActionId, "self.ui action id", true);
lens_token_type!(SelfUiOptionValue, "self.ui option value");
lens_token_type!(SelfUiStateKey, "self.ui state key");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LensHandleRef {
    pub name: LensHandleName,
    pub role: LensHandleRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensHandleRole {
    ClaimSet,
    EntitySet,
    Timeline,
    QueryResult,
    ActionTarget,
}
