//! A contact label can share its original immutable value backing and guard.

use std::fmt;
use std::sync::Arc;

use crate::write_envelope::claim_body::ClaimValueRead;
use serde::{Serialize, Serializer};

#[derive(Clone)]
pub(super) enum InterlocutorLabel {
    Owned(String),
    Guarded(Arc<ClaimValueRead>),
}

impl InterlocutorLabel {
    pub(super) fn from_contact_value(value: ClaimValueRead) -> Self {
        Self::Guarded(Arc::new(value))
    }

    pub(super) fn as_str(&self) -> &str {
        match self {
            Self::Owned(value) => value,
            Self::Guarded(value) => value.as_str().expect("validated contact label"),
        }
    }
}

impl fmt::Debug for InterlocutorLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), formatter)
    }
}

impl PartialEq for InterlocutorLabel {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Serialize for InterlocutorLabel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
