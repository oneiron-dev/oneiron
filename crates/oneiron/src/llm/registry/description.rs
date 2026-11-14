//! Ranked, source-attributed model descriptions; absent evidence stays absent.
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[doc(hidden)]
pub use oneiron_records::llm::registry::description::{
    DescriptionClass, DescriptionContribution, ModelDescription,
};
