use crate::note::files::metadata::FileReadiness;
use crate::note::files::metadata::NameOnlyReason;
pub use crate::note::folder_source::original::FileOriginal;
use oneiron_base::error::Result;
use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;

pub mod original;
