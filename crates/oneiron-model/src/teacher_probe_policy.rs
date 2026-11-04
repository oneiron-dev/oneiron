//! Resolved extraction-teacher probe policy values.

use crate::model_binding::invalid;
use oneiron_contracts::error::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const TEACHER_PROBE_ID: &str = "oneiron-conll-bio-v1";

/// Resolved vault policy exported to the offline bench. The vault re-resolves
/// it inside the teacher-pin transaction; a stale or caller-edited snapshot
/// cannot loosen the actual admission floor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeacherProbePolicy {
    pub probe_id: String,
    pub vault_min_f1_millionths: u32,
    pub min_f1_millionths: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_ref: Option<String>,
}

impl TeacherProbePolicy {
    pub fn resolved(vault_min: u32, effective_min: u32, holder: Option<&str>) -> Result<Self> {
        let policy = Self {
            probe_id: TEACHER_PROBE_ID.into(),
            vault_min_f1_millionths: vault_min,
            min_f1_millionths: effective_min,
            holder_ref: holder.map(str::to_owned),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let policy: Self = serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|e| invalid(&format!("invalid teacher probe policy: {e}")))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.probe_id != TEACHER_PROBE_ID
            || !(1..=1_000_000).contains(&self.vault_min_f1_millionths)
            || !(self.vault_min_f1_millionths..=1_000_000).contains(&self.min_f1_millionths)
            || self
                .holder_ref
                .as_deref()
                .is_some_and(|id| !valid_holder_ref(id))
        {
            return Err(invalid("invalid resolved teacher probe policy"));
        }
        Ok(())
    }

    pub fn identity_hash(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|e| invalid(&format!("teacher policy serialization failed: {e}")))?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }
}

pub fn valid_holder_ref(holder: &str) -> bool {
    holder.len() == 32
        && holder
            .bytes()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}
