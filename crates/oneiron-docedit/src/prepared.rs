//! Checked handoff commitment for retained bytes, base, writes, and validation report.
use crate::roundtrip::{EditManifest, ValidationReport};
use crate::{Error, Result};

/// Immutable commitment; changing any settled input requires a new preparation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedEdit {
    commit: [u8; 32],
}
/// The complete input to the ARTL storage handoff. Length framing keeps fields
/// unambiguous, including an absent versus a numbered base revision.
pub struct PrepareInput<'a, W = EditManifest, R = ValidationReport> {
    pub base_content_hash: [u8; 32],
    pub base_version: Option<u64>,
    pub run_ref: &'a str,
    pub output: &'a [u8],
    pub writes: &'a W,
    pub report: &'a R,
    pub engine: &'a crate::calc::EngineId,
}
pub trait PreparationReport: serde::Serialize {
    fn passed(&self) -> bool;
}
impl PreparationReport for ValidationReport {
    fn passed(&self) -> bool {
        self.ok && !self.checks.is_empty() && self.checks.iter().all(|check| check.passed)
    }
}
pub fn prepare<W: serde::Serialize, R: PreparationReport>(
    input: PrepareInput<'_, W, R>,
) -> Result<PreparedEdit> {
    if input.output.is_empty() || input.run_ref.trim().is_empty() {
        return Err(Error::EditFailed("empty prepared output or run reference"));
    }
    if input.base_version == Some(0) || !input.report.passed() {
        return Err(Error::InvalidManifest(
            "invalid preparation base or validation report",
        ));
    }
    input.engine.validate()?;
    let writes = rmp_serde::to_vec_named(input.writes)
        .map_err(|_| Error::InvalidManifest("writes encoding"))?;
    let engine = serde_json::to_vec(input.engine)
        .map_err(|_| Error::InvalidManifest("engine stamp encoding"))?;
    let report = serde_json::to_vec(input.report)
        .map_err(|_| Error::InvalidManifest("validation report encoding"))?;
    let mut hasher = blake3::Hasher::new_derive_key("oneiron.docedit.prepared.v1");
    hasher.update(&input.base_content_hash);
    hasher.update(&[u8::from(input.base_version.is_some())]);
    hasher.update(&input.base_version.unwrap_or(0).to_be_bytes());
    for bytes in [
        input.run_ref.as_bytes(),
        writes.as_slice(),
        report.as_slice(),
        engine.as_slice(),
        input.output,
    ] {
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(PreparedEdit {
        commit: *hasher.finalize().as_bytes(),
    })
}
impl PreparedEdit {
    #[must_use]
    pub fn commit_hash(&self) -> &[u8; 32] {
        &self.commit
    }
    pub fn verify<W: serde::Serialize, R: PreparationReport>(
        &self,
        input: PrepareInput<'_, W, R>,
    ) -> Result<()> {
        if self == &prepare(input)? {
            Ok(())
        } else {
            Err(Error::CommitMismatch)
        }
    }
}
