//! Hex, hash, base64, and id-set helpers.

use super::model::{ArmKind, BeamFixture, DatasetSource, RunManifest};
use super::report_model::{NotReadyState, ReportFormat, TokenAccountingSource};
use super::{BEAM_CONTRACT_EMBEDDING_DIMENSIONS, BeamError, DEFAULT_JSONL_RETRIEVAL_LIMIT};
use oneiron::{EmptyReason, PackFormat, Signal, VaultConfig};
use sha2::Digest;
use sha2::Sha256;
use std::path::Path;

pub(super) fn hash_str(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}
pub(super) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
pub(super) fn decode_base64_standard(input: &str) -> Result<Vec<u8>, String> {
    let bytes: Vec<u8> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 vector data length must be a multiple of 4".to_owned());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunk_count = bytes.len() / 4;
    for (chunk_index, chunk) in bytes.chunks_exact(4).enumerate() {
        let mut vals = [0_u8; 4];
        let mut padding = 0;
        for (index, byte) in chunk.iter().copied().enumerate() {
            if byte == b'=' {
                vals[index] = 0;
                padding += 1;
            } else if padding > 0 {
                return Err("base64 vector data has non-padding after padding".to_owned());
            } else {
                vals[index] = base64_value(byte)
                    .ok_or_else(|| "base64 vector data contains an invalid character".to_owned())?;
            }
        }
        if padding > 2 || (padding > 0 && chunk_index + 1 != chunk_count) {
            return Err("base64 vector data has invalid padding".to_owned());
        }
        out.push((vals[0] << 2) | (vals[1] >> 4));
        if padding < 2 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if padding == 0 {
            out.push((vals[2] << 6) | vals[3]);
        }
    }
    Ok(out)
}
pub(super) fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
pub(super) fn default_fixture_cost_source() -> TokenAccountingSource {
    TokenAccountingSource::FixtureDeclaredZero
}
pub(super) const fn default_jsonl_retrieval_limit() -> usize {
    DEFAULT_JSONL_RETRIEVAL_LIMIT
}
pub(super) fn accounting_reasons(count: usize, reason: &str) -> Vec<String> {
    if count == 0 {
        Vec::new()
    } else {
        vec![reason.to_owned()]
    }
}
pub(super) fn arm_not_ready(kind: ArmKind) -> NotReadyState {
    NotReadyState {
        component: format!("{} arm", kind.as_str()),
        reason: "adapter intentionally not implemented in EVAL-001 scaffold".to_owned(),
        retryable: false,
    }
}
pub(super) fn dataset_not_ready(source: &DatasetSource) -> NotReadyState {
    NotReadyState {
        component: "dataset loader".to_owned(),
        reason: format!(
            "{} datasets are declared in the schema but not implemented in EVAL-001",
            dataset_source_description(source)
        ),
        retryable: false,
    }
}
pub(super) fn beam_vault_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 32 * 1024 * 1024;
    cfg.dimensions = BEAM_CONTRACT_EMBEDDING_DIMENSIONS;
    cfg.embedding_model = Some("oneiron/eval-contract@v1".to_owned());
    cfg.max_readers = 16;
    cfg
}
pub(super) fn invalid_fixture(fixture: &BeamFixture, reason: impl Into<String>) -> BeamError {
    BeamError::InvalidFixture {
        fixture_id: fixture.fixture_id.clone(),
        reason: reason.into(),
    }
}
pub(super) fn invalid_manifest(manifest: &RunManifest, reason: impl Into<String>) -> BeamError {
    BeamError::InvalidManifest {
        run_id: manifest.run_id.clone(),
        reason: reason.into(),
    }
}
pub(super) fn invalid_run_jsonl(path: &Path, line: usize, reason: impl Into<String>) -> BeamError {
    BeamError::InvalidRunJsonl {
        path: path.display().to_string(),
        line,
        reason: reason.into(),
    }
}
pub(super) fn dataset_source_description(source: &DatasetSource) -> String {
    match source {
        DatasetSource::Fixture { fixture_id, .. } => format!("fixture `{fixture_id}`"),
        DatasetSource::Jsonl { path, .. } => format!("jsonl `{}`", path.display()),
        DatasetSource::Miracl { dataset } => format!("miracl `{dataset}`"),
        DatasetSource::MrTydi { dataset } => format!("mr_tydi `{dataset}`"),
    }
}
pub(super) fn report_format_label(format: ReportFormat) -> &'static str {
    match format {
        ReportFormat::Json => "json",
    }
}
pub(super) fn pack_format_label(format: PackFormat) -> &'static str {
    match format {
        PackFormat::Json => "json",
        PackFormat::Yaml => "yaml",
        PackFormat::Toon => "toon",
        PackFormat::Markdown => "markdown",
        PackFormat::Plaintext => "plaintext",
        _ => "unknown",
    }
}
pub(super) fn signal_label(signal: Signal) -> &'static str {
    match signal {
        Signal::Vector => "vector",
        Signal::Text => "text",
        Signal::Phonetic => "phonetic",
        Signal::Temporal => "temporal",
        Signal::Ppr => "ppr",
        _ => "unknown",
    }
}
pub(super) fn empty_reason_label(reason: EmptyReason) -> &'static str {
    match reason {
        EmptyReason::FilterMatchedNone => "filter_matched_none",
        EmptyReason::NoData => "no_data",
        EmptyReason::AllActivated => "all_activated",
        EmptyReason::BelowThreshold => "below_threshold",
    }
}
