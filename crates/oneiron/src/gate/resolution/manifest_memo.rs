//! Decodes a store keeps between policy resolutions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::error::{Error, Result};
use crate::gate::decode::{
    DecodedManifestCarrier, decode_manifest_carrier, decode_policy_manifest,
};

use super::manifest_types::SheetAnswerPrecedence;

/// Bodies kept at most. A vault holds a handful of manifests, so past this
/// the memo starts over rather than grow with a flood of distinct rows.
const MAX_ROWS: usize = 64;

/// What a store keeps between policy resolutions. Each entry is a pure
/// function of bytes: the shipped manifest is a constant of the build, and a
/// stored manifest body decodes the same way every time it is read.
#[derive(Default)]
pub(crate) struct ManifestDecodeMemo {
    shipped: OnceLock<ShippedPolicyRows>,
    rows: Mutex<HashMap<[u8; 32], Arc<ManifestRow>>>,
}

/// What a resolution takes from the shipped manifest: its sheet-answer
/// default and precedence.
#[derive(Debug, Clone, Copy)]
pub(super) struct ShippedPolicyRows {
    pub(super) sheet_answer_default_max_count: u64,
    pub(super) sheet_answer_precedence: SheetAnswerPrecedence,
}

/// One stored manifest body, decoded.
pub(super) struct ManifestRow {
    /// The body is a project-depth contribution envelope.
    pub(super) project_depth: bool,
    pub(super) carrier: Option<DecodedManifestCarrier>,
}

impl ManifestDecodeMemo {
    pub(super) fn shipped(&self) -> Result<ShippedPolicyRows> {
        if let Some(rows) = self.shipped.get() {
            return Ok(*rows);
        }
        let shipped =
            decode_policy_manifest(&crate::gate::default_manifest::default_policy_manifest()?)
                .ok_or(Error::InvariantViolation(
                    "shipped sheet-answer policy manifest invalid",
                ))?;
        let default_max_count = shipped
            .sheet_answer_limits
            .iter()
            .find(|row| row.artifact_ref.is_none() && row.sheet.is_none())
            .map(|row| row.max_count);
        let (Some(sheet_answer_default_max_count), Some(sheet_answer_precedence)) =
            (default_max_count, shipped.sheet_answer_precedence)
        else {
            return Err(Error::InvariantViolation(
                "shipped sheet-answer policy rows missing",
            ));
        };
        Ok(*self.shipped.get_or_init(|| ShippedPolicyRows {
            sheet_answer_default_max_count,
            sheet_answer_precedence,
        }))
    }

    /// `body` decoded, kept under its BLAKE3 hash: the identity the manifest
    /// trust and quarantine sidecars already judge a body by.
    pub(super) fn row(&self, body: &[u8]) -> Arc<ManifestRow> {
        let key = *blake3::hash(body).as_bytes();
        if let Some(row) = self
            .rows
            .lock()
            .ok()
            .and_then(|rows| rows.get(&key).cloned())
        {
            return row;
        }
        let row = Arc::new(ManifestRow {
            project_depth: crate::gate::project_depth::is_project_depth_contribution(body),
            carrier: decode_manifest_carrier(body),
        });
        if let Ok(mut rows) = self.rows.lock() {
            if rows.len() >= MAX_ROWS {
                rows.clear();
            }
            rows.insert(key, Arc::clone(&row));
        }
        row
    }
}
