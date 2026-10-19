//! The feedback previews an owner was shown, kept until they expire (FIX
//! 5212): a send reads back the exact bytes the preview showed and never
//! runs the in-vault filter again, so a filter that answers differently
//! twice cannot make the sent bundle differ from the previewed one.
//!
//! A row holds the previewed bytes, their encoding and digest, the digest of
//! the bundle as built before it was filtered (what the send's request must
//! still build), the owner and the route it was previewed for, and when it
//! expires. It is keyed by the time the preview was issued and its approval,
//! the two values the preview returned to the caller, so a caller who edits
//! either finds no row. A repeated send reads the same row; rows are dropped
//! once expired, at the next preview's write.

use serde::{Deserialize, Serialize};

use super::{
    FEEDBACK_APPROVAL_COMPONENT_PREFIX, FeedbackEncoding, FeedbackPreview, FeedbackSendRoute,
};
use crate::side_table::{self, Named, SideTable};
use crate::{Error, Result, Vault};

/// Every retained preview, keyed by (issued at, approval component digest).
const PREVIEWS: SideTable<(u64, [u8; 32]), PreviewRow, Named> =
    SideTable::new(&side_table::FEEDBACK_PREVIEW);

/// One preview as its owner was shown it, and what it is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedFeedbackPreview {
    /// The exact bytes previewed, their encoding and digest.
    pub preview: FeedbackPreview,
    /// The digest of the bundle as built, before the filter ran.
    pub source_digest: String,
    /// The owner principal the preview was made for.
    pub principal_ref: String,
    /// The route the preview would go over.
    pub route: FeedbackSendRoute,
    /// When the preview was issued, on the vault's recording clock.
    pub issued_at: u64,
    /// The last second it may still be sent.
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRow {
    encoding: String,
    bytes: Vec<u8>,
    digest: String,
    source_digest: String,
    principal_ref: String,
    route: FeedbackSendRoute,
    expires_at: u64,
}

/// The key half an approval names: the digest its component id carries.
fn approval_key(approval: &str) -> Option<[u8; 32]> {
    let hex = approval.strip_prefix(FEEDBACK_APPROVAL_COMPONENT_PREFIX)?;
    blake3::Hash::from_hex(hex)
        .ok()
        .map(|hash| *hash.as_bytes())
}

impl Vault {
    /// Keeps `retained` under `approval` and its issue time until it expires,
    /// and drops the previews that already have.
    ///
    /// # Errors
    ///
    /// An approval that is not a feedback approval component id; storage
    /// errors.
    pub fn retain_feedback_preview(
        &self,
        approval: &str,
        retained: &RetainedFeedbackPreview,
    ) -> Result<()> {
        let key = approval_key(approval).ok_or(Error::InvalidConfig(
            "feedback approval component id".into(),
        ))?;
        let row = PreviewRow {
            encoding: retained.preview.encoding().as_str().to_owned(),
            bytes: retained.preview.bytes().to_vec(),
            digest: retained.preview.digest().to_owned(),
            source_digest: retained.source_digest.clone(),
            principal_ref: retained.principal_ref.clone(),
            route: retained.route.clone(),
            expires_at: retained.expires_at,
        };
        let now = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            // Rows sort by issue time and share one lifetime, so the expired
            // ones lead; the first that still stands ends the sweep.
            let mut expired = Vec::new();
            for entry in PREVIEWS.iter_from(&self.store, txn, &[])? {
                let (key, stored) = entry?;
                if stored.expires_at >= now {
                    break;
                }
                expired.push(key);
            }
            for key in &expired {
                PREVIEWS.delete(&self.store, txn, key)?;
            }
            PREVIEWS.put(&self.store, txn, &(retained.issued_at, key), &row)
        })
    }

    /// The preview kept under `approval` at `issued_at`, while it has not
    /// expired at `now`; `None` when none stands. The bytes come back as
    /// stored, decoded and digested again but never filtered or re-encoded.
    ///
    /// # Errors
    ///
    /// A stored row whose bytes no longer match their digest or encoding;
    /// storage errors.
    pub fn retained_feedback_preview(
        &self,
        approval: &str,
        issued_at: u64,
        now: u64,
    ) -> Result<Option<RetainedFeedbackPreview>> {
        let Some(key) = approval_key(approval) else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        let Some(row) = PREVIEWS.get(&self.store, &txn, &(issued_at, key))? else {
            return Ok(None);
        };
        if row.expires_at < now {
            return Ok(None);
        }
        let corrupted = || Error::CorruptedIndex("retained feedback preview");
        let encoding = FeedbackEncoding::from_token(&row.encoding).map_err(|_| corrupted())?;
        let preview =
            FeedbackPreview::from_retained(encoding, row.bytes).map_err(|_| corrupted())?;
        if preview.digest() != row.digest {
            return Err(corrupted());
        }
        Ok(Some(RetainedFeedbackPreview {
            preview,
            source_digest: row.source_digest,
            principal_ref: row.principal_ref,
            route: row.route,
            issued_at,
            expires_at: row.expires_at,
        }))
    }
}
