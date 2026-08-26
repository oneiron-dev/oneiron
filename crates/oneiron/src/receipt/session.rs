use serde::{Deserialize, Serialize};

use super::kernel::ReceiptRecord;
use crate::error::{Error, Result};

/// Session-local holder for emit-adjacent receipts (OF-326 interaction).
///
/// Emit-adjacent receipts follow the transcript: in an off-record session
/// they are session-local and deleted with the transcript at session close
/// (the context field-set — `activated_memory_ids` above all — would betray
/// what the room was about). Floor receipts never ride this log: they
/// project from their own stored substrates and persist regardless of
/// session mode, which is exactly the OF-326 "only floor receipts persist"
/// split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLocalReceiptLog {
    session_ref: String,
    off_record: bool,
    receipts: Vec<ReceiptRecord>,
}

impl SessionLocalReceiptLog {
    /// Opens the emit receipt log for an on-record session: receipts are
    /// retained at close.
    #[must_use]
    pub fn on_record(session_ref: impl Into<String>) -> Self {
        Self {
            session_ref: session_ref.into(),
            off_record: false,
            receipts: Vec::new(),
        }
    }

    /// Opens the emit receipt log for an off-record session: receipts are
    /// deleted with the transcript at close.
    #[must_use]
    pub fn off_record(session_ref: impl Into<String>) -> Self {
        Self {
            session_ref: session_ref.into(),
            off_record: true,
            receipts: Vec::new(),
        }
    }

    #[must_use]
    pub fn session_ref(&self) -> &str {
        &self.session_ref
    }

    #[must_use]
    pub const fn is_off_record(&self) -> bool {
        self.off_record
    }

    /// Records one emit-adjacent receipt into the session-local log.
    ///
    /// Non-emit receipts are rejected: they persist through their own
    /// substrates and must never become deletable via session close.
    pub fn record(&mut self, receipt: ReceiptRecord) -> Result<()> {
        if !receipt.receipt_kind.is_emit_adjacent() {
            return Err(Error::EmitAdjacentReceiptRequired {
                surface: "session-local receipt log",
                kind: receipt.receipt_kind.as_str(),
            });
        }
        self.receipts.push(receipt);
        Ok(())
    }

    /// The receipts visible while the session lives, regardless of mode.
    #[must_use]
    pub fn receipts(&self) -> &[ReceiptRecord] {
        &self.receipts
    }

    /// Closes the session log. On-record sessions retain their emit
    /// receipts; off-record sessions delete them with the transcript.
    #[must_use]
    pub fn close(self) -> SessionReceiptClose {
        let (retained, deleted) = if self.off_record {
            (Vec::new(), self.receipts.len())
        } else {
            (self.receipts, 0)
        };
        SessionReceiptClose {
            session_ref: self.session_ref,
            off_record: self.off_record,
            retained,
            deleted,
        }
    }
}

/// Outcome of closing a [`SessionLocalReceiptLog`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReceiptClose {
    pub session_ref: String,
    pub off_record: bool,
    /// Emit receipts that survive the close (empty for off-record sessions).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained: Vec<ReceiptRecord>,
    /// Count of emit receipts deleted with the transcript.
    pub deleted: usize,
}
