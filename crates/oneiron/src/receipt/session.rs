use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::kernel::ReceiptRecord;
use crate::error::{ClaimError, Error, Result};

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
            return Err(Error::Claim(ClaimError::EmitAdjacentReceiptRequired {
                surface: "session-local receipt log",
                kind: receipt.receipt_kind.as_str(),
            }));
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
    pub fn close(mut self) -> SessionReceiptClose {
        let deleted = if self.off_record {
            self.receipts.len()
        } else {
            0
        };
        let retained = if self.off_record {
            Vec::new()
        } else {
            std::mem::take(&mut self.receipts)
        };
        SessionReceiptClose {
            session_ref: std::mem::take(&mut self.session_ref),
            off_record: self.off_record,
            retained,
            deleted,
        }
    }
}

// Off-record close (and an abandoned log) must not leave emit-context
// strings in allocator memory. On-record receipts move into the close result.
impl Drop for SessionLocalReceiptLog {
    fn drop(&mut self) {
        if !self.off_record {
            return;
        }
        self.session_ref.zeroize();
        for receipt in &mut self.receipts {
            zeroize_receipt(receipt);
        }
    }
}

fn zeroize_receipt(receipt: &mut ReceiptRecord) {
    receipt.receipt_id.zeroize();
    receipt.actor.zeroize();
    receipt.on_behalf_of.zeroize();
    receipt.outcome.zeroize();
    receipt.job_ref.zeroize();
    receipt.trigger_ref.zeroize();
    receipt.policy_trace.iter_mut().for_each(Zeroize::zeroize);
    for (mut key, mut value) in std::mem::take(&mut receipt.fields) {
        key.zeroize();
        value.zeroize();
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

// The off-record close result carries a short-lived session reference; scrub
// it as well when its caller has consumed the close counts. On-record result
// receipts remain caller-owned and must not be cleared here.
impl Drop for SessionReceiptClose {
    fn drop(&mut self) {
        if self.off_record {
            self.session_ref.zeroize();
            for receipt in &mut self.retained {
                zeroize_receipt(receipt);
            }
        }
    }
}

#[cfg(test)]
mod hygiene_tests {
    use super::*;
    use crate::receipt::ReceiptKind;
    use std::collections::BTreeMap;

    use crate::session_overlay::hygiene_tests::{allocation, observe_drop};

    fn emit_with_context() -> ReceiptRecord {
        ReceiptRecord {
            receipt_id: "receipt-private".into(),
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 1,
            actor: None,
            on_behalf_of: None,
            outcome: "done".into(),
            job_ref: None,
            trigger_ref: None,
            policy_trace: Vec::new(),
            fields: BTreeMap::from([("context".into(), "private-memory".into())]),
        }
    }

    #[test]
    fn close_and_abandon_scrub_off_record_receipts_but_preserve_on_record_output() {
        let mut log = SessionLocalReceiptLog::off_record("session-private");
        log.record(emit_with_context()).unwrap();
        let watched = allocation(log.receipts()[0].fields["context"].as_bytes());
        observe_drop(watched, true, || {
            let outcome = log.close();
            assert_eq!(outcome.deleted, 1);
            assert!(outcome.retained.is_empty());
        });

        let mut abandoned = SessionLocalReceiptLog::off_record("session-private");
        abandoned.record(emit_with_context()).unwrap();
        let watched = allocation(abandoned.receipts()[0].fields["context"].as_bytes());
        observe_drop(watched, true, || drop(abandoned));

        let mut log = SessionLocalReceiptLog::on_record("session-ordinary");
        log.record(emit_with_context()).unwrap();
        let watched = allocation(log.receipts()[0].fields["context"].as_bytes());
        let mut retained = None;
        observe_drop(watched, false, || {
            retained = Some(log.close());
        });
        assert_eq!(
            retained.as_ref().unwrap().retained[0].fields["context"],
            "private-memory"
        );
    }
}
