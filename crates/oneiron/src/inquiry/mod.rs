//! Inquiry: a company vault asks a member's vault (federation.md #inquiry,
//! ARCH-0082 #inquiry; owner ASK-YOUR-VAULT = A, 2026-11-11). INQUIRE-1,
//! PR 1: the records, their stores and the company setting. Nothing sends,
//! answers or admits an inquiry yet.
//!
//! * [`Inquiry`] and [`InquiryAnswer`], with the one wire shape both vaults
//!   read: statement text and its source, never a hit, score, vector or
//!   record id; `no_answer` in one shape whatever its reason.
//! * "Asked about you" ([`InquiryLogEntry`]), the member vault's own full
//!   log: the inquiry, its answer and who decided.
//! * The asking side's `inquiry` receipt: the asker, the task, the question,
//!   the time and the outcome, never answer text.
//! * The company setting `inquiry_keep` ([`InquiryKeep`]), a versioned row
//!   of the policy manifest ([`InquiryPolicy`]); no row means `task`.
//!
//! The inquiry edge and its opened scope (PR 2), the member-side answer on
//! the check-in ladder (PR 3), the asking side's send and task-held answer
//! (PR 4), the verbs (PR 5) and the copy landing (PR 6) are later builds.

mod log;
mod policy;
mod receipt;
mod record;
mod tables;

pub(crate) use log::erase_inquiry_log_actor_in_txn;
pub use log::{InquiryDecider, InquiryLogEntry};
#[cfg_attr(not(oneiron_test_support), allow(unused_imports))]
pub(crate) use log::{log_inquiry_in_txn, settle_inquiry_in_txn};
pub(crate) use policy::{INQUIRY_ROW_KEY, InquiryPolicyRead};
pub use policy::{INQUIRY_ROW_VERSION, InquiryKeepSetting, InquiryKeepSource, InquiryPolicy};
#[cfg_attr(not(oneiron_test_support), allow(unused_imports))]
pub(crate) use receipt::write_inquiry_receipt_in_txn;
pub(crate) use receipt::{erase_inquiry_receipt_actor_in_txn, inquiry_receipts};
pub use record::{
    Inquiry, InquiryAnswer, InquiryAsker, InquiryKeep, InquiryOutcome, InquiryStatement,
    InquiryTask, StatementSource,
};
