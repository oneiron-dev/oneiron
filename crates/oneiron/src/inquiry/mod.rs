//! Inquiry: a company vault asks a member's vault (federation.md #inquiry,
//! ARCH-0082 #inquiry; owner ASK-YOUR-VAULT = A, 2026-11-11). INQUIRE-1,
//! PRs 1 to 3: the records, their stores, the company setting, the edge and
//! the member side's answer. Nothing sends an inquiry yet.
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
//! * The inquiry edge (PR 2): the member's Connect guest grant to one
//!   company, verbs `inquire` alone, with its terms ([`InquiryTerms`]), the
//!   company's reciprocal grant, and the opened scope "What <company> can
//!   ask about" ([`InquiryScopeItem`]).
//!
//! * The member side (PR 3): the member's vault admits an inquiry over its
//!   edge ([`Vault::admit_inquiry`](crate::Vault::admit_inquiry)), reads
//!   the opened scope at the edge's tier, lets the companion check it
//!   ([`InquiryJudgment`]) and runs the check-in ladder with
//!   `vault.inquiry.answer` as the verb; an inquiry the ladder takes to the
//!   member waits as a pending check-in until the member answers
//!   ([`InquiryMemberAnswer`]) or it expires.
//!
//! The asking side's send and task-held answer (PR 4), the verbs (PR 5)
//! and the copy landing (PR 6) are later builds.

mod edge;
mod log;
mod member;
mod policy;
mod receipt;
mod record;
pub(crate) mod tables;
mod terms;

pub(crate) use edge::drop_inquiry_scope_links_in_txn;
pub use edge::{
    INQUIRY_STATEMENT_PREDICATE, InquiryEdge, InquiryEdgeReciprocalGrant, InquiryEdgeRequest,
    InquiryScopeItem,
};

pub(crate) use log::erase_inquiry_log_actor_in_txn;
pub use log::{InquiryDecider, InquiryLogEntry};
#[cfg_attr(not(oneiron_test_support), allow(unused_imports))]
pub(crate) use log::{log_inquiry_in_txn, settle_inquiry_in_txn};
pub use member::{
    INQUIRY_ANSWER_VERB, InquiryJudgment, InquiryJudgmentOutcome, InquiryMemberAnswer,
    UnsureInquiryJudgment,
};
pub(crate) use policy::{INQUIRY_ROW_KEY, InquiryPolicyRead};
pub use policy::{INQUIRY_ROW_VERSION, InquiryKeepSetting, InquiryKeepSource, InquiryPolicy};
#[cfg_attr(not(oneiron_test_support), allow(unused_imports))]
pub(crate) use receipt::write_inquiry_receipt_in_txn;
pub(crate) use receipt::{erase_inquiry_receipt_actor_in_txn, inquiry_receipts};
pub use record::{
    Inquiry, InquiryAnswer, InquiryAsker, InquiryKeep, InquiryOutcome, InquiryStatement,
    InquiryTask, StatementSource,
};
pub use terms::{InquiryCheckInMode, InquiryTerms, InquiryTierCeiling};
