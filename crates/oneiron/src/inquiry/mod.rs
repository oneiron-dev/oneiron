//! Inquiry: a company vault asks a member's vault (federation.md #inquiry,
//! ARCH-0082 #inquiry; owner ASK-YOUR-VAULT = A, 2026-11-11). INQUIRE-1,
//! PRs 1 to 4: the records, their stores, the company setting, the edge,
//! the member side's answer and the asking side. No verb reaches them yet.
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
//! * The asking side (PR 4), on the company vault: the route to a member's
//!   vault, bound to the member's seat ([`InquiryRoute`]); the send through
//!   an [`InquiryTransport`], which writes the receipt and gives
//!   `unavailable` when no route answers; and the task-held answer, in
//!   memory only, dropped when its task ends or at `valid_until`.
//!
//! The verbs and the member host's route (PR 5) and the copy landing
//! (PR 6) are later builds.

mod edge;
mod holder;
mod log;
mod member;
mod policy;
mod receipt;
mod record;
mod route;
mod send;
pub(crate) mod tables;
mod terms;

pub(crate) use edge::drop_inquiry_scope_links_in_txn;
pub use edge::{
    INQUIRY_STATEMENT_PREDICATE, InquiryEdge, InquiryEdgeReciprocalGrant, InquiryEdgeRequest,
    InquiryScopeItem,
};

pub(crate) use holder::InquiryAnswerHolder;
pub(crate) use log::erase_inquiry_log_actor_in_txn;
pub use log::{InquiryDecider, InquiryLogEntry};
#[cfg_attr(not(oneiron_test_support), allow(unused_imports))]
pub(crate) use log::{log_inquiry_in_txn, settle_inquiry_in_txn};
pub(crate) use member::erase_inquiry_pending_actor_in_txn;
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
pub use route::{InquiryRoute, InquiryRouteRequest};
pub(crate) use route::{end_inquiry_route_in_txn, erase_inquiry_route_actor_in_txn};
pub use send::{InquirySendRequest, InquirySent, InquiryTransport, InquiryTransportError};
pub use terms::{InquiryCheckInMode, InquiryTerms, InquiryTierCeiling};
