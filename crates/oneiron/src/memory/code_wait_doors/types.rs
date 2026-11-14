//! Code wait request, answer, settlement and receipt records.
//! `CodeWaitReceiptRequest` is the first of its records.
//! These are local definitions; `memory::code_wait_doors` re-exports them.

#[doc(hidden)]
pub use oneiron_verb_wire::memory::code_wait_doors::types::{
    CodeWaitAnswerView, CodeWaitBrowserAction, CodeWaitChoice, CodeWaitConsumptionView,
    CodeWaitLedgerLinks, CodeWaitRebindPrepareRequest, CodeWaitRebindPrepared,
    CodeWaitRebindReceipt, CodeWaitRebindRequest, CodeWaitReceiptRequest, CodeWaitReceiptView,
    CodeWaitRememberScope, CodeWaitResolveRequest, CodeWaitSettleOutcome, CodeWaitSettlementView,
    CodeWaitState, CodeWaitTarget,
};
