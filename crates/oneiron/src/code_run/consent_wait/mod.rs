//! Bound code consent waits (DOOR-079 1a, toward CODE-RUNTIME-03).
//!
//! A code-mode `connector.call` whose own gate holds it for consent alone
//! parks its run on a code consent wait, minted beside the held call in the
//! same writer. The wait binds the exact pending effect: its run and write
//! site, the frozen bytes' digest, the original caller and its instrument,
//! the governing key, grant and manifest. It asks the vault's owner one TASK
//! question with canon's confirm trio.
//!
//! The owner's answer is its own fact: authenticated from any surface the
//! owner is authenticated on, revalidated in the answering writer, bound to
//! the sealed wait, standing on the owner's own word on the ask, never from
//! the opener's lineage, first and once. The settlement is another: the
//! held effect runs once under its own current gate, with the answer's
//! code-bound one-shot approval and the original caller's own grant, and its
//! actual outcome settles the wait and wakes the run. The run's consumption
//! of that reply is the third: the step that parks seals the wait in its
//! replay commit, and the replay commit that takes the reply consumes it
//! once (1b, `replay.rs`).
//!
//! A browser act a press held binds the same way (FIX 10423, `browser.rs`):
//! its exact act, row, page and guest, settled by the served host's one
//! answered pass with the act's own answer.
//!
//! This module owns the control row; only it writes it.

mod binding;
mod browser;
mod host;
mod ledger;
mod replay;
mod settle;
mod types;

pub use self::browser::{AdmittedBrowserAct, CodeConsentBrowserOutcome};
pub(crate) use self::binding::{
    CodeConsentDraft, attach_code_consent_ask_in_txn, code_consent_binds,
    code_consent_binds_held_browser, code_consent_binds_held_call, code_consent_wait_id,
    code_consent_waits_bound_to_in_txn,
    mint_code_consent_wait_in_txn, read_code_consent_wait_in_txn,
    record_code_consent_admission_in_txn,
};
pub use self::host::CodeConsentEffectHost;
pub(crate) use self::replay::{
    CodeConsentResume, ParkedWait, code_consent_resume_evidence, consume_code_consent_wait_in_txn,
    seal_parked_code_consent_in_txn, verify_code_consent_consumed, verify_parked_code_consent,
};
pub(crate) use self::settle::{
    CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED, code_consent_admission_in_txn, offered_choices,
    original_authority_holds_in_txn, refuse_code_consent_wait_in_txn,
    settle_code_consent_wait_listing_in_txn,
};
pub use self::types::{
    CodeConsentAnswerInput, CodeConsentBrowserAction, CodeConsentChoice,
    CodeConsentSavedCredential, CodeConsentSettleOutcome, CodeConsentWaitState,
    CodeConsentWaitView,
};
pub(crate) use self::types::{
    CodeConsentCallSite, CodeConsentConnectorCall, CodeConsentPendingEffect, CodeConsentPrincipal,
    CodeConsentRememberOffer, CodeConsentWaitRow,
};
