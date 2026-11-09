//! Consent-wait choices, settlement outcomes and bound call identities.

#[doc(hidden)]
pub(crate) use oneiron_consent_state::consent::code_wait_state::CodeConsentCallSite;
#[doc(hidden)]
pub use oneiron_consent_state::consent::code_wait_state::{
    CodeConsentChoice, CodeConsentSettleOutcome, CodeConsentWaitState,
};

/// The reason a wait settles with when its original caller's own credential
/// no longer stands. No answer revives it.
pub(crate) const CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED: &str =
    "code_wait_original_authority_refused";
