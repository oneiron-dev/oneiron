//! Typed checkout custody calls. Holder identity and time come from the credential and vault.

#[doc(hidden)]
pub use oneiron_verb_wire::memory::checkout_doors::types::{
    CheckoutAction, CheckoutClaimInput, CheckoutClass, CheckoutGetInput, CheckoutLeaseView,
    CheckoutPublishInput, CheckoutPublished, CheckoutReclaimInput, CheckoutRenewInput,
    CheckoutRetention, CheckoutSettleInput, CheckoutSettled, CheckoutState, CheckoutTakeoverInput,
    CheckoutTeardownInput, CheckoutTornDown,
};
