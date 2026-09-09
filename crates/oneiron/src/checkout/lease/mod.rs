mod codec;
mod lifecycle;
mod types;

pub use self::codec::checkout_result_identity;
// `encode_act` / `decode_tombstone` have no non-test user inside `lease/`; the seam
// exposes them to `checkout::tests` only.
pub(super) use self::codec::{
    decode_act, decode_receipt, encode_receipt, encode_tombstone, tombstone_key,
};
#[cfg(test)]
pub(super) use self::codec::{decode_tombstone, encode_act};
pub(crate) use self::codec::{lease_key, settlement_key};
pub use self::lifecycle::CheckoutLeaseService;
pub use self::types::{
    CHECKOUT_LEASE_KEY_PREFIX, CHECKOUT_LEASE_SCHEMA_VERSION, CHECKOUT_RESULT_ID_DOMAIN,
    CHECKOUT_SETTLEMENT_KEY_PREFIX, CHECKOUT_TOMBSTONE_KEY_PREFIX, CheckoutClaimRequest,
    CheckoutError, CheckoutFactMutation, CheckoutFactSink, CheckoutHolder, CheckoutId,
    CheckoutLeaseAct, CheckoutLeaseFence, CheckoutLeaseGrant, CheckoutLeaseState, CheckoutLiveness,
    CheckoutLivenessPulse, CheckoutMaterializationOptions, CheckoutRepoOps, CheckoutResult,
    CheckoutRetainReason, CheckoutSettlementDisposition, CheckoutSettlementReceipt,
    CheckoutSettlementRequest, CheckoutTaskClass, CheckoutTeardownInspection,
    CheckoutTeardownOutcome, GitOid, PushedHeadReceipt, TeardownReceiptMatch,
};
