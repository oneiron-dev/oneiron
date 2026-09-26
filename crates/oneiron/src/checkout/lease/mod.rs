mod codec;
mod lifecycle;
mod types;

pub use self::codec::checkout_result_identity;
// The typed `LEASE`/`TOMBSTONE`/`SETTLEMENT` side tables now own every non-test read/write in
// `lease/`, so these row/key builders have no non-test user inside `lease/` at all; the seam
// exposes them to `checkout::tests` only.
pub(crate) use self::codec::load_act_in_txn;
#[cfg(test)]
pub(super) use self::codec::{
    decode_act, decode_receipt, decode_tombstone, encode_act, encode_receipt, encode_tombstone,
    lease_key, settlement_key, tombstone_key,
};
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
