#[derive(Clone, Copy)]
pub(crate) enum CheckoutTaskAccess {
    Claim,
    Holder,
    Reclaim,
    Takeover,
    Read,
}
