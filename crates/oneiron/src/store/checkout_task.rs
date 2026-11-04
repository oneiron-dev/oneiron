//! Checkout task classes and their lease-reclaim policy.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutTaskClass {
    Edit,
    Build,
    Verify,
    Effect,
}
impl CheckoutTaskClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Edit => "edit",
            Self::Build => "build",
            Self::Verify => "verify",
            Self::Effect => "effect",
        }
    }
    pub const fn allows_ttl_reclaim(self) -> bool {
        matches!(self, Self::Build | Self::Verify)
    }
}
