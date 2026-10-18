//! ChannelIdentity addressability shapes with wire serde.

/// ChannelIdentity addressability shape (OF-347 R1, ARCH-0063 R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ChannelIdentityShape {
    DedicatedAddress,
    DedicatedHandle,
    SharedPresence,
    /// A member/owner mailbox held under a scoped-read OAuth grant.
    ///
    /// The product never mints, owns, rotates, or quarantines the underlying
    /// account: it holds a custody record ref and reads. Routing, receipts,
    /// health claims, and manifests never special-case this shape.
    DelegatedGrant,
}

impl ChannelIdentityShape {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DedicatedAddress => "dedicated_address",
            Self::DedicatedHandle => "dedicated_handle",
            Self::SharedPresence => "shared_presence",
            Self::DelegatedGrant => "delegated_grant",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "dedicated_address" => Some(Self::DedicatedAddress),
            "dedicated_handle" => Some(Self::DedicatedHandle),
            "shared_presence" => Some(Self::SharedPresence),
            "delegated_grant" => Some(Self::DelegatedGrant),
            _ => None,
        }
    }

    /// Whether the product itself holds the underlying account.
    ///
    /// False only for [`Self::DelegatedGrant`], where the member's provider
    /// owns creation, rotation, and revocation.
    #[must_use]
    pub const fn is_self_held(self) -> bool {
        !matches!(self, Self::DelegatedGrant)
    }
}

/// The three shapes whose account the product actually holds.
///
/// This exists so that "a delegated grant asked for at a self-held door" has no
/// spelling. [`ChannelIdentity::requested`](crate::channel_identity::ChannelIdentity::requested) takes this type, and it has no
/// `DelegatedGrant` variant, so a caller cannot hand it a delegated shape for
/// the door to silently degrade — see that constructor for what the degrade
/// actually cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SelfHeldShape {
    DedicatedAddress,
    DedicatedHandle,
    SharedPresence,
}

impl SelfHeldShape {
    /// The wire shape this projects to.
    #[must_use]
    pub const fn shape(self) -> ChannelIdentityShape {
        match self {
            Self::DedicatedAddress => ChannelIdentityShape::DedicatedAddress,
            Self::DedicatedHandle => ChannelIdentityShape::DedicatedHandle,
            Self::SharedPresence => ChannelIdentityShape::SharedPresence,
        }
    }

    /// The self-held shape a wire shape names, if it names one.
    #[must_use]
    pub const fn from_shape(shape: ChannelIdentityShape) -> Option<Self> {
        match shape {
            ChannelIdentityShape::DedicatedAddress => Some(Self::DedicatedAddress),
            ChannelIdentityShape::DedicatedHandle => Some(Self::DedicatedHandle),
            ChannelIdentityShape::SharedPresence => Some(Self::SharedPresence),
            ChannelIdentityShape::DelegatedGrant => None,
        }
    }
}

