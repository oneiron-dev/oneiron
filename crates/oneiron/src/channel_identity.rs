//! ChannelIdentity record substrate (OF-347 CID-1).
//!
//! A ChannelIdentity is a vault-resident engine record plus a typed
//! `channel_identity.*` claim family. Provisioning verbs, provider adapters,
//! reputation scoring, and manifest contents are intentionally outside this
//! module; CID-1 pins the primitive shape and lifecycle invariants only.
//!
//! Two things live beside the record because they are properties OF the record
//! rather than of whichever adapter last touched it:
//!
//! - [`address`] — the channel key and the assignment address are VALUES,
//!   normalized once at construction, and [`AssignmentKey`] is the single
//!   canonical inhabitant every uniqueness road compares.
//! - [`custody`] — a `delegated_grant` row is a mailbox the product never
//!   minted. What makes such a row true is a live custody record that NAMES
//!   THIS MAILBOX, so the proof carries the mailbox and only the engine can
//!   mint one.

use std::io::Cursor;

use rmpv::Value;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Vault;
use crate::batch::BatchOp;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::apply_ops;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, MAX_PREDICATE_BYTES,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::entity_id_from_type_index_key;

mod address;
mod custody;

pub use address::{
    AssignmentAddress, AssignmentKey, ChannelKey, MailboxAddr, normalize_email_domain,
};
pub use custody::{
    DelegatedCustodyProof, DelegatedGrant, DelegatedGrantScope, delegated_custody_effector,
    delegated_custody_scopes, delegated_custody_subject_scope,
};

use custody::verify_delegated_custody_in_txn;

/// Pre-INB-06 self-held body schema version. DECODE ONLY.
///
/// A stored row at this version carries the twelve legacy keys and a
/// `binding_scope` of `agent`; it decodes to
/// [`ChannelIdentityBinding::Actor`] with no facet. Nothing writes it again.
pub const CHANNEL_IDENTITY_LEGACY_SCHEMA_VERSION: u64 = 1;

/// Pre-INB-06 `delegated_grant` body schema version (INB-00). DECODE ONLY.
pub const CHANNEL_IDENTITY_LEGACY_DELEGATED_SCHEMA_VERSION: u64 = 2;

/// Current ChannelIdentity body schema version for the three self-held shapes.
///
/// INB-06 bumped this off `1`. The binding is now an ACTOR reference that may
/// wear a facet mask on this channel, so every row carries a thirteenth
/// `binding_facet_ref` key and spells its scope `actor`. Neither is
/// expressible in the v1 key set, and a body must never be ambiguous about
/// which set it holds, so the version moves rather than the key set growing
/// optional holes.
///
/// Back-compat is a DECODE contract, not a byte contract: every v1/v2 row on
/// disk still decodes (see [`CHANNEL_IDENTITY_LEGACY_SCHEMA_VERSION`]), and a
/// rewrite re-emits it in this canonical encoding.
pub const CHANNEL_IDENTITY_SCHEMA_VERSION: u64 = 3;

/// ChannelIdentity body schema version for `delegated_grant` rows.
///
/// Only the fourth shape uses it. The version is what selects the pinned key
/// set at decode, so the shapes' key sets can never be mixed.
pub const CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION: u64 = 4;

/// Minimum self-hold window for a quarantined released identity (90 days).
pub const CHANNEL_IDENTITY_MIN_QUARANTINE_SECS: u64 = 90 * 24 * 60 * 60;

/// Pinned pre-INB-06 self-held key set. DECODE ONLY.
///
/// Spelled as literals, never derived from the live set: this is the shape of
/// rows already on disk, so it must not follow a future edit to the canonical
/// key list.
pub const CHANNEL_IDENTITY_LEGACY_BODY_KEYS: [&str; 12] = [
    "schema_version",
    "channel",
    "address_or_handle",
    "shape",
    "binding_scope",
    "binding_target",
    "state",
    "pending_fulfillment",
    "state_changed_at",
    "quarantine_until",
    "reputation_ref",
    "manifest_ref",
];

/// Pinned pre-INB-06 `delegated_grant` key set. DECODE ONLY.
pub const CHANNEL_IDENTITY_LEGACY_DELEGATED_BODY_KEYS: [&str; 14] = [
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[0],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[1],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[2],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[3],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[4],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[5],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[6],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[7],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[8],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[9],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[10],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[11],
    "delegated_grant_ref",
    "grant_scopes",
];

/// Pinned on-disk MessagePack key set for ChannelIdentity bodies.
///
/// The twelve legacy keys in the same order, then `binding_facet_ref` — the
/// mask this identity wears on this channel, `nil` when the actor speaks
/// unmasked.
pub const CHANNEL_IDENTITY_BODY_KEYS: [&str; 13] = [
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[0],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[1],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[2],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[3],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[4],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[5],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[6],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[7],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[8],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[9],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[10],
    CHANNEL_IDENTITY_LEGACY_BODY_KEYS[11],
    "binding_facet_ref",
];

/// Pinned on-disk MessagePack key set for `delegated_grant` bodies.
///
/// The thirteen self-held keys in the same order, then the two custody keys.
/// `delegated_grant_ref` is a custody record NAME; no token bytes are ever
/// written here.
pub const CHANNEL_IDENTITY_DELEGATED_BODY_KEYS: [&str; 15] = [
    CHANNEL_IDENTITY_BODY_KEYS[0],
    CHANNEL_IDENTITY_BODY_KEYS[1],
    CHANNEL_IDENTITY_BODY_KEYS[2],
    CHANNEL_IDENTITY_BODY_KEYS[3],
    CHANNEL_IDENTITY_BODY_KEYS[4],
    CHANNEL_IDENTITY_BODY_KEYS[5],
    CHANNEL_IDENTITY_BODY_KEYS[6],
    CHANNEL_IDENTITY_BODY_KEYS[7],
    CHANNEL_IDENTITY_BODY_KEYS[8],
    CHANNEL_IDENTITY_BODY_KEYS[9],
    CHANNEL_IDENTITY_BODY_KEYS[10],
    CHANNEL_IDENTITY_BODY_KEYS[11],
    CHANNEL_IDENTITY_BODY_KEYS[12],
    CHANNEL_IDENTITY_LEGACY_DELEGATED_BODY_KEYS[12],
    CHANNEL_IDENTITY_LEGACY_DELEGATED_BODY_KEYS[13],
];

const KEY_SCHEMA_VERSION: &str = CHANNEL_IDENTITY_BODY_KEYS[0];
const KEY_CHANNEL: &str = CHANNEL_IDENTITY_BODY_KEYS[1];
const KEY_ADDRESS_OR_HANDLE: &str = CHANNEL_IDENTITY_BODY_KEYS[2];
const KEY_SHAPE: &str = CHANNEL_IDENTITY_BODY_KEYS[3];
const KEY_BINDING_SCOPE: &str = CHANNEL_IDENTITY_BODY_KEYS[4];
const KEY_BINDING_TARGET: &str = CHANNEL_IDENTITY_BODY_KEYS[5];
const KEY_STATE: &str = CHANNEL_IDENTITY_BODY_KEYS[6];
const KEY_PENDING_FULFILLMENT: &str = CHANNEL_IDENTITY_BODY_KEYS[7];
const KEY_STATE_CHANGED_AT: &str = CHANNEL_IDENTITY_BODY_KEYS[8];
const KEY_QUARANTINE_UNTIL: &str = CHANNEL_IDENTITY_BODY_KEYS[9];
const KEY_REPUTATION_REF: &str = CHANNEL_IDENTITY_BODY_KEYS[10];
const KEY_MANIFEST_REF: &str = CHANNEL_IDENTITY_BODY_KEYS[11];
/// Optional channel facet key in the canonical body.
pub const KEY_BINDING_FACET_REF: &str = CHANNEL_IDENTITY_BODY_KEYS[12];
const KEY_DELEGATED_GRANT_REF: &str = CHANNEL_IDENTITY_DELEGATED_BODY_KEYS[13];
const KEY_GRANT_SCOPES: &str = CHANNEL_IDENTITY_DELEGATED_BODY_KEYS[14];

/// Pinned `channel_identity.*` claim predicates for the CID-1 record fields.
pub const CHANNEL_IDENTITY_CLAIM_PREDICATES: [&str; 12] = [
    PREDICATE_CHANNEL_IDENTITY_CHANNEL,
    PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE,
    PREDICATE_CHANNEL_IDENTITY_SHAPE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET,
    PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF,
    PREDICATE_CHANNEL_IDENTITY_STATE,
    PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT,
    PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT,
    PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL,
    PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF,
    PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF,
];

pub const PREDICATE_CHANNEL_IDENTITY_CHANNEL: &str = "channel_identity.channel";
pub const PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE: &str = "channel_identity.address_or_handle";
pub const PREDICATE_CHANNEL_IDENTITY_SHAPE: &str = "channel_identity.shape";
pub const PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE: &str = "channel_identity.binding_scope";
pub const PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET: &str = "channel_identity.binding_target";
/// Facet mask this identity wears on its channel; `nil` when unmasked.
pub const PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF: &str = "channel_identity.binding_facet_ref";
pub const PREDICATE_CHANNEL_IDENTITY_STATE: &str = "channel_identity.state";
pub const PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT: &str =
    "channel_identity.pending_fulfillment";
pub const PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT: &str = "channel_identity.state_changed_at";
pub const PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL: &str = "channel_identity.quarantine_until";
pub const PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF: &str = "channel_identity.reputation_ref";
pub const PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF: &str = "channel_identity.manifest_ref";

const MAX_CHANNEL_BYTES: usize = 64;
const MAX_ADDRESS_OR_HANDLE_BYTES: usize = 512;

/// ChannelIdentity addressability shape (OF-347 R1, ARCH-0063 R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
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
/// spelling. [`ChannelIdentity::requested`] takes this type, and it has no
/// `DelegatedGrant` variant, so a caller cannot hand it a delegated shape for
/// the door to silently degrade — see that constructor for what the degrade
/// actually cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
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

impl Serialize for ChannelIdentityShape {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ChannelIdentityShape {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).ok_or_else(|| {
            serde::de::Error::custom(format!("unknown channel identity shape {value:?}"))
        })
    }
}

/// Scope at which an identity is bound (OF-347 R2, ARCH-0063 R7).
///
/// [`Self::Actor`] names an AUTHORITY-BEARING ENTITY, not a new entity kind:
/// a named agent is normally an `AGENT_DEF`, and a connector/plumbing actor
/// keeps whatever reference it already had. Whether a someone stands behind
/// that actor is a SEPARATE question answered by an `actor.subject_ref`
/// anchor (see [`crate::subject_model`]) — never by the binding, and never by
/// forking the entity kind.
///
/// `facet_ref` is owned HERE rather than on the connector key record because
/// the facet is the mask worn ON THIS CHANNEL: one actor speaks through many
/// identities and may wear a different face on each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityBinding {
    Actor {
        actor_ref: EntityId,
        /// Type-13 FACET mask worn on this channel; `None` speaks unmasked.
        facet_ref: Option<EntityId>,
    },
    Vault {
        vault_id: u64,
    },
}

impl ChannelIdentityBinding {
    /// Binds an unmasked actor.
    #[must_use]
    pub const fn actor(actor_ref: EntityId) -> Self {
        Self::Actor {
            actor_ref,
            facet_ref: None,
        }
    }

    /// Binds an actor wearing `facet_ref` on this channel.
    #[must_use]
    pub const fn actor_with_facet(actor_ref: EntityId, facet_ref: EntityId) -> Self {
        Self::Actor {
            actor_ref,
            facet_ref: Some(facet_ref),
        }
    }

    /// Pre-INB-06 spelling of [`Self::actor`], kept because "the agent bound
    /// to this identity" is exactly an unmasked actor — the rename did not
    /// change what any existing caller meant.
    #[must_use]
    pub const fn agent(agent_ref: EntityId) -> Self {
        Self::actor(agent_ref)
    }

    #[must_use]
    pub const fn vault(vault_id: u64) -> Self {
        Self::Vault { vault_id }
    }

    /// Actor this identity speaks for, when it is actor-bound.
    #[must_use]
    pub const fn actor_ref(self) -> Option<EntityId> {
        match self {
            Self::Actor { actor_ref, .. } => Some(actor_ref),
            Self::Vault { .. } => None,
        }
    }

    /// Facet mask worn on this channel, when one is bound.
    #[must_use]
    pub const fn facet_ref(self) -> Option<EntityId> {
        match self {
            Self::Actor { facet_ref, .. } => facet_ref,
            Self::Vault { .. } => None,
        }
    }

    #[must_use]
    pub const fn scope_str(self) -> &'static str {
        match self {
            Self::Actor { .. } => "actor",
            Self::Vault { .. } => "vault",
        }
    }

    fn validate(self) -> Result<()> {
        match self {
            Self::Actor { .. } => Ok(()),
            Self::Vault { vault_id: 0 } => Err(invalid_identity()),
            Self::Vault { .. } => Ok(()),
        }
    }
}

/// Async fulfillment lane for PENDING_FULFILLMENT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityFulfillment {
    Api,
    Manual,
    Review,
}

impl ChannelIdentityFulfillment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Manual => "manual",
            Self::Review => "review",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "api" => Some(Self::Api),
            "manual" => Some(Self::Manual),
            "review" => Some(Self::Review),
            _ => None,
        }
    }
}

/// ChannelIdentity lifecycle state (OF-347 R3/R5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityState {
    Requested,
    PendingFulfillment,
    Active,
    Rotating,
    Released,
    Quarantine,
    Tombstone,
}

impl ChannelIdentityState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::PendingFulfillment => "pending_fulfillment",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Released => "released",
            Self::Quarantine => "quarantine",
            Self::Tombstone => "tombstone",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "requested" => Some(Self::Requested),
            "pending_fulfillment" => Some(Self::PendingFulfillment),
            "active" => Some(Self::Active),
            "rotating" => Some(Self::Rotating),
            "released" => Some(Self::Released),
            "quarantine" => Some(Self::Quarantine),
            "tombstone" => Some(Self::Tombstone),
            _ => None,
        }
    }

    /// The SELF-HELD edge table: an account the product minted and can rotate,
    /// release, and hold out of recycling for its quarantine window.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Requested, Self::PendingFulfillment)
                | (Self::PendingFulfillment, Self::Active)
                | (Self::Active, Self::Rotating)
                | (Self::Rotating, Self::Active)
                | (Self::Active, Self::Released)
                | (Self::Rotating, Self::Released)
                | (Self::Released, Self::Quarantine)
                | (Self::Quarantine, Self::Tombstone)
        )
    }

    /// The DELEGATED edge table, for a mailbox the product never minted.
    ///
    /// Two states of the self-held table are absent, and their absence is the
    /// enforcement rather than a predicate somewhere else: ROTATING (re-minting
    /// an account we never owned) and QUARANTINE (taking a never-recycle hold
    /// on someone else's mailbox). Retirement is `Active -> Released ->
    /// Tombstone`, and both retirement stops free the assignment key, because
    /// the mailbox was never ours to hold back — closing the row out must never
    /// be the act that locks a member out of re-consenting.
    #[must_use]
    pub const fn can_transition_to_delegated(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Requested, Self::PendingFulfillment)
                | (Self::PendingFulfillment, Self::Active)
                | (Self::Active, Self::Released)
                | (Self::Released, Self::Tombstone)
        )
    }

    /// Whether a `delegated_grant` row in this state asserts a LIVE grant over
    /// the member's mailbox.
    ///
    /// True for every state that claims we can still read it, false once the
    /// row is retiring — which is exactly when custody may no longer be
    /// provable, and must not be required to be.
    #[must_use]
    pub const fn asserts_delegated_custody(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::PendingFulfillment | Self::Active
        )
    }
}

/// Vault-resident ChannelIdentity record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentity {
    pub channel: String,
    pub address_or_handle: String,
    pub shape: ChannelIdentityShape,
    pub binding: ChannelIdentityBinding,
    pub state: ChannelIdentityState,
    pub pending_fulfillment: Option<ChannelIdentityFulfillment>,
    pub state_changed_at: u64,
    pub quarantine_until: Option<u64>,
    pub reputation_ref: Option<EntityId>,
    pub manifest_ref: Option<EntityId>,
    /// Present exactly when `shape` is [`ChannelIdentityShape::DelegatedGrant`].
    ///
    /// The one-to-one tie is enforced by [`ChannelIdentity::validate`], so a
    /// delegated row without custody, or a self-held row carrying custody,
    /// cannot be built, encoded, or decoded.
    pub grant: Option<DelegatedGrant>,
}

impl ChannelIdentity {
    /// Constructs a requested SELF-HELD identity row before provider
    /// fulfillment starts.
    ///
    /// The channel and address are normalized HERE, once, so two spellings of
    /// one mailbox cannot become two assignment keys with two occupants.
    ///
    /// The shape parameter is [`SelfHeldShape`], not the wire
    /// [`ChannelIdentityShape`], and that is the whole of ONE-1825's third
    /// root. A door that took the wire enum would have to answer for
    /// `DelegatedGrant`, and every available answer is wrong: mapping it onto a
    /// self-held shape hands a caller who asked for a read-only member-held
    /// mailbox a PRODUCT-OWNED, send-capable row instead (see [`Self::may_send`]
    /// — every self-held shape may send once Active, a delegated row never
    /// does), and silence makes that escalation invisible. Refusing at runtime
    /// is not available either: this signature is infallible and `#[must_use]`,
    /// and a `panic!` is not a product-code refusal.
    ///
    /// So the misuse is made UNSPELLABLE instead. `SelfHeldShape` has no
    /// `DelegatedGrant` variant, so there is no argument left that would need
    /// degrading. [`Self::requested_delegated`] — behind
    /// [`Vault::provision_delegated_identity`], which mints a real custody
    /// proof — is the only delegated door.
    #[must_use]
    pub fn requested(
        channel: impl AsRef<str>,
        address_or_handle: impl AsRef<str>,
        shape: SelfHeldShape,
        binding: ChannelIdentityBinding,
        requested_at: u64,
    ) -> Self {
        let channel = channel.as_ref();
        Self {
            address_or_handle: AssignmentAddress::normalize(channel, address_or_handle.as_ref())
                .as_str()
                .to_owned(),
            channel: ChannelKey::normalize(channel).as_str().to_owned(),
            shape: shape.shape(),
            binding,
            state: ChannelIdentityState::Requested,
            pending_fulfillment: None,
            state_changed_at: requested_at,
            quarantine_until: None,
            reputation_ref: None,
            manifest_ref: None,
            grant: None,
        }
    }

    /// Constructs a requested `delegated_grant` row over a member-held mailbox.
    ///
    /// `grant` names an already-granted custody record; this constructor does
    /// not mint, rotate, or read it. It also does not TAKE the caller's word
    /// that the grant exists: `custody` is a [`DelegatedCustodyProof`], which
    /// only the engine's verification door can mint, and it must cover this
    /// exact `(channel, address, custody record)` TRIPLE. A caller holding a
    /// proof for another member's mailbox is refused here rather than at one
    /// adapter.
    ///
    /// The row is born `Requested`, always. Custody is a local fact, consent is
    /// a local fact, and the BINDING is chosen by the local actor that
    /// consented; `Active` asserts all three already happened. Every later
    /// delegated state is therefore reachable only as a checked step from a row
    /// that already exists.
    ///
    /// `pub(crate)`: the proof borrows a transaction, so the only sound public
    /// spelling is an engine door that mints and consumes it in one txn —
    /// [`Vault::provision_delegated_identity`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidChannelIdentityBody`] when the proof does not cover the
    /// triple, or when the row fails the record's bounds checks.
    pub(crate) fn requested_delegated(
        channel: impl AsRef<str>,
        address_or_handle: impl AsRef<str>,
        binding: ChannelIdentityBinding,
        grant: DelegatedGrant,
        custody: &DelegatedCustodyProof<'_>,
        requested_at: u64,
    ) -> Result<Self> {
        let channel_key = ChannelKey::normalize(channel.as_ref());
        let address = AssignmentAddress::normalize(channel.as_ref(), address_or_handle.as_ref());
        if !custody.covers(channel_key.as_str(), address.as_str(), &grant) {
            return Err(Error::InvalidChannelIdentityBody(
                "delegated_grant identity requires a verified custody proof for its own \
                 (channel, mailbox, grant)",
            ));
        }
        let identity = Self {
            channel: channel_key.as_str().to_owned(),
            address_or_handle: address.as_str().to_owned(),
            shape: ChannelIdentityShape::DelegatedGrant,
            binding,
            state: ChannelIdentityState::Requested,
            pending_fulfillment: None,
            state_changed_at: requested_at,
            quarantine_until: None,
            reputation_ref: None,
            manifest_ref: None,
            grant: Some(grant),
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Constructs the pre-provisioned own-app home-channel identity for an agent.
    #[must_use]
    pub fn own_app_home(agent_ref: EntityId, created_at: u64) -> Self {
        Self {
            channel: "own_app".to_owned(),
            address_or_handle: format!("own_app:{}", agent_ref.to_hex()),
            shape: ChannelIdentityShape::DedicatedHandle,
            binding: ChannelIdentityBinding::agent(agent_ref),
            state: ChannelIdentityState::Active,
            pending_fulfillment: None,
            state_changed_at: created_at,
            quarantine_until: None,
            reputation_ref: None,
            manifest_ref: None,
            grant: None,
        }
    }

    /// Returns the uniqueness key used for never-recycle enforcement.
    ///
    /// DERIVED, not stored. Returning the stored pair verbatim meant a row
    /// decoded from disk — replay, rebuild, any body an older or third-party
    /// writer produced — was compared under whatever spelling was on disk,
    /// while another road normalized. Computing the key from the stored bytes
    /// makes every road agree by construction.
    ///
    /// The ROW is never rewritten: `self.channel` and `self.address_or_handle`
    /// keep the exact bytes the decoder read, so the codec's
    /// `encode(decode(bytes)) == bytes` pin is untouched. Only the KEY is
    /// canonical.
    #[must_use]
    pub fn assignment_key(&self) -> AssignmentKey {
        AssignmentKey::of(&self.channel, &self.address_or_handle)
    }

    /// Whether this row is a member-held mailbox under a scoped-read grant.
    #[must_use]
    pub const fn is_delegated(&self) -> bool {
        !self.shape.is_self_held()
    }

    /// Whether this row still OCCUPIES its assignment key.
    ///
    /// A self-held row occupies it forever: never-recycle is the whole point of
    /// releasing an address WE minted, so a quarantined or tombstoned row is
    /// still holding it back. A delegated row is the opposite case — the
    /// mailbox was never ours, so once the row is retiring we hold no claim on
    /// it at all, and lawful re-consent stays open after the close.
    #[must_use]
    pub const fn occupies_assignment_key(&self) -> bool {
        if self.is_delegated() {
            !matches!(
                self.state,
                ChannelIdentityState::Released | ChannelIdentityState::Tombstone
            )
        } else {
            true
        }
    }

    /// Whether this row may carry an OUTBOUND effect.
    ///
    /// Self-held and `Active`, and nothing else. A delegated row is a
    /// scoped-READ grant over a mailbox the product does not own; there is no
    /// state it can reach in which sending as the member is a thing we were
    /// given permission to do.
    #[must_use]
    pub const fn may_send(&self) -> bool {
        !self.is_delegated() && matches!(self.state, ChannelIdentityState::Active)
    }

    /// Validates CID-1 record invariants.
    pub fn validate(&self) -> Result<()> {
        validate_non_empty_bounded(
            &self.channel,
            MAX_CHANNEL_BYTES,
            "channel must be non-empty and at most 64 bytes",
        )?;
        validate_non_empty_bounded(
            &self.address_or_handle,
            MAX_ADDRESS_OR_HANDLE_BYTES,
            "address_or_handle must be non-empty and at most 512 bytes",
        )?;
        self.binding.validate()?;
        self.validate_custody()?;
        match self.state {
            ChannelIdentityState::PendingFulfillment => {
                if self.pending_fulfillment.is_none() {
                    return Err(invalid_identity());
                }
                if self.quarantine_until.is_some() {
                    return Err(invalid_identity());
                }
            }
            ChannelIdentityState::Quarantine => {
                if self.pending_fulfillment.is_some() {
                    return Err(invalid_identity());
                }
                let quarantine_until = self.quarantine_until.ok_or_else(invalid_identity)?;
                let min_until = self
                    .state_changed_at
                    .checked_add(CHANNEL_IDENTITY_MIN_QUARANTINE_SECS)
                    .ok_or(Error::ArithmeticOverflow(
                        "channel identity quarantine window",
                    ))?;
                if quarantine_until < min_until {
                    return Err(invalid_identity());
                }
            }
            _ => {
                if self.pending_fulfillment.is_some() || self.quarantine_until.is_some() {
                    return Err(invalid_identity());
                }
            }
        }
        Ok(())
    }

    /// The shape/grant tie, and the two states a delegated row has no business
    /// being in.
    ///
    /// `ROTATING` would be re-minting an account the product never owned;
    /// `QUARANTINE` would be a never-recycle hold on someone else's mailbox.
    /// Both are absent from [`ChannelIdentityState::can_transition_to_delegated`]
    /// so no lawful step reaches them, and refused here so no assembled or
    /// decoded body can claim one either.
    fn validate_custody(&self) -> Result<()> {
        match (self.shape.is_self_held(), &self.grant) {
            (true, None) => Ok(()),
            (false, Some(grant)) => {
                grant.validate()?;
                if matches!(
                    self.state,
                    ChannelIdentityState::Rotating | ChannelIdentityState::Quarantine
                ) {
                    return Err(Error::InvalidChannelIdentityBody(
                        "a delegated_grant identity is never rotated or quarantined: the \
                         product neither mints nor holds back the member's mailbox",
                    ));
                }
                Ok(())
            }
            (true, Some(_)) => Err(Error::InvalidChannelIdentityBody(
                "only a delegated_grant identity may carry a delegated grant ref",
            )),
            (false, None) => Err(Error::InvalidChannelIdentityBody(
                "delegated_grant identity requires a delegated grant ref",
            )),
        }
    }

    /// Returns a copy with a checked lifecycle transition applied.
    pub fn transition(
        &self,
        next: ChannelIdentityState,
        pending_fulfillment: Option<ChannelIdentityFulfillment>,
        state_changed_at: u64,
        quarantine_until: Option<u64>,
    ) -> Result<Self> {
        let admitted = if self.is_delegated() {
            self.state.can_transition_to_delegated(next)
        } else {
            self.state.can_transition_to(next)
        };
        if !admitted {
            return Err(invalid_identity());
        }
        if state_changed_at < self.state_changed_at {
            return Err(invalid_identity());
        }
        let next_identity = Self {
            state: next,
            pending_fulfillment,
            state_changed_at,
            quarantine_until,
            ..self.clone()
        };
        next_identity.validate()?;
        Ok(next_identity)
    }

    /// Builds typed `channel_identity.*` claim bodies for this record.
    #[must_use]
    pub fn claim_bodies(&self, identity_id: EntityId) -> Vec<ClaimBody> {
        CHANNEL_IDENTITY_CLAIM_PREDICATES
            .iter()
            .map(|predicate| {
                ClaimBody::new(
                    *predicate,
                    ClaimSubject::Entity(identity_id),
                    self.claim_value(predicate)
                        .expect("predicate drawn from channel identity family"),
                    1.0,
                    ClaimApprovalStatus::Auto,
                    ClaimLifecycleStatus::Active,
                )
            })
            .collect()
    }

    fn claim_value(&self, predicate: &str) -> Option<Value> {
        match predicate {
            PREDICATE_CHANNEL_IDENTITY_CHANNEL => Some(Value::from(self.channel.as_str())),
            PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE => {
                Some(Value::from(self.address_or_handle.as_str()))
            }
            PREDICATE_CHANNEL_IDENTITY_SHAPE => Some(Value::from(self.shape.as_str())),
            PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE => Some(Value::from(self.binding.scope_str())),
            PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET => Some(encode_binding_target(self.binding)),
            PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF => {
                Some(encode_optional_entity_ref(self.binding.facet_ref()))
            }
            PREDICATE_CHANNEL_IDENTITY_STATE => Some(Value::from(self.state.as_str())),
            PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT => Some(
                self.pending_fulfillment
                    .map_or(Value::Nil, |fulfillment| Value::from(fulfillment.as_str())),
            ),
            PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT => Some(Value::from(self.state_changed_at)),
            PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL => {
                Some(self.quarantine_until.map_or(Value::Nil, Value::from))
            }
            PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF => {
                Some(encode_optional_entity_ref(self.reputation_ref))
            }
            PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF => {
                Some(encode_optional_entity_ref(self.manifest_ref))
            }
            _ => None,
        }
    }
}

/// Encodes a ChannelIdentity body in canonical MessagePack field order.
///
/// A self-held row encodes the thirteen pinned keys at
/// [`CHANNEL_IDENTITY_SCHEMA_VERSION`]. Only a `delegated_grant` row appends
/// the two custody keys and stamps
/// [`CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION`].
///
/// There is exactly ONE canonical encoding: a row decoded from a legacy v1/v2
/// body re-emits here at the current version, which is what "rewrite
/// canonicalizes" means. Reading never rewrites.
pub fn encode_channel_identity_body(identity: &ChannelIdentity) -> Result<Vec<u8>> {
    identity.validate()?;
    let mut entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(body_schema_version(identity)),
        ),
        (
            Value::from(KEY_CHANNEL),
            Value::from(identity.channel.as_str()),
        ),
        (
            Value::from(KEY_ADDRESS_OR_HANDLE),
            Value::from(identity.address_or_handle.as_str()),
        ),
        (Value::from(KEY_SHAPE), Value::from(identity.shape.as_str())),
        (
            Value::from(KEY_BINDING_SCOPE),
            Value::from(identity.binding.scope_str()),
        ),
        (
            Value::from(KEY_BINDING_TARGET),
            encode_binding_target(identity.binding),
        ),
        (Value::from(KEY_STATE), Value::from(identity.state.as_str())),
        (
            Value::from(KEY_PENDING_FULFILLMENT),
            identity
                .pending_fulfillment
                .map_or(Value::Nil, |fulfillment| Value::from(fulfillment.as_str())),
        ),
        (
            Value::from(KEY_STATE_CHANGED_AT),
            Value::from(identity.state_changed_at),
        ),
        (
            Value::from(KEY_QUARANTINE_UNTIL),
            identity.quarantine_until.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_REPUTATION_REF),
            encode_optional_entity_ref(identity.reputation_ref),
        ),
        (
            Value::from(KEY_MANIFEST_REF),
            encode_optional_entity_ref(identity.manifest_ref),
        ),
        (
            Value::from(KEY_BINDING_FACET_REF),
            encode_optional_entity_ref(identity.binding.facet_ref()),
        ),
    ];

    if let Some(grant) = &identity.grant {
        entries.push((
            Value::from(KEY_DELEGATED_GRANT_REF),
            Value::from(grant.custody_record_ref.as_str()),
        ));
        entries.push((
            Value::from(KEY_GRANT_SCOPES),
            Value::Array(
                grant
                    .scopes
                    .iter()
                    .map(|scope| Value::from(scope.as_str()))
                    .collect(),
            ),
        ));
    }

    encode_msgpack_value(
        &Value::Map(entries),
        "channel identity body MessagePack encode failed",
    )
}

const fn body_schema_version(identity: &ChannelIdentity) -> u64 {
    if identity.grant.is_some() {
        CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION
    } else {
        CHANNEL_IDENTITY_SCHEMA_VERSION
    }
}

/// Decodes and validates a ChannelIdentity body.
pub fn decode_channel_identity_body(bytes: &[u8]) -> Result<ChannelIdentity> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_identity())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_identity());
    }
    decode_channel_identity_value(&value)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_channel_identity_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_channel_identity_body(bytes).map(|_| ())
}

/// Returns whether `predicate` belongs to the ChannelIdentity claim family.
#[must_use]
pub fn is_channel_identity_claim_predicate(predicate: &str) -> bool {
    CHANNEL_IDENTITY_CLAIM_PREDICATES.contains(&predicate)
}

/// Validates one `channel_identity.*` claim body.
pub(crate) fn validate_channel_identity_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "channel_identity claim subject must be an entity",
        ));
    }
    if !is_channel_identity_claim_predicate(&body.predicate) {
        return Err(Error::InvalidClaimBody(
            "unknown channel_identity claim predicate",
        ));
    }
    if body.predicate.len() > MAX_PREDICATE_BYTES {
        return Err(Error::InvalidClaimBody(
            "channel_identity predicate exceeds max predicate bytes",
        ));
    }

    match body.predicate.as_str() {
        PREDICATE_CHANNEL_IDENTITY_CHANNEL => validate_claim_string(
            &body.value,
            MAX_CHANNEL_BYTES,
            "channel_identity.channel value must be non-empty string",
        ),
        PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE => validate_claim_string(
            &body.value,
            MAX_ADDRESS_OR_HANDLE_BYTES,
            "channel_identity.address_or_handle value must be non-empty string",
        ),
        PREDICATE_CHANNEL_IDENTITY_SHAPE => body
            .value
            .as_str()
            .and_then(ChannelIdentityShape::parse)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "channel_identity.shape value must be a pinned shape",
            )),
        // `agent` stays readable because rows written before INB-06 spelled the
        // actor scope that way; only `actor` is ever emitted now.
        PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE => match body.value.as_str() {
            Some("actor" | "agent" | "vault") => Ok(()),
            _ => Err(Error::InvalidClaimBody(
                "channel_identity.binding_scope value must be actor|vault",
            )),
        },
        PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET => validate_claim_binding_target(&body.value),
        PREDICATE_CHANNEL_IDENTITY_STATE => body
            .value
            .as_str()
            .and_then(ChannelIdentityState::parse)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "channel_identity.state value must be a pinned state",
            )),
        PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT => {
            if matches!(body.value, Value::Nil)
                || body
                    .value
                    .as_str()
                    .and_then(ChannelIdentityFulfillment::parse)
                    .is_some()
            {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "channel_identity.pending_fulfillment value must be nil|api|manual|review",
                ))
            }
        }
        PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT => {
            body.value
                .as_u64()
                .map(|_| ())
                .ok_or(Error::InvalidClaimBody(
                    "channel_identity.state_changed_at value must be u64",
                ))
        }
        PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL => {
            if matches!(body.value, Value::Nil) || body.value.as_u64().is_some() {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "channel_identity.quarantine_until value must be nil or u64",
                ))
            }
        }
        PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF
        | PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF
        | PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF => {
            if matches!(body.value, Value::Nil) || decode_entity_ref(&body.value).is_ok() {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "channel_identity ref claim value must be nil or entity hex",
                ))
            }
        }
        _ => unreachable!("predicate membership checked above"),
    }
}

fn decode_channel_identity_value(value: &Value) -> Result<ChannelIdentity> {
    let Value::Map(entries) = value else {
        return Err(invalid_identity());
    };
    // The version selects the pinned key set, so no two key sets can ever be
    // mixed: an unknown version, a self-held body carrying custody keys, and a
    // delegated body missing them all fail closed before any field is read.
    // The two legacy versions are decode-only and carry no facet key.
    let (delegated_grant, carries_facet_key) =
        match required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() {
            Some(CHANNEL_IDENTITY_LEGACY_SCHEMA_VERSION) => {
                validate_keys(entries, &CHANNEL_IDENTITY_LEGACY_BODY_KEYS)?;
                (None, false)
            }
            Some(CHANNEL_IDENTITY_LEGACY_DELEGATED_SCHEMA_VERSION) => {
                validate_keys(entries, &CHANNEL_IDENTITY_LEGACY_DELEGATED_BODY_KEYS)?;
                (Some(decode_delegated_grant(entries)?), false)
            }
            Some(CHANNEL_IDENTITY_SCHEMA_VERSION) => {
                validate_keys(entries, &CHANNEL_IDENTITY_BODY_KEYS)?;
                (None, true)
            }
            Some(CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION) => {
                validate_keys(entries, &CHANNEL_IDENTITY_DELEGATED_BODY_KEYS)?;
                (Some(decode_delegated_grant(entries)?), true)
            }
            _ => return Err(invalid_identity()),
        };

    let channel = required_string(entries, KEY_CHANNEL)?.to_owned();
    let address_or_handle = required_string(entries, KEY_ADDRESS_OR_HANDLE)?.to_owned();
    let shape = ChannelIdentityShape::parse(required_string(entries, KEY_SHAPE)?)
        .ok_or_else(invalid_identity)?;
    let binding_scope = required_string(entries, KEY_BINDING_SCOPE)?;
    let facet_ref = if carries_facet_key {
        decode_optional_entity_ref(required_value(entries, KEY_BINDING_FACET_REF)?)?
    } else {
        None
    };
    let binding = decode_binding(
        binding_scope,
        required_value(entries, KEY_BINDING_TARGET)?,
        facet_ref,
    )?;
    let state = ChannelIdentityState::parse(required_string(entries, KEY_STATE)?)
        .ok_or_else(invalid_identity)?;
    let pending_fulfillment_value = required_value(entries, KEY_PENDING_FULFILLMENT)?;
    let pending_fulfillment = if matches!(pending_fulfillment_value, Value::Nil) {
        None
    } else {
        Some(
            pending_fulfillment_value
                .as_str()
                .and_then(ChannelIdentityFulfillment::parse)
                .ok_or_else(invalid_identity)?,
        )
    };
    let state_changed_at = required_value(entries, KEY_STATE_CHANGED_AT)?
        .as_u64()
        .ok_or_else(invalid_identity)?;
    let quarantine_until_value = required_value(entries, KEY_QUARANTINE_UNTIL)?;
    let quarantine_until = if matches!(quarantine_until_value, Value::Nil) {
        None
    } else {
        Some(
            quarantine_until_value
                .as_u64()
                .ok_or_else(invalid_identity)?,
        )
    };
    let reputation_ref = decode_optional_entity_ref(required_value(entries, KEY_REPUTATION_REF)?)?;
    let manifest_ref = decode_optional_entity_ref(required_value(entries, KEY_MANIFEST_REF)?)?;

    let identity = ChannelIdentity {
        channel,
        address_or_handle,
        shape,
        binding,
        state,
        pending_fulfillment,
        state_changed_at,
        quarantine_until,
        reputation_ref,
        manifest_ref,
        grant: delegated_grant,
    };
    identity.validate()?;
    Ok(identity)
}

fn decode_delegated_grant(entries: &[(Value, Value)]) -> Result<DelegatedGrant> {
    let custody_record_ref = required_string(entries, KEY_DELEGATED_GRANT_REF)?.to_owned();
    let Value::Array(scopes) = required_value(entries, KEY_GRANT_SCOPES)? else {
        return Err(invalid_identity());
    };
    let scopes = scopes
        .iter()
        .map(|scope| {
            scope
                .as_str()
                .and_then(DelegatedGrantScope::parse)
                .ok_or_else(invalid_identity)
        })
        .collect::<Result<Vec<_>>>()?;
    let grant = DelegatedGrant {
        custody_record_ref,
        scopes,
    };
    grant.validate()?;
    Ok(grant)
}

fn encode_binding_target(binding: ChannelIdentityBinding) -> Value {
    match binding {
        ChannelIdentityBinding::Actor { actor_ref, .. } => Value::from(actor_ref.to_hex()),
        ChannelIdentityBinding::Vault { vault_id } => Value::from(vault_id),
    }
}

/// Decodes a binding, accepting the legacy `agent` scope as an unmasked actor.
///
/// `agent` is not a second live spelling: nothing emits it (see
/// [`ChannelIdentityBinding::scope_str`]), and a legacy body has no facet key
/// to disagree with, so the two scopes cannot drift apart. A `vault` row
/// carrying a facet is refused rather than silently dropping the mask.
fn decode_binding(
    scope: &str,
    target: &Value,
    facet_ref: Option<EntityId>,
) -> Result<ChannelIdentityBinding> {
    match scope {
        "actor" | "agent" => Ok(ChannelIdentityBinding::Actor {
            actor_ref: decode_entity_ref(target)?,
            facet_ref,
        }),
        "vault" if facet_ref.is_none() => target
            .as_u64()
            .map(ChannelIdentityBinding::vault)
            .ok_or_else(invalid_identity),
        _ => Err(invalid_identity()),
    }
}

fn validate_claim_binding_target(value: &Value) -> Result<()> {
    if decode_entity_ref(value).is_ok() {
        return Ok(());
    }
    match value.as_u64() {
        Some(0) => Err(Error::InvalidClaimBody(
            "channel_identity.binding_target vault id must be non-zero",
        )),
        Some(_) => Ok(()),
        None => Err(Error::InvalidClaimBody(
            "channel_identity.binding_target value must be entity hex or non-zero vault id",
        )),
    }
}

fn encode_optional_entity_ref(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::from(id.to_hex()))
}

fn decode_optional_entity_ref(value: &Value) -> Result<Option<EntityId>> {
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        decode_entity_ref(value).map(Some)
    }
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_identity)?;
    EntityId::from_hex(hex).map_err(|_| invalid_identity())
}

fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(invalid_identity)
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_identity)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_identity());
        };
        if seen[index] {
            return Err(invalid_identity());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_identity())
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_identity)
}

fn validate_non_empty_bounded(value: &str, max: usize, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max {
        Err(Error::InvalidChannelIdentityBody(reason))
    } else {
        Ok(())
    }
}

fn validate_claim_string(value: &Value, max: usize, reason: &'static str) -> Result<()> {
    let Some(value) = value.as_str() else {
        return Err(Error::InvalidClaimBody(reason));
    };
    if value.trim().is_empty() || value.len() > max {
        Err(Error::InvalidClaimBody(reason))
    } else {
        Ok(())
    }
}

fn encode_msgpack_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

fn invalid_identity() -> Error {
    Error::InvalidChannelIdentityBody("body failed validation")
}

/// What an adapter hands the delegated door: NAMES, never evidence.
///
/// There is deliberately no proof field and no way to add one. A
/// [`DelegatedCustodyProof`] borrows the transaction that read the custody
/// record, so a proof that reached a caller-owned struct would be a proof that
/// outlived its evidence. The door mints its own inside the write transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedProvisionRequest {
    /// Channel key; normalized by the door.
    pub channel: String,
    /// The member-held mailbox; normalized by the door.
    pub address_or_handle: String,
    /// Which agent (or vault) the mailbox routes to. Chosen by a LOCAL actor.
    pub binding: ChannelIdentityBinding,
    /// The custody record NAME plus the read scopes it covers.
    pub grant: DelegatedGrant,
}

/// WHICH WRITE this is.
///
/// A door that takes a BODY — one incoming row, with no view of what stood at
/// `id` before it — has to guess the rest, and the guesses are exactly where a
/// re-keyed row looks like a fresh one and a crafted ACTIVE delegated body
/// looks like a lawfully stepped one. These two shapes are the only ways a
/// stored CHANNEL_IDENTITY row changes, and each is produced by a road that
/// ALREADY HOLDS the facts it needs: the creating door knows the id was empty,
/// the stepping door read the prior row in its own transaction.
#[derive(Debug, Clone, Copy)]
pub(crate) enum IdentityTransition<'a> {
    /// No CHANNEL_IDENTITY row stood at this id: the key is being claimed.
    Birth { next: &'a ChannelIdentity },
    /// A stored row moves. `prior` is what this transaction read at `id`.
    Step {
        prior: &'a ChannelIdentity,
        next: &'a ChannelIdentity,
    },
}

impl IdentityTransition<'_> {
    const fn next(&self) -> &ChannelIdentity {
        match self {
            Self::Birth { next } | Self::Step { next, .. } => next,
        }
    }
}

/// Admits a ChannelIdentity TRANSITION arriving at the store.
///
/// Every typed CID writer converges here, before its bytes are handed to the
/// batch funnel, and three laws are stated once rather than re-derived per
/// writer.
///
/// **B — a delegated row is BORN `Requested`.** Custody is a local fact,
/// consent is a local fact, and the BINDING is chosen by the local actor that
/// consented; `Active` claims all three already happened. A body that arrives
/// ACTIVE at a birth asserts them without any of them having occurred — no
/// provision decision, no bind edge, no fulfillment, no receipt. Every later
/// delegated state is reachable only as a checked step from a row that exists.
/// Self-held births in stepped states stay admitted: a self-held row asserts no
/// external fact, and `own_app_home` births ACTIVE on purpose.
///
/// **K — a stored row's assignment key is immutable across a step.** The key is
/// the mailbox the row was provisioned for; moving it would leave the key it
/// used to hold naming a row that is no longer there while another key gains a
/// second occupant.
///
/// **U — one occupant per key.** Uniqueness compares [`AssignmentKey`], not the
/// stored spellings, and it asks [`ChannelIdentity::occupies_assignment_key`]
/// rather than "does a row exist": a self-held row holds its address forever
/// (never-recycle), while a retired DELEGATED row holds nothing, because the
/// mailbox was never ours to hold back.
///
/// **C — custody is re-proved in THIS transaction for a live delegated row.**
/// The proof a constructor consumed was minted in the read transaction that
/// preceded the write, so a grant revoked in between would otherwise stand up a
/// row that claims a mailbox this device can no longer read. The wall is kept
/// exactly for the states that assert a live grant
/// ([`ChannelIdentityState::asserts_delegated_custody`]); the retirement lane is
/// deliberately exempt, because retirement after a member revokes is precisely
/// when custody can no longer be proved and must stay possible.
///
/// # Errors
///
/// [`Error::InvalidChannelIdentityBody`] for a delegated birth outside
/// `Requested` or a step that moves the key; [`Error::SecretRefNotFound`] /
/// [`Error::SecretCustodyNotActive`] / [`Error::SecretBindingDenied`] when a
/// live delegated row cannot re-prove custody for its own mailbox; and
/// [`Error::ChannelIdentityAlreadyExists`] when the write would put a second
/// occupant on a key.
pub(crate) fn admit_channel_identity_transition_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    transition: IdentityTransition<'_>,
) -> Result<()> {
    let next = transition.next();
    next.validate()?;
    if let Some(facet_ref) = next.binding.facet_ref() {
        let facet_type = store
            .entities
            .get(txn, facet_ref.as_bytes())?
            .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type));
        if facet_type != Some(crate::registry::ENTITY_TYPE_FACET) {
            return Err(Error::InvalidChannelIdentityBody(
                "channel identity binding facet_ref must name a FACET",
            ));
        }
    }
    match transition {
        IdentityTransition::Birth { next } => {
            if next.is_delegated() && next.state != ChannelIdentityState::Requested {
                return Err(Error::InvalidChannelIdentityBody(
                    "a delegated_grant identity is born Requested; every later state is a \
                     checked lifecycle step from a row that already exists",
                ));
            }
        }
        IdentityTransition::Step { prior, next } => {
            if prior.assignment_key() != next.assignment_key() {
                return Err(Error::InvalidChannelIdentityBody(
                    "a stored channel identity's assignment key is immutable",
                ));
            }
        }
    }
    if channel_identity_assignment_conflict_in_txn(store, txn, id, next)? {
        return Err(Error::ChannelIdentityAlreadyExists);
    }
    reprove_delegated_custody_in_txn(store, txn, next)
}

/// Law C, for the row a birth or a step is about to store.
fn reprove_delegated_custody_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity: &ChannelIdentity,
) -> Result<()> {
    let Some(grant) = &identity.grant else {
        return Ok(());
    };
    if identity.state.asserts_delegated_custody() {
        verify_delegated_custody_in_txn(
            store,
            txn,
            &identity.channel,
            &identity.address_or_handle,
            grant,
        )?;
    }
    Ok(())
}

/// Whether another row already OCCUPIES this row's assignment key.
fn channel_identity_assignment_conflict_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    identity: &ChannelIdentity,
) -> Result<bool> {
    if !identity.occupies_assignment_key() {
        return Ok(false);
    }
    let key = identity.assignment_key();
    for entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_CHANNEL_IDENTITY])?
    {
        let (index_key, _) = entry?;
        let existing_id = entity_id_from_type_index_key(&index_key)?;
        if existing_id == *id {
            continue;
        }
        let raw = store
            .entities
            .get(txn, existing_id.as_bytes())?
            .ok_or(Error::CorruptedIndex("type index row without entity"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::CorruptedIndex("type index row kind mismatch"));
        }
        let stored = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if stored.occupies_assignment_key() && stored.assignment_key() == key {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Vault {
    /// Creates a ChannelIdentity record through the engine maintenance door.
    ///
    /// Generic public entity puts for `ENTITY_TYPE_CHANNEL_IDENTITY` remain
    /// rejected with `MaintenanceKindNotWritable`; this method validates the
    /// CID-1 body and runs [`admit_channel_identity_transition_in_txn`] before
    /// writing.
    pub fn create_channel_identity(&self, id: &EntityId, identity: &ChannelIdentity) -> Result<()> {
        let data = encode_channel_identity_body(identity)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::ChannelIdentityAlreadyExists);
        }
        admit_channel_identity_transition_in_txn(
            &self.store,
            &wtxn,
            id,
            IdentityTransition::Birth { next: identity },
        )?;
        self.apply_channel_identity_body(&mut wtxn, id, identity.state_changed_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Creates the pre-provisioned own-app home-channel identity for an agent.
    pub fn create_own_app_channel_identity(
        &self,
        id: &EntityId,
        agent_ref: EntityId,
        created_at: u64,
    ) -> Result<ChannelIdentity> {
        let identity = ChannelIdentity::own_app_home(agent_ref, created_at);
        self.create_channel_identity(id, &identity)?;
        Ok(identity)
    }

    /// Stands up a requested `delegated_grant` row: THE delegated door.
    ///
    /// One call, one write transaction, and the custody proof is minted and
    /// consumed inside it. A caller cannot split this into "verify, then
    /// provision" and hold the answer across the gap: the proof borrows its
    /// transaction, so the window in which a member could revoke the grant
    /// between the check and the write is closed by construction rather than by
    /// a second check every host would have to remember to write.
    ///
    /// The adapter supplies `(channel, mailbox, binding, grant)` — NAMES — and
    /// never a proof. The row is born `Requested`; going live is the ordinary
    /// gated lifecycle road, and each step re-proves custody in its own
    /// transaction.
    ///
    /// # Errors
    ///
    /// [`Error::ChannelIdentityAlreadyExists`] when `id` is taken or the mailbox
    /// already has an occupant; [`Error::SecretRefNotFound`],
    /// [`Error::SecretCustodyNotActive`] or [`Error::SecretBindingDenied`] when
    /// the named custody record is missing, inactive, unbound for the channel's
    /// effector, or does not name this mailbox as its subject; and
    /// [`Error::InvalidChannelIdentityBody`] when the resulting row fails
    /// validation.
    pub fn provision_delegated_identity(
        &self,
        id: &EntityId,
        request: DelegatedProvisionRequest,
        requested_at: u64,
    ) -> Result<ChannelIdentity> {
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::ChannelIdentityAlreadyExists);
        }
        // The proof borrows `wtxn`; the block ends the borrow before the write
        // takes it mutably, and the row it produced outlives it because a row
        // carries names, never evidence.
        let identity = {
            let channel_key = ChannelKey::normalize(&request.channel);
            let address =
                AssignmentAddress::normalize(channel_key.as_str(), &request.address_or_handle);
            let proof = verify_delegated_custody_in_txn(
                &self.store,
                &wtxn,
                channel_key.as_str(),
                address.as_str(),
                &request.grant,
            )?;
            ChannelIdentity::requested_delegated(
                channel_key.as_str(),
                address.as_str(),
                request.binding,
                request.grant,
                &proof,
                requested_at,
            )?
        };
        let data = encode_channel_identity_body(&identity)?;
        admit_channel_identity_transition_in_txn(
            &self.store,
            &wtxn,
            id,
            IdentityTransition::Birth { next: &identity },
        )?;
        self.apply_channel_identity_body(&mut wtxn, id, requested_at, data)?;
        wtxn.commit()?;
        Ok(identity)
    }

    /// Verifies the custody record a delegated grant names for
    /// `(channel, address)`, without minting anything the caller can hold.
    ///
    /// The proof is intentionally NOT returned: it borrows the transaction that
    /// read the record, and a proof handed across a transaction boundary is
    /// exactly the stale evidence the type exists to make unspellable. Callers
    /// that want a row call [`Self::provision_delegated_identity`]; callers that
    /// only want the yes/no call this.
    ///
    /// # Errors
    ///
    /// As [`Self::provision_delegated_identity`]'s custody arms.
    pub fn verify_delegated_custody(
        &self,
        channel: &str,
        address_or_handle: &str,
        grant: &DelegatedGrant,
    ) -> Result<()> {
        let rtxn = self.store.env.read_txn()?;
        let channel_key = ChannelKey::normalize(channel);
        let address = AssignmentAddress::normalize(channel_key.as_str(), address_or_handle);
        verify_delegated_custody_in_txn(
            &self.store,
            &rtxn,
            channel_key.as_str(),
            address.as_str(),
            grant,
        )
        .map(|_| ())
    }

    /// Applies a checked ChannelIdentity lifecycle transition in place.
    pub fn transition_channel_identity(
        &self,
        id: &EntityId,
        next_state: ChannelIdentityState,
        pending_fulfillment: Option<ChannelIdentityFulfillment>,
        state_changed_at: u64,
        quarantine_until: Option<u64>,
    ) -> Result<ChannelIdentity> {
        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let current = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let next = current.transition(
            next_state,
            pending_fulfillment,
            state_changed_at,
            quarantine_until,
        )?;
        admit_channel_identity_transition_in_txn(
            &self.store,
            &wtxn,
            id,
            IdentityTransition::Step {
                prior: &current,
                next: &next,
            },
        )?;
        let data = encode_channel_identity_body(&next)?;
        self.apply_channel_identity_body(&mut wtxn, id, state_changed_at, data)?;
        wtxn.commit()?;
        Ok(next)
    }

    /// Reads and decodes a ChannelIdentity record.
    pub fn get_channel_identity(&self, id: &EntityId) -> Result<Option<ChannelIdentity>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Reads the ChannelIdentity holding a `(channel, address)` key.
    ///
    /// The lookup canonicalizes BOTH sides through [`AssignmentKey`], so a
    /// caller spelling the mailbox the way its provider did finds the row a
    /// normalizing writer stored, and a row decoded verbatim off disk is found
    /// under the key it means rather than the bytes it holds.
    ///
    /// A row that no longer OCCUPIES its key is skipped: a released or
    /// tombstoned delegated row has withdrawn its claim on a mailbox the
    /// product never owned, so it must not shadow the row a lawful re-consent
    /// stands up. Self-held rows occupy forever and are still found here in
    /// every state, which is what keeps a tombstoned address routing to its own
    /// rejection instead of looking unknown.
    pub fn channel_identity_by_assignment(
        &self,
        channel: &str,
        address_or_handle: &str,
    ) -> Result<Option<(EntityId, ChannelIdentity)>> {
        let wanted = AssignmentKey::of(channel, address_or_handle);
        let rtxn = self.store.env.read_txn()?;
        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_CHANNEL_IDENTITY])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
                return Err(Error::CorruptedIndex("type index row kind mismatch"));
            }
            let identity = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if identity.occupies_assignment_key() && identity.assignment_key() == wanted {
                return Ok(Some((id, identity)));
            }
        }
        Ok(None)
    }

    pub(crate) fn apply_channel_identity_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_CHANNEL_IDENTITY,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }
}

#[cfg(test)]
mod tests;
