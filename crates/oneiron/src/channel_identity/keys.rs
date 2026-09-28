//! Pinned ChannelIdentity schema versions, body key sets, claim predicates, and byte bounds.

/// Current ChannelIdentity body schema version for the three self-held shapes.
///
/// Every row carries `binding_facet_ref`, which is `nil` when unmasked.
/// Actor bindings use the `actor` scope.
pub const CHANNEL_IDENTITY_SCHEMA_VERSION: u64 = 5;

/// ChannelIdentity body schema version for `delegated_grant` rows.
///
/// Only the fourth shape uses it. The version is what selects the pinned key
/// set at decode, so the shapes' key sets can never be mixed.
pub const CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION: u64 = 6;

/// Wait class the quarantine hold resolves under, in the manifest's
/// `wait_policy` table (DEC-0005; owner rule 2026-09-27).
///
/// The number itself is NOT here. It is a row in the vault-resident default
/// manifest, resolved in the same snapshot as the row it governs, because how
/// long we hold an address we minted is a policy the vault owns and not an
/// engine invariant. What stays in code is the substrate: a `Quarantine` state
/// carries a window, that window is not before the state change it dates from,
/// and computing it does not overflow.
pub const WAIT_CLASS_CHANNEL_IDENTITY_QUARANTINE: &str = "channel_identity.quarantine";

/// Act class an outbound send resolves under, in the manifest's `act_policy`
/// table.
pub const ACT_CLASS_CHANNEL_IDENTITY_OUTBOUND_SEND: &str = "channel_identity.outbound_send";

/// Subject class of every self-held row in the `act_policy` table.
///
/// The three self-held SHAPES answer the same way about outbound reach, so one
/// row covers them; the delegated shape's own string is
/// [`ChannelIdentityShape::DelegatedGrant`](super::shape::ChannelIdentityShape::DelegatedGrant).
pub const SUBJECT_CLASS_SELF_HELD: &str = "self_held";

/// Shipped self-hold window for a quarantined released identity (90 days).
///
/// This is the value of the default manifest's
/// [`WAIT_CLASS_CHANNEL_IDENTITY_QUARANTINE`] row and the fail-closed answer a
/// caller with no resolved manifest takes — never a floor the engine asserts
/// over resolved policy.
pub const DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS: u64 = 90 * 24 * 60 * 60;

/// Pinned on-disk MessagePack key set for ChannelIdentity bodies.
///
/// `binding_facet_ref` names the mask this identity wears on this channel,
/// or is `nil` when unmasked.
pub const CHANNEL_IDENTITY_BODY_KEYS: [&str; 14] = [
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
    "binding_facet_ref",
    "auth_mode",
];

/// Pinned on-disk MessagePack key set for `delegated_grant` bodies.
///
/// The thirteen self-held keys in the same order, then the two custody keys.
/// `delegated_grant_ref` is a custody record NAME; no token bytes are ever
/// written here.
pub const CHANNEL_IDENTITY_DELEGATED_BODY_KEYS: [&str; 16] = [
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
    CHANNEL_IDENTITY_BODY_KEYS[13],
    "delegated_grant_ref",
    "grant_scopes",
];

pub(super) const KEY_SCHEMA_VERSION: &str = CHANNEL_IDENTITY_BODY_KEYS[0];

pub(super) const KEY_CHANNEL: &str = CHANNEL_IDENTITY_BODY_KEYS[1];

pub(super) const KEY_ADDRESS_OR_HANDLE: &str = CHANNEL_IDENTITY_BODY_KEYS[2];

pub(super) const KEY_SHAPE: &str = CHANNEL_IDENTITY_BODY_KEYS[3];

pub(super) const KEY_BINDING_SCOPE: &str = CHANNEL_IDENTITY_BODY_KEYS[4];

pub(super) const KEY_BINDING_TARGET: &str = CHANNEL_IDENTITY_BODY_KEYS[5];

pub(super) const KEY_STATE: &str = CHANNEL_IDENTITY_BODY_KEYS[6];

pub(super) const KEY_PENDING_FULFILLMENT: &str = CHANNEL_IDENTITY_BODY_KEYS[7];

pub(super) const KEY_STATE_CHANGED_AT: &str = CHANNEL_IDENTITY_BODY_KEYS[8];

pub(super) const KEY_QUARANTINE_UNTIL: &str = CHANNEL_IDENTITY_BODY_KEYS[9];

pub(super) const KEY_REPUTATION_REF: &str = CHANNEL_IDENTITY_BODY_KEYS[10];

pub(super) const KEY_MANIFEST_REF: &str = CHANNEL_IDENTITY_BODY_KEYS[11];

/// Optional channel facet key in the canonical body.
pub const KEY_BINDING_FACET_REF: &str = CHANNEL_IDENTITY_BODY_KEYS[12];

pub(super) const KEY_DELEGATED_GRANT_REF: &str = CHANNEL_IDENTITY_DELEGATED_BODY_KEYS[14];

pub(super) const KEY_GRANT_SCOPES: &str = CHANNEL_IDENTITY_DELEGATED_BODY_KEYS[15];

/// Pinned `channel_identity.*` claim predicates for the CID-1 record fields.
pub const CHANNEL_IDENTITY_CLAIM_PREDICATES: [&str; 13] = [
    PREDICATE_CHANNEL_IDENTITY_CHANNEL,
    PREDICATE_CHANNEL_IDENTITY_AUTH_MODE,
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

pub(super) const MAX_CHANNEL_BYTES: usize = 64;

pub(super) const MAX_ADDRESS_OR_HANDLE_BYTES: usize = 512;

/// Auth mechanism, never secret material.
pub(super) const PREDICATE_CHANNEL_IDENTITY_AUTH_MODE: &str = "channel_identity.auth_mode";
