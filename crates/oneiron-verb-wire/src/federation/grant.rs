//! Moved from `crates/oneiron/src/federation/grant.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::codec::decode_canonical_entity_ref;
use oneiron_authority::federation::codec::decode_entity_ref;
use oneiron_authority::federation::codec::encode_msgpack_value;
use oneiron_authority::federation::codec::invalid_grant;
use oneiron_authority::federation::codec::optional_value;
use oneiron_authority::federation::codec::required_value;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub(crate) use oneiron_store::serialize::grant_fields::FEDERATION_GRANT_FIELDS_FULL;
pub(crate) use oneiron_store::serialize::grant_fields::FEDERATION_GRANT_FIELDS_MINIMAL;
pub(crate) use oneiron_store::serialize::grant_fields::FEDERATION_GRANT_FIELDS_STANDARD;
use std::collections::BTreeSet;
use std::io::Cursor;

/// Scope addressed by a federation grant.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[non_exhaustive]
pub enum FederationGrantScope {
    /// Membership in a shared vault.
    Vault { vault_id: u64 },
    /// Access to facts explicitly disclosed for one ask.
    Ask { ask_ref: EntityId },
    /// The guest slice a vault-to-vault Connect pact governs: what this vault
    /// lets the peer vault (its genesis id) read and propose (FIX 3016).
    Connect {
        peer_vault_id: oneiron_authority::authority::AuthorityVaultId,
    },
}

impl FederationGrantScope {
    /// Constructs a shared-vault scope.
    #[must_use]
    pub const fn vault(vault_id: u64) -> Self {
        Self::Vault { vault_id }
    }

    /// Constructs a scope bound to exactly one ask.
    #[must_use]
    pub const fn ask(ask_ref: EntityId) -> Self {
        Self::Ask { ask_ref }
    }

    /// Constructs the scope of the guest grant a Connect with `peer_vault_id`
    /// governs.
    #[must_use]
    pub const fn connect(peer_vault_id: oneiron_authority::authority::AuthorityVaultId) -> Self {
        Self::Connect { peer_vault_id }
    }

    pub fn validate(self) -> Result<()> {
        match self {
            Self::Vault { vault_id: 0 } => Err(invalid_grant()),
            Self::Connect { peer_vault_id } if peer_vault_id == [0; 32] => Err(invalid_grant()),
            Self::Vault { .. } | Self::Ask { .. } | Self::Connect { .. } => Ok(()),
        }
    }
}

/// Role assigned by a federation grant.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FederationGrantRole {
    /// Full owner privileges for the shared vault.
    Owner,
    /// Admin's powers plus a Grant for delegated Owner powers, each Owner act
    /// carrying a check-in mode (ARCH-0082 #roles; DEPUTY = A, the lead
    /// 11 Nov 11:38). It rides the Admin envelope and never holds the org
    /// root. The delegated Owner Grant is ROLES-CHECKIN PR 2.
    Deputy,
    /// Administrative privileges without owner transfer semantics.
    Admin,
    /// A Steward looks after the vault's memory for its owners: it can read
    /// and organise everything in this vault, but it can only suggest who
    /// joins or what role they get, and it can never give itself more access.
    ///
    /// ARCH-0043's seventh role, between Admin and Member; a person or an
    /// agent holds it. Its preset reads and derives across this vault root,
    /// archives inside the grant and deletes in scope
    /// ([`super::grant_scope::membership_preset`]). It is never
    /// administrative ([`Self::is_admin`] is false), so it cannot add or
    /// remove members, assign roles, parent a delegate, widen any grant or
    /// do an owner act; a private member vault is another root it never
    /// holds a grant in.
    Steward,
    /// Read/write member privileges.
    Member,
    /// Read-only member privileges.
    Viewer,
    /// One-hop, expiring read privileges attenuated from an admin parent.
    ///
    /// A delegate is never administrative and can never itself delegate, so
    /// the tier cannot self-widen: the only minting path is
    /// [`FederationGrant::attenuated_delegate`] from an [`Self::is_admin`]
    /// parent.
    Delegate,
    /// Read/propose-only access to explicitly disclosed facts for one ask.
    Guest,
}

impl FederationGrantRole {
    /// Returns the pinned on-disk string for this role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Deputy => "deputy",
            Self::Admin => "admin",
            Self::Steward => "steward",
            Self::Member => "member",
            Self::Viewer => "viewer",
            Self::Delegate => "delegate",
            Self::Guest => "guest",
        }
    }

    /// Parses a pinned on-disk role string. The retired `auditor` is refused,
    /// with no alias (VS-OLD-NAMES = A, the lead 11 Nov 11:38).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "deputy" => Some(Self::Deputy),
            "admin" => Some(Self::Admin),
            "steward" => Some(Self::Steward),
            "member" => Some(Self::Member),
            "viewer" => Some(Self::Viewer),
            "delegate" => Some(Self::Delegate),
            "guest" => Some(Self::Guest),
            _ => None,
        }
    }

    /// Returns whether this role can administer membership or policy. A
    /// Deputy holds Admin's powers; the org root and the veto stay the
    /// Owner's alone.
    #[must_use]
    pub const fn is_admin(self) -> bool {
        matches!(self, Self::Owner | Self::Deputy | Self::Admin)
    }

    /// Returns whether this role is the isolated ask-scoped guest role.
    #[must_use]
    pub const fn is_guest(self) -> bool {
        matches!(self, Self::Guest)
    }
}
