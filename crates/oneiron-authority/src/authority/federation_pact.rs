//! Federation lifecycle and pact types.
//!
//! The pact/gesture data model plus the domain-separated pact transcript,
//! scope digest, and gesture signing helpers.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{FederationDirectionScope, FederationPactScope};

use super::*;

/// Federation relationship lifecycle kind (OF-156, option B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FederationLifecycleKind {
    /// Dual-signed pact creation.
    Connect,
    /// Dual-signed re-pact (epoch bump) or unilateral effective-scope narrow.
    Rescope,
    /// Unilateral terminal severance.
    Disconnect,
    /// Dual-signed terminal succession into a co-owned vault.
    Promote,
    /// Unilateral terminal dissolution.
    Dissolve,
}

impl FederationLifecycleKind {
    /// Public so `oneiron`'s authority code calls it across the crate line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => LIFECYCLE_KIND_CONNECT,
            Self::Rescope => LIFECYCLE_KIND_RESCOPE,
            Self::Disconnect => LIFECYCLE_KIND_DISCONNECT,
            Self::Promote => LIFECYCLE_KIND_PROMOTE,
            Self::Dissolve => LIFECYCLE_KIND_DISSOLVE,
        }
    }

    /// Public so `oneiron`'s authority code calls it across the crate line.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            LIFECYCLE_KIND_CONNECT => Some(Self::Connect),
            LIFECYCLE_KIND_RESCOPE => Some(Self::Rescope),
            LIFECYCLE_KIND_DISCONNECT => Some(Self::Disconnect),
            LIFECYCLE_KIND_PROMOTE => Some(Self::Promote),
            LIFECYCLE_KIND_DISSOLVE => Some(Self::Dissolve),
            _ => None,
        }
    }
}

/// Peer owner's signed gesture over the pact transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPactGesture {
    /// Peer owner authority key (Ed25519 or P-256).
    pub signer: AuthorityKey,
    /// Raw signature bytes over [`federation_pact_transcript`]; 64 bytes for
    /// both suites.
    pub signature: Vec<u8>,
}

/// Fold-verified federation lifecycle payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationLifecycleAction {
    /// Lifecycle kind.
    pub kind: FederationLifecycleKind,
    /// Shared pact identifier — identical on both vaults' logs.
    pub pact_id: [u8; 32],
    /// Local FEDERATION_GRANT entity this pact governs.
    pub grant_ref: EntityId,
    /// Peer vault id (peer's genesis hash).
    pub peer_vault_id: AuthorityVaultId,
    /// Pact consent epoch: Connect == 1; repact/Promote == cur+1;
    /// narrow/Disconnect/Dissolve == cur.
    pub pact_epoch: u64,
    /// Full disclosed scope pair. Some for Connect and Rescope-repact only.
    pub pact_scope: Option<FederationPactScope>,
    /// Local-outbound effective scope. Some ONLY for Rescope-narrow.
    pub effective_scope: Option<FederationDirectionScope>,
    /// Keyed scope commitment. Some for Connect / Rescope-repact / Promote.
    pub scope_digest: Option<[u8; 32]>,
    /// Peer owner gesture. Some for Connect / Rescope-repact / Promote.
    pub gesture: Option<FederationPactGesture>,
    /// Successor co-owned vault id. Some ONLY for Promote.
    pub successor_vault_id: Option<AuthorityVaultId>,
    /// Pact nonce feeding the scope commitment and transcript. Never all-zero.
    pub pact_nonce: [u8; 16],
}

/// Fold-derived status of one federation pact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FederationPactStatus {
    /// Pact is live; its grant confers access.
    Active,
    /// Equivocation-shaped divergence detected; confers nothing until a fresh
    /// dual-signed re-pact heals it.
    Suspended,
    /// Terminal: succeeded by a co-owned vault.
    Promoted,
    /// Terminal: unilaterally severed.
    Disconnected,
    /// Terminal: unilaterally dissolved.
    Dissolved,
}

impl FederationPactStatus {
    /// Terminal statuses reject every further lifecycle op.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Promoted | Self::Disconnected | Self::Dissolved)
    }
}

/// Fold-derived state of one federation pact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPactState {
    /// Current pact status.
    pub status: FederationPactStatus,
    /// Governed FEDERATION_GRANT entity.
    pub grant_ref: EntityId,
    /// Peer vault id.
    pub peer_vault_id: AuthorityVaultId,
    /// Peer owner key pinned at Connect (TOFU).
    pub peer_owner_key: AuthorityKey,
    /// Current pact consent epoch.
    pub pact_epoch: u64,
    /// Dual-signed scope commitment for the current ceiling.
    pub scope_digest: [u8; 32],
    /// Dual-signed ceiling scope pair.
    pub pact_scope: FederationPactScope,
    /// OUR outbound overlay, always ⊑ our half of the ceiling.
    pub effective_scope: FederationDirectionScope,
    /// Successor co-owned vault id, set by Promote.
    pub successor_vault_id: Option<AuthorityVaultId>,
    /// Epoch at which the pact went terminal.
    pub terminal_epoch: Option<u64>,
}

/// Activation of a federation grant against the fold-derived pact state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationGrantActivation {
    /// No lifecycle entries name this grant; legacy-allow.
    Unpacted,
    /// Pact-bound and Active.
    Active,
    /// Pact-bound and non-Active; confers nothing.
    Inactive(FederationPactStatus),
}

/// Deterministic per-entry rejection reason for lifecycle ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationLifecycleRejection {
    /// Non-Connect op names a pact absent from ancestry.
    UnknownPact,
    /// Connect names an already-known pact id.
    DuplicateConnect,
    /// Connect names a grant_ref already bound to a pact, or a lifecycle op
    /// names a grant_ref that conflicts with the pact's recorded binding.
    GrantAlreadyBound,
    /// Op targets a terminal (Promoted/Disconnected/Dissolved) pact.
    TerminalPact,
    /// Rescope-narrow/Promote on a suspended pact.
    SuspendedPact,
    /// Pact epoch violates the per-kind epoch rule.
    EpochMismatch,
    /// Required peer gesture is missing.
    GestureMissing,
    /// Peer gesture failed verification (bad signature, local-roster signer,
    /// or non-pinned signer).
    GestureInvalid,
    /// Scope digest does not commit to the carried scope, or Promote's digest
    /// differs from the stored one.
    ScopeDigestMismatch,
    /// Unilateral narrow escapes the dual-signed ceiling.
    WidenWithoutGesture,
    /// Op names a different peer vault than the pact records.
    PeerVaultMismatch,
    /// Carried scope failed structural validation.
    ScopeInvalid,
}

/// Domain-separated, side-symmetric transcript both pact owners sign.
///
/// `vault_a`/`vault_b` may be passed in either order; the transcript sorts
/// them ascending byte-wise into `vault_lo`/`vault_hi`, so both sides sign
/// byte-identical bytes. `successor_vault_id` must be `Some` exactly for
/// [`FederationLifecycleKind::Promote`].
#[allow(clippy::too_many_arguments)]
pub fn federation_pact_transcript(
    kind: FederationLifecycleKind,
    pact_id: &[u8; 32],
    vault_a: &AuthorityVaultId,
    vault_b: &AuthorityVaultId,
    pact_epoch: u64,
    scope_digest: &[u8; 32],
    successor_vault_id: Option<&AuthorityVaultId>,
    pact_nonce: &[u8; 16],
) -> Result<Vec<u8>> {
    if (kind == FederationLifecycleKind::Promote) != successor_vault_id.is_some() {
        return Err(invalid_authority());
    }
    let (vault_lo, vault_hi) = if vault_a <= vault_b {
        (vault_a, vault_b)
    } else {
        (vault_b, vault_a)
    };
    let value = Value::Map(vec![
        (Value::from("kind"), Value::from(kind.as_str())),
        (Value::from("pact_id"), binary_value(*pact_id)),
        (Value::from("vault_lo"), binary_value(*vault_lo)),
        (Value::from("vault_hi"), binary_value(*vault_hi)),
        (Value::from("pact_epoch"), Value::from(pact_epoch)),
        (Value::from("scope_digest"), binary_value(*scope_digest)),
        (
            Value::from("successor_vault_id"),
            successor_vault_id.map_or(Value::Nil, |successor| binary_value(*successor)),
        ),
        (Value::from("pact_nonce"), binary_value_16(*pact_nonce)),
    ]);
    let unsigned = encode_value(&value)?;
    let mut transcript = Vec::with_capacity(FEDERATION_PACT_DOMAIN.len() + unsigned.len());
    transcript.extend_from_slice(FEDERATION_PACT_DOMAIN);
    transcript.extend_from_slice(&unsigned);
    Ok(transcript)
}

/// Domain-separated nonce commitment over canonical pact scope bytes.
///
/// `blake3(FEDERATION_SCOPE_COMMIT_DOMAIN || pact_nonce || canonical_scope)`;
/// the gesture transcript carries only this digest, so a gesture shown to a
/// third party does not disclose scope contents.
#[must_use]
pub fn federation_scope_digest(pact_nonce: &[u8; 16], canonical_scope: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(
        FEDERATION_SCOPE_COMMIT_DOMAIN.len() + pact_nonce.len() + canonical_scope.len(),
    );
    material.extend_from_slice(FEDERATION_SCOPE_COMMIT_DOMAIN);
    material.extend_from_slice(pact_nonce);
    material.extend_from_slice(canonical_scope);
    *blake3::hash(&material).as_bytes()
}

/// Builds a peer gesture by signing the pact transcript with `signer`.
///
/// Pure helper usable from either side of the pact; the closure signs the
/// domain-prefixed transcript bytes (the `sign_guest_share_envelope` pattern).
#[allow(clippy::too_many_arguments)]
pub fn sign_federation_pact_gesture<S>(
    kind: FederationLifecycleKind,
    pact_id: &[u8; 32],
    vault_a: &AuthorityVaultId,
    vault_b: &AuthorityVaultId,
    pact_epoch: u64,
    scope_digest: &[u8; 32],
    successor_vault_id: Option<&AuthorityVaultId>,
    pact_nonce: &[u8; 16],
    signer_key: AuthorityKey,
    signer: S,
) -> Result<FederationPactGesture>
where
    S: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
    let transcript = federation_pact_transcript(
        kind,
        pact_id,
        vault_a,
        vault_b,
        pact_epoch,
        scope_digest,
        successor_vault_id,
        pact_nonce,
    )?;
    let signature = signer(&transcript)?;
    Ok(FederationPactGesture {
        signer: signer_key,
        signature,
    })
}
