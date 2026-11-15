//! Moved from `crates/oneiron/src/runtime_hooks/verb/credential.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_consent_state::runtime_hooks::verb::credential::VerbAskCredentialRef;
pub use oneiron_consent_state::runtime_hooks::verb::credential::VerbAskCredentialSource;
pub use oneiron_consent_state::runtime_hooks::verb::credential::VerbAskDoor;
pub use oneiron_consent_state::runtime_hooks::verb::credential::VerbAskInstrument;
pub use oneiron_consent_state::runtime_hooks::verb::credential::VerbAskMcpCeiling;
use oneiron_contracts::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED;
use oneiron_contracts::memory::MemoryError;

/// Why the drain ended a credential call before it ran. Every refusal ends
/// the call (OF-580 defaults): nothing waits for a credential to come back,
/// none unavailable is tried again, and no renewed one stands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbAskRefusal {
    /// The slip's mint, or the kept witness, is gone.
    CredentialMissing,
    /// The slip or an ancestor was revoked.
    CredentialRevoked,
    /// The slip's lifetime ended.
    CredentialExpired,
    /// The instrument no longer verifies as the one the call was admitted on.
    CredentialChanged,
    /// The host could not establish the credential: no check installed, the
    /// server stopping, or an MCP registration it no longer holds.
    CredentialUnavailable,
    /// The credential's scope, or its connector's, no longer admits the call.
    ScopeRefused,
    /// The door the call came in by cannot be rebuilt.
    ContextUnavailable,
    /// The attested owner the call was admitted for is no longer the vault's
    /// live owner (FIX 11063). Standing the host could not read is
    /// `CredentialUnavailable`, never this.
    OwnerNotLive,
}

impl VerbAskRefusal {
    pub const ALL: [Self; 8] = [
        Self::CredentialMissing,
        Self::CredentialRevoked,
        Self::CredentialExpired,
        Self::CredentialChanged,
        Self::CredentialUnavailable,
        Self::ScopeRefused,
        Self::ContextUnavailable,
        Self::OwnerNotLive,
    ];

    /// The stable code a retry's `CompletedWithError` carries.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CredentialMissing => "CREDENTIAL_MISSING",
            Self::CredentialRevoked => "CREDENTIAL_REVOKED",
            Self::CredentialExpired => "CREDENTIAL_EXPIRED",
            Self::CredentialChanged => "CREDENTIAL_CHANGED",
            Self::CredentialUnavailable => "CREDENTIAL_UNAVAILABLE",
            Self::ScopeRefused => "SCOPE_REFUSED",
            Self::ContextUnavailable => "CONTEXT_UNAVAILABLE",
            // The owner door's own refusal: the authority log no longer
            // binds this person as the vault's owner.
            Self::OwnerNotLive => MEMORY_CODE_OWNER_BINDING_REQUIRED,
        }
    }

    /// The refusal `code` names, if it names one.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|refusal| refusal.code() == code)
    }

    /// Whether the caller's own credential refused: anything but a door or
    /// a credential this host could not establish.
    #[must_use]
    pub const fn names_credential(self) -> bool {
        !matches!(self, Self::CredentialUnavailable | Self::ContextUnavailable)
    }

    const fn message(self) -> &'static str {
        match self {
            Self::CredentialMissing => "the credential this call was admitted on is gone",
            Self::CredentialRevoked => "the credential this call was admitted on was revoked",
            Self::CredentialExpired => "the credential this call was admitted on expired",
            Self::CredentialChanged => {
                "the credential no longer verifies as the one this call was admitted on"
            }
            Self::CredentialUnavailable => "this host could not verify the call's credential again",
            Self::ScopeRefused => "the credential's scope no longer admits this call",
            Self::ContextUnavailable => "the door this call came in by cannot run it again",
            Self::OwnerNotLive => "the attested owner is not this vault's live owner",
        }
    }

    const fn guidance(self) -> &'static str {
        match self {
            Self::OwnerNotLive => {
                "Sign in again as this vault's owner, then call again with a new invocation."
            }
            _ => "Call again with a new invocation, on a credential that holds now.",
        }
    }

    /// The error a refused call ends with. Its code is never the engine's
    /// internal one, so the drain saves it and the call ends.
    pub fn error(self) -> MemoryError {
        MemoryError::new(
            self.code(),
            format!("settlement did not run this call: {}", self.message()),
            &[self.guidance()],
        )
    }
}
