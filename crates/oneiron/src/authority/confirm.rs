//! Owner-confirm and critical-write-confirm action and state types.

use crate::entity_id::EntityId;

use super::*;

/// Federation confirm action recorded in the authority log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityConfirmKind {
    /// Connection accept.
    Accept,
    /// Re-scope or epoch bump.
    Rescope,
    /// Foreign A2A connect.
    A2aConnect,
    /// Revocation confirm.
    Revoke,
}

impl AuthorityConfirmKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Accept => CONFIRM_KIND_ACCEPT,
            Self::Rescope => CONFIRM_KIND_RESCOPE,
            Self::A2aConnect => CONFIRM_KIND_A2A_CONNECT,
            Self::Revoke => CONFIRM_KIND_REVOKE,
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            CONFIRM_KIND_ACCEPT => Some(Self::Accept),
            CONFIRM_KIND_RESCOPE => Some(Self::Rescope),
            CONFIRM_KIND_A2A_CONNECT => Some(Self::A2aConnect),
            CONFIRM_KIND_REVOKE => Some(Self::Revoke),
            _ => None,
        }
    }
}

/// Fold-verified federation confirm payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityConfirmAction {
    /// Confirm kind.
    pub kind: AuthorityConfirmKind,
    /// Connection/grant identifier.
    pub confirm_id: [u8; 32],
    /// Peer vault id.
    pub peer_vault_id: AuthorityVaultId,
    /// Consent epoch.
    pub epoch: u64,
    /// Device-bound nonce.
    pub nonce: [u8; 16],
}

pub const CRITICAL_WRITE_CONFIRM_DOMAIN: &[u8] = b"oneiron/authority/critical-write-confirm/v1";
pub const CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CriticalWriteConfirmDisposition {
    Clear,
    Decline,
}
impl CriticalWriteConfirmDisposition {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Decline => "decline",
        }
    }
    pub(super) fn parse(s: &str) -> Option<Self> {
        match s {
            "clear" => Some(Self::Clear),
            "decline" => Some(Self::Decline),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CriticalWriteConfirmMethod {
    TokenReauth,
    PassphraseReentry,
}
impl CriticalWriteConfirmMethod {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::TokenReauth => "token_reauth",
            Self::PassphraseReentry => "passphrase_reentry",
        }
    }
    pub(super) fn parse(s: &str) -> Option<Self> {
        match s {
            "token_reauth" => Some(Self::TokenReauth),
            "passphrase_reentry" => Some(Self::PassphraseReentry),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalWriteConfirmAction {
    pub schema_version: u64,
    pub confirm_id: [u8; 32],
    pub gate_decision_id: [u8; 16],
    pub claim_id: EntityId,
    pub effect_digest: [u8; 32],
    pub read_frontier_hash: [u8; 32],
    pub nonce: [u8; 16],
    pub expires_at: u64,
    pub disposition: CriticalWriteConfirmDisposition,
    pub method: CriticalWriteConfirmMethod,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalWriteConfirmState {
    pub action: CriticalWriteConfirmAction,
    pub signer: AuthorityKey,
    pub authority_entry_hash: AuthorityEntryHash,
}
