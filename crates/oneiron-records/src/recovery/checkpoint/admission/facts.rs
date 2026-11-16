//! Moved from `crates/oneiron/src/recovery/checkpoint/admission/facts.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_vault_contract::restore::EscrowRole;
pub use oneiron_vault_contract::restore::FreshRecipient;
pub use oneiron_vault_contract::restore::ReleasedRecipient;
pub use oneiron_vault_contract::restore::RestorePlan;
use serde::Deserialize;
use serde::Serialize;

/// What admitted a restore's checkpoint signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerTrust {
    /// One of the plan's external pins.
    Pinned,
    /// A signer the vault's mode roots delegated, not pinned.
    ModeRootDelegated,
}

/// How the restore took its image's custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyRouteFact {
    /// A head was admitted and landed beside the destination.
    Landed,
    /// The custody is on this host, or the image binds none.
    Local,
    /// No head was found: claim rows whose keys stayed behind dropped.
    NoHead,
}

/// What the restore proved of the head's currency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorDisposition {
    ConfiguredVerified,
    /// No anchor configured: the head was used as it is.
    UnsetRollbackNotProven,
    /// No head was admitted.
    NotApplicable,
}

/// Why a recipient retired in the restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetiredBy {
    /// The plan named it released.
    Plan,
    /// The custody log retired it earlier; the image still carried its wrap.
    CustodyLog,
}
