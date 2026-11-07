//! Research-loop budget configuration, settlement, and refusal values.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Loop purpose, kept separate from ordinary interactive LLM budget rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum RsiSpendPurpose {
    Experiment,
    Judge,
    HeldOut,
}

/// A share is advisory unless the owner pins its cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiBudgetShare {
    pub units: u64,
    pub pinned: bool,
}

/// Independent vault lines: loop spend is token-denominated, exploration is exposure-denominated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RsiBudgetConfig {
    pub limit: u64,
    pub exploration_exposure_limit: u64,
    pub shares: BTreeMap<String, RsiBudgetShare>,
}

/// One exact limiting line, raised by `units`. A top-up never lowers a line,
/// never touches receipts or spend, and never resumes held work by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "line")]
pub enum RsiTopUp {
    /// The token-denominated loop line's limit.
    Tokens { units: u64 },
    /// The exposure-denominated exploration line's limit.
    Exploration { units: u64 },
    /// One named share's allocation, soft or pinned.
    Share { share: String, units: u64 },
}

/// Token-denominated loop accounting, including reservations that survive reopen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiBudgetRead {
    pub limit: u64,
    pub spent: u64,
    pub reserved: u64,
    pub suspended: bool,
}

/// Exposure-denominated exploration accounting, independent of token spend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiExplorationRead {
    pub exposure_limit: u64,
    pub spent_exposure: u64,
    pub reserved_exposure: u64,
    pub suspended: bool,
}

/// The signed record of one token-share overflow admitted from the
/// unallocated token pool (ARCH-0011): the vault store, the reservation, the
/// share and the units it binds, signed by this install's device key. Units
/// record reservation-time overdraft, even if it settles for less. Byte
/// fields are lowercase hex. [`Self::verify`] checks the signature alone;
/// `Vault::verify_rsi_overdraft` also checks it names this vault and this
/// install's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RsiOverdraftReceipt {
    pub share: String,
    pub units: u64,
    /// The reservation the overdraft was admitted for.
    pub reservation: String,
    /// The vault store it binds: its 32-byte store id.
    pub vault: String,
    /// The Ed25519 device key that signed it.
    pub public_key: String,
    /// The signature over [`Self::transcript`].
    pub signature: String,
}

/// The signing domain of an RSI overdraft receipt.
const OVERDRAFT_RECEIPT_DOMAIN: &[u8] = b"oneiron/rsi/overdraft-receipt/v1";

impl RsiOverdraftReceipt {
    /// The bytes the signature covers: the domain, then the vault, the
    /// reservation, the share, the units and the public key, each field
    /// length-prefixed.
    ///
    /// # Errors
    /// A byte field that is not lowercase hex.
    pub fn transcript(&self) -> Result<Vec<u8>, RsiBudgetError> {
        let malformed =
            || RsiBudgetError::Engine(crate::Error::CorruptedIndex("RSI overdraft receipt"));
        let vault = hex_bytes(&self.vault).ok_or_else(malformed)?;
        let reservation = hex_bytes(&self.reservation).ok_or_else(malformed)?;
        let public_key = hex_bytes(&self.public_key).ok_or_else(malformed)?;
        let mut out = OVERDRAFT_RECEIPT_DOMAIN.to_vec();
        for field in [
            vault.as_slice(),
            reservation.as_slice(),
            self.share.as_bytes(),
            &self.units.to_le_bytes(),
            public_key.as_slice(),
        ] {
            out.extend_from_slice(&(field.len() as u64).to_le_bytes());
            out.extend_from_slice(field);
        }
        Ok(out)
    }

    /// Whether the signature is the embedded key's over the transcript.
    #[must_use]
    pub fn verify(&self) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Some(key) = hex_bytes(&self.public_key)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        else {
            return false;
        };
        let Some(signature) =
            hex_bytes(&self.signature).and_then(|bytes| Signature::from_slice(&bytes).ok())
        else {
            return false;
        };
        self.transcript()
            .is_ok_and(|transcript| key.verify(&transcript, &signature).is_ok())
    }
}

/// `bytes` as lowercase hex.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
    }
    out
}

/// The bytes lowercase hex `text` spells, or `None`.
fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let text = text.as_bytes();
    if text.len() % 2 != 0 {
        return None;
    }
    text.chunks(2)
        .map(|pair| Some((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

/// The durable receipt of one reservation's terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum RsiSettlement {
    Spent(u64),
    Exposure(u64),
    Refunded,
}

/// Fail-closed ledger refusals. Nothing is spent or reserved on a refusal.
#[derive(Debug, thiserror::Error)]
pub enum RsiBudgetError {
    #[error("RSI budget is not configured")]
    Unconfigured,
    #[error("RSI budget configuration is invalid or already set")]
    InvalidConfig,
    #[error("RSI reservation already exists")]
    DuplicateReservation,
    #[error("RSI spend requires an open reservation")]
    ReservationRequired,
    #[error("RSI settlement uses the wrong budget line")]
    WrongLine,
    #[error("RSI budget capacity exceeded")]
    Exhausted,
    #[error("RSI work is suspended")]
    Suspended,
    #[error(transparent)]
    Engine(#[from] crate::Error),
}
