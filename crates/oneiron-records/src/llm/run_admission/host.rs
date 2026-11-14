//! Moved from `crates/oneiron/src/llm/run_admission/host.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::resident_budget_rows::AllocationRef;
use oneiron_authority::federation::WalletRef;
use oneiron_run_budget::run_budget::LeaseUnit;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

/// Who pays the provider for a call an offer serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Payer {
    /// The host's key or account; the vault's allocation pays.
    Host,
    /// The customer's own model key (BYOK).
    CustomerKey,
    /// The customer's own cloud account (BYOC).
    CustomerAccount,
    /// The customer's signed-in vendor CLI (a BYO seat).
    CustomerSeat,
    /// The vault's own node or a paired device; nobody per call.
    Local,
}

/// The billing account a room-paid call bills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "billed", rename_all = "snake_case")]
pub enum PayerAccount {
    /// The PERSON's own billing account, as the host resolved it.
    Person { account: String },
    /// The vault's own account, the one owner spend bills: the PERSON is one
    /// of the vault's live Owners, so it is that PERSON's own account.
    VaultOwner,
    /// The vault owner's, which the owners approved on payer-needed ask
    /// `ask` because the PERSON's own account could not be resolved.
    VaultApproved { ask: u64 },
}

impl PayerAccount {
    /// Which account the call bills, as a code.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Person { .. } => "person",
            Self::VaultOwner => "vault_owner",
            Self::VaultApproved { .. } => "vault_approved",
        }
    }
}

/// Where the credential behind an offer sits while the call runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyCustody {
    /// No key: a local model.
    Keyless,
    /// T0: the key stays behind a door; the caller holds a handle.
    T0,
    /// T1: the key is in the caller's memory, so nothing sees each call.
    T1,
}

/// Why a route was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum OfferRouteError {
    #[error("an adapter name is non-empty, without '@', whitespace or control characters")]
    Adapter,
    /// An origin with userinfo, a query, a fragment or a web path could carry
    /// a credential into a receipt.
    #[error(
        "an origin is non-empty, without '@', '?', '#', '\\', whitespace or control characters, and a web origin is scheme://host[:port]"
    )]
    Origin,
}

/// Schemes whose origin is a host and a port, and whose path a URL parser
/// would read even from a lax spelling.
pub const WEB_SCHEMES: [&str; 4] = ["http", "https", "ws", "wss"];

/// `host[:port]`: a DNS name or IPv4 address, or a bracketed IPv6 address.
pub fn is_authority(authority: &str) -> bool {
    let (host_ok, port) = match authority.strip_prefix('[') {
        Some(bracketed) => match bracketed.split_once(']') {
            Some((address, port)) => (
                !address.is_empty()
                    && address
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.')),
                port,
            ),
            None => return false,
        },
        None => {
            let (host, port) = authority.split_at(authority.find(':').unwrap_or(authority.len()));
            (
                !host.is_empty()
                    && host
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')),
                port,
            )
        }
    };
    let port_ok = port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()));
    host_ok && port_ok
}

/// How many units of `unit` one native unit of an offer costs, as a rational:
/// `cost` per `per`. Pack data, never an engine price.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnitRate {
    pub unit: LeaseUnit,
    pub per: u64,
    pub cost: u64,
}

/// The identity a lease and the gate or paid adapter it leaves through
/// compare: a digest of every field the host bound. Two bindings of one model
/// or connector at one route that differ in payer, credential binding, catalog
/// revision, custody or price are two offers, and neither's permit starts a
/// call for the other.
pub fn identity(binding: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(binding).expect("an offer binding serializes");
    blake3::hash(&bytes).to_hex().to_string()
}

/// The money one vault may commit, as the host issued it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allocation {
    pub reference: AllocationRef,
    pub units: u64,
    pub unit: LeaseUnit,
    /// The host wallet that funds this allocation (FIX 7766), host-supplied
    /// metadata beside its generation reference: a run whose work an owner's
    /// agent Grant funds takes a hold only on an allocation of the wallet
    /// that Grant names. `None`: the host named none, and such a run takes
    /// no hold on it.
    pub wallet: Option<WalletRef>,
}

/// Why the host's grant of an allocation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum AllocationGrantError {
    /// The generation is not newer than one this account already held, so a
    /// consumed allocation cannot come back.
    #[error("allocation generation is not newer than one already held")]
    StaleGeneration,
}
