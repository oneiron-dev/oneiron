//! What a host feeds the run admission: the offers it bound, the money a
//! vault may commit and the account's status. Bindings and numbers, never a
//! rule list.
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use super::super::{BudgetExhaustionPolicy, BudgetGuard, DispatchBinding, ModelId, ModelLocality};
use super::declaration::LeaseUnit;

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

/// The adapter and the origin a call goes out through. The origin names
/// where the call goes, never how it authenticates: it lands in every receipt.
/// A web origin (`http`, `https`, `ws`, `wss`) is `scheme://host[:port]`
/// alone, since a path, like userinfo or a query, could carry a proxy's key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct OfferRoute {
    adapter: String,
    origin: String,
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

impl OfferRoute {
    pub fn new(
        adapter: impl Into<String>,
        origin: impl Into<String>,
    ) -> Result<Self, OfferRouteError> {
        let (adapter, origin) = (adapter.into(), origin.into());
        let plain = |name: &str, banned: &[char]| {
            !name.is_empty()
                && !name
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || banned.contains(&c))
        };
        if !plain(&adapter, &['@']) {
            return Err(OfferRouteError::Adapter);
        }
        let web = origin.split_once(':').filter(|(scheme, _)| {
            WEB_SCHEMES
                .iter()
                .any(|web| scheme.eq_ignore_ascii_case(web))
        });
        let web_ok = web.is_none_or(|(_, rest)| rest.strip_prefix("//").is_some_and(is_authority));
        if !plain(&origin, &['@', '?', '#', '\\']) || !web_ok {
            return Err(OfferRouteError::Origin);
        }
        Ok(Self { adapter, origin })
    }

    #[must_use]
    pub fn adapter(&self) -> &str {
        &self.adapter
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub(super) fn key(&self) -> String {
        format!("{}@{}", self.adapter, self.origin)
    }
}

/// Schemes whose origin is a host and a port, and whose path a URL parser
/// would read even from a lax spelling.
const WEB_SCHEMES: [&str; 4] = ["http", "https", "ws", "wss"];

/// `host[:port]`: a DNS name or IPv4 address, or a bracketed IPv6 address.
fn is_authority(authority: &str) -> bool {
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

/// Why an amount has no price in a line's unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unpriced {
    /// No rate names the target unit, so units never mix silently.
    NoRate,
    /// The price is more than any meter holds.
    TooLarge,
}

/// Converts `units` of `native` into `target`: unchanged in the same unit,
/// else through the first matching rate, rounded up. The amount stays wide
/// until the end, so a large one is refused rather than priced low.
pub(super) fn convert(
    units: u128,
    native: &LeaseUnit,
    target: &LeaseUnit,
    rates: &[UnitRate],
) -> Result<u64, Unpriced> {
    let converted = if native == target {
        units
    } else {
        let rate = rates
            .iter()
            .find(|rate| rate.unit == *target && rate.per > 0)
            .ok_or(Unpriced::NoRate)?;
        units
            .checked_mul(u128::from(rate.cost))
            .ok_or(Unpriced::TooLarge)?
            .div_ceil(u128::from(rate.per))
    };
    u64::try_from(converted).map_err(|_| Unpriced::TooLarge)
}

/// One model at one place, as the host bound it: the host, not the caller,
/// supplies its route, locality and payer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferBinding {
    pub offer: String,
    pub model: ModelId,
    pub route: OfferRoute,
    pub locality: ModelLocality,
    pub payer: Payer,
    /// The host catalog revision this binding came from.
    pub catalog_revision: Option<String>,
    pub custody: KeyCustody,
    /// Token prices in the units of the lines this offer's calls land on.
    pub rates: Vec<UnitRate>,
}

impl OfferBinding {
    pub(super) fn dispatch_binding(&self) -> DispatchBinding {
        DispatchBinding {
            subject: self.model.as_str().to_owned(),
            route: self.route.key(),
            locality: self.locality,
        }
    }
}

/// A paid service that is not a model (a search, a GPU job), as the host
/// bound it, with the per-unit cost its pack row names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidConnector {
    pub connector: String,
    pub route: OfferRoute,
    pub locality: ModelLocality,
    pub payer: Payer,
    pub catalog_revision: Option<String>,
    pub custody: KeyCustody,
    /// What one unit of this service costs, in `cost_unit`.
    pub unit_cost: u64,
    pub cost_unit: LeaseUnit,
    pub rates: Vec<UnitRate>,
}

impl PaidConnector {
    pub(super) fn dispatch_binding(&self) -> DispatchBinding {
        DispatchBinding {
            subject: self.connector.clone(),
            route: self.route.key(),
            locality: self.locality,
        }
    }
}

/// Which allocation a lease draws on: its id and generation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AllocationRef {
    pub id: String,
    pub generation: u64,
}

/// The money one vault may commit, as the host issued it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub reference: AllocationRef,
    pub units: u64,
    pub unit: LeaseUnit,
}

/// Why the host refused a vault a fresh allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AllocationRefusal {
    /// The host asked the account owner a question and holds new host-paid
    /// allocations until it is answered. Admitted work finishes.
    HostCheck,
}

/// What the host says about the account right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStatus {
    pub allocation: Option<AllocationRef>,
    pub fresh_allocation_refused: Option<AllocationRefusal>,
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

/// One vault's host-paid money and account status, shared by every run the
/// vault admits.
#[derive(Debug, Default)]
pub struct HostAccount {
    state: Mutex<AccountState>,
}

#[derive(Debug, Default)]
struct AccountState {
    live: Option<LiveAllocation>,
    newest_generation: Option<u64>,
    refused: Option<AllocationRefusal>,
}

#[derive(Debug, Clone)]
pub(super) struct LiveAllocation {
    pub(super) reference: AllocationRef,
    pub(super) unit: LeaseUnit,
    pub(super) meter: BudgetGuard,
}

impl HostAccount {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Installs a fresh allocation. Leases on the one it replaces still
    /// settle there.
    pub fn grant(&self, allocation: Allocation) -> Result<(), AllocationGrantError> {
        let mut state = self.lock();
        if state
            .newest_generation
            .is_some_and(|newest| allocation.reference.generation <= newest)
        {
            return Err(AllocationGrantError::StaleGeneration);
        }
        state.newest_generation = Some(allocation.reference.generation);
        let meter = BudgetGuard::with_reserve_units(
            format!(
                "allocation:{}:{}",
                allocation.reference.id, allocation.reference.generation
            ),
            allocation.units,
            1,
            BudgetExhaustionPolicy::Suspend,
        );
        state.live = Some(LiveAllocation {
            reference: allocation.reference,
            unit: allocation.unit,
            meter,
        });
        Ok(())
    }

    /// The host holds fresh allocations for `reason`. What is left of the
    /// live one stays spendable.
    pub fn refuse_fresh(&self, reason: AllocationRefusal) {
        self.lock().refused = Some(reason);
    }

    /// The host lifts its hold.
    pub fn lift_refusal(&self) {
        self.lock().refused = None;
    }

    #[must_use]
    pub fn status(&self) -> AccountStatus {
        let state = self.lock();
        AccountStatus {
            allocation: state.live.as_ref().map(|live| live.reference.clone()),
            fresh_allocation_refused: state.refused,
        }
    }

    pub(super) fn live(&self) -> (Option<LiveAllocation>, Option<AllocationRefusal>) {
        let state = self.lock();
        (state.live.clone(), state.refused)
    }

    fn lock(&self) -> MutexGuard<'_, AccountState> {
        self.state.lock().expect("host account mutex poisoned")
    }
}
