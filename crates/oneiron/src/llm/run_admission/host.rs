//! What a host feeds the run admission: the offers it bound, the money a
//! vault may commit and the account's status. Bindings and numbers, never a
//! rule list.
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use super::super::{BudgetExhaustionPolicy, BudgetGuard, DispatchBinding, ModelId, ModelLocality};
use super::declaration::LeaseUnit;
use super::resident::{ResidentLedger, Residents};
use crate::EntityId;
use crate::agent_dispatch::SpendScopeId;
use crate::federation::WalletRef;
pub use crate::store::resident_budget_rows::AllocationRef;

#[doc(hidden)]
pub use oneiron_records::llm::run_admission::host::{
    Allocation, AllocationGrantError, KeyCustody, OfferRouteError, Payer, PayerAccount, UnitRate,
};
#[doc(hidden)]
use oneiron_records::llm::run_admission::host::{WEB_SCHEMES, identity, is_authority};

/// Who funds a call that a room's root spend scope pays for (OF-531): the
/// PERSON whose consent the root carries, that root, and the billing account
/// the call bills. The host binds it before the run starts, from the scope's
/// root and its own account map; a caller never names it. Which provider
/// credential sends the call stays [`Payer`]. A kept media job keeps the one
/// it was submitted under, so its take-up bills it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayerPerson {
    pub person: EntityId,
    /// The root spend scope whose payer consent names `person`, for audit.
    pub root_scope: SpendScopeId,
    pub account: PayerAccount,
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

/// The one route id every model input mints (FIX 11768): `model@place`,
/// the model's full [`ModelId`] and the place [`offer_place`] names for
/// its locality and origin. A [`ModelId`] already holds `@` (its revision
/// separator), so an id holds two (`acme/gpt@7@api.example.com`): callers
/// compare whole strings, never parse. The ladder and the seat birth both
/// mint through this one fn, so the ids they judge against a world's order
/// are byte-identical.
///
/// Over the 128-byte route cap the id keeps its head and names its tail by
/// digest (lead pick under Engine delegation, rule 5: never drop the
/// host): a prefix cut on a char boundary to at most 119 bytes, then `-`,
/// then the first 8 lowercase hex chars of `blake3` over the full id
/// bytes. Deterministic: the same model and place always mint the same id,
/// truncated or not.
#[must_use]
pub fn offer_id(model: &ModelId, place: &str) -> String {
    let full = format!("{}@{}", model.as_str(), place);
    if full.len() <= 128 {
        return full;
    }
    let mut end = 119.min(full.len());
    while end > 0 && !full.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}-{}",
        &full[..end],
        &blake3::hash(full.as_bytes()).to_hex()[..8]
    )
}

/// The place an [`offer_id`] names for a binding (FIX 11768): one fn, so
/// the ladder's full ids and the seat's pre-filter spell every place the
/// same way. An on-device binding names `on_device`
/// ([`ModelLocality::as_str`]). Anywhere else names the origin's
/// authority: the scheme dropped (everything through `://`), cut at the
/// first `/`, `?` or `#`, kept host[:port] byte-for-byte (no case folding;
/// an `@` keeps only what follows its last run, as userinfo would). Real
/// origins today are the `[models]` providers' `base_url` origins
/// (`reqwest::Url::origin().ascii_serialization()`, so
/// `scheme://host[:port]`), `mesh:<hex>` mesh peers, `gpu:<region>` pod
/// pools, `host` host-injected and trainer routes, and `https://...`
/// web-connector providers. An empty origin on a non-local offer falls back
/// to the locality wire spelling, a place the receipt cannot name better.
#[must_use]
pub fn offer_place(locality: ModelLocality, origin: &str) -> String {
    if locality == ModelLocality::OnDevice || origin.is_empty() {
        return locality.as_str().to_owned();
    }
    let authority = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    let authority = &authority[..end];
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if authority.is_empty() {
        return locality.as_str().to_owned();
    }
    authority.to_owned()
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OfferBinding {
    pub offer: String,
    pub model: ModelId,
    pub route: OfferRoute,
    pub locality: ModelLocality,
    pub payer: Payer,
    /// The host's id for the credential binding that pays for this offer's
    /// calls: a name for the key's record, never the key. `None` for a
    /// keyless offer.
    pub credential_binding: Option<String>,
    /// The host catalog revision this binding came from.
    pub catalog_revision: Option<String>,
    pub custody: KeyCustody,
    /// Token prices in the units of the lines this offer's calls land on.
    pub rates: Vec<UnitRate>,
    /// Who funds the call when a room's root spend scope pays for it. The
    /// host binds none; a funded run binds its own payer into each offer it
    /// admits and gates, so the offer's identity carries it. `None` for a
    /// call no room pays for, which the vault owner funds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer_person: Option<PayerPerson>,
}

impl OfferBinding {
    /// The same full binding identity that permits and gates compare.
    /// A fingerprint identifies an offer; it grants no permission to use it.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        identity(self)
    }

    pub(super) fn dispatch_binding(&self) -> DispatchBinding {
        DispatchBinding {
            subject: self.model.as_str().to_owned(),
            route: self.route.key(),
            locality: self.locality,
            offer: identity(self),
            request_digest: None,
        }
    }
}

/// A paid service that is not a model (a search, a GPU job), as the host
/// bound it, with the per-unit cost its pack row names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaidConnector {
    pub connector: String,
    pub route: OfferRoute,
    pub locality: ModelLocality,
    pub payer: Payer,
    /// The host's id for the credential binding that pays for this
    /// connector's calls, never the key.
    pub credential_binding: Option<String>,
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
            offer: identity(self),
            request_digest: None,
        }
    }
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

/// One vault's host-paid money and account status, shared by every run the
/// vault admits.
#[derive(Debug, Default)]
pub struct HostAccount {
    state: Mutex<AccountState>,
    /// Each resident's share of the allocation (FIX 7767), when the host
    /// keeps them.
    residents: Option<Arc<Residents>>,
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
    /// The wallet the host named for this allocation (FIX 7766).
    pub(super) wallet: Option<WalletRef>,
}

impl HostAccount {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// An account whose residents each hold a share of its allocation, kept
    /// in `ledger` (FIX 7767): a soft share by default, which a call may
    /// overdraw with a receipt, or one the owner pinned.
    #[must_use]
    pub fn with_residents(ledger: Arc<dyn ResidentLedger>) -> Arc<Self> {
        Arc::new(Self {
            residents: Some(Residents::new(ledger)),
            ..Self::default()
        })
    }

    pub(super) fn residents(&self) -> Option<&Arc<Residents>> {
        self.residents.as_ref()
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
            wallet: allocation.wallet,
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
