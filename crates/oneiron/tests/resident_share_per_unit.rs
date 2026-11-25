//! Row RESIDENT-SHARE-NO-UNIT (Engine RESIDENT-SHARE-UNIT = A, 25 Nov 19:27): the owner sets
//! a resident's share per walletless unit.
//!
//! - A share binds only the host's walletless allocation in its own unit, so two walletless
//!   units each keep their own number and pin.
//! - A walletless unit with no share splits by the default soft share and is never pinned.
//! - A set that names no unit names the one walletless unit; with two it is refused with
//!   `unit_required`.
//! - A share stored before shares named a unit is a share in `micro_usd` only.
//! - The owner's view lists one block per walletless allocation.
//!
//! Compiled with `--cfg oneiron_test_support` (the door that writes a share row in its stored
//! shape from before shares named a unit).
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::WalletRef;
use oneiron::llm::run_admission::resident_doors::{
    ResidentSharesRequest, ResidentSharesView, SetResidentShareRequest,
    resident_shares_on_account_as_owner, set_resident_share_on_account_as_owner,
};
use oneiron::llm::run_admission::{
    AccountStatus, Allocation, AllocationRef, BudgetLine, CallOutcome, HostAccount, KeyCustody,
    LeaseUnit, MemoryReceipts, OfferRoute, PaidConnector, Payer, ResidentShare, RunAdmission,
    RunDeclaration, RunDenied, RunPermit, RunReceiptSink,
};
use oneiron::llm::{BudgetExhaustionPolicy, BudgetGuard, ModelLocality, VaultResidentLedger};
use oneiron::test_doors::resident_share_rows::put_unitless_resident_share;
use oneiron::{EntityId, Vault, VaultConfig};

const MONEY: &str = "micro_usd";
const GPU: &str = "gpu_seconds";

fn unit(name: &str) -> LeaseUnit {
    LeaseUnit::new(name).expect("unit")
}

fn allocation(id: &str, units: u64, in_unit: &str, wallet: Option<WalletRef>) -> Allocation {
    Allocation {
        reference: AllocationRef {
            id: id.to_owned(),
            generation: 1,
        },
        units,
        unit: unit(in_unit),
        wallet,
    }
}

/// A host-paid connector whose one unit costs one `cost_unit`.
fn connector(name: &str, cost_unit: &str) -> PaidConnector {
    PaidConnector {
        connector: name.to_owned(),
        route: OfferRoute::new(name, "https://paid.example.com").expect("route"),
        locality: ModelLocality::ThirdParty,
        payer: Payer::Host,
        credential_binding: Some(format!("{name}-key")),
        catalog_revision: Some("prices-1".to_owned()),
        custody: KeyCustody::T0,
        unit_cost: 1,
        cost_unit: unit(cost_unit),
        rates: Vec::new(),
    }
}

/// An unfunded run of `resident` on its own wide line in `connector`'s unit, so only the host's
/// allocation and the resident's share can refuse.
fn admit(
    connector: &PaidConnector,
    account: &Arc<HostAccount>,
    resident: EntityId,
    units: u64,
) -> Result<RunPermit, RunDenied> {
    let line = BudgetLine {
        limit_units: 1_000_000,
        reserve_units: 1,
        unit: connector.cost_unit.clone(),
    };
    let declaration = RunDeclaration::declared(line).with_connector(connector.connector.clone());
    let meter = BudgetGuard::with_reserve_units(
        format!("run-{}", connector.connector),
        1_000_000,
        1,
        BudgetExhaustionPolicy::Suspend,
    );
    let receipts = Arc::new(MemoryReceipts::default()) as Arc<dyn RunReceiptSink>;
    RunAdmission::with_funding(
        format!("run-{}", connector.connector),
        declaration,
        meter,
        Some(Arc::clone(account)),
        receipts,
        None,
        None,
    )
    .initiated_by(Some(resident))
    .admit_paid(connector, units)
}

fn spent_in(denied: RunDenied) -> (EntityId, LeaseUnit, u64) {
    match denied {
        RunDenied::ResidentShareSpent {
            resident,
            unit,
            needed_units,
        } => (resident, unit, needed_units),
        other => panic!("a pinned share refuses typed: {other:?}"),
    }
}

fn vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("vault"));
    (dir, vault)
}

fn owner(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof")
}

/// A host account over the vault's resident ledger that selects a walletless money allocation
/// and a walletless GPU seconds allocation, 1,000 units each.
fn two_walletless_units(vault: &Arc<Vault>) -> Arc<HostAccount> {
    let account = HostAccount::with_residents(VaultResidentLedger::new(Arc::clone(vault)));
    account
        .grant(allocation("host-money", 1_000, MONEY, None))
        .expect("walletless money");
    account
        .grant(allocation("host-gpu", 1_000, GPU, None))
        .expect("walletless gpu seconds");
    account
}

/// The resident's (units, pinned) in the view's block for `in_unit`.
fn shown(view: &ResidentSharesView, in_unit: &str, resident: EntityId) -> (Option<u64>, bool) {
    let block = view
        .allocations
        .iter()
        .find(|block| block.unit == in_unit)
        .unwrap_or_else(|| panic!("a block for {in_unit}: {view:?}"));
    let row = block
        .residents
        .iter()
        .find(|row| row.resident == resident.to_hex())
        .unwrap_or_else(|| panic!("the resident in the {in_unit} block: {view:?}"));
    (row.units, row.pinned)
}

fn set_request(resident: EntityId, units: u64, in_unit: Option<&str>) -> SetResidentShareRequest {
    SetResidentShareRequest {
        resident: resident.to_hex(),
        units: Some(units),
        pinned: true,
        unit: in_unit.map(str::to_owned),
    }
}

#[test]
fn two_walletless_units_each_keep_their_own_number_and_pin() {
    let (_dir, vault) = vault();
    let resident = EntityId::now();
    vault
        .set_resident_share(
            resident,
            &unit(MONEY),
            ResidentShare {
                units: Some(5),
                pinned: true,
            },
        )
        .expect("the owner pins 5 micro_usd");
    vault
        .set_resident_share(
            resident,
            &unit(GPU),
            ResidentShare {
                units: Some(50),
                pinned: true,
            },
        )
        .expect("the owner pins 50 gpu seconds");
    let account = two_walletless_units(&vault);
    let (search, gpu) = (connector("search", MONEY), connector("gpu", GPU));

    let (refused, in_unit, needed) =
        spent_in(admit(&search, &account, resident, 10).expect_err("10 past a pin of 5"));
    assert_eq!((refused, in_unit, needed), (resident, unit(MONEY), 10));

    let gpu_call = admit(&gpu, &account, resident, 40)
        .expect("40 gpu seconds fit the gpu pin of 50, not the money pin of 5");
    gpu_call.settle(CallOutcome::Used(40)).expect("settles");
    let (_, in_unit, needed) =
        spent_in(admit(&gpu, &account, resident, 20).expect_err("40 + 20 past a pin of 50"));
    assert_eq!((in_unit, needed), (unit(GPU), 60));

    let money_call = admit(&search, &account, resident, 5).expect("5 fits the money pin");
    money_call.settle(CallOutcome::Used(5)).expect("settles");

    let view = resident_shares_on_account_as_owner(
        &vault,
        &owner(&vault),
        &ResidentSharesRequest {},
        &account.status(),
    )
    .expect("server view");
    assert_eq!(
        view.allocations.len(),
        2,
        "one block per walletless allocation"
    );
    assert_eq!(shown(&view, MONEY, resident), (Some(5), true));
    assert_eq!(shown(&view, GPU, resident), (Some(50), true));
    let gpu_block = view
        .allocations
        .iter()
        .find(|block| block.unit == GPU)
        .expect("gpu block");
    let row = gpu_block
        .residents
        .iter()
        .find(|row| row.resident == resident.to_hex())
        .expect("row");
    assert_eq!(
        (row.allocation.as_deref(), row.used_units),
        (Some("host-gpu"), 40),
        "the gpu block shows the gpu allocation's depletion only"
    );
}

#[test]
fn a_walletless_unit_with_no_share_is_never_pinned() {
    let (_dir, vault) = vault();
    let resident = EntityId::now();
    vault
        .set_resident_share(
            resident,
            &unit(MONEY),
            ResidentShare {
                units: Some(5),
                pinned: true,
            },
        )
        .expect("the owner pins 5 micro_usd only");
    let account = two_walletless_units(&vault);
    let gpu = connector("gpu", GPU);
    let permit = admit(&gpu, &account, resident, 600)
        .expect("no gpu share: the default soft split admits 600, past it as an overdraft");
    permit.settle(CallOutcome::Used(600)).expect("settles");
    let permit = admit(&gpu, &account, resident, 300).expect("still never pinned");
    permit.settle(CallOutcome::Used(300)).expect("settles");
}

#[test]
fn a_set_with_no_unit_names_the_one_walletless_unit_and_is_refused_with_two() {
    let (_dir, vault) = vault();
    let owner = owner(&vault);
    let resident = EntityId::now();

    let one = HostAccount::with_residents(VaultResidentLedger::new(Arc::clone(&vault)));
    one.grant(allocation("host-gpu", 1_000, GPU, None))
        .expect("walletless gpu seconds");
    one.grant(allocation(
        "lane-money",
        1_000,
        MONEY,
        Some(WalletRef {
            issuer: "host".to_owned(),
            id: "lane".to_owned(),
        }),
    ))
    .expect("a wallet's money is no walletless unit");
    let view = set_resident_share_on_account_as_owner(
        &vault,
        &owner,
        &set_request(resident, 7, None),
        &one.status(),
    )
    .expect("one walletless unit: the set names it");
    assert_eq!(view.allocations.len(), 1, "{view:?}");
    assert_eq!(shown(&view, GPU, resident), (Some(7), true));
    let gpu = connector("gpu", GPU);
    let (_, in_unit, needed) =
        spent_in(admit(&gpu, &one, resident, 8).expect_err("8 past the gpu pin of 7"));
    assert_eq!((in_unit, needed), (unit(GPU), 8));

    let two = two_walletless_units(&vault);
    let refused = set_resident_share_on_account_as_owner(
        &vault,
        &owner,
        &set_request(resident, 9, None),
        &two.status(),
    )
    .expect_err("two walletless units: the set must name one");
    assert!(refused.to_string().contains("unit_required"), "{refused}");
    let view = set_resident_share_on_account_as_owner(
        &vault,
        &owner,
        &set_request(resident, 9, Some(MONEY)),
        &two.status(),
    )
    .expect("a set naming its unit");
    assert_eq!(shown(&view, MONEY, resident), (Some(9), true));
    assert_eq!(
        shown(&view, GPU, resident),
        (Some(7), true),
        "the refused set wrote nothing, and the money set left the gpu share"
    );

    let none = HostAccount::with_residents(VaultResidentLedger::new(Arc::clone(&vault)));
    let refused = set_resident_share_on_account_as_owner(
        &vault,
        &owner,
        &set_request(resident, 1, None),
        &none.status(),
    )
    .expect_err("no walletless unit: the set must name one");
    assert!(refused.to_string().contains("unit_required"), "{refused}");
}

#[test]
fn a_share_stored_with_no_unit_binds_micro_usd_only() {
    let (_dir, vault) = vault();
    let resident = EntityId::now();
    put_unitless_resident_share(
        &vault,
        resident,
        ResidentShare {
            units: Some(5),
            pinned: true,
        },
    )
    .expect("a share row in its shape from before shares named a unit");
    let account = two_walletless_units(&vault);
    let (search, gpu) = (connector("search", MONEY), connector("gpu", GPU));

    let (_, in_unit, needed) =
        spent_in(admit(&search, &account, resident, 10).expect_err("the stored pin is micro_usd"));
    assert_eq!((in_unit, needed), (unit(MONEY), 10));
    let permit = admit(&gpu, &account, resident, 600).expect("and no gpu seconds pin");
    permit.settle(CallOutcome::Used(600)).expect("settles");

    let status: AccountStatus = account.status();
    let view = resident_shares_on_account_as_owner(
        &vault,
        &owner(&vault),
        &ResidentSharesRequest {},
        &status,
    )
    .expect("server view");
    assert_eq!(shown(&view, MONEY, resident), (Some(5), true));
    assert_eq!(shown(&view, GPU, resident), (None, false));
}
