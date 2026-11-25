//! Row M2-I (allocations by wallet): one host account selects one live
//! allocation per slot, a slot being a unit and the wallet the host named.
//! A host-paid call holds on the slot of its own unit (and, for a run an
//! owner's agent Grant funds, of that Grant's wallet) and never falls back
//! to another slot. Generations are per allocation id, so a GPU line's
//! first period installs beside an older money allocation. The owner's
//! resident pin binds the host's walletless allocation only: it never
//! becomes a pin in a wallet's GPU seconds.

use std::sync::Arc;

use oneiron::agent_dispatch::GrantSpendBinding;
use oneiron::federation::WalletRef;
use oneiron::llm::run_admission::resident_doors::{
    ResidentShareView, ResidentSharesRequest, ResidentSharesView, resident_shares_as_owner,
    resident_shares_on_account_as_owner,
};
use oneiron::llm::run_admission::{
    Allocation, AllocationGrantError, AllocationRef, BudgetLine, CallOutcome, HostAccount,
    KeyCustody, LeaseUnit, MemoryReceipts, OfferRoute, PaidConnector, Payer, ResidentShare,
    RunAdmission, RunDeclaration, RunDenied, RunPermit, RunReceiptSink, UnitRate,
};
use oneiron::llm::{BudgetExhaustionPolicy, BudgetGuard, ModelLocality, VaultResidentLedger};
use oneiron::{EntityId, Vault, VaultConfig};

const MONEY: &str = "micro_usd";
const GPU: &str = "gpu_seconds";

fn unit(name: &str) -> LeaseUnit {
    LeaseUnit::new(name).expect("unit")
}

fn wallet(id: &str) -> WalletRef {
    WalletRef {
        issuer: "host".to_owned(),
        id: id.to_owned(),
    }
}

fn allocation(
    id: &str,
    generation: u64,
    units: u64,
    in_unit: &str,
    wallet: Option<WalletRef>,
) -> Allocation {
    Allocation {
        reference: AllocationRef {
            id: id.to_owned(),
            generation,
        },
        units,
        unit: unit(in_unit),
        wallet,
    }
}

/// A host-paid connector whose one unit costs one `cost_unit`, with `rates`
/// into other units.
fn connector(name: &str, cost_unit: &str, rates: Vec<UnitRate>) -> PaidConnector {
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
        rates,
    }
}

fn search() -> PaidConnector {
    connector("search", MONEY, Vec::new())
}

fn gpu() -> PaidConnector {
    connector("gpu", GPU, Vec::new())
}

/// A GPU connector that a rate also prices in money.
fn gpu_priced_in_money() -> PaidConnector {
    connector(
        "gpu",
        GPU,
        vec![UnitRate {
            unit: unit(MONEY),
            per: 1,
            cost: 1,
        }],
    )
}

fn binding(wallet_ref: WalletRef) -> GrantSpendBinding {
    GrantSpendBinding {
        grant_ref: EntityId::now(),
        mint_act: "a".repeat(64),
        wallet_ref,
    }
}

/// A run on its own line in `connector`'s unit, wide enough that only the
/// host's allocation can refuse, funded by `funding` when given.
fn run(
    connector: &PaidConnector,
    account: &Arc<HostAccount>,
    funding: Option<WalletRef>,
) -> RunAdmission {
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
        funding.map(binding),
    )
}

fn held_on(permit: &RunPermit) -> (String, u64, Option<LeaseUnit>) {
    let facts = permit.facts();
    let reference = facts
        .allocation
        .clone()
        .expect("a host-paid permit holds an allocation");
    (
        reference.id,
        reference.generation,
        facts.allocation_unit.clone(),
    )
}

/// The resident's row in the view's block for `in_unit`.
fn unit_row<'a>(
    view: &'a ResidentSharesView,
    in_unit: &str,
    resident: EntityId,
) -> &'a ResidentShareView {
    view.allocations
        .iter()
        .find(|block| block.unit == in_unit)
        .and_then(|block| {
            block
                .residents
                .iter()
                .find(|row| row.resident == resident.to_hex())
        })
        .unwrap_or_else(|| panic!("the resident's row in the {in_unit} block: {view:?}"))
}

fn kind(denied: &RunDenied) -> String {
    serde_json::to_value(denied).expect("denial serializes")["kind"]
        .as_str()
        .expect("tagged")
        .to_owned()
}

#[test]
fn a_money_allocation_and_a_gpu_seconds_allocation_are_both_live() {
    let account = HostAccount::new();
    account
        .grant(allocation("money", 1, 100, MONEY, None))
        .expect("money grant");
    account
        .grant(allocation("gpu-line", 2, 50, GPU, Some(wallet("lane"))))
        .expect("a gpu line in its own unit and wallet installs beside it");

    let search = search();
    let paid = run(&search, &account, None)
        .admit_paid(&search, 30)
        .expect("a money call holds on the money allocation");
    assert_eq!(held_on(&paid), ("money".to_owned(), 1, Some(unit(MONEY))));

    let gpu = gpu();
    let unit_run = run(&gpu, &account, Some(wallet("lane")))
        .admit_paid(&gpu, 20)
        .expect("a gpu call funded by the lane's wallet holds on the line");
    assert_eq!(
        held_on(&unit_run),
        ("gpu-line".to_owned(), 2, Some(unit(GPU)))
    );

    paid.settle(CallOutcome::Used(30)).expect("money settles");
    unit_run.settle(CallOutcome::Used(20)).expect("gpu settles");
}

#[test]
fn a_generation_is_newer_only_against_its_own_allocation_id() {
    let account = HostAccount::new();
    account
        .grant(allocation("money", 7, 100, MONEY, None))
        .expect("money at generation 7");
    account
        .grant(allocation("gpu-line", 1, 50, GPU, Some(wallet("lane"))))
        .expect("another id starts at its own generation 1");
    assert_eq!(
        account.grant(allocation("gpu-line", 1, 50, GPU, Some(wallet("lane")))),
        Err(AllocationGrantError::StaleGeneration),
        "a consumed generation of one id cannot come back"
    );
    assert_eq!(
        account.grant(allocation("money", 6, 100, MONEY, None)),
        Err(AllocationGrantError::StaleGeneration),
        "nor an older one"
    );
    account
        .grant(allocation("money", 8, 100, MONEY, None))
        .expect("the money id's next generation");

    // The money id's new generation replaced only its own slot.
    let gpu = gpu();
    let permit = run(&gpu, &account, None)
        .admit_paid(&gpu, 10)
        .expect("the gpu line is still live");
    assert_eq!(
        held_on(&permit),
        ("gpu-line".to_owned(), 1, Some(unit(GPU)))
    );
    permit.settle(CallOutcome::Used(10)).expect("settles");
}

#[test]
fn a_spent_gpu_allocation_never_falls_back_to_money_through_a_rate() {
    let account = HostAccount::new();
    account
        .grant(allocation("gpu-line", 1, 10, GPU, None))
        .expect("gpu grant");
    account
        .grant(allocation("money", 2, 1_000, MONEY, None))
        .expect("money grant");

    let gpu = gpu_priced_in_money();
    assert_eq!(
        run(&gpu, &account, None)
            .admit_paid(&gpu, 20)
            .expect_err("20 gpu seconds do not fit a 10-second line"),
        RunDenied::AllocationExhausted
    );
    // The money allocation was not touched: all of it still fits one call.
    let search = search();
    let permit = run(&search, &account, None)
        .admit_paid(&search, 1_000)
        .expect("money untouched");
    assert_eq!(held_on(&permit), ("money".to_owned(), 2, Some(unit(MONEY))));
    permit.settle(CallOutcome::Used(1_000)).expect("settles");
}

#[test]
fn a_funded_run_holds_only_on_its_grants_wallet_and_an_unfunded_run_never_guesses() {
    let account = HostAccount::new();
    account
        .grant(allocation("line-a", 1, 100, GPU, Some(wallet("lane-a"))))
        .expect("lane a's line");
    account
        .grant(allocation("line-b", 2, 100, GPU, Some(wallet("lane-b"))))
        .expect("lane b's line, same unit, another wallet");
    let gpu = gpu();

    let a = run(&gpu, &account, Some(wallet("lane-a")))
        .admit_paid(&gpu, 10)
        .expect("lane a's Grant holds on lane a's line");
    assert_eq!(held_on(&a), ("line-a".to_owned(), 1, Some(unit(GPU))));
    let b = run(&gpu, &account, Some(wallet("lane-b")))
        .admit_paid(&gpu, 10)
        .expect("lane b's Grant holds on lane b's line");
    assert_eq!(held_on(&b), ("line-b".to_owned(), 2, Some(unit(GPU))));

    match run(&gpu, &account, Some(wallet("lane-c")))
        .admit_paid(&gpu, 10)
        .expect_err("no line of lane c's wallet")
    {
        RunDenied::AllocationWalletMismatch { expected, .. } => {
            assert_eq!(expected, wallet("lane-c"));
        }
        other => panic!("a third wallet is refused as a wallet mismatch: {other:?}"),
    }

    let unfunded = run(&gpu, &account, None)
        .admit_paid(&gpu, 10)
        .expect_err("two wallets' lines and no walletless one: the host named none");
    assert_eq!(kind(&unfunded), "allocation_ambiguous");

    // The host's walletless allocation in the unit is the unfunded default.
    account
        .grant(allocation("host-gpu", 3, 100, GPU, None))
        .expect("walletless gpu");
    let default = run(&gpu, &account, None)
        .admit_paid(&gpu, 10)
        .expect("an unfunded run takes the walletless allocation");
    assert_eq!(
        held_on(&default),
        ("host-gpu".to_owned(), 3, Some(unit(GPU)))
    );

    for permit in [a, b, default] {
        permit.settle(CallOutcome::Used(10)).expect("settles");
    }
}

#[test]
fn the_owners_pinned_share_binds_the_walletless_allocation_and_never_the_gpu_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("vault"));
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
        .expect("the owner pins 5 units");
    let account = HostAccount::with_residents(VaultResidentLedger::new(Arc::clone(&vault)));
    account
        .grant(allocation("money", 1, 1_000, MONEY, None))
        .expect("money grant");
    account
        .grant(allocation("gpu-line", 2, 1_000, GPU, Some(wallet("lane"))))
        .expect("gpu line grant");

    let search = search();
    match run(&search, &account, None)
        .initiated_by(Some(resident))
        .admit_paid(&search, 10)
        .expect_err("10 micro_usd past a pinned share of 5")
    {
        RunDenied::ResidentShareSpent {
            resident: refused, ..
        } => assert_eq!(refused, resident),
        other => panic!("the money pin refuses typed: {other:?}"),
    }

    let gpu = gpu();
    let permit = run(&gpu, &account, Some(wallet("lane")))
        .initiated_by(Some(resident))
        .admit_paid(&gpu, 600)
        .expect("the money pin is no pin of 5 gpu seconds");
    assert_eq!(
        held_on(&permit),
        ("gpu-line".to_owned(), 2, Some(unit(GPU)))
    );
    permit.settle(CallOutcome::Used(600)).expect("settles");
}

/// Review 10403 P1-1: the slots refuse a call before anything is
/// reserved, so a refused call leaves the run's line and its ladder as they
/// were: the next call that fits still fires every threshold it crosses.
#[test]
fn a_call_the_slots_refuse_leaves_the_runs_ladder_unfired() {
    let account = HostAccount::new();
    account
        .grant(allocation("money-b", 1, 1_000, MONEY, Some(wallet("b"))))
        .expect("wallet b's money");
    account
        .grant(allocation("money-c", 1, 1_000, MONEY, Some(wallet("c"))))
        .expect("wallet c's money");
    let search = search();
    let line = BudgetLine {
        limit_units: 100,
        reserve_units: 1,
        unit: search.cost_unit.clone(),
    };
    let declaration = RunDeclaration::declared(line).with_connector(search.connector.clone());
    let meter =
        BudgetGuard::with_reserve_units("run-ladder", 100, 1, BudgetExhaustionPolicy::Suspend);
    let receipts = Arc::new(MemoryReceipts::default()) as Arc<dyn RunReceiptSink>;
    let run = RunAdmission::with_funding(
        "run-ladder".to_owned(),
        declaration,
        meter.clone(),
        Some(Arc::clone(&account)),
        receipts,
        None,
        None,
    );
    match run.admit_paid(&search, 100) {
        Ok(_) => panic!("two wallets serve money and the host named none"),
        Err(denied) => assert!(
            matches!(denied, RunDenied::AllocationAmbiguous { .. }),
            "{denied:?}"
        ),
    }
    let admission = meter
        .admit_reserve(100)
        .expect("the run's line is untouched");
    assert_eq!(
        admission.ladder_events.len(),
        3,
        "the refused call fired none of the line's thresholds: {:?}",
        admission.ladder_events
    );
}

/// Review 10403 P1-2: with no walletless allocation selected, the owner's
/// shares govern nothing, so the server's view shows each setting with no
/// depletion, never a named wallet's GPU seconds beside the pin. The
/// embedded view keeps each resident's newest charged generation.
#[test]
fn the_share_view_shows_no_named_wallets_usage_beside_the_owners_pin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("vault"));
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
        .expect("the owner pins 5 units");
    let account = HostAccount::with_residents(VaultResidentLedger::new(Arc::clone(&vault)));
    account
        .grant(allocation("gpu-line", 1, 1_000, GPU, Some(wallet("lane"))))
        .expect("gpu line grant");
    let gpu = gpu();
    run(&gpu, &account, Some(wallet("lane")))
        .initiated_by(Some(resident))
        .admit_paid(&gpu, 10)
        .expect("10 gpu seconds")
        .settle(CallOutcome::Used(10))
        .expect("settles");

    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof");
    let status = account.status();
    assert_eq!(status.walletless_allocations().count(), 0);
    let server =
        resident_shares_on_account_as_owner(&vault, &owner, &ResidentSharesRequest {}, &status)
            .expect("server view");
    assert_eq!(server.allocations.len(), 1, "one block, the money share's");
    let row = unit_row(&server, MONEY, resident);
    assert_eq!((row.units, row.pinned), (Some(5), true));
    assert_eq!(
        (
            row.allocation.as_deref(),
            row.used_units,
            row.overdraft_units
        ),
        (None, 0, 0),
        "no named wallet's usage beside the pin"
    );

    let embedded =
        resident_shares_as_owner(&vault, &owner, &ResidentSharesRequest {}).expect("embedded view");
    let row = unit_row(&embedded, MONEY, resident);
    assert_eq!(
        (row.allocation.as_deref(), row.used_units),
        (None, 0),
        "the embedded view: the newest charged generation in micro_usd, never the line's"
    );
}

/// A run on its own `limit`-unit line in `connector`'s unit, whose meter
/// the test keeps.
fn run_on_line(
    connector: &PaidConnector,
    account: &Arc<HostAccount>,
    limit: u64,
) -> (RunAdmission, BudgetGuard) {
    let line = BudgetLine {
        limit_units: limit,
        reserve_units: 1,
        unit: connector.cost_unit.clone(),
    };
    let declaration = RunDeclaration::declared(line).with_connector(connector.connector.clone());
    let meter = BudgetGuard::with_reserve_units(
        format!("line-{limit}"),
        limit,
        1,
        BudgetExhaustionPolicy::Suspend,
    );
    let receipts = Arc::new(MemoryReceipts::default()) as Arc<dyn RunReceiptSink>;
    let run = RunAdmission::with_funding(
        format!("line-{limit}"),
        declaration,
        meter.clone(),
        Some(Arc::clone(account)),
        receipts,
        None,
        None,
    );
    (run, meter)
}

/// Review 10403 round 2, P1-1: the allocation holds before the run's line,
/// so a call its allocation cannot fit leaves the line's ladder unfired.
#[test]
fn a_call_its_allocation_cannot_fit_leaves_the_runs_ladder_unfired() {
    let account = HostAccount::new();
    account
        .grant(allocation("money", 1, 1, MONEY, None))
        .expect("one unit of money");
    let search = search();
    let (run, meter) = run_on_line(&search, &account, 100);
    match run.admit_paid(&search, 100) {
        Ok(_) => panic!("one unit left in the allocation"),
        Err(denied) => assert!(
            matches!(denied, RunDenied::AllocationExhausted),
            "{denied:?}"
        ),
    }
    let admission = meter
        .admit_reserve(100)
        .expect("the run's line is untouched");
    assert_eq!(admission.ladder_events.len(), 3);
}

/// The other order: when the run's line refuses a call the allocation
/// already held, the allocation's hold and the resident's draw are released
/// uncharged, so the same room admits the next call.
#[test]
fn a_call_the_runs_line_refuses_releases_its_allocation_hold() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("vault"));
    let resident = EntityId::now();
    vault
        .set_resident_share(
            resident,
            &unit(MONEY),
            ResidentShare {
                units: Some(100),
                pinned: true,
            },
        )
        .expect("the owner pins 100 units");
    let account = HostAccount::with_residents(VaultResidentLedger::new(Arc::clone(&vault)));
    account
        .grant(allocation("money", 1, 100, MONEY, None))
        .expect("100 units of money");
    let search = search();
    let (narrow, _) = run_on_line(&search, &account, 50);
    match narrow.initiated_by(Some(resident)).admit_paid(&search, 100) {
        Ok(_) => panic!("the run's line holds 50"),
        Err(denied) => assert!(
            !matches!(
                denied,
                RunDenied::AllocationExhausted | RunDenied::ResidentShareSpent { .. }
            ),
            "the run's line refuses, not the allocation: {denied:?}"
        ),
    }
    let (wide, _) = run_on_line(&search, &account, 1_000);
    let permit = wide
        .initiated_by(Some(resident))
        .admit_paid(&search, 100)
        .expect("the allocation and the pinned share are whole again");
    assert_eq!(held_on(&permit), ("money".to_owned(), 1, Some(unit(MONEY))));
    permit.settle(CallOutcome::Used(100)).expect("settles");
}

/// Review 10403 round 2, P1-3: with walletless allocations in two units,
/// both enforce the owner's pin, and the server's view shows the one of the
/// highest generation, with its depletion.
#[test]
fn the_share_view_shows_each_walletless_allocation_in_its_own_block() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("vault"));
    let resident = EntityId::now();
    vault
        .set_resident_share(
            resident,
            &unit(MONEY),
            ResidentShare {
                units: Some(50),
                pinned: true,
            },
        )
        .expect("the owner pins 50 units");
    let account = HostAccount::with_residents(VaultResidentLedger::new(Arc::clone(&vault)));
    account
        .grant(allocation("money", 7, 1_000, MONEY, None))
        .expect("money at generation 7");
    let search = search();
    run(&search, &account, None)
        .initiated_by(Some(resident))
        .admit_paid(&search, 10)
        .expect("10 micro_usd")
        .settle(CallOutcome::Used(10))
        .expect("settles");
    account
        .grant(allocation("gpu", 1, 1_000, GPU, None))
        .expect("walletless gpu at generation 1");

    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof");
    let status = account.status();
    let view =
        resident_shares_on_account_as_owner(&vault, &owner, &ResidentSharesRequest {}, &status)
            .expect("server view");
    assert_eq!(view.allocations.len(), 2, "{view:?}");
    let row = unit_row(&view, MONEY, resident);
    assert_eq!(
        (
            row.units,
            row.allocation.as_deref(),
            row.allocation_generation,
            row.used_units
        ),
        (Some(50), Some("money"), Some(7), 10)
    );
    let row = unit_row(&view, GPU, resident);
    assert_eq!(
        (
            row.units,
            row.pinned,
            row.allocation.as_deref(),
            row.used_units
        ),
        (None, false, None, 0),
        "the money pin is no gpu seconds share"
    );
}
