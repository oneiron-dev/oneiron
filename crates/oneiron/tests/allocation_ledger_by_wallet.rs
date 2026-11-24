//! Row M2-I on the durable allocation ledger ([`VaultAllocationLedger`]):
//! one selection per slot (a unit and the wallet the host named), the
//! generation per allocation id, the funding Grant's wallet checked inside
//! the reserve writer, and a close that stops one selection only.

use std::sync::Arc;

use oneiron::federation::WalletRef;
use oneiron::llm::run_admission::{
    Allocation, AllocationCallKey, AllocationRef, AllocationStoreError, DurableAllocationHold,
    LeaseUnit, SelectedAllocation, UnitRate, VaultAllocationLedger,
};
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

fn reference(id: &str, generation: u64) -> AllocationRef {
    AllocationRef {
        id: id.to_owned(),
        generation,
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
        reference: reference(id, generation),
        units,
        unit: unit(in_unit),
        wallet,
    }
}

fn open() -> (tempfile::TempDir, Arc<VaultAllocationLedger>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault =
        Arc::new(Vault::open_owned(dir.path(), VaultConfig::default()).expect("owned vault"));
    let ledger = VaultAllocationLedger::new(vault).expect("ledger").value;
    (dir, ledger)
}

fn grant(ledger: &VaultAllocationLedger, allocation: Allocation) {
    let committed = ledger.grant(allocation).expect("grant");
    assert!(committed.postcommit_error.is_none());
}

fn key(lease: &str) -> AllocationCallKey {
    AllocationCallKey {
        instance: EntityId::now(),
        lease: lease.to_owned(),
    }
}

fn reserve(
    ledger: &VaultAllocationLedger,
    key: AllocationCallKey,
    units: u128,
    native: &str,
    rates: &[UnitRate],
    funding: Option<&WalletRef>,
) -> Result<DurableAllocationHold, AllocationStoreError> {
    ledger
        .reserve(
            key,
            units,
            &unit(native),
            rates,
            None,
            funding,
            |_txn, _hold| Ok(()),
        )
        .map(|committed| committed.value.0)
}

fn refused(result: Result<DurableAllocationHold, AllocationStoreError>) -> AllocationStoreError {
    match result {
        Ok(hold) => panic!("expected a refusal, got a hold on {:?}", hold.allocation),
        Err(error) => error,
    }
}

/// Remaining units and accepting flag of each allocation, by reference.
fn balances(ledger: &VaultAllocationLedger) -> Vec<(AllocationRef, u64, bool)> {
    ledger
        .allocations()
        .expect("allocations")
        .into_iter()
        .map(|read| {
            (
                read.allocation.reference,
                read.remaining_units,
                read.accepting,
            )
        })
        .collect()
}

#[test]
fn two_slots_stay_selected_and_each_call_reserves_in_its_own_unit() {
    let (_dir, ledger) = open();
    grant(&ledger, allocation("money", 1, 100, MONEY, None));
    grant(
        &ledger,
        allocation("gpu-line", 1, 50, GPU, Some(wallet("lane"))),
    );

    let mut selected = ledger.status().expect("status").allocations;
    selected.sort_by(|a, b| a.reference.id.cmp(&b.reference.id));
    assert_eq!(
        selected,
        vec![
            SelectedAllocation {
                reference: reference("gpu-line", 1),
                unit: unit(GPU),
                wallet: Some(wallet("lane")),
            },
            SelectedAllocation {
                reference: reference("money", 1),
                unit: unit(MONEY),
                wallet: None,
            },
        ]
    );

    let money = reserve(&ledger, key("money-call"), 30, MONEY, &[], None).expect("money call");
    assert_eq!(money.allocation, reference("money", 1));
    let gpu = reserve(
        &ledger,
        key("gpu-call"),
        20,
        GPU,
        &[],
        Some(&wallet("lane")),
    )
    .expect("the lane's Grant reserves on its line");
    assert_eq!(gpu.allocation, reference("gpu-line", 1));
    assert_eq!(gpu.unit, unit(GPU));

    let mut rows = balances(&ledger);
    rows.sort_by(|a, b| a.0.id.cmp(&b.0.id));
    assert_eq!(
        rows,
        vec![
            (reference("gpu-line", 1), 30, true),
            (reference("money", 1), 70, true),
        ]
    );
}

#[test]
fn the_reserve_writer_checks_the_grants_wallet_and_never_guesses_one() {
    let (_dir, ledger) = open();
    grant(
        &ledger,
        allocation("line-a", 1, 100, GPU, Some(wallet("lane-a"))),
    );
    grant(
        &ledger,
        allocation("line-b", 1, 100, GPU, Some(wallet("lane-b"))),
    );
    let before = balances(&ledger);

    let other = key("other-wallet");
    assert!(matches!(
        refused(reserve(
            &ledger,
            other.clone(),
            10,
            GPU,
            &[],
            Some(&wallet("lane-c"))
        )),
        AllocationStoreError::WalletMismatch { .. }
    ));
    assert!(matches!(
        refused(reserve(&ledger, key("unfunded"), 10, GPU, &[], None)),
        AllocationStoreError::Ambiguous { .. }
    ));
    assert_eq!(balances(&ledger), before, "a refusal reserves nothing");
    assert_eq!(ledger.hold(&other).expect("hold read"), None);

    let b = reserve(
        &ledger,
        key("lane-b"),
        10,
        GPU,
        &[],
        Some(&wallet("lane-b")),
    )
    .expect("lane b's Grant reserves on lane b's line");
    assert_eq!(b.allocation, reference("line-b", 1));
}

#[test]
fn a_close_stops_one_selection_and_a_spent_slot_never_falls_back() {
    let (_dir, ledger) = open();
    grant(&ledger, allocation("gpu-line", 1, 10, GPU, None));
    grant(&ledger, allocation("money", 1, 1_000, MONEY, None));
    let gpu_in_money = [UnitRate {
        unit: unit(MONEY),
        per: 1,
        cost: 1,
    }];
    assert!(matches!(
        refused(reserve(
            &ledger,
            key("too-long"),
            20,
            GPU,
            &gpu_in_money,
            None
        )),
        AllocationStoreError::Exhausted
    ));

    let closed = ledger.close(&reference("money", 1)).expect("close");
    assert!(closed.postcommit_error.is_none());
    assert!(matches!(
        refused(reserve(&ledger, key("money-closed"), 1, MONEY, &[], None)),
        AllocationStoreError::Closed
    ));
    reserve(&ledger, key("gpu-open"), 5, GPU, &[], None).expect("the gpu slot stays open");

    assert!(matches!(
        ledger.grant(allocation("money", 1, 1_000, MONEY, None)),
        Err(AllocationStoreError::StaleGeneration)
    ));
    grant(&ledger, allocation("money", 2, 1_000, MONEY, None));
    let fresh = reserve(&ledger, key("money-fresh"), 1, MONEY, &[], None).expect("generation 2");
    assert_eq!(fresh.allocation, reference("money", 2));
}
