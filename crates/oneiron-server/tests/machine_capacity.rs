#![cfg(oneiron_test_support)]
//! UNBUILT-14 PR 3a (CROSS-ARCH-0024 #my-network 01 and 05): this install
//! measures its machine (cores, memory, GPU memory, disk, power) and records
//! it on its own MACHINE entity as the engine-owned claim `machine.capacity`,
//! with the agents it can run: free memory after the reserve over the
//! per-agent budget. The record moves only when a total, the power source or
//! the agent count moves, and no public claim door writes it.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --no-fail-fast --test machine_capacity`.

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::machine_capacity::{
    AGENT_MEMORY_BUDGET_BYTES, MachineCapacity, MachineCapacityWrite, MachineMeasurement,
    MachinePower, PREDICATE_MACHINE_CAPACITY,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// Runs `test` on a thread with the engine's stack, as the server's binary
/// runs its work, so an enrolment's authority fold never meets a test
/// thread's default stack.
fn on_engine_stack(test: impl FnOnce() -> TestResult + Send + 'static) -> TestResult {
    let driver = std::thread::Builder::new()
        .stack_size(oneiron_server::ENGINE_THREAD_STACK_BYTES)
        .spawn(move || test().map_err(|error| error.to_string()))?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// A vault whose serving install is enrolled, as `serve` enrols it at start:
/// this install has its MACHINE row.
fn enrolled_vault() -> TestResult<(tempfile::TempDir, Vault, EntityId)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let machine = vault
        .local_machine()?
        .ok_or("the enrolled install names no machine")?
        .id;
    Ok((dir, vault, machine))
}

/// A 16 GiB, 8-core machine on mains power with `available` memory free.
fn sixteen_gib_machine(available: u64) -> MachineMeasurement {
    MachineMeasurement {
        cores: 8,
        memory_total_bytes: 16 * GIB,
        memory_available_bytes: available,
        gpu_memory_mib: vec![24_576],
        disk_total_bytes: 512 * GIB,
        disk_free_bytes: 100 * GIB,
        power: MachinePower::Mains,
    }
}

#[test]
fn the_probe_records_this_machines_measured_capacity_on_its_machine_entity() -> TestResult {
    on_engine_stack(|| {
        let (_dir, vault, machine) = enrolled_vault()?;
        assert_eq!(vault.machine_capacity(machine)?, None);

        let MachineCapacityWrite::Recorded(claim) =
            oneiron_server::machine_capacity::record_measured_capacity(&vault)?
        else {
            panic!("the first probe of an enrolled install records its capacity");
        };

        let body = vault
            .get_claim(&claim)?
            .ok_or("the recorded claim is stored")?;
        assert_eq!(body.predicate, PREDICATE_MACHINE_CAPACITY);
        assert!(
            matches!(body.subject, ClaimSubject::Entity(subject) if subject == machine),
            "the record is about this install's MACHINE entity"
        );
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);

        let recorded = vault
            .machine_capacity(machine)?
            .ok_or("the MACHINE entity reads its capacity")?;
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        assert_eq!(recorded.cores, u64::try_from(cores)?);
        assert_eq!(
            recorded.memory_total_bytes,
            oneiron::host_memory::memory_bytes().unwrap_or(0)
        );
        assert_eq!(
            recorded.memory_reserve_bytes,
            oneiron::host_memory::memory_reserve(recorded.memory_total_bytes)
        );
        assert_eq!(
            recorded.agent_memory_budget_bytes,
            AGENT_MEMORY_BUDGET_BYTES
        );
        assert_eq!(
            recorded.agents,
            recorded
                .memory_available_bytes
                .saturating_sub(recorded.memory_reserve_bytes)
                / AGENT_MEMORY_BUDGET_BYTES
        );
        assert!(recorded.disk_total_bytes > 0, "the data disk is measured");
        assert!(recorded.disk_free_bytes <= recorded.disk_total_bytes);
        assert!(recorded.measured_at > 0);
        Ok(())
    })
}

#[test]
fn agents_it_can_run_is_available_memory_after_the_reserve_over_the_agent_budget() {
    // About 0.45 GiB per active agent (CROSS-ARCH-0024 RAM budget table).
    assert_eq!(AGENT_MEMORY_BUDGET_BYTES, 483_183_820);

    // The reserve is a sixteenth of 16 GiB; 7 GiB over 0.45 GiB is 15.6.
    let capacity = MachineCapacity::from_measurement(sixteen_gib_machine(8 * GIB), 1_000);
    assert_eq!(capacity.memory_reserve_bytes, GIB);
    assert_eq!(
        capacity.agent_memory_budget_bytes,
        AGENT_MEMORY_BUDGET_BYTES
    );
    assert_eq!(capacity.agents, 15);
    assert_eq!(capacity.measured_at, 1_000);

    // Free memory under the reserve runs no agent.
    let full = MachineCapacity::from_measurement(sixteen_gib_machine(GIB / 2), 1_000);
    assert_eq!(full.agents, 0);

    // A small machine keeps the 256 MiB floor: 768 MiB over 0.45 GiB is 1.7.
    let small = MachineCapacity::from_measurement(
        MachineMeasurement {
            memory_total_bytes: 2 * GIB,
            memory_available_bytes: GIB,
            ..sixteen_gib_machine(0)
        },
        1_000,
    );
    assert_eq!(small.memory_reserve_bytes, 256 * MIB);
    assert_eq!(small.agents, 1);
}

#[test]
fn a_public_claim_write_cannot_record_machine_capacity() -> TestResult {
    on_engine_stack(|| {
        let (_dir, vault, machine) = enrolled_vault()?;
        let forged = MachineCapacity::from_measurement(sixteen_gib_machine(15 * GIB), 1_000);
        let body = ClaimBody::new(
            PREDICATE_MACHINE_CAPACITY,
            ClaimSubject::Entity(machine),
            forged.to_value(),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        let id = EntityId::now();
        let refused = vault.put_claim(&id, &body, TimeRange { start: 1, end: 1 }, 1);
        assert!(
            refused.is_err(),
            "the public claim door refuses machine.capacity"
        );
        assert_eq!(vault.get_claim(&id)?, None);
        assert_eq!(vault.machine_capacity(machine)?, None);
        Ok(())
    })
}

#[test]
fn an_unchanged_probe_writes_no_new_capacity_revision() -> TestResult {
    on_engine_stack(|| {
        let (_dir, vault, machine) = enrolled_vault()?;
        let first = MachineCapacity::from_measurement(sixteen_gib_machine(8 * GIB), 100);
        let MachineCapacityWrite::Recorded(standing) = vault.record_machine_capacity(&first)?
        else {
            panic!("the first record lands");
        };

        // An hour on: less disk free and a little more memory, the same agent
        // count. Nothing it records moved, so the record stands as it was.
        let later = MachineCapacity::from_measurement(
            MachineMeasurement {
                disk_free_bytes: 90 * GIB,
                ..sixteen_gib_machine(8 * GIB + 100 * MIB)
            },
            3_700,
        );
        assert_eq!(later.agents, first.agents);
        assert_eq!(
            vault.record_machine_capacity(&later)?,
            MachineCapacityWrite::Unchanged(standing)
        );
        assert_eq!(vault.machine_capacity(machine)?, Some(first.clone()));

        // Unplugged: the power source moved, so a new record supersedes it.
        let unplugged = MachineCapacity::from_measurement(
            MachineMeasurement {
                power: MachinePower::Battery,
                ..sixteen_gib_machine(8 * GIB)
            },
            7_300,
        );
        let MachineCapacityWrite::Recorded(on_battery) =
            vault.record_machine_capacity(&unplugged)?
        else {
            panic!("a moved power source records again");
        };
        assert_ne!(on_battery, standing);
        assert_eq!(
            vault.get_claim(&standing)?.map(|body| body.lifecycle),
            Some(ClaimLifecycleStatus::Superseded)
        );
        assert_eq!(vault.machine_capacity(machine)?, Some(unplugged.clone()));

        // Busy: the agent count moved.
        let busy = MachineCapacity::from_measurement(
            MachineMeasurement {
                power: MachinePower::Battery,
                ..sixteen_gib_machine(4 * GIB)
            },
            10_900,
        );
        assert_ne!(busy.agents, unplugged.agents);
        assert!(matches!(
            vault.record_machine_capacity(&busy)?,
            MachineCapacityWrite::Recorded(id) if id != on_battery
        ));
        assert_eq!(vault.machine_capacity(machine)?, Some(busy));
        Ok(())
    })
}

#[test]
fn an_install_with_no_machine_row_records_nothing() -> TestResult {
    on_engine_stack(|| {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::device())?;
        assert!(vault.local_machine()?.is_none());
        let capacity = MachineCapacity::from_measurement(sixteen_gib_machine(8 * GIB), 1_000);
        assert_eq!(
            vault.record_machine_capacity(&capacity)?,
            MachineCapacityWrite::NoMachine
        );
        assert!(
            vault.local_machine()?.is_none(),
            "the probe mints no machine"
        );
        Ok(())
    })
}
