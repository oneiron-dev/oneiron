//! Trusted host allocation intake. Startup and ctl use the same original
//! descriptor and native writer; neither mirrors a live remaining balance.

use std::fs::File;
use std::os::fd::FromRawFd;

use oneiron::llm::run_admission::{
    Allocation, AllocationRef, AllocationTerms, LeaseUnit, UnitRate,
};
use oneiron_vault_contract::allocation::AllocationDelivery;

use super::ManagedArgs;
use crate::server::SyncServer;

/// Consumes the inherited descriptor exactly once, after descriptor-alias
/// validation and before the vault opens. EOF terminates the single object.
pub(super) fn read(args: &ManagedArgs) -> anyhow::Result<Option<AllocationDelivery>> {
    let Some(fd) = args.allocation_fd else {
        return Ok(None);
    };
    // SAFETY: managed argv validation requires a non-negative descriptor that
    // aliases no other adopted input or listener. This is its sole adoption.
    let file = unsafe { File::from_raw_fd(fd) };
    Ok(Some(serde_json::from_reader(file)?))
}

/// Selects native usage before AI attachment or any worker starts. Without a
/// delivery the caller never reaches this function and keeps ordinary startup.
pub(super) fn bind(
    server: SyncServer,
    vault_name: &str,
    delivery: AllocationDelivery,
) -> anyhow::Result<SyncServer> {
    install(&server, vault_name, delivery)?;
    Ok(server)
}

/// Returns the native account revision of this transaction, not a money ACK or
/// a claim that the delivered allocation is still the current selection.
pub(super) fn install(
    server: &SyncServer,
    vault_name: &str,
    delivery: AllocationDelivery,
) -> anyhow::Result<u64> {
    anyhow::ensure!(
        delivery.vault_id == vault_name,
        "allocation names another managed vault"
    );
    let allocation = Allocation {
        reference: AllocationRef {
            id: delivery.allocation.id,
            generation: delivery.allocation.generation,
        },
        units: delivery.units,
        unit: LeaseUnit::new(delivery.unit)?,
    };
    let terms = AllocationTerms {
        usage_owner: delivery.usage_owner,
        rates: delivery
            .rates
            .into_iter()
            .map(|rate| {
                Ok(UnitRate {
                    unit: LeaseUnit::new(rate.unit)?,
                    per: rate.per,
                    cost: rate.cost,
                })
            })
            .collect::<Result<Vec<_>, oneiron::llm::run_admission::DeclarationError>>()?,
        issued_at: delivery.issued_at,
    };
    let commit = server.install_native_allocation(allocation, terms)?;
    if commit.postcommit_error.is_some() {
        tracing::error!(
            revision = commit.revision,
            "allocation install committed before later vault work failed"
        );
    }
    Ok(commit.revision)
}
