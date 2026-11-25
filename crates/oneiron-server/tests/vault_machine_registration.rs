#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! R6 runbook B2: server start registers the `vault_machine` backend only where pass 33 (8.1
//! and 8.7) lets it exist, an enabled `[gpu_jobs.vault_machine]` on its issuer.
//!
//! Run on the fleet, not on a workstation:
//! ```sh
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test vault_machine_registration
//! ```

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::sync::Arc;

use engine_stack::run_on_engine_stack;
use mesh_machines::Machines;
use oneiron::EntityId;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::gpu_jobs::VaultMachineSettings;
use oneiron_server::gpu_execution_node::issuer::{
    VAULT_MACHINE_BACKEND, VaultMachineNotRegistered, register_vault_machine_at_start,
};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::gpu_backend::gpu_backend_registered;

fn issued_by(issuer: EntityId) -> SyncServerConfig {
    let mut config = SyncServerConfig::default();
    config.gpu_jobs.vault_machine = VaultMachineSettings {
        enabled: true,
        issuer: Some(issuer),
        ..VaultMachineSettings::default()
    };
    config
}

#[test]
fn server_start_registers_the_vault_machine_backend_only_on_its_enabled_issuer() {
    run_on_engine_stack("vault-machine-registration", || async move {
        // Both machines' servers name machine 0 as the issuer.
        let mesh = Machines::start_with(2, |_, machines| issued_by(machines[0]))
            .await
            .expect("two machines, both naming machine 0 as the issuer");
        let issuer = mesh.machine(0).device.machine;
        let replica = mesh.machine(1).device.machine;
        let on_issuer = Arc::clone(&mesh.machine(0).served.server);
        let on_replica = Arc::clone(&mesh.machine(1).served.server);
        let replica_vault = Arc::clone(&mesh.machine(1).device.vault);
        tokio::task::block_in_place(|| {
            assert!(
                !gpu_backend_registered(&on_issuer, VAULT_MACHINE_BACKEND),
                "nothing registers the backend before server start does",
            );
            register_vault_machine_at_start(&on_issuer)
                .expect("the enabled issuer registers the backend at start");
            assert!(
                gpu_backend_registered(&on_issuer, VAULT_MACHINE_BACKEND),
                "the issuer's offers now reach the vault_machine backend",
            );

            assert_eq!(
                register_vault_machine_at_start(&on_replica).err(),
                Some(VaultMachineNotRegistered::NotTheIssuer {
                    issuer: Some(issuer),
                    local: replica,
                }),
                "a replica that is not the issuer registers nothing",
            );
            assert!(
                !gpu_backend_registered(&on_replica, VAULT_MACHINE_BACKEND),
                "the replica's start answers no_backend",
            );

            let disabled = Arc::new(
                SyncServer::new(replica_vault, SyncServerConfig::default())
                    .expect("boot a server with the section off"),
            );
            assert_eq!(
                register_vault_machine_at_start(&disabled).err(),
                Some(VaultMachineNotRegistered::Disabled),
                "a disabled section registers nothing",
            );
            assert!(
                !gpu_backend_registered(&disabled, VAULT_MACHINE_BACKEND),
                "the section is off by default",
            );
        });
        drop((on_issuer, on_replica));
        mesh.stop().await;
    });
}
