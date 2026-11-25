//! Work orders on the server (pass 34, row Q1; rulings EM-19 and pass 33's one issuer, 8.7): an
//! order is made on the vault's issuer only, and the node, the start gate and the order name a
//! refusal with one code.
//!
//! Run on the fleet, not on a workstation:
//! ```sh
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test work_orders
//! ```
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::gpu_job::{GpuOffer, PriceShape};
use oneiron::job_workload::{TEMPLATE_CHANGED, TEMPLATE_NOT_OFFERED, WorkloadStartRefusal};
use oneiron::llm::ModelLocality;
use oneiron::llm::run_admission::{KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer};
use oneiron::work_order::Blocker;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::gpu_jobs::{AtMaximum, GpuOfferSettings};
use oneiron_server::gpu_execution_node::issuer::{VAULT_MACHINE_BACKEND, job_refusal_code};
use oneiron_server::gpu_execution_node::wire::{JobAnswer, JobRefusal, JobState};
use oneiron_server::server::SyncServer;
use oneiron_server::work_order_host::{dispatches_offer, facts_of_answer};

fn offer(name: &str) -> GpuOffer {
    GpuOffer {
        name: name.to_owned(),
        class: "machine".to_owned(),
        provider: "vault-machines".to_owned(),
        region: "home".to_owned(),
        connector: PaidConnector {
            connector: "vault-machines".to_owned(),
            route: OfferRoute::new("vault-machines", "https://machines.example.com")
                .expect("route"),
            locality: ModelLocality::ThirdParty,
            payer: Payer::Local,
            credential_binding: None,
            catalog_revision: None,
            custody: KeyCustody::T0,
            unit_cost: 1,
            cost_unit: LeaseUnit::new("credit-micros").expect("unit"),
            rates: Vec::new(),
        },
        price_shape: PriceShape::AtOneironList,
        list_cost_per_second: None,
        startup_secs: 0,
        teardown_secs: 0,
        rounding_secs: 0,
    }
}

#[test]
fn an_order_on_a_replica_that_is_not_the_issuer_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("vault"));
    let issuer = EntityId::now();
    let mut config = SyncServerConfig::default();
    config.gpu_jobs.vault_machine.enabled = true;
    config.gpu_jobs.vault_machine.issuer = Some(issuer);
    config.gpu_jobs.offers.insert(
        "home".to_owned(),
        GpuOfferSettings {
            backend: VAULT_MACHINE_BACKEND.to_owned(),
            offer: offer("home"),
            at_maximum: Some(AtMaximum::Stop),
        },
    );
    config.gpu_jobs.offers.insert(
        "cloud".to_owned(),
        GpuOfferSettings {
            backend: "skypilot".to_owned(),
            offer: offer("cloud"),
            at_maximum: None,
        },
    );
    let server = SyncServer::new(vault, config).expect("boot a replica that is not the issuer");
    let refused = dispatches_offer(&server, "home").expect_err("the replica makes no order");
    assert_eq!(refused.code(), "not_the_issuer");
    assert_eq!(
        refused,
        Blocker::NotTheIssuer {
            issuer: Some(issuer.to_hex())
        }
    );
    // An order on an offer whose backend is not the vault's own machines is not the issuer's
    // alone.
    assert!(dispatches_offer(&server, "cloud").is_ok());
}

#[test]
fn the_node_the_gate_and_the_order_name_a_refusal_with_one_code() {
    // Every node refusal keeps its code on the order.
    let node_refusals = [
        JobRefusal::NotEnabled,
        JobRefusal::PeerNotProven,
        JobRefusal::NotIssuer,
        JobRefusal::OwnGrantEnded,
        JobRefusal::IssuerStandingEnded,
        JobRefusal::Paused {
            why: "maintenance".to_owned(),
        },
        JobRefusal::Drained {
            why: "three fast failures".to_owned(),
        },
        JobRefusal::NotReleasable {
            state: JobState::Held,
        },
        JobRefusal::HistoryLost,
        JobRefusal::KeyConflict,
        JobRefusal::NotTheKeysIssuer,
        JobRefusal::SubmitSignatureInvalid,
        JobRefusal::DevicesUnreadable {
            why: "nvml".to_owned(),
        },
    ];
    for refusal in &node_refusals {
        assert_eq!(
            Blocker::from(refusal).code(),
            job_refusal_code(refusal),
            "{refusal:?}"
        );
    }
    // Every gate refusal keeps its code, and a node's reason the gate passes on is named by
    // the node's own code.
    let gate_refusals = [
        WorkloadStartRefusal::MachineMissing,
        WorkloadStartRefusal::WorkloadUnknown,
        WorkloadStartRefusal::WorkloadNotApproved,
        WorkloadStartRefusal::WorkloadWaiting,
        WorkloadStartRefusal::ComputeGrantEnded,
        WorkloadStartRefusal::WorkloadRevoked,
        WorkloadStartRefusal::WorkloadExpired,
        WorkloadStartRefusal::StarterNotNamed,
        WorkloadStartRefusal::RequestAbovePin,
        WorkloadStartRefusal::MachineNotApproved,
        WorkloadStartRefusal::MachineUnreachable {
            reason: "timeout".to_owned(),
        },
        WorkloadStartRefusal::MachineRefuses {
            reason: "the node says something new".to_owned(),
        },
    ];
    for refusal in &gate_refusals {
        assert_eq!(Blocker::from(refusal).code(), refusal.code(), "{refusal:?}");
    }
    for (reason, code) in [
        (TEMPLATE_CHANGED, TEMPLATE_CHANGED),
        (TEMPLATE_NOT_OFFERED, TEMPLATE_NOT_OFFERED),
        ("paused: maintenance", "paused"),
        ("drained", "drained"),
    ] {
        let gate = WorkloadStartRefusal::MachineRefuses {
            reason: reason.to_owned(),
        };
        assert_eq!(Blocker::from(&gate).code(), code, "{reason}");
    }
    // The order's reasons for a machine whose node refused are the node's codes too.
    let machine = EntityId::now();
    let paused = JobRefusal::Paused {
        why: "maintenance".to_owned(),
    };
    let facts = facts_of_answer(machine, Some(&JobAnswer::Refused(paused.clone())), 1);
    assert_eq!(
        facts.refusal.as_ref().map(Blocker::code),
        Some(job_refusal_code(&paused))
    );
}
