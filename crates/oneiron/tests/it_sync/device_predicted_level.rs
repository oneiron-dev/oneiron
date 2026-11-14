//! The predicted residence level (census L7-46 + L10-14; ARCH-0023b
//! #predicted-residence). The owner's `sync_predicted` directive is the
//! approval the home's predictions name (Engine ruling PLAN-SIGNER A, 14 Nov
//! 03:02) and carries the owner's budget: 32 windows and 128 entity
//! documents when the owner sets none, and no ceiling when the owner does
//! (L7-46-BUDGET B; L7-46-BUDGET-CEILING, 14 Nov 11:28). The machine runs the
//! level as opened on the wire plus a persisted predicted flag, which a
//! later mode act clears.
#![cfg(oneiron_test_support)]

use oneiron::authority::{
    HostSlipIssuer, RESIDENCE_PREDICTED_DOCUMENTS_DEFAULT, RESIDENCE_PREDICTED_WINDOWS_DEFAULT,
    ResidenceAct, ResidenceResultStatus,
};
use oneiron::sync::SyncResidenceMode;
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::residence::load_device_sync_preference;
use oneiron::task_verb::sdk::{ResidenceModeName, ResidenceModeRequest, ResidencePredictedBudget};
use oneiron::{EntityId, Vault};

use super::device_world_follow::{Device, FIXTURE_HOST_SECRET};

/// Runs `test` on a current-thread runtime with room for the engine's deep
/// stacks.
fn run_async<F>(name: &str, test: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    let run = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(test());
        })
        .expect("test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

fn local_machine(vault: &Vault) -> EntityId {
    vault
        .local_machine()
        .expect("the install's machine")
        .expect("a minted machine")
        .id
}

/// Issues `act` as the owner's residence directive to this device's own
/// machine, as the host door relays one; answers the directive's id.
fn issue(device: &Device, act: ResidenceAct) -> EntityId {
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST_SECRET).expect("fixture host issuer");
    device
        .vault
        .issue_residence_directive_as(
            &device.owner,
            &issuer,
            EntityId::now(),
            local_machine(&device.vault),
            act,
        )
        .expect("the owner's directive")
        .directive
        .id
}

fn result_of(device: &Device, directive: EntityId) -> Option<ResidenceResultStatus> {
    device
        .vault
        .residence_directive_as(&device.owner, directive)
        .expect("the owner's read-back")
        .expect("the directive")
        .result
        .map(|result| result.status)
}

fn mode_request(machine: EntityId, mode: &str, budget: Option<(u32, u32)>) -> ResidenceModeRequest {
    let mut input = serde_json::json!({ "machine": machine.to_hex(), "mode": mode });
    if let Some((windows, documents)) = budget {
        input["budget"] = serde_json::json!({ "windows": windows, "documents": documents });
    }
    serde_json::from_value(input).expect("a vault.residence.mode input")
}

#[test]
fn a_sync_predicted_directive_carries_the_owner_budget() {
    let device = Device::open();
    let machine = local_machine(&device.vault);

    let unset = mode_request(machine, "predicted", None);
    assert_eq!(unset.mode, ResidenceModeName::Predicted);
    assert_eq!(
        unset.act().expect("the predicted act"),
        ResidenceAct::SyncPredicted {
            window_budget: RESIDENCE_PREDICTED_WINDOWS_DEFAULT,
            document_budget: RESIDENCE_PREDICTED_DOCUMENTS_DEFAULT,
        },
    );
    assert_eq!(
        (
            RESIDENCE_PREDICTED_WINDOWS_DEFAULT,
            RESIDENCE_PREDICTED_DOCUMENTS_DEFAULT
        ),
        (32, 128),
    );
    let owner_budget = mode_request(machine, "predicted", Some((5_000, 2_000_000)));
    assert_eq!(
        owner_budget.budget,
        Some(ResidencePredictedBudget {
            windows: 5_000,
            documents: 2_000_000,
        }),
    );
    let act = owner_budget
        .act()
        .expect("no ceiling on the owner's number");
    assert!(
        mode_request(machine, "all", Some((1, 1))).act().is_err(),
        "a budget beside another mode is refused",
    );

    // Issued and read back through the signed, stored entry: the budget
    // survives, and the directive waits for its machine.
    let directive = issue(&device, act.clone());
    let states = device
        .vault
        .residence_directives_as(&device.owner, Some(machine))
        .expect("the owner's read-back");
    let state = states
        .iter()
        .find(|state| state.directive.id == directive)
        .expect("the issued directive");
    assert_eq!(state.directive.act, act);
    assert_eq!(state.directive.act.wire(), "sync_predicted");
    assert!(
        state.result.is_none(),
        "pending until its machine applies it"
    );
}

#[test]
fn a_machine_applies_the_predicted_level_as_opened_plus_prediction() {
    run_async(
        "a_machine_applies_the_predicted_level_as_opened_plus_prediction",
        || async {
            let device = Device::open();
            let directive = issue(
                &device,
                ResidenceAct::SyncPredicted {
                    window_budget: 8,
                    document_budget: 16,
                },
            );
            let connection = SyncConnection::new(device.manager(), ConnectionConfig::default())
                .expect("the device's connection");

            let finished =
                oneiron::test_doors::predicted_residence::apply_residence_directives(&connection)
                    .await
                    .expect("the directive runs");
            assert_eq!(finished, 1);
            assert_eq!(
                result_of(&device, directive),
                Some(ResidenceResultStatus::Applied)
            );
            let preference = load_device_sync_preference(&device.vault)
                .expect("the preference reads")
                .expect("the owner's choice is recorded");
            assert_eq!(preference.mode, SyncResidenceMode::Opened);
            assert!(
                preference.predicted,
                "the machine is at the predicted level"
            );
            assert_eq!(
                connection.residence_mode(),
                SyncResidenceMode::Opened,
                "the wire runs opened",
            );
        },
    );
}

#[test]
fn a_mode_switch_clears_the_predicted_flag() {
    run_async("a_mode_switch_clears_the_predicted_flag", || async {
        let device = Device::open();
        let connection = SyncConnection::new(device.manager(), ConnectionConfig::default())
            .expect("the device's connection");
        let predicted = |device: &Device| {
            load_device_sync_preference(&device.vault)
                .expect("the preference reads")
                .expect("a recorded choice")
                .predicted
        };

        issue(
            &device,
            ResidenceAct::SyncPredicted {
                window_budget: 32,
                document_budget: 128,
            },
        );
        oneiron::test_doors::predicted_residence::apply_residence_directives(&connection)
            .await
            .expect("the predicted directive runs");
        assert!(predicted(&device));

        // The owner's opened directive ends the level.
        let opened = issue(&device, ResidenceAct::SyncOpened);
        oneiron::test_doors::predicted_residence::apply_residence_directives(&connection)
            .await
            .expect("the opened directive runs");
        assert_eq!(
            result_of(&device, opened),
            Some(ResidenceResultStatus::Applied)
        );
        assert!(!predicted(&device), "opened clears the predicted flag");

        // So does the owner's switch on a host that runs this connection.
        issue(
            &device,
            ResidenceAct::SyncPredicted {
                window_budget: 32,
                document_budget: 128,
            },
        );
        oneiron::test_doors::predicted_residence::apply_residence_directives(&connection)
            .await
            .expect("the predicted directive runs again");
        assert!(predicted(&device));
        connection
            .set_residence_mode(SyncResidenceMode::Opened)
            .await
            .expect("the owner's local switch");
        assert!(!predicted(&device), "a local mode switch clears it");
    });
}
