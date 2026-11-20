//! A machine at the predicted level applies its home's prediction, fetches the windows and
//! entity documents it names, and evicts what a newer prediction drops (census L7-46 + L10-14,
//! ARCH-0023b #predicted-residence). The device runs its real residence doors against the fake
//! home of the world-follow live tests, extended with the prediction RPCs: the fake home records
//! each residence.predict ask and answers unchanged, serves a planted predicted set, records each
//! residence.promote ask and refuses it, and answers an empty version vector.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use oneiron::EntityId;
use oneiron::authority::{
    ActAuthority, ActSurface, HostSlipIssuer, MachineDeviceClass, MachineOwnership, MachineRole,
    PredictedResidenceSet, ResidenceAct, ResidenceResultStatus,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::NoteSyncSession;
use oneiron::sync::connection::{ConnectionConfig, FetchConditions, SyncConnection};
use oneiron::sync::{
    SyncClientConfig, SyncResidenceMode, SyncSelector, SyncSelectorWorld, WindowKey, WindowManager,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::predicted_residence::{
    append_prediction, append_prediction_dated, apply_residence_directives, run_predicted_pass,
};
use oneiron::{Vault, VaultConfig};

use super::device_world_follow::{FIXTURE_HOST_SECRET, now_secs};
use super::device_world_follow_live::{FakeHome, HomeEvent, PredictedHome};

/// A device vault holding two worlds readable everywhere. The owner answers its machine as a work
/// or school machine: its proof stands here, so it takes the owner's residence directives (FIX
/// 8888), and it is still never "mine".
struct Device {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    founder: EntityId,
    granted: EntityId,
}

impl Device {
    /// Opens a device of `class`.
    fn open_as(class: MachineDeviceClass) -> Self {
        let dir = tempfile::tempdir().expect("device vault directory");
        let mut config = VaultConfig::device();
        config.machine_device_class = class;
        let vault = Vault::open(dir.path(), config).expect("fresh device vault");
        let person = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST_SECRET).expect("fixture host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("a live install profile, never marked yours");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("authenticated owner");
        vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall),
                &issuer,
            )
            .expect("the owner enrols this install's owner signing key");
        let landing = vault
            .set_machine_role(
                &owner,
                ActSurface::ThisInstall,
                local_machine(&vault),
                MachineRole::Owned(MachineOwnership::WorkSchool),
                None,
            )
            .expect("the owner answers the device's machine");
        assert!(
            landing.held().is_none(),
            "FIXTURE: the owner key this install holds proves the work-or-school answer"
        );
        let founder = vault
            .create_world(&owner, "Founder world", vault.now_recorded_at())
            .expect("founder world");
        let granted = vault
            .create_world(&owner, "Granted world", vault.now_recorded_at())
            .expect("granted world");
        Self {
            _dir: dir,
            vault: Arc::new(vault),
            owner,
            founder,
            granted,
        }
    }

    /// Opens a computer device.
    fn open() -> Self {
        Self::open_as(MachineDeviceClass::Computer)
    }

    /// This device's window manager.
    fn manager(&self) -> Arc<WindowManager> {
        Arc::new(WindowManager::new(
            Arc::clone(&self.vault),
            Arc::new(Materializer::new()),
            "device-predicted-residence",
        ))
    }
}

/// Runs `test` on a current-thread runtime with room for the engine's deep stacks.
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

/// This vault's own machine.
fn local_machine(vault: &Vault) -> EntityId {
    vault
        .local_machine()
        .expect("the install's machine")
        .expect("a minted machine")
        .id
}

/// Issues `act` as the owner's residence directive to this device's own machine, as the host
/// door relays one; answers the directive's id.
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

/// The machine's result status for `directive`.
fn result_of(device: &Device, directive: EntityId) -> Option<ResidenceResultStatus> {
    device
        .vault
        .residence_directive_as(&device.owner, directive)
        .expect("the owner's read-back")
        .expect("the directive")
        .result
        .map(|result| result.status)
}

/// The machine's result count for `directive`.
fn count_of(device: &Device, directive: EntityId) -> u64 {
    device
        .vault
        .residence_directive_as(&device.owner, directive)
        .expect("the owner's read-back")
        .expect("the directive")
        .result
        .map(|result| result.count)
        .expect("the result")
}

/// A refused result's reason, when the machine recorded one.
fn reason_of(device: &Device, directive: EntityId) -> Option<String> {
    device
        .vault
        .residence_directive_as(&device.owner, directive)
        .expect("the owner's read-back")
        .expect("the directive")
        .result
        .and_then(|result| result.reason)
}

/// The device's NOTE session: a slip of this host's mint, bound to the key the device holds.
fn note_session(device: &Device) -> NoteSyncSession {
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST_SECRET).expect("fixture host issuer");
    let key = SigningKey::from_bytes(&[0x5a; 32]);
    let mut claims = device
        .vault
        .ensure_host_root_slip(&issuer)
        .expect("host root")
        .claims;
    claims.slip_id = [0x5b; 32];
    claims.holder_ref = "device-world-follow-holder".to_owned();
    claims.binding_key = key.verifying_key().to_bytes();
    let slip = device
        .vault
        .mint_capability_slip(&issuer, claims)
        .expect("the device's NOTE slip");
    NoteSyncSession::new(slip.to_token().expect("slip token"), key)
}

/// The device's connection to `url`, opened with a residence selector and a NOTE session.
fn device_connection(device: &Device, url: String) -> SyncConnection {
    SyncConnection::new(
        device.manager(),
        ConnectionConfig {
            client_config: SyncClientConfig {
                server_url: url,
                residence_mode: SyncResidenceMode::Opened,
                residence_selector: Some(SyncSelector::new(
                    EntityId::now(),
                    EntityId::now(),
                    SyncSelectorWorld::All,
                    Vec::new(),
                    Vec::new(),
                )),
                note_session: Some(note_session(device)),
                ..SyncClientConfig::default()
            },
            auto_reconnect: false,
        },
    )
    .expect("the device's connection")
}

/// A predicted set of `windows` and `documents`.
fn predicted_set(windows: &[WindowKey], documents: &[EntityId]) -> PredictedResidenceSet {
    PredictedResidenceSet {
        windows: windows
            .iter()
            .map(|window| window.as_str().to_owned())
            .collect(),
        documents: documents.iter().copied().collect(),
    }
}

/// A TURN row on `device` as a machine holds an entity document before its text arrives: a
/// canonical MessagePack map holding only `txt`, the text the sync plane births lazily (FIX
/// 11794). The home predicts only entities that hold a document; a WORLD row holds no text plane.
fn predicted_turn(device: &Device) -> EntityId {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("txt"),
            rmpv::Value::from("a predicted turn"),
        )]),
    )
    .expect("the turn body encodes");
    let turn = EntityId::now();
    let at = now_secs();
    device
        .vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            &body,
        )
        .expect("the predicted turn");
    turn
}

/// Lowercase hex of `bytes`.
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// This fixture's host slip issuer.
fn issuer() -> HostSlipIssuer {
    HostSlipIssuer::from_secret(FIXTURE_HOST_SECRET).expect("fixture host issuer")
}

/// Serves `set`'s canonical body from the fake home under its digest; answers the body.
fn serve(predicted: &Arc<PredictedHome>, set: &PredictedResidenceSet) -> Vec<u8> {
    let body = set.encode().expect("the set's canonical body");
    predicted.sets.lock().expect("the served sets").insert(
        hex_lower(&PredictedResidenceSet::body_digest(&body)),
        body.clone(),
    );
    body
}

/// Starts the fake home serving `predicted`, its thin index read unheld.
async fn start_home(
    predicted: Arc<PredictedHome>,
) -> (String, tokio::sync::mpsc::UnboundedReceiver<HomeEvent>) {
    let (url, seen, release) = FakeHome::start_predicted(Vec::new(), predicted).await;
    release.send(()).expect("the index read is not held");
    (url, seen)
}

#[test]
fn a_predicted_machine_fetches_its_windows() {
    run_async("a_predicted_machine_fetches_its_windows", || async {
        let device = Device::open();
        let window = WindowKey::for_world(now_secs(), device.founder);
        let anchor = EntityId::now();
        device
            .vault
            .sync_state_put(
                &format!("ri:w:{window}:{}", anchor.to_hex()),
                b"thin index anchor",
            )
            .expect("the thin index anchor");
        let predicted = Arc::new(PredictedHome::default());
        let (url, _seen) = start_home(Arc::clone(&predicted)).await;
        let connection = device_connection(&device, url);
        let parent = issue(
            &device,
            ResidenceAct::SyncPredicted {
                window_budget: 8,
                document_budget: 16,
            },
        );
        assert_eq!(
            apply_residence_directives(&connection)
                .await
                .expect("the level applies"),
            1
        );
        assert_eq!(
            result_of(&device, parent),
            Some(ResidenceResultStatus::Applied)
        );
        let set = predicted_set(&[window.clone()], &[]);
        let body = serve(&predicted, &set);
        let prediction = append_prediction(
            &device.vault,
            &issuer(),
            local_machine(&device.vault),
            parent,
            &set,
        )
        .expect("the home's prediction");
        assert_eq!(
            apply_residence_directives(&connection)
                .await
                .expect("the prediction applies"),
            1
        );
        assert_eq!(
            result_of(&device, prediction),
            Some(ResidenceResultStatus::Applied)
        );
        assert_eq!(
            count_of(&device, prediction),
            1,
            "one window and no documents"
        );
        assert_eq!(
            device
                .vault
                .sync_state_get("pr:t")
                .expect("pr:t reads")
                .expect("the adopted set"),
            body
        );
        run_predicted_pass(&connection)
            .await
            .expect("the fetching pass");
        assert_eq!(predicted.asks.lock().expect("the asks").len(), 1);
        assert_eq!(
            *predicted.promotes.lock().expect("the promotes"),
            vec![window.as_str().to_owned()]
        );
    });
}

#[test]
fn a_phone_waits_for_wifi_and_power() {
    run_async("a_phone_waits_for_wifi_and_power", || async {
        let device = Device::open_as(MachineDeviceClass::Phone);
        let window = WindowKey::for_world(now_secs(), device.founder);
        let anchor = EntityId::now();
        device
            .vault
            .sync_state_put(
                &format!("ri:w:{window}:{}", anchor.to_hex()),
                b"thin index anchor",
            )
            .expect("the thin index anchor");
        let predicted = Arc::new(PredictedHome::default());
        let (url, _seen) = start_home(Arc::clone(&predicted)).await;
        let connection = device_connection(&device, url);
        let parent = issue(
            &device,
            ResidenceAct::SyncPredicted {
                window_budget: 8,
                document_budget: 16,
            },
        );
        assert_eq!(
            apply_residence_directives(&connection)
                .await
                .expect("the level applies"),
            1
        );
        let set = predicted_set(&[window.clone()], &[]);
        let body = serve(&predicted, &set);
        let prediction = append_prediction(
            &device.vault,
            &issuer(),
            local_machine(&device.vault),
            parent,
            &set,
        )
        .expect("the home's prediction");
        assert_eq!(
            apply_residence_directives(&connection)
                .await
                .expect("the prediction applies"),
            1
        );
        assert_eq!(
            result_of(&device, prediction),
            Some(ResidenceResultStatus::Applied)
        );
        assert_eq!(
            device
                .vault
                .sync_state_get("pr:t")
                .expect("pr:t reads")
                .expect("the adopted set"),
            body
        );
        run_predicted_pass(&connection)
            .await
            .expect("a closed gate fetches nothing");
        assert!(
            predicted.asks.lock().expect("the asks").is_empty(),
            "no ask without wifi and power"
        );
        assert!(
            predicted.promotes.lock().expect("the promotes").is_empty(),
            "no prefetch without wifi and power"
        );
        connection.set_fetch_conditions(FetchConditions {
            unmetered: true,
            powered: true,
        });
        run_predicted_pass(&connection)
            .await
            .expect("the fetching pass");
        assert_eq!(predicted.asks.lock().expect("the asks").len(), 1);
        assert_eq!(
            *predicted.promotes.lock().expect("the promotes"),
            vec![window.as_str().to_owned()]
        );
    });
}

/// Applies the predicted level and the home's prediction of one window of `device` on
/// `connection`, as `a_phone_waits_for_wifi_and_power` does, its set served by `predicted`;
/// answers the predicted window.
async fn adopt_one_predicted_window(
    device: &Device,
    connection: &SyncConnection,
    predicted: &Arc<PredictedHome>,
) -> WindowKey {
    let window = WindowKey::for_world(now_secs(), device.founder);
    device
        .vault
        .sync_state_put(
            &format!("ri:w:{window}:{}", EntityId::now().to_hex()),
            b"thin index anchor",
        )
        .expect("the thin index anchor");
    let parent = issue(
        device,
        ResidenceAct::SyncPredicted {
            window_budget: 8,
            document_budget: 16,
        },
    );
    assert_eq!(
        apply_residence_directives(connection)
            .await
            .expect("the level applies"),
        1
    );
    let set = predicted_set(&[window.clone()], &[]);
    serve(predicted, &set);
    let prediction = append_prediction(
        &device.vault,
        &issuer(),
        local_machine(&device.vault),
        parent,
        &set,
    )
    .expect("the home's prediction");
    assert_eq!(
        apply_residence_directives(connection)
            .await
            .expect("the prediction applies"),
        1
    );
    assert_eq!(
        result_of(device, prediction),
        Some(ResidenceResultStatus::Applied)
    );
    window
}

/// The shell's report is a fact of the open install, not of one connection: a connection
/// rebuilt over the same vault (a credential renewal, an embedded engine's wake) fetches on the
/// report the shell made before it, with no new report.
#[test]
fn a_reconnected_phone_keeps_its_reported_fetch_conditions() {
    run_async(
        "a_reconnected_phone_keeps_its_reported_fetch_conditions",
        || async {
            let device = Device::open_as(MachineDeviceClass::Phone);
            let predicted = Arc::new(PredictedHome::default());
            let (url, _seen) = start_home(Arc::clone(&predicted)).await;
            let first = device_connection(&device, url.clone());
            let window = adopt_one_predicted_window(&device, &first, &predicted).await;
            first.set_fetch_conditions(FetchConditions {
                unmetered: true,
                powered: true,
            });
            drop(first);
            let reconnected = device_connection(&device, url);
            run_predicted_pass(&reconnected)
                .await
                .expect("the reconnected pass");
            assert_eq!(
                predicted.asks.lock().expect("the asks").len(),
                1,
                "the rebuilt connection asks on the shell's earlier report"
            );
            assert_eq!(
                *predicted.promotes.lock().expect("the promotes"),
                vec![window.as_str().to_owned()]
            );
        },
    );
}

/// The shell may report before any connection runs (an embedded engine reports at app start,
/// before device sync dials its home): the report stands on the open vault, and the first
/// connection fetches on it.
#[test]
fn a_shell_report_before_the_connection_opens_its_gate() {
    run_async(
        "a_shell_report_before_the_connection_opens_its_gate",
        || async {
            let device = Device::open_as(MachineDeviceClass::Phone);
            assert_eq!(
                device.vault.reported_fetch_conditions(),
                FetchConditions::default(),
                "closed until the shell reports"
            );
            let open = FetchConditions {
                unmetered: true,
                powered: true,
            };
            device.vault.report_fetch_conditions(open);
            assert_eq!(device.vault.reported_fetch_conditions(), open);
            let predicted = Arc::new(PredictedHome::default());
            let (url, _seen) = start_home(Arc::clone(&predicted)).await;
            let connection = device_connection(&device, url);
            let window = adopt_one_predicted_window(&device, &connection, &predicted).await;
            run_predicted_pass(&connection)
                .await
                .expect("the fetching pass");
            assert_eq!(predicted.asks.lock().expect("the asks").len(), 1);
            assert_eq!(
                *predicted.promotes.lock().expect("the promotes"),
                vec![window.as_str().to_owned()]
            );
        },
    );
}

#[test]
fn a_dropped_window_is_demoted_never_deleted() {
    run_async("a_dropped_window_is_demoted_never_deleted", || async {
        let device = Device::open();
        let window = WindowKey::for_world(now_secs(), device.founder);
        let predicted = Arc::new(PredictedHome::default());
        let (url, mut seen) = start_home(Arc::clone(&predicted)).await;
        let connection = device_connection(&device, url);
        let parent = issue(
            &device,
            ResidenceAct::SyncPredicted {
                window_budget: 8,
                document_budget: 16,
            },
        );
        assert_eq!(
            apply_residence_directives(&connection)
                .await
                .expect("the level applies"),
            1
        );
        let first = predicted_set(&[window.clone()], &[]);
        serve(&predicted, &first);
        let prediction = append_prediction(
            &device.vault,
            &issuer(),
            local_machine(&device.vault),
            parent,
            &first,
        )
        .expect("the first prediction");
        assert_eq!(
            apply_residence_directives(&connection)
                .await
                .expect("the first prediction applies"),
            1
        );
        assert_eq!(
            result_of(&device, prediction),
            Some(ResidenceResultStatus::Applied)
        );
        // The window as fetched: its prediction marker and its promotion.
        device
            .vault
            .sync_state_put(&format!("pr:w:{window}"), &[])
            .expect("the prediction marker");
        device
            .vault
            .sync_state_put(&format!("rp:w:{window}"), &[1])
            .expect("the promotion marker");
        // A second prediction leaves the window out, strictly after the first.
        let second = predicted_set(&[], &[]);
        let second_body = serve(&predicted, &second);
        let prediction = append_prediction(
            &device.vault,
            &issuer(),
            local_machine(&device.vault),
            parent,
            &second,
        )
        .expect("the second prediction");
        assert_eq!(
            apply_residence_directives(&connection)
                .await
                .expect("the second prediction applies"),
            1
        );
        assert_eq!(
            result_of(&device, prediction),
            Some(ResidenceResultStatus::Applied)
        );
        assert_eq!(
            device
                .vault
                .sync_state_get("pr:t")
                .expect("pr:t reads")
                .expect("the adopted set"),
            second_body
        );
        run_predicted_pass(&connection)
            .await
            .expect("the evicting pass");
        assert!(
            device
                .vault
                .sync_state_get(&format!("pr:w:{window}"))
                .expect("the marker reads")
                .is_none(),
            "the demoted window's marker is gone"
        );
        assert!(
            device
                .vault
                .sync_state_get(&format!("rp:w:{window}"))
                .expect("the promotion reads")
                .is_none(),
            "the window is demoted"
        );
        assert_eq!(
            *predicted.vvs.lock().expect("the vv asks"),
            vec![window.as_str().to_owned()]
        );
        assert!(seen.try_recv().is_err(), "no sync socket ever opened");
        for method in predicted.methods.lock().expect("the methods").iter() {
            assert!(
                method.starts_with("residence."),
                "only residence RPCs reach the home: {method}"
            );
        }
    });
}

#[test]
fn a_followed_world_is_neither_fetched_nor_evicted_by_prediction() {
    run_async(
        "a_followed_world_is_neither_fetched_nor_evicted_by_prediction",
        || async {
            let device = Device::open();
            let window = WindowKey::for_world(now_secs(), device.founder);
            let anchor = EntityId::now();
            device
                .vault
                .sync_state_put(
                    &format!("ri:w:{window}:{}", anchor.to_hex()),
                    b"thin index anchor",
                )
                .expect("the thin index anchor");
            let turn = predicted_turn(&device);
            let predicted = Arc::new(PredictedHome::default());
            let (url, _seen) = start_home(Arc::clone(&predicted)).await;
            let connection = device_connection(&device, url);
            connection
                .set_followed_worlds(BTreeSet::from([device.founder]))
                .expect("the owner's pick");
            let parent = issue(
                &device,
                ResidenceAct::SyncPredicted {
                    window_budget: 8,
                    document_budget: 16,
                },
            );
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the level applies"),
                1
            );
            let first = predicted_set(&[window.clone()], &[turn]);
            serve(&predicted, &first);
            let prediction = append_prediction(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                parent,
                &first,
            )
            .expect("the first prediction");
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the first prediction applies"),
                1
            );
            assert_eq!(
                result_of(&device, prediction),
                Some(ResidenceResultStatus::Applied)
            );
            assert_eq!(
                count_of(&device, prediction),
                2,
                "one window and one document"
            );
            run_predicted_pass(&connection)
                .await
                .expect("the fetching pass");
            assert!(
                predicted.promotes.lock().expect("the promotes").is_empty(),
                "a followed world is not prefetched"
            );
            let document = format!("ds:e:{}", turn.to_hex());
            assert!(
                device
                    .vault
                    .sync_state_get(&document)
                    .expect("the subscription reads")
                    .is_some(),
                "the predicted document subscribes"
            );
            assert!(
                device
                    .vault
                    .sync_state_get(&format!("pr:e:{}", turn.to_hex()))
                    .expect("the marker reads")
                    .is_some(),
                "the predicted document is marked"
            );
            // The followed window as fetched earlier: dropping it must only drop the marker.
            device
                .vault
                .sync_state_put(&format!("pr:w:{window}"), &[])
                .expect("the prediction marker");
            // A second prediction drops the window and the document, strictly after the first.
            let second = predicted_set(&[], &[]);
            serve(&predicted, &second);
            append_prediction(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                parent,
                &second,
            )
            .expect("the second prediction");
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the second prediction applies"),
                1
            );
            run_predicted_pass(&connection)
                .await
                .expect("the evicting pass");
            assert!(
                predicted.vvs.lock().expect("the vv asks").is_empty(),
                "dropping a followed window demotes nothing"
            );
            assert!(
                device
                    .vault
                    .sync_state_get(&format!("pr:w:{window}"))
                    .expect("the marker reads")
                    .is_none(),
                "the followed window only loses its marker"
            );
            assert!(predicted.promotes.lock().expect("the promotes").is_empty());
            assert!(
                device
                    .vault
                    .sync_state_get(&document)
                    .expect("the subscription reads")
                    .is_none(),
                "the dropped document unsubscribes"
            );
            assert!(
                device
                    .vault
                    .sync_state_get(&format!("pr:e:{}", turn.to_hex()))
                    .expect("the marker reads")
                    .is_none(),
                "the dropped document's marker is gone"
            );
        },
    );
}

#[test]
fn a_home_down_machine_keeps_its_prediction() {
    run_async("a_home_down_machine_keeps_its_prediction", || async {
        let device = Device::open();
        let window = WindowKey::for_world(now_secs(), device.founder);
        let predicted = Arc::new(PredictedHome::default());
        let (url, _seen) = start_home(Arc::clone(&predicted)).await;
        let connection = device_connection(&device, url);
        let parent = issue(
            &device,
            ResidenceAct::SyncPredicted {
                window_budget: 8,
                document_budget: 16,
            },
        );
        assert_eq!(
            apply_residence_directives(&connection)
                .await
                .expect("the level applies"),
            1
        );
        let set = predicted_set(&[window.clone()], &[]);
        let body = serve(&predicted, &set);
        let prediction = append_prediction(
            &device.vault,
            &issuer(),
            local_machine(&device.vault),
            parent,
            &set,
        )
        .expect("the prediction");
        assert_eq!(
            apply_residence_directives(&connection)
                .await
                .expect("the prediction applies"),
            1
        );
        device
            .vault
            .sync_state_put(&format!("pr:w:{window}"), &[])
            .expect("the prediction marker");
        device
            .vault
            .sync_state_put(&format!("rp:w:{window}"), &[1])
            .expect("the promotion marker");
        // The home goes down: the same vault through a port with nothing listening.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let dead = format!(
            "ws://{}/ws",
            listener.local_addr().expect("listener address")
        );
        drop(listener);
        let down = device_connection(&device, dead);
        run_predicted_pass(&down)
            .await
            .expect("a frozen pass stays quiet");
        run_predicted_pass(&down)
            .await
            .expect("a frozen pass stays quiet");
        assert_eq!(
            device
                .vault
                .sync_state_get("pr:t")
                .expect("pr:t reads")
                .expect("the kept set"),
            body
        );
        assert!(
            device
                .vault
                .sync_state_get(&format!("pr:w:{window}"))
                .expect("the marker reads")
                .is_some(),
            "nothing is evicted while the home is down"
        );
        assert!(
            device
                .vault
                .sync_state_get(&format!("rp:w:{window}"))
                .expect("the promotion reads")
                .is_some(),
            "nothing is demoted while the home is down"
        );
    });
}

#[test]
fn a_prediction_without_its_live_parent_is_refused() {
    run_async(
        "a_prediction_without_its_live_parent_is_refused",
        || async {
            let predicted = Arc::new(PredictedHome::default());
            let (url, _seen) = start_home(Arc::clone(&predicted)).await;

            // After the owner's SyncOpened the predicted level ended: a prediction is refused.
            let device = Device::open();
            let connection = device_connection(&device, url.clone());
            let stale = issue(
                &device,
                ResidenceAct::SyncPredicted {
                    window_budget: 8,
                    document_budget: 16,
                },
            );
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the level applies"),
                1
            );
            let opened = issue(&device, ResidenceAct::SyncOpened);
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the level ends"),
                1
            );
            assert_eq!(
                result_of(&device, opened),
                Some(ResidenceResultStatus::Applied)
            );
            let set = predicted_set(&[WindowKey::for_world(now_secs(), device.founder)], &[]);
            serve(&predicted, &set);
            let prediction = append_prediction(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                stale,
                &set,
            )
            .expect("the stale prediction");
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the refusal records"),
                1
            );
            assert_eq!(
                result_of(&device, prediction),
                Some(ResidenceResultStatus::Refused)
            );
            let reason = reason_of(&device, prediction).expect("a refusal reason");
            assert!(
                reason.contains("predicted level"),
                "the level ended: {reason}"
            );

            // A body that is not the digest's is refused with the digest reason.
            let device = Device::open();
            let connection = device_connection(&device, url.clone());
            let parent = issue(
                &device,
                ResidenceAct::SyncPredicted {
                    window_budget: 8,
                    document_budget: 16,
                },
            );
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the level applies"),
                1
            );
            let set = predicted_set(&[WindowKey::for_world(now_secs(), device.founder)], &[]);
            let body = set.encode().expect("the set's canonical body");
            let other = predicted_set(&[], &[device.granted])
                .encode()
                .expect("another set's body");
            predicted
                .sets
                .lock()
                .expect("the served sets")
                .insert(hex_lower(&PredictedResidenceSet::body_digest(&body)), other);
            let prediction = append_prediction(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                parent,
                &set,
            )
            .expect("the prediction");
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the refusal records"),
                1
            );
            assert_eq!(
                result_of(&device, prediction),
                Some(ResidenceResultStatus::Refused)
            );
            let reason = reason_of(&device, prediction).expect("a refusal reason");
            assert!(
                reason.contains("the predicted set does not match its digest"),
                "the digest reason: {reason}"
            );

            // A prediction whose parent is not the owner's live predicted level is refused.
            let device = Device::open();
            let connection = device_connection(&device, url.clone());
            let first = issue(
                &device,
                ResidenceAct::SyncPredicted {
                    window_budget: 8,
                    document_budget: 16,
                },
            );
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the first level applies"),
                1
            );
            let live = issue(
                &device,
                ResidenceAct::SyncPredicted {
                    window_budget: 8,
                    document_budget: 16,
                },
            );
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the live level applies"),
                1
            );
            assert_eq!(
                result_of(&device, live),
                Some(ResidenceResultStatus::Applied)
            );
            let set = predicted_set(&[WindowKey::for_world(now_secs(), device.founder)], &[]);
            serve(&predicted, &set);
            let prediction = append_prediction(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                first,
                &set,
            )
            .expect("the stale prediction");
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the refusal records"),
                1
            );
            assert_eq!(
                result_of(&device, prediction),
                Some(ResidenceResultStatus::Refused)
            );
            let reason = reason_of(&device, prediction).expect("a refusal reason");
            assert!(
                reason.contains("under the owner's live predicted level"),
                "the parent reason: {reason}"
            );

            // A prediction a newer one replaced is refused, and the newer one applies.
            let device = Device::open();
            let connection = device_connection(&device, url);
            let parent = issue(
                &device,
                ResidenceAct::SyncPredicted {
                    window_budget: 8,
                    document_budget: 16,
                },
            );
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the level applies"),
                1
            );
            let set = predicted_set(&[WindowKey::for_world(now_secs(), device.founder)], &[]);
            serve(&predicted, &set);
            let older = append_prediction(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                parent,
                &set,
            )
            .expect("the older prediction");
            let newer = append_prediction(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                parent,
                &set,
            )
            .expect("the newer prediction");
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("both predictions run"),
                2
            );
            assert_eq!(
                result_of(&device, older),
                Some(ResidenceResultStatus::Refused)
            );
            let reason = reason_of(&device, older).expect("a refusal reason");
            assert!(
                reason.contains("a newer prediction replaced it"),
                "the newer reason: {reason}"
            );
            assert_eq!(
                result_of(&device, newer),
                Some(ResidenceResultStatus::Applied)
            );
        },
    );
}

/// A prediction dated ahead by another home's clock (the home moved, or its clock runs fast)
/// replaces no later prediction while this machine's own clock has not reached its date: this
/// home's next prediction, dated before it, still applies (FIX PREDICTED-FUTURE-DATED-BLOCKS-LATER).
#[test]
fn a_prediction_dated_ahead_replaces_none_before_its_date() {
    run_async(
        "a_prediction_dated_ahead_replaces_none_before_its_date",
        || async {
            let predicted = Arc::new(PredictedHome::default());
            let (url, _seen) = start_home(Arc::clone(&predicted)).await;
            let device = Device::open();
            let connection = device_connection(&device, url);
            let parent = issue(
                &device,
                ResidenceAct::SyncPredicted {
                    window_budget: 8,
                    document_budget: 16,
                },
            );
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the level applies"),
                1
            );
            let ahead_set = predicted_set(&[WindowKey::for_world(now_secs(), device.founder)], &[]);
            serve(&predicted, &ahead_set);
            let ahead = append_prediction_dated(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                parent,
                &ahead_set,
                now_secs() + 86_400,
            )
            .expect("the prediction dated a day ahead");
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the prediction dated ahead runs"),
                1
            );
            assert_eq!(
                result_of(&device, ahead),
                Some(ResidenceResultStatus::Applied)
            );

            let due_set = predicted_set(
                &[
                    WindowKey::for_world(now_secs(), device.founder),
                    WindowKey::for_world(now_secs(), device.granted),
                ],
                &[],
            );
            serve(&predicted, &due_set);
            let due = append_prediction(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                parent,
                &due_set,
            )
            .expect("the prediction dated now");
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the prediction dated now runs"),
                1
            );
            assert_eq!(
                reason_of(&device, due),
                None,
                "a prediction dated ahead replaces nothing before its date"
            );
            assert_eq!(
                result_of(&device, due),
                Some(ResidenceResultStatus::Applied)
            );
            assert_eq!(count_of(&device, due), 2, "the set dated now is adopted");
        },
    );
}

/// A prediction under a predicted level the owner has since replaced applies nowhere, so it
/// replaces none under the live level, even when it sorts after one: the live one applies and the
/// stale one is refused (FIX PREDICTED-FUTURE-DATED-BLOCKS-LATER).
#[test]
fn a_prediction_under_a_replaced_parent_replaces_none() {
    run_async(
        "a_prediction_under_a_replaced_parent_replaces_none",
        || async {
            let predicted = Arc::new(PredictedHome::default());
            let (url, _seen) = start_home(Arc::clone(&predicted)).await;
            let device = Device::open();
            let connection = device_connection(&device, url);
            let replaced = issue(
                &device,
                ResidenceAct::SyncPredicted {
                    window_budget: 8,
                    document_budget: 16,
                },
            );
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the first level applies"),
                1
            );
            let live = issue(
                &device,
                ResidenceAct::SyncPredicted {
                    window_budget: 8,
                    document_budget: 16,
                },
            );
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the live level applies"),
                1
            );
            let set = predicted_set(&[WindowKey::for_world(now_secs(), device.founder)], &[]);
            serve(&predicted, &set);
            let current = append_prediction(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                live,
                &set,
            )
            .expect("the prediction under the live level");
            let stale = append_prediction(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                replaced,
                &set,
            )
            .expect("the prediction under the replaced level, sorting after");
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("both predictions run"),
                2
            );
            assert_eq!(
                reason_of(&device, current),
                None,
                "a prediction under a replaced level replaces none under the live one"
            );
            assert_eq!(
                result_of(&device, current),
                Some(ResidenceResultStatus::Applied)
            );
            assert_eq!(
                result_of(&device, stale),
                Some(ResidenceResultStatus::Refused)
            );
            let reason = reason_of(&device, stale).expect("a refusal reason");
            assert!(
                reason.contains("under the owner's live predicted level"),
                "the parent reason: {reason}"
            );
        },
    );
}

/// A predicted document whose subscribe fails with more than an admission refusal (a WORLD row,
/// which holds no text plane: a kind the machine and its home disagree on) holds back neither the
/// other documents nor the eviction of what the set dropped, and leaves no subscription row that
/// every reconnect's requests would fail on; the pass answers the fault after it evicted.
#[test]
fn a_document_fault_still_evicts_and_leaves_no_subscription() {
    run_async(
        "a_document_fault_still_evicts_and_leaves_no_subscription",
        || async {
            let device = Device::open();
            let window = WindowKey::for_world(now_secs(), device.founder);
            let turn = predicted_turn(&device);
            let predicted = Arc::new(PredictedHome::default());
            let (url, _seen) = start_home(Arc::clone(&predicted)).await;
            let connection = device_connection(&device, url);
            let parent = issue(
                &device,
                ResidenceAct::SyncPredicted {
                    window_budget: 8,
                    document_budget: 16,
                },
            );
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the level applies"),
                1
            );
            let first = predicted_set(&[window.clone()], &[]);
            serve(&predicted, &first);
            append_prediction(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                parent,
                &first,
            )
            .expect("the first prediction");
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the first prediction applies"),
                1
            );
            // The window as fetched: its prediction marker and its promotion.
            device
                .vault
                .sync_state_put(&format!("pr:w:{window}"), &[])
                .expect("the prediction marker");
            device
                .vault
                .sync_state_put(&format!("rp:w:{window}"), &[1])
                .expect("the promotion marker");
            // A second prediction drops the window and names a WORLD row and a TURN as
            // documents, strictly after the first.
            let second = predicted_set(&[], &[device.granted, turn]);
            let second_body = serve(&predicted, &second);
            let prediction = append_prediction(
                &device.vault,
                &issuer(),
                local_machine(&device.vault),
                parent,
                &second,
            )
            .expect("the second prediction");
            assert_eq!(
                apply_residence_directives(&connection)
                    .await
                    .expect("the second prediction applies"),
                1
            );
            assert_eq!(
                result_of(&device, prediction),
                Some(ResidenceResultStatus::Applied)
            );
            assert_eq!(
                device
                    .vault
                    .sync_state_get("pr:t")
                    .expect("pr:t reads")
                    .expect("the adopted set"),
                second_body
            );
            let fault = run_predicted_pass(&connection)
                .await
                .expect_err("the WORLD row's subscribe fault is the pass's answer");
            assert!(
                device
                    .vault
                    .sync_state_get(&format!("pr:w:{window}"))
                    .expect("the marker reads")
                    .is_none(),
                "the dropped window is evicted after the fault: {fault}"
            );
            assert!(
                device
                    .vault
                    .sync_state_get(&format!("rp:w:{window}"))
                    .expect("the promotion reads")
                    .is_none(),
                "the dropped window is demoted after the fault: {fault}"
            );
            assert_eq!(
                *predicted.vvs.lock().expect("the vv asks"),
                vec![window.as_str().to_owned()]
            );
            assert!(
                device
                    .vault
                    .sync_state_get(&format!("ds:e:{}", device.granted.to_hex()))
                    .expect("the subscription reads")
                    .is_none(),
                "a document whose request cannot be built leaves no subscription row"
            );
            assert!(
                device
                    .vault
                    .sync_state_get(&format!("pr:e:{}", device.granted.to_hex()))
                    .expect("the marker reads")
                    .is_none(),
                "the faulted document is not marked"
            );
            assert!(
                device
                    .vault
                    .sync_state_get(&format!("ds:e:{}", turn.to_hex()))
                    .expect("the subscription reads")
                    .is_some(),
                "the other predicted document subscribes"
            );
            assert!(
                device
                    .vault
                    .sync_state_get(&format!("pr:e:{}", turn.to_hex()))
                    .expect("the marker reads")
                    .is_some(),
                "the other predicted document is marked"
            );
        },
    );
}
