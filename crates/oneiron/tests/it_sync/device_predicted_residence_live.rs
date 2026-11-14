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
    ActSurface, HostSlipIssuer, MachineDeviceClass, MachineOwnership, MachineRole,
    PredictedResidenceSet, ResidenceAct, ResidenceResultStatus,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::NoteSyncSession;
use oneiron::sync::connection::{ConnectionConfig, FetchConditions, SyncConnection};
use oneiron::sync::{
    SyncClientConfig, SyncResidenceMode, SyncSelector, SyncSelectorWorld, WindowKey, WindowManager,
};
use oneiron::test_doors::predicted_residence::{
    append_prediction, apply_residence_directives, run_predicted_pass,
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
            .set_machine_role(
                &owner,
                ActSurface::ThisInstall,
                local_machine(&vault),
                MachineRole::Owned(MachineOwnership::WorkSchool),
                None,
            )
            .expect("the owner answers the device's machine");
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
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
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
            let first = predicted_set(&[window.clone()], &[device.granted]);
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
            let document = format!("ds:e:{}", device.granted.to_hex());
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
                    .sync_state_get(&format!("pr:e:{}", device.granted.to_hex()))
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
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
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
                    .sync_state_get(&format!("pr:e:{}", device.granted.to_hex()))
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
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
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
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
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
