#![cfg(oneiron_test_support)]
//! The owner's backup setting through its routes (FIX-LIST row 5822): `GET`
//! and `PUT /v1/owner/settings/backup` while unset, after a stored choice,
//! and after an explicit off, and the schedule's next tick under each.
//!
//! A test-gap row: these cases pass on unmodified main. Unset answers the
//! deployment's `[backup]` section as effective; a stored choice answers
//! whole in both halves; an explicit off is stored as a choice, never a
//! reset to null or to the fallback; a policy that breaks the rules is
//! refused and stores nothing; and one schedule pass takes a backup exactly
//! when the policy in force has the schedule on.
//!
//! Deterministic: in-process vault and router (`oneshot`, no TCP ports, no
//! sleeps, no models).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --test owner_backup_setting`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::settings::backup::BackupPolicy;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::{DeviceKeystore, KeystoreError, KeystoreLocality, KeystoreSlot};
use oneiron_server::build_app;
use oneiron_server::config::{BackupConfig, SyncServerConfig};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::owner_backup::{attach_owner_host, take_if_due_now};
use serde_json::{Value, json};
use tower::ServiceExt;
use zeroize::Zeroizing;

/// This process's memory as the vault's keystore, as `MemoryKeystore`: the
/// slots `serve` roots the vault and seals its backups with. This test runs
/// without `oneiron/test-support`, which forwards the shared one.
#[derive(Default)]
struct TestKeystore {
    slots: Mutex<HashMap<KeystoreSlot, Zeroizing<[u8; 32]>>>,
}

impl DeviceKeystore for TestKeystore {
    fn get(&self, slot: &KeystoreSlot) -> oneiron_keystore::Result<Option<Zeroizing<[u8; 32]>>> {
        let slots = self.slots.lock().map_err(|_| KeystoreError::Denied)?;
        Ok(slots.get(slot).map(|secret| Zeroizing::new(**secret)))
    }

    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> oneiron_keystore::Result<()> {
        let mut slots = self.slots.lock().map_err(|_| KeystoreError::Denied)?;
        if slots.contains_key(slot) {
            return Err(KeystoreError::AlreadyExists);
        }
        slots.insert(*slot, Zeroizing::new(*secret));
        Ok(())
    }

    fn delete(&self, slot: &KeystoreSlot) -> oneiron_keystore::Result<()> {
        let mut slots = self.slots.lock().map_err(|_| KeystoreError::Denied)?;
        slots.remove(slot);
        Ok(())
    }

    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> oneiron_keystore::Result<bool> {
        let mut slots = self.slots.lock().map_err(|_| KeystoreError::Denied)?;
        let Some(held) = slots.get_mut(slot) else {
            return Ok(false);
        };
        **held = *secret;
        Ok(true)
    }

    fn locality(&self) -> KeystoreLocality {
        KeystoreLocality::ThisDeviceOnly
    }
}

/// A `[backup]` section holding `enabled`, `every_hours` and `keep`.
fn backup_section(enabled: bool, every_hours: u64, keep: usize) -> BackupConfig {
    BackupConfig {
        enabled,
        every_hours,
        keep,
        ..Default::default()
    }
}

/// A policy body and answer: `{enabled, every_hours, keep}`.
fn policy_json(enabled: bool, every_hours: u64, keep: usize) -> Value {
    json!({"enabled": enabled, "every_hours": every_hours, "keep": keep})
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A served vault with the `[backup]` section `backup` as its schedule's
/// fallback, and the owner's host-root credential for its routes.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

fn fixture(backup: BackupConfig) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault_path = dir.path().join("vault");
    let vault =
        Arc::new(Vault::open(vault_path.as_path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(TestKeystore::default()));
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("owner-backup-setting".into()),
            ..Default::default()
        },
    )
    .expect("create server");
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    // The owner's acts are carried by this install's live machine profile,
    // as a serving start enrols it.
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let server = attach_owner_host(server, vault_path.as_path(), backup);
    let server = Arc::new(server);
    let app = build_app(Arc::clone(&server));
    Fixture {
        _dir: dir,
        vault,
        server,
        app,
        issuer,
        owner_slip,
        owner_token,
    }
}

impl Fixture {
    fn owner_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = hex(&self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())
            .expect("owner holder proof"));
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    /// `GET /v1/owner/settings/backup` as the owner: its status and answer.
    async fn get(&self) -> (StatusCode, Value) {
        let request = Request::get("/v1/owner/settings/backup")
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding())
            .body(Body::empty())
            .expect("backup setting request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("backup setting response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("backup setting body");
        (
            status,
            serde_json::from_slice(&bytes).expect("backup setting JSON"),
        )
    }

    /// `PUT /v1/owner/settings/backup` as the owner: its status and answer.
    async fn put(&self, body: Value) -> (StatusCode, Value) {
        let request = Request::put("/v1/owner/settings/backup")
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding())
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("backup setting request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("backup setting response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("backup setting body");
        (
            status,
            serde_json::from_slice(&bytes).expect("backup setting JSON"),
        )
    }
}

#[test]
fn get_while_unset_answers_the_deployment_section() {
    run_on_engine_stack("backup-setting-unset", || async {
        let fx = fixture(backup_section(true, 24, 2));
        let (status, answer) = fx.get().await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert!(answer["stored"].is_null(), "{answer}");
        assert_eq!(answer["effective"], policy_json(true, 24, 2), "{answer}");
    });
}

#[test]
fn put_stores_the_whole_triple_and_get_reads_it_back() {
    run_on_engine_stack("backup-setting-put", || async {
        let fx = fixture(BackupConfig::default());
        let (status, answer) = fx.put(policy_json(true, 12, 3)).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["stored"], policy_json(true, 12, 3), "{answer}");
        assert_eq!(answer["effective"], policy_json(true, 12, 3), "{answer}");
        let (status, answer) = fx.get().await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["stored"], policy_json(true, 12, 3), "{answer}");
        assert_eq!(answer["effective"], policy_json(true, 12, 3), "{answer}");
        assert_eq!(
            fx.vault.backup_policy().expect("read the stored choice"),
            Some(BackupPolicy {
                enabled: true,
                every_hours: 12,
                keep: 3,
            })
        );
    });
}

#[test]
fn explicit_off_is_a_stored_choice_not_a_reset() {
    run_on_engine_stack("backup-setting-off", || async {
        // The fallback is on, so an explicit off reads differently from
        // unset in both halves of the answer.
        let fx = fixture(backup_section(true, 24, 2));
        let (status, answer) = fx.put(policy_json(false, 48, 5)).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["stored"], policy_json(false, 48, 5), "{answer}");
        assert_eq!(answer["effective"], policy_json(false, 48, 5), "{answer}");
        let (status, answer) = fx.get().await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["stored"], policy_json(false, 48, 5), "{answer}");
        assert_eq!(answer["effective"], policy_json(false, 48, 5), "{answer}");
    });
}

#[test]
fn put_refuses_a_policy_that_breaks_the_rules() {
    run_on_engine_stack("backup-setting-invalid", || async {
        let fx = fixture(BackupConfig::default());
        for body in [policy_json(true, 0, 2), policy_json(true, 24, 0)] {
            let (status, answer) = fx.put(body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
        }
        let (status, answer) = fx.get().await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert!(answer["stored"].is_null(), "{answer}");
    });
}

#[test]
fn an_unset_schedule_follows_the_deployment_section() {
    run_on_engine_stack("backup-setting-tick-unset", || async {
        let on = fixture(backup_section(true, 24, 2));
        assert!(
            take_if_due_now(&on.server).expect("the tick runs"),
            "an unset schedule on an enabled section takes the first backup"
        );
        let off = fixture(BackupConfig::default());
        assert!(
            !take_if_due_now(&off.server).expect("the tick runs"),
            "an unset schedule on the default section takes nothing"
        );
    });
}

#[test]
fn the_next_tick_reads_the_stored_setting() {
    run_on_engine_stack("backup-setting-tick-stored", || async {
        // Stored on beats a fallback that is off: the tick takes a backup.
        let fx = fixture(BackupConfig::default());
        let (status, _) = fx.put(policy_json(true, 24, 2)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            take_if_due_now(&fx.server).expect("the tick runs"),
            "the tick takes a backup once the stored choice turns it on"
        );
        // Stored off beats a fallback that is on, on an empty backup
        // shelf: the tick takes nothing.
        let fx = fixture(backup_section(true, 24, 2));
        let (status, _) = fx.put(policy_json(false, 24, 2)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !take_if_due_now(&fx.server).expect("the tick runs"),
            "the tick takes nothing once the stored choice turns it off"
        );
    });
}
