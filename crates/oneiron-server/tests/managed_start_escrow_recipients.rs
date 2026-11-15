//! The escrow recipients a supervisor names at a managed start (FIX 2856).
//!
//! Each row boots the real `serve_managed` over a canary vault, as the spawn
//! order rows in `managed_mode.rs` do, because the ready byte is the
//! supervisor's only evidence that the start went on:
//! - `a_retired_escrow_recipient_is_skipped_and_the_start_reports_ready`: a
//!   recipient file naming a label the vault retired no longer stops the
//!   start (RULING FIX-2856-RETIRED-ESCROW-BOOT = C), and no capsule is
//!   spooled for it.
//! - `a_fresh_escrow_recipient_seals_at_start_beside_a_retired_label`: the
//!   same fixture seals a fresh recipient and spools its capsule, so the row
//!   above fails only on the retired recipient.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test managed_start_escrow_recipients`.

use std::collections::BTreeSet;
use std::os::fd::IntoRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use oneiron_server::config::ServeArgs;
use oneiron_server::managed::{CANARY_MARKER_KEY, CANARY_MARKER_VALUE, ManagedArgs, serve_managed};
use oneiron_vault_contract::{CONTRACT_VERSION, DEK_LEN, READY_BYTE, TOKEN_LEN, write_credentials};

const VAULT_NAME: &str = "canary-vault";

/// Drives `ServeArgs` through a real clap parse, so these rows pass the
/// flags the supervisor types.
#[derive(Parser)]
struct ArgvProbe {
    #[command(flatten)]
    serve: ServeArgs,
}

fn parse_serve(argv: &[String]) -> ServeArgs {
    let mut full = vec!["oneiron-server".to_owned()];
    full.extend_from_slice(argv);
    ArgvProbe::try_parse_from(full).unwrap().serve
}

/// A complete managed argv rooted at `root`, as `managed_mode.rs` builds it.
/// The two fds are placeholders that [`boot_args`] replaces.
fn managed_argv(root: &Path) -> Vec<String> {
    let path = |name: &str| root.join(name).display().to_string();
    vec![
        "--managed-by-hypnos".to_owned(),
        "--contract-version".to_owned(),
        CONTRACT_VERSION.to_string(),
        "--vault-name".to_owned(),
        VAULT_NAME.to_owned(),
        "--derivation-owner".to_owned(),
        "09".repeat(32),
        "--data-dir".to_owned(),
        path("data"),
        "--keystore-dir".to_owned(),
        path("keys"),
        "--http-socket".to_owned(),
        path("http.sock"),
        "--ctl-socket".to_owned(),
        path("ctl.sock"),
        "--hypnos-socket".to_owned(),
        path("sup.sock"),
        "--ready-fd".to_owned(),
        "7".to_owned(),
        "--credentials-fd".to_owned(),
        "9".to_owned(),
    ]
}

/// The run directory under `root` the sockets go in.
fn sockets_dir(root: &Path) -> PathBuf {
    let dir = root.join("run");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

/// Opens a vault the way managed mode will, so the seeding open and the
/// managed open agree about dimensions and map size.
fn open_vault(dir: &Path) -> Arc<oneiron::Vault> {
    Arc::new(oneiron::Vault::open(dir, oneiron::VaultConfig::server()).unwrap())
}

/// The managed start's args rooted at `root` with the flags `extra` after
/// the managed argv, a credentials descriptor over a real frame and a ready
/// descriptor over the ready file, which comes back with them.
fn boot_args(root: &Path, extra: &[String]) -> (ServeArgs, PathBuf) {
    let ready_path = root.join("ready");
    let credentials_path = root.join("creds");
    let mut frame = Vec::new();
    write_credentials(&mut frame, &[0x11; DEK_LEN], &[0x22; TOKEN_LEN]).unwrap();
    std::fs::write(&credentials_path, &frame).unwrap();

    let mut argv = managed_argv(root);
    argv.extend_from_slice(extra);
    let mut args = parse_serve(&argv);
    args.credentials_fd = Some(
        std::fs::File::open(&credentials_path)
            .unwrap()
            .into_raw_fd(),
    );
    args.ready_fd = Some(std::fs::File::create(&ready_path).unwrap().into_raw_fd());
    (args, ready_path)
}

/// The public key bytes of a hybrid escrow recipient, as a supervisor's
/// recipient file holds them; `seed` picks the recipient.
fn escrow_recipient(seed: u8) -> Vec<u8> {
    oneiron::world_keys::HybridSecretKey::from_seeds(&[seed; 64], &[seed; 32])
        .public_key()
        .to_bytes()
}

/// The label of the managed escrow wrap to `recipient`, as the start names
/// it: the role and the first 16 hex of the recipient's fingerprint.
fn managed_escrow_label(recipient: &[u8]) -> String {
    format!("managed.{}", &blake3::hash(recipient).to_hex()[..16])
}

/// A canary vault whose owner retired the managed escrow label of
/// `released`, as a restore by capsule retires a released recipient, and the
/// managed start's args, which name `recipient` as the managed escrow
/// recipient file and an escrow outbox. The ready file and the outbox come
/// back with them.
fn escrow_boot_args(
    run: &Path,
    released: &[u8],
    recipient: &[u8],
) -> (ServeArgs, PathBuf, PathBuf) {
    {
        let vault = open_vault(&run.join("data"));
        vault
            .sync_state_put(CANARY_MARKER_KEY, CANARY_MARKER_VALUE)
            .unwrap();
        let actor = vault
            .ensure_embedded_owner_actor()
            .expect("the vault's embedded owner");
        let owner = vault
            .authenticate_owner(
                actor,
                &actor.to_hex(),
                true,
                oneiron::store::GateDecisionId::now(),
            )
            .expect("the embedded owner's proof");
        vault
            .retire_vault_key_escrow_as(&owner, &managed_escrow_label(released))
            .expect("the owner retires the released recipient's label");
    }
    let recipient_file = run.join("managed.pub");
    std::fs::write(&recipient_file, recipient).unwrap();
    let outbox = run.join("escrow-outbox");
    std::fs::create_dir_all(&outbox).unwrap();
    std::fs::set_permissions(&outbox, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (args, ready_path) = boot_args(
        run,
        &[
            "--escrow-recipient-file".to_owned(),
            recipient_file.display().to_string(),
            "--escrow-outbox-dir".to_owned(),
            outbox.display().to_string(),
        ],
    );
    (args, ready_path, outbox)
}

/// The labels of the escrow capsule reports the start spooled to `outbox`.
fn spooled_escrow_labels(outbox: &Path) -> BTreeSet<String> {
    std::fs::read_dir(outbox)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("vault-key-escrow-"))
        })
        .map(|path| {
            let report: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            report["label"].as_str().unwrap().to_owned()
        })
        .collect()
}

/// Waits for the ready byte at `path`, for at most 10 s.
async fn wait_for_ready(path: &Path) {
    for _ in 0..400 {
        if std::fs::read(path).is_ok_and(|bytes| bytes == [READY_BYTE]) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("ready byte never arrived at {}", path.display());
}

/// What a managed start that ended before it reported ready came back
/// with, for the failure message.
fn start_end<T>(ended: Result<anyhow::Result<T>, tokio::task::JoinError>) -> String {
    match ended {
        Ok(Ok(_)) => "it returned".to_owned(),
        Ok(Err(error)) => format!("it was refused: {error:#}"),
        Err(error) => format!("its task failed: {error}"),
    }
}

/// The fixture the retired row below stands on starts and seals: a fresh
/// managed escrow recipient beside a label the vault retired gets its wrap,
/// and the outbox gets that wrap's capsule.
#[tokio::test]
async fn a_fresh_escrow_recipient_seals_at_start_beside_a_retired_label() {
    let dir = tempfile::tempdir().unwrap();
    let run = sockets_dir(dir.path());
    let released = escrow_recipient(0x31);
    let fresh = escrow_recipient(0x32);
    let (args, ready_path, outbox) = escrow_boot_args(&run, &released, &fresh);
    let managed = ManagedArgs::from_serve_args(&args).unwrap().unwrap();
    let mut boot = tokio::spawn(async move { serve_managed(&args, managed).await });
    tokio::select! {
        ended = &mut boot => panic!("the start ended before ready: {}", start_end(ended)),
        () = wait_for_ready(&ready_path) => {}
    }

    assert_eq!(
        spooled_escrow_labels(&outbox),
        BTreeSet::from([managed_escrow_label(&fresh)])
    );
    boot.abort();
}

/// A supervisor that still names a recipient this vault retired does not
/// stop the start (FIX 2856, RULING FIX-2856-RETIRED-ESCROW-BOOT = C: a start
/// never waits on the control plane). The vault reports ready and seals no
/// wrap to the released recipient, so the outbox gets no capsule for it.
/// The start used to end with the vault's refusal of the retired label,
/// before the ready byte.
#[tokio::test]
async fn a_retired_escrow_recipient_is_skipped_and_the_start_reports_ready() {
    let dir = tempfile::tempdir().unwrap();
    let run = sockets_dir(dir.path());
    let released = escrow_recipient(0x31);
    let (args, ready_path, outbox) = escrow_boot_args(&run, &released, &released);
    let managed = ManagedArgs::from_serve_args(&args).unwrap().unwrap();
    let mut boot = tokio::spawn(async move { serve_managed(&args, managed).await });
    tokio::select! {
        ended = &mut boot => panic!("the start ended before ready: {}", start_end(ended)),
        () = wait_for_ready(&ready_path) => {}
    }

    assert!(
        spooled_escrow_labels(&outbox).is_empty(),
        "no capsule may be spooled for a retired recipient"
    );
    boot.abort();
}
