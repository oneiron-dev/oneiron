//! A vault in a folder a sync service watches is named by the shipped
//! binary: `init` prints a warning and `doctor` reports the service and its
//! folder under `location.synced_folder`. Vaults live in the app folder,
//! never in a synced folder (CROSS-ARCH-0019 #vault-20-hot, owner card
//! E2-HOT B, 2026-10-09).
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const SECRET: &str = "synced-folder-check-issuer-key-not-a-bearer";

#[test]
fn init_and_doctor_name_the_sync_service_of_a_vault_in_a_synced_folder() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let dropbox = base.join("Dropbox");
    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::write(dropbox.join(".dropbox"), "{}").unwrap();
    let mobile_documents = base.join("home/Library/Mobile Documents");
    let cloud_storage = base.join("home/Library/CloudStorage/GoogleDrive-owner@example.com");
    let syncthing = base.join("shared");
    std::fs::create_dir_all(syncthing.join(".stfolder")).unwrap();
    // A link into a synced folder counts: the files live where it points.
    let linked_target = dropbox.join("linked");
    std::fs::create_dir_all(&linked_target).unwrap();
    std::os::unix::fs::symlink(&linked_target, base.join("linked")).unwrap();
    let cases: [(&str, PathBuf, &str, &Path); 5] = [
        (
            "a Dropbox root",
            dropbox.join("notes/vault"),
            "dropbox",
            &dropbox,
        ),
        (
            "iCloud Drive",
            mobile_documents.join("com~apple~CloudDocs/vault"),
            "icloud-drive",
            &mobile_documents,
        ),
        (
            "a macOS cloud storage provider",
            cloud_storage.join("vault"),
            "google-drive",
            &cloud_storage,
        ),
        (
            "a Syncthing folder",
            syncthing.join("vault"),
            "syncthing",
            &syncthing,
        ),
        (
            "a link into a Dropbox root",
            base.join("linked/vault"),
            "dropbox",
            &dropbox,
        ),
    ];
    for (index, (case, vault, service, root)) in cases.into_iter().enumerate() {
        let config = base.join(format!("oneiron-{index}.toml"));
        assert_reported(case, &vault, &config, service, root, false);
    }
}

/// iCloud's Desktop & Documents sync leaves no marker on the home folder, so
/// a vault under it is reported as likely synced when iCloud Drive holds a
/// folder of the same name.
#[test]
fn init_and_doctor_report_icloud_desktop_and_documents_sync_as_likely() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().canonicalize().unwrap().join("home");
    std::fs::create_dir_all(home.join("Library/Mobile Documents/com~apple~CloudDocs/Documents"))
        .unwrap();
    let documents = home.join("Documents");
    assert_reported(
        "a home Documents folder iCloud Drive mirrors",
        &documents.join("oneiron/vault"),
        &dir.path().join("oneiron.toml"),
        "icloud-desktop-documents",
        &documents,
        true,
    );
}

/// `~/.dropbox` is the Dropbox client's settings directory, not a synced
/// root, and a home Documents folder with no iCloud Drive twin is not
/// synced: vaults there are reported as in no synced folder.
#[test]
fn a_vault_in_no_synced_folder_gets_no_warning() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".dropbox")).unwrap();
    std::fs::create_dir_all(home.join("Library/Mobile Documents/com~apple~CloudDocs")).unwrap();
    let vaults = [
        home.join("Library/Application Support/Oneiron/vault"),
        home.join("Documents/vault"),
    ];
    for (index, vault) in vaults.iter().enumerate() {
        std::fs::create_dir_all(vault.parent().unwrap()).unwrap();
        let config = dir.path().join(format!("oneiron-{index}.toml"));
        let init = stdout(oneiron(
            &["init", vault.to_str().unwrap(), "--embedder", "none"],
            &config,
        ));
        assert!(
            !init.contains("warning: the vault is"),
            "init warns of no sync service for {}: {init}",
            vault.display()
        );
        let report = doctor(vault, &config);
        assert!(
            report["location"].get("vault").is_some(),
            "doctor reports the location: {report}"
        );
        assert!(
            report["location"].get("synced_folder").is_none(),
            "doctor reports no synced folder for {}: {report}",
            vault.display()
        );
    }
}

/// `init` of `vault` prints the synced-folder warning, and `doctor` reports
/// `service`, its canonical `root` and whether the service is inferred.
fn assert_reported(
    case: &str,
    vault: &Path,
    config: &Path,
    service: &str,
    root: &Path,
    likely: bool,
) {
    std::fs::create_dir_all(vault.parent().unwrap()).unwrap();
    let init = stdout(oneiron(
        &["init", vault.to_str().unwrap(), "--embedder", "none"],
        config,
    ));
    let warning = format!(
        "warning: the vault is {}in a folder `{service}` syncs ({})",
        if likely { "likely " } else { "" },
        root.display()
    );
    assert!(
        init.contains(&warning),
        "init under {case} prints {warning:?}: {init}"
    );
    let report = doctor(vault, config);
    let folder = &report["location"]["synced_folder"];
    assert_eq!(
        folder["service"].as_str(),
        Some(service),
        "doctor names the service under {case}: {report}"
    );
    assert_eq!(
        folder["root"].as_str(),
        root.to_str(),
        "doctor names the synced folder under {case}: {report}"
    );
    assert_eq!(
        folder["likely"].as_bool(),
        Some(likely),
        "doctor says whether the service is inferred under {case}: {report}"
    );
}

fn doctor(vault: &Path, config: &Path) -> Value {
    let text = stdout(oneiron(&["doctor", vault.to_str().unwrap()], config));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("doctor printed no JSON ({error}): {text}"))
}

fn oneiron(args: &[&str], config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    // Do not inherit vault/model/URL overrides from the build host.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("ONEIRON_") {
            command.env_remove(name);
        }
    }
    command
        .args(args)
        .arg("--config")
        .arg(config)
        .env("ONEIRON_AUTH_SECRET", SECRET);
    command
}

fn stdout(mut command: Command) -> String {
    let output = command.output().expect("run oneiron");
    assert!(
        output.status.success(),
        "oneiron exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 stdout")
}
