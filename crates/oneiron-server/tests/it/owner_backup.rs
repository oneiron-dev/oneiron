//! The owner's backup loop through the shipped `oneiron` binary: back up,
//! change the vault, rehearse (live vault untouched), restore (content back),
//! and `doctor` saying where the data lives.
use std::path::Path;
use std::process::Command;

use oneiron::registry::{ENTITY_TYPE_PERSON, entity_type_registry_entry};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::Value;

fn oneiron(config: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_oneiron"))
        .args(args)
        .arg("--config")
        .arg(config)
        .env_remove("ONEIRON_VAULT_PATH")
        .env_remove("ONEIRON_BACKUP_DIR")
        .output()
        .expect("run oneiron")
}

fn json(output: &std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON on stdout")
}

fn open(path: &Path) -> Vault {
    Vault::open_owned(path, VaultConfig::server()).expect("open vault")
}

fn add_person(path: &Path, body: &[u8]) -> EntityId {
    let vault = open(path);
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )
        .expect("put person");
    id
}

#[test]
fn backup_rehearse_restore_and_doctor_through_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    let init = Command::new(env!("CARGO_BIN_EXE_oneiron"))
        .args(["init", vault_path.to_str().unwrap()])
        .args(["--config", config.to_str().unwrap(), "--embedder", "none"])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    // The schedule is opt-in; turning it on is one config section.
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("\n[backup]\nenabled = true\nevery_hours = 12\nkeep = 3\n");
    std::fs::write(&config, text).unwrap();
    let person = entity_type_registry_entry(ENTITY_TYPE_PERSON).unwrap().kind;

    let kept = add_person(&vault_path, b"in the backup");
    let people_at_backup = open(&vault_path)
        .count_entities_by_type(ENTITY_TYPE_PERSON)
        .unwrap();
    let taken = json(&oneiron(&config, &["backup"]));
    let backup = taken["backup"]["path"].as_str().unwrap().to_owned();
    assert!(backup.starts_with(dir.path().join("vault.backups").to_str().unwrap()));
    let later = add_person(&vault_path, b"after the backup");

    // Rehearse while another process holds the vault: it never opens it.
    let live = open(&vault_path);
    let rehearsal = json(&oneiron(&config, &["restore", &backup, "--rehearse"]));
    assert_eq!(rehearsal["verified"], true);
    assert_eq!(rehearsal["checkpoint_id"], taken["checkpoint_id"]);
    assert_eq!(rehearsal["kinds"][person], people_at_backup);
    assert_eq!(rehearsal["kept"], false);
    assert!(!Path::new(rehearsal["restored_into"].as_str().unwrap()).exists());
    assert!(live.get(&kept).unwrap().is_some());
    assert!(live.get(&later).unwrap().is_some());
    // A real restore refuses a vault in use and leaves it as it was.
    let refused = oneiron(&config, &["restore", &backup]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("running `oneiron serve`"));
    assert!(live.get(&later).unwrap().is_some());
    drop(live);

    let restored = json(&oneiron(&config, &["restore", &backup]));
    assert_eq!(restored["checkpoint_id"], taken["checkpoint_id"]);
    let vault = open(&vault_path);
    assert!(vault.get(&kept).unwrap().is_some());
    assert!(vault.get(&later).unwrap().is_none());
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_PERSON).unwrap(),
        people_at_backup
    );
    drop(vault);
    let previous = Path::new(restored["previous_vault"].as_str().unwrap());
    assert!(open(previous).get(&later).unwrap().is_some());
    // It shares the restored vault's key custody, so it is archived: it reads
    // but takes no write until the owner activates it beside the vault.
    let write = open(previous).put_entity(
        &EntityId::now(),
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"into the archive",
    );
    assert!(write.is_err());
    let activated = json(&oneiron(
        &config,
        &["restore", "--activate", previous.to_str().unwrap()],
    ));
    assert_eq!(activated["vault"], previous.to_str().unwrap());
    add_person(previous, b"after the activation");

    // Where the data lives: path, size, last backup, last export.
    let export_file = dir.path().join("vault.md");
    let exported = json(&oneiron(
        &config,
        &[
            "export",
            "--format",
            "md",
            "--out",
            export_file.to_str().unwrap(),
        ],
    ));
    assert_eq!(exported["format"], "md");
    assert!(std::fs::metadata(&export_file).unwrap().len() > 0);
    let doctor = Command::new(env!("CARGO_BIN_EXE_oneiron"))
        .args(["doctor", vault_path.to_str().unwrap()])
        .args(["--config", config.to_str().unwrap()])
        .output()
        .unwrap();
    let doctor = json(&doctor);
    let location = &doctor["location"];
    assert_eq!(
        location["vault"],
        vault_path.canonicalize().unwrap().to_str().unwrap()
    );
    assert!(location["disk_bytes"].as_u64().unwrap() > 0);
    assert_eq!(location["backups"]["count"], 1);
    assert_eq!(location["backups"]["last"]["path"], backup.as_str());
    assert_eq!(location["backups"]["every_hours"], 12);
    assert_eq!(location["backups"]["keep"], 3);
    assert_eq!(location["last_export"]["format"], "md");
    assert_eq!(location["secret_scan"], "on");
}

#[test]
fn secret_scan_switch_from_the_cli_is_receipted() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    let init = Command::new(env!("CARGO_BIN_EXE_oneiron"))
        .args(["init", vault_path.to_str().unwrap()])
        .args(["--config", config.to_str().unwrap(), "--embedder", "none"])
        .output()
        .unwrap();
    assert!(init.status.success());
    let receipt = json(&oneiron(&config, &["secret-scan", "off"]));
    assert_eq!(receipt["mode"], "off");
    assert_eq!(receipt["previous"], "on");
    let state = json(&oneiron(&config, &["secret-scan"]));
    assert_eq!(state["mode"], "off");
    assert_eq!(state["changes"].as_array().unwrap().len(), 1);
    let receipt = json(&oneiron(&config, &["secret-scan", "on"]));
    assert_eq!(receipt["revision"], 2);
}

/// First try, 2026-10-10: `doctor --config` refused a vault `init` made 1024
/// wide with a larger map unless `--dimensions` and `--map-size` were passed
/// again. It opens the vault as `serve` and `import` do, from the config, and
/// a flag still overrides.
#[test]
fn doctor_opens_the_vault_with_the_configs_dimensions_and_map_size() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    let map_size = (1_u64 << 34).to_string();
    let init = Command::new(env!("CARGO_BIN_EXE_oneiron"))
        .args(["init", vault_path.to_str().unwrap()])
        .args(["--config", config.to_str().unwrap()])
        .args(["--embedder", "none", "--dimensions", "1024"])
        .args(["--map-size", &map_size])
        .env_remove("ONEIRON_VAULT_PATH")
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let doctor = |flags: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["doctor", vault_path.to_str().unwrap()])
            .args(["--config", config.to_str().unwrap()])
            .args(flags)
            .env_remove("ONEIRON_VAULT_PATH")
            .output()
            .unwrap()
    };

    let report = json(&doctor(&[]));
    assert!(report.get("config_errors").is_none(), "{report}");
    assert_eq!(
        report["location"]["vault"],
        vault_path.canonicalize().unwrap().to_str().unwrap()
    );
    json(&doctor(&["--dimensions", "1024"]));
    assert!(
        !doctor(&["--dimensions", "4096"]).status.success(),
        "the flag, not the config, is what opens the vault"
    );
}
