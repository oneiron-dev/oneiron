use super::*;

#[test]
fn a_failed_export_write_leaves_no_file_and_the_same_out_retries() {
    let root = tempfile::tempdir().unwrap();
    let out = root.path().join("vault.md");
    let error = write_new_file(&out, |file| {
        file.write_all(b"half an exp")?;
        Err(io::Error::other("disk full"))
    })
    .unwrap_err();
    assert!(error.to_string().contains("disk full"), "{error}");
    assert!(!out.exists(), "the partial export is removed");

    write_new_file(&out, |file| file.write_all(b"the whole export")).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"the whole export");
    assert!(
        write_new_file(&out, |_| Ok(())).is_err(),
        "an existing export is never overwritten"
    );
    assert_eq!(std::fs::read(&out).unwrap(), b"the whole export");
}

#[test]
fn doctor_reports_the_vault_beside_a_serve_setting_that_does_not_resolve() {
    let root = tempfile::tempdir().unwrap();
    let vault_path = root.path().join("vault");
    drop(oneiron::Vault::open_owned(&vault_path, oneiron::VaultConfig::server()).unwrap());
    let backups = root.path().join("kept-backups");
    let config = root.path().join("oneiron.toml");
    // A server setting doctor never reads fails validation; the backup
    // section is sound.
    std::fs::write(
        &config,
        format!(
            "ephemeral_timeout_ms = 0\n[backup]\ndir = {:?}\nkeep = 3\n",
            backups.display().to_string()
        ),
    )
    .unwrap();
    let report = doctor_report(DoctorArgs {
        vault: crate::cli::VaultArgs {
            path: vault_path.clone(),
            dimensions: oneiron::VaultConfig::server().dimensions,
            map_size: oneiron::VaultConfig::server().map_size,
            dict_search_paths: None,
        },
        config: Some(config),
    })
    .expect("doctor reports despite the bad setting");
    let location = &report["location"];
    assert_eq!(
        location["vault"],
        vault_path.canonicalize().unwrap().display().to_string()
    );
    assert_eq!(location["backups"]["dir"], backups.display().to_string());
    assert_eq!(location["backups"]["keep"], 3);
    assert!(report.get("unreadable_fields").is_some(), "{report}");
    let errors = report["config_errors"].as_array().expect("errors listed");
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].as_str().unwrap().contains("ephemeral_timeout_ms"),
        "{errors:?}"
    );
}

/// ASTRA-9A-2-R2 F4: a serve setting of the wrong type elsewhere in the file
/// does not hide the configured backups: doctor reads the `[backup]` table on
/// its own and finds the backup there.
#[test]
fn doctor_finds_the_configured_backups_beside_a_mistyped_serve_setting() {
    let root = tempfile::tempdir().unwrap();
    let vault_path = root.path().join("vault");
    let backups = root.path().join("kept-backups");
    {
        let vault =
            oneiron::Vault::open_owned(&vault_path, oneiron::VaultConfig::server()).unwrap();
        let plan = BackupPlan::new(&vault_path, backups.clone(), 3);
        backup::take(&vault, &plan).unwrap();
    }
    let config = root.path().join("oneiron.toml");
    std::fs::write(
        &config,
        format!(
            "ephemeral_timeout_ms = \"oops\"\n[backup]\ndir = {:?}\nkeep = 3\n",
            backups.display().to_string()
        ),
    )
    .unwrap();
    let report = doctor_report(DoctorArgs {
        vault: crate::cli::VaultArgs {
            path: vault_path,
            dimensions: oneiron::VaultConfig::server().dimensions,
            map_size: oneiron::VaultConfig::server().map_size,
            dict_search_paths: None,
        },
        config: Some(config),
    })
    .expect("doctor reports despite the mistyped setting");
    let location = &report["location"]["backups"];
    assert_eq!(location["dir"], backups.display().to_string(), "{report}");
    assert_eq!(location["count"], 1, "{report}");
    let errors = report["config_errors"].as_array().expect("errors listed");
    assert!(
        errors
            .iter()
            .any(|error| error.as_str().unwrap().contains("ephemeral_timeout_ms")),
        "{errors:?}"
    );
}
