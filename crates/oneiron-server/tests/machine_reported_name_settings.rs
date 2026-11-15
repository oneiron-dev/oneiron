//! The settings file's machine-reported name and model reach the vault config.
//!
//! The host declares what this install reports for itself in the owner's
//! machine list (`machine_reported_name`, `machine_reported_model`), as it
//! declares the install's class (`device_class`): file-only keys, display
//! only, never read off the operating system (FIX [DEVICE-DISPLAY-NAME]).
//! Public paths only: the public serve-config loader and
//! `ServeConfig::base_vault_config`.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use oneiron_server::config::{
    EnvConfig, ServeArgs, ServeConfig, resolve_serve_config_with_sources,
};

/// The serve config the settings file at `path` resolves to, with an empty
/// environment and no default config path, so only the file speaks.
fn resolve(path: &Path) -> ServeConfig {
    let args = ServeArgs {
        config: Some(path.to_path_buf()),
        ..ServeArgs::default()
    };
    let env = EnvConfig::from_pairs(std::iter::empty::<(&str, &str)>()).expect("empty env");
    resolve_serve_config_with_sources(&args, env, None).expect("the settings resolve")
}

#[test]
fn a_settings_file_naming_the_machine_reaches_the_vault_config() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("oneiron.toml");
    std::fs::write(
        &config,
        "machine_reported_name = \"Maya's MacBook\"\n\
         machine_reported_model = \"MacBook Air\"\n",
    )
    .unwrap();
    let vault = resolve(&config).base_vault_config();
    assert_eq!(
        vault.machine_reported_name.as_deref(),
        Some("Maya's MacBook")
    );
    assert_eq!(vault.machine_reported_model.as_deref(), Some("MacBook Air"));
}

#[test]
fn a_settings_file_without_the_keys_declares_no_name() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("oneiron.toml");
    std::fs::write(&config, "").unwrap();
    let vault = resolve(&config).base_vault_config();
    assert_eq!(vault.machine_reported_name, None);
    assert_eq!(vault.machine_reported_model, None);
}
