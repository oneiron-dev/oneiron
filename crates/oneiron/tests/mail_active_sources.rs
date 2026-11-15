//! [VAULT-STORE-FIELD-PUBLIC]: the host steps of `oneiron-mail-pack`
//! (`mail_sources_due`, `mail_sync_sources`) read the pack's sources through
//! `oneiron::mail_pack::source::active_sources`, since the vault's store is
//! crate-private again. The door answers what the lifted scans read before:
//! none while the pack is not installed, then every Active source with its
//! kind, and no source its person paused.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test mail_active_sources`.

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::mail_pack::source::active_sources;
use oneiron::mail_pack::{
    MailProvider, MailSourceConnectRequest, MailSourceKind, MailSourceSettingsRequest,
    MailSourceStatus,
};
use oneiron::memory::hook_regen_doors::PackPutOutcome;
use oneiron::secret_custody::{SECRET_CUSTODY_SCHEMA_VERSION, decode_secret_custody_body};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Registers a Gmail credential under `custody_ref`, stored for the owner,
/// as the owner's custody door registers one.
fn register_mail_credential(vault: &Vault, custody_ref: &str) -> TestResult {
    use rmpv::Value;
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    let floor = Value::Map(vec![
        (Value::from("portable"), band(0, 2)),
        (Value::from("device_bound"), band(0, 2)),
        (Value::from("cross_vault"), band(0, 0)),
        (Value::from("rotation_max_age_secs"), Value::Nil),
        (Value::from("env_bindings"), Value::Map(vec![])),
    ]);
    let binding = Value::Map(vec![
        (Value::from("effector"), Value::from("connector:gmail")),
        (Value::from("tier_ceiling"), Value::from(0_u64)),
        (Value::from("scopes"), Value::Array(vec![])),
    ]);
    let body = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION)),
        ),
        (Value::from("name"), Value::from(custody_ref)),
        (Value::from("class"), Value::from("custody-portable")),
        (Value::from("device_only"), Value::from(false)),
        (
            Value::from("value_bytes"),
            Value::Binary(b"test-mail-token".to_vec()),
        ),
        (Value::from("status"), Value::from("active")),
        (Value::from("registered_at"), Value::from(1_u64)),
        (Value::from("rotated_at"), Value::Nil),
        (Value::from("rotation_generation"), Value::from(0_u64)),
        (Value::from("bindings"), Value::Array(vec![binding])),
        (Value::from("manifest_ref"), Value::from("")),
        (Value::from("declared_paths"), Value::Array(vec![])),
        (Value::from("policy_floor_snapshot"), floor),
        (Value::from("model_reveal_allowed"), Value::from(true)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body)?;
    vault.register_secret(decode_secret_custody_body(&bytes)?)?;
    Ok(())
}

/// The connect request for the owner's own Gmail mailbox `address`, backed
/// by the credential `custody_ref`.
fn personal_mailbox(address: &str, custody_ref: &str) -> MailSourceConnectRequest {
    MailSourceConnectRequest {
        provider: MailProvider::Google,
        kind: MailSourceKind::PersonalMailbox,
        address: address.to_owned(),
        provider_account: address.to_owned(),
        custody_ref: custody_ref.to_owned(),
        members: Vec::new(),
        for_person: None,
        channel_identity_ref: None,
        copy: None,
        on_provider_delete: None,
        calendar_details: None,
    }
}

/// The door, sorted by source id: the store keeps no order the test names.
fn active(vault: &Vault) -> Result<Vec<(EntityId, MailSourceKind)>, Box<dyn std::error::Error>> {
    let mut sources = active_sources(vault)?;
    sources.sort_by_key(|(source, _)| source.to_hex());
    Ok(sources)
}

#[test]
fn active_sources_lists_each_active_source_while_the_pack_is_installed() -> TestResult {
    let directory = tempfile::tempdir()?;
    // The pack installs as the embedded owner, whose proof needs the vault's
    // writer lease: open it owned, and start the host as a server does.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"mail active sources test host")?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let memory = vault.memory(owner, EdgeActorClass::Human);

    assert!(
        active(&vault)?.is_empty(),
        "a vault without the pack has no source to step"
    );

    let installed = oneiron::mail_pack::install_mail_calendar_pack_embedded(&memory)?;
    assert_eq!(
        installed.outcome,
        PackPutOutcome::Installed,
        "the embedded owner installs the pack: {installed:?}"
    );
    assert!(
        active(&vault)?.is_empty(),
        "the pack installed alone connects no source"
    );

    register_mail_credential(&vault, "test-mail-cred-first")?;
    register_mail_credential(&vault, "test-mail-cred-second")?;
    let first = memory.mail_sources_connect(&personal_mailbox(
        "first@test.example",
        "test-mail-cred-first",
    ))?;
    let second = memory.mail_sources_connect(&personal_mailbox(
        "second@test.example",
        "test-mail-cred-second",
    ))?;
    let first = EntityId::from_hex(&first.source.source_ref)?;
    let second = EntityId::from_hex(&second.source.source_ref)?;
    let mut both = vec![
        (first, MailSourceKind::PersonalMailbox),
        (second, MailSourceKind::PersonalMailbox),
    ];
    both.sort_by_key(|(source, _)| source.to_hex());
    assert_eq!(
        active(&vault)?,
        both,
        "every connected source is Active, and the door names its kind"
    );

    let paused = memory.mail_sources_settings_set(&MailSourceSettingsRequest {
        source_ref: second.to_hex(),
        copy: None,
        on_provider_delete: None,
        calendar_details: None,
        status: Some(MailSourceStatus::Paused),
        own_addresses: None,
    })?;
    assert_eq!(paused.status, MailSourceStatus::Paused, "{paused:?}");
    assert_eq!(
        active(&vault)?,
        vec![(first, MailSourceKind::PersonalMailbox)],
        "a paused source is not stepped"
    );
    Ok(())
}
