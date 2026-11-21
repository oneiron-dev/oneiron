//! The fixture the Gmail quota tests share: a vault with the mail pack
//! installed and the owner's Gmail mailbox connected, and one import step
//! through any wire, as the owner's `vault.mail.sources.sync` runs it.

#![allow(dead_code)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::mail_pack::source::due_sources;
use oneiron::mail_pack::{
    MailCopySetting, MailProvider, MailProviderWire, MailSourceConnectRequest, MailSourceKind,
    MailSourceRef, MailSyncBudget, MailSyncReport, MailSyncStatusView,
};
use oneiron::secret_custody::{SECRET_CUSTODY_SCHEMA_VERSION, decode_secret_custody_body};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The mailbox's address and the custody record its credential is under.
pub(crate) const OWNER_ADDRESS: &str = "owen@example.com";
const CUSTODY_REF: &str = "test-gmail-quota-cred";

/// Unix seconds now.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Registers the Gmail credential `CUSTODY_REF`, stored for the owner, as
/// the owner's custody door registers one.
fn register_mail_credential(vault: &Vault) -> TestResult {
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
        (Value::from("name"), Value::from(CUSTODY_REF)),
        (Value::from("class"), Value::from("custody-portable")),
        (Value::from("device_only"), Value::from(false)),
        (
            Value::from("value_bytes"),
            Value::Binary(b"test-gmail-token".to_vec()),
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

/// A vault with the mail pack installed and the owner's Gmail mailbox
/// connected, copying all mail.
pub(crate) struct Mailbox {
    _directory: tempfile::TempDir,
    pub(crate) vault: Vault,
    pub(crate) owner: EntityId,
    pub(crate) source: EntityId,
}

impl Mailbox {
    pub(crate) fn connect() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        // The pack installs as the embedded owner, whose proof needs the
        // vault's writer lease: open it owned, and start the host as a
        // server does.
        let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let issuer = HostSlipIssuer::from_secret(b"mail gmail quota test host")?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault.ensure_host_root_slip(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let memory = vault.memory(owner, EdgeActorClass::Human);
        oneiron::mail_pack::install_mail_calendar_pack_embedded(&memory)?;
        register_mail_credential(&vault)?;
        let connected = memory.mail_sources_connect(&MailSourceConnectRequest {
            provider: MailProvider::Google,
            kind: MailSourceKind::PersonalMailbox,
            address: OWNER_ADDRESS.to_owned(),
            provider_account: OWNER_ADDRESS.to_owned(),
            custody_ref: CUSTODY_REF.to_owned(),
            members: Vec::new(),
            for_person: None,
            channel_identity_ref: None,
            copy: Some(MailCopySetting::All),
            on_provider_delete: None,
            calendar_details: None,
        })?;
        let source = EntityId::from_hex(&connected.source.source_ref)?;
        Ok(Self {
            _directory: directory,
            vault,
            owner,
            source,
        })
    }

    /// One import step through `wire`, as the owner's
    /// `vault.mail.sources.sync` runs it.
    pub(crate) fn step(
        &self,
        wire: &dyn MailProviderWire,
        budget: MailSyncBudget,
    ) -> Result<MailSyncReport, Box<dyn std::error::Error>> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let owner = memory.embedded_owner("vault.mail.sources.sync")?;
        Ok(self
            .vault
            .mail_sync_step(&owner, self.source, wire, budget)?)
    }

    pub(crate) fn status(&self) -> Result<MailSyncStatusView, Box<dyn std::error::Error>> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        Ok(memory.mail_sources_sync_status(&MailSourceRef {
            source_ref: self.source.to_hex(),
        })?)
    }

    pub(crate) fn due(&self) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(due_sources(&self.vault)?
            .iter()
            .any(|(source, _)| *source == self.source))
    }
}
