//! Schema-key discovery and validation of resolved serve settings.
//! Validates the existing sections without changing their merge order.
//! Configuration definitions and source coordination stay in the parent.

use super::{
    BackupConfigOverride, EmbedderConfig, EmbedderConfigOverride, EmbedderProvider,
    FailureSignalsConfigOverride, FeedbackConfigOverride, FileServeConfig, HostingPrivacyPosture,
    ImportConfigOverride, KeystoreConfigOverride, LimitsConfigOverride, ModelsFile,
    OneironerConfigOverride, RecallConfigOverride, RuntimeConfigOverride, SelfHealConfigOverride,
    ServeConfig, SkillsConfigOverride, SyncConfigField, SyncProtocolValidation,
};

/// The keys the config file's schema holds: its top-level fields for
/// `None`, and for `Some(section)` that section's own keys. `None` for a
/// section whose keys are names (`[connectors.<name>]`), a key that is no
/// section, and a section whose type is no struct.
/// Each list is the one the schema's own derive names, so it cannot drift
/// from what deserializes.
pub(crate) fn settings_schema_keys(section: Option<&str>) -> Option<&'static [&'static str]> {
    let Some(section) = section else {
        return Some(struct_fields::<FileServeConfig>());
    };
    let keys = match section {
        "runtime" => struct_fields::<RuntimeConfigOverride>(),
        "embedder" => struct_fields::<EmbedderConfigOverride>(),
        "oneironer" => struct_fields::<OneironerConfigOverride>(),
        "backup" => struct_fields::<BackupConfigOverride>(),
        "feedback" => struct_fields::<FeedbackConfigOverride>(),
        "failure_signals" => struct_fields::<FailureSignalsConfigOverride>(),
        "self_heal" => struct_fields::<SelfHealConfigOverride>(),
        "recall" => struct_fields::<RecallConfigOverride>(),
        "policy" => struct_fields::<crate::config::PolicyConfig>(),
        "skills" => struct_fields::<SkillsConfigOverride>(),
        "keystore" => struct_fields::<KeystoreConfigOverride>(),
        "limits" => struct_fields::<LimitsConfigOverride>(),
        "import" => struct_fields::<ImportConfigOverride>(),
        "models" => struct_fields::<ModelsFile>(),
        "browser" => struct_fields::<super::BrowserConfig>(),
        "desktop" => struct_fields::<super::DesktopConfig>(),
        "merge_queue" => struct_fields::<super::MergeQueueCheckerConfig>(),
        "gpu" => struct_fields::<crate::runtime::GpuPoolConfig>(),
        "native_mail" => struct_fields::<super::NativeMailConfig>(),
        "device_sync" => struct_fields::<super::DeviceSyncConfig>(),
        "embedding" => struct_fields::<super::EmbeddingConfig>(),
        "line" => struct_fields::<super::LineConfig>(),
        "channel_endpoints" => struct_fields::<crate::config::ChannelEndpointsConfig>(),
        "linear" => struct_fields::<super::LinearConfig>(),
        _ => return None,
    };
    (!keys.is_empty()).then_some(keys)
}

/// The field names a derived struct reads, as its derive passes them to
/// `deserialize_struct`: this deserializer keeps them and refuses, so no
/// value is read. Empty for a type that is not a struct.
fn struct_fields<T: serde::de::DeserializeOwned>() -> &'static [&'static str] {
    struct Fields(&'static [&'static str]);
    impl<'de> serde::Deserializer<'de> for &mut Fields {
        type Error = serde::de::value::Error;
        fn deserialize_any<V: serde::de::Visitor<'de>>(
            self,
            _: V,
        ) -> Result<V::Value, Self::Error> {
            Err(serde::de::Error::custom("not a struct"))
        }
        fn deserialize_struct<V: serde::de::Visitor<'de>>(
            self,
            _: &'static str,
            fields: &'static [&'static str],
            _: V,
        ) -> Result<V::Value, Self::Error> {
            self.0 = fields;
            Err(serde::de::Error::custom("field names only"))
        }
        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes
            byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct map enum
            identifier ignored_any
        }
    }
    let mut fields = Fields(&[]);
    let _ = T::deserialize(&mut fields);
    fields.0
}

/// The engine's own config-validation refusal, wrapped for this crate's
/// `anyhow` boundary so it survives as a downcastable `oneiron::Error`.
fn invalid_sync_config(field: SyncConfigField) -> anyhow::Error {
    oneiron::Error::sync_protocol(SyncProtocolValidation::InvalidConfig { field }).into()
}

pub(super) fn validate_serve_config(config: &ServeConfig) -> anyhow::Result<()> {
    // The SAME three rules `SyncServerConfig::validate` enforces, returning the
    // SAME typed error rather than a second, stringly copy of it: this door and
    // that one must not drift when a field is added, and a caller reading the
    // merge failure gets the field back as `SyncConfigField`, not as prose.
    // Display text is unchanged — `oneiron::error::SyncError::SyncProtocolError` renders
    // "sync protocol error: <field> must be positive".
    if config.ephemeral_timeout_ms <= 0 {
        return Err(invalid_sync_config(SyncConfigField::EphemeralTimeoutMs));
    }
    if config.max_ephemeral_payload_bytes == 0 {
        return Err(invalid_sync_config(
            SyncConfigField::MaxEphemeralPayloadBytes,
        ));
    }
    if config.max_ephemeral_snapshot_bytes == 0 {
        return Err(invalid_sync_config(
            SyncConfigField::MaxEphemeralSnapshotBytes,
        ));
    }
    validate_embedder_config(config)?;
    config.runtime.validate_key_source()?;
    if let Some(oneironer) = &config.oneironer {
        oneironer.validate()?;
    }
    config.backup.validate()?;
    config.feedback.validate()?;
    config.failure_signals.validate()?;
    config.self_heal.validate()?;
    config.recall.validate()?;
    config.skills.validate()?;
    config.keystore.validate()?;
    config.limits.validate()?;
    config.import.validate(&config.vault_path)?;
    if let Some(browser) = &config.browser {
        browser.validate()?;
    }
    if let Some(desktop) = &config.desktop {
        desktop.validate()?;
    }
    if let Some(merge_queue) = &config.merge_queue {
        merge_queue.validate()?;
    }
    if let Some(gpu) = &config.gpu {
        gpu.validate()?;
    }
    if let Some(native_mail) = &config.native_mail {
        native_mail.validate()?;
    }
    if let Some(device_sync) = &config.device_sync {
        device_sync.validate()?;
    }
    for (name, connector) in &config.connectors {
        connector.validate(name)?;
    }
    config.line.validate()?;
    config.channel_endpoints.validate()?;
    if let Some(linear) = &config.linear {
        linear.validate()?;
    }
    crate::conversation_training::validate_outbox_dir(
        config.publisher_training_outbox_dir.as_deref(),
    )?;
    crate::conversation_training::validate_intake_origin(&config.publisher_training_intake_origin)?;
    if let Some(embedding) = &config.embedding {
        embedding.validate()?;
    }
    // Mirrors `oneiron::VaultPrivacyConfig::validate`, so a bad pairing is
    // refused while it is still a config error with an operator-facing
    // remedy, not only at open time. Placement never vetoes a custody: a
    // hosted vault may run on the owner's key, a self-hosted one on the
    // owner's own KMS.
    if let Some(key_ref) = config.hosted_kms_key_ref.as_deref() {
        if key_ref.trim().is_empty() {
            anyhow::bail!(
                "KMS key custody requires a non-empty key reference (--hosted-kms-key-ref / ONEIRON_HOSTED_KMS_KEY_REF)"
            );
        }
        if config.privacy_posture == HostingPrivacyPosture::Relay {
            anyhow::bail!(
                "a blind relay holds no data key; drop --hosted-kms-key-ref / ONEIRON_HOSTED_KMS_KEY_REF or select --privacy-posture hosted or self-host"
            );
        }
    }
    Ok(())
}

/// Refuses an embedder section that cannot produce a working slot.
///
/// The `model_id` grammar is deliberately NOT re-checked here: the vault
/// enforces it at open, and a second copy of that grammar in this crate is a
/// place for the two to drift.
pub(super) fn validate_embedder_config(config: &ServeConfig) -> anyhow::Result<()> {
    let Some(embedder) = config.embedder.as_ref() else {
        return Ok(());
    };
    super::remote_embedder::validate_remote(embedder)?;
    if !embedder.is_active() {
        return Ok(());
    }
    if embedder.dimensions != config.dimensions {
        anyhow::bail!(
            "embedder.dimensions ({}) must equal dimensions ({}); one vault holds one embedding space",
            embedder.dimensions,
            config.dimensions
        );
    }
    if embedder.batch_size == 0 {
        anyhow::bail!("embedder.batch_size must be greater than zero");
    }
    if embedder.max_input_tokens == 0 {
        anyhow::bail!("embedder.max_input_tokens must be greater than zero");
    }
    match embedder.provider {
        EmbedderProvider::Endpoint => validate_endpoint_embedder(embedder)?,
        EmbedderProvider::Local => validate_local_embedder(embedder)?,
        EmbedderProvider::None => {}
    }
    Ok(())
}

fn validate_endpoint_embedder(embedder: &EmbedderConfig) -> anyhow::Result<()> {
    if embedder
        .endpoint
        .endpoint
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        anyhow::bail!(
            "embedder.provider = \"endpoint\" requires embedder.endpoint (--embedder-endpoint / ONEIRON_EMBEDDER_ENDPOINT)"
        );
    }
    if embedder.endpoint.timeout_ms == 0 {
        anyhow::bail!(
            "embedder.timeout_ms must be greater than zero; a zero timeout refuses every request before it is sent"
        );
    }
    if embedder
        .endpoint
        .model_key
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        anyhow::bail!(
            "embedder.provider = \"endpoint\" requires embedder.model_key (--embedder-model-key / ONEIRON_EMBEDDER_MODEL_KEY)"
        );
    }
    Ok(())
}

fn validate_local_embedder(embedder: &EmbedderConfig) -> anyhow::Result<()> {
    // The input cap is checked when the model loads, against the window its
    // own `config.json` declares.
    //
    // bf16 has no CPU matmul path in candle worth running, so the pairing is
    // refused while it is still a config error rather than a load failure ten
    // minutes into a download.
    if embedder.local.quant == super::embedder::EmbedderQuant::None
        && embedder.local.device == super::embedder::EmbedderDevice::Cpu
    {
        anyhow::bail!(
            "embedder.quant = \"none\" needs a GPU device; keep quant = \"q8_0\" on a CPU host"
        );
    }
    Ok(())
}
