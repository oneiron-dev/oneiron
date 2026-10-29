//! Environment lookup and application of layered serve sections.
//! Applies each section at its existing position in the merge order.
//! Configuration types, fields, and layer coordination stay in the parent.

use super::{
    ConfigLayer, DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_FILE, EmbedderConfig, EnvConfig, HashMap,
    OneironerConfig, PartialServeConfig, Path, PathBuf, RuntimeConfigOverride, RuntimeMode,
    RuntimeProviderKind, RuntimeRole, RuntimeRoleTargetOverride, ServeConfig, expand_home,
    lookup_backup_override, lookup_bool, lookup_embedder_override, lookup_failure_signals_override,
    lookup_feedback_override, lookup_keystore_override, lookup_list, lookup_oneironer_override,
    lookup_parse, lookup_path, lookup_path_list, lookup_recall_override, lookup_skills_override,
    normalize_list, parse_trusted_proxies,
};

impl EnvConfig {
    pub fn from_process() -> anyhow::Result<Self> {
        // Privacy inputs fail closed by presence. Read each once and never
        // attach VarError::NotUnicode, whose diagnostics expose the raw value.
        let privacy_value = |key: &str| match std::env::var(key) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(anyhow::anyhow!("{key} must contain valid Unicode"))
            }
        };
        let privacy_posture = privacy_value("ONEIRON_PRIVACY_POSTURE")?;
        let hosted_kms_key_ref = privacy_value("ONEIRON_HOSTED_KMS_KEY_REF")?;
        Self::from_lookup(|key| match key {
            "ONEIRON_PRIVACY_POSTURE" => privacy_posture.clone(),
            "ONEIRON_HOSTED_KMS_KEY_REF" => hosted_kms_key_ref.clone(),
            // Keep the existing semantics for every unrelated environment key.
            _ => std::env::var(key).ok(),
        })
    }

    pub fn from_pairs<I, K, V>(pairs: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let values: HashMap<String, String> = pairs
            .into_iter()
            .map(|(key, value)| (key.as_ref().to_owned(), value.as_ref().to_owned()))
            .collect();
        Self::from_lookup(|key| values.get(key).cloned())
    }

    /// The vault directory the environment names (`ONEIRON_VAULT_PATH`),
    /// which stands over a config file's.
    pub(crate) fn vault_path(&self) -> Option<&Path> {
        self.values.vault_path.as_deref()
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> anyhow::Result<Self> {
        let mut values = PartialServeConfig::default();
        let config_path = lookup("ONEIRON_CONFIG").map(PathBuf::from);

        values.vault_path = lookup_path(&mut lookup, "ONEIRON_VAULT_PATH");
        values.host = lookup("ONEIRON_HOST");
        values.port = lookup_parse(&mut lookup, "ONEIRON_PORT")?;
        values.artifact_port = lookup_parse(&mut lookup, "ONEIRON_ARTIFACT_PORT")?;
        values.auth_secret = lookup("ONEIRON_AUTH_SECRET");
        values.oauth_issuer = lookup("ONEIRON_OAUTH_ISSUER");
        values.oauth_jwks_uri = lookup("ONEIRON_OAUTH_JWKS_URI");
        values.oauth_resource_indicator = lookup("ONEIRON_OAUTH_RESOURCE_INDICATOR");
        values.kit_bundle_public_urls = lookup_list(&mut lookup, "ONEIRON_KIT_BUNDLE_PUBLIC_URLS");
        values.allow_unauthenticated =
            lookup_bool(&mut lookup, "ONEIRON_INSECURE_ALLOW_UNAUTHENTICATED")?;
        values.allowed_origins = lookup_list(&mut lookup, "ONEIRON_ALLOWED_ORIGINS");
        values.artifact_domains = lookup_list(&mut lookup, "ONEIRON_ARTIFACT_DOMAINS");
        values.artifact_vault_name = lookup("ONEIRON_ARTIFACT_VAULT_NAME");
        values.trusted_proxies = lookup_list(&mut lookup, "ONEIRON_TRUSTED_PROXIES");
        values.lease_vault_id = lookup_parse(&mut lookup, "ONEIRON_LEASE_VAULT_ID")?;
        values.dimensions = lookup_parse(&mut lookup, "ONEIRON_DIMENSIONS")?;
        values.fast_dims = lookup_parse(&mut lookup, "ONEIRON_FAST_DIMS")?;
        values.map_size = lookup_parse(&mut lookup, "ONEIRON_MAP_SIZE")?;
        values.log_level = lookup("ONEIRON_LOG_LEVEL");
        values.dict_search_paths = lookup_path_list(&mut lookup, "ONEIRON_DICT_SEARCH_PATHS");
        values.assistant_display_names =
            lookup_list(&mut lookup, "ONEIRON_ASSISTANT_DISPLAY_NAMES");
        values.default_window_count = lookup_parse(&mut lookup, "ONEIRON_DEFAULT_WINDOW_COUNT")?;
        values.compaction_threshold_bytes =
            lookup_parse(&mut lookup, "ONEIRON_COMPACTION_THRESHOLD_BYTES")?;
        values.compaction_throttle_secs =
            lookup_parse(&mut lookup, "ONEIRON_COMPACTION_THROTTLE_SECS")?;
        values.bulk_chunk_size = lookup_parse(&mut lookup, "ONEIRON_BULK_CHUNK_SIZE")?;
        values.max_frame_size = lookup_parse(&mut lookup, "ONEIRON_MAX_FRAME_SIZE")?;
        values.max_update_payload = lookup_parse(&mut lookup, "ONEIRON_MAX_UPDATE_PAYLOAD")?;
        values.max_windows_per_connection =
            lookup_parse(&mut lookup, "ONEIRON_MAX_WINDOWS_PER_CONNECTION")?;
        values.max_messages_per_sec = lookup_parse(&mut lookup, "ONEIRON_MAX_MESSAGES_PER_SEC")?;
        values.ephemeral_timeout_ms = lookup_parse(&mut lookup, "ONEIRON_EPHEMERAL_TIMEOUT_MS")?;
        values.max_ephemeral_payload_bytes =
            lookup_parse(&mut lookup, "ONEIRON_MAX_EPHEMERAL_PAYLOAD_BYTES")?;
        values.max_ephemeral_snapshot_bytes =
            lookup_parse(&mut lookup, "ONEIRON_MAX_EPHEMERAL_SNAPSHOT_BYTES")?;
        values.max_entity_blob = lookup_parse(&mut lookup, "ONEIRON_MAX_ENTITY_BLOB")?;
        values.max_lfs_object_bytes = lookup_parse(&mut lookup, "ONEIRON_MAX_LFS_OBJECT_BYTES")?;
        values.max_bulk_decompressed = lookup_parse(&mut lookup, "ONEIRON_MAX_BULK_DECOMPRESSED")?;
        values.runtime = lookup_runtime_override(&mut lookup)?;
        values.embedder = lookup_embedder_override(&mut lookup)?;
        values.oneironer = lookup_oneironer_override(&mut lookup)?;
        values.backup = lookup_backup_override(&mut lookup)?;
        values.feedback = lookup_feedback_override(&mut lookup)?;
        values.failure_signals = lookup_failure_signals_override(&mut lookup)?;
        values.recall = lookup_recall_override(&mut lookup)?;
        values.skills = lookup_skills_override(&mut lookup)?;
        values.keystore = lookup_keystore_override(&mut lookup)?;
        values.privacy_posture = lookup_parse(&mut lookup, "ONEIRON_PRIVACY_POSTURE")?;
        values.failure_signal_export = lookup_bool(&mut lookup, "ONEIRON_FAILURE_SIGNAL_EXPORT")?;
        values.failure_signal_training =
            lookup_bool(&mut lookup, "ONEIRON_FAILURE_SIGNAL_TRAINING")?;
        values.hosted_kms_key_ref = lookup("ONEIRON_HOSTED_KMS_KEY_REF");

        Ok(Self {
            config_path,
            values,
        })
    }
}

pub fn default_config_path() -> Option<PathBuf> {
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(
            PathBuf::from(base)
                .join(DEFAULT_CONFIG_DIR)
                .join(DEFAULT_CONFIG_FILE),
        );
    }

    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join(DEFAULT_CONFIG_DIR)
            .join(DEFAULT_CONFIG_FILE)
    })
}

impl PartialServeConfig {
    pub(super) fn apply_to(
        self,
        resolved: &mut ServeConfig,
        source: ConfigLayer,
    ) -> anyhow::Result<()> {
        if let Some(value) = self.vault_path {
            resolved.vault_path = expand_home(value);
        }
        if let Some(value) = self.host {
            resolved.host = value;
        }
        if let Some(value) = self.port {
            resolved.port = value;
        }
        if let Some(value) = self.artifact_port {
            resolved.artifact_port = value;
        }
        if let Some(value) = self.auth_secret {
            resolved.auth_secret = Some(value);
        }
        if let Some(value) = self.oauth_issuer {
            resolved.oauth_issuer = Some(value);
        }
        if let Some(value) = self.oauth_jwks_uri {
            resolved.oauth_jwks_uri = Some(value);
        }
        if let Some(value) = self.oauth_resource_indicator {
            resolved.oauth_resource_indicator = Some(value);
        }
        if let Some(value) = self.kit_bundle_public_urls {
            resolved.kit_bundle_public_urls = normalize_list(value);
        }
        if let Some(value) = self.allow_unauthenticated {
            resolved.allow_unauthenticated = value;
        }
        if let Some(value) = self.allowed_origins {
            resolved.allowed_origins = normalize_list(value);
        }
        if let Some(value) = self.artifact_domains {
            resolved.artifact_domains = normalize_list(value);
        }
        if let Some(value) = self.artifact_vault_name {
            let value = value.trim().to_ascii_lowercase();
            if !oneiron_vault_contract::valid_vault_name(&value) {
                anyhow::bail!("artifact_vault_name must be a DNS label of [a-z0-9-]");
            }
            resolved.artifact_vault_name = Some(value);
        }
        if let Some(value) = self.trusted_proxies {
            resolved.trusted_proxies = parse_trusted_proxies(&normalize_list(value))?;
        }
        if let Some(value) = self.lease_vault_id {
            resolved.lease_vault_id = value;
        }
        if let Some(value) = self.dimensions {
            resolved.dimensions = value;
        }
        if let Some(value) = self.fast_dims {
            resolved.fast_dims = Some(value);
        }
        if let Some(value) = self.map_size {
            resolved.map_size = value;
        }
        if let Some(value) = self.log_level {
            resolved.log_level = value;
        }
        if let Some(value) = self.dict_search_paths {
            resolved.dict_search_paths = value.into_iter().map(expand_home).collect();
        }
        if let Some(value) = self.assistant_display_names {
            resolved.assistant_display_names = value;
        }
        if let Some(value) = self.default_window_count {
            resolved.default_window_count = value;
        }
        if let Some(value) = self.compaction_threshold_bytes {
            resolved.compaction_threshold_bytes = value;
        }
        if let Some(value) = self.compaction_throttle_secs {
            resolved.compaction_throttle_secs = value;
        }
        if let Some(value) = self.bulk_chunk_size {
            resolved.bulk_chunk_size = value;
        }
        if let Some(value) = self.max_frame_size {
            resolved.max_frame_size = value;
        }
        if let Some(value) = self.max_update_payload {
            resolved.max_update_payload = value;
        }
        if let Some(value) = self.max_windows_per_connection {
            resolved.max_windows_per_connection = value;
        }
        if let Some(value) = self.max_messages_per_sec {
            resolved.max_messages_per_sec = value;
        }
        if let Some(value) = self.ephemeral_timeout_ms {
            resolved.ephemeral_timeout_ms = value;
        }
        if let Some(value) = self.max_ephemeral_payload_bytes {
            resolved.max_ephemeral_payload_bytes = value;
        }
        if let Some(value) = self.max_ephemeral_snapshot_bytes {
            resolved.max_ephemeral_snapshot_bytes = value;
        }
        if let Some(value) = self.max_entity_blob {
            resolved.max_entity_blob = value;
        }
        if let Some(value) = self.max_lfs_object_bytes {
            resolved.max_lfs_object_bytes = value;
        }
        if let Some(value) = self.max_bulk_decompressed {
            resolved.max_bulk_decompressed = value;
        }
        if let Some(value) = self.runtime {
            resolved.runtime.apply_override(value);
        }
        // Naming any embedder key in any layer is what makes the section
        // present. Absent everywhere, `resolved.embedder` stays `None` and the
        // server runs exactly as it did before this key existed.
        if let Some(value) = self.embedder {
            resolved
                .embedder
                .get_or_insert_with(EmbedderConfig::default)
                .apply_override(value, source)?;
        }
        if let Some(value) = self.oneironer {
            resolved
                .oneironer
                .get_or_insert_with(OneironerConfig::default)
                .apply_override(value);
        }
        if let Some(value) = self.backup {
            resolved.backup.apply_override(value);
        }
        if let Some(value) = self.feedback {
            resolved.feedback.apply_override(value);
        }
        if let Some(value) = self.failure_signals {
            resolved.failure_signals.apply_override(value);
        }
        if let Some(value) = self.self_heal {
            resolved.self_heal.apply_override(value);
        }
        if let Some(value) = self.keystore {
            resolved.keystore.apply_override(value);
        }
        if let Some(value) = self.recall {
            resolved.recall.apply_override(value);
        }
        if let Some(value) = self.policy {
            resolved.policy.apply_override(value);
        }
        if let Some(value) = self.skills {
            resolved.skills.apply_override(value);
        }
        if let Some(value) = self.limits {
            resolved.limits.apply_override(value);
        }
        if let Some(value) = self.import {
            resolved.import.apply_override(value);
        }
        if let Some(value) = self.models {
            resolved.models = Some(value);
        }
        if let Some(value) = self.browser {
            resolved.browser = Some(value);
        }
        if let Some(value) = self.embedding {
            resolved.embedding = Some(value);
        }
        if let Some(value) = self.desktop {
            resolved.desktop = Some(value);
        }
        if let Some(value) = self.merge_queue {
            resolved.merge_queue = Some(value);
        }
        if let Some(value) = self.line {
            resolved.line = value;
        }
        if let Some(value) = self.linear {
            resolved.linear = Some(value);
        }
        if let Some(value) = self.gpu {
            resolved.gpu = Some(value);
        }
        if let Some(value) = self.native_mail {
            resolved.native_mail = Some(value);
        }
        if let Some(value) = self.device_sync {
            resolved.device_sync = Some(value);
        }
        if let Some(value) = self.connectors {
            resolved.connectors = value;
        }
        // An explicit no stands as firmly as a yes.
        if let Some(value) = self.failure_signal_export {
            resolved.failure_signal_export = Some(value);
        }
        if let Some(value) = self.failure_signal_training {
            resolved.failure_signal_training = Some(value);
        }
        if let Some(value) = self.privacy_posture {
            resolved.privacy_posture = value;
        }
        if let Some(value) = self.hosted_kms_key_ref {
            resolved.hosted_kms_key_ref = Some(value);
        }
        if let Some(value) = self.maximum_tier {
            resolved.maximum_tier = value;
        }
        if let Some(value) = self.device_class {
            resolved.device_class = value;
        }
        if let Some(value) = self.esign_delivery_outbox_dir {
            resolved.esign_delivery_outbox_dir = Some(value);
        }
        if let Some(value) = self.cloud_registration_pins {
            resolved.cloud_registration_pins = Some(value);
        }
        if let Some(value) = self.publisher_training_outbox_dir {
            resolved.publisher_training_outbox_dir = Some(value);
        }
        if let Some(value) = self.publisher_training_self_host_shipper {
            resolved.publisher_training_self_host_shipper = value;
        }
        if let Some(value) = self.publisher_training_intake_origin {
            resolved.publisher_training_intake_origin = value;
        }
        Ok(())
    }
}

fn lookup_runtime_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<RuntimeConfigOverride>> {
    let mut runtime = RuntimeConfigOverride::default();
    let mut has_runtime = false;

    if let Some(mode) = lookup_parse(lookup, "ONEIRON_RUNTIME_MODE")? {
        runtime.merge(RuntimeConfigOverride::mode(mode));
        has_runtime = true;
    }
    if let Some(byo_key_env) = lookup("ONEIRON_RUNTIME_BYO_KEY_ENV") {
        runtime.merge(RuntimeConfigOverride::with_byo_key_env(Some(byo_key_env)));
        has_runtime = true;
    }

    for role in RuntimeRole::ALL {
        let prefix = role_env_prefix(role);
        let mode_key = format!("{prefix}_MODE");
        let provider_key = format!("{prefix}_PROVIDER_KIND");
        let model_key = format!("{prefix}_MODEL");
        let mode = lookup(&mode_key)
            .map(|value| {
                value
                    .parse::<RuntimeMode>()
                    .map_err(|e| anyhow::anyhow!("parse {mode_key}={value:?}: {e}"))
            })
            .transpose()?;
        let provider_kind = lookup(&provider_key)
            .map(|value| {
                value
                    .parse::<RuntimeProviderKind>()
                    .map_err(|e| anyhow::anyhow!("parse {provider_key}={value:?}: {e}"))
            })
            .transpose()?;
        let model = lookup(&model_key);

        if mode.is_some() || provider_kind.is_some() || model.is_some() {
            runtime.merge(RuntimeConfigOverride::with_role_override(
                role,
                RuntimeRoleTargetOverride {
                    mode,
                    provider_kind,
                    model,
                },
            ));
            has_runtime = true;
        }
    }

    Ok(has_runtime.then_some(runtime))
}

fn role_env_prefix(role: RuntimeRole) -> &'static str {
    match role {
        RuntimeRole::Orchestrator => "ONEIRON_RUNTIME_ORCHESTRATOR",
        RuntimeRole::Subagent => "ONEIRON_RUNTIME_SUBAGENT",
        RuntimeRole::Summarizer => "ONEIRON_RUNTIME_SUMMARIZER",
    }
}
