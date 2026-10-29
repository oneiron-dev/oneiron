//! The redacting `Debug` of [`SyncServerConfig`] and [`ServeConfig`]: a
//! secret prints as redacted, never its value.

use std::fmt;

use super::super::lookup::redacted_secret;
use super::{ServeConfig, SyncServerConfig};

impl fmt::Debug for SyncServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncServerConfig")
            .field("default_window_count", &self.default_window_count)
            .field(
                "compaction_threshold_bytes",
                &self.compaction_threshold_bytes,
            )
            .field("compaction_throttle_secs", &self.compaction_throttle_secs)
            .field("bulk_chunk_size", &self.bulk_chunk_size)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field("cloud_registration_pins", &self.cloud_registration_pins)
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .field("allowed_origins", &self.allowed_origins)
            .field("artifact_domains", &self.artifact_domains)
            .field("artifact_vault_name", &self.artifact_vault_name)
            .field(
                "artifact_internal_vault_id",
                &self.artifact_internal_vault_id,
            )
            .field("trusted_proxies", &self.trusted_proxies)
            .field("lease_vault_id", &self.lease_vault_id)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_update_payload", &self.max_update_payload)
            .field(
                "max_windows_per_connection",
                &self.max_windows_per_connection,
            )
            .field("max_messages_per_sec", &self.max_messages_per_sec)
            .field("ephemeral_timeout_ms", &self.ephemeral_timeout_ms)
            .field(
                "max_ephemeral_payload_bytes",
                &self.max_ephemeral_payload_bytes,
            )
            .field(
                "max_ephemeral_snapshot_bytes",
                &self.max_ephemeral_snapshot_bytes,
            )
            .field("max_entity_blob", &self.max_entity_blob)
            .field("max_lfs_object_bytes", &self.max_lfs_object_bytes)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .field("limits", &self.limits)
            .field("feedback_inbox", &self.feedback_inbox)
            .field("runtime", &self.runtime)
            .field("skills", &self.skills)
            .field("line", &self.line)
            .field("linear", &self.linear)
            .field("ingress", &self.ingress)
            .field("merge_queue", &self.merge_queue)
            .field("trusted_organ_builds", &self.trusted_organ_builds)
            .field("hosted_private_origins", &self.hosted_private_origins)
            .finish()
    }
}

impl fmt::Debug for ServeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeConfig")
            .field("vault_path", &self.vault_path)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("artifact_port", &self.artifact_port)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field("cloud_registration_pins", &self.cloud_registration_pins)
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .field("allowed_origins", &self.allowed_origins)
            .field("artifact_domains", &self.artifact_domains)
            .field("artifact_vault_name", &self.artifact_vault_name)
            .field(
                "artifact_internal_vault_id",
                &self.artifact_internal_vault_id,
            )
            .field("trusted_proxies", &self.trusted_proxies)
            .field("lease_vault_id", &self.lease_vault_id)
            .field("dimensions", &self.dimensions)
            .field("fast_dims", &self.fast_dims)
            .field("map_size", &self.map_size)
            .field("log_level", &self.log_level)
            .field("dict_search_paths", &self.dict_search_paths)
            .field("assistant_display_names", &self.assistant_display_names)
            .field("default_window_count", &self.default_window_count)
            .field(
                "compaction_threshold_bytes",
                &self.compaction_threshold_bytes,
            )
            .field("compaction_throttle_secs", &self.compaction_throttle_secs)
            .field("bulk_chunk_size", &self.bulk_chunk_size)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_update_payload", &self.max_update_payload)
            .field(
                "max_windows_per_connection",
                &self.max_windows_per_connection,
            )
            .field("max_messages_per_sec", &self.max_messages_per_sec)
            .field("ephemeral_timeout_ms", &self.ephemeral_timeout_ms)
            .field(
                "max_ephemeral_payload_bytes",
                &self.max_ephemeral_payload_bytes,
            )
            .field(
                "max_ephemeral_snapshot_bytes",
                &self.max_ephemeral_snapshot_bytes,
            )
            .field("max_entity_blob", &self.max_entity_blob)
            .field("max_lfs_object_bytes", &self.max_lfs_object_bytes)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .field("runtime", &self.runtime)
            .field("embedder", &self.embedder)
            .field("oneironer", &self.oneironer)
            .field("backup", &self.backup)
            .field("feedback", &self.feedback)
            .field("failure_signals", &self.failure_signals)
            .field("self_heal", &self.self_heal)
            .field("recall", &self.recall)
            .field("policy", &self.policy)
            .field("skills", &self.skills)
            .field("keystore", &self.keystore)
            .field("limits", &self.limits)
            .field("import", &self.import)
            .field("models", &self.models)
            .field("browser", &self.browser)
            .field("desktop", &self.desktop)
            .field("merge_queue", &self.merge_queue)
            .field("gpu", &self.gpu)
            .field("native_mail", &self.native_mail)
            .field("device_sync", &self.device_sync)
            .field("connectors", &self.connectors)
            .field("embedding", &self.embedding)
            .field("line", &self.line)
            .field("linear", &self.linear)
            .field("privacy_posture", &self.privacy_posture)
            .field(
                "hosted_kms_key_ref",
                &redacted_secret(&self.hosted_kms_key_ref),
            )
            .field("hooks", &self.hooks)
            .field("maximum_tier", &self.maximum_tier)
            .field("device_class", &self.device_class)
            .field("esign_delivery_outbox_dir", &self.esign_delivery_outbox_dir)
            .field(
                "publisher_training_outbox_dir",
                &self.publisher_training_outbox_dir,
            )
            .field(
                "publisher_training_self_host_shipper",
                &self.publisher_training_self_host_shipper,
            )
            .field(
                "publisher_training_intake_origin",
                &self.publisher_training_intake_origin,
            )
            .field("shared_model_root", &self.shared_model_root)
            .field("trusted_organ_builds", &self.trusted_organ_builds)
            .finish()
    }
}
