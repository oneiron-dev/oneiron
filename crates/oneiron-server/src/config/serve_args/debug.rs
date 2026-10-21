//! `ServeArgs`'s redacting `Debug`.

use std::fmt;

use super::ServeArgs;
use crate::config::lookup::redacted_secret;

impl fmt::Debug for ServeArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeArgs")
            .field("config", &self.config)
            .field("vault_path", &self.vault_path)
            .field("managed_by_hypnos", &self.managed_by_hypnos)
            .field("contract_version", &self.contract_version)
            .field("vault_name", &self.vault_name)
            .field("organization_owner", &self.organization_owner)
            .field("member_vault", &self.member_vault)
            .field("data_dir", &self.data_dir)
            .field("http_socket", &self.http_socket)
            .field("ctl_socket", &self.ctl_socket)
            .field("hypnos_socket", &self.hypnos_socket)
            .field("ready_fd", &self.ready_fd)
            .field("credentials_fd", &self.credentials_fd)
            .field(
                "custody_anchor_credentials_fd",
                &self.custody_anchor_credentials_fd,
            )
            .field("restore", &self.restore)
            .field("restore_input_fd", &self.restore_input_fd)
            .field("restore_result_fd", &self.restore_result_fd)
            .field("vsock_guest", &self.vsock_guest)
            .field("vm_restore_revision", &self.vm_restore_revision)
            .field("keystore_dir", &self.keystore_dir)
            .field("escrow_recipient_file", &self.escrow_recipient_file)
            .field(
                "break_glass_recipient_file",
                &self.break_glass_recipient_file,
            )
            .field("escrow_outbox_dir", &self.escrow_outbox_dir)
            .field("maximum_tier", &self.maximum_tier)
            .field("artifact_http_socket", &self.artifact_http_socket)
            .field("settings_file", &self.settings_file)
            .field("voice_socket", &self.voice_socket)
            .field("seal_key_file", &self.seal_key_file)
            .field("seal_chain_file", &self.seal_chain_file)
            .field("seal_trust_file", &self.seal_trust_file)
            .field("seal_tsa_url", &self.seal_tsa_url)
            .field("seal_signing_url", &self.seal_signing_url)
            .field("seal_organ", &self.seal_organ)
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
            .field("browser_runtime", &self.browser_runtime)
            .field("desktop_runtime", &self.desktop_runtime)
            .field("organ_dir", &self.organ_dir)
            .field("mesh_bind", &self.mesh_bind)
            .field("mesh_relays", &self.mesh_relays)
            .field("shared_model_root", &self.shared_model_root)
            .field("container_home", &self.container_home)
            .field("container_runtime_dir", &self.container_runtime_dir)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("artifact_port", &self.artifact_port)
            .field("artifact_domains", &self.artifact_domains)
            .field("artifact_vault_name", &self.artifact_vault_name)
            .field("kit_bundle_public_urls", &self.kit_bundle_public_urls)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field(
                "insecure_allow_unauthenticated",
                &self.insecure_allow_unauthenticated,
            )
            .field("allowed_origins", &self.allowed_origins)
            .field("trusted_proxies", &self.trusted_proxies)
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
            .field("runtime_mode", &self.runtime_mode)
            .field("runtime_byo_key_env", &self.runtime_byo_key_env)
            .field("runtime_orchestrator_mode", &self.runtime_orchestrator_mode)
            .field(
                "runtime_orchestrator_provider_kind",
                &self.runtime_orchestrator_provider_kind,
            )
            .field(
                "runtime_orchestrator_model",
                &self.runtime_orchestrator_model,
            )
            .field("runtime_subagent_mode", &self.runtime_subagent_mode)
            .field(
                "runtime_subagent_provider_kind",
                &self.runtime_subagent_provider_kind,
            )
            .field("runtime_subagent_model", &self.runtime_subagent_model)
            .field("runtime_summarizer_mode", &self.runtime_summarizer_mode)
            .field(
                "runtime_summarizer_provider_kind",
                &self.runtime_summarizer_provider_kind,
            )
            .field("runtime_summarizer_model", &self.runtime_summarizer_model)
            .field("embedder", &self.embedder)
            .field("oneironer", &self.oneironer)
            .field("privacy_posture", &self.privacy_posture)
            .field(
                "hosted_kms_key_ref",
                &redacted_secret(&self.hosted_kms_key_ref),
            )
            .field("no_hooks", &self.no_hooks)
            .finish()
    }
}
