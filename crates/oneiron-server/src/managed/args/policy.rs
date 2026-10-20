//! The managed argv allowlist: what managed mode does with each `ServeArgs`
//! field, and the refusal of every unmanaged layer it never reads.

use crate::config::ServeArgs;
use crate::config::embedder::EmbedderConfigOverride;

use super::ManagedError;

const NO_HOST_PORT_REASON: &str =
    "managed mode serves the supervisor's socket, never a host:port bind";

const NO_CONFIG_LAYER_REASON: &str = "managed mode reads its configuration from argv and the one settings file --settings-file names; other config files, ONEIRON_* environment and XDG layers are never consulted";

const NO_AUTH_LAYER_REASON: &str = "bearer auth terminates at the supervisor, which owns the listening socket inside an owner-only directory; a managed child holds no second opinion about who may talk to it";

const NO_EMBEDDER_FLAGS_REASON: &str =
    "managed mode reads its embedder from the settings file's [embedder] (--settings-file)";

const NO_TUNING_LAYER_REASON: &str = "managed mode reads the owner's settings from the one file --settings-file names; this flag would be a second layer nothing reads";

const NO_TENANT_LAYER_REASON: &str = "the supervisor binds the vault's tenant identity, privacy posture and key custody; contract v1 has no managed override for them";

/// What managed mode does with one `ServeArgs` field.
#[derive(Debug, Clone, Copy)]
enum ArgvUse {
    /// Read: either part of the managed group itself or one of the fields
    /// [`ManagedArgs::serve_config`](super::ManagedArgs::serve_config) consults.
    Read,
    /// Belongs to a layer managed mode never consults, and is refused with
    /// this reason rather than accepted and dropped.
    Refused(&'static str),
}

/// One [`MANAGED_ARGV`] row: the flag as the operator types it, the probe that
/// says whether they typed it, and what managed mode does with it.
type ArgvRule = (&'static str, fn(&ServeArgs) -> bool, ArgvUse);

/// The whole `ServeArgs` surface in one table: the flag as the operator types
/// it, the probe that says whether they typed it, and what managed mode does
/// with it.
///
/// One allowlist drives both halves of the rule. The [`ArgvUse::Read`] rows
/// are exactly what the managed group and
/// [`ManagedArgs::serve_config`](super::ManagedArgs::serve_config) read;
/// [`reject_unmanaged_layers`] refuses every other row that was set. Before
/// this table the two halves were written separately, and the gap between them
/// was silent: clap accepted `--auth-secret` and `serve_config` dropped it, so
/// an operator who typed it got neither the setting nor an error.
const MANAGED_ARGV: &[ArgvRule] = &[
    // The managed group: argv is the whole configuration.
    (
        "config",
        |args| args.config.is_some(),
        ArgvUse::Refused(NO_CONFIG_LAYER_REASON),
    ),
    (
        "vault-path",
        |args| args.vault_path.is_some(),
        ArgvUse::Read,
    ),
    (
        "managed-by-hypnos",
        |args| args.managed_by_hypnos,
        ArgvUse::Read,
    ),
    (
        "contract-version",
        |args| args.contract_version.is_some(),
        ArgvUse::Read,
    ),
    (
        "vault-name",
        |args| args.vault_name.is_some(),
        ArgvUse::Read,
    ),
    (
        "derivation-owner",
        |args| args.derivation_owner.is_some(),
        ArgvUse::Read,
    ),
    (
        "organization-owner",
        |args| args.organization_owner.is_some(),
        ArgvUse::Read,
    ),
    ("member-vault", |args| args.member_vault, ArgvUse::Read),
    ("data-dir", |args| args.data_dir.is_some(), ArgvUse::Read),
    (
        "http-socket",
        |args| args.http_socket.is_some(),
        ArgvUse::Read,
    ),
    (
        "ctl-socket",
        |args| args.ctl_socket.is_some(),
        ArgvUse::Read,
    ),
    (
        "hypnos-socket",
        |args| args.hypnos_socket.is_some(),
        ArgvUse::Read,
    ),
    ("ready-fd", |args| args.ready_fd.is_some(), ArgvUse::Read),
    (
        "credentials-fd",
        |args| args.credentials_fd.is_some(),
        ArgvUse::Read,
    ),
    (
        "custody-anchor-credentials-fd",
        |args| args.custody_anchor_credentials_fd.is_some(),
        ArgvUse::Read,
    ),
    ("restore", |args| args.restore, ArgvUse::Read),
    (
        "restore-input-fd",
        |args| args.restore_input_fd.is_some(),
        ArgvUse::Read,
    ),
    (
        "restore-result-fd",
        |args| args.restore_result_fd.is_some(),
        ArgvUse::Read,
    ),
    ("vsock-guest", |args| args.vsock_guest, ArgvUse::Read),
    (
        "keystore-dir",
        |args| args.keystore_dir.is_some(),
        ArgvUse::Read,
    ),
    (
        "escrow-recipient-file",
        |args| args.escrow_recipient_file.is_some(),
        ArgvUse::Read,
    ),
    (
        "break-glass-recipient-file",
        |args| args.break_glass_recipient_file.is_some(),
        ArgvUse::Read,
    ),
    (
        "escrow-outbox-dir",
        |args| args.escrow_outbox_dir.is_some(),
        ArgvUse::Read,
    ),
    (
        "maximum-tier",
        |args| args.maximum_tier.is_some(),
        ArgvUse::Read,
    ),
    (
        "settings-file",
        |args| args.settings_file.is_some(),
        ArgvUse::Read,
    ),
    (
        "voice-socket",
        |args| args.voice_socket.is_some(),
        ArgvUse::Read,
    ),
    // The embedder's layered flags: managed mode reads its settings file.
    (
        "embedder-*",
        |args| !EmbedderConfigOverride::from(&args.embedder).is_empty(),
        ArgvUse::Refused(NO_EMBEDDER_FLAGS_REASON),
    ),
    (
        "seal-key-file",
        |args| args.seal_key_file.is_some(),
        ArgvUse::Read,
    ),
    (
        "seal-chain-file",
        |args| args.seal_chain_file.is_some(),
        ArgvUse::Read,
    ),
    (
        "seal-trust-file",
        |args| args.seal_trust_file.is_some(),
        ArgvUse::Read,
    ),
    (
        "seal-tsa-url",
        |args| args.seal_tsa_url.is_some(),
        ArgvUse::Read,
    ),
    (
        "seal-signing-url",
        |args| args.seal_signing_url.is_some(),
        ArgvUse::Read,
    ),
    (
        "seal-organ",
        |args| args.seal_organ.is_some(),
        ArgvUse::Read,
    ),
    (
        "esign-delivery-outbox-dir",
        |args| args.esign_delivery_outbox_dir.is_some(),
        ArgvUse::Read,
    ),
    (
        "publisher-training-outbox-dir",
        |args| args.publisher_training_outbox_dir.is_some(),
        ArgvUse::Read,
    ),
    // Read, and inactive here (TL-6): `serve_config` keeps the self-host
    // shipper off, as the supervisor pushes the intake's keys and ships.
    (
        "publisher-training-self-host-shipper",
        |args| args.publisher_training_self_host_shipper,
        ArgvUse::Read,
    ),
    (
        "publisher-training-intake-origin",
        |args| args.publisher_training_intake_origin.is_some(),
        ArgvUse::Read,
    ),
    // The supervisor's bindings for the guests' container CLIs, the pack
    // organ directory and the mesh listener (WILL-PLAN L14 rows 05, 14).
    (
        "browser-runtime",
        |args| args.browser_runtime.is_some(),
        ArgvUse::Read,
    ),
    (
        "desktop-runtime",
        |args| args.desktop_runtime.is_some(),
        ArgvUse::Read,
    ),
    ("organ-dir", |args| args.organ_dir.is_some(), ArgvUse::Read),
    ("mesh-bind", |args| args.mesh_bind.is_some(), ArgvUse::Read),
    (
        "mesh-relays",
        |args| args.mesh_relays.is_some(),
        ArgvUse::Read,
    ),
    // The bind: the supervisor's socket, never a host:port.
    (
        "host",
        |args| args.host.is_some(),
        ArgvUse::Refused(NO_HOST_PORT_REASON),
    ),
    (
        "port",
        |args| args.port.is_some(),
        ArgvUse::Refused(NO_HOST_PORT_REASON),
    ),
    (
        "artifact-port",
        |args| args.artifact_port.is_some(),
        ArgvUse::Refused(NO_HOST_PORT_REASON),
    ),
    (
        "artifact-domains",
        |args| args.artifact_domains.is_some(),
        ArgvUse::Read,
    ),
    (
        "artifact-http-socket",
        |args| args.artifact_http_socket.is_some(),
        ArgvUse::Read,
    ),
    (
        "artifact-public-slug",
        |args| args.artifact_public_slug.is_some(),
        ArgvUse::Read,
    ),
    (
        "artifact-vault-name",
        |args| args.artifact_vault_name.is_some(),
        ArgvUse::Refused(NO_HOST_PORT_REASON),
    ),
    // The auth layer: the supervisor's, not this child's.
    (
        "auth-secret",
        |args| args.auth_secret.is_some(),
        ArgvUse::Refused(NO_AUTH_LAYER_REASON),
    ),
    (
        "oauth-issuer",
        |args| args.oauth_issuer.is_some(),
        ArgvUse::Refused(NO_AUTH_LAYER_REASON),
    ),
    (
        "oauth-jwks-uri",
        |args| args.oauth_jwks_uri.is_some(),
        ArgvUse::Refused(NO_AUTH_LAYER_REASON),
    ),
    (
        "insecure-allow-unauthenticated",
        |args| args.insecure_allow_unauthenticated.is_some(),
        ArgvUse::Refused(NO_AUTH_LAYER_REASON),
    ),
    (
        "allowed-origins",
        |args| args.allowed_origins.is_some(),
        ArgvUse::Read,
    ),
    (
        "trusted-proxies",
        |args| args.trusted_proxies.is_some(),
        ArgvUse::Refused(NO_AUTH_LAYER_REASON),
    ),
    // The host's public addresses, which the supervisor owns and passes on:
    // its https origin and the URLs a kit dials. The settings file never
    // sets them, and no auth layer is built from them.
    (
        "oauth-resource-indicator",
        |args| args.oauth_resource_indicator.is_some(),
        ArgvUse::Read,
    ),
    (
        "kit-bundle-public-urls",
        |args| args.kit_bundle_public_urls.is_some(),
        ArgvUse::Read,
    ),
    // The owner's own choices, which the supervisor passes on (FIX 4488).
    (
        "failure-signal-export",
        |args| args.failure_signal_export.is_some(),
        ArgvUse::Read,
    ),
    (
        "failure-signal-training",
        |args| args.failure_signal_training.is_some(),
        ArgvUse::Read,
    ),
    // Contract v1 has no managed privacy override: refuse instead of dropping it.
    (
        "privacy-posture",
        |args| args.privacy_posture.is_some(),
        ArgvUse::Refused(NO_TENANT_LAYER_REASON),
    ),
    (
        "hosted-kms-key-ref",
        |args| args.hosted_kms_key_ref.is_some(),
        ArgvUse::Refused(NO_TENANT_LAYER_REASON),
    ),
    (
        "lease-vault-id",
        |args| args.lease_vault_id.is_some(),
        ArgvUse::Refused(NO_TENANT_LAYER_REASON),
    ),
    // The tuning layer: the settings file's, except the fields read below.
    (
        "dimensions",
        |args| args.dimensions.is_some(),
        ArgvUse::Read,
    ),
    ("fast-dims", |args| args.fast_dims.is_some(), ArgvUse::Read),
    ("map-size", |args| args.map_size.is_some(), ArgvUse::Read),
    ("log-level", |args| args.log_level.is_some(), ArgvUse::Read),
    ("no-hooks", |args| args.no_hooks, ArgvUse::Read),
    (
        "dict-search-paths",
        |args| args.dict_search_paths.is_some(),
        ArgvUse::Read,
    ),
    (
        "assistant-display-names",
        |args| args.assistant_display_names.is_some(),
        ArgvUse::Read,
    ),
    (
        "default-window-count",
        |args| args.default_window_count.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "compaction-threshold-bytes",
        |args| args.compaction_threshold_bytes.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "compaction-throttle-secs",
        |args| args.compaction_throttle_secs.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "bulk-chunk-size",
        |args| args.bulk_chunk_size.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-frame-size",
        |args| args.max_frame_size.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-update-payload",
        |args| args.max_update_payload.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-windows-per-connection",
        |args| args.max_windows_per_connection.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-messages-per-sec",
        |args| args.max_messages_per_sec.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "ephemeral-timeout-ms",
        |args| args.ephemeral_timeout_ms.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-ephemeral-payload-bytes",
        |args| args.max_ephemeral_payload_bytes.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-ephemeral-snapshot-bytes",
        |args| args.max_ephemeral_snapshot_bytes.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-entity-blob",
        |args| args.max_entity_blob.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-lfs-object-bytes",
        |args| args.max_lfs_object_bytes.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-bulk-decompressed",
        |args| args.max_bulk_decompressed.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    // The runtime routing layer: the settings file's `[runtime]`.
    (
        "runtime-mode",
        |args| args.runtime_mode.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-byo-key-env",
        |args| args.runtime_byo_key_env.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-orchestrator-mode",
        |args| args.runtime_orchestrator_mode.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-orchestrator-provider-kind",
        |args| args.runtime_orchestrator_provider_kind.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-orchestrator-model",
        |args| args.runtime_orchestrator_model.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-subagent-mode",
        |args| args.runtime_subagent_mode.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-subagent-provider-kind",
        |args| args.runtime_subagent_provider_kind.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-subagent-model",
        |args| args.runtime_subagent_model.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-summarizer-mode",
        |args| args.runtime_summarizer_mode.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-summarizer-provider-kind",
        |args| args.runtime_summarizer_provider_kind.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-summarizer-model",
        |args| args.runtime_summarizer_model.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    // The tagger slot's flags: the settings file's `[oneironer]`.
    (
        "oneironer-provider",
        |args| args.oneironer.oneironer_provider.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "oneironer-mode",
        |args| args.oneironer.oneironer_mode.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "oneironer-url",
        |args| args.oneironer.oneironer_url.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "oneironer-checkpoint-sha16",
        |args| args.oneironer.oneironer_checkpoint_sha16.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "oneironer-stack-sha16",
        |args| args.oneironer.oneironer_stack_sha16.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "oneironer-label-count",
        |args| args.oneironer.oneironer_label_count.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "oneironer-labels",
        |args| args.oneironer.oneironer_labels.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "oneironer-timeout-ms",
        |args| args.oneironer.oneironer_timeout_ms.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
];

/// Managed mode takes its whole configuration from argv, and reads only part
/// of it. A flag it does not read is not harmless: `--host` would move a bind
/// that the supervisor owns, `--config` would open a layer this mode never
/// consults, and `--auth-secret` would look like a second answer to "who may
/// talk to this vault" while changing nothing. So every field outside the
/// [`MANAGED_ARGV`] allowlist is a loud refusal that names the conflict rather
/// than a flag clap accepts and nothing honours.
pub(super) fn reject_unmanaged_layers(args: &ServeArgs) -> Result<(), ManagedError> {
    for &(flag, is_set, use_of) in MANAGED_ARGV {
        if let ArgvUse::Refused(reason) = use_of
            && is_set(args)
        {
            return Err(ManagedError::ConflictingFlag { flag, reason });
        }
    }
    // Check presence only: never parse these values or load the requested file.
    // Even an empty or non-Unicode setting is an explicit unmanaged request,
    // not permission to fall back to the managed default custody.
    for env in [
        "ONEIRON_PRIVACY_POSTURE",
        "ONEIRON_HOSTED_KMS_KEY_REF",
        "ONEIRON_CONFIG",
        "ONEIRON_FAILURE_SIGNAL_EXPORT",
        "ONEIRON_FAILURE_SIGNAL_TRAINING",
        "ONEIRON_TRUSTED_PROXIES",
    ] {
        if std::env::var_os(env).is_some() {
            return Err(ManagedError::ConflictingEnvironment {
                env,
                reason: NO_CONFIG_LAYER_REASON,
            });
        }
    }
    Ok(())
}
