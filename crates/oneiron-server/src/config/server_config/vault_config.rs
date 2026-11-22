//! The vault config a [`ServeConfig`] names: with this device's page seal,
//! with none, and the privacy posture and data key custody it carries.

use oneiron::{VaultDataKeyCustody, VaultPrivacyConfig};

use super::super::oneironer::OneironerConfig;
use super::ServeConfig;

impl ServeConfig {
    /// [`Self::base_vault_config`], a sealed vault's page seal unlocked with
    /// this device's keystore.
    pub fn vault_config(&self) -> oneiron::VaultConfig {
        let mut config = self.base_vault_config();
        config.page_seal = self.device_page_seal();
        config
    }

    /// The vault config these settings name, with no page seal: this
    /// device's keystore is not tried, so nothing is probed or logged for a
    /// sealed vault. A caller that unlocks the vault its own way (a managed
    /// node's delivered key, the seal a restore chose) sets that seal alone
    /// (FIX 2544, 2709).
    pub fn base_vault_config(&self) -> oneiron::VaultConfig {
        let mut config = oneiron::VaultConfig::server();
        // `[runtime] clock`: the clock the vault reads. A manual clock stays
        // manual even if its file has gone since validation; it never falls
        // back to the host's clock.
        if let Some(clock) = self.runtime.store_clock() {
            config.store_clock = clock;
        }
        config.dimensions = self.dimensions;
        config.fast_dims = self.fast_dims;
        config.map_size = self.map_size;
        config.dict_search_paths = self.dict_search_paths.clone();
        config.assistant_display_names = self.assistant_display_names.clone();
        config.privacy = self.vault_privacy_config();
        config.allow_host_checkpoint_opt_out = self.allow_host_checkpoint_opt_out;
        // `[import] storage_cap_bytes`: an archive an import unpacks stops at
        // the room it leaves, in every door that unpacks one (ARCH-0027
        // #archive-precheck).
        config.storage_cap_bytes = self.import.storage_cap_bytes;
        config.machine_device_class = self.device_class;
        config.machine_reported_name = self.machine_reported_name.clone();
        config.machine_reported_model = self.machine_reported_model.clone();
        config.limits = self.limits.engine.clone();
        config.call_mode_deadline = std::time::Duration::from_millis(self.recall.call_deadline_ms);
        // Retrieval-run capture stays off unless this server's owner turns it
        // on (`[recall] retrieval_telemetry_capture`, FIX 21998).
        config.retrieval_telemetry_capture = self.recall.retrieval_telemetry_capture;
        // A plain serve is self-run whatever posture it declares, so "Help
        // improve Oneiron" and training on what it sends stay off until its
        // owner turns them on; only the managed serve entry sets the managed
        // deployment (CALLS 1459).
        config.failure_signals = oneiron::config::failure_signals::FailureSignalConfig {
            deployment: oneiron::config::failure_signals::DeploymentTier::SelfHost,
            export_opt_in: self.failure_signal_export,
            training_opt_in: self.failure_signal_training,
        };
        // An active embedder pins the vault's embedding space. The engine then
        // refuses any embedder whose `model_id` disagrees with what the vault
        // already holds, which is the door that keeps one vault to one space.
        // The prefix stays unset unless the host explicitly selects a measured MRL width.
        let embedder = self
            .embedder
            .as_ref()
            .filter(|embedder| embedder.is_active());
        config.embedding_model = embedder.map(|embedder| embedder.model_id.clone());
        // Beside it, how the embedder turns that model's output into stored
        // vectors, when the section says so before the provider loads.
        config.embedding_transform = embedder.and_then(crate::embedder::declared_transform);
        // And where a vector hit counts as evidence in that space.
        config.vector_evidence = embedder
            .map(crate::embedder::evidence_floors)
            .unwrap_or_default();
        // An active tagger arms the outbox marker: every witnessed turn owes
        // it a pass, committed with the turn (ARCH-0036, serving the tagger).
        config.tagging = self
            .oneironer
            .as_ref()
            .and_then(OneironerConfig::marker_config);
        config
    }

    /// Maps posture and custody without repairing invalid direct caller input.
    ///
    /// The resolver clears only lower-precedence references when a relay
    /// wins; a self-hosted vault keeps one as its own KMS key's custody. A
    /// reference still present here must survive conversion so
    /// `VaultPrivacyConfig::validate` refuses contradictory custody before any
    /// store opens. No reference is an owner-held key on any posture.
    fn vault_privacy_config(&self) -> VaultPrivacyConfig {
        let data_key_custody = match &self.hosted_kms_key_ref {
            Some(key_ref) => VaultDataKeyCustody::HostManagedKms {
                key_ref: key_ref.clone(),
            },
            None => VaultDataKeyCustody::OwnerHeldLocal,
        };
        VaultPrivacyConfig {
            posture: self.privacy_posture,
            data_key_custody,
        }
    }
}
