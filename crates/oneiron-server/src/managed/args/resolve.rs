//! Resolution and validation of the managed argv group.
//! Builds managed settings from argv and retains descriptor-refusal order.
//! Argument types, refusal vocabulary, and shared helpers stay in the parent.

use super::{
    CONTRACT_VERSION, DerivationOwner, HYPNOS_LISTEN_FD, KeystoreBackend, KeystoreConfig,
    MANAGED_MAXIMUM_TIER_DEFAULT, ManagedArgs, ManagedError, ManagedStartMode, NO_FD, RawFd,
    ServeArgs, ServeConfig, VSOCK_BOOT_REASON, decode_hex, nonempty, refuse_fd_alias,
    reject_unmanaged_layers, require, require_fd, valid_vault_name, vm_transport,
};

impl ManagedArgs {
    /// Returns `None` when `--managed-by-hypnos` is absent — the whole
    /// off-by-default guarantee lives in this one early return.
    ///
    /// Validation order is deliberate: the contract version is checked first,
    /// so an engine spawned against a wire it does not speak exits non-zero
    /// before touching a descriptor, a socket or the data directory.
    pub fn from_serve_args(args: &ServeArgs) -> Result<Option<Self>, ManagedError> {
        if !args.managed_by_hypnos {
            if args.organization_owner.is_some() || args.member_vault {
                return Err(ManagedError::VaultRoutingRejected {
                    reason: "organization flags require managed mode".into(),
                });
            }
            if args.restore || args.restore_input_fd.is_some() || args.restore_result_fd.is_some() {
                return Err(ManagedError::RestoreFlagsRejected {
                    reason: "a cold restore start is managed mode's (--managed-by-hypnos)",
                });
            }
            return Ok(None);
        }

        let found = require(args.contract_version, "contract-version")?;
        if found != CONTRACT_VERSION {
            return Err(ManagedError::UnknownContractVersion {
                found,
                expected: CONTRACT_VERSION,
            });
        }
        reject_unmanaged_layers(args)?;

        let vault_name = require(args.vault_name.clone(), "vault-name")?;
        if !valid_vault_name(&vault_name) {
            return Err(ManagedError::InvalidVaultName { name: vault_name });
        }

        let owner_text = require(args.derivation_owner.as_deref(), "derivation-owner")?;
        if !owner_text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ManagedError::InvalidDerivationOwner);
        }
        let owner = decode_hex(owner_text).ok_or(ManagedError::InvalidDerivationOwner)?;
        let organization_owner = args
            .organization_owner
            .as_deref()
            .map(|text| {
                decode_hex(text)
                    .filter(|_| text.bytes().all(|byte| byte.is_ascii_hexdigit()))
                    .map(DerivationOwner)
                    .ok_or_else(|| ManagedError::VaultRoutingRejected {
                        reason: "--organization-owner must be a 32-byte id in hexadecimal".into(),
                    })
            })
            .transpose()?;

        let (ready_fd, credentials_fd) = if args.vsock_guest {
            for (flag, given) in [
                ("ready-fd", args.ready_fd.is_some()),
                ("credentials-fd", args.credentials_fd.is_some()),
            ] {
                if given {
                    return Err(ManagedError::ConflictingFlag {
                        flag,
                        reason: VSOCK_BOOT_REASON,
                    });
                }
            }
            (NO_FD, NO_FD)
        } else {
            (
                require_fd(args.ready_fd, "ready-fd")?,
                require_fd(args.credentials_fd, "credentials-fd")?,
            )
        };
        // A vault VM takes the credential's pipe only from its bootstrap.
        let vm_anchor = vm_transport::anchor_handoff(args)?;
        let custody_anchor_credentials_fd = args
            .custody_anchor_credentials_fd
            .map(|fd| require_fd(Some(fd), "custody-anchor-credentials-fd"))
            .transpose()?;
        let start_mode = ManagedStartMode::of(args)?;
        let managed = Self {
            vault_name,
            derivation_owner: DerivationOwner(owner),
            organization_owner,
            member_vault: args.member_vault,
            // `--vault-path` stays the alias for the same directory.
            data_dir: require(
                args.data_dir.clone().or_else(|| args.vault_path.clone()),
                "data-dir",
            )?,
            http_socket: require(args.http_socket.clone(), "http-socket")?,
            ctl_socket: require(args.ctl_socket.clone(), "ctl-socket")?,
            hypnos_socket: require(args.hypnos_socket.clone(), "hypnos-socket")?,
            ready_fd,
            credentials_fd,
            custody_anchor_credentials_fd,
            vm_anchor,
            start_mode,
            vsock_guest: args.vsock_guest,
            keystore_dir: args.keystore_dir.clone(),
            escrow_recipient: args.escrow_recipient_file.clone(),
            break_glass_recipient: args.break_glass_recipient_file.clone(),
            escrow_outbox: args.escrow_outbox_dir.clone(),
            maximum_tier: args.maximum_tier.unwrap_or(MANAGED_MAXIMUM_TIER_DEFAULT),
            artifact_socket: args.artifact_http_socket.clone(),
            settings_file: args.settings_file.clone(),
            voice_socket: args.voice_socket.clone(),
            seal_key: args.seal_key_file.clone(),
            seal_chain: args.seal_chain_file.clone(),
            seal_trust: args.seal_trust_file.clone(),
            seal_tsa: nonempty(args.seal_tsa_url.as_deref()),
            seal_signing_url: nonempty(args.seal_signing_url.as_deref()),
            seal_organ: args.seal_organ.clone(),
            esign_delivery_outbox: args.esign_delivery_outbox_dir.clone(),
            publisher_training_outbox: args.publisher_training_outbox_dir.clone(),
            browser_runtime: args.browser_runtime.clone(),
            desktop_runtime: args.desktop_runtime.clone(),
            organ_dir: args.organ_dir.clone(),
            mesh_bind: args.mesh_bind,
            mesh_relays: crate::config::normalize_list(
                args.mesh_relays.clone().unwrap_or_default(),
            ),
            // Not among the absolute paths refused below: a root that fails
            // its check is ignored, never a refused start.
            shared_model_root: args.shared_model_root.clone(),
            // Nor are the container CLI's directories (FIX 6876).
            container_home: args.container_home.clone(),
            container_runtime_dir: args.container_runtime_dir.clone(),
            guest_runtime_fact: args.guest_runtime_fact,
            hosted_private_origins: args.hosted_private_origins.iter().cloned().collect(),
        };
        if managed
            .artifact_socket
            .as_deref()
            .is_some_and(std::path::Path::is_relative)
        {
            return Err(ManagedError::RelativeArtifactSocket);
        }
        if managed
            .keystore_dir
            .as_deref()
            .is_some_and(std::path::Path::is_relative)
        {
            return Err(ManagedError::RelativeKeystoreDir);
        }
        for (flag, path) in [
            ("escrow-recipient-file", &managed.escrow_recipient),
            ("break-glass-recipient-file", &managed.break_glass_recipient),
            ("escrow-outbox-dir", &managed.escrow_outbox),
            ("settings-file", &managed.settings_file),
            ("voice-socket", &managed.voice_socket),
            ("seal-key-file", &managed.seal_key),
            ("seal-chain-file", &managed.seal_chain),
            ("seal-trust-file", &managed.seal_trust),
            ("seal-organ", &managed.seal_organ),
            ("esign-delivery-outbox-dir", &managed.esign_delivery_outbox),
            (
                "publisher-training-outbox-dir",
                &managed.publisher_training_outbox,
            ),
            ("browser-runtime", &managed.browser_runtime),
            ("desktop-runtime", &managed.desktop_runtime),
            ("organ-dir", &managed.organ_dir),
        ] {
            if path.as_deref().is_some_and(std::path::Path::is_relative) {
                return Err(ManagedError::RelativeRecipientFile { flag });
            }
        }
        // Non-negative is not enough. Both descriptors are adopted by owners
        // that close what they hold — `read_managed_credentials` and
        // `signal_ready` each take theirs over with `from_raw_fd` — so one
        // number on both flags is not a harmless duplicate: the credential
        // frame's descriptor is closed under the ready write, or the ready byte
        // lands in the number the supervisor is still reading credentials from.
        // Refused here, before either is consumed. The custody anchor
        // credentials pipe is adopted the same way, so it aliases neither.
        if !managed.vsock_guest {
            refuse_fd_alias(
                ("--ready-fd", managed.ready_fd),
                ("--credentials-fd", managed.credentials_fd),
            )?;
            if let Some(anchor) = managed.custody_anchor_credentials_fd {
                for other in [
                    ("--ready-fd", managed.ready_fd),
                    ("--credentials-fd", managed.credentials_fd),
                ] {
                    refuse_fd_alias(("--custody-anchor-credentials-fd", anchor), other)?;
                }
            }
            // A cold restore's two pipes are adopted the same way: each is
            // refused when it names any descriptor before it.
            if let ManagedStartMode::Restore {
                input_fd,
                result_fd,
            } = managed.start_mode
            {
                let mut taken = vec![
                    ("--ready-fd", managed.ready_fd),
                    ("--credentials-fd", managed.credentials_fd),
                ];
                taken.extend(
                    managed
                        .custody_anchor_credentials_fd
                        .map(|anchor| ("--custody-anchor-credentials-fd", anchor)),
                );
                for pipe in [
                    ("--restore-input-fd", input_fd),
                    ("--restore-result-fd", result_fd),
                ] {
                    for other in &taken {
                        refuse_fd_alias(pipe, *other)?;
                    }
                    taken.push(pipe);
                }
            }
        }
        managed.vault_binding()?;
        Ok(Some(managed))
    }

    /// Refuses an inherited listening descriptor that aliases any argv fd.
    ///
    /// Three inputs, three distinct owners: a `UnixListener` over the inherited
    /// socket, a `File` over the credential frame, a `File` over the ready
    /// pipe. Each closes what it holds on drop, so a listener that is also
    /// `--credentials-fd` is read as a credential frame and closed under the
    /// listener, and one that is also `--ready-fd` has the ready byte written
    /// into it. The custody anchor credentials pipe, when handed, is a fourth,
    /// and a cold restore's two pipes a fifth and a sixth.
    /// [`serve_managed`](crate::managed::serve_managed) calls this before any of them is
    /// consumed and before the vault is opened, so neither the frame nor
    /// storage is touched on the way to the refusal.
    pub fn refuse_listen_fd_alias(&self, listen_fd: RawFd) -> Result<(), ManagedError> {
        refuse_fd_alias((HYPNOS_LISTEN_FD, listen_fd), ("--ready-fd", self.ready_fd))?;
        if let Some(anchor) = self.custody_anchor_credentials_fd {
            refuse_fd_alias(
                (HYPNOS_LISTEN_FD, listen_fd),
                ("--custody-anchor-credentials-fd", anchor),
            )?;
        }
        if let ManagedStartMode::Restore {
            input_fd,
            result_fd,
        } = self.start_mode
        {
            refuse_fd_alias(
                (HYPNOS_LISTEN_FD, listen_fd),
                ("--restore-input-fd", input_fd),
            )?;
            refuse_fd_alias(
                (HYPNOS_LISTEN_FD, listen_fd),
                ("--restore-result-fd", result_fd),
            )?;
        }
        refuse_fd_alias(
            (HYPNOS_LISTEN_FD, listen_fd),
            ("--credentials-fd", self.credentials_fd),
        )
    }

    /// The vault's own e-sign seal settings, from its argv alone (FIX 3487).
    #[cfg(unix)]
    pub(crate) fn seal_config(&self) -> crate::api::EsignSealConfig {
        crate::api::EsignSealConfig {
            key: self.seal_key.clone(),
            chain: self.seal_chain.clone(),
            trust: self.seal_trust.clone(),
            tsa: self.seal_tsa.clone(),
            signing_url: self.seal_signing_url.clone(),
            organ: self.seal_organ.clone(),
            argv: true,
        }
    }

    /// Serve configuration for managed mode as argv builds it, the base the
    /// owner's settings file is settled over (`managed::settings`).
    ///
    /// Outside the managed group, the argv allowlist permits exactly the
    /// fields read here: dimensions, the MRL prefix, map size, dictionary
    /// roots, log level, `--no-hooks`, the maximum tier and the owner's
    /// failure-signal export and training choices. Each of them, given,
    /// stands over the settings file's own value. The supervisor's own
    /// bindings read here too (browser origins, the host's public origin,
    /// the kit fetch URLs and the trusted organ builds) are ones the settings
    /// file never sets. Everything else on `ServeArgs` is refused before this
    /// runs, so nothing reaches here to be quietly dropped.
    ///
    /// `auth_secret` stays `None`: bearer auth terminates at the supervisor,
    /// which owns the listening socket inside an owner-only directory.
    /// Consulting `ONEIRON_AUTH_SECRET` here would give the child a second,
    /// weaker opinion about who may talk to it. Unauthenticated requests are
    /// not allowed: a request the supervisor forwards is its caller's own
    /// slip, the owner it attested, or anonymous, and an anonymous one never
    /// takes the dev mode's owner credential at a door that reads headers
    /// alone (FIX 2222, FIX 5255); the public doors serve it on their own
    /// proofs.
    pub fn serve_config(&self, args: &ServeArgs) -> ServeConfig {
        let defaults = ServeConfig::default();
        let mut config = ServeConfig {
            vault_path: self.data_dir.clone(),
            auth_secret: None,
            allow_unauthenticated: false,
            // Browser origins are argv policy too, for the external shared UI.
            allowed_origins: args.allowed_origins.clone().unwrap_or_default(),
            // The host's public https origin and the URLs a kit dials, as
            // the supervisor, which owns them, passes them. Neither builds an
            // auth layer: the OAuth relay also needs the issuer and JWKS
            // flags, which managed mode refuses.
            oauth_resource_indicator: nonempty(args.oauth_resource_indicator.as_deref()),
            kit_bundle_public_urls: crate::config::normalize_list(
                args.kit_bundle_public_urls.clone().unwrap_or_default(),
            ),
            // The organ builds the supervisor vouches for as first party
            // (FIX 7644); the settings file never names one.
            trusted_organ_builds: args.trusted_organ_builds.iter().cloned().collect(),
            dimensions: args.dimensions.unwrap_or(defaults.dimensions),
            fast_dims: args.fast_dims,
            map_size: args.map_size.unwrap_or(defaults.map_size),
            // Argv only: the usual resolver probes HOME and the XDG roots,
            // which managed mode does not get to read.
            dict_search_paths: args.dict_search_paths.clone().unwrap_or_default(),
            assistant_display_names: args.assistant_display_names.clone().unwrap_or_default(),
            // Fact and verb hooks run unless the supervisor passes `--no-hooks`.
            hooks: !args.no_hooks,
            maximum_tier: self.maximum_tier,
            // The supervisor's key directory or none: the platform default
            // lies under HOME and the XDG roots, which managed mode never reads.
            keystore: KeystoreConfig {
                backend: if self.keystore_dir.is_some() {
                    KeystoreBackend::Platform
                } else {
                    KeystoreBackend::Off
                },
                dir: self.keystore_dir.clone(),
                service: None,
            },
            // Our cloud sends feedback to our own inbox unless the settings
            // file chooses otherwise (ARCH-0056 r6); every send still asks the
            // owner first.
            feedback: crate::config::FeedbackConfig::cloud_default(),
            // The owner's "Help improve Oneiron" choice as the supervisor
            // passes it, either way; unset, the settings file's, then the
            // managed default.
            failure_signal_export: args.failure_signal_export,
            // Training on what it sends: unset, the settings file's, then
            // whatever the switch is (FIX 5188).
            failure_signal_training: args.failure_signal_training,
            // The supervisor's e-sign delivery outbox, when it runs a sender.
            esign_delivery_outbox_dir: self.esign_delivery_outbox.clone(),
            // The supervisor's training outbox, when it ships for one.
            publisher_training_outbox_dir: self.publisher_training_outbox.clone(),
            // Read and inactive whatever argv says (TL-6): the supervisor
            // pushes the intake's keys and ships, so this vault never fetches
            // the intake's descriptor or ships through the anonymous window.
            publisher_training_self_host_shipper: false,
            ..defaults
        };
        if let Some(log_level) = args.log_level.clone() {
            config.log_level = log_level;
        }
        // The artifact origin answers on this vault's internal authority,
        // `<vault_name>.artifact.invalid` and `<app>.<vault_name>.artifact.invalid`,
        // and on no artifact domain (FIX 6716): the edge checks the public
        // name and forwards that authority, so no public name reaches here.
        if self.artifact_socket.is_some() {
            config.artifact_internal_vault_id = Some(self.vault_name.clone());
        }
        config
    }
}
