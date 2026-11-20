//! The layers serve merges, read and applied in precedence order: the
//! config file, the owner's settings file, the environment, the flags
//! ([`super::resolve_serve_config_with_sources`]).

use super::{
    ConfigLayer, EnvConfig, HostingPrivacyPosture, PartialServeConfig, PathBuf, ServeArgs,
    ServeConfig, load_file_config, refusal_origin,
};

/// One layer of the merge: its place in the precedence order, where its
/// values came from, and the values.
pub(super) struct Layer {
    source: ConfigLayer,
    /// `None` for a config file layer with no file to read.
    origin: Option<refusal_origin::LayerOrigin>,
    values: PartialServeConfig,
}

/// Every layer serve merges, lowest precedence first: the config file, the
/// owner's settings file, the environment, the flags.
pub(super) fn read_layers(
    args: &ServeArgs,
    env: EnvConfig,
    default_config_path: Option<PathBuf>,
) -> anyhow::Result<Vec<Layer>> {
    let flag_values = PartialServeConfig::from(args);
    let config_path = args
        .config
        .clone()
        .or_else(|| env.config_path.clone())
        .or(default_config_path);
    let explicit_config = args.config.is_some() || env.config_path.is_some();
    // A config path whose existence cannot be checked (a parent this process
    // may not search) is not taken as absent, even the default one: its file
    // may set what the defaults do not, such as a manual `[runtime] clock`.
    let file_layer = match config_path {
        Some(path) => match path.try_exists() {
            Ok(true) => {
                let (values, raw) = load_file_config(&path)?;
                Layer {
                    source: ConfigLayer::Vault,
                    origin: Some(refusal_origin::LayerOrigin::ConfigFile { path, raw }),
                    values,
                }
            }
            Ok(false) if explicit_config => {
                anyhow::bail!("config file {} does not exist", path.display());
            }
            Ok(false) => Layer::unread(),
            Err(error) => {
                let path = path.display();
                anyhow::bail!("config file {path} cannot be checked: {error}");
            }
        },
        None => Layer::unread(),
    };
    let mut layers = vec![file_layer];
    // The owner's settings file (`--settings-file`, FIX 5016), in the config
    // file's schema as a managed vault reads it: one more vault file layer,
    // over the config file and under the environment and the flags.
    if let Some(path) = args.settings_file.as_deref() {
        let (values, raw) = load_file_config(path)?;
        layers.push(Layer {
            source: ConfigLayer::Vault,
            origin: Some(refusal_origin::LayerOrigin::SettingsFile {
                path: path.to_path_buf(),
                raw,
            }),
            values,
        });
    }
    layers.push(Layer {
        source: ConfigLayer::Environment,
        origin: Some(refusal_origin::LayerOrigin::Environment),
        values: env.values,
    });
    layers.push(Layer {
        source: ConfigLayer::Holder,
        origin: Some(refusal_origin::LayerOrigin::CommandLine),
        values: flag_values,
    });
    Ok(layers)
}

impl Layer {
    /// The config file's layer when there is no file to read.
    fn unread() -> Self {
        Self {
            source: ConfigLayer::Vault,
            origin: None,
            values: PartialServeConfig::default(),
        }
    }
}

/// `layers` merged over the defaults in order, then settled and held to
/// `check`. A value refused as its layer is applied names that layer; one
/// refused once every layer has applied (the local embedder's space, then
/// `check`) names the layer [`refusal_origin::locate_refusal`] finds (FIX
/// CONFIG-REFUSED-VALUE-NAMES-NO-FILE-LINE).
pub(super) fn merge_layers(
    args: &ServeArgs,
    layers: &[Layer],
    check: fn(&ServeConfig) -> anyhow::Result<()>,
) -> anyhow::Result<ServeConfig> {
    let (resolved, space_naming) = apply_layers(args, layers)?;
    settle_merged(resolved, space_naming, check).map_err(|refusal| {
        let origins: Vec<_> = layers.iter().map(|layer| layer.origin.as_ref()).collect();
        refusal_origin::locate_refusal(refusal, &origins, |start| {
            let (resolved, space_naming) = apply_layers(args, &layers[start..]).ok()?;
            settle_merged(resolved, space_naming, check).err()
        })
    })
}

/// `resolved`'s local embedder space settled as `space_naming` says, then
/// `resolved` held to `check`.
fn settle_merged(
    mut resolved: ServeConfig,
    space_naming: super::super::embedder_space::SpaceNaming,
    check: fn(&ServeConfig) -> anyhow::Result<()>,
) -> anyhow::Result<ServeConfig> {
    if let Some(embedder) = resolved.embedder.as_mut() {
        super::super::embedder_space::settle_local_space(embedder, space_naming)?;
    }
    check(&resolved)?;
    Ok(resolved)
}

/// `layers` applied over the defaults in order, then the settings only argv
/// gives, and what the layers name of the local embedder's space and files.
/// A layer's value refused as it is applied names that layer.
fn apply_layers(
    args: &ServeArgs,
    layers: &[Layer],
) -> anyhow::Result<(ServeConfig, super::super::embedder_space::SpaceNaming)> {
    let mut embedders = [None; 4];
    for (slot, layer) in embedders.iter_mut().zip(layers) {
        *slot = layer.values.embedder.as_ref();
    }
    let space_naming = super::super::embedder_space::SpaceNaming::of(embedders);
    let mut resolved = ServeConfig::default();
    let mut posture_source = None;
    let mut key_ref_source = None;
    for layer in layers {
        let source = layer.source;
        let values = layer.values.clone();
        if values.privacy_posture.is_some() {
            posture_source = Some(source);
        }
        if values.hosted_kms_key_ref.is_some() {
            key_ref_source = Some(source);
        }
        values
            .apply_to(&mut resolved, source)
            .map_err(|refusal| match &layer.origin {
                Some(origin) => origin.attach(refusal),
                None => refusal,
            })?;
    }
    // Only the final posture may discard inherited custody, and only a blind
    // relay, which holds no key: a self-hosted vault keeps an inherited KMS
    // reference as its own key's custody. An intermediate relay layer can
    // still be overridden by a later hosted layer, which needs the
    // highest-precedence reference even when it came from the file.
    if resolved.privacy_posture == HostingPrivacyPosture::Relay
        && let (Some(posture_source), Some(key_ref_source)) = (posture_source, key_ref_source)
        && key_ref_source < posture_source
    {
        resolved.hosted_kms_key_ref = None;
    }
    // The organ builds this server runs as first party, from argv alone
    // (FIX 7644): no file, settings file or environment layer names one.
    resolved.trusted_organ_builds = args.trusted_organ_builds.iter().cloned().collect();
    // The self-hoster's lift of the payment-credential withholding, from
    // argv alone (L8-60).
    resolved.release_payment_credentials_unfenced = args.release_payment_credentials_unfenced;
    // `--voice-socket` names where the voice loop the layered
    // `[models.voice]` turns on listens, over its `socket` (FIX 5016), as
    // managed mode sets it on its settings file. With no voice configured it
    // names nothing.
    if let Some(socket) = &args.voice_socket
        && let Some(models) = resolved.models.as_mut()
    {
        models.voice.listen_on(socket)?;
    }
    Ok((resolved, space_naming))
}
