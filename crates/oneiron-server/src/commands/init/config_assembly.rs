//! The config file init writes: its tables from init's answers, merged over
//! the file already there, and staged beside it for [`super::setup_models`]
//! to validate before it replaces the file. An existing file that does not
//! parse names only itself and the place it failed (FIX 9477), and stays as
//! it was. The existing file is read through serve's own reader, so one serve
//! refuses (any user can write it, or it sets the issuer key and others can
//! read it) is refused with serve's words and stays as it was too: the keys
//! init keeps are keys serve would trust (FIX INIT-ADOPTS-UNADMITTED-CONFIG).

use crate::cli::InitArgs;
use crate::config::{
    EmbedderConfig, EmbedderDevice, EmbedderLocality, EmbedderProvider, OneironerConfig,
    OneironerMode, OneironerProvider,
};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The local section init's answers describe, the bundle's identity filled
/// in where no flag gave it.
pub(super) fn local_tagger_config(args: &InitArgs) -> anyhow::Result<OneironerConfig> {
    let dir = args
        .oneironer_model_dir
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--oneironer local requires --oneironer-model-dir"))?;
    // The config file outlives the shell init ran in: a relative directory
    // would move with whatever directory serve starts from.
    let dir = std::fs::canonicalize(dir).map_err(|error| {
        anyhow::anyhow!(
            "tagger model directory {} is unreadable: {error}",
            dir.display()
        )
    })?;
    let identity = crate::oneironer::engines::bundle_identity(&dir)?;
    Ok(OneironerConfig {
        provider: OneironerProvider::Local,
        model_dir: Some(dir),
        checkpoint_sha16: Some(
            args.oneironer_checkpoint_sha16
                .clone()
                .unwrap_or(identity.checkpoint_sha16),
        ),
        label_count: Some(args.oneironer_label_count.unwrap_or(identity.label_count)),
        device: args.oneironer_device.unwrap_or(EmbedderDevice::Auto),
        ..OneironerConfig::default()
    })
}

/// The `[oneironer]` table init writes: the provider always, so a rerun with
/// `none` turns an old tagger off; the bundle and its identity for a local
/// tagger, the endpoint keys for an endpoint.
pub(super) fn tagger_table(args: &InitArgs) -> anyhow::Result<toml::Table> {
    let choice = args.oneironer.unwrap_or(OneironerProvider::None);
    if choice != OneironerProvider::Endpoint && args.oneironer_url.is_some() {
        anyhow::bail!("--oneironer-url requires --oneironer endpoint");
    }
    if choice != OneironerProvider::Local
        && (args.oneironer_model_dir.is_some()
            || args.oneironer_device.is_some()
            || args.oneironer_tier.is_some())
    {
        anyhow::bail!("tagger model directory, tier and device options require --oneironer local");
    }
    if choice == OneironerProvider::None
        && (args.oneironer_checkpoint_sha16.is_some() || args.oneironer_label_count.is_some())
    {
        anyhow::bail!(
            "tagger checkpoint and label count options require --oneironer local or endpoint"
        );
    }
    let mut table = toml::Table::new();
    table.insert("provider".into(), choice.as_str().into());
    // A tagger without a stated mode saves its tags, as the interactive
    // default does.
    let mode = match (choice, args.oneironer_mode) {
        (_, Some(mode)) => Some(mode),
        (OneironerProvider::Endpoint | OneironerProvider::Local, None) => Some(OneironerMode::Save),
        _ => None,
    };
    if let Some(mode) = mode {
        table.insert("mode".into(), mode.as_str().into());
    }
    if choice == OneironerProvider::Local {
        let config = local_tagger_config(args)?;
        let dir = config
            .model_dir
            .as_deref()
            .and_then(Path::to_str)
            .ok_or_else(|| anyhow::anyhow!("tagger model directory is not UTF-8"))?;
        let mut bundle = toml::Table::new();
        bundle.insert("model_dir".into(), dir.into());
        if let Some(checkpoint) = config.checkpoint_sha16 {
            bundle.insert("checkpoint_sha16".into(), checkpoint.into());
        }
        if let Some(labels) = config.label_count {
            bundle.insert("label_count".into(), i64::from(labels).into());
        }
        // A named tier is one row of `[oneironer.tiers]`, served by name.
        match &args.oneironer_tier {
            Some(tier) => {
                anyhow::ensure!(
                    !tier.is_empty() && tier.len() <= 64,
                    "--oneironer-tier must be 1 to 64 bytes"
                );
                let mut tiers = toml::Table::new();
                tiers.insert(tier.clone(), bundle.into());
                table.insert("tier".into(), tier.as_str().into());
                table.insert("tiers".into(), tiers.into());
            }
            None => {
                for (key, value) in bundle {
                    table.insert(key, value);
                }
            }
        }
        if let Some(device) = args.oneironer_device {
            table.insert("device".into(), device.as_str().into());
        }
    }
    if choice == OneironerProvider::Endpoint {
        let missing = |flag: &str| anyhow::anyhow!("--oneironer endpoint requires {flag}");
        let url = args
            .oneironer_url
            .clone()
            .ok_or_else(|| missing("--oneironer-url"))?;
        let checkpoint = args
            .oneironer_checkpoint_sha16
            .clone()
            .ok_or_else(|| missing("--oneironer-checkpoint-sha16"))?;
        let labels = args
            .oneironer_label_count
            .ok_or_else(|| missing("--oneironer-label-count"))?;
        table.insert("url".into(), url.into());
        table.insert("checkpoint_sha16".into(), checkpoint.into());
        table.insert("label_count".into(), i64::from(labels).into());
    }
    Ok(table)
}

pub(super) fn endpoint_locality(args: &InitArgs) -> anyhow::Result<EmbedderLocality> {
    if let Some(locality) = args.embedder_locality {
        return Ok(locality);
    }
    let endpoint = args
        .embedder_endpoint
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--embedder endpoint requires --embedder-endpoint URL"))?;
    let url = reqwest::Url::parse(endpoint)?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    Ok(if loopback {
        EmbedderLocality::OnDevice
    } else {
        EmbedderLocality::ThirdParty
    })
}

pub(super) fn config_text(
    args: &InitArgs,
    choice: EmbedderProvider,
    path: &Path,
) -> anyhow::Result<String> {
    let mut table: toml::Table = match crate::config::merge::read_config_file(path) {
        Ok(text) => crate::config::parse_toml(path, &text)?,
        Err(error) if is_absent(&error) => toml::Table::new(),
        Err(error) => return Err(error),
    };
    if choice != EmbedderProvider::Endpoint
        && (args.embedder_endpoint.is_some()
            || args.embedder_api_key_env.is_some()
            || args.embedder_locality.is_some()
            || args.embedder_fallback_endpoint.is_some()
            || args.embedder_egress_allow_all
            || !args.embedder_egress_allow.is_empty())
    {
        anyhow::bail!("endpoint options require --embedder endpoint");
    }
    let defaults = EmbedderConfig::default();
    let dims = args
        .dimensions
        .unwrap_or(if choice == EmbedderProvider::None {
            4096
        } else {
            defaults.dimensions
        });
    let model_id = args.embedder_model_id.clone().unwrap_or(defaults.model_id);
    if choice != EmbedderProvider::None
        && !model_id
            .split_once('@')
            .is_some_and(|(model, revision)| !model.is_empty() && !revision.is_empty())
    {
        anyhow::bail!("embedder model must be pinned as model_id@revision");
    }
    if choice == EmbedderProvider::Local
        && (dims != defaults.dimensions || args.embedder_model_id.is_some())
    {
        anyhow::bail!("local init uses the pinned default model and its 1024 dimensions");
    }
    let mut embedder = toml::Table::new();
    embedder.insert("provider".into(), choice.as_str().into());
    embedder.insert("dimensions".into(), i64::try_from(dims)?.into());
    embedder.insert("model_id".into(), model_id.into());
    if choice == EmbedderProvider::Endpoint {
        let endpoint = args
            .embedder_endpoint
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("--embedder endpoint requires --embedder-endpoint URL")
            })?;
        let locality = endpoint_locality(args)?;
        let model_key = args
            .embedder_model_key
            .clone()
            .unwrap_or(defaults.local.repo);
        if locality == EmbedderLocality::OnDevice {
            if args.embedder_fallback_endpoint.is_some()
                || args.embedder_egress_allow_all
                || !args.embedder_egress_allow.is_empty()
            {
                anyhow::bail!("fallback and egress options require a remote endpoint locality");
            }
            embedder.insert("endpoint".into(), endpoint.clone().into());
            embedder.insert("model_key".into(), model_key.into());
            if let Some(name) = &args.embedder_api_key_env {
                embedder.insert("api_key_env".into(), name.clone().into());
            }
        } else {
            let fallback = args.embedder_fallback_endpoint.as_ref().filter(|url| !url.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("network endpoints require --embedder-fallback-endpoint with the same model on device"))?;
            if !args.embedder_egress_allow_all && args.embedder_egress_allow.is_empty() {
                anyhow::bail!(
                    "network endpoints require explicit --embedder-egress-allow IDs or --embedder-egress-allow-all authorization"
                );
            }
            embedder.insert("endpoint".into(), fallback.clone().into());
            embedder.insert("model_key".into(), model_key.clone().into());
            let mut remote = toml::Table::new();
            remote.insert("endpoint".into(), endpoint.clone().into());
            remote.insert("model_key".into(), model_key.into());
            remote.insert("locality".into(), locality.as_str().into());
            if let Some(name) = &args.embedder_api_key_env {
                remote.insert("api_key_env".into(), name.clone().into());
            }
            let mut egress = toml::Table::new();
            egress.insert("allow_all".into(), args.embedder_egress_allow_all.into());
            egress.insert(
                "allow".into(),
                toml::Value::Array(
                    args.embedder_egress_allow
                        .iter()
                        .cloned()
                        .map(toml::Value::from)
                        .collect(),
                ),
            );
            remote.insert("egress".into(), egress.into());
            embedder.insert("remote".into(), remote.into());
        }
    }
    let vault_path = std::path::absolute(&args.path)?;
    table.insert(
        "vault_path".into(),
        vault_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("vault path must be UTF-8"))?
            .into(),
    );
    table.insert("dimensions".into(), i64::try_from(dims)?.into());
    table.insert("map_size".into(), i64::try_from(args.map_size)?.into());
    if args.maximum_tier {
        table.insert("maximum_tier".into(), true.into());
    }
    if let Some(paths) = &args.dict_search_paths {
        let paths = paths
            .iter()
            .map(|p| {
                p.to_str()
                    .map(toml::Value::from)
                    .ok_or_else(|| anyhow::anyhow!("dictionary path must be UTF-8"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        table.insert("dict_search_paths".into(), toml::Value::Array(paths));
    }
    table.insert("embedder".into(), toml::Value::Table(embedder));
    // An existing label table survives a rerun; init never writes one.
    let labels = table
        .get("oneironer")
        .and_then(|section| section.get("labels"))
        .cloned();
    let mut tagger = tagger_table(args)?;
    if let Some(labels) = labels {
        tagger.insert("labels".into(), labels);
    }
    table.insert("oneironer".into(), toml::Value::Table(tagger));
    Ok(toml::to_string_pretty(&table)?)
}

/// Whether `error` says the config file is not there: init then writes a
/// new one.
fn is_absent(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|io_error| io_error.kind() == io::ErrorKind::NotFound)
}

pub(super) fn stage_config(path: &Path, text: &str) -> anyhow::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staged = parent.join(format!(
        ".oneiron-init-{}.toml",
        oneiron::EntityId::now().to_hex()
    ));
    // The config may carry the issuer secret: owner-only, and on macOS with
    // no ACL entry from its directory.
    let mut file = super::super::credential_file::create(&staged)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(staged)
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::{init_with_env, read_config};
    use crate::cli::InitArgs;
    use crate::config::{EmbedderProvider, EnvConfig};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    /// A config init keeps a key of (`port`) and replaces a section of.
    const EXISTING: &str = "port = 12345\n[embedder]\nprovider = \"local\"\n";

    fn answers(dir: &Path, config: &Path) -> InitArgs {
        InitArgs {
            path: dir.join("vault"),
            config: Some(config.to_path_buf()),
            embedder: Some(EmbedderProvider::None),
            dimensions: Some(32),
            map_size: 64 * 1024 * 1024,
            ..Default::default()
        }
    }

    /// `text` at `path` with exactly `mode`, whatever the umask.
    fn config_file(path: &Path, text: &str, mode: u32) {
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn init_refuses_a_config_any_user_can_write_and_leaves_it_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oneiron.toml");
        config_file(&path, EXISTING, 0o666);
        let error = init_with_env(answers(dir.path(), &path), EnvConfig::default(), None)
            .expect_err("init kept the keys of a config any user can write");
        let message = format!("{error:#}");
        assert!(
            message.contains("can be written by any user (mode 666)")
                && message.contains("chmod o-w"),
            "{message}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), EXISTING);
        assert_eq!(mode(&path), 0o666);
        assert!(!dir.path().join("vault").exists());
    }

    #[test]
    fn init_refuses_a_config_that_sets_the_issuer_key_where_others_can_read_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oneiron.toml");
        let secret = "ab".repeat(32);
        let text = format!("auth_secret = \"{secret}\"\n{EXISTING}");
        config_file(&path, &text, 0o644);
        let error = init_with_env(answers(dir.path(), &path), EnvConfig::default(), None)
            .expect_err("init kept an issuer key other users can read");
        let message = format!("{error:#}");
        assert!(message.contains("sets auth_secret at line 1"), "{message}");
        assert!(!message.contains(&secret), "{message}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        assert_eq!(mode(&path), 0o644);
    }

    #[test]
    fn init_keeps_the_keys_of_a_config_only_its_owner_can_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oneiron.toml");
        config_file(&path, EXISTING, 0o644);
        init_with_env(answers(dir.path(), &path), EnvConfig::default(), None).unwrap();
        let config = read_config(&path, EnvConfig::default()).unwrap();
        assert_eq!(config.port, 12345);
        assert!(!config.embedder.unwrap().is_active());
        assert_eq!(mode(&path), 0o600);
    }
}
