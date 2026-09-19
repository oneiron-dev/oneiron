//! First-run embedder choice, using the same config and provider as serve.
use crate::cli::InitArgs;
use crate::config::{
    EmbedderConfig, EmbedderLocality, EmbedderProvider, EnvConfig, ServeArgs, ServeConfig,
};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

const EMBEDDER_DOCS: &str = "https://oneiron.dev/oneiron/agents/oneiron-arch-0036-runtime-v1/";

pub fn init(args: InitArgs) -> anyhow::Result<()> {
    init_with_env(args, EnvConfig::from_process()?)
}

fn init_with_env(mut args: InitArgs, env: EnvConfig) -> anyhow::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let choice = match args.embedder {
        Some(choice) => choice,
        None if input.is_terminal() => ask_choice(&mut input, &mut output, recommended_local())?,
        None => EmbedderProvider::None,
    };
    if choice == EmbedderProvider::Endpoint
        && args.embedder_endpoint.is_none()
        && input.is_terminal()
    {
        write!(output, "OpenAI-compatible embedder URL (no credentials): ")?;
        output.flush()?;
        let mut line = String::new();
        input.read_line(&mut line)?;
        args.embedder_endpoint = Some(line.trim().to_owned());
    }
    if choice == EmbedderProvider::Endpoint
        && endpoint_locality(&args)? != EmbedderLocality::OnDevice
        && input.is_terminal()
    {
        ask_remote_options(&mut args, &mut input, &mut output)?;
    }
    let path = args
        .config
        .clone()
        .or_else(crate::config::default_config_path)
        .ok_or_else(|| anyhow::anyhow!("no config location; pass --config"))?;
    let config_text = config_text(&args, choice, &path)?;
    // Validate exactly what serve will read before downloading or creating a vault.
    let staged = stage_config(&path, &config_text)?;
    let result = (|| {
        let config = read_config(&staged, env)?;
        let device = match config.embedder.as_ref().filter(|c| c.is_active()) {
            Some(embedder) if embedder.provider == EmbedderProvider::Local => {
                crate::embedder::prepare_local(embedder)?.to_owned()
            }
            Some(embedder) => {
                crate::embedder::build_slot(Some(embedder))?;
                crate::embedder::build_remote_rung(embedder)?;
                if let Some(remote) = &embedder.remote {
                    format!(
                        "{} endpoint with on-device fallback and queries",
                        remote.locality.as_str()
                    )
                } else {
                    "on-device endpoint".to_owned()
                }
            }
            None => "none".to_owned(),
        };
        let vault = oneiron::Vault::open_owned(&config.vault_path, config.vault_config())?;
        std::fs::rename(&staged, &path)?;
        super::print_doctor_report(&vault)?;
        writeln!(output, "config: {}", path.display())?;
        if let Some(embedder) = config.embedder.as_ref() {
            writeln!(
                output,
                "embedder: provider={} model_id={} dimensions={} device={device}",
                embedder.provider.as_str(),
                embedder.model_id,
                embedder.dimensions
            )?;
        }
        writeln!(output, "Embedder guide: {EMBEDDER_DOCS}")?;
        if choice == EmbedderProvider::Endpoint {
            writeln!(
                output,
                "Known-good servers: LM Studio (https://lmstudio.ai), Ollama (https://ollama.com), llama-server (https://github.com/ggml-org/llama.cpp), mistral.rs serve (https://mistral.rs). Keys come from --embedder-api-key-env NAME, never argv values."
            )?;
        }
        Ok(())
    })();
    if staged.exists() {
        let _ = std::fs::remove_file(staged);
    }
    result
}

fn ask_choice(
    input: &mut impl BufRead,
    output: &mut impl Write,
    local_default: bool,
) -> anyhow::Result<EmbedderProvider> {
    let default = if local_default { "local" } else { "none" };
    writeln!(
        output,
        "Local: ~1.2 GB download, ~0.7 GB steady memory. Endpoint: a server you configure. None: lexical search only."
    )?;
    write!(output, "Embedder local | endpoint | none [{default}]: ")?;
    output.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    let value = if line.trim().is_empty() {
        default
    } else {
        line.trim()
    };
    value.parse().map_err(anyhow::Error::msg)
}

fn recommended_local() -> bool {
    #[cfg(target_os = "linux")]
    {
        let memory = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        memory
            .lines()
            .find_map(|line| {
                line.strip_prefix("MemAvailable:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
            .is_some_and(|kb| kb >= 2 * 1024 * 1024)
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/usr/sbin/sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .is_some_and(|bytes| bytes >= 2 * 1024 * 1024 * 1024)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

fn endpoint_locality(args: &InitArgs) -> anyhow::Result<EmbedderLocality> {
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

fn ask_remote_options(
    args: &mut InitArgs,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> anyhow::Result<()> {
    if args.embedder_fallback_endpoint.is_none() {
        write!(
            output,
            "On-device fallback URL (must serve the same embedding model; also used for queries): "
        )?;
        output.flush()?;
        let mut line = String::new();
        input.read_line(&mut line)?;
        args.embedder_fallback_endpoint = Some(line.trim().to_owned());
    }
    if !args.embedder_egress_allow_all && args.embedder_egress_allow.is_empty() {
        write!(
            output,
            "Authorize this network endpoint to receive all embeddable entities? [y/N]: "
        )?;
        output.flush()?;
        let mut line = String::new();
        input.read_line(&mut line)?;
        if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            anyhow::bail!(
                "remote egress was not authorized; choose local/none or pass explicit entity IDs"
            );
        }
        args.embedder_egress_allow_all = true;
    }
    Ok(())
}

fn config_text(args: &InitArgs, choice: EmbedderProvider, path: &Path) -> anyhow::Result<String> {
    let mut table: toml::Table = match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => toml::Table::new(),
        Err(error) => return Err(error.into()),
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
        anyhow::bail!("local init uses the pinned Harrier model and its 1024 dimensions");
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
    Ok(toml::to_string_pretty(&table)?)
}

fn read_config(path: &Path, env: EnvConfig) -> anyhow::Result<ServeConfig> {
    crate::config::resolve_serve_config_with_sources(
        &ServeArgs {
            config: Some(path.to_path_buf()),
            ..Default::default()
        },
        env,
        None,
    )
}

fn stage_config(path: &Path, text: &str) -> anyhow::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staged = parent.join(format!(
        ".oneiron-init-{}.toml",
        oneiron::EntityId::now().to_hex()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&staged)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn init_choice_defaults_and_rejects_bad_answers() {
        for (answer, capable, expected) in [
            ("\n", true, EmbedderProvider::Local),
            ("\n", false, EmbedderProvider::None),
            ("endpoint\n", true, EmbedderProvider::Endpoint),
        ] {
            assert_eq!(
                ask_choice(&mut answer.as_bytes(), &mut Vec::new(), capable).unwrap(),
                expected
            );
        }
        assert!(ask_choice(&mut "invalid\n".as_bytes(), &mut Vec::new(), true).is_err());
    }
    #[test]
    fn init_none_preserves_unrelated_config_and_disables_old_provider() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oneiron.toml");
        std::fs::write(
            &path,
            r#"port = 12345
[embedder]
provider = "local"
"#,
        )
        .unwrap();
        let args = InitArgs {
            path: dir.path().join("vault"),
            config: Some(path.clone()),
            embedder: Some(EmbedderProvider::None),
            dimensions: Some(32),
            map_size: 64 * 1024 * 1024,
            ..Default::default()
        };
        init_with_env(args, EnvConfig::default()).unwrap();
        let config = read_config(&path, EnvConfig::default()).unwrap();
        assert_eq!(config.port, 12345);
        assert!(!config.embedder.unwrap().is_active());
    }
    #[test]
    fn init_uses_serve_environment_and_refuses_invalid_overrides_before_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oneiron.toml");
        let args = InitArgs {
            path: dir.path().join("vault"),
            config: Some(path.clone()),
            embedder: Some(EmbedderProvider::Local),
            map_size: 64 * 1024 * 1024,
            ..Default::default()
        };
        let overrides = [
            ("ONEIRON_EMBEDDER_PROVIDER", "endpoint"),
            ("ONEIRON_EMBEDDER_ENDPOINT", "http://127.0.0.1:8080/v1"),
            ("ONEIRON_EMBEDDER_MODEL_ID", "fixture/embedder@v1"),
            ("ONEIRON_EMBEDDER_MODEL_KEY", "fixture"),
            ("ONEIRON_EMBEDDER_DIMENSIONS", "8"),
            ("ONEIRON_DIMENSIONS", "8"),
        ];
        let invalid = EnvConfig::from_pairs(
            overrides
                .into_iter()
                .chain([("ONEIRON_EMBEDDER_DIMENSIONS", "16")]),
        )
        .unwrap();
        assert!(init_with_env(args.clone(), invalid).is_err());
        assert!(!args.path.exists());
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        let env = EnvConfig::from_pairs(overrides).unwrap();
        init_with_env(args.clone(), env.clone()).unwrap();
        let serve = crate::config::resolve_serve_config_with_sources(
            &ServeArgs {
                config: Some(path.clone()),
                ..Default::default()
            },
            env,
            None,
        )
        .unwrap();
        let embedder = serve.embedder.as_ref().unwrap();
        assert_eq!(embedder.provider, EmbedderProvider::Endpoint);
        assert_eq!(embedder.model_id, "fixture/embedder@v1");
        assert_eq!(serve.dimensions, 8);
        // The created vault accepts serve's effective dimensions and model pin.
        let vault = oneiron::Vault::open_owned(&serve.vault_path, serve.vault_config()).unwrap();
        drop(vault);
        let mut wrong = serve.vault_config();
        wrong.dimensions = 1024;
        assert!(oneiron::Vault::open_owned(&serve.vault_path, wrong).is_err());
    }

    #[test]
    fn network_init_requires_explicit_egress_and_a_local_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oneiron.toml");
        let mut args = InitArgs {
            path: dir.path().join("vault"),
            embedder_endpoint: Some("https://embed.example/v1".into()),
            ..Default::default()
        };
        assert_eq!(
            endpoint_locality(&args).unwrap(),
            EmbedderLocality::ThirdParty
        );
        assert!(config_text(&args, EmbedderProvider::Endpoint, &path).is_err());
        args.embedder_fallback_endpoint = Some("http://127.0.0.1:8080/v1".into());
        assert!(config_text(&args, EmbedderProvider::Endpoint, &path).is_err());
        args.embedder_egress_allow = vec![oneiron::EntityId::now().to_hex()];
        let text = config_text(&args, EmbedderProvider::Endpoint, &path).unwrap();
        let staged = stage_config(&path, &text).unwrap();
        let config = read_config(&staged, EnvConfig::default())
            .unwrap()
            .embedder
            .unwrap();
        let remote = config.remote.as_ref().unwrap();
        assert_eq!(remote.locality, EmbedderLocality::ThirdParty);
        assert_eq!(remote.endpoint, "https://embed.example/v1");
        assert_eq!(
            remote.egress.as_ref().unwrap().allow,
            args.embedder_egress_allow
        );
        assert!(!remote.egress.as_ref().unwrap().allow_all);
        assert_eq!(config.endpoint.locality, EmbedderLocality::OnDevice);
        crate::embedder::build_remote_rung(&config).unwrap();
        assert!(!path.exists());
        assert!(!args.path.exists());
    }

    #[test]
    fn interactive_remote_authorization_defaults_to_refusal() {
        let mut args = InitArgs::default();
        assert!(
            ask_remote_options(
                &mut args,
                &mut "http://127.0.0.1:8080/v1\n\n".as_bytes(),
                &mut Vec::new()
            )
            .is_err()
        );
        assert!(!args.embedder_egress_allow_all);
        ask_remote_options(&mut args, &mut "yes\n".as_bytes(), &mut Vec::new()).unwrap();
        assert!(args.embedder_egress_allow_all);
    }
}
