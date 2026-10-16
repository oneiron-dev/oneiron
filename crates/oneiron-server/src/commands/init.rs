//! First-run embedder and tagger choices, using the same config and providers as serve.
use crate::cli::InitArgs;
use crate::config::{
    EmbedderConfig, EmbedderDevice, EmbedderLocality, EmbedderProvider, EnvConfig, OneironerConfig,
    OneironerMode, OneironerProvider, ServeArgs, ServeConfig,
};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

const EMBEDDER_DOCS: &str = "https://oneiron.dev/oneiron/agents/oneiron-arch-0036-runtime-v1/";

pub fn init(args: InitArgs) -> anyhow::Result<()> {
    init_with_env(
        args,
        EnvConfig::from_process()?,
        crate::config::default_config_path(),
    )
}

fn init_with_env(
    mut args: InitArgs,
    env: EnvConfig,
    default_path: Option<PathBuf>,
) -> anyhow::Result<()> {
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
    if args.oneironer.is_none() && input.is_terminal() {
        ask_tagger(&mut args, &mut input, &mut output)?;
    }
    let path = args
        .config
        .clone()
        .or_else(|| env.config_path.clone())
        .or(default_path)
        .ok_or_else(|| anyhow::anyhow!("no config location; pass --config"))?;
    let config_text = config_text(&args, choice, &path)?;
    // Validate exactly what serve will read before downloading or creating a vault.
    let staged = stage_config(&path, &config_text)?;
    let result = (|| {
        let config = read_config(&staged, env)?;
        // The same slot serve builds: a local bundle loads on its engine, and
        // a reachable tagger must be the configured one.
        // Checked first, so a refusal comes before the local model download.
        let tagger_slot = crate::oneironer::build_slot(config.oneironer.as_ref())?;
        let device = match config.embedder.as_ref().filter(|c| c.is_active()) {
            Some(embedder) if embedder.provider == EmbedderProvider::Local => {
                crate::embedder::prepare_local(embedder)?.to_owned()
            }
            Some(embedder) => {
                // The probe's run rows go to the log, as serve's do.
                let receipts = std::sync::Arc::new(crate::models::ServerReceipts::default());
                crate::embedder::build_slot(Some(embedder), receipts.clone())?;
                // Built to check the section only; it never sends here.
                crate::embedder::build_remote_rung(embedder, Default::default(), receipts)?;
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
        if let Some(tagger) = config.oneironer.as_ref().filter(|t| t.is_active()) {
            write!(
                output,
                "tagger: provider={} mode={}",
                tagger.provider.as_str(),
                tagger.mode.as_str()
            )?;
            match tagger_slot.as_ref().and_then(|slot| slot.serving()) {
                Some(serving) => writeln!(
                    output,
                    " engine={} ({})",
                    serving.engine.id(),
                    serving.pick.as_str()
                )?,
                None => writeln!(output)?,
            }
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

/// Asks for the tagger the way the embedder is asked for: local, endpoint or
/// none. The local tagger runs a model bundle already on this machine, so the
/// default is none. A vault with a tagger saves its tags, so the mode
/// defaults to save; shadow is the test switch.
fn ask_tagger(
    args: &mut InitArgs,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> anyhow::Result<()> {
    let choice = ask_line(input, output, "Tagger local | endpoint | none [none]: ")?;
    let choice: OneironerProvider = if choice.is_empty() {
        OneironerProvider::None
    } else {
        choice.parse().map_err(anyhow::Error::msg)?
    };
    args.oneironer = Some(choice);
    match choice {
        OneironerProvider::None => return Ok(()),
        OneironerProvider::Local => ask_local_tagger(args, input, output)?,
        OneironerProvider::Endpoint => {
            if args.oneironer_url.is_none() {
                args.oneironer_url = Some(ask_line(
                    input,
                    output,
                    "Tagger server URL on this machine: ",
                )?);
            }
            if args.oneironer_checkpoint_sha16.is_none() {
                args.oneironer_checkpoint_sha16 = Some(ask_line(
                    input,
                    output,
                    "Tagger checkpoint (16 hex digits): ",
                )?);
            }
            if args.oneironer_label_count.is_none() {
                args.oneironer_label_count =
                    Some(ask_line(input, output, "Tagger label count: ")?.parse()?);
            }
        }
    }
    if args.oneironer_mode.is_none() {
        let mode = ask_line(input, output, "Tagger mode save | shadow [save]: ")?;
        args.oneironer_mode = Some(if mode.is_empty() {
            OneironerMode::Save
        } else {
            mode.parse().map_err(anyhow::Error::msg)?
        });
    }
    Ok(())
}

/// The local tagger's questions: the bundle, then the engine. The bundle's
/// manifest names its checkpoint and label count, so neither is asked. Every
/// engine this machine runs is measured against the bundle's reference and
/// listed; `auto` serves the fastest that clears the bar, and any other one
/// listed may be picked by name (ARCH-0036).
fn ask_local_tagger(
    args: &mut InitArgs,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> anyhow::Result<()> {
    if args.oneironer_model_dir.is_none() {
        let dir = ask_line(
            input,
            output,
            "Tagger model directory (holds oneironer.json): ",
        )?;
        args.oneironer_model_dir = Some(PathBuf::from(dir));
    }
    if args.oneironer_device.is_some() {
        return Ok(());
    }
    let config = local_tagger_config(args)?;
    let survey = crate::oneironer::engines::survey(&config)?;
    writeln!(output, "Tagger engines on this machine:")?;
    for (engine, row) in &survey.engines {
        let measured = match row {
            Some(row) => match (row.clears, row.mean_ms) {
                (true, Some(ms)) => format!("{ms:.1} ms per reference case"),
                (false, Some(ms)) => {
                    format!("{ms:.1} ms per reference case, misses the parity bar")
                }
                (_, None) => "could not run the bundle".to_owned(),
            },
            None => "no reference in the bundle; unmeasured".to_owned(),
        };
        let default = if Some(*engine) == survey.default {
            " (auto)"
        } else {
            ""
        };
        writeln!(output, "  {}{default}: {measured}", engine.id())?;
    }
    let names: Vec<&str> = survey
        .engines
        .iter()
        .map(|(engine, _)| engine.device.as_str())
        .collect();
    // With no engine clearing the bar there is no `auto` to offer: the
    // operator names one, knowing what it measured.
    let prompt = if survey.default.is_some() {
        format!("Tagger engine auto | {} [auto]: ", names.join(" | "))
    } else {
        format!(
            "No engine clears the bundle's parity bar; tagger engine {}: ",
            names.join(" | ")
        )
    };
    let picked = ask_line(input, output, &prompt)?;
    let device: EmbedderDevice = if picked.is_empty() && survey.default.is_some() {
        EmbedderDevice::Auto
    } else {
        // `candle/metal` as listed, or the device alone.
        let device = picked.rsplit('/').next().unwrap_or_default();
        device.parse().map_err(anyhow::Error::msg)?
    };
    args.oneironer_device = Some(device);
    Ok(())
}

/// The local section init's answers describe, the bundle's identity filled
/// in where no flag gave it.
fn local_tagger_config(args: &InitArgs) -> anyhow::Result<OneironerConfig> {
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

fn ask_line(
    input: &mut impl BufRead,
    output: &mut impl Write,
    prompt: &str,
) -> anyhow::Result<String> {
    write!(output, "{prompt}")?;
    output.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

/// The `[oneironer]` table init writes: the provider always, so a rerun with
/// `none` turns an old tagger off; the bundle and its identity for a local
/// tagger, the endpoint keys for an endpoint.
fn tagger_table(args: &InitArgs) -> anyhow::Result<toml::Table> {
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

fn ask_choice(
    input: &mut impl BufRead,
    output: &mut impl Write,
    local_default: bool,
) -> anyhow::Result<EmbedderProvider> {
    let default = if local_default { "local" } else { "none" };
    writeln!(
        output,
        "Local: ~2.4 GB download, ~1.4 GB steady memory. Endpoint: a server you configure. None: lexical search only."
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
        oneiron_spawn::command("/usr/sbin/sysctl")
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
    // The config may carry the issuer secret: owner-only, and on macOS with
    // no ACL entry from its directory.
    let mut file = super::credential_file::create(&staged)?;
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
        init_with_env(args, EnvConfig::default(), None).unwrap();
        let config = read_config(&path, EnvConfig::default()).unwrap();
        assert_eq!(config.port, 12345);
        assert!(!config.embedder.unwrap().is_active());
    }
    #[test]
    fn init_uses_serve_environment_and_refuses_invalid_overrides_before_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oneiron.toml");
        let default_path = dir.path().join("unused-default.toml");
        let args = InitArgs {
            path: dir.path().join("vault"),
            config: None,
            embedder: Some(EmbedderProvider::Local),
            map_size: 64 * 1024 * 1024,
            ..Default::default()
        };
        let overrides = [
            ("ONEIRON_CONFIG", path.to_str().unwrap()),
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
        assert!(init_with_env(args.clone(), invalid, Some(default_path.clone())).is_err());
        assert!(!args.path.exists());
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        let env = EnvConfig::from_pairs(overrides).unwrap();
        init_with_env(args, env.clone(), Some(default_path.clone())).unwrap();
        assert!(path.is_file());
        assert!(!default_path.exists());
        let serve =
            crate::config::resolve_serve_config_with_sources(&ServeArgs::default(), env, None)
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
        crate::embedder::build_remote_rung(
            &config,
            Default::default(),
            std::sync::Arc::new(crate::models::ServerReceipts::default()),
        )
        .unwrap();
        assert!(!path.exists());
        assert!(!args.path.exists());
    }

    #[test]
    fn the_interactive_tagger_question_defaults_to_none() {
        let mut args = InitArgs::default();
        ask_tagger(&mut args, &mut "\n".as_bytes(), &mut Vec::new()).unwrap();
        assert_eq!(args.oneironer, Some(OneironerProvider::None));
        let mut args = InitArgs::default();
        ask_tagger(
            &mut args,
            &mut "endpoint\nhttp://127.0.0.1:9100\n0123456789abcdef\n3\nshadow\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(args.oneironer, Some(OneironerProvider::Endpoint));
        assert_eq!(args.oneironer_label_count, Some(3));
        assert_eq!(
            args.oneironer_mode,
            Some(crate::config::OneironerMode::Shadow)
        );
        assert!(
            tagger_table(&InitArgs {
                oneironer_url: Some("http://127.0.0.1:9100".into()),
                ..InitArgs::default()
            })
            .is_err()
        );
    }

    #[test]
    fn the_interactive_tagger_mode_defaults_to_save() {
        let mut args = InitArgs::default();
        let mut shown = Vec::new();
        ask_tagger(
            &mut args,
            &mut "endpoint\nhttp://127.0.0.1:9100\n0123456789abcdef\n3\n\n".as_bytes(),
            &mut shown,
        )
        .unwrap();
        assert_eq!(args.oneironer_mode, Some(OneironerMode::Save));
        let shown = String::from_utf8(shown).unwrap();
        assert!(shown.contains("save | shadow [save]"), "{shown}");
        let table = tagger_table(&args).unwrap();
        assert_eq!(
            table.get("mode").and_then(toml::Value::as_str),
            Some("save")
        );
    }

    #[test]
    fn a_non_interactive_endpoint_init_without_a_mode_writes_save() {
        let args = InitArgs {
            oneironer: Some(OneironerProvider::Endpoint),
            oneironer_url: Some("http://127.0.0.1:9100".into()),
            oneironer_checkpoint_sha16: Some("0123456789abcdef".into()),
            oneironer_label_count: Some(3),
            ..InitArgs::default()
        };
        let table = tagger_table(&args).unwrap();
        assert_eq!(
            table.get("mode").and_then(toml::Value::as_str),
            Some("save")
        );
        let none = tagger_table(&InitArgs::default()).unwrap();
        assert!(none.get("mode").is_none());
    }

    #[test]
    fn a_tagger_refusal_comes_before_the_local_embedder_setup() {
        let dir = tempfile::tempdir().unwrap();
        let args = InitArgs {
            path: dir.path().join("vault"),
            config: Some(dir.path().join("oneiron.toml")),
            embedder: Some(EmbedderProvider::Local),
            oneironer: Some(OneironerProvider::Local),
            map_size: 64 * 1024 * 1024,
            ..Default::default()
        };
        // CUDA is not built into this crate on any host: were the local
        // embedder prepared first, its device refusal would come back instead,
        // and with a device that resolved, its model download would start.
        let env = EnvConfig::from_pairs([("ONEIRON_EMBEDDER_DEVICE", "cuda")]).unwrap();
        let refused = init_with_env(args.clone(), env, None).unwrap_err();
        assert_eq!(
            refused.downcast_ref::<crate::oneironer::TaggerNotBuilt>(),
            Some(&crate::oneironer::TaggerNotBuilt::LocalProvider),
            "{refused}"
        );
        assert!(!args.path.exists());
        assert!(!dir.path().join("oneiron.toml").exists());
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
