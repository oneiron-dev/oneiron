//! First-run embedder choice, using the same config and provider as serve.
use crate::cli::InitArgs;
use crate::config::{EmbedderConfig, EmbedderProvider, EnvConfig, ServeArgs, ServeConfig};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

const EMBEDDER_DOCS: &str = "https://oneiron.dev/oneiron/agents/oneiron-arch-0036-runtime-v1/";

pub fn init(mut args: InitArgs) -> anyhow::Result<()> {
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
    let path = args
        .config
        .clone()
        .or_else(crate::config::default_config_path)
        .ok_or_else(|| anyhow::anyhow!("no config location; pass --config"))?;
    let config_text = config_text(&args, choice, &path)?;
    // Validate exactly what serve will read before downloading or creating a vault.
    let staged = stage_config(&path, &config_text)?;
    let result = (|| {
        let config = read_config(&staged)?;
        let device = match config.embedder.as_ref().filter(|c| c.is_active()) {
            Some(embedder) if choice == EmbedderProvider::Local => {
                crate::embedder::prepare_local(embedder)?.to_owned()
            }
            Some(embedder) => {
                crate::embedder::build_slot(Some(embedder))?;
                "on-device endpoint".to_owned()
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

fn config_text(args: &InitArgs, choice: EmbedderProvider, path: &Path) -> anyhow::Result<String> {
    let mut table: toml::Table = match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => toml::Table::new(),
        Err(error) => return Err(error.into()),
    };
    if choice != EmbedderProvider::Endpoint
        && (args.embedder_endpoint.is_some() || args.embedder_api_key_env.is_some())
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
        embedder.insert("endpoint".into(), endpoint.clone().into());
        embedder.insert(
            "model_key".into(),
            args.embedder_model_key
                .clone()
                .unwrap_or(defaults.local.repo)
                .into(),
        );
        if let Some(name) = &args.embedder_api_key_env {
            embedder.insert("api_key_env".into(), name.clone().into());
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

fn read_config(path: &Path) -> anyhow::Result<ServeConfig> {
    crate::config::resolve_serve_config_with_sources(
        &ServeArgs {
            config: Some(path.to_path_buf()),
            ..Default::default()
        },
        EnvConfig::default(),
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
        init(args).unwrap();
        let config = read_config(&path).unwrap();
        assert_eq!(config.port, 12345);
        assert!(!config.embedder.unwrap().is_active());
    }
}
