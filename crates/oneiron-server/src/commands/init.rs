//! First-run embedder and tagger choices, using the same config and providers as serve.
//! `init` asks the questions; [`setup_models`] is the shared non-terminal
//! operation that writes the config and opens the vault (ARCH-0036). A vault
//! init creates also asks, once, whether its conversations may be used for
//! training (FIX 5537).
use crate::cli::InitArgs;
use crate::config::{
    EmbedderDevice, EmbedderLocality, EmbedderProvider, EnvConfig, OneironerMode,
    OneironerProvider, ServeArgs, ServeConfig,
};
use anyhow::Context as _;
use oneiron::authority::{ActSurface, MachineRole};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

mod config_assembly;

#[cfg(test)]
use self::config_assembly::tagger_table;
use self::config_assembly::{config_text, endpoint_locality, local_tagger_config, stage_config};

const EMBEDDER_DOCS: &str = "https://oneiron.dev/oneiron/agents/oneiron-arch-0036-runtime-v1/";
/// The question init asks once, on a terminal, when it creates the vault: the
/// vault's conversation-learning setting, off unless the answer is yes.
const CONVERSATION_LEARNING_QUESTION: &str = "Use conversations in this vault for training? People, agents and guests count; private worlds never do. [y/N]: ";
/// What init says to a yes it cannot write: the setting is an act this
/// install carries, and a vault with no host root has no install profile yet.
const CONVERSATION_LEARNING_NEEDS_ROOT: &str = "conversation learning stays off: this vault has no signing root yet (no auth_secret or ONEIRON_AUTH_SECRET is configured). Once `oneiron serve` runs with one, turn it on with the conversation-learning setting (PUT /v1/owner/conversation-learning).";

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
    // Asked once: only when this init creates the vault, and only on a
    // terminal. Anything but a yes writes nothing, which reads as off.
    let vault_dir = env.vault_path().unwrap_or(args.path.as_path());
    let learning = !vault_dir.join("data.mdb").exists()
        && input.is_terminal()
        && ask_learning(&mut input, &mut output)?;
    let path = args
        .config
        .clone()
        .or_else(|| env.config_path.clone())
        .or(default_path)
        .ok_or_else(|| anyhow::anyhow!("no config location; pass --config"))?;
    // The questions are answered; the shared operation does the work.
    args.embedder = Some(choice);
    if args.maximum_tier {
        writeln!(output, "warning: {}", oneiron::PAGE_SEAL_WARNING)?;
    }
    let (vault, outcome) = setup_models(&args, &path, env.clone())?;
    if learning {
        turn_on_learning(&vault, &read_config(&path, env)?, &mut output)
            .context("conversation learning was not turned on; it stays off")?;
    }
    super::print_doctor_report(&vault)?;
    writeln!(output, "config: {}", outcome.config.display())?;
    if let Some(embedder) = &outcome.embedder {
        writeln!(
            output,
            "embedder: provider={} model_id={} dimensions={} device={}",
            embedder.provider, embedder.model_id, embedder.dimensions, embedder.device
        )?;
    }
    if let Some(tagger) = &outcome.tagger {
        write!(
            output,
            "tagger: provider={} mode={}",
            tagger.provider, tagger.mode
        )?;
        match &tagger.engine {
            Some(engine) => writeln!(output, " engine={} ({})", engine.id, engine.pick)?,
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
}

/// What first-run model setup configured: the config file it wrote, the
/// embedder and the active tagger as serve will run them.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ModelSetupOutcome {
    pub(crate) config: PathBuf,
    pub(crate) embedder: Option<EmbedderOutcome>,
    pub(crate) tagger: Option<TaggerOutcome>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct EmbedderOutcome {
    pub(crate) provider: &'static str,
    pub(crate) model_id: String,
    pub(crate) dimensions: usize,
    /// Where it runs: the local device, or the endpoint's locality.
    pub(crate) device: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct TaggerOutcome {
    pub(crate) provider: &'static str,
    pub(crate) mode: &'static str,
    /// The engine a local tagger serves on, and how it was picked.
    pub(crate) engine: Option<TaggerEngine>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct TaggerEngine {
    pub(crate) id: String,
    pub(crate) pick: &'static str,
}

/// First-run model setup (ARCH-0036): the one operation every first-run
/// door shares. `init` asks its questions on a terminal and hands the
/// answers here; a caller with no terminal states them directly. The answers
/// are init's typed flags (an embedder left unset is none). It writes the one
/// config serve reads (`[embedder]`, `[oneironer]`, the vault keys), after
/// validating exactly what serve will read, building the tagger and embedder
/// slots serve builds and preparing a local embedder's model; then it opens
/// the vault, creating it on a first run, and returns it with what it
/// configured. It reads no terminal and prints nothing.
pub(crate) fn setup_models(
    answers: &InitArgs,
    path: &Path,
    env: EnvConfig,
) -> anyhow::Result<(oneiron::Vault, ModelSetupOutcome)> {
    let choice = answers.embedder.unwrap_or(EmbedderProvider::None);
    let config_text = config_text(answers, choice, path)?;
    // Validate exactly what serve will read before downloading or creating a vault.
    let staged = stage_config(path, &config_text)?;
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
        let vault = open_vault(answers, &config)?;
        std::fs::rename(&staged, path)?;
        let outcome = ModelSetupOutcome {
            config: path.to_path_buf(),
            embedder: config.embedder.as_ref().map(|embedder| EmbedderOutcome {
                provider: embedder.provider.as_str(),
                model_id: embedder.model_id.clone(),
                dimensions: embedder.dimensions,
                device,
            }),
            tagger: config
                .oneironer
                .as_ref()
                .filter(|tagger| tagger.is_active())
                .map(|tagger| TaggerOutcome {
                    provider: tagger.provider.as_str(),
                    mode: tagger.mode.as_str(),
                    engine: tagger_slot
                        .as_ref()
                        .and_then(|slot| slot.serving())
                        .map(|serving| TaggerEngine {
                            id: serving.engine.id(),
                            pick: serving.pick.as_str(),
                        }),
                }),
        };
        Ok((vault, outcome))
    })();
    if staged.exists() {
        let _ = std::fs::remove_file(staged);
    }
    result
}

/// Opens the configured vault, creating it on a first run: sealed when the
/// config asks for the maximum tier (OF-570). A new sealed vault's key is
/// wrapped to this device's keystore and to the password `--secret-file`
/// names, and init fails unless its mirror then opens it. A page-seal mirror
/// whose vault's data is missing is refused, never adopted.
fn open_vault(answers: &InitArgs, config: &ServeConfig) -> anyhow::Result<oneiron::Vault> {
    super::owner::refuse_orphaned_page_seal(&config.vault_path)?;
    let fresh = !config.vault_path.join("data.mdb").exists();
    anyhow::ensure!(
        fresh || answers.secret_file.is_none(),
        "--secret-file sets a new sealed vault's password; `oneiron vault-key set-password` \
         changes it"
    );
    let password = answers
        .secret_file
        .as_deref()
        .map(|file| super::owner::read_secret_file(file, "the vault password"))
        .transpose()?
        .map(super::owner::HostUnlock::Password);
    let mut vault_config = config.vault_config();
    if vault_config.page_seal.is_none() {
        vault_config.page_seal = super::owner::prepare_page_seal(config, password.as_ref())?;
    }
    let vault = oneiron::Vault::open_owned(&config.vault_path, vault_config)?;
    if vault.vault_pages_sealed() {
        config
            .keystore
            .install_on_boot(&vault, &config.vault_path)?;
        if let Some(super::owner::HostUnlock::Password(password)) = &password {
            vault.set_vault_key_password(password, None)?;
        }
        super::owner::ensure_page_seal_wrapped(&vault, &config.vault_path)?;
    }
    // This install's own machine profile (FIX 4648), only on a vault the
    // configured host root already roots: a new vault's first serving start
    // roots it and profiles this install then. Init never mints a root.
    if let Some(issuer) = super::owner::configured_host_issuer(config, &vault)
        && vault
            .authority_fold()
            .is_ok_and(|fold| fold.vault_id.is_some())
    {
        if !vault.vault_pages_sealed() {
            config.keystore.install_on(&vault, &config.vault_path);
        }
        vault.ensure_serving_install_profile_at_start(Some(&issuer), "init");
    }
    Ok(vault)
}

/// The conversation-learning question: only `y` or `yes` turns it on; Enter,
/// `n` and `no` leave it off.
fn ask_learning(input: &mut impl BufRead, output: &mut impl Write) -> anyhow::Result<bool> {
    let answer = ask_line(input, output, CONVERSATION_LEARNING_QUESTION)?;
    match answer.to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(true),
        "" | "n" | "no" => Ok(false),
        _ => anyhow::bail!("answer y or n"),
    }
}

/// Turns the new vault's conversation learning on, the admin having said yes
/// (FIX 5537), through the setting's own writer, as the vault's embedded
/// owner on this install. The configured host root first roots the vault
/// and profiles this install, as serve's first start would: it signs the
/// enrolment, never the setting. With no host root configured, nothing is
/// written and learning stays off.
fn turn_on_learning(
    vault: &oneiron::Vault,
    config: &ServeConfig,
    output: &mut impl Write,
) -> anyhow::Result<()> {
    let Some(issuer) = super::owner::configured_host_issuer(config, vault) else {
        writeln!(output, "{CONVERSATION_LEARNING_NEEDS_ROOT}")?;
        return Ok(());
    };
    vault.ensure_host_root_slip(&issuer)?;
    if !vault.vault_pages_sealed() {
        config.keystore.install_on(vault, &config.vault_path);
    }
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let owner = crate::owner::local_owner(vault)?;
    let seen = vault.conversation_learning_view(&owner)?.revision;
    vault.set_conversation_learning(&owner, ActSurface::ThisInstall, true, false, Some(seen))?;
    writeln!(output, "conversation learning: on")?;
    Ok(())
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
    let survey = crate::oneironer::engines::survey(&config, None)?;
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
