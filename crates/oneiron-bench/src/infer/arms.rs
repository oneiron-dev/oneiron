//! The two production paths a call takes, each an `LlmBackend` the
//! measurement loop drives the same way.
//!
//! * direct: `ModelsConfig` → `ModelRuntime::build` → `router().served(id)`
//!   → `RunBackend` under an undeclared run, which is how the server's own
//!   engine code (the Dreamer's step layer) reaches a configured model.
//! * own-server: a loopback `oneiron-server` given the same `[models]`
//!   block, reached through `RemoteLlmClient` and `OwnServerBackend`, as one
//!   of the owner's other machines reaches it. Its times include the extra
//!   SDK and server hop.

use std::io::Write as _;
use std::path::Path;

use oneiron::llm::run_admission::RunAdmission;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, LlmBackend, LlmCapability, ModelId, ModelLocality,
};
use oneiron_llm_own_server::{OwnServerBackend, RemoteLlmClient};
use oneiron_server::models::{ModelRuntime, RunBackend};

use super::config::Models;
use super::engine::Reaper;
use crate::load::server::{Embedding, Running, Vault, free_port};

/// The run meter's limit: far past any bench run, so no case is refused
/// for spend while each call still reserves and settles on it.
pub(super) const RUN_UNITS: u64 = 1_000_000_000_000;

pub(super) struct Arm {
    pub(super) backend: Box<dyn LlmBackend>,
    pub(super) model: ModelId,
    pub(super) locality: ModelLocality,
    /// Whether the served catalog row takes a reasoning level.
    pub(super) reasoning: bool,
    /// The runtime whose ladder the direct backend calls through.
    _runtime: ModelRuntime,
    server: Option<Running>,
}

impl Arm {
    /// Stops the loopback server, if this arm started one; says how it
    /// exited.
    pub(super) fn finish(self, reaper: &Reaper) -> Option<String> {
        let server = self.server?;
        reaper.forget(server.pid);
        Some(server.stop())
    }
}

/// The models runtime for `models`, built the way `serve` builds it, after
/// checking that the named provider came up.
fn models_runtime(models: &Models, rt: &tokio::runtime::Runtime) -> Result<ModelRuntime, String> {
    let runtime = {
        let _entered = rt.enter();
        ModelRuntime::build(Some(&models.config))
    };
    let provider = &models.model.provider;
    let status = runtime
        .status()
        .providers
        .iter()
        .find(|status| status.name == *provider)
        .ok_or_else(|| format!("the models config built no provider `{provider}`"))?;
    if status.state != "ready" {
        return Err(format!(
            "provider `{provider}` is {}: {}",
            status.state,
            status.reason.as_deref().unwrap_or("no reason given")
        ));
    }
    Ok(runtime)
}

pub(super) fn direct(models: &Models, rt: &tokio::runtime::Runtime) -> Result<Arm, String> {
    let runtime = models_runtime(models, rt)?;
    let (locality, ladder) = runtime
        .router()
        .and_then(|router| router.served(&models.engine_id))
        .ok_or_else(|| format!("no configured route serves {}", models.engine_id))?;
    let meter = BudgetGuard::new("infer-bench", RUN_UNITS, BudgetExhaustionPolicy::Suspend);
    let run: RunAdmission = runtime.undeclared_run("infer-bench", meter);
    let backend = RunBackend::new(ladder, run);
    let reasoning = backend.supports(&models.engine_id, LlmCapability::Reasoning);
    Ok(Arm {
        backend: Box::new(backend),
        model: models.engine_id.clone(),
        locality,
        reasoning,
        _runtime: runtime,
        server: None,
    })
}

/// Appends the `[models]` section to the vault's config file, the one
/// `serve` reads.
fn add_models(config: &Path, section: &str) -> Result<(), String> {
    std::fs::OpenOptions::new()
        .append(true)
        .open(config)
        .and_then(|mut file| file.write_all(section.as_bytes()))
        .map_err(|e| format!("write [models] into {}: {e}", config.display()))
}

pub(super) fn own_server(
    models: &Models,
    server_bin: &Path,
    work: &Path,
    rt: &tokio::runtime::Runtime,
    reaper: &Reaper,
) -> Result<Arm, String> {
    // The same config built here gives the catalog row the server serves
    // the model under, so the client admits what the server will.
    let runtime = models_runtime(models, rt)?;
    let entry = runtime
        .router()
        .and_then(|router| {
            router
                .chat_catalog()
                .find(|entry| entry.model == models.engine_id)
                .cloned()
        })
        .ok_or_else(|| format!("no configured catalog row for {}", models.engine_id))?;
    let reasoning = entry.supports(&LlmCapability::Reasoning);
    let locality = entry.locality;
    let vault = Vault::init(server_bin, work, &Embedding::None, &[])?;
    add_models(&vault.config, &models.server_section())?;
    let port = free_port()?;
    let origin = format!("http://127.0.0.1:{port}");
    let link = vault.bootstrap_owner(server_bin, &origin)?;
    let server = Running::start_on(server_bin, &vault, &[], "serve.log", "info", port)?;
    reaper.keep(server.pid);
    let client = oneiron_remote::OneironClient::pair(&link)
        .map_err(|e| format!("redeem the owner pairing link: {e}"))
        .and_then(|(_, credential, _)| {
            RemoteLlmClient::connect(&server.base, &credential)
                .map_err(|e| format!("connect to the loopback server: {e}"))
        });
    let client = match client {
        Ok(client) => client,
        Err(error) => {
            // Dropping the server below kills it.
            reaper.forget(server.pid);
            return Err(error);
        }
    };
    Ok(Arm {
        backend: Box::new(OwnServerBackend::serving(client, [entry])),
        model: models.engine_id.clone(),
        locality,
        reasoning,
        _runtime: runtime,
        server: Some(server),
    })
}

/// The same catalog and OpenAI request codec, sent once over the native wire.
pub(super) fn native(
    models: &Models,
    socket: &Path,
    rt: &tokio::runtime::Runtime,
) -> Result<Arm, String> {
    let runtime = models_runtime(models, rt)?;
    let entry = runtime
        .router()
        .and_then(|router| {
            router
                .chat_catalog()
                .find(|entry| entry.model == models.engine_id)
                .cloned()
        })
        .ok_or("no configured native catalog row")?;
    let reasoning = entry.supports(&LlmCapability::Reasoning);
    let locality = entry.locality;
    let provider = &models.config.providers[&models.model.provider];
    let transport = rt.block_on(super::native::Transport::connect(socket, provider))?;
    let config =
        oneiron_llm_openai::OpenAiCompatConfig::from_catalog([entry]).with_solo_admission(true);
    Ok(Arm {
        backend: Box::new(oneiron_llm_openai::OpenAiCompatBackend::new(
            config, transport,
        )),
        model: models.engine_id.clone(),
        locality,
        reasoning,
        _runtime: runtime,
        server: None,
    })
}
