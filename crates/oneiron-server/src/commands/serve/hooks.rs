//! The vault's one hook sandbox and the fact-hook runner that runs on it,
//! for plain and managed serve.

use std::sync::Arc;

use crate::server::SyncServer;

/// The vault's one hook sandbox, kept on `server`, so verb hooks, the
/// fact-hook runner and an explicit replay (`vault.hooks.replay`, a pack's
/// hook qualification) run on the same one. Taking it starts no runner:
/// `--no-hooks` stops only the automatic fact-hook runner, and an explicit
/// replay takes the sandbox here all the same (FIX 1122). Building it
/// compiles and probes the component, once per process, so a caller on the
/// async runtime calls this off it.
///
/// # Errors
/// Why the sandbox did not build, or that this build has none.
pub(crate) fn hook_sandbox(
    server: &SyncServer,
) -> Result<Arc<dyn oneiron::runtime_hooks::HookBodyRuntime>, String> {
    if let Some(runtime) = server.hook_runtime.get() {
        return Ok(Arc::clone(runtime));
    }
    let runtime = server.vault().hook_runtime()?;
    Ok(Arc::clone(server.hook_runtime.get_or_init(|| runtime)))
}

/// Takes the vault's one hook sandbox off the runtime ([`hook_sandbox`]) and
/// starts the fact-hook runner on it, each pass under `admit`. A sandbox
/// that fails to load starts no runner. Managed serve starts it too.
#[cfg(feature = "code-sandbox-wasmtime")]
pub(crate) async fn spawn_fact_hooks(
    server: &Arc<SyncServer>,
    admit: crate::server::HousekeepingAdmission,
    stop: tokio::sync::watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    use oneiron::runtime_hooks::FactHookRunner;
    let held = Arc::clone(server);
    let built = crate::logging::off_runtime("hook sandbox", move || hook_sandbox(&held))
        .await
        .and_then(|built| built.map_err(anyhow::Error::msg));
    match built {
        Ok(runtime) => {
            // A credential caller's settled verb-hook ask runs again through
            // the door it came in by, checked before the runner's first pass.
            server.vault().install_verb_ask_credential_check(Arc::new(
                crate::credential_resume::ServerVerbAskCredentialCheck::new(
                    server,
                    tokio::runtime::Handle::current(),
                ),
            ));
            // Generative fact hooks ask `ai.verdict` on serve's own ladder.
            let verdict: Arc<dyn oneiron::runtime_hooks::HookVerdict> =
                Arc::new(crate::hook_verdict::ServerHookVerdict::new(server));
            Some(FactHookRunner::spawn(
                Arc::clone(server.vault()),
                runtime,
                Some(verdict),
                admit,
                stop,
            ))
        }
        Err(error) => {
            tracing::warn!(%error, "hook sandbox did not load; fact hooks are off");
            None
        }
    }
}

/// Runs [`spawn_fact_hooks`] on a task of its own, so serve's gated startup
/// never waits while the sandbox compiles and probes the component
/// (FIX 25667). Nothing the gate holds needs the runner first: a bound verb
/// hook, a replay, a pack's qualification and a hook regeneration each take
/// the same sandbox through the vault's get-or-initialize step on a blocking
/// thread, so a call that comes during the build waits for that build; the
/// connector settler has already installed the verb-ask credential check;
/// and the runner catches up from every cursor at its first pass. Aborting
/// the returned task aborts the runner with it, as serve's shutdown aborts
/// each worker.
#[cfg(feature = "code-sandbox-wasmtime")]
pub(crate) fn spawn_fact_hooks_in_background(
    server: Arc<SyncServer>,
    admit: crate::server::HousekeepingAdmission,
    stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let began = std::time::Instant::now();
        let Some(runner) = spawn_fact_hooks(&server, admit, stop).await else {
            return;
        };
        tracing::info!(
            build_ms = %began.elapsed().as_millis(),
            "fact hooks started; their sandbox built off the gated startup"
        );
        let mut runner = AbortOnDrop(runner);
        let _ = (&mut runner.0).await;
    })
}

/// A task handle that aborts its task when dropped.
#[cfg(feature = "code-sandbox-wasmtime")]
struct AbortOnDrop(tokio::task::JoinHandle<()>);

#[cfg(feature = "code-sandbox-wasmtime")]
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
