//! The voice host as a wake-pass attachment: it serves the owner's admitted
//! stream beside one pass and spends that pass's meter.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use oneiron::llm::{BudgetGuard, LlmBackend};
use oneiron_driver::{
    AttachedPassFuture, LinkedShutdown, PassAttachment, PassAttachmentSource, WakePassFuture,
};

use super::{VoiceHost, VoiceHostBindings, VoiceHostConfig, VoiceServeConnection};
use crate::managed::ManagedShutdown;

impl VoiceHostConfig {
    /// Builds the host over the supervisor's vault, its backend allocation
    /// and the pass meter. No provider, listener or budget is created here.
    pub fn host_for_pass(
        &self,
        vault: &oneiron::Vault,
        backend: &Arc<dyn LlmBackend>,
        guard: &BudgetGuard,
    ) -> oneiron::Result<VoiceHost> {
        if !std::ptr::eq(vault, self.vault.as_ref()) {
            return Err(oneiron::Error::InvalidConfig(
                "voice attachment must use the supervisor vault".into(),
            ));
        }
        VoiceHost::new(
            Arc::clone(&self.vault),
            &self.runtime,
            VoiceHostBindings {
                backend: Arc::clone(backend),
                budget: guard.clone(),
                extraction_prompt: self.extraction_prompt.clone(),
                session: self.session.clone(),
                shutdown: self.shutdown.clone(),
            },
        )
        .map_err(|error| {
            oneiron::Error::InvalidConfig(format!("voice attachment refused: {error}"))
        })
    }
}

impl PassAttachmentSource for VoiceHostConfig {
    /// Only an owner-supplied connection attaches. Extraction-only config
    /// builds no host during a pass, and a claimed connection is never reused.
    fn attach(
        &self,
        vault: &oneiron::Vault,
        backend: &Arc<dyn LlmBackend>,
        guard: &BudgetGuard,
    ) -> oneiron::Result<Option<Box<dyn PassAttachment>>> {
        let Some(bindings) = &self.serve_bindings else {
            return Ok(None);
        };
        let Some(connection) = bindings.take().map_err(|error| {
            oneiron::Error::InvalidConfig(format!("voice serve bindings refused: {error}"))
        })?
        else {
            return Ok(None);
        };
        let host = self.host_for_pass(vault, backend, guard)?;
        Ok(Some(Box::new(VoicePass { host, connection })))
    }

    fn linked_shutdown(&self) -> Option<Arc<dyn LinkedShutdown>> {
        Some(Arc::new(self.shutdown.clone()))
    }
}

struct VoicePass {
    host: VoiceHost,
    connection: VoiceServeConnection,
}

impl PassAttachment for VoicePass {
    fn serve<'p>(self: Box<Self>, pass: WakePassFuture<'p>) -> AttachedPassFuture<'p> {
        let Self { host, connection } = *self;
        Box::pin(async move {
            let (result, served) = connection.serve_for_pass(host, pass).await;
            (result, served.map_err(|error| error.to_string()))
        })
    }
}

impl LinkedShutdown for ManagedShutdown {
    fn trigger(&self) {
        ManagedShutdown::trigger(self);
    }

    fn is_triggered(&self) -> bool {
        ManagedShutdown::is_triggered(self)
    }

    fn triggered(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        ManagedShutdown::triggered(self)
    }
}
