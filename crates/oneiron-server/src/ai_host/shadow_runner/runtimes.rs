//! The checked-in QuickJS component's runtimes (FIX 1661, 2144, 3607): the
//! component is compiled and readiness-probed once, on its first use, and
//! each step gets a fresh runtime of it. A shadow arm's step and a
//! contribution fork's program run on it alike, under the SHA-256 the
//! reviewed manifest pins it to. A server built without the code sandbox has
//! none, and each caller says so.

use std::sync::Arc;

use oneiron::engine_executor::JsCodeModeRuntime;

use super::ShadowRuntimes;

/// The checked-in component, loaded at its first use.
#[derive(Default)]
pub(crate) struct CheckedInRuntimes {
    #[cfg(feature = "code-sandbox-wasmtime")]
    component: std::sync::OnceLock<Option<oneiron::code_sandbox::quickjs::QuickJsRuntimeFactory>>,
}

#[cfg(feature = "code-sandbox-wasmtime")]
impl CheckedInRuntimes {
    /// The component, compiled and probed at the first call; `None` when it
    /// did not load, which is logged once.
    fn factory(&self) -> Option<&oneiron::code_sandbox::quickjs::QuickJsRuntimeFactory> {
        self.component
            .get_or_init(|| match crate::mcp::checked_in_quickjs_runtime() {
                Ok(factory) => Some(factory),
                Err(error) => {
                    tracing::error!(%error, "the checked-in QuickJS component did not load");
                    None
                }
            })
            .as_ref()
    }

    /// The SHA-256 the reviewed manifest pins the component to, once it
    /// loaded.
    pub(crate) fn pin(&self) -> Option<[u8; 32]> {
        self.factory()
            .map(oneiron::code_sandbox::quickjs::QuickJsRuntimeFactory::sha256)
    }

    /// A fresh runtime of the component.
    pub(crate) fn runtime(&self) -> oneiron::Result<Box<dyn JsCodeModeRuntime + Send>> {
        let factory = self.factory().ok_or_else(|| {
            oneiron::Error::InvalidConfig(
                "the checked-in QuickJS component did not load".to_owned(),
            )
        })?;
        let runtime: Box<dyn JsCodeModeRuntime + Send> = Box::new(factory.runtime()?);
        Ok(runtime)
    }
}

#[cfg(not(feature = "code-sandbox-wasmtime"))]
impl CheckedInRuntimes {
    /// A server without the code sandbox pins no component.
    pub(crate) const fn pin(&self) -> Option<[u8; 32]> {
        None
    }

    /// A server without the code sandbox runs no program.
    pub(crate) fn runtime(&self) -> oneiron::Result<Box<dyn JsCodeModeRuntime + Send>> {
        Err(oneiron::Error::InvalidConfig(
            "this server has no code sandbox".to_owned(),
        ))
    }
}

/// Each shadow arm step's runtime: a fresh one of the checked-in component,
/// which is compiled once, on the first step's blocking worker.
pub(crate) fn checked_in_runtimes() -> ShadowRuntimes {
    let runtimes = Arc::new(CheckedInRuntimes::default());
    Arc::new(move || runtimes.runtime())
}
