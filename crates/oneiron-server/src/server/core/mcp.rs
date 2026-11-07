//! The server's MCP code host: the builder that binds it and the
//! accessors the gateway reads it through.
use std::sync::Arc;

use super::SyncServer;

impl SyncServer {
    /// Bind a readiness-verified QuickJS provider before exposing this vault's
    /// routes, running at most `runs` at once. Missing components or providers
    /// keep execute_code unadvertised.
    #[cfg(feature = "code-sandbox-wasmtime")]
    #[must_use]
    pub fn with_mcp_quickjs_provider(
        mut self,
        provider: crate::mcp::McpQuickJsProvider,
        runs: crate::mcp::CodeRunLimits,
    ) -> Self {
        let provider = provider.with_run_receipts(self.run_receipts());
        let host: Arc<dyn crate::mcp::McpCodeExecutionHost> = Arc::new(
            crate::mcp::McpEngineNativeCodeHost::new(
                Arc::new(provider),
                runs,
                Arc::clone(self.wire_telemetry.limit_questions()),
            )
            .with_reader_seats(self.reader_runner.seats())
            .with_git_door_base(self.config.git_door_base.clone()),
        );
        // Reader children run on the same provider and pool.
        self.reader_runner.bind_host(Arc::clone(&host));
        self.mcp_code_host = Some(host);
        self
    }

    pub(crate) fn code_execution_host(&self) -> Option<&Arc<dyn crate::mcp::McpCodeExecutionHost>> {
        self.mcp_code_host
            .as_ref()
            .filter(|host| host.production_runtime_available())
    }

    /// The surface `mode` registers on this server, or the verb row that
    /// keeps it from registering: callers answer that as a typed error.
    pub(crate) fn mcp_surface(
        &self,
        mode: crate::mcp::McpSurfaceMode,
    ) -> Result<crate::mcp::McpRegisteredSurface, crate::mcp::McpSurfaceConstructionError> {
        crate::mcp::McpRegisteredSurface::register_with_execution(
            mode,
            self.code_execution_host().is_some(),
        )
    }
}
