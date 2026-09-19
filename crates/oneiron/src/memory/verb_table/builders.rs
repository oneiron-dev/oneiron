//! Builder plans accumulate locally; run crosses one facade boundary.
use super::{
    CoreContextPackRequest, CoreContextPackResponse, CoreQueryRequest, CoreQueryResponse,
    FacadeClient, FacadeTransport, Memory, MemoryError, MemoryResult,
};
use crate::claim::ScopedReadActorKey;
use crate::code_run::vault_read::{
    ContextPackBudgetControls, ContextPackDepthControls, CountMode, InProcessVaultReadAdapter,
    VaultReadClient, VaultReadError, View,
};

impl Memory<'_> {
    fn read_adapter(&self) -> MemoryResult<InProcessVaultReadAdapter<'_>> {
        self.verified_actor_class()?;
        let class = match self.actor_class {
            crate::EdgeActorClass::Human => "human",
            crate::EdgeActorClass::Agent => "agent",
            crate::EdgeActorClass::System => "system",
        };
        let key = ScopedReadActorKey::with_actor_class(self.actor.to_hex(), class)
            .ok_or_else(|| MemoryError::bad_request("invalid actor binding"))?;
        Ok(InProcessVaultReadAdapter::new(self.vault, key))
    }
    /// Runs a typed query plan under this actor's read policy.
    pub fn query_plan(&self, request: &CoreQueryRequest) -> MemoryResult<CoreQueryResponse> {
        self.read_adapter()?
            .query(request.clone())
            .map_err(read_error)
    }
    /// Runs a typed context-pack plan under this actor's read policy.
    pub fn context_pack_plan(
        &self,
        request: &CoreContextPackRequest,
    ) -> MemoryResult<CoreContextPackResponse> {
        self.read_adapter()?
            .context_pack(request.clone())
            .map_err(read_error)
    }
}
fn read_error(error: VaultReadError) -> MemoryError {
    let code = match &error {
        VaultReadError::InvalidRequest { .. } => super::super::MEMORY_CODE_BAD_REQUEST,
        VaultReadError::Engine { engine_code, .. } => engine_code,
        _ => super::super::MEMORY_CODE_INTERNAL,
    };
    MemoryError::new(
        code,
        error.to_string(),
        &["Check the request and the actor's read scope."],
    )
}

/// Lazy query plan. No host work occurs before `run`.
pub struct QueryBuilder<'a, T> {
    client: FacadeClient<&'a T>,
    request: CoreQueryRequest,
}
impl<T: FacadeTransport> FacadeClient<T> {
    /// Starts a local query plan.
    pub fn query_builder(&self) -> QueryBuilder<'_, T> {
        QueryBuilder::new(&self.0)
    }
    /// Starts a local context-pack plan.
    pub fn context_pack_builder(&self) -> ContextPackBuilder<'_, T> {
        ContextPackBuilder::new(&self.0)
    }
}
impl<'a, T: FacadeTransport> QueryBuilder<'a, T> {
    /// Starts a plan over a host transport without making a call.
    pub fn new(transport: &'a T) -> Self {
        Self {
            client: FacadeClient(transport),
            request: CoreQueryRequest {
                query: None,
                query_vector: None,
                limit: 10,
                view: None,
                count_mode: CountMode::Estimate,
            },
        }
    }
    /// Sets the text seed locally.
    #[must_use]
    pub fn text(mut self, query: impl Into<String>) -> Self {
        self.request.query = Some(query.into());
        self
    }
    /// Sets the vector seed locally.
    #[must_use]
    pub fn vector(mut self, vector: Vec<f32>) -> Self {
        self.request.query_vector = Some(vector);
        self
    }
    /// Sets the result ceiling locally.
    #[must_use]
    pub fn limit(mut self, limit: usize) -> Self {
        self.request.limit = limit;
        self
    }
    /// Sets the response projection locally.
    #[must_use]
    pub fn view(mut self, view: View) -> Self {
        self.request.view = Some(view);
        self
    }
    /// Makes exactly one facade call with the completed plan.
    pub fn run(self) -> MemoryResult<CoreQueryResponse> {
        self.client.query(&self.request)
    }
}

/// Lazy context-pack plan. No host work occurs before `run`.
pub struct ContextPackBuilder<'a, T> {
    client: FacadeClient<&'a T>,
    request: CoreContextPackRequest,
}
impl<'a, T: FacadeTransport> ContextPackBuilder<'a, T> {
    /// Starts a plan over a host transport without making a call.
    pub fn new(transport: &'a T) -> Self {
        Self {
            client: FacadeClient(transport),
            request: CoreContextPackRequest {
                query: None,
                query_vector: None,
                limit: 10,
                depth: None,
                edge_hop: None,
                max_neighbors: None,
                budget: None,
            },
        }
    }
    /// Sets the text seed locally.
    #[must_use]
    pub fn text(mut self, query: impl Into<String>) -> Self {
        self.request.query = Some(query.into());
        self
    }
    /// Sets the vector seed locally.
    #[must_use]
    pub fn vector(mut self, vector: Vec<f32>) -> Self {
        self.request.query_vector = Some(vector);
        self
    }
    /// Sets the result ceiling locally.
    #[must_use]
    pub fn limit(mut self, limit: usize) -> Self {
        self.request.limit = limit;
        self
    }
    /// Sets edge expansion locally.
    #[must_use]
    pub fn depth(mut self, depth: ContextPackDepthControls) -> Self {
        self.request.depth = Some(depth);
        self
    }
    /// Sets token and retrieval budgets locally.
    #[must_use]
    pub fn budget(mut self, budget: ContextPackBudgetControls) -> Self {
        self.request.budget = Some(budget);
        self
    }
    /// Makes exactly one facade call with the completed plan.
    pub fn run(self) -> MemoryResult<CoreContextPackResponse> {
        self.client.context_pack(&self.request)
    }
}
