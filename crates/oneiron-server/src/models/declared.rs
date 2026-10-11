//! A declared run on this server's models (ARCH-0053 `#run-declaration`):
//! the host that states a run's teachers, connectors and budget starts one,
//! and every teacher call goes through its admission and the gate.
use std::sync::Arc;

use oneiron::llm::run_admission::RunAdmission;
use oneiron::{FatalLlmError, LlmRequest, LlmResponse, LlmResult};

use super::ModelRouter;

pub struct DeclaredRun {
    admission: RunAdmission,
    router: Option<Arc<ModelRouter>>,
}

impl DeclaredRun {
    pub(super) fn new(admission: RunAdmission, router: Option<Arc<ModelRouter>>) -> Self {
        Self { admission, router }
    }

    /// The run's admission: its declaration, line, receipts and report.
    #[must_use]
    pub fn admission(&self) -> &RunAdmission {
        &self.admission
    }

    /// One teacher call. `selector` names a teacher by its id, or by an alias
    /// the run froze at its start. The call goes out as that model, rung by
    /// rung when it is a seat, each rung admitted against the declaration.
    /// A model this server does not serve is refused before admission.
    pub async fn generate(
        &self,
        selector: &str,
        mut request: LlmRequest,
    ) -> LlmResult<LlmResponse> {
        let model = self.admission.resolve(selector)?;
        let (locality, ladder) = self
            .router
            .as_ref()
            .and_then(|router| router.served(&model))
            .ok_or(FatalLlmError::InvalidRequest)?;
        request.model = model;
        request.envelope.locality = locality;
        ladder
            .generate(&self.admission, request, Some(selector))
            .await
    }
}
