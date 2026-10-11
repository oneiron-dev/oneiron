//! A declared run on this server's models (ARCH-0053 `#run-declaration`):
//! the host that states a run's teachers, connectors and budget starts one,
//! and every teacher call goes through its admission and the gate.
use std::sync::Arc;

use oneiron::llm::run_admission::{RunAdmission, RunDenied, UNRESOLVED_SELECTOR};
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
    /// A selector the run cannot resolve, or a model this server does not
    /// serve, is refused before admission, with its `Denied` row. The row
    /// for an unresolved selector keeps none of its bytes: a caller may pass
    /// any text there.
    pub async fn generate(
        &self,
        selector: &str,
        mut request: LlmRequest,
    ) -> LlmResult<LlmResponse> {
        let model = self
            .admission
            .resolve(selector)
            .map_err(|denied| self.admission.refuse(None, UNRESOLVED_SELECTOR, denied))?;
        let Some((locality, ladder)) = self
            .router
            .as_ref()
            .and_then(|router| router.served(&model))
        else {
            let subject = model.as_str().to_owned();
            self.admission
                .refuse(Some(selector), &subject, RunDenied::NoOffer { model });
            return Err(FatalLlmError::InvalidRequest.into());
        };
        request.model = model;
        request.envelope.locality = locality;
        ladder
            .generate(&self.admission, request, Some(selector))
            .await
    }
}
