//! The backend of a run whose input is the caller's code (FIX EXECUTE-CALLER-CODE).
//!
//! A caller-source run never calls the model: every model call is refused. The source entry
//! resolves no backend, so in a correct run none of these methods is reached; a call that does
//! reach one is refused rather than sent.

use crate::{
    BudgetLease, EntityId, FatalLlmError, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture,
    LlmRequest, LlmStreamResult, ModelId,
};

/// The backend of a run whose input is the caller's code (FIX EXECUTE-CALLER-CODE): every model
/// call is refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoModelBackend;

impl NoModelBackend {
    fn refused() -> LlmError {
        LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
            message: "a caller-source run makes no model calls".to_owned(),
            code: None,
        })
    }
}

impl LlmBackend for NoModelBackend {
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        false
    }

    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(std::future::ready(Err(Self::refused())))
    }

    fn generate_sourced<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
        _sources: Option<Vec<EntityId>>,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(std::future::ready(Err(Self::refused())))
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(Self::refused())
    }
}
