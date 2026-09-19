//! Gemini wire adapter. Vendors and prices are registry data; retries and budget stay above LlmBackend.
mod transport;
mod wire;
mod stream;
pub use transport::*;
pub use wire::{build_request,parse_response,classify_status};
pub use stream::GeminiAccumulator;
use std::collections::BTreeMap;
use oneiron::{LlmBackend,LlmGenerateFuture,LlmStreamResult,LlmRequest,BudgetLease,ModelId,LlmCatalogEntry,LlmCapability,FatalLlmError,LlmStream};
pub struct GeminiBackend<T> { transport:T, models:BTreeMap<ModelId,LlmCatalogEntry> }
impl<T:GeminiTransport> GeminiBackend<T> {
    pub fn from_registry(vault:&oneiron::Vault,transport:T)->oneiron::Result<Self>{Ok(Self {transport,models:vault.model_catalog_entries(oneiron::llm::registry::ModelWireFormat::Gemini)?.into_iter().map(|e|(e.model.clone(),e)).collect()})}
}
impl<T:GeminiTransport> LlmBackend for GeminiBackend<T> {
    fn supports(&self,model:&ModelId,capability:LlmCapability)->bool{self.models.get(model).is_some_and(|e|e.supports(&capability))}
    fn generate<'a>(&'a self,request:LlmRequest,lease:&'a BudgetLease)->LlmGenerateFuture<'a>{Box::pin(async move {
        let entry=self.models.get(&request.model).ok_or(FatalLlmError::InvalidRequest)?;
        let response=self.transport.execute(build_request(entry,&request,false)?,lease).await?;
        if !(200..300).contains(&response.status){return Err(classify_status(response.status,&response.body));}
        parse_response(response.body)
    })}
    fn stream<'a>(&'a self,request:LlmRequest,lease:&'a BudgetLease)->LlmStreamResult<'a>{let entry=self.models.get(&request.model).ok_or(FatalLlmError::InvalidRequest)?;let source=self.transport.stream(build_request(entry,&request,true)?,lease)?;Ok(LlmStream::new(stream::GeminiEventStream::new(source)))}
}
#[cfg(test)]
mod tests;
