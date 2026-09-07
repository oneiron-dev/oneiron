//! Pipeline construction bound to a host execution capability.

use crate::Vault;
use crate::error::{Error, Result};

use super::builder::PipelineBuilder;

impl<'a> PipelineBuilder<'a> {
    pub(crate) fn for_execution(
        vault: &'a Vault,
        execution: &crate::code_run::HostSelfDispatcher<'_>,
    ) -> Result<Self> {
        if !std::ptr::eq(execution.store_identity(), &vault.store) {
            return Err(Error::InvalidConfig(
                "query execution capability belongs to a different vault".to_owned(),
            ));
        }
        // A canonical pipeline cannot stand in for a session's composed read
        // view or its route validation. Do not shed that boundary here.
        if execution.session_ref().is_some() {
            return Err(Error::InvalidConfig(
                "query execution capability requires a canonical run".to_owned(),
            ));
        }
        let mut query = Self::new(vault);
        query.execution_actor = Some(execution.actor());
        Ok(query)
    }
}
