//! Apply the owner's persisted Responses store switch to this host's providers.

use oneiron::consent::AuthenticatedOwner;

impl super::SyncServer {
    pub(crate) fn apply_responses_store(
        &self,
        owner: &AuthenticatedOwner,
        on: bool,
    ) -> oneiron::Result<()> {
        self.vault().set_responses_store(owner, on)?;
        // Only this server's providers read it, after its vault kept it.
        self.ai.models().responses_context().set_store(on);
        Ok(())
    }
}
