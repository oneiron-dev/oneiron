//! One hosted read, retained on its native worker while the async owner yields.
use std::sync::Arc;

use super::{ArtifactServedFile, ArtifactSnapshotSelector};
use crate::batch::secret_scan::{ContainerReader, read_cooperatively};
use crate::error::Result;
use crate::{EntityId, Vault};

impl Vault {
    /// Resolve the same authorized file as the synchronous door, off the async
    /// executor. Inline, file-backed and retained repository masks cooperate
    /// at native checkpoints on the same worker and read transaction.
    /// The owner receives one final answer, never partial bytes or a poll URL.
    /// There is no wall timeout or new content refusal. Dropping this future
    /// cancels at the next checkpoint; an opaque codec unit is not preempted.
    pub async fn resolve_authorized_artifact_file_cooperative(
        self: &Arc<Self>,
        artifact: &str,
        selector: ArtifactSnapshotSelector,
        path: &str,
        token: Option<&str>,
        principal: Option<EntityId>,
    ) -> Result<Option<ArtifactServedFile>> {
        let vault = Arc::clone(self);
        let artifact = artifact.to_owned();
        let path = path.to_owned();
        let token = token.map(str::to_owned);
        read_cooperatively(move |pacing| {
            vault.resolve_authorized_artifact_file_with_reader(
                &artifact,
                selector,
                &path,
                token.as_deref(),
                principal,
                &ContainerReader { pacing },
            )
        })
        .await?
    }
}
