//! A mirror's Git-LFS objects (FIX 919): after its refs went out, every
//! object the pushed history's pointers name goes to the mirror's own LFS
//! endpoint from this vault's store, under the mirror's push credential,
//! so a mirror clone holds the bytes, not pointers alone.
//!
//! On a served host the upload goes only through the host's transport
//! (`git_transport`, FIX 19876): its credential broker sends each batch call
//! and object action, the mirror's credential installed by the broker
//! alone, and the mirror is judged again before each exchange; a broker
//! that fails leaves the objects missing and never falls back. On a vault
//! opened with no host the daemon's own LFS client sends them, the custody
//! door handing it the mirror's credential. Either way the orchestration
//! (`lfs::upload_lfs_objects`) keeps the batches, their order and every
//! store check, and the run records which route the objects took.
use std::collections::BTreeSet;

use super::types::OriginPublishDestination;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::lfs::{DirectLfsRemote, LfsOid, upload_lfs_objects};
use crate::origin::mirror::{OriginMirrorLfsRoute, OriginMirrorLfsTransfer, OriginMirrorTarget};

impl Vault {
    /// Sends each of `objects` the mirror `target` of the repository
    /// `repo_id` does not hold yet, and answers the ones it is still not
    /// known to hold, with how they went out.
    ///
    /// The answer's error is a mirror URL the batch API cannot take, a
    /// credential the custody door does not release, or a batch call that
    /// fails.
    pub(crate) fn push_mirror_lfs_objects(
        &self,
        repo_id: EntityId,
        target: &OriginMirrorTarget,
        objects: &[(LfsOid, u64)],
    ) -> (Result<BTreeSet<LfsOid>>, OriginMirrorLfsTransfer) {
        let destination = OriginPublishDestination {
            url: target.url.clone(),
            user: target.user.clone(),
            secret_ref: target.secret_ref.clone(),
            target_generation: target.target_generation,
            audience: target.audience,
        };
        if let Some(transport) = self.served_origin_git_transport() {
            let report = transport.push_lfs_objects(repo_id, &destination, objects);
            let transfer = OriginMirrorLfsTransfer {
                route: OriginMirrorLfsRoute::Broker,
                broker_isolation: report.broker_isolation,
                credential_rewrites: report.credential_rewrites,
            };
            return (report.missing, transfer);
        }
        let transfer = OriginMirrorLfsTransfer {
            route: OriginMirrorLfsRoute::Daemon,
            broker_isolation: None,
            credential_rewrites: 0,
        };
        (
            self.push_mirror_lfs_objects_direct(&destination, objects),
            transfer,
        )
    }

    /// The upload through the daemon's own LFS client, under the
    /// `Authorization` value the custody door releases for `destination`.
    fn push_mirror_lfs_objects_direct(
        &self,
        destination: &OriginPublishDestination,
        objects: &[(LfsOid, u64)],
    ) -> Result<BTreeSet<LfsOid>> {
        let remote = DirectLfsRemote::of(&destination.url)?;
        let mut answer = Err(Error::InvariantViolation("mirror LFS push never ran"));
        self.with_publish_credential(destination, &mut |header| {
            answer = upload_lfs_objects(self, &remote.transport(Some(header)), objects);
        })?;
        answer
    }
}
