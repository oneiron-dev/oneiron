//! A mirror's Git-LFS objects (FIX 919): after its refs went out, every
//! object the pushed history's pointers name goes to the mirror's own LFS
//! endpoint from this vault's store, under the mirror's push credential,
//! so a mirror clone holds the bytes, not pointers alone.
use std::collections::BTreeSet;

use super::types::OriginPublishDestination;
use crate::Vault;
use crate::error::{Error, Result};
use crate::origin::lfs::{LfsBatchRemote, LfsOid};
use crate::origin::mirror::OriginMirrorTarget;

impl Vault {
    /// Sends each of `objects` the mirror `target` does not hold yet, and
    /// answers the ones it is still not known to hold.
    ///
    /// # Errors
    /// A mirror URL the batch API cannot take, a credential the custody
    /// door does not release, or a batch call that fails.
    pub(crate) fn push_mirror_lfs_objects(
        &self,
        target: &OriginMirrorTarget,
        objects: &[(LfsOid, u64)],
    ) -> Result<BTreeSet<LfsOid>> {
        let remote = LfsBatchRemote::of(&target.url)?;
        let destination = OriginPublishDestination {
            url: target.url.clone(),
            user: target.user.clone(),
            secret_ref: target.secret_ref.clone(),
            target_generation: target.target_generation,
            audience: target.audience,
        };
        let mut answer = Err(Error::InvariantViolation("mirror LFS push never ran"));
        self.with_publish_credential(&destination, &mut |header| {
            answer = remote.upload(self, header, objects);
        })?;
        answer
    }
}
