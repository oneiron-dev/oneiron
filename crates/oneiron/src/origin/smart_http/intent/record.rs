//! The receive-pack intent's recorder: the one write that journals an
//! admitted push while pre-receive still blocks every ref effect. A push
//! admitted with its keys marked (FIX 7608) writes those marks in the same
//! transaction, so marks and intent commit together or not at all.

use std::path::Path;

use super::super::door::DoorAdmissionStamp;
use super::super::door_window::{DoorWindowReport, held_by_ref, unlandable_ref_reasons};
use super::super::evidence::{
    RECEIVE_PACK_ADMISSION_PREDICATE, receive_pack_field, receive_pack_provenance_refused,
};
use super::super::serve_cmd::path_arg;
#[cfg(test)]
use super::count_journal_bytes;
use super::{
    INTENTS, ReceivePackIntent, ReceivePackIntentKey, ReceivePackIntentRef, ReceivePackRefStatus,
    push_admission, receive_pack_repo_identity_hex,
};
use crate::Vault;
use crate::codebase::RepoRef;
use crate::error::Result;
use crate::federation::git_push::GitPushRefChange;
use crate::origin::residence::OriginAuthorityStamp;
use crate::origin::secret_marks::{admitted_marks, record_receive_secret_marks_in_txn};

impl Vault {
    pub(in crate::origin::smart_http) fn record_receive_pack_intent(
        &self,
        repo: &RepoRef,
        stamp: &DoorAdmissionStamp,
        door: &DoorWindowReport,
        changes: Option<&[GitPushRefChange]>,
    ) -> Result<()> {
        let RepoRef::LocalFolder { path, .. } = repo else {
            return Err(receive_pack_provenance_refused("intent is not local"));
        };
        let root = Path::new(path).canonicalize()?;
        let root_text = path_arg(&root)?;
        let admission = {
            let rtxn = self.store.env.read_txn()?;
            self.receive_pack_evidence_in_txn(
                &rtxn,
                stamp.operation_id,
                RECEIVE_PACK_ADMISSION_PREDICATE,
            )?
        };
        if !door.admitted()
            || !unlandable_ref_reasons(&door.ref_updates).is_empty()
            || receive_pack_field(&admission, "door_seam")?.as_str() != Some("landed")
            || receive_pack_field(&admission, "effector_check")?.as_str() != Some("admitted")
            || receive_pack_field(&admission, "actor_id")?.as_str() != Some(stamp.principal_ref())
            || receive_pack_field(&admission, "repo_root")?.as_str() != Some(root_text.as_str())
            || receive_pack_field(&admission, "origin_authority")?
                != &OriginAuthorityStamp::evidence_value(stamp.origin_authority.as_ref())
        {
            return Err(receive_pack_provenance_refused(
                "intent was not admitted and scanned",
            ));
        }
        let push = push_admission::admitted_push(&admission, stamp)?;
        // The serving thread holds the coordinator while this hook runs.
        // Do not acquire that thread's lock here; only verify its epoch.
        self.require_receive_pack_host_at(&root, stamp.origin_authority.as_ref())?;
        let intent = ReceivePackIntent {
            operation_id: stamp.operation_id.to_hex(),
            actor_id: stamp.principal_ref().to_owned(),
            repo_root: root_text,
            admitted_at: stamp.admitted_at(),
            origin_authority: stamp.origin_authority.clone(),
            transport_bytes: None,
            refs: door
                .ref_updates
                .iter()
                .enumerate()
                .map(|(index, update)| {
                    let pointers = door.ref_lfs_pointers.get(index).cloned();
                    held_by_ref(&door.lfs_pointers, pointers.as_deref())
                        .ok_or_else(|| receive_pack_provenance_refused("pointer out of range"))?;
                    Ok(ReceivePackIntentRef {
                        name: update.name.clone(),
                        old_oid: update.old_oid.as_ref().map(|oid| oid.as_str().to_owned()),
                        new_oid: update.new_oid.as_ref().map(|oid| oid.as_str().to_owned()),
                        outcome_id: self.store.clock.entity_id()?.to_hex(),
                        observed: false,
                        status: ReceivePackRefStatus::Pending,
                        pointers,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            pointers: door
                .lfs_pointers
                .iter()
                .map(|pointer| {
                    (
                        pointer.path.clone(),
                        pointer.oid.to_hex(),
                        pointer.size_bytes,
                    )
                })
                .collect(),
            push: stamp.push.clone(),
        };
        let key = ReceivePackIntentKey {
            repo_identity_hex: receive_pack_repo_identity_hex(self, &root)?,
            operation_id: stamp.operation_id,
        };
        INTENTS.encode_value(&intent)?;
        #[cfg(test)]
        count_journal_bytes(INTENTS.encode_value(&intent));
        let marks = admitted_marks(door, stamp)?;
        self.with_write_txn_grouped(|wtxn| {
            if INTENTS.contains(&self.store, wtxn, &key)? {
                return Err(receive_pack_provenance_refused("intent already exists"));
            }
            self.recheck_git_push_in_txn(wtxn, push, repo, changes)?;
            record_receive_secret_marks_in_txn(
                self,
                wtxn,
                stamp,
                &key.repo_identity_hex,
                marks,
                &door.ref_updates,
            )?;
            INTENTS.put(&self.store, wtxn, &key, &intent)?;
            Ok(())
        })
    }
}
