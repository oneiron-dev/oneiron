//! The crash-durable per-ref intent journal and its reconcile/resume path.

use std::path::Path;

use super::cgi_finish::realized_updates;
use super::door::DoorAdmissionStamp;
use super::door_window::{DoorWindowReport, DoorWindowVerdict, unlandable_ref_reasons};
use super::evidence::{
    PackStats, RECEIVE_PACK_ADMISSION_PREDICATE, ReceivePackOutcome, RefUpdate, receive_pack_field,
    receive_pack_provenance_refused,
};
use super::landing::ReceivePackLanding;
use super::serve::repo_common_dir;
use super::serve_cmd::path_arg;
use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, lock_repository};
use crate::origin::lfs::{LfsOid, LfsPushedPointer};
use serde::{Deserialize, Serialize};

// A local operation journal, not an exported claim or caller-supplied authority.
// Its initial row is committed while pre-receive still blocks every ref effect.
const RECEIVE_PACK_INTENT_PREFIX: &[u8] = b"origin:receive_pack_intent:v1:";

/// Per-ref completion, independent of the backend's transport success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceivePackRefStatus {
    /// Publication and its attachments are durable.
    Published,
    /// The backend did not leave this ref at the proposed value.
    NotApplied,
    /// A previously observed effect was replaced; recovery never overwrites it.
    Superseded,
    /// An observed effect still needs publication or attachment recovery.
    Pending,
}

/// One ref's result. A multi-ref operation can contain different results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivePackRefResult {
    /// Full ref name from the admitted intent.
    pub name: String,
    /// Durable completion, or an explicit pending result.
    pub status: ReceivePackRefStatus,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ReceivePackIntentRef {
    pub(super) name: String,
    old_oid: Option<String>,
    new_oid: Option<String>,
    pub(super) outcome_id: String,
    pub(super) observed: bool,
    pub(super) status: ReceivePackRefStatus,
}

impl ReceivePackIntentRef {
    fn update(&self) -> Result<RefUpdate> {
        Ok(RefUpdate {
            name: self.name.clone(),
            old_oid: self.old_oid.clone().map(GitOid::parse_hex).transpose()?,
            new_oid: self.new_oid.clone().map(GitOid::parse_hex).transpose()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct ReceivePackIntent {
    pub(super) operation_id: String,
    actor_id: String,
    repo_root: String,
    admitted_at: u64,
    // Written once after the exchange, before any outcome evidence. Recovery
    // without this checkpoint has no measured transport totals.
    pub(super) transport_bytes: Option<(u64, u64)>,
    pub(super) refs: Vec<ReceivePackIntentRef>,
    pointers: Vec<(String, String, u64)>,
}

fn receive_pack_intent_prefix(repo_root: &Path) -> Result<Vec<u8>> {
    let mut key = RECEIVE_PACK_INTENT_PREFIX.to_vec();
    key.extend_from_slice(
        blake3::hash(path_arg(&repo_root.canonicalize()?)?.as_bytes()).as_bytes(),
    );
    Ok(key)
}

impl Vault {
    pub(super) fn record_receive_pack_intent(
        &self,
        repo: &RepoRef,
        stamp: &DoorAdmissionStamp,
        door: &DoorWindowReport,
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
        {
            return Err(receive_pack_provenance_refused(
                "intent was not admitted and scanned",
            ));
        }
        let intent = ReceivePackIntent {
            operation_id: stamp.operation_id.to_hex(),
            actor_id: stamp.principal_ref().to_owned(),
            repo_root: root_text,
            admitted_at: stamp.admitted_at(),
            transport_bytes: None,
            refs: door
                .ref_updates
                .iter()
                .map(|update| ReceivePackIntentRef {
                    name: update.name.clone(),
                    old_oid: update.old_oid.as_ref().map(|oid| oid.as_str().to_owned()),
                    new_oid: update.new_oid.as_ref().map(|oid| oid.as_str().to_owned()),
                    outcome_id: EntityId::now().to_hex(),
                    observed: false,
                    status: ReceivePackRefStatus::Pending,
                })
                .collect(),
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
        };
        let mut key = receive_pack_intent_prefix(&root)?;
        key.extend_from_slice(stamp.operation_id.as_bytes());
        let encoded = rmp_serde::to_vec_named(&intent)
            .map_err(|_| receive_pack_provenance_refused("intent does not encode"))?;
        self.with_write_txn(|wtxn| {
            if self.store.vault_meta.get(wtxn, &key)?.is_some() {
                return Err(receive_pack_provenance_refused("intent already exists"));
            }
            self.store.vault_meta.put(wtxn, &key, &encoded)?;
            Ok(())
        })
    }

    pub(super) fn save_receive_pack_intent(
        &self,
        key: &[u8],
        intent: &ReceivePackIntent,
    ) -> Result<()> {
        let encoded = rmp_serde::to_vec_named(intent)
            .map_err(|_| receive_pack_provenance_refused("intent does not encode"))?;
        self.with_write_txn(|wtxn| {
            self.store.vault_meta.put(wtxn, key, &encoded)?;
            Ok(())
        })
    }

    /// Resumes locally journaled pushes, including a crash before any outcome
    /// claim existed. Only observed post-images are published: recovery never
    /// applies a ref that the backend declined. GitWire remains the effect owner.
    pub fn reconcile_receive_pack_operations(&self, repo_root: &Path) -> Result<()> {
        let _guard = lock_repository(&repo_common_dir(repo_root)?)?;
        for (key, mut intent) in self.receive_pack_intents(repo_root)? {
            self.resume_receive_pack_intent(&key, &mut intent)?;
        }
        Ok(())
    }

    pub(super) fn receive_pack_intents(
        &self,
        repo_root: &Path,
    ) -> Result<Vec<(Vec<u8>, ReceivePackIntent)>> {
        let prefix = receive_pack_intent_prefix(repo_root)?;
        let rtxn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for (index, row) in self
            .store
            .vault_meta
            .prefix_iter(&rtxn, &prefix)?
            .enumerate()
        {
            if index >= super::publication::ORIGIN_PUBLICATION_MAX_ROWS {
                return Err(Error::IndexOverflow("receive-pack intents"));
            }
            let (key, value) = row?;
            let intent = rmp_serde::from_slice(&value)
                .map_err(|_| Error::CorruptedIndex("receive-pack intent"))?;
            rows.push((key.to_vec(), intent));
        }
        Ok(rows)
    }

    pub(super) fn resume_receive_pack_intent(
        &self,
        key: &[u8],
        intent: &mut ReceivePackIntent,
    ) -> Result<(Option<ReceivePackOutcome>, Option<ReceivePackLanding>)> {
        let root = Path::new(&intent.repo_root);
        let stamp = DoorAdmissionStamp {
            principal_ref: intent.actor_id.clone(),
            credential_fingerprint: None,
            method: "bearer+registered-principal",
            admitted_at: intent.admitted_at,
            operation_id: EntityId::from_hex(&intent.operation_id)
                .map_err(|_| Error::CorruptedIndex("receive-pack operation id"))?,
        };
        let pointers = intent
            .pointers
            .iter()
            .map(|(path, oid, size)| {
                Ok(LfsPushedPointer {
                    path: path.clone(),
                    oid: LfsOid::parse_hex(oid)?,
                    size_bytes: *size,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut replay_outcome = None;
        let mut landing: Option<ReceivePackLanding> = None;
        let (request_bytes, response_bytes) = intent.transport_bytes.unwrap_or((0, 0));
        for index in 0..intent.refs.len() {
            if intent.refs[index].status != ReceivePackRefStatus::Pending {
                continue;
            }
            let update = intent.refs[index].update()?;
            // A failed proof is uncertainty, not permission to replay a ref.
            let observed = realized_updates(self, root, std::slice::from_ref(&update));
            match observed {
                Ok(updates) if updates.is_empty() => {
                    intent.refs[index].status = if intent.refs[index].observed {
                        ReceivePackRefStatus::Superseded
                    } else {
                        ReceivePackRefStatus::NotApplied
                    };
                    self.save_receive_pack_intent(key, intent)?;
                    continue;
                }
                Err(_) => continue,
                Ok(_) => {}
            }
            if !intent.refs[index].observed {
                intent.refs[index].observed = true;
                self.save_receive_pack_intent(key, intent)?;
            }
            let outcome = ReceivePackOutcome {
                repo_root: root.to_path_buf(),
                ref_updates: vec![update.clone()],
                lfs_pointers: pointers.clone(),
                staged_objects_dir: root.join("objects"),
                // These are whole-exchange totals, not a per-ref allocation.
                // Only a crash before the checkpoint leaves them unmeasured:
                // zero then means unknown, not newly measured recovery traffic.
                pack_stats: PackStats {
                    request_bytes,
                    response_bytes,
                    ref_update_count: 1,
                },
            };
            let door = DoorWindowReport {
                verdict: DoorWindowVerdict::Clean,
                ref_updates: vec![update],
                lfs_pointers: pointers.clone(),
                quarantine_path: None,
            };
            let result = (|| {
                let attribution = self.record_receive_pack_outcome_at(
                    &stamp,
                    &door,
                    &outcome,
                    0,
                    EntityId::from_hex(&intent.refs[index].outcome_id)
                        .map_err(|_| Error::CorruptedIndex("receive-pack outcome id"))?,
                )?;
                if replay_outcome.is_none() {
                    replay_outcome = Some(outcome.clone());
                }
                self.apply_receive_pack_update_with_attribution(
                    &outcome.pinned_repo_ref()?,
                    &outcome,
                    &attribution,
                )
            })();
            if let Ok(receipt) = result {
                intent.refs[index].status = ReceivePackRefStatus::Published;
                self.save_receive_pack_intent(key, intent)?;
                if let Some(previous) = &mut landing {
                    previous.replayed &= receipt.replayed;
                } else {
                    // The exposed replay outcome must name the same ref and
                    // source as the first receipt, not an uncertified aggregate.
                    replay_outcome = Some(outcome);
                    landing = Some(receipt);
                }
            }
            // Do not stop after a failed ref: retain its Pending disposition
            // and recover the other refs independently.
        }
        Ok((replay_outcome, landing))
    }
}
