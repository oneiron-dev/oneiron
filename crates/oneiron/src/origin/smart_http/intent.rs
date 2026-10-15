//! The crash-durable per-ref intent journal and its reconcile/resume path.

use std::ops::Bound;
use std::path::Path;

use super::cgi_finish::realized_updates;
use super::door::DoorAdmissionStamp;
use super::door_window::{DoorWindowReport, DoorWindowVerdict, unlandable_ref_reasons};
use super::evidence::{
    PackStats, RECEIVE_PACK_ADMISSION_PREDICATE, ReceivePackOutcome, RefUpdate, receive_pack_field,
    receive_pack_provenance_refused,
};
use super::landing::ReceivePackLanding;
use super::serve_cmd::path_arg;
use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitWire, lock_repository};
use crate::origin::lfs::{LfsOid, LfsPushedPointer, lfs_repo_id};
use crate::origin::residence::OriginAuthorityStamp;
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::Store;
use heed::RwTxn;
use serde::{Deserialize, Serialize};

// A local operation journal, not an exported claim or caller-supplied authority.
// Its initial row is committed while pre-receive still blocks every ref effect.
/// Crash-durable per-push intent journal recording every proposed ref move before any effect
/// lands, keyed by repo identity then operation id. Key: string(repo identity hex) + id16
/// (operation id), with NO separator — the repo identity hex is always the fixed-length hash
/// spelling, so the trailing 16 raw bytes are unambiguous.
const INTENTS: SideTable<ReceivePackIntentKey, ReceivePackIntent, Named> =
    SideTable::new(&side_table::ORIGIN_RECEIVE_PACK_INTENT);

/// Settled intents one write transaction prunes when a scan meets them.
const PRUNE_BATCH: usize = 4096;

type IntentRows<'txn> =
    Box<dyn Iterator<Item = Result<(ReceivePackIntentKey, ReceivePackIntent)>> + 'txn>;

#[derive(Clone)]
pub(super) struct ReceivePackIntentKey {
    repo_identity_hex: String,
    operation_id: EntityId,
}

impl SideKey for ReceivePackIntentKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.repo_identity_hex.as_bytes());
        self.operation_id.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let id_start = bytes.len().checked_sub(16)?;
        let (text_bytes, id_bytes) = bytes.split_at(id_start);
        Some(Self {
            repo_identity_hex: String::from_utf8(text_bytes.to_vec()).ok()?,
            operation_id: EntityId::from_bytes(id_bytes.try_into().ok()?).ok()?,
        })
    }
}

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
    origin_authority: Option<OriginAuthorityStamp>,
    // Written once after the exchange, before any outcome evidence. Recovery
    // without this checkpoint has no measured transport totals.
    pub(super) transport_bytes: Option<(u64, u64)>,
    pub(super) refs: Vec<ReceivePackIntentRef>,
    pointers: Vec<(String, String, u64)>,
}

impl ReceivePackIntent {
    /// Whether every ref reached its final status. Nothing reads a settled
    /// intent again: its results went to the push that settled it.
    pub(super) fn is_settled(&self) -> bool {
        self.refs
            .iter()
            .all(|entry| entry.status != ReceivePackRefStatus::Pending)
    }
}

/// Removes one intent's rows. Every prune of a settled intent goes here, so
/// a settled push leaves no row behind.
fn prune_receive_pack_intent_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    key: &ReceivePackIntentKey,
) -> Result<()> {
    INTENTS.delete(store, wtxn, key)?;
    Ok(())
}

fn receive_pack_repo_identity_hex(vault: &Vault, repo_root: &Path) -> Result<String> {
    // Authority and the coordinator name the object store, not a worktree.
    // A cutover from any linked root must drain every accepted operation.
    Ok(GitWire::new(vault)?
        .repository_identity(repo_root)?
        .as_hex())
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
            || receive_pack_field(&admission, "origin_authority")?
                != &OriginAuthorityStamp::evidence_value(stamp.origin_authority.as_ref())
        {
            return Err(receive_pack_provenance_refused(
                "intent was not admitted and scanned",
            ));
        }
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
                .map(|update| {
                    Ok(ReceivePackIntentRef {
                        name: update.name.clone(),
                        old_oid: update.old_oid.as_ref().map(|oid| oid.as_str().to_owned()),
                        new_oid: update.new_oid.as_ref().map(|oid| oid.as_str().to_owned()),
                        outcome_id: self.store.clock.entity_id()?.to_hex(),
                        observed: false,
                        status: ReceivePackRefStatus::Pending,
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
        };
        let key = ReceivePackIntentKey {
            repo_identity_hex: receive_pack_repo_identity_hex(self, &root)?,
            operation_id: stamp.operation_id,
        };
        INTENTS.encode_value(&intent)?;
        self.with_write_txn_grouped(|wtxn| {
            if INTENTS.contains(&self.store, wtxn, &key)? {
                return Err(receive_pack_provenance_refused("intent already exists"));
            }
            INTENTS.put(&self.store, wtxn, &key, &intent)?;
            Ok(())
        })
    }

    /// Saves an intent's progress. The save that settles it prunes it
    /// instead, in the same transaction, so no settled row outlives it.
    pub(super) fn save_receive_pack_intent(
        &self,
        key: &ReceivePackIntentKey,
        intent: &ReceivePackIntent,
    ) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            if intent.is_settled() {
                return prune_receive_pack_intent_in_txn(&self.store, wtxn, key);
            }
            INTENTS.put(&self.store, wtxn, key, intent)?;
            Ok(())
        })
    }

    /// Resumes locally journaled pushes, including a crash before any outcome
    /// claim existed. Only observed post-images are published: recovery never
    /// applies a ref that the backend declined. GitWire remains the effect owner.
    pub fn reconcile_receive_pack_operations(&self, repo_root: &Path) -> Result<()> {
        let wire = GitWire::new(self)?;
        let _guard = lock_repository(&wire.canonical_common_dir(repo_root)?)?;
        for (key, mut intent) in self.receive_pack_intents(repo_root)? {
            self.resume_receive_pack_intent(&key, &mut intent)?;
        }
        Ok(())
    }

    /// How many intent rows the repository holds, settled or not, read
    /// without pruning.
    #[cfg(test)]
    pub(super) fn receive_pack_intent_rows_for_test(&self, repo_root: &Path) -> usize {
        let repo_identity_hex = receive_pack_repo_identity_hex(self, repo_root).expect("identity");
        let rtxn = self.store.env.read_txn().expect("read txn");
        INTENTS
            .iter_from(&self.store, &rtxn, repo_identity_hex.as_bytes())
            .expect("intent rows")
            .count()
    }

    /// Writes an intent row as given, settled or not: the row a crash leaves
    /// between a settling save and its prune.
    #[cfg(test)]
    pub(super) fn put_receive_pack_intent_for_test(
        &self,
        key: &ReceivePackIntentKey,
        intent: &ReceivePackIntent,
    ) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            INTENTS.put(&self.store, wtxn, key, intent)?;
            Ok(())
        })
    }

    pub(in crate::origin) fn has_pending_receive_pack_operations(
        &self,
        repo_root: &Path,
    ) -> Result<bool> {
        Ok(!self.receive_pack_intents(repo_root)?.is_empty())
    }

    /// One operation's journaled intent, if it is still pending.
    pub(super) fn receive_pack_intent(
        &self,
        repo_root: &Path,
        operation_id: EntityId,
    ) -> Result<Option<(ReceivePackIntentKey, ReceivePackIntent)>> {
        let key = ReceivePackIntentKey {
            repo_identity_hex: receive_pack_repo_identity_hex(self, repo_root)?,
            operation_id,
        };
        let rtxn = self.store.env.read_txn()?;
        Ok(INTENTS
            .get(&self.store, &rtxn, &key)?
            .map(|intent| (key, intent)))
    }

    /// The repository's pending intents, in operation order.
    ///
    /// A settled row the scan meets is pruned on the way, a batch per write
    /// transaction: one a crash left between its settling save and its
    /// prune, or one journaled before settled intents were pruned. So the
    /// rows a scan reads are the pending pushes, not the repository's
    /// history. The scan never refuses for their number (rule 5): past its
    /// threshold row it raises an origin scan check and reads on. Callers
    /// hold the repository coordinator.
    pub(super) fn receive_pack_intents(
        &self,
        repo_root: &Path,
    ) -> Result<Vec<(ReceivePackIntentKey, ReceivePackIntent)>> {
        let repo_identity_hex = receive_pack_repo_identity_hex(self, repo_root)?;
        let mut count = {
            let rtxn = self.store.env.read_txn()?;
            ScanCount::start(
                &self.store,
                &rtxn,
                EngineScan::ReceivePackIntents,
                lfs_repo_id(&repo_identity_hex)?.as_bytes(),
            )?
        };
        let mut pending = Vec::new();
        let mut after: Option<ReceivePackIntentKey> = None;
        loop {
            let mut settled = Vec::new();
            {
                let rtxn = self.store.env.read_txn()?;
                let rows: IntentRows<'_> = match &after {
                    None => Box::new(INTENTS.iter_from(
                        &self.store,
                        &rtxn,
                        repo_identity_hex.as_bytes(),
                    )?),
                    Some(key) => Box::new(INTENTS.iter_range(
                        &self.store,
                        &rtxn,
                        Bound::Excluded(key),
                        Bound::Unbounded,
                    )?),
                };
                for row in rows {
                    let (key, intent) = row?;
                    if key.repo_identity_hex != repo_identity_hex {
                        break;
                    }
                    count.row();
                    if !intent.is_settled() {
                        pending.push((key, intent));
                        continue;
                    }
                    settled.push(key);
                    if settled.len() == PRUNE_BATCH {
                        break;
                    }
                }
            }
            if !settled.is_empty() {
                self.with_write_txn_grouped(|wtxn| {
                    for key in &settled {
                        prune_receive_pack_intent_in_txn(&self.store, wtxn, key)?;
                    }
                    Ok(())
                })?;
            }
            if settled.len() < PRUNE_BATCH {
                break;
            }
            after = settled.pop();
        }
        count.finish(self);
        Ok(pending)
    }

    pub(super) fn resume_receive_pack_intent(
        &self,
        key: &ReceivePackIntentKey,
        intent: &mut ReceivePackIntent,
    ) -> Result<(Option<ReceivePackOutcome>, Option<ReceivePackLanding>)> {
        if !intent
            .refs
            .iter()
            .any(|entry| entry.status == ReceivePackRefStatus::Pending)
        {
            return Ok((None, None));
        }
        let root = Path::new(&intent.repo_root);
        let stamp = DoorAdmissionStamp {
            principal_ref: intent.actor_id.clone(),
            credential_fingerprint: None,
            method: "bearer+registered-principal",
            admitted_at: intent.admitted_at,
            origin_authority: intent.origin_authority.clone(),
            operation_id: EntityId::from_hex(&intent.operation_id)
                .map_err(|_| Error::CorruptedIndex("receive-pack operation id"))?,
        };
        // Recovery uses the accepted host, never the current pusher or a new
        // lease. The producer receipt seals the journal's epoch binding too.
        let admission = {
            let rtxn = self.store.env.read_txn()?;
            self.receive_pack_evidence_in_txn(
                &rtxn,
                stamp.operation_id,
                RECEIVE_PACK_ADMISSION_PREDICATE,
            )?
        };
        if receive_pack_field(&admission, "origin_authority")?
            != &OriginAuthorityStamp::evidence_value(stamp.origin_authority.as_ref())
        {
            return Err(receive_pack_provenance_refused(
                "recovery host authority differs from admission",
            ));
        }
        self.require_receive_pack_host_at(root, stamp.origin_authority.as_ref())?;
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
