//! The owner's execute of a frozen purge plan (FIX 7608 slice 10): each
//! ref moves through the origin publication protocol, the plan's
//! change-index owners are released, and the store is collected (module
//! docs of `origin::secret_purge`).
//!
//! Each ref move is its own publication, under the plan's CAS: an intent
//! claim derived from the plan and the ref, written while the owner's proof
//! is live, then `publish_origin_ref`, which takes the repository
//! coordinator, checks the origin authority and records a new `Published`
//! row; the old rows stay as evidence. No outer coordinator is held across
//! a move. A move already made counts as made, so an execute stopped part
//! way is run again from the start; only a filed receipt ends it.

use std::collections::HashMap;

use super::plan::{open_purge_store, purge_facts};
use super::{
    OUTSTANDING, REPO_SECRET_PURGE_RECEIPT_PREDICATE, RepoSecretPurgeKeepRoot, RepoSecretPurgePlan,
    RepoSecretPurgeReceipt, RepoSecretPurgeRefOutcome, RepoSecretPurgeState, purge_claim,
    put_purge_claim, receipt_id, receipt_value, require_owner_in_txn,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRejection, GitWireRepo};
use crate::origin::publication::{
    OriginKeepRefKind, OriginPublicationReceipt, OriginPublicationRequest, OriginPublicationStatus,
    origin_keep_ref_name,
};
use crate::origin::residence::OriginAuthorityLease;
use crate::origin::secret_projection::graph_objects::copy_repo_projection_objects;
use crate::store::code_snapshot::entity_id_from_hash_material;
use crate::temporal::TimeRange;

/// The hash domain each ref move's intent id is derived under, from its
/// plan and its ref.
const INTENT_ID_DOMAIN: &[u8] = b"oneiron:repo-secret-purge-intent:v1";

/// One planned ref move, parsed.
struct Move {
    name: GitRefName,
    old: GitOid,
    new: GitOid,
}

impl Vault {
    /// Executes the frozen plan `plan` as `owner`, under `authority` when
    /// this host holds the served store's origin authority, and files its
    /// receipt. A plan with a receipt answers that receipt; nothing runs
    /// again.
    ///
    /// # Errors
    /// The owner's proof is not live or is not the planner's, no plan has
    /// that id, or a store, Git or publication failure, after which the
    /// execute may be run again.
    pub(crate) fn execute_repo_secret_purge(
        &self,
        owner: &AuthenticatedOwner,
        plan: EntityId,
        authority: Option<&OriginAuthorityLease>,
    ) -> Result<RepoSecretPurgeReceipt> {
        let actor = owner.revalidate(self)?;
        let frozen = self
            .repo_secret_purge_plan(plan)?
            .ok_or(Error::EntityNotFound)?;
        if frozen.owner != actor {
            return Err(Error::Refused(
                "a repo secret purge is executed by the owner who planned it".to_owned(),
            ));
        }
        if let Some(receipt) = self.repo_secret_purge_receipt(plan)? {
            return Ok(receipt);
        }
        let moves = frozen
            .moves
            .iter()
            .map(|step| {
                Ok(Move {
                    name: GitRefName::parse_full(step.ref_name.clone())?,
                    old: GitOid::parse_hex(step.old_oid.clone())?,
                    new: GitOid::parse_hex(step.new_oid.clone())?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let wire = GitWire::new(self)?;
        let (store, repo) = open_purge_store(self, &wire, &frozen.repo)?;
        let now = self.now_recorded_at();
        if store != frozen.store {
            let ended = stale(&moves, &HashMap::new());
            return self.file_purge_receipt(owner, &frozen, ended, now);
        }
        let published: HashMap<GitRefName, GitOid> = self
            .published_origin_refs(&wire, store, &repo)?
            .into_iter()
            .collect();
        // A ref still at its old object moves now; one at its copy moved in
        // an earlier run. Anything else moved under the plan: it is stale.
        let mut pending: Vec<&Move> = Vec::new();
        for step in &moves {
            match published.get(&step.name) {
                Some(current) if *current == step.new => {}
                Some(current) if *current == step.old => pending.push(step),
                _ => {
                    let ended = stale(&moves, &published);
                    return self.file_purge_receipt(owner, &frozen, ended, now);
                }
            }
        }
        if !pending.is_empty() && !self.copies_stand(&wire, &repo, &frozen, &pending)? {
            let ended = stale(&moves, &published);
            return self.file_purge_receipt(owner, &frozen, ended, now);
        }
        let mut refs = Vec::with_capacity(moves.len());
        for step in &moves {
            let mut outcome = RepoSecretPurgeRefOutcome {
                ref_name: step.name.as_str().to_owned(),
                old_oid: step.old.as_str().to_owned(),
                new_oid: step.new.as_str().to_owned(),
                moved: false,
                failure: None,
            };
            if pending.iter().any(|waiting| waiting.name == step.name) {
                let receipt = self.move_purged_ref(
                    &wire, owner, actor, &frozen, store, &repo, step, authority, now,
                )?;
                // A replayed Published row answers with the wire's verdict on
                // this call: a rejected re-drive is no move.
                outcome.failure = match receipt.wire_rejection() {
                    Some(reason) => Some(rejection_text(reason).to_owned()),
                    None if receipt.record.status != OriginPublicationStatus::Published => Some(
                        receipt
                            .record
                            .failure
                            .clone()
                            .unwrap_or_else(|| "the publication refused the move".to_owned()),
                    ),
                    None => None,
                };
            }
            refs.push(outcome);
        }
        // The advertisement decides what moved: each ref must name its copy,
        // published, after every move ran.
        let after: HashMap<GitRefName, GitOid> = self
            .published_origin_refs(&wire, store, &repo)?
            .into_iter()
            .collect();
        for (outcome, step) in refs.iter_mut().zip(&moves) {
            outcome.moved = outcome.failure.is_none() && after.get(&step.name) == Some(&step.new);
            if !outcome.moved && outcome.failure.is_none() {
                outcome.failure = Some("the ref no longer names its masked copy".to_owned());
            }
        }
        let all_moved = refs.iter().all(|outcome| outcome.moved);
        let mut released = Vec::new();
        if all_moved {
            for root in frozen.keep_roots.iter().filter(|root| root.releases) {
                let kind = OriginKeepRefKind::parse(&root.kind)?;
                let oid = GitOid::parse_hex(root.oid.clone())?;
                // A release stopped between its owner row and its keep-ref
                // is driven again while the physical root stands; the
                // zero-owner check keeps it for any other owner.
                let held = self.origin_keep_owner_held(store, &oid, kind, &root.owner)?;
                let rooted = wire
                    .read_ref(&repo, &origin_keep_ref_name(&oid)?)?
                    .is_some();
                if held || rooted {
                    self.unpin_origin_object(&wire, &repo, kind, &root.owner, &oid, now)?;
                }
                released.push(root.clone());
            }
        }
        wire.collect_purged_objects(&repo)?;
        let mut still_present = Vec::new();
        for blob in &frozen.purged_blobs {
            if wire.object_exists(&repo, &GitOid::parse_hex(blob.clone())?)? {
                still_present.push(blob.clone());
            }
        }
        let state = if all_moved && still_present.is_empty() {
            RepoSecretPurgeState::CompleteLocal
        } else {
            RepoSecretPurgeState::Partial
        };
        self.file_purge_receipt(
            owner,
            &frozen,
            Ended {
                state,
                refs,
                released,
                still_present,
            },
            now,
        )
    }

    /// Whether the masked copy of each pending ref's object, rewritten now
    /// under the plan's marks and the values custody knows now (FIX 8966
    /// part 3, as the plan's copy was), is still the copy the plan froze. The
    /// copy is written again, so a copy collected since the plan stands
    /// again. `false` when a planned mark is no longer readable, or when a
    /// value custody learned since the plan changes the copy: the owner plans
    /// again.
    fn copies_stand(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        frozen: &RepoSecretPurgePlan,
        pending: &[&Move],
    ) -> Result<bool> {
        let Some(facts) = purge_facts(self, Some(frozen.marks.as_slice()))? else {
            return Ok(false);
        };
        let tips: Vec<GitOid> = pending.iter().map(|step| step.old.clone()).collect();
        let copy = self.with_known_values(|known| {
            copy_repo_projection_objects(
                self,
                wire,
                repo,
                repo,
                &tips,
                &facts,
                frozen.store,
                None,
                known,
            )
        })?;
        Ok(pending
            .iter()
            .all(|step| copy.copy_of(&step.old) == step.new))
    }

    /// Moves one planned ref to its copy: the intent, written while the
    /// owner's proof is live, then the origin publication with the plan's
    /// CAS.
    #[allow(clippy::too_many_arguments)]
    fn move_purged_ref(
        &self,
        wire: &GitWire<'_>,
        owner: &AuthenticatedOwner,
        actor: EntityId,
        frozen: &RepoSecretPurgePlan,
        store: EntityId,
        repo: &GitWireRepo,
        step: &Move,
        authority: Option<&OriginAuthorityLease>,
        now: u64,
    ) -> Result<OriginPublicationReceipt> {
        let intent = entity_id_from_hash_material(
            INTENT_ID_DOMAIN,
            &[
                frozen.plan.as_bytes().as_slice(),
                step.name.as_str().as_bytes(),
            ],
        )?;
        let request = OriginPublicationRequest {
            repo_id: store,
            repo: repo.clone(),
            ref_name: step.name.clone(),
            expected_old_oid: Some(step.old.clone()),
            new_oid: step.new.clone(),
            required_objects: vec![step.new.clone()],
            required_lfs_oids: Vec::new(),
            provenance_claim_id: intent,
            actor_id: actor,
            occurred: TimeRange {
                start: frozen.planned_at,
                end: frozen.planned_at,
            },
            learned_at: now,
        };
        // The owner's proof is judged in the intent's own writer: a revoked
        // proof writes no intent, so nothing publishes.
        let checked = self.put_origin_publication_intent_checked(&request, |txn| {
            Ok(require_owner_in_txn(self, owner, actor, txn))
        })?;
        checked?;
        match authority {
            Some(lease) => self.publish_origin_ref_authorized(wire, request, lease),
            None => self.publish_origin_ref(wire, request),
        }
    }

    /// Files `ended` as `frozen`'s one receipt and answers the receipt that
    /// stands: a concurrent execute may have filed it first.
    fn file_purge_receipt(
        &self,
        owner: &AuthenticatedOwner,
        frozen: &RepoSecretPurgePlan,
        ended: Ended,
        now: u64,
    ) -> Result<RepoSecretPurgeReceipt> {
        let receipt = RepoSecretPurgeReceipt {
            receipt: receipt_id(frozen.plan)?,
            plan: frozen.plan,
            state: ended.state,
            refs: ended.refs,
            released: ended.released,
            still_present: ended.still_present,
            outstanding: OUTSTANDING.to_vec(),
            executed_at: now,
        };
        let body = purge_claim(
            REPO_SECRET_PURGE_RECEIPT_PREDICATE,
            frozen.owner,
            frozen.store,
            receipt_value(&receipt),
        )?;
        put_purge_claim(self, owner, frozen.owner, receipt.receipt, &body, now)?;
        Ok(self
            .repo_secret_purge_receipt(frozen.plan)?
            .unwrap_or(receipt))
    }
}

/// How one execute ended, before it is filed.
struct Ended {
    state: RepoSecretPurgeState,
    refs: Vec<RepoSecretPurgeRefOutcome>,
    released: Vec<RepoSecretPurgeKeepRoot>,
    still_present: Vec<String>,
}

/// What one wire rejection of a ref move says.
const fn rejection_text(reason: GitWireRejection) -> &'static str {
    match reason {
        GitWireRejection::RefMoved => "the ref moved before the purge could move it",
        GitWireRejection::ObjectsUnavailable => {
            "the masked copy's objects are not all in the store"
        }
        GitWireRejection::EffectUnconfirmed => "the ref move could not be confirmed",
        GitWireRejection::Unauthorized => "the origin authority refused the move",
    }
}

/// A stale plan's end: no ref moved by this run, each ref named as
/// `published` shows it.
fn stale(moves: &[Move], published: &HashMap<GitRefName, GitOid>) -> Ended {
    Ended {
        state: RepoSecretPurgeState::Stale,
        refs: moves
            .iter()
            .map(|step| RepoSecretPurgeRefOutcome {
                ref_name: step.name.as_str().to_owned(),
                old_oid: step.old.as_str().to_owned(),
                new_oid: step.new.as_str().to_owned(),
                moved: published.get(&step.name) == Some(&step.new),
                failure: None,
            })
            .collect(),
        released: Vec::new(),
        still_present: Vec::new(),
    }
}
