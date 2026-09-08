//! The single-writer landing: apply path, per-ref publication fan-out, and
//! wire-outcome mapping.

use std::path::Path;

use super::door_window::printable_ref_name;
use super::evidence::{
    ObservedRef, ReceivePackOutcome, RefUpdate, receive_pack_provenance_refused,
};
use super::landing_lfs::{
    admit_landing_lfs_pointers, attach_landing_lfs_pointers, ref_required_lfs_oids,
};
use super::paths::{now_secs, serve_failed};
use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{
    GitOid, GitRefName, GitWire, GitWireCommitOutcome, GitWireReceipt, GitWireRepo, lock_repository,
};
use crate::origin::lfs::{LfsPointerIntent, lfs_repo_id};
use crate::origin::publication::{
    OriginPublicationReceipt, OriginPublicationRequest, OriginPublicationStatus,
};
use crate::temporal::TimeRange;

/// Attribution from the durable receive-pack observer. The landing verifies
/// the local producer receipt and the actor/repository/operation binding.
#[derive(Debug, Clone, Copy)]
pub struct ReceivePackAttribution {
    /// Server-derived authenticated principal, not an origin-local stand-in.
    pub actor_id: EntityId,
    /// Durable observed-outcome claim written by this module's serve path.
    /// Landing reads it; caller-supplied active claims are not source proof.
    pub provenance_claim_id: EntityId,
}

/// The durable record of one landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivePackLanding {
    /// The first certified ref's receipt. A multi-ref landing is not atomic;
    /// success means every ref certified, but failure never rolls earlier refs back.
    pub receipt: GitWireReceipt,
    /// Whether a durable terminal record answered without re-running git.
    pub replayed: bool,
}

/// Whether the repository already carries every observed value.
///
/// The observed-ref check is what makes a replayed outcome a no-op: a landing
/// whose refs already match publishes nothing new.
pub fn refs_already_applied(
    vault: &Vault,
    repo: &RepoRef,
    repo_root: &Path,
    refs: &[ObservedRef],
) -> Result<bool> {
    if refs.is_empty() {
        return Ok(true);
    }
    let wire = GitWire::new(vault)?;
    let handle = wire.open_repo(repo.clone(), repo_root)?;
    let names = refs
        .iter()
        .map(|entry| GitRefName::parse_full(entry.name.clone()))
        .collect::<Result<Vec<_>>>()?;
    let observed = wire.read_refs(&handle, &names)?;
    Ok(refs
        .iter()
        .zip(observed)
        .all(|(wanted, seen)| wanted.oid == seen.oid && wanted.name == seen.name.as_str()))
}

impl Vault {
    /// Replays a receive-pack outcome through the single-writer path.
    ///
    /// New advancing publications require
    /// [`Vault::apply_receive_pack_update_with_attribution`]. This outcome-only
    /// door recovers attribution from an existing journal row or refuses.
    ///
    /// Crate-local inherent impl: it lives HERE, and `vault.rs` is never
    /// edited.
    ///
    /// The whole landing runs under the repository coordinator — the advisory
    /// lock in the git common directory that every queued repo mutation and
    /// every GitWire ref effect also take — so the origin's receive-pack is the
    /// single writer and no queued mutation can interleave with it. Served
    /// through [`serve`] the guard is already held for the whole mutation
    /// window and this acquisition is the re-entrant depth bump; called
    /// directly (a replay, a recovery) it is the acquisition itself. Either way
    /// the landing never runs without it.
    ///
    /// The ref advance is journaled through the origin publication protocol,
    /// which is the crash-window protocol for refs: a durable intent exists
    /// before the effect is claimed, the postcondition is re-verified against
    /// the repository, object availability is proved *whole* before any ref is
    /// certified, and the census finishes any record a crash left `Prepared`.
    /// Nothing here writes the sync plane.
    ///
    /// # Why an advance and a deletion take different routes
    ///
    /// An advance PUBLISHES: it makes a new head visible, so it owes the
    /// availability proof, the claim, and the visible-ref row that
    /// [`Vault::published_origin_refs`] projects. It therefore runs through
    /// [`Vault::publish_origin_ref`], one publication per ref, and a
    /// publication the protocol refuses refuses the landing.
    ///
    /// A deletion publishes nothing. It withdraws a name, needs no object to
    /// be present (deleting a ref unlinks a name rather than removing an
    /// object), and mints no visibility — so it stays on the plain journaled
    /// ref path. Routing it through the publication protocol would demand an
    /// availability proof for a head that is being retired.
    ///
    /// # LFS pointer admission
    ///
    /// The admission runs HERE rather than at the transport, so a replay and a
    /// recovery pass through it exactly as a served push does — a gate a caller
    /// can route around is not a gate. It is the one place that knows both the
    /// proven repository identity and the pointers the door framed.
    pub fn apply_receive_pack_update(
        &self,
        repo: &RepoRef,
        outcome: &ReceivePackOutcome,
    ) -> Result<ReceivePackLanding> {
        self.apply_receive_pack_update_inner(repo, outcome, None)
    }

    /// Lands an authenticated push with a real, already-durable source claim.
    /// Authentication belongs to the transport. Its served operation produces
    /// the evidence here; actor, repository and outcome bindings are checked
    /// against both active claims and the local producer receipts.
    pub fn apply_receive_pack_update_with_attribution(
        &self,
        repo: &RepoRef,
        outcome: &ReceivePackOutcome,
        attribution: &ReceivePackAttribution,
    ) -> Result<ReceivePackLanding> {
        self.apply_receive_pack_update_inner(repo, outcome, Some(attribution))
    }

    fn apply_receive_pack_update_inner(
        &self,
        repo: &RepoRef,
        outcome: &ReceivePackOutcome,
        attribution: Option<&ReceivePackAttribution>,
    ) -> Result<ReceivePackLanding> {
        if outcome.ref_updates.is_empty() {
            return Err(serve_failed("receive-pack outcome moved no ref"));
        }
        let wire = GitWire::new(self)?;
        let handle = wire.open_repo(repo.clone(), &outcome.repo_root)?;
        let _guard = lock_repository(handle.common_dir())?;
        let repo_id = lfs_repo_id(&handle.identity().as_hex())?;
        let recovered;
        let attribution = match attribution {
            Some(attribution) => attribution,
            None => {
                let existing = self
                    .origin_publication_rows(Some(repo_id))?
                    .into_iter()
                    .find(|row| {
                        outcome.ref_updates.iter().any(|update| {
                            row.ref_name.as_str() == update.name
                                && row.expected_old_oid == update.old_oid
                                && Some(&row.new_oid) == update.new_oid.as_ref()
                        })
                    })
                    .ok_or_else(|| {
                        receive_pack_provenance_refused("no journal-backed operation to replay")
                    })?;
                recovered = ReceivePackAttribution {
                    actor_id: existing.actor_id,
                    provenance_claim_id: existing.provenance_claim_id,
                };
                &recovered
            }
        };
        self.validate_receive_pack_attribution(repo_id, outcome, attribution)?;
        // Decided BEFORE the refs move: a RepositoryLarge pointer whose bytes
        // this vault does not hold refuses the landing, so no head is ever
        // advertised that a stock client could not check out.
        let admitted = admit_landing_lfs_pointers(self, repo_id, &outcome.lfs_pointers)?;
        let learned_at = now_secs();
        let landing = self.land_receive_pack_refs(
            &wire,
            &handle,
            repo_id,
            outcome,
            &admitted,
            Some(attribution),
            learned_at,
        )?;
        // The landing's own postcondition, proved against the repository
        // rather than inferred from the receipts: a replay that changed
        // nothing and a first landing that changed everything both have to end
        // with the repository carrying exactly what this outcome named.
        if !refs_already_applied(self, repo, &outcome.repo_root, &certified_refs(outcome))? {
            return Err(Error::ReceivePackLandingRefused {
                reason: "the landing did not leave the refs it certified".to_owned(),
            });
        }
        Ok(landing)
    }

    /// Lands every ref this outcome named, advances through the publication
    /// protocol and deletions through the plain journaled path.
    ///
    /// The landing is `replayed` only when EVERY ref replayed: a push where one
    /// ref was already durable and another genuinely moved did new work, and
    /// reporting it as a replay would claim the origin had nothing to do.
    #[expect(
        clippy::too_many_arguments,
        reason = "per-ref publication carries availability and authenticated attribution"
    )]
    fn land_receive_pack_refs(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        repo_id: EntityId,
        outcome: &ReceivePackOutcome,
        admitted: &[LfsPointerIntent],
        attribution: Option<&ReceivePackAttribution>,
        learned_at: u64,
    ) -> Result<ReceivePackLanding> {
        let mut certified: Option<GitWireReceipt> = None;
        let mut replayed = true;
        for update in &outcome.ref_updates {
            let (receipt, was_replayed) = match update.new_oid.as_ref() {
                Some(next) => self.publish_landing_advance(
                    wire,
                    handle,
                    repo_id,
                    update,
                    next,
                    admitted,
                    attribution,
                    learned_at,
                )?,
                None => landed_wire_outcome(wire.publish_refs(
                    handle,
                    vec![update.publication()?],
                    learned_at,
                )?)?,
            };
            // One publication per ref, not an atomic multi-ref push. Preserve
            // each successful ref's attachment even if a later ref is refused.
            // Never roll back a ref over a third party's later value.
            attach_landing_lfs_pointers(
                self,
                wire,
                handle,
                repo_id,
                std::slice::from_ref(update),
                admitted,
                learned_at,
            )?;
            replayed &= was_replayed;
            if certified.is_none() {
                certified = Some(receipt);
            }
        }
        let receipt = certified.ok_or_else(|| serve_failed("receive-pack outcome moved no ref"))?;
        Ok(ReceivePackLanding { receipt, replayed })
    }

    /// Publishes one advancing ref through the origin publication protocol.
    ///
    /// The protocol owns the compare-and-swap, the availability proof, the
    /// LEDGER claim and the visible-ref row in one crash-consistent unit; this
    /// function's whole job is to say what the push asked for and to translate
    /// the protocol's verdict back into a landing.
    #[expect(
        clippy::too_many_arguments,
        reason = "per-ref publication carries availability and authenticated attribution"
    )]
    fn publish_landing_advance(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        repo_id: EntityId,
        update: &RefUpdate,
        next: &GitOid,
        admitted: &[LfsPointerIntent],
        attribution: Option<&ReceivePackAttribution>,
        learned_at: u64,
    ) -> Result<(GitWireReceipt, bool)> {
        let ref_name = GitRefName::parse_full(update.name.clone())?;
        let attribution = match attribution {
            Some(attribution) => *attribution,
            None => {
                // The old outcome-only API is a replay door, not authority to
                // create a new publication. Recover attribution only from the
                // durable publication it is actually replaying.
                let existing = self
                    .origin_publication_rows(Some(repo_id))?
                    .into_iter()
                    .find(|row| {
                        row.ref_name == ref_name
                            && row.expected_old_oid == update.old_oid
                            && row.new_oid == *next
                    })
                    .ok_or_else(|| Error::ReceivePackLandingRefused {
                        reason: "receive-pack needs authenticated actor and durable provenance"
                            .to_owned(),
                    })?;
                ReceivePackAttribution {
                    actor_id: existing.actor_id,
                    provenance_claim_id: existing.provenance_claim_id,
                }
            }
        };
        let request = OriginPublicationRequest {
            repo_id,
            repo: handle.clone(),
            ref_name: GitRefName::parse_full(update.name.clone())?,
            expected_old_oid: update.old_oid.clone(),
            new_oid: next.clone(),
            required_objects: vec![next.clone()],
            required_lfs_oids: ref_required_lfs_oids(wire, handle, admitted, next)?,
            provenance_claim_id: attribution.provenance_claim_id,
            actor_id: attribution.actor_id,
            occurred: TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
        };
        let receipt = self.publish_origin_ref(wire, request)?;
        landing_from_publication(&update.name, &receipt)
    }
}

/// The values this outcome claims the repository carries once it has landed.
fn certified_refs(outcome: &ReceivePackOutcome) -> Vec<ObservedRef> {
    outcome
        .ref_updates
        .iter()
        .map(|update| ObservedRef {
            name: update.name.clone(),
            oid: update.new_oid.clone(),
        })
        .collect()
}

/// Turns one publication's verdict into this ref's landing evidence.
///
/// The rejection is read BEFORE the status, and that order is the point. A
/// record that already reached `Published` stays `Published` when a later
/// re-drive is refused — the protocol never restates a terminal record — so the
/// wire outcome, not the record, is the authority on whether THIS attempt moved
/// the ref. Reading the status first would report a refused re-drive as a
/// successful landing.
fn landing_from_publication(
    name: &str,
    receipt: &OriginPublicationReceipt,
) -> Result<(GitWireReceipt, bool)> {
    if let Some(reason) = receipt.wire_rejection() {
        return Err(Error::ReceivePackLandingRefused {
            reason: format!("{reason:?}"),
        });
    }
    if receipt.record.status != OriginPublicationStatus::Published {
        return Err(Error::ReceivePackLandingRefused {
            reason: format!(
                "publication for {} is {}",
                printable_ref_name(name),
                receipt.record.status.as_str()
            ),
        });
    }
    let Some(outcome) = receipt.wire.clone() else {
        return Err(Error::ReceivePackLandingRefused {
            reason: format!("publication for {} moved no ref", printable_ref_name(name)),
        });
    };
    landed_wire_outcome(outcome)
}

/// The receipt and replay flag of one journaled ref effect, or a refusal.
fn landed_wire_outcome(outcome: GitWireCommitOutcome) -> Result<(GitWireReceipt, bool)> {
    match outcome {
        GitWireCommitOutcome::Applied(receipt) => Ok((receipt, false)),
        GitWireCommitOutcome::Replayed(receipt) => Ok((receipt, true)),
        GitWireCommitOutcome::Rejected { reason, .. } => Err(Error::ReceivePackLandingRefused {
            reason: format!("{reason:?}"),
        }),
    }
}
