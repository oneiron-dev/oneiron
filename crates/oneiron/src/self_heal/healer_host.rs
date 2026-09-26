//! External healer capability, durable propose receipts, and human-only PR release.
use super::{
    DiagnosticEvent, DiagnosticWorkingSet, Healer, RepairBundle, RepairConsentRoute,
    RepairOperation, RepairProposal,
    repair::{RegisteredHealer, run_healer_proposals},
};
use crate::side_table::{self, Named, SideTable};
use crate::{
    EntityId, Error, Result, Vault, consent::AuthenticatedOwner, write_envelope::WriteActor,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealerDeployment {
    EmbeddedInProcess,
    Daemon,
    SelfHostSingleWriter,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HealerBand {
    Dev,
    Production,
}
/// Engine-minted registration. Request JSON cannot choose the band or actor.
pub struct HealerRegistration<'a> {
    vault: &'a Vault,
    actor: WriteActor,
    band: HealerBand,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalState {
    Proposed,
    Denied,
    Released { release_ref: String },
    Reversed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealerProposalRecord {
    pub proposal: RepairProposal,
    pub state: ProposalState,
    pub run_ref: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalBurstCheck {
    #[serde(with = "super::receipt_serde::id")]
    pub actor: EntityId,
    pub count: u64,
    /// Run that crossed the threshold, not the scope of the actor-wide burst.
    /// Use `Vault::reverse_healer_burst` to reverse the flagged actor's submissions.
    pub run_ref: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealerRunReceipt {
    pub run_ref: String,
    #[serde(with = "super::receipt_serde::id")]
    pub actor: EntityId,
    #[serde(with = "super::receipt_serde::ids")]
    pub proposals: Vec<EntityId>,
    pub reversed: bool,
}
// Review pressure is independent of a detector's bounded observation window.
// This check never rejects submissions or grants execution authority.
pub(super) const PROPOSAL_BURST_THRESHOLD: u64 = 100_000;
#[derive(Default, Serialize, Deserialize)]
struct ActorCount {
    count: u64,
    check: Option<ProposalBurstCheck>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchPullRequest {
    #[serde(with = "super::receipt_serde::id")]
    pub proposal_id: EntityId,
    pub target_ref: String,
    pub patch_ref: String,
    pub schema: bool,
    pub release_ref: String,
    #[serde(with = "super::receipt_serde::id")]
    pub approved_by: EntityId,
}
struct Drafts(RepairProposal);
impl Healer for Drafts {
    fn propose(&self, _: &DiagnosticWorkingSet<'_>, _: &[DiagnosticEvent]) -> Vec<RepairProposal> {
        vec![self.0.clone()]
    }
}

/// Per-actor healer-submission counter and burst-check flag. Key: id16 (actor).
const COUNT: SideTable<EntityId, ActorCount, Named> =
    SideTable::new(&side_table::SELF_HEAL_HEALER_COUNT);
/// An external healer's repair proposal record and its review state. Key: id16.
const PROPOSAL: SideTable<EntityId, HealerProposalRecord, Named> =
    SideTable::new(&side_table::SELF_HEAL_HEALER_PROPOSAL);
/// A human-ratified patch pull-request record for a released healer proposal. Key: id16.
const RELEASE: SideTable<EntityId, PatchPullRequest, Named> =
    SideTable::new(&side_table::SELF_HEAL_HEALER_RELEASE);
/// Per-actor per-run healer receipt: submitted proposals and reversal state.
/// Key: id16 (actor) + bytes32 (blake3 hash of the run name).
const RUN: SideTable<(EntityId, [u8; 32]), HealerRunReceipt, Named> =
    SideTable::new(&side_table::SELF_HEAL_HEALER_RUN);

/// The digest half of a run receipt's key: a run name is unbounded text, so
/// only its blake3 hash is stored.
fn run_digest(run: &str) -> [u8; 32] {
    *blake3::hash(run.as_bytes()).as_bytes()
}
impl Vault {
    pub fn register_dev_healer(
        &self,
        deployment: HealerDeployment,
        actor: WriteActor,
    ) -> Result<HealerRegistration<'_>> {
        if deployment == HealerDeployment::EmbeddedInProcess || self.writer_lease().is_none() {
            return Err(Error::InvalidConfig(
                "dev healer requires a daemon or self-host single-writer vault".into(),
            ));
        }
        Ok(HealerRegistration {
            vault: self,
            actor,
            band: HealerBand::Dev,
        })
    }
    pub fn register_prod_healer(&self, actor: WriteActor) -> HealerRegistration<'_> {
        HealerRegistration {
            vault: self,
            actor,
            band: HealerBand::Production,
        }
    }
    pub fn healer_proposal(&self, id: &EntityId) -> Result<Option<HealerProposalRecord>> {
        let txn = self.store.env.read_txn()?;
        PROPOSAL.get(&self.store, &txn, id)
    }
    pub fn proposal_burst_check(&self, actor: &EntityId) -> Result<Option<ProposalBurstCheck>> {
        let txn = self.store.env.read_txn()?;
        Ok(COUNT.get(&self.store, &txn, actor)?.and_then(|r| r.check))
    }
    pub fn healer_run_receipt(
        &self,
        actor: &EntityId,
        run: &str,
    ) -> Result<Option<HealerRunReceipt>> {
        let txn = self.store.env.read_txn()?;
        RUN.get(&self.store, &txn, &(*actor, run_digest(run)))
    }
    /// Reversal changes the entire still-proposed run in one transaction. History stays.
    pub fn reverse_healer_run(
        &self,
        owner: &AuthenticatedOwner,
        actor: &EntityId,
        run: &str,
    ) -> Result<HealerRunReceipt> {
        self.authenticate_owner(
            owner.actor(),
            owner.principal_ref(),
            true,
            owner.decision_id(),
        )?;
        self.with_write_txn(|txn| {
            let receipt = RUN
                .get(&self.store, txn, &(*actor, run_digest(run)))?
                .ok_or(Error::EntityNotFound)?;
            if receipt.actor != *actor || receipt.run_ref != run {
                return Err(Error::CorruptedIndex("healer run key mismatch"));
            }
            reverse_receipt_in_txn(self, txn, receipt)
        })
    }
    /// Reverses all still-proposed submissions for a flagged actor, across
    /// caller-chosen run names. Every run receipt changes in one transaction.
    /// Released or denied proposals remain terminal and are never undone.
    pub fn reverse_healer_burst(
        &self,
        owner: &AuthenticatedOwner,
        check: &ProposalBurstCheck,
    ) -> Result<Vec<HealerRunReceipt>> {
        self.authenticate_owner(
            owner.actor(),
            owner.principal_ref(),
            true,
            owner.decision_id(),
        )?;
        self.with_write_txn(|txn| {
            let counter = COUNT
                .get(&self.store, txn, &check.actor)?
                .ok_or_else(|| Error::InvalidConfig("actor has no burst check".into()))?;
            if counter.check.as_ref() != Some(check) {
                return Err(Error::InvalidConfig("burst check is not current".into()));
            }
            let receipts = RUN.scan_from(&self.store, txn, check.actor.as_bytes())?;
            let mut reversed = Vec::with_capacity(receipts.len());
            for (_, receipt) in receipts {
                if receipt.actor != check.actor {
                    return Err(Error::CorruptedIndex("healer burst actor mismatch"));
                }
                reversed.push(reverse_receipt_in_txn(self, txn, receipt)?);
            }
            Ok(reversed)
        })
    }
    /// A human-ratified shipped-release PR shape. There is no apply/execute method.
    pub fn review_patch_pr(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        release: Option<&str>,
    ) -> Result<Option<PatchPullRequest>> {
        self.authenticate_owner(
            owner.actor(),
            owner.principal_ref(),
            true,
            owner.decision_id(),
        )?;
        if let Some(release) = release {
            super::validate_ref(release)?;
        }
        self.with_write_txn(|txn| {
            let mut record = PROPOSAL
                .get(&self.store, txn, id)?
                .ok_or(Error::EntityNotFound)?;
            if record.state != ProposalState::Proposed {
                return Err(Error::InvalidConfig("patch review is terminal".into()));
            }
            let (target, patch, schema) = match &record.proposal.operation {
                RepairOperation::DevPatch {
                    repo_ref,
                    patch_ref,
                } => (repo_ref.clone(), patch_ref.clone(), false),
                RepairOperation::SchemaPatch {
                    schema_ref,
                    patch_ref,
                } => (schema_ref.clone(), patch_ref.clone(), true),
                _ => return Err(Error::InvalidConfig("not a code or schema PR".into())),
            };
            let pr = release.map(|release| PatchPullRequest {
                proposal_id: *id,
                target_ref: target,
                patch_ref: patch,
                schema,
                release_ref: release.into(),
                approved_by: owner.actor(),
            });
            record.state = match release {
                Some(release) => ProposalState::Released {
                    release_ref: release.into(),
                },
                None => ProposalState::Denied,
            };
            PROPOSAL.put(&self.store, txn, id, &record)?;
            if let Some(pr) = &pr {
                RELEASE.put(&self.store, txn, id, pr)?;
            }
            Ok(pr)
        })
    }
}
fn reverse_receipt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    mut receipt: HealerRunReceipt,
) -> Result<HealerRunReceipt> {
    for id in &receipt.proposals {
        let mut record = PROPOSAL
            .get(&vault.store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        if record.state == ProposalState::Proposed {
            record.state = ProposalState::Reversed;
            PROPOSAL.put(&vault.store, txn, id, &record)?;
        }
    }
    receipt.reversed = true;
    let run_key = (receipt.actor, run_digest(&receipt.run_ref));
    RUN.put(&vault.store, txn, &run_key, &receipt)?;
    Ok(receipt)
}
impl HealerRegistration<'_> {
    /// Read-only diagnostic-band access for the external runner's identity.
    /// The receipt counts the stored events this runner may not read.
    pub fn failure_corpus(
        &self,
    ) -> Result<crate::claim::ScopedReadResult<Vec<(EntityId, DiagnosticEvent)>>> {
        let actor = crate::claim::ScopedReadActorKey::new(self.actor.entity_ref().to_hex())
            .ok_or(Error::InvalidKey)?;
        self.vault.scoped_read(actor).diagnostic_events()
    }
    pub fn submit(
        &self,
        run: &str,
        session: &str,
        proposal: RepairProposal,
    ) -> Result<RepairBundle> {
        super::validate_ref(run)?;
        if self.band == HealerBand::Production && !production_intent_allowed(self.vault, &proposal)?
        {
            return Err(Error::InvalidConfig(
                "production healer operation is outside its capability".into(),
            ));
        }
        let txn = self.vault.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &txn)?;
        let drafts = Drafts(proposal);
        let registration = RegisteredHealer {
            healer_id: "external_healer",
            actor: self.actor,
            agent_definition_ceiling: Some(crate::gate::PolicyApprovalCeiling::Proposed),
            healer: &drafts,
        };
        let bundle = run_healer_proposals(
            &policy,
            &registration,
            run,
            session,
            &DiagnosticWorkingSet {
                scope_ref: run,
                observations: &[],
            },
            &[],
        )?;
        drop(txn);
        let reviewed = &bundle.proposals()[0];
        if reviewed.route() == RepairConsentRoute::Denied {
            return Err(Error::InvalidConfig("repair admission denied".into()));
        }
        let mut proposal = reviewed.proposal().clone();
        // Persist authority attribution, not the runner's claimed actor/source.
        proposal.actor = reviewed.invocation().actor().clone();
        proposal.source = reviewed.invocation().source();
        let threshold = PROPOSAL_BURST_THRESHOLD;
        self.vault.with_write_txn(|txn| {
            let proposal_id = proposal.proposal_id;
            if PROPOSAL.contains(&self.vault.store, txn, &proposal_id)? {
                return Err(Error::InvalidConfig("proposal id already exists".into()));
            }
            let actor = self.actor.entity_ref();
            let run_key = (actor, run_digest(run));
            let mut receipt =
                RUN.get(&self.vault.store, txn, &run_key)?
                    .unwrap_or(HealerRunReceipt {
                        run_ref: run.into(),
                        actor,
                        proposals: vec![],
                        reversed: false,
                    });
            if receipt.reversed {
                return Err(Error::InvalidConfig("healer run was reversed".into()));
            }
            receipt.proposals.push(proposal_id);
            let mut counter = COUNT
                .get(&self.vault.store, txn, &actor)?
                .unwrap_or_default();
            counter.count = counter.count.saturating_add(1);
            if counter.count > threshold && counter.check.is_none() {
                counter.check = Some(ProposalBurstCheck {
                    actor,
                    count: counter.count,
                    run_ref: run.into(),
                });
            }
            PROPOSAL.put(
                &self.vault.store,
                txn,
                &proposal_id,
                &HealerProposalRecord {
                    proposal,
                    state: ProposalState::Proposed,
                    run_ref: run.into(),
                },
            )?;
            RUN.put(&self.vault.store, txn, &run_key, &receipt)?;
            COUNT.put(&self.vault.store, txn, &actor, &counter)?;
            Ok(())
        })?;
        Ok(bundle)
    }
}

fn protected_target(target: &str) -> bool {
    // Refs are opaque text, not predicates. Treat every non-identifier byte as
    // a namespace boundary, including slash and backslash. Percent syntax is
    // refused outright: encoded separators or identifier bytes are ambiguous.
    // Reserved components stay protected even behind a path or URI prefix.
    if target.contains('%') {
        return true;
    }
    target
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|component| {
            ["engine", "soul", "core"]
                .iter()
                .any(|reserved| component.eq_ignore_ascii_case(reserved))
        })
}
fn production_intent_allowed(vault: &Vault, proposal: &RepairProposal) -> Result<bool> {
    if protected_target(&proposal.target_predicate) {
        return Ok(false);
    }
    match &proposal.operation {
        RepairOperation::DevPatch { .. }
        | RepairOperation::SchemaPatch { .. }
        | RepairOperation::SkillEdit { .. } => Ok(false),
        RepairOperation::Reindex { scope_ref } => Ok(!protected_target(scope_ref)),
        RepairOperation::Rescore { target_ref } => {
            let Some(raw) = vault.get_raw(target_ref)? else {
                return Ok(false);
            };
            let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
                return Ok(false);
            };
            // Only ordinary memory entities may be rescored. Maintenance and policy
            // records cannot be smuggled through a benign target_predicate label.
            if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                return Ok(vault
                    .get_claim(target_ref)?
                    .is_some_and(|claim| !protected_target(&claim.predicate)));
            }
            Ok(header.entity_type == crate::registry::ENTITY_TYPE_SUMMARY)
        }
        RepairOperation::Retry { run_ref } => Ok(!protected_target(run_ref)),
        RepairOperation::NarrowPolicy { predicate, .. }
        | RepairOperation::ProposeClaim { predicate, .. } => Ok(!protected_target(predicate)),
    }
}
