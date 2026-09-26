//! External healer capability, durable propose receipts, and human-only PR release.
use super::{
    DiagnosticEvent, DiagnosticWorkingSet, Healer, RepairBundle, RepairConsentRoute,
    RepairOperation, RepairProposal,
    repair::{RegisteredHealer, run_healer_proposals},
};
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
/// Trusted host binding, rechecked alongside proposal persistence.
pub(crate) struct CaseBinding {
    pub(crate) healer_attempt_id: crate::attempt_queue::AttemptId,
    pub(crate) lease_owner: String,
    pub(crate) attempt_count: u32,
    pub(crate) healer_ref: EntityId,
    pub(crate) case: crate::failure_ladder::HealerCase,
}

impl CaseBinding {
    fn require_in_txn(&self, vault: &Vault, txn: &heed::RwTxn<'_>) -> Result<()> {
        use crate::attempt_queue::{AttemptQueue, AttemptState};
        let invalid =
            || Error::InvalidConfig("healer repair requires a live case-bound lease".into());
        let record = AttemptQueue::new(vault)
            .get_in_write_txn(txn, self.healer_attempt_id)?
            .ok_or_else(invalid)?;
        if record.state != AttemptState::Leased
            || record.lease_owner.as_deref() != Some(&self.lease_owner)
            || record.attempt_count != self.attempt_count
        {
            return Err(invalid());
        }
        let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)
            .map_err(|_| invalid())?;
        if payload.attempt_type != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE
            || payload.parent_attempt != Some(self.case.failing_attempt_id)
        {
            return Err(invalid());
        }
        let dispatch = crate::agent_dispatch::decode_agent_dispatch_input(&payload.input)
            .map_err(|_| invalid())?;
        if dispatch.healer_case.as_ref() != Some(&self.case)
            || dispatch.target.agent_definition_ref().ok() != Some(self.healer_ref)
        {
            return Err(invalid());
        }
        crate::failure_ladder::require_healer_case_in_txn(
            vault,
            txn,
            &self.case,
            record.run_id.as_deref(),
        )?;
        let definition = crate::agent_dispatch::AgentDispatcher::new(vault)
            .dispatchable_definition_in_txn(txn, &dispatch.target)?;
        if definition.ceiling != crate::agent_def::AgentCeiling::Proposed {
            return Err(invalid());
        }
        Ok(())
    }
}
struct Drafts(RepairProposal);
impl Healer for Drafts {
    fn propose(&self, _: &DiagnosticWorkingSet<'_>, _: &[DiagnosticEvent]) -> Vec<RepairProposal> {
        vec![self.0.clone()]
    }
}
fn key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    [prefix, suffix].concat()
}
fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(v).map_err(|_| Error::InvariantViolation("healer receipt encode"))
}
fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("healer receipt"))
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
        self.store
            .vault_meta
            .get(&txn, &key(b"healer:proposal:", id.as_bytes()))?
            .map(|b| decode(&b))
            .transpose()
    }
    pub fn proposal_burst_check(&self, actor: &EntityId) -> Result<Option<ProposalBurstCheck>> {
        let txn = self.store.env.read_txn()?;
        let row: Option<ActorCount> = self
            .store
            .vault_meta
            .get(&txn, &key(b"healer:count:", actor.as_bytes()))?
            .map(|b| decode(&b))
            .transpose()?;
        Ok(row.and_then(|r| r.check))
    }
    pub fn healer_run_receipt(
        &self,
        actor: &EntityId,
        run: &str,
    ) -> Result<Option<HealerRunReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &run_key(actor, run))?
            .map(|b| decode(&b))
            .transpose()
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
            let rk = run_key(actor, run);
            let raw = self
                .store
                .vault_meta
                .get(txn, &rk)?
                .ok_or(Error::EntityNotFound)?;
            let receipt: HealerRunReceipt = decode(&raw)?;
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
            let count_key = key(b"healer:count:", check.actor.as_bytes());
            let row = self
                .store
                .vault_meta
                .get(txn, &count_key)?
                .ok_or_else(|| Error::InvalidConfig("actor has no burst check".into()))?;
            let counter: ActorCount = decode(&row)?;
            if counter.check.as_ref() != Some(check) {
                return Err(Error::InvalidConfig("burst check is not current".into()));
            }
            let prefix = key(b"healer:run:", check.actor.as_bytes());
            let receipts: Vec<HealerRunReceipt> = self
                .store
                .vault_meta
                .prefix_iter(txn, &prefix)?
                .map(|row| {
                    let (_, raw) = row?;
                    decode(&raw)
                })
                .collect::<Result<_>>()?;
            let mut reversed = Vec::with_capacity(receipts.len());
            for receipt in receipts {
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
            let pk = key(b"healer:proposal:", id.as_bytes());
            let raw = self
                .store
                .vault_meta
                .get(txn, &pk)?
                .ok_or(Error::EntityNotFound)?;
            let mut record: HealerProposalRecord = decode(&raw)?;
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
            self.store.vault_meta.put(txn, &pk, &encode(&record)?)?;
            if let Some(pr) = &pr {
                self.store.vault_meta.put(
                    txn,
                    &key(b"healer:release:", id.as_bytes()),
                    &encode(pr)?,
                )?;
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
        let pk = key(b"healer:proposal:", id.as_bytes());
        let raw = vault
            .store
            .vault_meta
            .get(txn, &pk)?
            .ok_or(Error::EntityNotFound)?;
        let mut record: HealerProposalRecord = decode(&raw)?;
        if record.state == ProposalState::Proposed {
            record.state = ProposalState::Reversed;
            vault.store.vault_meta.put(txn, &pk, &encode(&record)?)?;
        }
    }
    receipt.reversed = true;
    vault.store.vault_meta.put(
        txn,
        &run_key(&receipt.actor, &receipt.run_ref),
        &encode(&receipt)?,
    )?;
    Ok(receipt)
}
fn run_key(actor: &EntityId, run: &str) -> Vec<u8> {
    let mut k = key(b"healer:run:", actor.as_bytes());
    k.extend_from_slice(blake3::hash(run.as_bytes()).as_bytes());
    k
}
impl HealerRegistration<'_> {
    /// Read-only diagnostic-band access for the external runner's identity.
    pub fn failure_corpus(&self) -> Result<Vec<(EntityId, DiagnosticEvent)>> {
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
        self.submit_checked(run, session, proposal, None)
    }

    pub(crate) fn submit_case_bound(
        &self,
        run: &str,
        session: &str,
        proposal: RepairProposal,
        binding: CaseBinding,
    ) -> Result<RepairBundle> {
        self.submit_checked(run, session, proposal, Some(binding))
    }

    fn submit_checked(
        &self,
        run: &str,
        session: &str,
        proposal: RepairProposal,
        binding: Option<CaseBinding>,
    ) -> Result<RepairBundle> {
        super::validate_ref(run)?;
        if binding
            .as_ref()
            .is_some_and(|b| b.case.case_ref != run || b.healer_ref != self.actor.entity_ref())
        {
            return Err(Error::InvalidConfig(
                "healer repair binding mismatch".into(),
            ));
        }
        let case_bound = binding.as_ref().is_some_and(|b| {
            matches!(
                &proposal.operation,
                RepairOperation::FixAgent { case_ref, .. } if *case_ref == b.case.case_ref
            )
        });
        if matches!(proposal.operation, RepairOperation::FixAgent { .. }) && !case_bound {
            return Err(Error::InvalidConfig(
                "fix-agent repair requires a case-bound healer".into(),
            ));
        }
        if self.band == HealerBand::Production
            && !production_intent_allowed(self.vault, &proposal, case_bound)?
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
            if let Some(binding) = &binding {
                binding.require_in_txn(self.vault, txn)?;
            }
            let pk = key(b"healer:proposal:", proposal.proposal_id.as_bytes());
            if self.vault.store.vault_meta.get(txn, &pk)?.is_some() {
                return Err(Error::InvalidConfig("proposal id already exists".into()));
            }
            let actor = self.actor.entity_ref();
            let rk = run_key(&actor, run);
            let ck = key(b"healer:count:", actor.as_bytes());
            let mut receipt: HealerRunReceipt = self
                .vault
                .store
                .vault_meta
                .get(txn, &rk)?
                .map(|b| decode(&b))
                .transpose()?
                .unwrap_or(HealerRunReceipt {
                    run_ref: run.into(),
                    actor,
                    proposals: vec![],
                    reversed: false,
                });
            if receipt.reversed {
                return Err(Error::InvalidConfig("healer run was reversed".into()));
            }
            receipt.proposals.push(proposal.proposal_id);
            let mut counter: ActorCount = self
                .vault
                .store
                .vault_meta
                .get(txn, &ck)?
                .map(|b| decode(&b))
                .transpose()?
                .unwrap_or_default();
            counter.count = counter.count.saturating_add(1);
            if counter.count > threshold && counter.check.is_none() {
                counter.check = Some(ProposalBurstCheck {
                    actor,
                    count: counter.count,
                    run_ref: run.into(),
                });
            }
            self.vault.store.vault_meta.put(
                txn,
                &pk,
                &encode(&HealerProposalRecord {
                    proposal,
                    state: ProposalState::Proposed,
                    run_ref: run.into(),
                })?,
            )?;
            self.vault
                .store
                .vault_meta
                .put(txn, &rk, &encode(&receipt)?)?;
            self.vault
                .store
                .vault_meta
                .put(txn, &ck, &encode(&counter)?)?;
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
fn production_intent_allowed(
    vault: &Vault,
    proposal: &RepairProposal,
    case_bound: bool,
) -> Result<bool> {
    if protected_target(&proposal.target_predicate) {
        return Ok(false);
    }
    match &proposal.operation {
        RepairOperation::DevPatch { .. }
        | RepairOperation::SchemaPatch { .. }
        | RepairOperation::SkillEdit { .. } => Ok(false),
        RepairOperation::FixAgent { .. } => Ok(case_bound),
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
