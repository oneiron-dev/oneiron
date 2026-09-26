//! Lease-fenced, case-bound fix-agent proposals from dispatched healers.

use crate::agent_def::AgentCeiling;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use crate::claim::ClaimSource;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::failure_ladder::HealerRepairRoute;
use crate::self_heal::healer_host::CaseBinding;
use crate::self_heal::{RepairActor, RepairBundle, RepairOperation, RepairProposal};
use crate::write_envelope::WriteActor;

use super::{AgentDispatchTarget, AgentDispatcher, codec::record_dispatch_input};

impl AgentDispatcher<'_> {
    /// Emits one gated, review-only repair intent from a leased healer.
    ///
    /// This trusted host door takes the live lease fence, never a case supplied
    /// by the healer. It binds the route to the durable failed attempt and
    /// rechecks the lease, case and live ceiling in the proposal transaction.
    /// No route executes a patch, restarts a task or changes an agent definition.
    pub fn propose_healer_repair(
        &self,
        healer_attempt_id: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
        proposal_id: EntityId,
        route: HealerRepairRoute,
        session_tag: &str,
    ) -> Result<RepairBundle> {
        let invalid = || Error::InvalidConfig("fix-agent proposal requires a leased healer".into());
        let record = AttemptQueue::new(self.vault)
            .get(healer_attempt_id)?
            .ok_or_else(invalid)?;
        if record.state != AttemptState::Leased
            || record.lease_owner.as_deref() != Some(lease_owner)
            || record.attempt_count != attempt_count
        {
            return Err(invalid());
        }
        let input = record_dispatch_input(&record).ok_or_else(invalid)?;
        let case = input.healer_case.ok_or_else(invalid)?;
        let healer_ref = match input.target {
            AgentDispatchTarget::Custom(id) => id,
            AgentDispatchTarget::Workflow(_) => return Err(invalid()),
        };
        let definition = self.dispatchable_definition(&AgentDispatchTarget::Custom(healer_ref))?;
        if definition.ceiling != AgentCeiling::Proposed {
            return Err(invalid());
        }
        crate::genui::require_diagnosed_route(
            self.vault,
            case.failing_attempt_id,
            EntityId::from_hex(&case.pre_fail_checkpoint_ref)?,
            &route,
        )?;
        let diagnostic = EntityId::from_hex(&case.evidence_ref)?;
        let actor = WriteActor::new(healer_ref, EdgeActorClass::Agent);
        let proposal = RepairProposal {
            proposal_id,
            diagnostic_refs: vec![diagnostic],
            actor: RepairActor {
                actor_class: "agent".into(),
                actor_ref: healer_ref,
            },
            source: ClaimSource::Generated,
            target_predicate: "maintenance.healer".into(),
            operation: RepairOperation::FixAgent {
                case_ref: case.case_ref.clone(),
                route,
            },
            session_tag: session_tag.into(),
        };
        let run_ref = case.case_ref.clone();
        self.vault.register_prod_healer(actor).submit_case_bound(
            &run_ref,
            session_tag,
            proposal,
            CaseBinding {
                healer_attempt_id,
                lease_owner: lease_owner.into(),
                attempt_count,
                healer_ref,
                case,
            },
        )
    }
}
