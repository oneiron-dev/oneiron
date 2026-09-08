//! Second OffRecordSession block: executor witness doors, routed shells and executor traps.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::session_overlay::{RouteTarget, SessionWriteRoute};

use super::session::OffRecordSession;
use super::types::ExecutorUtterance;

/// Session-bound EXECUTOR surfaces (ONE-1729/P4b).
///
/// Everything a session-bound code run needs that is not already an ordinary
/// session accessor, gathered where the private `&Vault` borrow lives. The
/// executor holds a typed session handle and nothing else: no vault getter,
/// no raw store, no second [`Vault`] clone. Post-flip writes are ORDINARY
/// base writes — the room is on record — so they run the same trap functions
/// a canonical run runs, reached through [`Self::base_write_vault`], which
/// never leaves this module.
impl OffRecordSession<'_> {
    /// Witnesses ONE executor turn through ONE-1728's facade door.
    ///
    /// Guest-supplied turn identity meets a TYPED PRE-CONSTRUCTION REFUSAL
    /// (owner ruling R-20260807-02): `turn_ref` `Some(_)` returns
    /// [`Error::OffRecordGuestTurnRefRejected`] before a `WitnessTurn` is
    /// formed — zero overlay/base delta, zero gate decisions — and the rule
    /// holds in BOTH modes, because a room that flipped on record is still
    /// not a place where a guest names turns. `None` is the only passing
    /// value on this surface. Deterministic executor retries use the distinct
    /// crate-private [`Self::witness_host_executor_turn`] capability below;
    /// they do not weaken or special-case this refusal.
    ///
    /// `route` is the caller's RUN-ENTRY route, revalidated here so a mid-run
    /// flip refuses the turn outright rather than letting the door mint a
    /// fresh route and publish across the flip.
    ///
    /// The shell is the session's own (rider 1); the door re-resolves it from
    /// the session on both arms, so `container` cannot redirect the turn — it
    /// states, at the call site, the identity the door will use.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the guest turn-ref refusal is a preserved contract exercised by the branch-store oracle"
        )
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "every parameter is a distinct binding the refusal or the door needs; folding \
                  them into a struct would hide which one the typed refusal reads"
    )]
    ///
    /// `order` is the caller's position for this bubble. A run that emits
    /// several utterances in one executor step passes its bridge ordering
    /// here, so the bubbles carry the interleaving they actually had; a
    /// standalone turn passes `0`.
    pub(crate) fn witness_executor_turn(
        &self,
        container: &EntityId,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
        order: u32,
        message_id: Option<EntityId>,
        turn_ref: Option<&EntityId>,
        route: &SessionWriteRoute,
        actor: crate::WriteActor,
    ) -> Result<crate::memory::WitnessReceipt> {
        if turn_ref.is_some() {
            return Err(Error::OffRecordGuestTurnRefRejected {
                session_ref: self.session_ref.clone(),
            });
        }
        self.witness_bound_executor_turn(
            container,
            kind,
            text,
            occurred_at,
            order,
            message_id,
            None,
            route,
            actor,
        )
    }

    /// Host-only deterministic executor turn path.
    ///
    /// Unlike [`Self::witness_executor_turn`], there is no guest `Option` to
    /// accept or reject. Both ids are derived inside the bound executor from
    /// its run identity, then carried through this distinct crate-private
    /// capability so a retry can create-or-verify one TURN and one MESSAGE
    /// without weakening `OffRecordGuestTurnRefRejected`.
    #[expect(
        clippy::too_many_arguments,
        reason = "every parameter is a host-bound witness axis; the separate function is the turn-ref capability"
    )]
    pub(crate) fn witness_host_executor_turn(
        &self,
        container: &EntityId,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
        order: u32,
        message_id: EntityId,
        turn_ref: EntityId,
        route: &SessionWriteRoute,
        actor: crate::WriteActor,
    ) -> Result<crate::memory::WitnessReceipt> {
        self.witness_bound_executor_turn(
            container,
            kind,
            text,
            occurred_at,
            order,
            Some(message_id),
            Some(turn_ref),
            route,
            actor,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "internal join point keeps the guest refusal and host capability on distinct public paths"
    )]
    fn witness_bound_executor_turn(
        &self,
        container: &EntityId,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
        order: u32,
        message_id: Option<EntityId>,
        host_turn_ref: Option<EntityId>,
        route: &SessionWriteRoute,
        actor: crate::WriteActor,
    ) -> Result<crate::memory::WitnessReceipt> {
        route.revalidate()?;
        let memory = self.vault.memory(actor.entity_ref(), actor.actor_class());
        let turn = crate::memory::WitnessTurn {
            conversation_ref: container.to_hex(),
            turn_ref: None,
            messages: vec![crate::memory::WitnessMessage {
                // HOST-derived when present (ONE-1686): the executor names the
                // bubble from its run/order identity. Guest callers cannot
                // reach this parameter.
                id: message_id.map(|id| id.to_hex()),
                author: crate::memory::WitnessAuthor::Companion,
                message_type: kind.as_message_type().to_owned(),
                content: text.to_owned(),
                metadata: None,
                is_visible: kind.is_visible(),
                order,
            }],
            occurred_at,
        };
        let result = match host_turn_ref {
            Some(turn_ref) => {
                memory.witness_into_session_with_host_turn(self, &turn, None, turn_ref)
            }
            None => memory.witness_into_session(self, &turn, None),
        };
        result
            // The door reports a code+message `MemoryError`. A CEILING refusal
            // is a policy verdict the caller must be able to route on, so it
            // travels back out as the typed gate denial it was (ONE-1686) —
            // flattening it into an invariant violation would turn "the owner's
            // policy refused this bubble" into "the engine is broken". Every
            // other refusal this entry OWNS is raised typed above, and the turn
            // is built here from executor-controlled parts, so anything else
            // the door rejects does mean an executor-side invariant broke.
            .map_err(|error| {
                error
                    .gate_denial_error()
                    .unwrap_or(Error::InvariantViolation(
                        "executor witness door rejected the session turn",
                    ))
            })
    }

    /// The conversation shell this run's turns ride, for `route`'s mode.
    ///
    /// Off record it is the ROOM's shell, created at session entry (rider 1);
    /// on record it is the session's continuation shell, deliberately a
    /// different conversation so a base row never references an overlay
    /// member. Either way the session machinery owns it — the executor reads
    /// it, never mints it.
    pub(crate) fn routed_conversation_shell(&self, route: &SessionWriteRoute) -> Result<EntityId> {
        match route.target() {
            RouteTarget::Overlay => self.overlay_conversation_shell(),
            RouteTarget::Base => self.on_record_continuation_shell(),
        }
    }

    /// The owning vault for a write the route says is ORDINARY.
    ///
    /// MODULE-PRIVATE on purpose: it is the one place a `&Vault` is produced
    /// from a session handle, and it produces one only under a revalidated
    /// `Base` route — the sole evidence the room went on record. An `Overlay`
    /// route means the caller reached a durable write while off record, which
    /// the effect policy is supposed to have refused first.
    fn base_write_vault(&self, route: &SessionWriteRoute) -> Result<&Vault> {
        route.revalidate()?;
        match route.target() {
            RouteTarget::Base => Ok(self.vault),
            RouteTarget::Overlay => Err(Error::OffRecordTalkOnly {
                session_ref: self.session_ref.clone(),
            }),
        }
    }

    /// Write-path gate check for a session-bound code run's durable write.
    pub(crate) fn executor_check_write_gate(
        &self,
        route: &SessionWriteRoute,
        id: EntityId,
        body: &crate::ClaimBody,
        envelope: &crate::WriteEnvelope,
        can_resolve_pending_consent: bool,
    ) -> Result<()> {
        let vault = self.base_write_vault(route)?;
        crate::code_run::check_write_gate_against_vault(
            vault,
            id,
            body,
            envelope,
            can_resolve_pending_consent,
        )
    }

    /// `self.memory.write_fixture` on a session-bound run.
    pub(crate) fn executor_batch_claim_candidate(
        &self,
        route: &SessionWriteRoute,
        id: &EntityId,
        candidate: crate::ClaimCandidate,
        envelope: &crate::WriteEnvelope,
        occurred: crate::TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.base_write_vault(route)?
            .batch()
            .claim_candidate(id, candidate, envelope, occurred, learned_at)
            .commit()
    }

    /// `self.memory.put_claim` on a session-bound run.
    pub(crate) fn executor_put_claim_candidate(
        &self,
        route: &SessionWriteRoute,
        id: &EntityId,
        candidate: crate::ClaimCandidate,
        envelope: &crate::WriteEnvelope,
        occurred: crate::TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.base_write_vault(route)?
            .put_claim_candidate_without_lexical_query_reconcile(
                id, candidate, envelope, occurred, learned_at,
            )
    }

    /// `self.memory.supersede_claim` on a session-bound run. ONE-1936's
    /// stale-target guard lives INSIDE this trap and stays authoritative
    /// there; this only chooses the route.
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the canonical supersede trap arity exactly"
    )]
    pub(crate) fn executor_supersede_claim(
        &self,
        route: &SessionWriteRoute,
        new_id: &EntityId,
        old_id: &EntityId,
        now: u64,
        envelope: &crate::WriteEnvelope,
        claim_gate_id: EntityId,
        claim_gate_body: &crate::ClaimBody,
        edge_gate_id: EntityId,
        edge_gate_body: &crate::ClaimBody,
    ) -> Result<()> {
        self.base_write_vault(route)?
            .supersede_claim_for_code_run_trap(
                new_id,
                old_id,
                now,
                envelope,
                claim_gate_id,
                claim_gate_body,
                edge_gate_id,
                edge_gate_body,
            )
    }

    /// `self.memory.put_edge` on a session-bound run.
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the canonical put-edge trap arity exactly"
    )]
    pub(crate) fn executor_put_edge(
        &self,
        route: &SessionWriteRoute,
        src: &EntityId,
        kind: crate::EdgeKind,
        tgt: &EntityId,
        weight: f32,
        envelope: &crate::WriteEnvelope,
        gate_id: EntityId,
        gate_body: &crate::ClaimBody,
    ) -> Result<()> {
        self.base_write_vault(route)?
            .put_edge_for_code_run_trap(src, kind, tgt, weight, envelope, gate_id, gate_body)
    }
}
