//! The four durable memory writes, search, and the off-record policy that refuses them.

use rmpv::Value;

use crate::claim::{ClaimReadStatus, ScopedReadActorKey};
use crate::code_run::consent;
use crate::code_run::storage::{ExecutorStorage, require_facet_placement_in, unplaceable};
use crate::code_run::types::{
    SelfCall, SelfDispatchOutcome, SelfEffect, SelfMemoryEdgeWriteResult, SelfMemoryPutClaimCall,
    SelfMemoryPutEdgeCall, SelfMemorySearchCall, SelfMemorySearchResult,
    SelfMemorySupersedeClaimCall, SelfMemoryWriteFixtureCall, SelfMemoryWriteResult,
};
use crate::error::{Error, Result};
use crate::{ClaimSubject, EdgeActorClass, EdgeKind, EntityId, ScoredEntity, Vault};
use oneiron_base::edge::kind_tables::ensure_public_memory_edge_kind;

use super::envelope::edge_operation_gate_id;
use super::read_worlds::{ServedRows, served_row_in};
use super::{ExecutorCallSite, HostSelfDispatcher};
use crate::error::{CodeError, OffRecordError};

/// Maximum results a first-party `vault.search` call can request.
pub const SELF_MEMORY_SEARCH_MAX_RESULTS: usize = 16;

impl HostSelfDispatcher<'_> {
    /// Effect-level off-record policy — the FIRST check on the session path.
    ///
    /// While the bound room is off record, the durable memory-write verbs
    /// that would reach base are refused before `write_envelope`, policy/gate
    /// evaluation, transaction acquisition, decision append, ONE-1936's
    /// stale-target guard, or any overlay/base mutation. A claim put, a
    /// fixture claim and a NOTE or claim verb forward are the exception the
    /// Engine ruled for DOOR-127 (10-18, ARCH-0052 D1/D2): written through
    /// the session's handle, they are ephemeral writes that stage in the
    /// room's overlay, under its byte budget, and close drops them. Nothing
    /// they write reaches base.
    ///
    /// The rejection is mode-scoped POLICY, never inferred from where a row
    /// would route: after the same live session flips `OnRecord` the ordinary
    /// verb path is available again to a run that binds after the flip. A run
    /// that was already in flight keeps its run-entry route, whose
    /// `revalidate` refuses the write instead of splitting the record across
    /// the flip.
    ///
    /// An anonymous room keeps no memory (ARCH-0052), so it serves only a
    /// call that keeps nothing: the run's own search, a context descriptor,
    /// and the five reads its room's view answers (FIX 5166). The rule reads
    /// the whole `call`, not only its effect: an `AgentVerb` read passes
    /// only when [`Self::room_session_read`] routes it to
    /// `dispatch_session_read`, never because its verb writes nothing.
    ///
    /// The match is exhaustive so a new effect cannot default into either
    /// answer — it has to be ruled on here.
    pub(super) fn enforce_off_record_effect_policy(&self, call: &SelfCall) -> Result<()> {
        let effect = call.effect();
        // Anonymous permits only calls with no transcript or mandatory
        // audit. Do not execute destructive/outbound/approval effects while
        // silently dropping the evidence their ordinary doors require. A
        // room read's retrieval telemetry and its hooks' records take the
        // room's Discard route (FIX 5166).
        if !matches!(call, SelfCall::MemorySearch(_) | SelfCall::Context(_))
            && self.room_session_read(call).is_none()
            && let ExecutorStorage::Session(binding) = &self.storage
        {
            binding
                .route
                .require_recording(binding.session.session_ref())?;
        }
        if !self.storage.off_record_policy_active()? {
            return Ok(());
        }
        match effect {
            // Delegation mints a synced TASK entity, so it lands on the
            // durable-record side of the talk-only line with the memory writes.
            SelfEffect::MemorySupersedeClaim
            | SelfEffect::MemoryPutEdge
            | SelfEffect::ReportBlocked
            | SelfEffect::InferenceDefaultsRead
            | SelfEffect::InferenceDefaultsReplace
            | SelfEffect::WakePolicyWrite
            | SelfEffect::ConnectorAnswer
            // A world's settings, a proposal or an ask are canonical rows.
            | SelfEffect::WorldPrivacySet
            | SelfEffect::AgentsSpawn
            | SelfEffect::AgentsPut
            | SelfEffect::TasksAsk
            | SelfEffect::TasksWait
            | SelfEffect::TasksRefuse
            // A consult's landing settles a canonical TASK.
            | SelfEffect::ConsultResult
            // A callable skill loads against the canonical vault and the
            // running attempt's lease, and records its invocation there.
            | SelfEffect::SkillsCall
            // Leader advice and a pattern load read the canonical vault on
            // the leader's lease and stamp her attempt's manifest there.
            | SelfEffect::Leader
            // A split mints a canonical PROJECT and links her TASK to it.
            | SelfEffect::LeaderSplit
            // A team spawns canonical children and writes a canonical receipt.
            | SelfEffect::Team
            // A bound workflow run queues canonical attempts and takes a
            // canonical TASK.
            | SelfEffect::WorkflowDispatch
            // The run repo rows read and write canonical repo rows under the
            // run's lease: none copies a room's content to base (FIX 6867).
            | SelfEffect::RepoSnapshotsGet
            | SelfEffect::RepoSnapshotsRead
            | SelfEffect::RepoSymbolsDefinitions
            | SelfEffect::RepoViewsGet
            | SelfEffect::RepoViewsRead
            | SelfEffect::RepoMergeQueueObserve
            | SelfEffect::RepoSnapshotsIngest
            | SelfEffect::RepoWorkOpen
            | SelfEffect::RepoSymbolsDeclare
            | SelfEffect::RepoSymbolsRenew
            | SelfEffect::RepoSymbolsRelease
            | SelfEffect::RepoProposalSubmit
            | SelfEffect::RepoMergeQueueEnqueue
            | SelfEffect::RepoCheckoutBind
            | SelfEffect::RepoExport
            | SelfEffect::TaskDelegate => {
                Err(Error::OffRecord(OffRecordError::OffRecordTalkOnly {
                    session_ref: self.storage.session_ref().unwrap_or_default().to_owned(),
                }))
            }
            // `self.context` stores nothing and reads nothing — a descriptor
            // round-trip has no durable-record side for the talk-only line to
            // protect.
            //
            // The speech family is what TALK-ONLY means: a room that is off
            // record is still a room somebody is speaking in, and its
            // utterances ride the session's own route into the overlay, where
            // they evaporate with it. Refusing them here would make an
            // off-record room mute rather than private.
            //
            // DOOR-127: a claim put and a fixture claim stage in the room's
            // overlay (`OffRecordSession::stage_session_claim`). A verb
            // forward reaches `dispatch_agent_verb`, which writes a NOTE or a
            // claim into the room, reads the five session reads through its
            // view, and refuses every other verb, whose door runs against
            // the canonical vault.
            SelfEffect::MemoryPutClaim
            | SelfEffect::MemoryWriteFixture
            | SelfEffect::AgentVerb
            | SelfEffect::MemorySearch
            | SelfEffect::Ask
            | SelfEffect::DestructiveFixture
            | SelfEffect::OutboundFixture
            | SelfEffect::Context
            | SelfEffect::Speak
            | SelfEffect::Think
            | SelfEffect::Express
            // A fold is the run's own view of its own log: its ledger rides
            // the room's route into the overlay and evaporates with it.
            | SelfEffect::Fold
            // A reader child, its finding and a wait over children are the
            // run's own job rows on the same route: they evaporate with the
            // room, and their spend scopes hold units and ids, no content.
            | SelfEffect::ReaderSpawn
            | SelfEffect::ReaderReport
            | SelfEffect::TasksWaitSet
            // A summary is one more job row of the run on the same route,
            // its memo row beside it, and its text a result of the job's run
            // there: all of it evaporates with the room.
            | SelfEffect::Summarize => Ok(()),
        }
    }

    /// A search its door admitted with a key reads on that key's lane: in a
    /// room, the room's view on that lane (WILL L11-01). One with no key
    /// reads the whole text index, and an agent's or the system's keeps only
    /// the hits its actor reads by its own entry, as a keyed one does
    /// (`own_entry_kept`). In a room the verb hooks bound to it run around
    /// it, keyed or not, and what each did joins its answer as they leave
    /// (`verb_hooks::session`). An executor run's search on the vault notes
    /// the world of each hit it serves in the run's ledger (FIX 6130).
    pub(super) fn dispatch_memory_search(
        &self,
        call: SelfMemorySearchCall,
        read_as: Option<ScopedReadActorKey>,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        let limit = call.limit.min(SELF_MEMORY_SEARCH_MAX_RESULTS);
        let results = match (&self.storage, site) {
            (ExecutorStorage::Canonical(vault), Some(site)) => {
                self.search_noting_worlds(vault, site, &call.query, limit, read_as)?
            }
            _ => match read_as {
                Some(reader) => {
                    let claims = self.keyed_claims();
                    self.storage
                        .search_text_as(&call.query, limit, reader, claims)?
                }
                None => self.own_entry_hits(self.storage.search_text(&call.query, limit)?)?,
            },
        };
        Ok(SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
            query: call.query,
            results,
            hooks: Vec::new(),
        }))
    }

    /// The claim statuses a keyed search keeps: every status where the door
    /// filters by the key's authorization alone (FIX 5976).
    fn keyed_claims(&self) -> ClaimReadStatus {
        match &self.agent_verbs {
            Some(door) if !door.keyed_search_surfaceable_only() => ClaimReadStatus::Recorded,
            _ => ClaimReadStatus::Surfaceable,
        }
    }

    /// [`Self::dispatch_memory_search`]'s read on the vault for the executor
    /// run at `site`, serving the same hits: each hit's world proved in the
    /// read that scored it and, for a keyed search, in the read that admitted
    /// it, then noted in the run's ledger (FIX 6130).
    fn search_noting_worlds(
        &self,
        vault: &Vault,
        site: ExecutorCallSite<'_>,
        query: &str,
        limit: usize,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<Vec<ScoredEntity>> {
        let mut scored = ServedRows::new();
        let hits = vault.search_text_observed(query, limit, |txn, hits| {
            scored = hits
                .iter()
                .map(|hit| (hit.id, served_row_in(vault, txn, hit.id)))
                .collect();
        })?;
        let (hits, admitted) = match read_as {
            Some(reader) => {
                let mut admitted = ServedRows::new();
                let hits = vault
                    .scoped_read(reader)
                    .with_claim_status(self.keyed_claims())
                    .filter_scored_entities_observed(hits, None, |txn, id| {
                        admitted.insert(id, served_row_in(vault, txn, id));
                    })?
                    .value;
                (hits, Some(admitted))
            }
            None => (self.own_entry_hits(hits)?, None),
        };
        self.note_search_worlds(site, &hits, &scored, admitted.as_ref());
        Ok(hits)
    }

    /// The no-key search's hits an agent or the system reads by its own
    /// entry, as a person's own read does (FIX 6488, the owner's
    /// ROOM-HISTORY ruling of FIX 5861): a room row from before it joined
    /// drops out. Any other actor keeps every hit.
    fn own_entry_hits(&self, hits: Vec<ScoredEntity>) -> Result<Vec<ScoredEntity>> {
        if hits.is_empty()
            || !matches!(
                self.actor.actor_class(),
                EdgeActorClass::Agent | EdgeActorClass::System
            )
        {
            return Ok(hits);
        }
        let reader = self.actor.entity_ref();
        match &self.storage {
            ExecutorStorage::Canonical(vault) => {
                let txn = vault.store.env.read_txn()?;
                own_entry_kept(vault, &txn, hits, reader, |id| {
                    crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, id)
                })
            }
            ExecutorStorage::Session(binding) => {
                binding.session.read_composed_in_vault(|vault, view, txn| {
                    own_entry_kept(vault, txn, hits, reader, |id| {
                        crate::ports::EntityStoreRead::port_entity_raw(view, txn, id)
                    })
                })
            }
        }
    }

    pub(super) fn dispatch_memory_write_fixture(
        &self,
        call: SelfMemoryWriteFixtureCall,
    ) -> Result<SelfDispatchOutcome> {
        let admission = self.code_emission_admission()?;
        let candidate = match admission
            .as_ref()
            .and_then(|admission| admission.candidate_evidence.clone())
        {
            Some(evidence) => (*call.candidate).clone().with_evidence(evidence),
            None => *call.candidate,
        };
        let envelope = self.write_envelope(SelfEffect::MemoryWriteFixture, admission.as_ref())?;
        let predicate = candidate.predicate().to_owned();
        match &self.storage {
            ExecutorStorage::Canonical(vault) => vault
                .batch()
                .claim_candidate(
                    &call.id,
                    candidate,
                    &envelope,
                    call.occurred,
                    call.learned_at,
                )
                .commit_with_target_guard(|txn| {
                    vault.validate_code_run_claim_target_in_txn(txn, &call.id, Some(&predicate))
                })?,
            ExecutorStorage::Session(binding) => {
                binding.session.executor_batch_claim_candidate(
                    &binding.route,
                    &call.id,
                    candidate,
                    &envelope,
                    call.occurred,
                    call.learned_at,
                )?;
            }
        }

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.id,
        }))
    }

    pub(super) fn dispatch_memory_put_claim(
        &self,
        call: SelfMemoryPutClaimCall,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<SelfDispatchOutcome> {
        let admission = self.code_emission_admission()?;
        let candidate = match admission
            .as_ref()
            .and_then(|admission| admission.candidate_evidence.clone())
        {
            Some(evidence) => (*call.candidate).clone().with_evidence(evidence),
            None => *call.candidate,
        };
        let envelope = self.write_envelope(SelfEffect::MemoryPutClaim, admission.as_ref())?;
        // The write gate reads no facet; the stored body takes the vault
        // default when the write applies.
        let gate_body = candidate.clone().into_claim_body(
            &envelope,
            crate::claim::substrate_facet_id(envelope.actor().entity_ref())?,
        )?;
        let authored_rules = crate::dreamer_consolidation::prepare_authored_claim(
            &gate_body.predicate,
            &gate_body.value,
        )?;
        if authored_rules.is_some()
            && (gate_body.subject != ClaimSubject::Entity(self.actor.entity_ref())
                || self.actor.actor_class() != crate::EdgeActorClass::Agent)
        {
            return Err(Error::InvalidConfig(
                "Dreamer rule author is not the bound resident".into(),
            ));
        }
        // The subject it names resolves for its writer (OF-063, FIX 1214).
        let subject = match gate_body.subject {
            ClaimSubject::Entity(id) => vec![("/subject", id)],
            ClaimSubject::Edge { source, target, .. } => {
                vec![("/subject", source), ("/subject", target)]
            }
        };
        if let Some(refused) = self.refused_write_reference(
            SelfEffect::MemoryPutClaim,
            "vault.claims.put",
            read_as.as_ref(),
            &subject,
        )? {
            return Ok(refused);
        }
        self.check_write_gate(call.id, &gate_body, &envelope, true)?;
        let actual_id = match &self.storage {
            ExecutorStorage::Canonical(vault) => vault
                .put_claim_candidate_with_landing_returning_actual(
                    &call.id,
                    candidate,
                    &envelope,
                    call.occurred,
                    call.learned_at,
                    |_| Ok(()),
                )?,
            ExecutorStorage::Session(binding) => binding.session.executor_put_claim_candidate(
                &binding.route,
                &call.id,
                candidate,
                &envelope,
                call.occurred,
                call.learned_at,
            )?,
        };

        if let Some(json) = authored_rules {
            let admitted = match &self.storage {
                ExecutorStorage::Canonical(vault) => {
                    crate::dreamer_consolidation::admitted_authored_claim(
                        vault, &actual_id, self.actor,
                    )?
                }
                ExecutorStorage::Session(binding) => binding.session.admitted_executor_claim(
                    &binding.route,
                    &actual_id,
                    self.actor,
                )?,
            };
            if !admitted {
                return Err(Error::InvalidConfig(
                    "Dreamer rules require an admitted resident claim".into(),
                ));
            }
            let record =
                crate::dreamer_consolidation::resident_record(self.actor, &json, Some(&actual_id))?;
            match &self.storage {
                ExecutorStorage::Canonical(vault) => {
                    vault.set_claimed_dreamer_failure_rules(self.actor, &json, &actual_id)?;
                }
                ExecutorStorage::Session(binding) => {
                    binding.session.side_table_put_routed(
                        &binding.route,
                        &crate::dreamer_consolidation::DREAMER_FAILURE_RULES,
                        &(),
                        &record,
                    )?;
                }
            }
        }
        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: actual_id,
        }))
    }

    pub(super) fn dispatch_memory_supersede_claim(
        &self,
        call: SelfMemorySupersedeClaimCall,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<SelfDispatchOutcome> {
        // Both claims it names resolve for its writer (OF-063, FIX 1214).
        if let Some(refused) = self.refused_write_reference(
            SelfEffect::MemorySupersedeClaim,
            "vault.claims.supersede",
            read_as.as_ref(),
            &[("/new_id", call.new_id), ("/old_id", call.old_id)],
        )? {
            return Ok(refused);
        }
        let admission = self.non_candidate_code_emission_admission()?;
        if matches!(
            admission.as_ref().map(|admission| admission.lane),
            Some(consent::ConsentLane::Review)
        ) {
            return Err(Error::Code(CodeError::CodeReviewUnsupportedOperation));
        }
        let envelope = self.write_envelope(SelfEffect::MemorySupersedeClaim, admission.as_ref())?;
        let claim_gate_body = self.operation_gate_body(
            SelfEffect::MemorySupersedeClaim,
            ClaimSubject::Entity(call.old_id),
            Value::Binary(call.new_id.as_bytes().to_vec()),
            &envelope,
        )?;

        let supersedes_weight =
            EdgeKind::Supersedes
                .default_weight()
                .ok_or(Error::InvariantViolation(
                    "Supersedes edge missing default weight",
                ))?;
        let edge_gate_body = self.operation_gate_body(
            SelfEffect::MemorySupersedeClaim,
            ClaimSubject::Edge {
                source: call.new_id,
                kind: EdgeKind::Supersedes,
                target: call.old_id,
            },
            Value::F32(supersedes_weight),
            &envelope,
        )?;
        let edge_gate_id = edge_operation_gate_id(
            SelfEffect::MemorySupersedeClaim,
            call.new_id,
            EdgeKind::Supersedes,
            call.old_id,
        )?;
        match &self.storage {
            ExecutorStorage::Canonical(vault) => vault.supersede_claim_for_code_run_trap(
                &call.new_id,
                &call.old_id,
                call.now,
                &envelope,
                call.old_id,
                &claim_gate_body,
                edge_gate_id,
                &edge_gate_body,
                |_| Ok(()),
            )?,
            ExecutorStorage::Session(binding) => binding.session.executor_supersede_claim(
                &binding.route,
                &call.new_id,
                &call.old_id,
                call.now,
                &envelope,
                call.old_id,
                &claim_gate_body,
                edge_gate_id,
                &edge_gate_body,
            )?,
        }

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.new_id,
        }))
    }

    /// A facet stamp its door admitted with a key places only a row that
    /// key's lane reads, judged in the edge's own write transaction
    /// (`require_facet_placement_in`).
    pub(super) fn dispatch_memory_put_edge(
        &self,
        call: SelfMemoryPutEdgeCall,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<SelfDispatchOutcome> {
        ensure_public_memory_edge_kind(call.kind)?;
        // Both ends it names resolve for its writer (OF-063, FIX 1214).
        if let Some(refused) = self.refused_write_reference(
            SelfEffect::MemoryPutEdge,
            "vault.edges.put",
            read_as.as_ref(),
            &[("/src", call.src), ("/tgt", call.tgt)],
        )? {
            return Ok(refused);
        }
        let placement = read_as.filter(|_| call.kind == EdgeKind::FacetOf);
        if placement.is_some() && matches!(self.storage, ExecutorStorage::Session(_)) {
            // A room's rows include overlay rows a door's lane cannot name, so
            // a session-bound run places no facet stamp on a door's key, as
            // its narrowed search is refused.
            return Err(unplaceable(call.src, call.tgt));
        }
        let admission = self.non_candidate_code_emission_admission()?;
        if matches!(
            admission.as_ref().map(|admission| admission.lane),
            Some(consent::ConsentLane::Review)
        ) {
            return Err(Error::Code(CodeError::CodeReviewUnsupportedOperation));
        }
        let envelope = self.write_envelope(SelfEffect::MemoryPutEdge, admission.as_ref())?;
        let gate_body = self.operation_gate_body(
            SelfEffect::MemoryPutEdge,
            ClaimSubject::Edge {
                source: call.src,
                kind: call.kind,
                target: call.tgt,
            },
            Value::F32(call.weight),
            &envelope,
        )?;
        let gate_id =
            edge_operation_gate_id(SelfEffect::MemoryPutEdge, call.src, call.kind, call.tgt)?;
        match &self.storage {
            ExecutorStorage::Canonical(vault) => {
                vault
                    .put_edge_for_code_run_trap(
                        &call.src,
                        call.kind,
                        &call.tgt,
                        call.weight,
                        &envelope,
                        gate_id,
                        &gate_body,
                        |txn| match &placement {
                            Some(reader) => {
                                require_facet_placement_in(vault, reader, txn, call.src, call.tgt)
                            }
                            None => Ok(()),
                        },
                    )
                    .map_err(|refused| match refused {
                        // A door's credential learns no endpoint type from the type
                        // table either: its every FacetOf refusal reads alike (Astra
                        // R12 F1 on #1432). A NOTE's or ASSET's refused restamp is
                        // judged only once the target is a stored FACET, so it reads
                        // alike too (Astra R13 F1).
                        Error::Registry(
                            crate::error::RegistryError::InvalidFacetOfEdge { .. }
                            | crate::error::RegistryError::FacetStampImmutable { .. },
                        ) if placement.is_some() => unplaceable(call.src, call.tgt),
                        other => other,
                    })?;
            }
            ExecutorStorage::Session(binding) => binding.session.executor_put_edge(
                &binding.route,
                &call.src,
                call.kind,
                &call.tgt,
                call.weight,
                &envelope,
                gate_id,
                &gate_body,
            )?,
        }

        Ok(SelfDispatchOutcome::MemoryEdgeWrite(
            SelfMemoryEdgeWriteResult {
                src: call.src,
                kind: call.kind,
                tgt: call.tgt,
            },
        ))
    }
}

/// The hits `reader` reads by its own entry, each checked on the revision
/// the search read (`raw_of`) with the same predicate a keyed read applies
/// (`AudienceCache::own_entry_readable_raw`). A hit whose row is gone stays:
/// that is the other gates' to refuse.
fn own_entry_kept(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    hits: Vec<ScoredEntity>,
    reader: EntityId,
    raw_of: impl Fn(&EntityId) -> Result<Option<Vec<u8>>>,
) -> Result<Vec<ScoredEntity>> {
    let entry = crate::conversation::AudienceCache::default();
    let mut kept = Vec::with_capacity(hits.len());
    for hit in hits {
        let readable = match raw_of(&hit.id)? {
            Some(raw) => entry.own_entry_readable_raw(
                vault,
                &vault.store.read(),
                txn,
                hit.id,
                &raw,
                reader,
            )?,
            None => true,
        };
        if readable {
            kept.push(hit);
        }
    }
    Ok(kept)
}
