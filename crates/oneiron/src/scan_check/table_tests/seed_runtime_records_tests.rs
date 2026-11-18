//! Threshold fixtures of the runtime_records scans for `no_engine_scan_refuses_for_its_row_count`
//! (FIX LIBTEST-SCAN-CHECK-TABLE-UNSEEDED-SCANS).

use super::*;

pub(super) fn seed(vault: &Vault, scan: EngineScan) -> Option<(usize, Read<'_>)> {
    match scan {
        // PredicateClaimRows: 3 claims indexed under one predicate;
        // read walks the posting list (3 rows past ROW=2), serves PAST.
        EngineScan::PredicateClaimRows => {
            let predicate = "fixture.predicate";
            vault
                .with_write_txn(|wtxn| {
                    let write = crate::secret_custody::CustodyWrite::of(vault);
                    for index in 0..PAST {
                        let body = crate::claim::ClaimBody::new(
                            predicate,
                            crate::claim::ClaimSubject::Entity(id(0xA0, index)),
                            rmpv::Value::Nil,
                            0.5,
                            crate::claim::ClaimApprovalStatus::Approved,
                            crate::claim::ClaimLifecycleStatus::Active,
                        )
                        .expect("body");
                        crate::store::claim_projection::maintain_claim_projection_index(
                            &write,
                            wtxn,
                            id(0xA0, index),
                            &body,
                        )?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    Ok(
                        crate::store::claim_projection::claim_ids_for_predicate_in_txn(
                            &vault.store,
                            &txn,
                            predicate,
                        )?
                        .len(),
                    )
                }),
            ))
        }

        // VaultEdgeRows: counted at store/ppr_community.rs:232 in
        // Store::compute_ppr_communities_in_txn (pub(crate)). Unit: one outgoing
        // edge row vault-wide; 3 edges_out rows pass ROW=2. The open seeds its own
        // entities, so `served` is read once here: the same deterministic community
        // count both test reads return.
        EngineScan::VaultEdgeRows => {
            vault
                .with_write_txn(|wtxn| {
                    for index in 1..=PAST {
                        let key = Store::encode_edge_key(
                            &id(0xA1, 0),
                            EdgeKind::BelongsTo,
                            &id(0xA1, index),
                        );
                        vault.store.edges_out.put(wtxn, &key, &edge_value())?;
                    }
                    Ok(())
                })
                .expect("seed");
            let run = move || -> Result<usize> {
                let txn = vault.store.env.read_txn()?;
                let config = crate::config::community_graph::PprCommunityConfig::default();
                Ok(vault
                    .store
                    .compute_ppr_communities_in_txn(&txn, None, &[], LEARNED_AT, &config)?
                    .0
                    .members
                    .len())
            };
            Some((run().expect("communities"), Box::new(run)))
        }

        // PrefilterReceiptRows: 1 write call, 3 skipped turns -> 3 SKIP + 1 ROUND rows;
        // an Extraction-only receipts read walks 4 rows, serves newest PAST=3.
        EngineScan::PrefilterReceiptRows => {
            use crate::dreamer_prefilter::{
                PrefilterScreen, PrefilterTurnVerdict, PrefilterVerdict,
            };
            use crate::dreamer_runner::{DreamerConsolidationScope, DreamerTurnRole};
            let turns: Vec<crate::dreamer_consolidation::WorkingSetTurn> = (0..PAST)
                .map(|index| crate::dreamer_consolidation::WorkingSetTurn {
                    turn_id: id(0xA2, index),
                    role: DreamerTurnRole::User,
                    learned_at: LEARNED_AT,
                    carrier: None,
                    conversation: None,
                })
                .collect();
            let screen = PrefilterScreen {
                enabled: true,
                threshold: 0.5,
                kept: Vec::new(),
                verdicts: turns
                    .iter()
                    .map(|turn| PrefilterTurnVerdict {
                        turn_id: turn.turn_id,
                        verdict: PrefilterVerdict {
                            pass: false,
                            score: 0.1,
                            features: Default::default(),
                            estimated_tokens: 10,
                        },
                    })
                    .collect(),
                scanned: PAST,
                passed: 0,
                skipped: PAST,
                estimated_tokens_saved: 30,
            };
            vault
                .with_write_txn(|wtxn| {
                    crate::dreamer_prefilter::write_prefilter_receipts_in_txn(
                        vault,
                        wtxn,
                        DreamerConsolidationScope::Micro,
                        &turns,
                        &screen,
                        LEARNED_AT,
                    )
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    let query =
                        crate::receipt::ReceiptQuery::new(PAST).with_kind(ReceiptKind::Extraction);
                    Ok(vault.receipts(query)?.len())
                }),
            ))
        }

        // MachineHandoffChain: counted at claim/history_projection/chain.rs:265 in
        // read_handoff_chain_from (pub(crate)), reached via pub(crate)
        // read_handoff_chain. Unit: one packet walked (tip included); a 3-packet
        // chain with empty deltas passes ROW=2. Ancestors live under the first 16
        // bytes of their content hash as machine.handoff CLAIM rows.
        EngineScan::MachineHandoffChain => {
            use crate::claim::{ClaimBirth, ClaimBody, ClaimHistoryHandoff, HandoffKind};
            let target = id(0xA3, 0);
            let packet = |nonce: u8, previous: Option<[u8; 32]>| ClaimHistoryHandoff {
                kind: HandoffKind::Handoff,
                vault_id: [0xA3; 32],
                genesis_hash: [0xA3; 32],
                scope: vec![0xA3],
                births: vec![ClaimBirth {
                    id: target,
                    digest: [0xA3; 32],
                }],
                transitions: Vec::new(),
                heads: vec![[0xA3; 32]],
                authority_head: [0xA3; 32],
                previous_handoff_hash: previous,
                nonce: [nonce; 32],
                challenge: [0xA3; 32],
                signer: crate::authority::AuthorityKey::Ed25519([0xA3; 32]),
                signature: [0; 64],
            };
            let first = packet(0, None);
            let second = packet(1, Some(first.content_hash().expect("hash")));
            let tip = packet(2, Some(second.content_hash().expect("hash")));
            vault
                .with_write_txn(|wtxn| {
                    for ancestor in [&first, &second] {
                        let hash = ancestor.content_hash().expect("hash");
                        let row =
                            EntityId::from_bytes(hash[..16].try_into().expect("id")).expect("row");
                        let body = ClaimBody::new(
                            crate::claim::history_store::MACHINE_HANDOFF_PREDICATE,
                            crate::claim::ClaimSubject::Entity(target),
                            rmpv::Value::Binary(ancestor.encode().expect("wire")),
                            0.5,
                            crate::claim::ClaimApprovalStatus::Approved,
                            crate::claim::ClaimLifecycleStatus::Active,
                        )
                        .expect("body");
                        let bytes = crate::claim::encode_claim_body(&body).expect("data");
                        vault.store.entities.put(
                            wtxn,
                            row.as_bytes(),
                            &crate::test_util::entity_record(
                                crate::registry::ENTITY_TYPE_CLAIM,
                                crate::temporal::TimeRange { start: 1, end: 1 },
                                1,
                                1,
                                &bytes,
                            ),
                        )?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    Ok(crate::claim::history_projection::read_handoff_chain(
                        &vault.store,
                        &txn,
                        &tip,
                    )?
                    .len())
                }),
            ))
        }

        // MachineHistoryTargetRows: counted at claim/history_projection/pin.rs:23 in
        // Vault::machine_history_pinned_targets (pub(crate)). Unit: one pin row
        // under PIN_PREFIX in vault_meta; 3 pins pass ROW=2. Each pin value is an
        // encoded packet whose single birth is its target.
        EngineScan::MachineHistoryTargetRows => {
            use crate::claim::{ClaimBirth, ClaimHistoryHandoff, HandoffKind};
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        let target = id(0xA4, index);
                        let pin = ClaimHistoryHandoff {
                            kind: HandoffKind::Handoff,
                            vault_id: [0xA4; 32],
                            genesis_hash: [0xA4; 32],
                            scope: vec![0xA4],
                            births: vec![ClaimBirth {
                                id: target,
                                digest: [0xA4; 32],
                            }],
                            transitions: Vec::new(),
                            heads: vec![[0xA4; 32]],
                            authority_head: [0xA4; 32],
                            previous_handoff_hash: None,
                            nonce: [index as u8; 32],
                            challenge: [0xA4; 32],
                            signer: crate::authority::AuthorityKey::Ed25519([0xA4; 32]),
                            signature: [0; 64],
                        };
                        vault.store.vault_meta.put(
                            wtxn,
                            &crate::claim::history_projection::pin_key(target),
                            &pin.encode().expect("pin"),
                        )?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || Ok(vault.machine_history_pinned_targets()?.len())),
            ))
        }

        // MachineTransitionFrontier: PUT-door validator read twice (no write) over a planted
        // birth; a signed Approve with 3 predecessors passes ROW=2, serves PAST.
        EngineScan::MachineTransitionFrontier => {
            use crate::claim::transition::{
                ClaimTransitionKind, SignedClaimTransitionEvent, TransitionDelta,
            };
            use ed25519_dalek::{Signer, SigningKey};
            use rmpv::Value;
            let (target, machine) = (id(0xA5, 0), id(0xA5, 1));
            let vault_id = [0xA5; 32];
            let signer = SigningKey::from_bytes(&[0xA5; 32]);
            let key = signer.verifying_key().to_bytes();
            let mut original = crate::claim::ClaimBody::new(
                "profile.preference",
                crate::claim::ClaimSubject::Entity(machine),
                Value::from("quiet"),
                0.9,
                crate::claim::ClaimApprovalStatus::Proposed,
                crate::claim::ClaimLifecycleStatus::Active,
            )
            .expect("body");
            original.evidence = Some(Value::Map(vec![
                (
                    Value::from("actor_class"),
                    Value::from(crate::edge::EdgeActorClass::System as u8),
                ),
                (
                    Value::from("actor_entity_ref"),
                    Value::Binary(machine.as_bytes().to_vec()),
                ),
                (
                    Value::from("machine_signature"),
                    Value::Array(vec![
                        Value::Binary(key.to_vec()),
                        Value::Binary(vec![0; 64]),
                    ]),
                ),
            ]));
            let transcript =
                crate::authority::machine_claim_transcript(&vault_id, &target, &original)
                    .expect("transcript");
            let sig = signer.sign(&transcript).to_bytes();
            let Some(Value::Map(evidence)) = &mut original.evidence else {
                unreachable!()
            };
            evidence[2].1 = Value::Array(vec![
                Value::Binary(key.to_vec()),
                Value::Binary(sig.to_vec()),
            ]);
            let birth = crate::claim::SignedClaimBirth::new(
                vault_id,
                target,
                crate::claim::encode_claim_body(&original).expect("initial"),
                key,
                sig,
            )
            .expect("birth");
            let birth_id = EntityId::from_bytes(birth.digest[..16].try_into().expect("digest"))
                .expect("birth id");
            vault
                .with_write_txn(|wtxn| {
                    let carrier = crate::claim::history_store::machine_history_claim(
                        crate::claim::history_store::MachineHistoryKind::Birth,
                        target,
                        &original,
                        birth.encode().expect("birth wire"),
                    )?;
                    let bytes = crate::claim::encode_claim_body(&carrier).expect("carrier");
                    vault.store.entities.put(
                        wtxn,
                        birth_id.as_bytes(),
                        &crate::test_util::entity_record(
                            crate::registry::ENTITY_TYPE_CLAIM,
                            crate::temporal::TimeRange { start: 1, end: 1 },
                            1,
                            1,
                            &bytes,
                        ),
                    )?;
                    Ok(())
                })
                .expect("seed");
            let mut event = SignedClaimTransitionEvent {
                vault_id,
                target,
                birth_digest: birth.digest,
                predecessors: vec![[0xA5; 32], [0xA6; 32], [0xA7; 32]],
                authority_head: [0xA5; 32],
                actor: machine,
                actor_class: crate::edge::EdgeActorClass::System,
                host_public_key: key,
                kind: ClaimTransitionKind::Approve,
                delta: TransitionDelta::None,
                signature: [0; 64],
            };
            event.signature = signer
                .sign(
                    &crate::claim::transition::machine_claim_transition_transcript(&event)
                        .expect("event transcript"),
                )
                .to_bytes();
            let put_id = crate::claim::transition::machine_claim_transition_event_id(&event)
                .expect("event id");
            let body = crate::claim::history_store::machine_history_claim(
                crate::claim::history_store::MachineHistoryKind::Transition,
                target,
                &original,
                crate::claim::transition::encode_machine_claim_transition_event(&event)
                    .expect("event wire"),
            )
            .expect("carrier");
            let data = crate::claim::encode_claim_body(&body).expect("data");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::claim::history_store::validate_machine_history_put(
                        &vault.store,
                        &txn,
                        crate::claim::history_store::MachineHistoryPut {
                            id: &put_id,
                            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                            occurred: crate::temporal::TimeRange { start: 1, end: 1 },
                            learned_at: 1,
                            data: data.as_slice(),
                            body: Some(&body),
                            replicated: false,
                            posture: crate::HostingPrivacyPosture::SelfHostLocal,
                        },
                    )?;
                    Ok(PAST)
                }),
            ))
        }

        // ClaimVadIncidentEdges: counted at affect/consolidation.rs:573+591 in
        // private claim_vad_incident_edges_in_txn, reached via pub
        // Vault::consolidate_claim_vad_now. Unit: one incident edge row per way
        // (Out/In scopes differ); 3 structural out-edges and 0 in-edges cross
        // once. Structural edges count but take no SetEdgeVad op, so both reads
        // are edge-write-free and serve the same skip count.
        EngineScan::ClaimVadIncidentEdges => {
            let claim = id(0xA6, 0);
            vault
                .with_write_txn(|wtxn| {
                    let body = crate::claim::ClaimBody::new(
                        "core.example",
                        crate::claim::ClaimSubject::Entity(id(0xA6, 1)),
                        rmpv::Value::Nil,
                        0.5,
                        crate::claim::ClaimApprovalStatus::Approved,
                        crate::claim::ClaimLifecycleStatus::Active,
                    )
                    .expect("body");
                    let bytes = crate::claim::encode_claim_body(&body).expect("data");
                    vault.store.entities.put(
                        wtxn,
                        claim.as_bytes(),
                        &crate::test_util::entity_record(
                            crate::registry::ENTITY_TYPE_CLAIM,
                            crate::temporal::TimeRange { start: 1, end: 1 },
                            1,
                            1,
                            &bytes,
                        ),
                    )?;
                    for index in 1..=PAST {
                        vault.store.edges_out.put(
                            wtxn,
                            &Store::encode_edge_key(&claim, EdgeKind::BelongsTo, &id(0xA6, index)),
                            &edge_value(),
                        )?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    Ok(vault
                        .consolidate_claim_vad_now(&claim, LEARNED_AT)?
                        .structural_edges_skipped)
                }),
            ))
        }

        // counted-at: crates/oneiron/src/store/retrieval_telemetry/run_store.rs:642
        //   (ScanCount::start inside private read_retrieval_runs_in_txn, :634)
        // read: Store::retrieval_runs (pub, run_store.rs:540); unit = one ledger row
        //   passed, provisional rows included. 3 published rows walked past ROW=2;
        //   limit PAST serves all 3.
        EngineScan::RetrievalRunRows => {
            use crate::store::{RetrievalAction, RetrievalRunId, RetrievalRunRecord};
            for _ in 0..PAST {
                let run = RetrievalRunRecord::new(
                    RetrievalRunId::now(),
                    RetrievalAction::Pipeline,
                    100,
                    10,
                    Vec::new(),
                    Vec::new(),
                    1,
                    0,
                    None,
                );
                vault.store.record_retrieval_run(&run).expect("run");
            }
            Some((
                PAST,
                Box::new(move || Ok(vault.store.retrieval_runs(PAST)?.len())),
            ))
        }

        // counted-at: crates/oneiron/src/self_heal/served_signals.rs:79 (ScanCount::start)
        // read: Vault::run_served_signal_detectors (pub, served_signals.rs:41); unit =
        //   one CALL_RECEIPT row walked, before its time and kind filters. 3 rows
        //   walked past ROW=2; none is an MCP refusal in window, so 0 served.
        EngineScan::CallReceiptRows => {
            use crate::receipt::{CallOutcome, CallReceiptInput, CallTransport};
            vault.install_device_keystore(std::sync::Arc::new(
                oneiron_keystore::MemoryKeystore::default(),
            ));
            for index in 0..PAST {
                vault
                    .record_call_receipt(CallReceiptInput {
                        transport: CallTransport::HttpFacade,
                        verb: format!("fixture.verb.{index}"),
                        actor_ref: id(0xA8, index).to_hex(),
                        actor_class: "agent".to_owned(),
                        credential_ref: None,
                        carrier_machine: None,
                        outcome: CallOutcome::Ok,
                        request_digest: "0f".repeat(32),
                        result_digest: None,
                        inputs: None,
                        attempt: None,
                        served: Vec::new(),
                    })
                    .expect("receipt");
            }
            Some((
                0,
                Box::new(move || Ok(vault.run_served_signal_detectors(LEARNED_AT)?.len())),
            ))
        }

        // counted-at: crates/oneiron/src/self_heal/blocked_reports.rs:213-218
        //   (ScanCount::start inside pub(crate) receipts_of_run_in, :208)
        // read: Vault::blocked_reports_of_run (pub, blocked_reports.rs:194); unit =
        //   one BY_RUN row from the run's prefix on. 3 rows walked past ROW=2;
        //   every receipt served.
        EngineScan::BlockedRunReports => {
            const BY_RUN: crate::side_table::SideTable<[u8; 32], u64, crate::side_table::Raw> =
                crate::side_table::SideTable::new(&crate::side_table::COACH_BLOCKED_RUN);
            let run = id(0xA9, 0);
            vault
                .with_write_txn(|wtxn| {
                    for index in 1..=PAST {
                        let mut key = [0u8; 32];
                        key[..16].copy_from_slice(run.as_bytes());
                        key[16..].copy_from_slice(id(0xA9, index).as_bytes());
                        BY_RUN.put(&vault.store, wtxn, &key, &LEARNED_AT)?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || Ok(vault.blocked_reports_of_run(run)?.len())),
            ))
        }

        // SieveAuditRows: 3 sampled Flagged AUDIT rows (direct puts; the write door is
        // pub(super)); sieve_audits_in_txn walks 3 rows, serves 3.
        EngineScan::SieveAuditRows => {
            use crate::attempt_queue::AttemptId;
            use crate::dreamer_wake::sieve::{SieveAudit, SieveAuditRecord, SpanKind};
            use crate::side_table::{Named, SideTable};
            const AUDIT: SideTable<AttemptId, SieveAuditRecord, Named> =
                SideTable::new(&crate::side_table::DREAMER_SIEVE_AUDIT);
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        let attempt =
                            AttemptId::from_bytes(id(0xAA, index).as_bytes()).expect("attempt");
                        let audit = SieveAudit {
                            sampled: true,
                            span: [0xAA; 32],
                            turn: id(0xAA, index),
                            source: id(0xAA, index),
                            source_digest: [0; 32],
                            expected_kind: SpanKind::Name,
                            actual_kind: SpanKind::Name,
                            expected_entity: None,
                            actual_entity: None,
                            novel: false,
                            confidence: 9,
                            agrees: true,
                            at: LEARNED_AT,
                            completed_units: 0,
                            step_bindings: Vec::new(),
                            decisions: Vec::new(),
                        };
                        AUDIT.put(
                            &vault.store,
                            wtxn,
                            &attempt,
                            &SieveAuditRecord::Flagged(audit),
                        )?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    Ok(crate::dreamer_wake::sieve::sieve_audits_in_txn(vault, &txn)?.len())
                }),
            ))
        }

        // counted-at: crates/oneiron/src/vault/edges.rs:572 (ScanCount::start inside
        //   pub(crate) ancestors_in, :567; scope = node bytes)
        // read: Vault::ancestors (pub, edges.rs:485); unit = one parent step walked
        //   via outbound ChildOf edges. A 3-edge chain walks 3 rows past ROW=2;
        //   all 3 ancestors served.
        EngineScan::DagWalkRecords => {
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        let key = Store::encode_edge_key(
                            &id(0xAB, index),
                            EdgeKind::ChildOf,
                            &id(0xAB, index + 1),
                        );
                        vault.store.edges_out.put(wtxn, &key, &edge_value())?;
                    }
                    Ok(())
                })
                .expect("seed");
            let leaf = id(0xAB, 0);
            Some((PAST, Box::new(move || Ok(vault.ancestors(&leaf)?.len()))))
        }

        // Counted at task_authority/mod.rs:856 (`ScanCount::start`) and :869 (`row`
        // per inbound `ScopedTo` edge). Read: `Vault::task_authority_state` (pub,
        // task_authority/mod.rs:777) through `task_authority_facts_in` (pub(crate),
        // :843). Unit: inbound `ScopedTo` edges of one TASK; 3 Cancelled facts pass
        // ROW=2 and fold to `None` (served 0).
        EngineScan::TaskAuthorityFactEdges => {
            let task = id(0xAC, 0);
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        crate::task_authority::put_task_authority_fact_in_txn(
                            vault,
                            wtxn,
                            crate::task_authority::TaskAuthorityFact {
                                task_ref: task,
                                kind: crate::task_authority::TaskAuthorityFactKind::Cancelled,
                                actor_ref: id(0xAC, index + 1),
                                assigned_ref: None,
                                actor_generation: None,
                                assigned_generation: None,
                                occurred_at: LEARNED_AT,
                            },
                        )?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                0,
                Box::new(move || Ok(vault.task_authority_state(task)?.map_or(0, |_| 1))),
            ))
        }

        // Counted at agent_dispatch/context.rs:176 (`ScanCount::start`) and :191
        // (`rows(seen.len())`). Read: `AgentDispatcher::resolve_attempt_context`
        // (pub, agent_dispatch/widen/context.rs:23) through
        // `resolve_ancestor_projection_in_txn` (pub(super), context.rs:167). Unit:
        // attempt rows on one dispatch lineage; a 3-deep seeded-default chain passes
        // ROW=2. Served is resolved once at seed (same scope, deduped check).
        EngineScan::DispatchAncestorRows => {
            let dispatcher = crate::agent_dispatch::AgentDispatcher::new(vault);
            let root = dispatcher
                .dispatch_default_base(None, None, None, 1)
                .expect("root");
            let crate::agent_dispatch::AgentDispatchOutcome::Dispatched(root) = root else {
                panic!("root dispatch");
            };
            let child = dispatcher
                .dispatch_default_base(Some(root.attempt.id), None, None, 2)
                .expect("child");
            let crate::agent_dispatch::AgentDispatchOutcome::Dispatched(child) = child else {
                panic!("child dispatch");
            };
            let leaf = dispatcher
                .dispatch_default_base(Some(child.attempt.id), None, None, 3)
                .expect("leaf");
            let crate::agent_dispatch::AgentDispatchOutcome::Dispatched(leaf) = leaf else {
                panic!("leaf dispatch");
            };
            let leaf_id = leaf.attempt.id;
            let resolve = move || {
                crate::agent_dispatch::AgentDispatcher::new(vault)
                    .resolve_attempt_context(leaf_id)
                    .map(|projection| {
                        projection.memory_sections.len()
                            + projection.chat_sections.len()
                            + projection.sibling_result_refs.len()
                            + projection.workflow_output_refs.len()
                    })
            };
            let served = resolve().expect("resolve");
            Some((served, Box::new(resolve)))
        }

        // LinearProvenanceRows: TASK + 3 mirror events; provenance page (default limit 50)
        // reads 3 index rows + no lookahead, serves PAST.
        EngineScan::LinearProvenanceRows => {
            let task = id(0xAE, 0);
            let actor = id(0xAE, 1);
            let at = crate::temporal::TimeRange { start: 1, end: 1 };
            let body = crate::habit::task_body_for_test(crate::habit::TaskRole::Task);
            vault
                .put_entity(&task, crate::registry::ENTITY_TYPE_TASK, at, 1, &body)
                .expect("task");
            vault
                .put_entity(&actor, crate::registry::ENTITY_TYPE_PERSON, at, 1, b"actor")
                .expect("actor");
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        let key = crate::linear_sync::task_edit_key(
                            task,
                            actor,
                            &format!("edit-{index}"),
                        );
                        let mut row = crate::linear_sync::LinearMirrorEvent::blank(
                            crate::linear_sync::EventDirection::TaskEdit,
                            "edited",
                            index as u64 + 1,
                        );
                        row.task_ref = Some(task.to_hex());
                        crate::linear_sync::put_event_in(vault, wtxn, &key, &row)?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    let request = crate::linear_sync::LinearProvenanceRequest {
                        task_ref: task.to_hex(),
                        cursor: None,
                        limit: None,
                    };
                    let page = vault
                        .memory(actor, crate::edge::EdgeActorClass::Agent)
                        .linear_provenance(&request)
                        .map_err(|error| crate::Error::InvalidConfig(error.message))?;
                    Ok(page.events.len())
                }),
            ))
        }

        // SpendAncestorScopes: root + 3 carves (4-deep chain); root walk counts the 3
        // parents past ROW=2, serves 1 (Some).
        EngineScan::SpendAncestorScopes => {
            let dispatcher = crate::agent_dispatch::AgentDispatcher::new(vault);
            let root =
                crate::agent_dispatch::SpendScopeId::launch("spend-ancestors-af").expect("launch");
            let attempts: [crate::attempt_queue::AttemptId; 3] =
                std::array::from_fn(|_| crate::attempt_queue::AttemptId::now());
            vault
                .with_write_txn(|wtxn| {
                    dispatcher.open_root_spend_scope_in_txn(
                        wtxn,
                        root.clone(),
                        crate::llm::run_admission::DeclaredMaximum {
                            units: 1_000_000,
                            unit: crate::llm::run_admission::LeaseUnit::tokens(),
                        },
                        Some(crate::llm::run_admission::MaximumShown { at_ms: 1 }),
                        LEARNED_AT,
                    )?;
                    let mut parent = root;
                    for (attempt, cap) in attempts.iter().zip([100_000, 10_000, 1_000]) {
                        let ask = crate::agent_dispatch::ChildSpend::Carve { cap_units: cap };
                        dispatcher.reserve_child_in_txn(wtxn, &parent, attempt, ask, LEARNED_AT)?;
                        parent = crate::agent_dispatch::SpendScopeId::for_attempt(attempt);
                    }
                    Ok(())
                })
                .expect("seed");
            let leaf = crate::agent_dispatch::SpendScopeId::for_attempt(&attempts[2]);
            Some((
                1,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    Ok(crate::agent_dispatch::AgentDispatcher::new(vault)
                        .scope_with_root_in_txn(&txn, &leaf)?
                        .map_or(0, |_| 1))
                }),
            ))
        }

        // Counted at agent_dispatch/spend_lease/ancestry.rs:95 (`observe`, rows =
        // retry lineage length). Read: `AgentDispatcher::spend_scope_for_attempt`
        // (pub, spend_lease.rs:612) through `scope_for_attempt_in_txn` (pub(in
        // agent_dispatch), ancestry.rs:88). Unit: attempt rows on one retry lineage;
        // 3 tries with no scopes pass ROW=2 and read `None` (served 0).
        EngineScan::SpendRetryAttempts => {
            let queue = crate::attempt_queue::AttemptQueue::new(vault);
            let ids: [crate::attempt_queue::AttemptId; 3] =
                std::array::from_fn(|_| crate::attempt_queue::AttemptId::now());
            vault
                .with_write_txn(|wtxn| {
                    for (slot, retry_of) in [
                        (ids[0], None),
                        (ids[1], Some(ids[0])),
                        (ids[2], Some(ids[1])),
                    ] {
                        let input = crate::attempt_queue::EnqueueAttempt {
                            kind: "spend_retry".to_owned(),
                            payload: vec![0xB0],
                            dedupe_key: None,
                            run_id: None,
                            now: 1,
                        };
                        queue.enqueue_handed_over_in_txn(wtxn, slot, input, None, retry_of)?;
                    }
                    Ok(())
                })
                .expect("seed");
            let leaf = ids[2];
            Some((
                0,
                Box::new(move || {
                    Ok(crate::agent_dispatch::AgentDispatcher::new(vault)
                        .spend_scope_for_attempt(leaf)?
                        .map_or(0, |_| 1))
                }),
            ))
        }

        // Counted at attempt_queue/engine/reads.rs:460 (`ScanCount::start_at`,
        // threshold = caller's `max_scanned`) and :466 (`rows(ids.len())`). Read:
        // `AttemptQueue::list_kind_bounded` (pub(crate), reads.rs:444). Unit:
        // kind-index rows before the kind filter; 3 rows with max_scanned = ROW
        // pass ROW=2.
        EngineScan::AttemptKindRows => {
            let queue = crate::attempt_queue::AttemptQueue::new(vault);
            for index in 0..PAST {
                queue
                    .enqueue(crate::attempt_queue::EnqueueAttempt {
                        kind: "attempt_kind".to_owned(),
                        payload: vec![0xB1],
                        dedupe_key: None,
                        run_id: None,
                        now: index as u64 + 1,
                    })
                    .expect("enqueue");
            }
            Some((
                PAST,
                Box::new(move || {
                    Ok(crate::attempt_queue::AttemptQueue::new(vault)
                        .list_kind_bounded("attempt_kind", ROW as usize)?
                        .len())
                }),
            ))
        }

        // AttemptEventActorBytes — counted at attempt_queue/engine/mod.rs:93-94
        // (observe_event_bytes, via encode_in_txn on every attempt write).
        // Read: crate::attempt_queue::AttemptQueue::intervene (pub). WRITE-door
        // scan: the read closure itself intervenes and returns a constant.
        // Unit: longest event/cancel-receipt actor in bytes for one record
        // (scope = record id); passes ROW when longest > 2.
        EngineScan::AttemptEventActorBytes => {
            let queue = crate::attempt_queue::AttemptQueue::new(vault);
            let outcome = queue
                .enqueue(crate::attempt_queue::EnqueueAttempt {
                    kind: "table".to_owned(),
                    payload: b"attempt".to_vec(),
                    dedupe_key: None,
                    run_id: None,
                    now: LEARNED_AT,
                })
                .expect("enqueue");
            let attempt = match outcome {
                crate::attempt_queue::EnqueueOutcome::Enqueued(record) => record.id,
                crate::attempt_queue::EnqueueOutcome::Existing(record) => record.id,
            };
            Some((
                1,
                Box::new(move || {
                    let queue = crate::attempt_queue::AttemptQueue::new(vault);
                    queue.intervene(crate::attempt_queue::InterveneAttempt {
                        id: attempt,
                        kind: crate::attempt_queue::AttemptInterventionKind::Interrupt,
                        actor: "abc".to_owned(),
                        note: None,
                        now: LEARNED_AT,
                    })?;
                    Ok(1)
                }),
            ))
        }

        // AttemptEventNoteBytes — counted at attempt_queue/engine/mod.rs:93-94
        // (observe_event_bytes, via encode_in_txn on every attempt write).
        // Read: crate::attempt_queue::AttemptQueue::intervene (pub). WRITE-door
        // scan: the read closure itself intervenes and returns a constant.
        // Unit: longest event note in bytes for one record (scope = record id);
        // passes ROW when longest > 2.
        EngineScan::AttemptEventNoteBytes => {
            let queue = crate::attempt_queue::AttemptQueue::new(vault);
            let outcome = queue
                .enqueue(crate::attempt_queue::EnqueueAttempt {
                    kind: "table".to_owned(),
                    payload: b"attempt".to_vec(),
                    dedupe_key: None,
                    run_id: None,
                    now: LEARNED_AT,
                })
                .expect("enqueue");
            let attempt = match outcome {
                crate::attempt_queue::EnqueueOutcome::Enqueued(record) => record.id,
                crate::attempt_queue::EnqueueOutcome::Existing(record) => record.id,
            };
            Some((
                1,
                Box::new(move || {
                    let queue = crate::attempt_queue::AttemptQueue::new(vault);
                    queue.intervene(crate::attempt_queue::InterveneAttempt {
                        id: attempt,
                        kind: crate::attempt_queue::AttemptInterventionKind::Interrupt,
                        actor: "a".to_owned(),
                        note: Some("abc".to_owned()),
                        now: LEARNED_AT,
                    })?;
                    Ok(1)
                }),
            ))
        }

        // ReceiptSourceRows — counted at receipt/record.rs:505-510
        // (scan_suppression_receipts, scope "outbound_suppression").
        // Read: Vault::scan_receipts (pub) with an Outbound-only query; its other
        // four sources hold no rows, so only this family crosses.
        // Unit: outbound suppression index rows; passes ROW when 3 > 2.
        EngineScan::ReceiptSourceRows => {
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        suppression(vault, wtxn, index)?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    let query =
                        crate::receipt::ReceiptQuery::new(PAST).with_kind(ReceiptKind::Outbound);
                    Ok(vault.scan_receipts(query)?.records.len())
                }),
            ))
        }

        // Its threshold test: crate::scan_check::table_tests::seed_runtime_records_tests::sync_prefix_rows_reads_past_its_fixed_row.
        // start_at uses MAX_SYNC_STATE_KEYS, so the table's threshold == ROW cannot hold.
        EngineScan::SyncPrefixRows => None,

        // DependentWalkRows — counted at ports/dependent_walk.rs:329-330
        // (batch_in_txn raises when walk.walked > policy.check_threshold).
        // Read: Vault::dependent_walk_checks (pub), pure; the seed's delete runs
        // the whole walk in one transaction. Unit: distinct dependents withdrawn
        // for one source; passes ROW when 3 > 2.
        EngineScan::DependentWalkRows => {
            vault.install_device_keystore(std::sync::Arc::new(
                oneiron_keystore::MemoryKeystore::default(),
            ));
            let source = id(0xB6, 0);
            let body = |text: &str| {
                rmp_serde::to_vec_named(&serde_json::json!({ "txt": text })).expect("body")
            };
            vault
                .put_entity(
                    &source,
                    crate::registry::ENTITY_TYPE_TURN,
                    crate::temporal::TimeRange { start: 1, end: 1 },
                    1,
                    &body("the source"),
                )
                .expect("source");
            let mut batch = vault.batch();
            for index in 1..=PAST {
                let dependent = id(0xB6, index);
                batch = batch
                    .put(
                        &dependent,
                        crate::registry::ENTITY_TYPE_TURN,
                        crate::temporal::TimeRange { start: 2, end: 2 },
                        2,
                        &body("needle"),
                    )
                    .text(&dependent, &[("body", "needle")])
                    .edge(&dependent, EdgeKind::DerivedFrom, &source, 1.0);
            }
            batch.commit().expect("dependents");
            vault.delete_entity(&source).expect("erase");
            Some((
                1,
                Box::new(move || Ok(vault.dependent_walk_checks()?.len())),
            ))
        }

        EngineScan::ResearchContinuationRoots => {
            use crate::autoreason_campaign::general::{
                BudgetLease, CampaignConfig, DecideRules, MetricAxis, MetricDirection, MetricRole,
                MetricSet, SearchAxis,
            };
            use crate::autoreason_campaign::research::{ResearchBinding, ResearchTarget};
            use crate::autoreason_campaign::{CampaignDatasetRef, CampaignSplits};
            // The counted unit is every BINDING row, before execution is filtered.
            // Three workflow-driven roots are all read; no host work is served.
            // Mirror the private table, as rv_turns does for room fixtures.
            let bindings: crate::side_table::SideTable<
                [u8; 16],
                ResearchBinding,
                crate::side_table::Named,
            > = crate::side_table::SideTable::new(&crate::side_table::AUTORESEARCH_BINDING);
            let dataset = |name: &str| CampaignDatasetRef {
                dataset_id: name.to_owned(),
                revision: "1".to_owned(),
            };
            let config = CampaignConfig {
                campaign_id: "scan-check-continuation".to_owned(),
                search_axes: vec![SearchAxis {
                    name: "prompt".to_owned(),
                    values: vec!["base".to_owned()],
                }],
                metric_set: MetricSet {
                    set_id: "scan-check".to_owned(),
                    revision: "1".to_owned(),
                    axes: vec![MetricAxis {
                        name: "quality".to_owned(),
                        direction: MetricDirection::Higher,
                        role: MetricRole::Primary,
                        tolerance: 0.0,
                    }],
                },
                splits: CampaignSplits {
                    search: dataset("search"),
                    held_out: dataset("held-out"),
                    sealed: dataset("sealed"),
                },
                budget: BudgetLease {
                    budget_id: "scan-check".to_owned(),
                    max_units: 10,
                    exploration_units: 1,
                },
                decide: DecideRules::Dominance,
                knobs: Default::default(),
            };
            config.validate().expect("valid config");
            let config_sha256 = {
                use sha2::Digest;
                format!(
                    "{:x}",
                    sha2::Sha256::digest(serde_json::to_vec(&config).expect("config"))
                )
            };
            vault
                .with_write_txn(|txn| {
                    for index in 0..PAST {
                        let root = crate::attempt_queue::AttemptId::from_bytes(
                            id(0xcd, index).as_bytes(),
                        )?;
                        let binding = ResearchBinding {
                            root,
                            run_id: format!("scan-check-root-{index}"),
                            config: config.clone(),
                            config_sha256: config_sha256.clone(),
                            target: ResearchTarget::Config {
                                subject: "scan-check".to_owned(),
                            },
                            goal: None,
                            holder: None,
                            policy_digest: "scan-check-unused-policy".to_owned(),
                            confirmation: None,
                            share: None,
                            prior_ladder: Vec::new(),
                            execution: None,
                            bound_at: LEARNED_AT,
                        };
                        bindings.put(&vault.store, txn, root.as_bytes(), &binding)?;
                    }
                    Ok(())
                })
                .expect("bindings");
            let coach = crate::attempt_queue::AttemptId::from_bytes(id(0xcd, PAST).as_bytes())
                .expect("coach id");
            Some((
                0,
                Box::new(move || {
                    crate::autoreason_campaign::research::advance_research_continuations(
                        vault, coach, LEARNED_AT,
                    )?;
                    Ok(0)
                }),
            ))
        }

        other => unreachable!("{} is seeded in another module", other.code()),
    }
}

/// `SyncPrefixRows` reads past its FIXED row (rule 5): 10_001 `rm:w:` rows
/// past MAX_SYNC_STATE_KEYS (10_000), served twice, one check at 10_000.
/// Separate from the table because the count sites use `start_at` with the
/// fixed threshold, never the vault row `set_scan_threshold` lowers.
#[test]
fn sync_prefix_rows_reads_past_its_fixed_row() {
    const FIXED: u64 = crate::vault::MAX_SYNC_STATE_KEYS as u64;
    const ROWS: usize = crate::vault::MAX_SYNC_STATE_KEYS + 1;
    const PREFIX: &str = "rm:w:2099-12:scancheck:";
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).expect("open");
    vault
        .with_write_txn(|wtxn| {
            for index in 0..ROWS {
                let key = format!("{PREFIX}{index:05}");
                vault.sync_state_put_in_write_txn(&mut *wtxn, &key, b"scancheck")?;
            }
            Ok(())
        })
        .expect("seed 10_001 rows");
    for _ in 0..2 {
        let keys = vault.sync_state_keys_with_prefix(PREFIX).expect("read");
        assert_eq!(keys.len(), ROWS, "serves every row past the fixed row");
    }
    let checks = vault.scan_checks().expect("checks");
    let raised: Vec<_> = checks
        .iter()
        .filter(|check| check.scan == EngineScan::SyncPrefixRows.code())
        .collect();
    match raised.as_slice() {
        [check] if check.threshold == FIXED && check.rows == ROWS as u64 => {}
        [check] => panic!(
            "raised its check at threshold {} rows {}, not {FIXED} rows {ROWS}",
            check.threshold, check.rows
        ),
        _ => panic!("raised its check {} times, not once", raised.len()),
    }
}
