//! The record seam's inner claim-policy check and its Dreamer isolation class (moved from `claim_write.rs`, FIX 19106).

use super::*;

/// The isolation class of a Dreamer candidate's predicate: a prefix a trusted
/// pack declares persona-core (`persona_core_prefixes`, H393) first, so the
/// host names its own protected namespace and the engine names none; else the
/// built-in tables.
pub(super) fn isolation_class(
    policy: &PolicyManifestResolution,
    predicate: &str,
) -> Option<DreamerIsolationClass> {
    if policy
        .persona_core_prefixes
        .iter()
        .any(|prefix| predicate.starts_with(prefix.as_str()))
    {
        return Some(DreamerIsolationClass::PersonaCore);
    }
    dreamer_isolation_class(predicate)
}

// The inner executor carries the outer record seam's axis tuple plus the
// preflight identity exactly once; a parameter struct would only rename the
// same boundary.
#[expect(
    clippy::too_many_arguments,
    reason = "the record seam carries the preflight receipt identity and explicit write mode"
)]
pub(super) fn check_claim_policy_for_write_with_record_inner(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    recorded_decision: &mut Option<RecordedClaimGateDecision>,
    preflight_decision_id: Option<GateDecisionId>,
    operation_effect_body: bool,
    skip_precommit: bool,
    reader: Option<&crate::claim::ScopedRead<'_>>,
    capture_decision: bool,
) -> Result<()> {
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    let ClaimGateWrite {
        body,
        envelope,
        auto_checker,
        defer_metrics_until_commit,
        transition,
        owner_authored,
        pending_prompt,
    } = write;
    *recorded_decision = None;
    if let Some(envelope) = envelope {
        validate_write_envelope(envelope)?;
    }

    // Preserve the write's member identities for both source-trust checks:
    // the evaluator below and the final Auto ceiling check. No member's
    // permit can answer for a different member of the observed history. An
    // exact close by its verified closer renews neither, and is decided,
    // ceilinged and receipted as that closer (FIX 8655).
    let closing_actor = closer::exact_close_closer(store, &*wtxn, id, body, transition);
    let verified_close = closing_actor.is_some();
    let lineage = envelope
        .map(WriteEnvelope::lineage)
        .filter(|_| !verified_close);

    // GATE-12: Dreamer authorship is detected exactly once, here, and the
    // provenance handle carries it into the evaluator input below. Pre-commit
    // validation asks whether the CLAIM IS VALID, not whether the author is
    // authorized, so it is computed OUTSIDE the `enforces_write_gate` arm: a
    // vault with no policy manifest loaded still refuses a degenerate,
    // malformed or evidence-free Dreamer candidate instead of letting the
    // bootstrap path commit it unchecked.
    //
    // `operation_effect_body` is the ONE exception on a real write, and it is not an exemption
    // from the floor: a host-typed synthetic memory-verb effect body is GATE
    // MATERIAL, never a persisted claim (the verb's traps persist a lifecycle
    // Put plus an Edge, never the body they gate), so asking a claim-candidate
    // question of it is a category error rather than a check it evades. The
    // mode is HOST-CONSTRUCTED at the three synthetic call sites in
    // `claim/put.rs` and is never read off the body, envelope, provenance,
    // predicate, value, approval or actor. It skips pre-commit validation and
    // NOTHING else: detection above, the provenance handles below, policy
    // authority, pending/source-trust behaviour and decision recording all run
    // unchanged — and every persisted Dreamer claim candidate, on every
    // candidate door, still clears the full evidence floor.
    let dreamer_run_id = envelope.and_then(dreamer_run_id_from_write_envelope);
    // The derivation floors (GATE-12, GATE-13, the checker) hold every
    // derivation-class write: a Dreamer run's or a `vault.derive` commit's.
    let dreamer_candidate = envelope.is_some_and(derivation_class_write) && !operation_effect_body;
    // FIX 3983 (review 6881 P1): a caller's live-run claim put is the other Generated producer the
    // host's auto checker reviews. It is not a Dreamer write, so the GATE-12 pre-commit floor above stays
    // Dreamer-only; only the checker consult below reads this.
    let checked_producer =
        dreamer_candidate || envelope.is_some_and(live_run_claim_put_from_write_envelope);
    let precommit_denial = if dreamer_candidate && !skip_precommit {
        dreamer_precommit_denial(store, &*wtxn, body)
    } else {
        None
    };
    // OF-063 (FIX 1218): the reference verdict over the writer's own read.
    let reference_denial =
        reference_hook::reference_denial(&*wtxn, body, reader, operation_effect_body)?;
    let hard_denial = precommit_denial.or(reference_denial);

    if policy.enforces_write_gate() {
        let (actor, provenance, agent_definition_ceiling) = if let Some(envelope) = envelope {
            let actor = closing_actor.unwrap_or_else(|| envelope.actor());
            let agent_definition_ceiling = agent_definition_ceiling_for_actor(store, &*wtxn, actor);
            (
                GateActor {
                    actor_class: edge_actor_class_str(actor.actor_class()).to_owned(),
                    actor_ref: Some(actor.entity_ref().to_hex()),
                    delegation_grant_ref: None,
                },
                GateProvenanceHandles {
                    actor_entity_ref: Some(actor.entity_ref()),
                    derive_commit: dreamer_run_id.is_none() && derivation_class_write(envelope),
                    dreamer_run_id,
                    ..GateProvenanceHandles::default()
                },
                agent_definition_ceiling,
            )
        } else {
            (
                GateActor {
                    actor_class: LOCAL_WRITE_ACTOR_CLASS.to_owned(),
                    actor_ref: None,
                    delegation_grant_ref: None,
                },
                GateProvenanceHandles {
                    actor_entity_ref: Some(local_write_actor_entity_ref()),
                    ..GateProvenanceHandles::default()
                },
                None,
            )
        };
        let mut input = claim_gate_input(
            body,
            policy,
            actor,
            GateContentKind::Claim,
            provenance,
            // Restricted lineage also needs the declared source's normal
            // check and candidate sensitivity, even for non-Auto public writes.
            // This boolean controls input shape, not permit authorization.
            mode.include_source_in_gate_input
                || envelope.is_some_and(WriteEnvelope::effective_requires_explicit_auto_permit)
                    && !verified_close,
            agent_definition_ceiling,
            // Claim bodies carry no effect-fact axes the consent evaluator
            // could classify honestly; this door keeps its pre-DEC-0006
            // criticality behaviour (the `None` arm of `evaluate_gate`)
            // rather than guess at defaults that would silently auto-run.
            None,
        );
        // FIX 8655: an exact close by its verified closer admits nothing
        // new, so the stored body's source and its Auto approval are
        // history, not a request. `claim_gate_input` keeps the source of
        // every Auto body; left in, the evaluator asks the closer for the
        // birth source's Auto permit, and an owner who never held the
        // Dreamer's `generated` permit cannot retract the Dreamer's claim.
        if verified_close {
            input.source = None;
            input.sensitivity_band = None;
        }
        // A pre-commit failure REPLACES the policy verdict: the recording,
        // pending and enforcement paths below then run unchanged, and the
        // Deny aborts the caller's batch op before any claim-side write lands.
        let writing = envelope.map(|envelope| closing_actor.unwrap_or_else(|| envelope.actor()));
        input.foreign_agent_ceiling =
            crate::gate::foreign_agent::resolve_writing(store, &*wtxn, writing)?;
        let mut decision = match hard_denial {
            Some(reason_code) => GateDecision::deny(reason_code),
            None => evaluate_with_delegation_chain(store, &*wtxn, policy, &input, lineage, writing),
        };
        // GATE-13: persona-core and mirroring-prone predicates are isolated
        // for the DREAMER path only, and only AFTER the validity pass above.
        // Authorship reuses the one detection computed at the top of this
        // door, so there is no second notion of "is this a Dreamer write";
        // owner/human writes never enter, and replicated replay never reaches
        // this module at all.
        //
        // The guard is deny-first in both directions. A denial already
        // returned — a GATE-12 validity refusal or a fail-closed policy
        // verdict — is stricter than anything isolation would say, so it
        // stands; isolation may only refuse or park a write that would
        // otherwise have been allowed. It also runs BEFORE the
        // critical-confirm attachment below, whose exact single-code match on
        // `[PendingCriticalityFloor]` an isolation pend can therefore never
        // satisfy: a persona-core write has no confirm-attached Auto path.
        if dreamer_candidate
            && decision.outcome() != GateOutcome::Deny
            && let Some(isolation_class) = isolation_class(policy, &body.predicate)
        {
            decision = dreamer_isolation_decision(store, &*wtxn, body, isolation_class);
        }
        // The subtype confidence floor is a Gate decision, not merely a
        // writer convention. A generic candidate can neither turn a held
        // proposal into Auto nor bypass the stricter care threshold.
        if decision.outcome() == GateOutcome::Allow
            && let Some(kind) =
                crate::write_envelope::carry_forward::CarryForwardKind::from_predicate(
                    &body.predicate,
                )
            && body.confidence
                < policy.carry_forward_floor(
                    kind,
                    envelope.map(|envelope| envelope.actor().entity_ref()),
                )
            && (body.approval == ClaimApprovalStatus::Proposed
                || body.approval == ClaimApprovalStatus::Auto
                    && !transition.is_some_and(|proof| {
                        proof.matches_body(store, &*wtxn, id, body).unwrap_or(false)
                    }))
        {
            decision = GateDecision::pending(vec![GateReasonCode::PendingCarryForwardConfidence]);
        }
        let critical_floor_only = body.approval == ClaimApprovalStatus::Auto
            && critical_claim_can_land_auto_with_confirm(
                &input,
                decision.reason_codes(),
                &body.predicate,
            );
        // Owner-authored writes carry their own confirmation: the vault's
        // owner, revalidated in this transaction, wrote this claim in person,
        // so it lands Auto with nothing to confirm. The proof rides the
        // write's options from the door that authenticated the owner; the
        // envelope only has to name the same actor.
        let owner_write = owner_authored.filter(|write| {
            envelope.is_some_and(|envelope| {
                envelope.actor().entity_ref() == write.actor()
                    && envelope.actor().actor_class() == crate::edge::EdgeActorClass::Human
            })
        });
        let owner_authored = critical_floor_only && owner_write.is_some();
        // Only a declared critical class attaches a confirmation. A predicate
        // no policy rule names resolves Critical by fallback, and that
        // default sets the legibility and truncation floors; it does not stop
        // the write (ARCH-0003 §Criticality, FIX 8782). Attaching for it put a
        // 300 s lapse on every ordinary agent claim, after which it stopped
        // surfacing (FIX 12368). `comm.*` never reaches here:
        // `critical_claim_can_land_auto_with_confirm` already excludes it, so
        // it keeps its floor.
        let declared_critical = policy.declares_predicate_critical(&body.predicate);
        let attach_critical_confirm = critical_floor_only && !owner_authored && declared_critical;
        // A verified close changes only its row's lifecycle, so a stored
        // Approved there is history, not a request: the fallback floor does
        // not stop that close either, as it does not stop an Auto one (an
        // owner's correction closing a settled prior, FIX 22041).
        let approved_close_floor_only = verified_close
            && body.approval == ClaimApprovalStatus::Approved
            && critical_claim_can_land_auto_with_confirm(
                &input,
                decision.reason_codes(),
                &body.predicate,
            );
        let fallback_floor_only = (critical_floor_only || approved_close_floor_only)
            && !owner_authored
            && !declared_critical;
        if owner_authored {
            decision = GateDecision::allow()
                .with_receipt_reasons([GATE_REASON_ALLOW_CRITICAL_OWNER_AUTHORED]);
        } else if attach_critical_confirm {
            decision = GateDecision::allow()
                .with_receipt_reasons([GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED]);
        } else if fallback_floor_only {
            decision = GateDecision::allow()
                .with_receipt_reasons([GATE_REASON_ALLOW_FALLBACK_CRITICALITY]);
        }

        // ONE-1296: the host's auto checker is the LAST word on an ORDINARY
        // Auto verdict, and only that. It runs after everything the engine
        // decides for itself — pre-commit validity, the policy verdict,
        // GATE-13 isolation, the critical-confirm attachment — so a write
        // already refused or already parked is never consulted about, and the
        // checker can only NARROW a verdict, never widen one.
        //
        // The consult is EXACTLY: a manifest names a checker, the ordinary
        // decision is Auto, the write is an agent-class Dreamer write or a
        // caller's live-run claim put (FIX 3983; its Proposed resubmission
        // too, so a hold parks it with a pending review, review 6908 P1), and its
        // source is one that requires an explicit auto permit. Human and owner
        // writes therefore never reach a checker at all. A door that injects
        // no checker for a write the manifest wants checked gets no verdict,
        // so the write pends as checker-unavailable rather than landing
        // unreviewed.
        //
        // A confirm-attached Auto is excluded because it is not the ordinary
        // verdict: the ordinary verdict there was a criticality-floor PEND,
        // and what replaced it is an owner ceremony bound to this exact claim.
        // A host hedge must not overrule a confirmation the owner just gave,
        // and rewriting that decision would also drop the criticality marker
        // the inbox classifies on.
        //
        // ONE-1314 widens this source check to source OR lineage.
        // This only selects a checker consult; authorization still checks
        // each restricted lineage member's own permit above and below.
        let model_manifest = crate::llm::manifest::read_manifest(store, &*wtxn)?;
        let verdict_binding = model_manifest.as_ref().and_then(|m| m.verdict.as_ref());
        let mut checker_receipt_reasons: Vec<String> = Vec::new();
        if decision.outcome() == GateOutcome::Allow
            && !attach_critical_confirm
            && checked_producer
            && (policy.auto_checker().is_some() || verdict_binding.is_some())
            && preflight_decision_id.is_none()
            && let Some(source) = body.source.filter(|source| {
                source.requires_explicit_auto_permit()
                    || lineage.is_some_and(SourceLineage::requires_explicit_auto_permit)
            })
            && !closes_stored_value(store, &*wtxn, id, body, transition)
        {
            // A value the preview cannot hold whole is never sent: the
            // checker would answer for a prefix while the write stores the
            // rest. With no checker to ask, the write is held below.
            let value_preview = auto_check_value_preview(&body.value);
            if value_preview.is_none() {
                checker_receipt_reasons.push(CHECKER_PARTIAL_VIEW_RECEIPT_REASON.to_owned());
            }
            let auto_checker = auto_checker.filter(|_| value_preview.is_some());
            let value_preview = value_preview.unwrap_or_default();
            let candidate = AutoCheckCandidate {
                signals: crate::gate::auto_signals::auto_check_signals(
                    store,
                    &*wtxn,
                    input.actor.actor_ref.as_deref(),
                    crate::unix_seconds_now(),
                )?,
                predicate: &body.predicate,
                value_preview: &value_preview,
                source,
                lineage,
                actor_class: &input.actor.actor_class,
                sensitivity_band: claim_sensitivity_band(body),
                burst: input
                    .provenance
                    .actor_entity_ref
                    .map(|actor| {
                        claim_burst_inputs(
                            store,
                            &*wtxn,
                            &actor,
                            &input.actor.actor_class,
                            crate::unix_seconds_now(),
                        )
                    })
                    .transpose()?,
            };
            // The concrete wrapper is required at every injection boundary:
            // one capacity-bounded consult, with panic and timeout isolation.
            let outcome = auto_checker.map_or(AutoCheckOutcome::Unavailable, |checker| {
                checker.check(&candidate)
            });
            let (outcome, verdict_note) =
                crate::claim_check::apply_verdict_floor(verdict_binding, outcome);
            if let Some(note) = verdict_note.and_then(checker_hold_receipt_reason) {
                checker_receipt_reasons.push(note);
            }
            match outcome {
                AutoCheckOutcome::Allow => {}
                AutoCheckOutcome::Verdict(_) => unreachable!("floor consumes calibrated outcomes"),
                AutoCheckOutcome::Hold { reasons } => {
                    // A host names its reasons in prose; the decision ledger's
                    // receipt field is a closed token vocabulary vetted on the
                    // append AND decode paths. Rendering them here is what
                    // keeps a hold RECORDABLE: the raw text would fail the vet
                    // and cost the whole decision row, so the write the
                    // checker meant to park would fail with a corrupt-ledger
                    // error instead of parking.
                    checker_receipt_reasons = reasons
                        .iter()
                        .filter_map(|reason| checker_hold_receipt_reason(reason.as_str()))
                        .collect();
                    // Same rule `AutoCheckOutcome::normalized` already applies
                    // one step earlier: a hold left naming no reason is a
                    // malformed verdict, not a quiet hold, and an unexplained
                    // refusal on the receipt is the one thing this seam must
                    // not produce. Both verdicts park the write, so nothing
                    // widens either way.
                    decision = if checker_receipt_reasons.is_empty() {
                        GateDecision::pending(vec![GateReasonCode::PendingCheckerUnavailable])
                    } else {
                        GateDecision::pending(vec![GateReasonCode::PendingChecker])
                    };
                }
                AutoCheckOutcome::Unavailable => {
                    decision =
                        GateDecision::pending(vec![GateReasonCode::PendingCheckerUnavailable]);
                }
            }
        }

        // FIX 3433: an Allow landing past Proposed under the owner's
        // auto-weave Grant records that Grant and a positive reason. It
        // changes no verdict; any other landing records as before.
        let weave_grant = if decision.outcome() == GateOutcome::Allow
            && !attach_critical_confirm
            && owner_write.is_none()
            && !verified_close
        {
            landing_weave_grant_in_txn(store, &*wtxn, writing, body)?
        } else {
            None
        };

        let binding = GateConsentBinding::for_claim(body, policy)?;
        let decision_id = crate::store::GateDecisionId::from_bytes(store.clock.ulid()?);
        let created_at = mutation_recorded_at;
        let mut decision_record = GateDecisionRecord {
            version: 0,
            decision_id,
            created_at,
            outcome: decision.outcome().as_str().to_owned(),
            reason_codes: decision
                .reason_codes()
                .iter()
                .map(|code| code.as_str().to_owned())
                .collect(),
            receipt_reasons: decision
                .receipt_reasons()
                .iter()
                .map(|reason| (*reason).to_owned())
                // The checker's own reasons append to the receipt, rendered
                // above into the ledger's token vocabulary: an owner reviewing
                // a held write reads WHY the host held it, not just that
                // something did.
                .chain(
                    decision
                        .policy_row_ref()
                        .map(|row| format!("policy_row_{row}")),
                )
                .chain(decision.precedence_row_ref().map(|row| match row {
                    Some(row) => format!("policy_precedence_row_{row}"),
                    None => "policy_precedence_shipped_default".to_owned(),
                }))
                .chain(decision.delegation_narrowing_receipt())
                .chain(checker_receipt_reasons)
                .chain(
                    weave_grant
                        .as_ref()
                        .map(|_| GATE_REASON_ALLOW_WEAVE_GRANT.to_owned()),
                )
                .collect(),
            system_notices: Vec::new(),
            actor_class: input.actor.actor_class.clone(),
            actor_ref: input.actor.actor_ref.clone(),
            content_kind: input.content_kind.as_str().to_owned(),
            policy_manifest_version: input.policy_manifest_version,
            claim_id: Some(*id.as_bytes()),
            grant_ref: weave_grant,
            diff_handle: binding.diff_handle.clone(),
            read_frontier_hash: binding.read_frontier_hash,
            context: decision_context::claim_decision_context_store_in(
                store,
                &*wtxn,
                id,
                body,
                input.provenance.dreamer_run_id.as_deref(),
                envelope.and_then(dreamer_attempt_id_from_write_envelope),
                pending_prompt,
            ),
            redacted_at: None,
        };

        if matches!(input.actor.actor_class.as_str(), "agent" | "system")
            && policy.criticality_for_predicate(&body.predicate)
                == crate::gate::PolicyCriticality::Normal
        {
            decision_record.receipt_reasons.push(
                crate::self_heal::tripwires::normal_baseline_token(&body.predicate),
            );
        }
        // FIX 8752: a batch apply skips the checker its preflight already
        // asked, so policy alone answers Allow here. A checker hold that
        // preflight recorded for this same candidate stays the verdict: the
        // write lands held, and the writer below binds that receipt's pending
        // row instead of dropping the hold. A fresh Deny or Pending stands.
        if decision.outcome() == GateOutcome::Allow
            && let Some(preflight_id) = preflight_decision_id
        {
            let preflight = store.gate_decision_in_txn(&*wtxn, preflight_id)?.ok_or(
                Error::InvariantViolation("preflight gate decision missing during apply"),
            )?;
            let checker_hold = [
                GateReasonCode::PendingChecker,
                GateReasonCode::PendingCheckerUnavailable,
            ]
            .into_iter()
            .find(|reason| {
                preflight.outcome == GateOutcome::Pending.as_str()
                    && preflight.reason_codes.as_slice() == [reason.as_str()]
            });
            if let Some(reason) = checker_hold {
                let mut held = decision_record.clone();
                held.outcome.clone_from(&preflight.outcome);
                held.reason_codes.clone_from(&preflight.reason_codes);
                held.receipt_reasons.clone_from(&preflight.receipt_reasons);
                held.grant_ref.clone_from(&preflight.grant_ref);
                if !gate_decision_matches_pending_candidate(&preflight, &held) {
                    return Err(Error::InvariantViolation(
                        "preflight gate decision does not match pending candidate",
                    ));
                }
                decision = GateDecision::pending(vec![reason]);
                decision_record = held;
            }
        }
        if mode.record_decision {
            // A structural streak follows durable append order, including
            // ordinary receipts created within the same clock millisecond.
            store.append_fresh_gate_decision_in_txn(wtxn, &mut decision_record)?;
            store.stamp_claim_gate_retention_context_in_txn(
                wtxn,
                decision_record.decision_id,
                id,
                crate::gate::GateRetentionContext {
                    world: Some(body.world.unwrap_or_else(crate::claim::base_world_id)),
                    project: Some(body.scope_project),
                    sub_project: None,
                    thread: None,
                },
            )?;
            let recorded = RecordedClaimGateDecision {
                record: decision_record.clone(),
                decision: decision.clone(),
            };
            if !defer_metrics_until_commit {
                recorded.record_metrics(&store.diagnostics.gate);
            }
            *recorded_decision = Some(recorded);
        } else if capture_decision {
            // An off-record room's claim (FIX 9967): the decision as judged,
            // for the room to stage beside its claim. Nothing is appended,
            // no metric is recorded and no key custody is touched here.
            *recorded_decision = Some(RecordedClaimGateDecision {
                record: decision_record.clone(),
                decision: decision.clone(),
            });
        }

        if mode.persist_pending_consent
            && ((decision.outcome() == GateOutcome::Pending
                && body.approval == ClaimApprovalStatus::Proposed)
                || (attach_critical_confirm && body.approval == ClaimApprovalStatus::Auto))
        {
            let pending_decision = if mode.record_decision {
                decision_record.clone()
            } else if let Some(decision_id) = preflight_decision_id {
                let record = store.gate_decision_in_txn(&*wtxn, decision_id)?.ok_or(
                    Error::InvariantViolation(
                        "preflight gate decision missing during pending bind",
                    ),
                )?;
                if !gate_decision_matches_pending_candidate(&record, &decision_record) {
                    return Err(Error::InvariantViolation(
                        "preflight gate decision does not match pending candidate",
                    ));
                }
                record
            } else {
                // Caller-owned transactions have no same-transaction preflight
                // identity, so they always mint a new attachment receipt.
                store.append_fresh_gate_decision_in_txn(wtxn, &mut decision_record)?;
                store.diagnostics.gate.record_decision(&decision);
                decision_record.clone()
            };
            let pending = PendingGateConsentRecord {
                version: crate::store::PENDING_GATE_CONSENT_VERSION,
                claim_id: *id.as_bytes(),
                decision_id: pending_decision.decision_id,
                created_at: pending_decision.created_at,
                diff_handle: pending_decision.diff_handle,
                read_frontier_hash: pending_decision.read_frontier_hash,
                reason_codes: if attach_critical_confirm {
                    vec![GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED.to_owned()]
                } else {
                    pending_decision.reason_codes
                },
                dreamer_run_id: pending_consent_dreamer_run_id(envelope, body),
                predicate: Some(body.predicate.clone()),
                // The confirm's deadline is the policy's lifetime now,
                // frozen with it (FIX 8760).
                expires_at: attach_critical_confirm.then(|| {
                    pending_decision
                        .created_at
                        .saturating_add(policy.critical_confirm_lifetime_seconds())
                }),
            };
            store.put_pending_gate_consent_in_txn(wtxn, &pending)?;
            // A fresh local confirm on this revision is the item the claim's
            // owner answers now. Ordinary pending work and replicated input
            // never rebind it.
            if attach_critical_confirm {
                crate::gate::owner_answer::rebind_owner_answer_obligation_in_txn(
                    store, wtxn, id, &pending,
                )?;
            }
        }
        // A revision its owner wrote in person answers whatever the claim's
        // owner had not.
        if owner_authored
            && mode.persist_pending_consent
            && let Some(write) = owner_write
        {
            crate::gate::owner_answer::close_owner_answer_obligation_by_owner_revision_in_txn(
                store, wtxn, id, write,
            )?;
        }

        let resolve_pending = mode.resolve_pending && !attach_critical_confirm;
        // A held claim's own close (a supersession or retraction that changes
        // only its lifecycle) narrows it and is not the owner's answer: its
        // tray row goes silently, as a retraction's does, and the obligation
        // stays open. Redeeming the confirm instead would fail on a binding to
        // the body it closes.
        if resolve_pending
            && decision.outcome() == GateOutcome::Allow
            && closes_stored_row_only(store, &*wtxn, id, body, transition)
            && store
                .pending_gate_consent_in_txn(&*wtxn, id)?
                .is_some_and(|row| pending_row_holds_critical_confirm(&row))
        {
            store.remove_pending_gate_consent_in_txn(wtxn, id, TrayRemoval::Silent)?;
        }
        enforce_claim_gate_decision_with_consent(
            store,
            wtxn,
            id,
            &decision,
            body.approval,
            &binding,
            GateWriteMode {
                resolve_pending,
                ..mode
            },
            owner_write,
        )?;
    } else if let Some(reason_code) = hard_denial {
        // No manifest is loaded, so there is no policy verdict for the denial
        // to replace and no gate-decision row this bootstrap path would have
        // written anyway. The refusal itself is not optional: the same Deny
        // reaches the caller and aborts the batch op before any claim-side
        // write lands, so an absent manifest cannot be used to smuggle an
        // invalid Dreamer claim past the pre-commit floor.
        return reject_gate_decision(GateDecision::deny(reason_code));
    }

    if verified_close {
        return Ok(());
    }
    let actor_ref = write_envelope_actor_ref(envelope);
    check_claim_source_trust(body, actor_ref.as_deref(), policy, lineage)
}
