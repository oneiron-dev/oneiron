//! The whole external-effect governance evaluation; `effect` re-exports it.

use super::*;

/// Evaluates consent and connector governance without charging or recording.
/// The caller must either finalize the returned decision or abort its txn.
pub(crate) fn evaluate_external_effect_policy(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    required_grant_id: Option<EntityId>,
    prepared: Option<&crate::outbound_consent::tool_call::PreparedToolCall>,
    approval_context: ApprovalContext,
) -> Result<ExternalEffectGovernance> {
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    let (mut hydrated_effect, counterparty_send_override, counterparty_contact_revoked) =
        hydrate_external_effect_contact(store, &*wtxn, effect, policy)?;
    // Send eligibility is checked with the Gate's writer snapshot. A sender
    // released after dispatch preparation cannot authorize even a known
    // contact through an ordinary policy grant. Terminal replay never enters
    // this evaluation lane.
    if hydrated_effect.channel == "email"
        && hydrated_effect.verb == "send"
        && let Some(identity) = hydrated_effect.channel_identity_ref
        && crate::channel_identity_provider::native_mail::is_native_mail_identity_in_txn(
            store, &*wtxn, identity,
        )?
        && !crate::channel_identity_provider::native_mail::native_mail_actor_may_send_in_txn(
            store,
            &*wtxn,
            identity,
            hydrated_effect.provenance.actor_entity_ref,
        )?
    {
        return Err(crate::error::Error::InvalidConfig(
            "inactive native-mail sender".into(),
        ));
    }
    // OF-374: the same writer-snapshot check for a member mailbox. A row
    // released, or a grant that lost send, after preparation sends nothing.
    if hydrated_effect.channel == "email"
        && hydrated_effect.verb == "send"
        && let Some(identity) = hydrated_effect.channel_identity_ref
        && crate::channel_identity_provider::member_mail::is_member_mail_identity_in_txn(
            store, &*wtxn, identity,
        )?
        && !crate::channel_identity_provider::member_mail::member_mail_actor_may_send_in_txn(
            store,
            &*wtxn,
            identity,
            hydrated_effect.provenance.actor_entity_ref,
        )?
    {
        return Err(crate::error::Error::InvalidConfig(
            "inactive member-mail sender".into(),
        ));
    }
    hydrated_effect.standing_grant_ref = None;
    let mut scoped_mcp_grant_authorized = false;
    let matched_grant = standing_outbound_grant_for_effect(
        store,
        wtxn,
        &hydrated_effect,
        policy,
        required_grant_id,
        prepared,
    )?;
    if let Some((grant_id, grant)) = matched_grant.as_ref() {
        hydrated_effect.standing_grant_ref = Some(format!("grant:{}", grant_id.to_hex()));
        scoped_mcp_grant_authorized = grant.scope.scoped_mcp_grant().is_some();
    }
    // The effect door NEVER gates ceiling resolution on the caller-asserted
    // class alone: the resolver binds the identity pair, derives authority
    // from the governing entity's own type, and fails closed on unrecognized
    // class assertions.
    let agent_definition_ceiling = agent_definition_ceiling_for_effect_actor(
        store,
        &*wtxn,
        &hydrated_effect.actor.actor_class,
        hydrated_effect.actor.actor_ref.as_deref(),
        hydrated_effect.provenance.actor_entity_ref,
    );
    // DEC-0006: this door composes its consent context at the chokepoint, so
    // consent is evaluated by the one ladder rather than re-implemented per
    // call site. The coverage set folds three already-verified authorization
    // facts read on THIS write txn — the vault's ACTIVE consent grants, the
    // scope-matched `StandingOutboundGrant` (through the pinned adapter), and
    // any budget-free POLICY-scoped grant the compiler's four-axis matcher
    // accepts (echoed as a covering grant; see below) — so an effect already
    // authorized on remembered state is Auto on the consent axis exactly once,
    // honors revocation immediately, and an UNGRANTED irreversible effect is
    // the only one that enters the ask lane (invariant 1).
    let mut consent_grants = crate::consent::load_active_standing_grants(store, wtxn)?;
    let mail_cold = crate::channel_identity_provider::native_mail::native_mail_cold_send_in_txn(
        store,
        &*wtxn,
        &hydrated_effect,
        policy,
    )?;
    // OF-374: a member-mailbox send takes the same canonical mail digest, so
    // one owner press releases exactly that send (ARCH-0046 "a press per
    // send"); a covering standing grant still releases it with no press.
    let member_mail = crate::channel_identity_provider::member_mail::member_mail_send_in_txn(
        store,
        &*wtxn,
        &hydrated_effect,
    )?;
    let mail_once = mail_cold || member_mail;
    let mail_graduated = crate::channel_identity_provider::native_mail::mail_graduated_in_txn(
        store,
        &*wtxn,
        &hydrated_effect,
        policy,
    )?;
    let provisional = hydrated_effect.gate_input(agent_definition_ceiling, None);
    let requirement = external_effect_action_requirement(&hydrated_effect);
    let mail_retry_authorized = match approval_context {
        ApprovalContext::Retry(proof) => native_mail_cold_composed_effect(&hydrated_effect)
            .is_some_and(|effect| effect.digest() == proof.effect_digest()),
        _ => false,
    };
    // FIX 6362/6679: an e-sign or failure-signal retry on its recorded press.
    let press_retry_authorized =
        admitted_approval::press_retry_authorized(&hydrated_effect, approval_context);
    if (mail_retry_authorized || press_retry_authorized)
        && let Some(bound) = requirement.as_ref()
        && let Ok(grant) = crate::consent::ActionGrant::new(bound.clone())
    {
        consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
    }
    if mail_graduated
        && let Some(bound) = requirement.as_ref()
        && let Ok(grant) = crate::consent::ActionGrant::new(bound.clone())
    {
        // DEC-0006 evaluates its ordinary send requirement. The separate
        // cold-mail class is echoed as coverage only after the gate has
        // checked recipient class, actor, sender, and live owner grant here.
        consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
    }
    // OF-374 (L02 seam): a sender row at `AutonomousWithinEnvelope` releases
    // this send with no press while its envelope has room (ARCH-0063). The
    // slot is proven here and spent only with an admitting Allow; a held,
    // denied or observed send spends nothing, and an exact replay finds its
    // own slot. A native-mail cold send keeps its own OF-399 graduation.
    // FIX 7948: a full window gives the send its place in the envelope's
    // line instead; a grant that refuses keeps the press.
    let envelope_admission = if mail_cold {
        None
    } else {
        native_mail_cold_composed_effect(&hydrated_effect)
            .map(|composed| {
                channel_identity_envelope_admission_in_txn(
                    store,
                    &*wtxn,
                    &hydrated_effect,
                    *composed.digest().as_bytes(),
                    mutation_recorded_at,
                )
            })
            .transpose()?
            .flatten()
    };
    let (envelope_reservation, mut envelope_wait) = match envelope_admission {
        Some(crate::outbound_grant::ChannelIdentityGrantAdmission::Reserved(reservation)) => {
            (Some(*reservation), None)
        }
        Some(crate::outbound_grant::ChannelIdentityGrantAdmission::WindowWait(place)) => {
            (None, Some(place))
        }
        Some(crate::outbound_grant::ChannelIdentityGrantAdmission::Denied) | None => (None, None),
    };
    if envelope_reservation.is_some()
        && let Some(bound) = requirement.as_ref()
        && let Ok(grant) = crate::consent::ActionGrant::new(bound.clone())
    {
        consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
    }
    if let (Some(requirement), Some(effect_ctx)) =
        (requirement, provisional.external_effect.as_ref())
    {
        let scoped_covers = policy.scoped_grants().iter().any(|grant| {
            grant.budget.is_none()
                && external_effect_grant_matches(grant, &provisional.actor, effect_ctx)
        });
        if scoped_covers && let Ok(grant) = crate::consent::ActionGrant::new(requirement.clone()) {
            consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
        }
        // A scope-matched `StandingOutboundGrant` resolved on this txn — the
        // matcher already enforced actor identity, channel/contact/verb-class
        // scope, and ACTIVE status — is folded as remembered coverage by
        // ECHOING the requirement as its covering grant. Dial vocabularies
        // differ per scope kind (channel/contact/brief/scoped-MCP), so the
        // adapter's normalized bound cannot be trusted to subset-match the
        // requirement's verb-shaped selectors; the door's own four-axis match
        // is the authority the echo records. Revocation is honored by the
        // matcher upstream: a revoked row never reaches this arm.
        if matched_grant.is_some()
            && let Ok(grant) = crate::consent::ActionGrant::new(requirement)
        {
            consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
        }
    }
    // A payload-aware scoped-MCP grant ALREADY authorized this effect at the
    // registry-match stage (`scoped_mcp_grant_authorized`) — the only safe MCP
    // auto path. Fold it: the effect is consent-covered, not re-asked.
    if scoped_mcp_grant_authorized
        && let Some(requirement) = external_effect_action_requirement(&hydrated_effect)
        && let Ok(grant) = crate::consent::ActionGrant::new(requirement)
    {
        consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
    }
    // ARCH-0072 `always allow` (L08 seam addition): the governing key's slate
    // row bypasses the per-call ask. It folds in as a covering grant only, so
    // a catastrophe still asks inside the consent verdict (DEC-0006).
    let slate_scoped = matched_grant
        .as_ref()
        .filter(|(_, grant)| grant.scope.scoped_mcp_grant().is_some())
        .zip(hydrated_effect.scoped_mcp_call.as_ref())
        .map(|((grant_id, _), call)| (call.server.as_str(), grant_id, call.tool.as_str()));
    if connector_key::effect_slate_always_allows(
        store,
        &*wtxn,
        &hydrated_effect.channel,
        &hydrated_effect.verb,
        slate_scoped,
        hydrated_effect.provenance.actor_entity_ref.as_ref(),
    )? && let Some(requirement) = external_effect_action_requirement(&hydrated_effect)
        && let Ok(grant) = crate::consent::ActionGrant::new(requirement)
    {
        consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
    }
    // The exact engine-computed digest is the only approve-once lookup key.
    // Reading it on THIS write transaction yields either no approval, one
    // unforgeable available authorization, or a typed spent-replay refusal.
    // The marker is changed to spent only when the final Gate decision is
    // recorded as Allow in this same transaction.
    let code_wait = match approval_context {
        ApprovalContext::CodeWait(binding_digest) => Some(binding_digest),
        _ => None,
    };
    let composed = if mail_once || mail_retry_authorized {
        native_mail_cold_composed_effect(&hydrated_effect)
    } else if let Some(binding_digest) = code_wait.as_ref() {
        effect_consent::code_wait_composed_effect(&hydrated_effect, binding_digest)
    } else {
        external_effect_composed_effect(&hydrated_effect)
    };
    let approve_once = if mail_retry_authorized || press_retry_authorized {
        None // The first admission spent it; this exact Pending retry reuses it.
    } else {
        composed
            .as_ref()
            .map(|effect| {
                crate::consent::approve_once_authorization_in_txn(store, &*wtxn, &effect.digest())
            })
            .transpose()?
            .flatten()
    };
    let consent_under = |grants: &[crate::consent::StandingConsentGrant]| {
        if mail_once || mail_retry_authorized || code_wait.is_some() {
            composed
                .as_ref()
                .map(|effect| ConsentGateContext::evaluate(effect, approve_once.as_ref(), grants))
        } else {
            external_effect_consent_context(&hydrated_effect, approve_once.as_ref(), grants)
        }
    };
    let mut consent = consent_under(&consent_grants);
    // FIX 7948: a full window holds the send in its envelope's line only when
    // that envelope is all that would cover it; a press or another grant
    // releases it as before. Its grant does cover it, so the Gate judges the
    // send as covered, and the chokepoint keeps its place instead of
    // admitting it.
    envelope_wait = envelope_wait.filter(|_| {
        consent
            .as_ref()
            .is_some_and(|context| context.decision != crate::consent::ConsentDecision::Auto)
    });
    if envelope_wait.is_some()
        && let Some(requirement) = external_effect_action_requirement(&hydrated_effect)
        && let Ok(grant) = crate::consent::ActionGrant::new(requirement)
    {
        consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
        consent = consent_under(&consent_grants);
    }
    let mut input = hydrated_effect.gate_input(agent_definition_ceiling, consent);
    // Resolve by audited identity, regardless of the caller's actor-class spelling.
    input.foreign_agent_ceiling = hydrated_effect
        .provenance
        .actor_entity_ref
        .map(|actor| {
            super::super::foreign_agent::resolve(
                store,
                &*wtxn,
                crate::write_envelope::WriteActor::new(actor, crate::edge::EdgeActorClass::Agent),
            )
        })
        .transpose()?
        .flatten();
    if let Some(effect) = input.external_effect.as_mut() {
        effect.scoped_mcp_grant_authorized = scoped_mcp_grant_authorized;
        effect.mail_graduated = mail_graduated;
        effect.mail_approve_once = mail_retry_authorized || (mail_once && approve_once.is_some());
        // Only a still-available marker looked up by the engine-computed,
        // exact publish digest can release this one proposed public effect.
        effect.artifact_publish_approve_once = approve_once.is_some()
            && hydrated_effect.channel == "artifact"
            && hydrated_effect.verb == "publish"
            && hydrated_effect.brief_ref.is_some();
        // ONE-1752: the same post-conversion seam. Hydration cannot reach a
        // context that does not exist until `gate_input()` builds it, so the
        // override it resolved is written on here, once, before evaluation.
        effect.counterparty_send_override = counterparty_send_override;
        effect.counterparty_contact_revoked = counterparty_contact_revoked;
    }
    let mut decision = policy.evaluate_gate(&input);
    let binding = GateConsentBinding::for_external_effect(&input, policy)?;
    let decision_id = crate::store::GateDecisionId::from_bytes(store.clock.ulid()?);
    let created_at = mutation_recorded_at;
    let grant_ref = input
        .external_effect
        .as_ref()
        .and_then(|effect| effect.standing_grant_ref.clone());

    // CA-06 campaign-compliance stage (ONE-1777). The evaluator hydrates its
    // own typed facts from the claim substrate on THIS txn and answers with a
    // pure verdict; the mapping to a decision stays here, where decisions are
    // constructed. It runs BEFORE the connector-key and budget stages — both
    // guarded on would-be-Allow — so a legal-row refusal never consumes budget,
    // exactly like the counterparty-opt-out wall. It converts a would-be Allow
    // AND a Pending: an owner approval must not be able to unlock a dispatch
    // the governing row forbids. It is enforcement, not a new approval step;
    // effects outside a campaign never reach the evaluator at all.
    if decision.outcome() != GateOutcome::Deny
        && let Some(crate::campaign::compliance::ComplianceVerdict::Block { reason, .. }) =
            crate::campaign::compliance::campaign_compliance_gate(
                store,
                &*wtxn,
                &hydrated_effect,
                created_at,
            )?
    {
        decision = GateDecision::deny(GateReasonCode::DenyCampaignCompliance)
            .with_receipt_reasons([reason.receipt_reason()])
            .with_receipt_reasons(external_effect_receipt_reasons(
                input
                    .external_effect
                    .as_ref()
                    .expect("external effect input"),
            ));
    }

    // GOV-01 connector-key stage (ONE-1416). Channel keys retain
    // unset-is-noop; synthetic scoped-MCP keys fail closed below. The status
    // wall and the budget stage are BOTH guarded on would-be-Allow (M1
    // resolution 2026-07-10): a law-class deny from `evaluate_gate` (e.g.
    // counterparty opt-out) keeps its reason code and never consumes budget.
    let normalized_channel = connector_key::normalize_connector_key(&hydrated_effect.channel);
    // The ONE typed per-grant capability identity in this scope. It is minted
    // only from the VERIFIED matched scoped-MCP grant and its admitted call's
    // safe canonical server — never from the effect's channel text — and it is
    // what the charter stage, the chokepoint, and the durable row all carry
    // (ONE-1885).
    let scoped_mcp_capability = matched_grant.as_ref().and_then(|(grant_id, grant)| {
        grant.scope.scoped_mcp_grant().and_then(|_| {
            hydrated_effect.scoped_mcp_call.as_ref().and_then(|call| {
                connector_key::ScopedCapabilityProvenance::mint(&call.server, grant_id)
            })
        })
    });
    let uses_scoped_mcp_governing_connector = matched_grant
        .as_ref()
        .is_some_and(|(_, grant)| grant.scope.scoped_mcp_grant().is_some())
        && hydrated_effect.scoped_mcp_call.is_some();
    let governing_connector = scoped_mcp_capability.as_ref().map_or_else(
        || normalized_channel.clone(),
        |capability| capability.connector().to_owned(),
    );
    let governing = connector_key::governing_connector_key(
        store,
        wtxn,
        &governing_connector,
        hydrated_effect.provenance.actor_entity_ref.as_ref(),
    )?;
    let budget_target = governing
        .as_ref()
        .map(|(key_id, key)| ExternalEffectBudgetTarget {
            key_id: *key_id,
            key: key.clone(),
            governing_connector: governing_connector.clone(),
        });
    if uses_scoped_mcp_governing_connector
        && decision.outcome() == GateOutcome::Allow
        && (scoped_mcp_capability.is_none() || governing.is_none())
    {
        // The real completion—registering each per-grant connector key through
        // the connector lifecycle—rides ONE-1794 with the live transport.
        // Until then, scoped MCP authority fails closed instead of inheriting
        // the channel unset-is-noop behavior. A matched scoped grant whose
        // server cannot produce the one safe canonical capability identity has
        // no per-grant key at all and fails closed on this same wall rather
        // than falling back to the ordinary channel key (ONE-1885).
        decision = GateDecision::pending(vec![GateReasonCode::PendingConnectorKeyUnregistered])
            .with_receipt_reasons(["connector_key_unregistered"])
            .with_receipt_reasons(external_effect_receipt_reasons(
                input
                    .external_effect
                    .as_ref()
                    .expect("external effect input"),
            ));
    }
    if let Some((_key_id, key)) = governing
        && decision.outcome() == GateOutcome::Allow
    {
        // GOV-10 charter stage (ONE-1417), between the status wall and the
        // budget stage: enforcement reads ONLY the compiled policy, never the
        // charter text. Drift degrades to proposed-only (Pending) until a
        // human re-stamps; a never-list match denies. Neither debits.
        // A per-grant key's call meets its catalog connector's charter too
        // (ONE-1794); the first wall wins.
        let mut charter_wall = None;
        let catalog_charter = connector_key::catalog_charter_in_txn(store, &*wtxn, &key)?;
        for block in key.charter.iter().chain(catalog_charter.iter()) {
            if key.status != ConnectorKeyStatus::Active || charter_wall.is_some() {
                break;
            }
            let effect_verb = hydrated_effect
                .scoped_mcp_call
                .as_ref()
                .map_or(hydrated_effect.verb.as_str(), |call| call.tool.as_str());
            // The two never-list modes are read separately and never confused.
            // A capability dispatch is measured against its typed identity by
            // the capability-only rules, and against the ORDINARY channel it
            // travels on (`mcp:{server}`, derived from that same typed value so
            // recovery reads the identical string) by the ordinary rules.
            let never_list_matches = || match scoped_mcp_capability.as_ref() {
                Some(capability) => {
                    connector_key::charter_never_list_matches_capability(block, capability)
                        || connector_key::charter_never_list_matches_scoped_channel(
                            block,
                            &capability.ordinary_channel(),
                            effect_verb,
                        )
                }
                None => connector_key::charter_never_list_matches(
                    block,
                    &governing_connector,
                    effect_verb,
                ),
            };
            if connector_key::charter_block_drifted(block)? {
                charter_wall = Some(
                    GateDecision::pending(vec![GateReasonCode::PendingCharterDrift])
                        .with_receipt_reasons(["charter_drift"]),
                );
            } else if never_list_matches() {
                charter_wall = Some(
                    GateDecision::deny(GateReasonCode::DenyCharterNeverList)
                        .with_receipt_reasons(["charter_never_list"]),
                );
            }
        }

        // A rendered scoped call binds the approved snapshot and revision.
        // Check the binding before per-tool drift classification: a removed or
        // renamed tool can make `tool_requires_confirmation` true, but if its
        // approved manifest changed the useful refusal is the stale snapshot
        // with the current hash. It must also run before budget admission.
        if charter_wall.is_none()
            && uses_scoped_mcp_governing_connector
            && prepared.is_some()
            && let Some(manifest) = key.retained_manifest.as_ref()
        {
            let current_hash = manifest.hash()?;
            if prepared
                .and_then(|call| call.manifest_binding())
                .is_none_or(|binding| {
                    binding.key_ref != _key_id.to_hex()
                        || binding.manifest_hash != current_hash
                        || Some(binding.protocol_revision.as_str())
                            != key.protocol_revision.as_deref()
                })
            {
                charter_wall = Some(
                    GateDecision::pending(vec![GateReasonCode::PendingConnectorManifestStale])
                        .with_receipt_reasons(["connector_manifest_stale"]),
                );
            }
        }

        // Retained resolved schemas are the only auto-fire surface. A staged
        // change downgrades just the affected tool; other rows remain live.
        let manifest_verb = hydrated_effect
            .scoped_mcp_call
            .as_ref()
            .map_or(hydrated_effect.verb.as_str(), |call| call.tool.as_str());
        if charter_wall.is_none()
            && (key.tool_requires_confirmation(manifest_verb)
                || uses_scoped_mcp_governing_connector
                    && prepared.is_some()
                    && key.retained_manifest.is_none())
        {
            charter_wall = Some(
                GateDecision::pending(vec![GateReasonCode::PendingConnectorManifestDrift])
                    .with_receipt_reasons(["connector_manifest_drift"]),
            );
        }

        // ARCH-0072 capability settings (L08 seam addition): `never allow`
        // removes the tool; `always ask` asks unless this exact call was
        // approved once. FIX 990 (L02 splice): a Pending retry's own kept
        // scoped-MCP press, validated above against this call's pinned
        // target, is that approval too; a mail proof or a spent marker is not.
        let scoped_retry_proof = press_retry_authorized
            && matches!(
                hydrated_effect.provenance.approval_target,
                Some(ApprovalTarget::ScopedMcp(_))
            );
        if charter_wall.is_none() {
            match connector_key::connector_tool_setting_in_txn(
                store,
                &*wtxn,
                &_key_id,
                &key,
                manifest_verb,
            )? {
                connector_key::SlateDisposition::NeverAllow => {
                    charter_wall = Some(
                        GateDecision::deny(GateReasonCode::DenyCharterNeverList)
                            .with_receipt_reasons(["connector_key_slate_never_allow"]),
                    );
                }
                connector_key::SlateDisposition::AlwaysAsk
                    if approve_once.is_none() && !scoped_retry_proof =>
                {
                    charter_wall = Some(
                        GateDecision::pending(vec![
                            GateReasonCode::PendingConsentIrreversibleEffect,
                        ])
                        .with_receipt_reasons(["connector_key_slate_always_ask"]),
                    );
                }
                _ => {}
            }
        }

        if key.status != ConnectorKeyStatus::Active {
            let status_reason = match key.status {
                ConnectorKeyStatus::Suspended => "connector_key_suspended",
                ConnectorKeyStatus::Revoked => "connector_key_revoked",
                ConnectorKeyStatus::Pending => "connector_key_pending",
                ConnectorKeyStatus::Active => unreachable!("guarded above"),
            };
            decision = GateDecision::deny(GateReasonCode::DenyConnectorKeySuspended)
                .with_receipt_reasons([status_reason])
                .with_receipt_reasons(external_effect_receipt_reasons(
                    input
                        .external_effect
                        .as_ref()
                        .expect("external effect input"),
                ));
        } else if let Some(wall) = charter_wall {
            // Charter drift / never-list are governance walls, not
            // accounting: they convert the decision whether or not the
            // pipeline will execute this dispatch.
            decision = wall.with_receipt_reasons(external_effect_receipt_reasons(
                input
                    .external_effect
                    .as_ref()
                    .expect("external effect input"),
            ));
        }
    }

    Ok(ExternalEffectGovernance {
        decision_id,
        decision,
        created_at,
        input,
        binding,
        grant_ref,
        approve_once,
        approval_context,
        matched_grant,
        envelope_reservation,
        envelope_wait,
        budget_target,
        scoped_capability: scoped_mcp_capability,
    })
}
