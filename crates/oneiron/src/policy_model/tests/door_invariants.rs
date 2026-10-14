//! The two invariants of the F14 policy fix, each checked over every door in
//! its class (H121, H122).
//!
//! (A) A hosted attestation is a fail-safe cache. It is minted only from a
//! non-halting pass the hosted seam ran here, over the exact policy, content,
//! frontier, selector and dial it names. Any doubt means unattested, which
//! only makes the CloudVault door run its own hosted pass.
//!
//! (B) Every door settles what it hands out against the policy in force in its
//! LAST transaction, which writes its row; a change after that is the enforce
//! door's job.

use std::cell::Cell;
use std::rc::Rc;

use super::*;
use crate::error::RelayError;
use crate::llm::{BudgetExhaustionPolicy, BudgetGuard};

const WARN_ANSWER: &str = r#"{"violation":1,"policy_category":"owner:spoilers"}"#;

/// What a door handed out.
enum Handed {
    Verdict(PolicyClassifyVerdict),
    Relay(RelayBoundaryPass),
    Dual(DualPlanePass),
    Decision(PolicyClassifyDecision),
    Refused,
}

/// One drive of one door: its vault, how often the door reached its
/// settling point, and what it handed out.
struct Leg {
    _tmp: TempDir,
    vault: Rc<Vault>,
    reached: Rc<Cell<usize>>,
    handed: Handed,
}

/// A vault under the owner's warn policy, for one leg of one door.
fn warn_vault() -> Result<(TempDir, Rc<Vault>)> {
    let (tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    Ok((tmp, Rc::new(vault)))
}

/// Moves the policy to block, once, as `door` reaches the transactions that
/// settle what it hands out; counts how often `door` got there.
fn arm(vault: &Rc<Vault>, door: SettlingDoor) -> Rc<Cell<usize>> {
    let reached = Rc::new(Cell::new(0));
    let seen = Rc::clone(&reached);
    let hook_vault = Rc::clone(vault);
    let mut pending = Some(spoilers_manifest("block"));
    BEFORE_SETTLING.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |at| {
            if at != door {
                return;
            }
            seen.set(seen.get() + 1);
            if let Some(manifest) = pending.take() {
                put_policy_manifest_bytes(&hook_vault, test_id(0x48), &manifest)
                    .expect("settle-time manifest write");
            }
        }));
    });
    reached
}

/// A CloudVault receipt source holding a hosted-attested owner verdict for
/// `request`, deciding `decision`, minted from a real hosted pass.
fn attested_source(
    vault: &Vault,
    request: &PolicyClassifyRequest,
    registry: &EdgeServiceRegistry,
    config: &PolicyModelConfig,
    decision: PolicyClassifyDecision,
) -> Result<StaticVaultSideVerdicts> {
    let budget = lease("rule-b-carrier");
    let hosted_pass = relay_pass(
        vault,
        CLEAN_CONTENT,
        registry,
        config,
        Some(tier(&clean_backend(), &budget)),
    )?;
    let mut carrier = PolicyClassifyVerdict::clean_allow(
        vault.relay_verify_binding(request, config)?,
        config,
        PolicyPlane::OwnerPolicy,
    );
    carrier.decision = decision;
    let verdict =
        carrier.attesting_hosted_plane(&registered_policy(registry), config, &hosted_pass);
    assert!(
        verdict.hosted_attestation.is_some(),
        "the carrier is attested"
    );
    Ok(StaticVaultSideVerdicts {
        verdict,
        requested_hash: Mutex::new(None),
    })
}

/// Rule B, over every door [`SettlingDoor`] names. Each door is driven with
/// the owner's policy moved at the point just before the transactions that
/// settle its result. What it hands out answers the policy in force, halts
/// the relay on the binding that moved, or is refused.
#[test]
fn rule_b_every_door_settles_what_it_hands_out_in_its_last_transaction() -> Result<()> {
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let budget = lease("rule-b");
    for &door in SettlingDoor::ALL {
        let mut legs: Vec<Leg> = Vec::new();
        match door {
            SettlingDoor::BareClassify => {
                let (tmp, vault) = warn_vault()?;
                let reached = arm(&vault, door);
                let verdict = block_on(vault.classify_policy_model_with_backend(
                    request.clone(),
                    &config,
                    &static_backend(WARN_ANSWER),
                    &budget,
                ))?;
                legs.push(Leg {
                    _tmp: tmp,
                    vault,
                    reached,
                    handed: Handed::Verdict(verdict),
                });
            }
            SettlingDoor::RecordAndEnforce => {
                let (tmp, vault) = warn_vault()?;
                let reached = arm(&vault, door);
                let enforcement = block_on(vault.enforce_policy_model_with_backend(
                    request.clone(),
                    &config,
                    &static_backend(WARN_ANSWER),
                    &budget,
                ))?;
                legs.push(Leg {
                    _tmp: tmp,
                    vault,
                    reached,
                    handed: Handed::Verdict(enforcement.verdict),
                });
            }
            SettlingDoor::StaleFailOpen => {
                let (tmp, vault) = warn_vault()?;
                let reached = arm(&vault, door);
                let backend = ManifestMovingBackend {
                    vault: &vault,
                    manifest: spoilers_manifest("block"),
                    body: WARN_ANSWER,
                    keep_moving: true,
                    calls: AtomicUsize::new(0),
                };
                let enforcement = block_on(vault.enforce_policy_model_with_backend(
                    request.clone(),
                    &config,
                    &backend,
                    &budget,
                ))?;
                legs.push(Leg {
                    _tmp: tmp,
                    vault,
                    reached,
                    handed: Handed::Verdict(enforcement.verdict),
                });
            }
            SettlingDoor::EnforceRecorded => {
                let (tmp, vault) = warn_vault()?;
                let verdict = block_on(vault.classify_policy_model_with_backend(
                    request.clone(),
                    &config,
                    &static_backend(WARN_ANSWER),
                    &budget,
                ))?;
                assert_eq!(verdict.decision, PolicyClassifyDecision::Warn);
                let reached = arm(&vault, door);
                let handed = match vault.enforce_policy_model_verdict(
                    request.clone(),
                    &config,
                    verdict,
                    false,
                ) {
                    Ok(enforcement) => Handed::Verdict(enforcement.verdict),
                    Err(Error::Relay(RelayError::PolicyVerdictNotInForce)) => Handed::Refused,
                    Err(error) => return Err(error),
                };
                legs.push(Leg {
                    _tmp: tmp,
                    vault,
                    reached,
                    handed: handed,
                });
            }
            SettlingDoor::DualPlane => {
                // A CloudVault reuse, and a hosted pass run here.
                let (tmp, vault) = warn_vault()?;
                let source = attested_source(
                    &vault,
                    &request,
                    &registry,
                    &config,
                    PolicyClassifyDecision::Allow,
                )?;
                let reached = arm(&vault, door);
                let pass = block_on(vault.classify_both_planes(
                    request.clone(),
                    &cloud_witness(),
                    &registry,
                    &config,
                    Some(tier(&clean_backend(), &budget)),
                    &source,
                ))?;
                legs.push(Leg {
                    _tmp: tmp,
                    vault,
                    reached,
                    handed: Handed::Dual(pass),
                });
                let (tmp, vault) = warn_vault()?;
                let reached = arm(&vault, door);
                let pass = block_on(vault.classify_both_planes(
                    request.clone(),
                    &hosted_witness(),
                    &registry,
                    &config,
                    Some(tier(&clean_backend(), &budget)),
                    &EMPTY_VAULT_SIDE_VERDICTS,
                ))?;
                legs.push(Leg {
                    _tmp: tmp,
                    vault,
                    reached,
                    handed: Handed::Dual(pass),
                });
            }
            SettlingDoor::RelayBoundary => {
                // A CloudVault reuse of each shape: a trusted Allow and a
                // returned Warn.
                for decision in [PolicyClassifyDecision::Allow, PolicyClassifyDecision::Warn] {
                    let (tmp, vault) = warn_vault()?;
                    let source = attested_source(&vault, &request, &registry, &config, decision)?;
                    let reached = arm(&vault, door);
                    let pass = block_on(vault.relay_boundary_pass(
                        request.clone(),
                        &cloud_witness(),
                        &registry,
                        &config,
                        Some(tier(&clean_backend(), &budget)),
                        &source,
                    ))?;
                    legs.push(Leg {
                        _tmp: tmp,
                        vault,
                        reached,
                        handed: Handed::Relay(pass),
                    });
                }
                // A hosted pass run here.
                let (tmp, vault) = warn_vault()?;
                let reached = arm(&vault, door);
                let pass = relay_pass(
                    &vault,
                    CLEAN_CONTENT,
                    &registry,
                    &config,
                    Some(tier(&clean_backend(), &budget)),
                )?;
                legs.push(Leg {
                    _tmp: tmp,
                    vault,
                    reached,
                    handed: Handed::Relay(pass),
                });
            }
            SettlingDoor::AnonymousChat => {
                let (tmp, vault) = warn_vault()?;
                let reached = arm(&vault, door);
                let budget = BudgetGuard::with_reserve_units(
                    "rule-b",
                    100,
                    10,
                    BudgetExhaustionPolicy::Suspend,
                );
                let handed = match block_on(crate::policy_model::stateless_owner_classification(
                    &vault,
                    CLEAN_CONTENT,
                    &config,
                    &static_backend(WARN_ANSWER),
                    &budget,
                )) {
                    Ok((decision, _)) => Handed::Decision(decision),
                    Err(Error::ConcurrentWrite(_)) => Handed::Refused,
                    Err(error) => return Err(error),
                };
                legs.push(Leg {
                    _tmp: tmp,
                    vault,
                    reached,
                    handed: handed,
                });
            }
        }
        BEFORE_SETTLING.with(|slot| slot.borrow_mut().take());
        for Leg {
            vault,
            reached,
            handed,
            ..
        } in legs
        {
            assert!(
                reached.get() > 0,
                "{door:?} never reached its settling point"
            );
            match handed {
                Handed::Verdict(verdict) => {
                    assert_owner_in_force(&vault, door, &request, &verdict)?
                }
                Handed::Relay(pass) => assert_relay_halted(door, &pass),
                Handed::Dual(pass) => {
                    assert_owner_in_force(&vault, door, &request, &pass.owner)?;
                    assert_relay_halted(door, &pass.relay);
                }
                Handed::Decision(decision) => assert_ne!(
                    decision,
                    PolicyClassifyDecision::Warn,
                    "{door:?} answered with the replaced policy's warn"
                ),
                Handed::Refused => {}
            }
        }
    }
    Ok(())
}

fn assert_owner_in_force(
    vault: &Vault,
    door: SettlingDoor,
    request: &PolicyClassifyRequest,
    verdict: &PolicyClassifyVerdict,
) -> Result<()> {
    assert!(
        !vault.policy_model_verdict_is_stale_with_config(
            verdict,
            request,
            &PolicyModelConfig::default()
        )?,
        "{door:?} handed out {:?} for a replaced policy",
        verdict.decision
    );
    Ok(())
}

fn assert_relay_halted(door: SettlingDoor, pass: &RelayBoundaryPass) {
    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::PolicyBindingMovedMidPass),
        "{door:?} handed out a hosted pass on a binding no longer in force: {pass:?}"
    );
    assert!(pass.must_halt_relay());
}

/// Which evidence field of a pass names something other than the carrier and
/// policy it is minted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    Exact,
    None,
    OtherVersion,
    OtherHash,
    OtherContent,
    OtherFrontier,
    OtherSelector,
    OtherDial,
}

const EVIDENCE: [Evidence; 8] = [
    Evidence::Exact,
    Evidence::None,
    Evidence::OtherVersion,
    Evidence::OtherHash,
    Evidence::OtherContent,
    Evidence::OtherFrontier,
    Evidence::OtherSelector,
    Evidence::OtherDial,
];

/// How the pass ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    Answered(PolicyClassifyDecision),
    Degraded { halts: bool },
}

const ENDINGS: [Ending; 5] = [
    Ending::Answered(PolicyClassifyDecision::Allow),
    Ending::Answered(PolicyClassifyDecision::Warn),
    Ending::Answered(PolicyClassifyDecision::Block),
    Ending::Degraded { halts: false },
    Ending::Degraded { halts: true },
];

/// Whether a pass reaching `resolution` ran the hosted plane here, rather
/// than replaying a vault-side verdict or finding no hosted policy bound.
fn ran_on_the_hosted_seam(resolution: RelayResolution) -> bool {
    match resolution {
        RelayResolution::PatternDecided
        | RelayResolution::ModelDecided
        | RelayResolution::PatternGatedAllow
        | RelayResolution::LogOnly
        | RelayResolution::Unresolved => true,
        RelayResolution::NoPolicyInPlay | RelayResolution::VaultSideDecided => false,
    }
}

fn synthetic_pass(
    policy: &HostedLegalPolicy,
    carrier: PolicyContentBinding,
    config: &PolicyModelConfig,
    resolution: RelayResolution,
    ending: Ending,
    evidence: Evidence,
    hosted_policy_in_play: bool,
) -> RelayBoundaryPass {
    let binding = PolicyContentBinding {
        content_hash: [0x01; 32],
        read_frontier_hash: if evidence == Evidence::OtherFrontier {
            [0x66; 32]
        } else {
            carrier.read_frontier_hash
        },
    };
    let mut verdict = match ending {
        Ending::Answered(decision) => {
            let mut verdict =
                PolicyClassifyVerdict::clean_allow(binding, config, PolicyPlane::HostedLegal);
            verdict.decision = decision;
            verdict
        }
        Ending::Degraded { .. } => PolicyClassifyVerdict::skipped(
            PolicySkipReason::BackendUnavailable,
            binding,
            config,
            PolicyPlane::HostedLegal,
        ),
    };
    if evidence == Evidence::OtherSelector {
        verdict.safeguard_binding = "another-selector".to_owned();
    }
    if evidence == Evidence::OtherDial {
        verdict.classifier_mode = Some(RelayClassifierMode::PatternGated);
    }
    let hosted_evidence = (evidence != Evidence::None).then(|| HostedPassEvidence {
        version: if evidence == Evidence::OtherVersion {
            "2099-01-01".to_owned()
        } else {
            policy.version.clone()
        },
        policy_hash: if evidence == Evidence::OtherHash {
            "another-policy-hash".to_owned()
        } else {
            policy.policy_hash.clone()
        },
        verify_content_hash: if evidence == Evidence::OtherContent {
            [0x77; 32]
        } else {
            carrier.content_hash
        },
    });
    RelayBoundaryPass::Classified(Box::new(RelayClassifiedPass {
        verdict,
        degraded: matches!(ending, Ending::Degraded { .. })
            .then_some(RelayBoundaryDegrade::SafeguardModelUnavailable),
        degrade_halts: matches!(ending, Ending::Degraded { halts: true }),
        hosted_policy_in_play,
        resolution,
        hosted_evidence,
    }))
}

/// Rule A, over every pass the mint can be handed: each pass shape, every
/// [`RelayResolution`], every ending, each evidence field naming something
/// else, both outage postures, a carrier that allows and one that warns.
/// Every door that reads an attestation is asked about each carrier: the
/// standalone and dual-plane CloudVault doors trust it only when it came
/// from a non-halting pass the seam ran over exactly what it names, and
/// otherwise run their own hosted pass; the enforce door refuses it.
#[test]
fn rule_a_an_attestation_comes_only_from_a_seam_pass_over_what_it_names() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let policy = registered_policy(&registry);
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let budget = lease("rule-a");
    let mut attested_and_trusted = 0;
    for outage in [
        HostedOutagePolicy::Halt,
        HostedOutagePolicy::ProceedReceipted,
    ] {
        let config = PolicyModelConfig {
            hosted_outage_policy: outage,
            ..PolicyModelConfig::default()
        };
        let carrier_binding = vault.relay_verify_binding(&request, &config)?;
        let mut passes = vec![
            (RelayBoundaryPass::TrustedVaultSide, false, Evidence::None),
            (RelayBoundaryPass::NotRelayedByUs, false, Evidence::None),
        ];
        for resolution in RelayResolution::ALL {
            for ending in ENDINGS {
                for evidence in EVIDENCE {
                    for in_play in [true, false] {
                        if !in_play && evidence != Evidence::Exact {
                            continue;
                        }
                        let halts = match ending {
                            Ending::Answered(decision) => decision == PolicyClassifyDecision::Block,
                            Ending::Degraded { halts } => halts,
                        };
                        // A pass under another dial is still evidence of
                        // what it ran: it attests, naming its own dial, and
                        // no door reuses it under the dial in force now.
                        let may_attest = ran_on_the_hosted_seam(resolution)
                            && in_play
                            && !halts
                            && matches!(evidence, Evidence::Exact | Evidence::OtherDial);
                        let pass = synthetic_pass(
                            &policy,
                            carrier_binding,
                            &config,
                            resolution,
                            ending,
                            evidence,
                            in_play,
                        );
                        passes.push((pass, may_attest, evidence));
                    }
                }
            }
        }
        for (pass, may_attest, evidence) in passes {
            let may_trust = may_attest && evidence == Evidence::Exact;
            for decision in [PolicyClassifyDecision::Allow, PolicyClassifyDecision::Warn] {
                let mut carrier = PolicyClassifyVerdict::clean_allow(
                    carrier_binding,
                    &config,
                    PolicyPlane::OwnerPolicy,
                );
                carrier.decision = decision;
                let carrier = carrier.attesting_hosted_plane(&policy, &config, &pass);
                let attested = carrier.hosted_attestation.is_some();
                assert!(
                    may_attest || !attested,
                    "H122: attested from {pass:?} under {outage:?}"
                );
                if attested {
                    let dial = carrier
                        .hosted_attestation
                        .as_ref()
                        .and_then(|attestation| attestation.classifier_mode);
                    assert_eq!(
                        dial,
                        pass_dial(&pass),
                        "the attestation names the dial the pass ran under"
                    );
                }
                let source = StaticVaultSideVerdicts {
                    verdict: carrier.clone(),
                    requested_hash: Mutex::new(None),
                };
                let backend = CountingPolicyBackend::clean();
                let standalone = block_on(vault.relay_boundary_pass(
                    request.clone(),
                    &cloud_witness(),
                    &registry,
                    &config,
                    Some(tier(&backend, &budget)),
                    &source,
                ))?;
                let trusted = reused(&standalone);
                assert!(
                    may_trust || !trusted,
                    "H122: the CloudVault door trusted a carrier minted from {pass:?}"
                );
                if !trusted {
                    assert_eq!(backend.calls(), 1, "an untrusted carrier runs its own pass");
                }
                let dual = block_on(vault.classify_both_planes(
                    request.clone(),
                    &cloud_witness(),
                    &registry,
                    &config,
                    Some(tier(&CountingPolicyBackend::clean(), &budget)),
                    &source,
                ))?;
                assert_eq!(
                    reused(&dual.relay),
                    trusted,
                    "both CloudVault doors read one carrier the same way"
                );
                if attested {
                    assert!(matches!(
                        vault.enforce_policy_model_verdict(
                            request.clone(),
                            &config,
                            carrier,
                            false
                        ),
                        Err(Error::Relay(RelayError::PolicyVerdictNotInForce))
                    ));
                }
                if attested && trusted {
                    attested_and_trusted += 1;
                }
                // The control: a pass the model answered without halting, over
                // exactly what it names, is reusable.
                if may_trust && pass.degraded().is_none() {
                    assert!(attested && trusted, "the control is attested and trusted");
                }
            }
        }
    }
    assert!(attested_and_trusted > 0);
    Ok(())
}

fn pass_dial(pass: &RelayBoundaryPass) -> Option<RelayClassifierMode> {
    match pass {
        RelayBoundaryPass::Classified(ran) => ran.verdict.classifier_mode,
        RelayBoundaryPass::TrustedVaultSide | RelayBoundaryPass::NotRelayedByUs => None,
    }
}

fn reused(pass: &RelayBoundaryPass) -> bool {
    matches!(pass, RelayBoundaryPass::TrustedVaultSide)
        || pass.resolution() == Some(RelayResolution::VaultSideDecided)
}
