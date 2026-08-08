use super::*;

use core::assert_matches;
use std::collections::BTreeSet;

use crate::claim::{ClaimApprovalStatus, ClaimBody, encode_claim_body, validate_claim_body_bytes};
use crate::config::VaultConfig;
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateOutcome,
    GateProvenanceHandles, GateReasonCode, POLICY_SCHEMA_VERSION, check_external_effect_policy,
    resolve_policy_manifest,
};
use crate::temporal::TimeRange;
use crate::test_util::{entity, put_policy_manifest_bytes};

/// PERSON subject for value-shape fixtures.
const SUBJECT_SEED: u8 = 0x61;
/// CAMPAIGN referenced by membership and stage values.
const CAMPAIGN_SEED: u8 = 0x62;
/// A second referenced entity (evidence, sender, ICP, saved query).
const REF_SEED: u8 = 0x63;
/// A second CAMPAIGN, for scope-isolation arms.
const OTHER_CAMPAIGN_SEED: u8 = 0x64;

fn subject() -> EntityId {
    entity(SUBJECT_SEED)
}

fn map(entries: &[(&str, Value)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(key, value)| (Value::from(*key), value.clone()))
            .collect(),
    )
}

fn hex(seed: u8) -> Value {
    Value::from(entity(seed).to_hex())
}

fn body(predicate: &str, value: Value) -> ClaimBody {
    ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject()),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
}

/// Round-trips through the same codec storage uses, then through the
/// write-only validator chokepoint in `crate::claim`.
fn through_chokepoint(body: &ClaimBody) -> Result<()> {
    validate_claim_body_bytes(&encode_claim_body(body)?, false)
}

fn reject(predicate: &str, value: Value) {
    assert_matches!(
        through_chokepoint(&body(predicate, value)),
        Err(Error::InvalidClaimBody(_)),
        "{predicate} must reject this value"
    );
}

fn enrolled_state() -> Value {
    map(&[(KEY_KIND, Value::from("enrolled"))])
}

fn channel_row(channel: &str) -> Value {
    map(&[
        (KEY_CHANNEL, Value::from(channel)),
        (KEY_BASIS_EVIDENCE, hex(REF_SEED)),
        (KEY_SENDER_REF, hex(REF_SEED)),
    ])
}

fn member_value(state: Value, channels: Vec<Value>) -> Value {
    map(&[
        (KEY_CAMPAIGN, hex(CAMPAIGN_SEED)),
        (KEY_STATE, state),
        (KEY_CHANNELS, Value::Array(channels)),
    ])
}

fn canonical_member() -> Value {
    member_value(enrolled_state(), vec![channel_row("email")])
}

fn canonical_fit() -> Value {
    map(&[
        (KEY_ICP_SCOPE, hex(REF_SEED)),
        (KEY_VERDICT, Value::from(CrmFitVerdict::Fit.as_str())),
    ])
}

fn stage_value(campaign_seed: u8, stage: &str) -> Value {
    map(&[
        (KEY_CAMPAIGN_REF, hex(campaign_seed)),
        (KEY_STAGE, Value::from(stage)),
        (
            KEY_EVIDENCE_CLASS,
            Value::from(StageEvidenceClass::MeaningfulReply.as_str()),
        ),
        (KEY_EVIDENCE_REFS, Value::Array(vec![hex(REF_SEED)])),
        (KEY_BASIS, Value::from(EvidenceBasis::Machine.as_str())),
        (KEY_RECORDED_AT, Value::from(1_754_400_000_u64)),
    ])
}

fn canonical_stage() -> Value {
    stage_value(CAMPAIGN_SEED, "replied")
}

fn do_not_contact_value(channel: Option<&str>, scope: &str) -> Value {
    let mut entries = vec![(KEY_SCOPE, Value::from(scope))];
    if let Some(channel) = channel {
        entries.push((KEY_CHANNEL, Value::from(channel)));
    }
    map(&entries)
}

fn canonical_bounce() -> Value {
    map(&[
        (KEY_CHANNEL, Value::from("email")),
        (KEY_BOUNCE, Value::from(BounceKind::Hard.as_str())),
        (KEY_SENDER_REF, hex(REF_SEED)),
        (KEY_OCCURRED_AT, Value::from(1_754_400_000_u64)),
    ])
}

fn canonical_jurisdiction() -> Value {
    map(&[
        (KEY_JURISDICTION, Value::from("us-ca")),
        (KEY_OBSERVED_AT, Value::from(1_754_400_000_u64)),
    ])
}

/// `comm.jurisdiction` is the one family member that also requires
/// `ClaimBody::evidence`, so its canonical body is built separately.
fn jurisdiction_body(value: Value) -> ClaimBody {
    let mut claim = body(PREDICATE_COMM_JURISDICTION, value);
    claim.evidence = Some(Value::from("connector:linkedin:profile-region"));
    claim
}

/// Replaces one key of an existing map fixture.
fn with_key(value: &Value, key: &str, replacement: Value) -> Value {
    let mut value = value.clone();
    if let Value::Map(entries) = &mut value {
        for (candidate, slot) in entries.iter_mut() {
            if candidate.as_str() == Some(key) {
                *slot = replacement.clone();
            }
        }
    }
    value
}

#[test]
fn campaign_claim_family_exact_match_precedes_comm_family() -> Result<()> {
    // Every minted predicate is in the CA table and NOT in the comm table.
    let minted: BTreeSet<&str> = CAMPAIGN_PACK_CLAIM_PREDICATES.iter().copied().collect();
    assert_eq!(
        minted,
        BTreeSet::from([
            "campaign.member",
            "crm.fit",
            "crm.stage",
            "comm.do_not_contact",
            "comm.bounce",
            "comm.jurisdiction",
        ])
    );
    assert_eq!(CAMPAIGN_PACK_CLAIM_PREDICATES.len(), minted.len());
    for predicate in CAMPAIGN_PACK_CLAIM_PREDICATES {
        assert!(is_campaign_pack_claim_predicate(predicate));
        assert!(
            !crate::comm::is_comm_claim_predicate(predicate),
            "{predicate} must not also be claimed by the comm family"
        );
    }

    // SPINE-COMM keeps its own family: none of them enter the CA branch.
    for predicate in [
        "comm.opt_out",
        "comm.last_touch",
        "comm.thread_member",
        "comm.reachable_via",
    ] {
        assert!(crate::comm::is_comm_claim_predicate(predicate));
        assert!(!is_campaign_pack_claim_predicate(predicate));
    }

    // Routing evidence, not just table membership: an empty map under
    // `comm.do_not_contact` fails with the CA validator's message, while the
    // same value under `comm.opt_out` fails with the comm validator's.
    assert_matches!(
        through_chokepoint(&body(PREDICATE_COMM_DO_NOT_CONTACT, Value::Map(Vec::new()))),
        Err(Error::InvalidClaimBody(
            "campaign pack value missing required key"
        ))
    );
    assert_matches!(
        through_chokepoint(&body("comm.opt_out", Value::Map(Vec::new()))),
        Err(Error::InvalidClaimBody(reason)) if reason.starts_with("comm ")
    );

    // Lookalikes belong to NEITHER family: exact-match tables, no prefixes.
    for lookalike in [
        "comm.do_not_contact.extra",
        "comm.do_not_contac",
        "campaign.members",
        "crm.stages",
    ] {
        assert!(!is_campaign_pack_claim_predicate(lookalike), "{lookalike}");
        assert!(
            !crate::comm::is_comm_claim_predicate(lookalike),
            "{lookalike}"
        );
    }

    // Canonical shapes all pass the chokepoint.
    for (predicate, value) in [
        (PREDICATE_CAMPAIGN_MEMBER, canonical_member()),
        (PREDICATE_CRM_FIT, canonical_fit()),
        (PREDICATE_CRM_STAGE, canonical_stage()),
        (
            PREDICATE_COMM_DO_NOT_CONTACT,
            do_not_contact_value(Some("email"), DO_NOT_CONTACT_SCOPE_ALL),
        ),
        (PREDICATE_COMM_BOUNCE, canonical_bounce()),
    ] {
        through_chokepoint(&body(predicate, value))?;
    }
    through_chokepoint(&jurisdiction_body(canonical_jurisdiction()))?;
    Ok(())
}

#[test]
fn campaign_member_requires_argument_shape() -> Result<()> {
    // A non-entity subject is refused structurally, before any value decode.
    let edge_subject = ClaimBody::new(
        PREDICATE_CAMPAIGN_MEMBER,
        ClaimSubject::Edge {
            source: entity(REF_SEED),
            target: subject(),
            kind: crate::edge::EdgeKind::ClaimOf,
        },
        canonical_member(),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    assert_matches!(
        through_chokepoint(&edge_subject),
        Err(Error::InvalidClaimBody(
            "campaign pack claim subject must be an entity"
        ))
    );

    // Every accepted state form, including both paused wake shapes.
    let paused_both = map(&[
        (KEY_KIND, Value::from("paused")),
        (KEY_UNTIL, Value::from(1_754_400_000_u64)),
        (KEY_NEW_TRIGGER, Value::Boolean(true)),
    ]);
    for state in [
        enrolled_state(),
        map(&[(KEY_KIND, Value::from("exited"))]),
        map(&[(KEY_KIND, Value::from("suppressed"))]),
        map(&[
            (KEY_KIND, Value::from("paused")),
            (KEY_UNTIL, Value::from(1_754_400_000_u64)),
        ]),
        map(&[
            (KEY_KIND, Value::from("paused")),
            (KEY_NEW_TRIGGER, Value::Boolean(true)),
        ]),
        paused_both.clone(),
    ] {
        through_chokepoint(&body(
            PREDICATE_CAMPAIGN_MEMBER,
            member_value(state, vec![channel_row("email")]),
        ))?;
    }
    // Both wake fields present is the AtOrNewTrigger form, not a conflict.
    assert_eq!(
        decode_campaign_member_value(&member_value(paused_both, vec![channel_row("email")]))?.state,
        CampaignMemberState::Paused {
            until: Some(1_754_400_000),
            new_trigger: Some(true),
        }
    );

    // Manual membership omits derivation; a derived one carries all three fields.
    assert_eq!(
        decode_campaign_member_value(&canonical_member())?.derivation,
        None
    );
    let derived_value = map(&[
        (KEY_CAMPAIGN, hex(CAMPAIGN_SEED)),
        (KEY_STATE, enrolled_state()),
        (KEY_CHANNELS, Value::Array(vec![channel_row("email")])),
        (
            KEY_DERIVATION,
            map(&[
                (KEY_SOURCE_QUERY, hex(REF_SEED)),
                (KEY_EVIDENCE_HASH, Value::Binary(vec![9u8; 32])),
                (KEY_EPOCH, Value::from(7_u64)),
            ]),
        ),
    ]);
    through_chokepoint(&body(PREDICATE_CAMPAIGN_MEMBER, derived_value.clone()))?;
    assert_eq!(
        decode_campaign_member_value(&derived_value)?.derivation,
        Some(CampaignMemberDerivation {
            source_query: entity(REF_SEED),
            evidence_hash: [9u8; 32],
            epoch: 7,
        })
    );

    // Missing campaign.
    reject(
        PREDICATE_CAMPAIGN_MEMBER,
        map(&[
            (KEY_STATE, enrolled_state()),
            (KEY_CHANNELS, Value::Array(vec![channel_row("email")])),
        ]),
    );
    // Unknown state tag.
    reject(
        PREDICATE_CAMPAIGN_MEMBER,
        member_value(
            map(&[(KEY_KIND, Value::from("dormant"))]),
            vec![channel_row("email")],
        ),
    );
    // Paused with neither wake field never wakes.
    reject(
        PREDICATE_CAMPAIGN_MEMBER,
        member_value(
            map(&[(KEY_KIND, Value::from("paused"))]),
            vec![channel_row("email")],
        ),
    );
    // Empty channel set.
    reject(
        PREDICATE_CAMPAIGN_MEMBER,
        member_value(enrolled_state(), Vec::new()),
    );
    // Duplicate channel, and a non-normalized spelling of one already present.
    reject(
        PREDICATE_CAMPAIGN_MEMBER,
        member_value(
            enrolled_state(),
            vec![channel_row("email"), channel_row("email")],
        ),
    );
    reject(
        PREDICATE_CAMPAIGN_MEMBER,
        member_value(
            enrolled_state(),
            vec![channel_row("email"), channel_row("EMAIL")],
        ),
    );
    // Channel row missing its consent basis, and one missing its sticky sender.
    for missing in [KEY_BASIS_EVIDENCE, KEY_SENDER_REF] {
        let row = Value::Map(
            [
                (KEY_CHANNEL, Value::from("email")),
                (KEY_BASIS_EVIDENCE, hex(REF_SEED)),
                (KEY_SENDER_REF, hex(REF_SEED)),
            ]
            .into_iter()
            .filter(|(key, _)| *key != missing)
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
        );
        reject(
            PREDICATE_CAMPAIGN_MEMBER,
            member_value(enrolled_state(), vec![row]),
        );
    }
    // Malformed derivation fields.
    for derivation in [
        map(&[
            (KEY_SOURCE_QUERY, Value::from("not-hex")),
            (KEY_EVIDENCE_HASH, Value::Binary(vec![9u8; 32])),
            (KEY_EPOCH, Value::from(7_u64)),
        ]),
        map(&[
            (KEY_SOURCE_QUERY, hex(REF_SEED)),
            (KEY_EVIDENCE_HASH, Value::Binary(vec![9u8; 31])),
            (KEY_EPOCH, Value::from(7_u64)),
        ]),
        map(&[
            (KEY_SOURCE_QUERY, hex(REF_SEED)),
            (KEY_EVIDENCE_HASH, Value::from("9".repeat(64))),
            (KEY_EPOCH, Value::from(7_u64)),
        ]),
        map(&[
            (KEY_SOURCE_QUERY, hex(REF_SEED)),
            (KEY_EVIDENCE_HASH, Value::Binary(vec![9u8; 32])),
        ]),
    ] {
        reject(
            PREDICATE_CAMPAIGN_MEMBER,
            map(&[
                (KEY_CAMPAIGN, hex(CAMPAIGN_SEED)),
                (KEY_STATE, enrolled_state()),
                (KEY_CHANNELS, Value::Array(vec![channel_row("email")])),
                (KEY_DERIVATION, derivation),
            ]),
        );
    }
    Ok(())
}

#[test]
fn crm_fit_not_fit_wins_restrictive_fold() -> Result<()> {
    let icp = entity(REF_SEED);
    let other_icp = entity(OTHER_CAMPAIGN_SEED);
    let fit = CrmFitValue {
        icp_scope: icp,
        verdict: CrmFitVerdict::Fit,
    };
    let not_fit = CrmFitValue {
        icp_scope: icp,
        verdict: CrmFitVerdict::NotFit,
    };

    assert_eq!(resolve_crm_fit(&icp, &[]), None);
    assert_eq!(
        resolve_crm_fit(&icp, std::slice::from_ref(&fit)),
        Some(CrmFitVerdict::Fit)
    );
    // Order-independent: the restrictive verdict wins from either side.
    assert_eq!(
        resolve_crm_fit(&icp, &[fit.clone(), not_fit.clone()]),
        Some(CrmFitVerdict::NotFit)
    );
    assert_eq!(
        resolve_crm_fit(&icp, &[not_fit.clone(), fit.clone()]),
        Some(CrmFitVerdict::NotFit)
    );

    // Scope isolation is a property of the fold, not of the caller: a
    // rejection under one ICP never contaminates another's verdict.
    let cross_scope = [
        fit,
        CrmFitValue {
            icp_scope: other_icp,
            verdict: CrmFitVerdict::NotFit,
        },
    ];
    assert_eq!(
        resolve_crm_fit(&icp, &cross_scope),
        Some(CrmFitVerdict::Fit)
    );
    assert_eq!(
        resolve_crm_fit(&other_icp, &cross_scope),
        Some(CrmFitVerdict::NotFit)
    );
    assert_eq!(resolve_crm_fit(&entity(CAMPAIGN_SEED), &cross_scope), None);

    // Wire shape.
    assert_eq!(
        decode_crm_fit_value(&map(&[
            (KEY_ICP_SCOPE, hex(REF_SEED)),
            (KEY_VERDICT, Value::from(CrmFitVerdict::NotFit.as_str())),
        ]))?,
        not_fit
    );
    reject(
        PREDICATE_CRM_FIT,
        map(&[
            (KEY_ICP_SCOPE, hex(REF_SEED)),
            (KEY_VERDICT, Value::from("maybe")),
        ]),
    );
    reject(
        PREDICATE_CRM_FIT,
        map(&[(KEY_VERDICT, Value::from(CrmFitVerdict::Fit.as_str()))]),
    );
    Ok(())
}

#[test]
fn crm_stage_requires_exact_evidence_and_scoped_supersession() -> Result<()> {
    // Accepts only the CA-owned shape.
    through_chokepoint(&body(PREDICATE_CRM_STAGE, canonical_stage()))?;
    assert_eq!(
        decode_crm_stage_value(&canonical_stage())?,
        CrmStageValue {
            campaign_ref: entity(CAMPAIGN_SEED),
            stage: StageKey("replied".to_owned()),
            evidence_class: StageEvidenceClass::MeaningfulReply,
            evidence_refs: vec![entity(REF_SEED)],
            basis: EvidenceBasis::Machine,
            recorded_at: 1_754_400_000,
        }
    );
    for class in StageEvidenceClass::ALL {
        let value = with_key(
            &with_key(
                &canonical_stage(),
                KEY_EVIDENCE_CLASS,
                Value::from(class.as_str()),
            ),
            KEY_BASIS,
            Value::from(EvidenceBasis::OwnerAttested.as_str()),
        );
        through_chokepoint(&body(PREDICATE_CRM_STAGE, value))?;
    }

    // Extra field, missing field, empty stage, empty evidence, bad tokens.
    let mut extra = canonical_stage();
    if let Value::Map(entries) = &mut extra {
        entries.push((Value::from("surprise"), Value::from(1)));
    }
    reject(PREDICATE_CRM_STAGE, extra);
    let mut missing = canonical_stage();
    if let Value::Map(entries) = &mut missing {
        entries.retain(|(key, _)| key.as_str() != Some(KEY_BASIS));
    }
    reject(PREDICATE_CRM_STAGE, missing);
    reject(PREDICATE_CRM_STAGE, stage_value(CAMPAIGN_SEED, ""));
    for (key, bad) in [
        (KEY_EVIDENCE_REFS, Value::Array(Vec::new())),
        (KEY_EVIDENCE_REFS, Value::Array(vec![Value::from("nope")])),
        (KEY_EVIDENCE_CLASS, Value::from("vibes")),
        (KEY_BASIS, Value::from("inferred")),
        (KEY_RECORDED_AT, Value::from("yesterday")),
    ] {
        reject(PREDICATE_CRM_STAGE, with_key(&canonical_stage(), key, bad));
    }

    // Scoped supersession against real storage.
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let person = subject();
    let other_person = entity(0x65);
    let fresh_person = entity(0x6B);
    let occurred = TimeRange { start: 1, end: 1 };
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred, 1, b"campaign person")?;
    vault.put_entity(
        &other_person,
        ENTITY_TYPE_PERSON,
        occurred,
        1,
        b"other person",
    )?;
    vault.put_entity(
        &fresh_person,
        ENTITY_TYPE_PERSON,
        occurred,
        1,
        b"fresh person",
    )?;

    let head = entity(0x66);
    let replacement = entity(0x67);
    let wrong_campaign = entity(0x68);
    let wrong_subject = entity(0x69);
    let unrelated_predicate = entity(0x6A);
    vault.put_claim(
        &head,
        &body(PREDICATE_CRM_STAGE, canonical_stage()),
        occurred,
        1,
    )?;
    vault.put_claim(
        &wrong_campaign,
        &body(
            PREDICATE_CRM_STAGE,
            stage_value(OTHER_CAMPAIGN_SEED, "meeting"),
        ),
        occurred,
        2,
    )?;
    let mut other_subject_body = body(PREDICATE_CRM_STAGE, stage_value(CAMPAIGN_SEED, "meeting"));
    other_subject_body.subject = ClaimSubject::Entity(other_person);
    vault.put_claim(&wrong_subject, &other_subject_body, occurred, 2)?;
    vault.put_claim(
        &unrelated_predicate,
        &body(PREDICATE_CRM_FIT, canonical_fit()),
        occurred,
        2,
    )?;

    // Predicate, subject, and campaign-scope mismatches all fail closed.
    assert_matches!(
        cas_stage_head(&vault, &unrelated_predicate, Some(&head)),
        Err(Error::InvalidClaimBody("claim is not crm.stage"))
    );
    assert_matches!(
        cas_stage_head(&vault, &wrong_subject, Some(&head)),
        Err(Error::InvalidClaimBody(
            "crm.stage supersession subject mismatch"
        ))
    );
    // Nothing was written by any rejection: the head is still live.
    assert_eq!(
        vault.get_claim(&head)?.expect("head claim").lifecycle,
        ClaimLifecycleStatus::Active
    );

    // ATOMICITY. The replacement head is PUT and the prior head superseded in
    // ONE caller-owned txn, so the two either land together or not at all.
    // A rejected CAS rolls the put back with it — split the txn (put in its own
    // write txn, supersede in another) and `torn` survives as a second live
    // head, failing the assertion below.
    let torn = entity(0x6C);
    assert_matches!(
        vault.try_with_write_txn(|wtxn| {
            vault.put_claim_in_txn(
                wtxn,
                &torn,
                &body(PREDICATE_CRM_STAGE, stage_value(CAMPAIGN_SEED, "won")),
                occurred,
                2,
            )?;
            // `wrong_campaign` is a live stage head on the same PERSON scoped
            // to a DIFFERENT campaign, so this CAS names a non-current head.
            supersede_crm_stage_in_txn(&vault, wtxn, &torn, Some(&wrong_campaign), 10)
        }),
        Err(Error::InvalidClaimBody(
            "crm.stage supersession campaign mismatch"
        ))
    );
    assert_eq!(vault.get_claim(&torn)?, None);
    assert_eq!(live_stage_heads(&vault, person, CAMPAIGN_SEED)?, vec![head]);

    // The composed happy path: put + supersede, one txn, one surviving head.
    vault.try_with_write_txn(|wtxn| {
        vault.put_claim_in_txn(
            wtxn,
            &replacement,
            &body(PREDICATE_CRM_STAGE, stage_value(CAMPAIGN_SEED, "meeting")),
            occurred,
            2,
        )?;
        supersede_crm_stage_in_txn(&vault, wtxn, &replacement, Some(&head), 10)
    })?;
    assert_eq!(
        vault.get_claim(&head)?.expect("head claim").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        live_stage_heads(&vault, person, CAMPAIGN_SEED)?,
        vec![replacement]
    );
    // Replaying the same supersession fails: the old head is no longer current.
    assert_matches!(
        cas_stage_head(&vault, &replacement, Some(&head)),
        Err(Error::InvalidClaimBody("crm.stage claim is not live"))
    );

    // FIRST HEAD. `None` compares against the ABSENCE of a head, so the opening
    // stage of a campaign needs no invented sentinel predecessor...
    let first = entity(0x6D);
    let second = entity(0x6E);
    let mut first_body = body(PREDICATE_CRM_STAGE, stage_value(CAMPAIGN_SEED, "replied"));
    first_body.subject = ClaimSubject::Entity(fresh_person);
    vault.try_with_write_txn(|wtxn| {
        vault.put_claim_in_txn(wtxn, &first, &first_body, occurred, 2)?;
        supersede_crm_stage_in_txn(&vault, wtxn, &first, None, 10)
    })?;
    assert_eq!(
        live_stage_heads(&vault, fresh_person, CAMPAIGN_SEED)?,
        vec![first]
    );
    // ...and a second writer that also thinks it is first loses instead of
    // quietly becoming a competing live head.
    let mut second_body = body(PREDICATE_CRM_STAGE, stage_value(CAMPAIGN_SEED, "meeting"));
    second_body.subject = ClaimSubject::Entity(fresh_person);
    assert_matches!(
        vault.try_with_write_txn(|wtxn| {
            vault.put_claim_in_txn(wtxn, &second, &second_body, occurred, 2)?;
            supersede_crm_stage_in_txn(&vault, wtxn, &second, None, 11)
        }),
        Err(Error::InvalidClaimBody(
            "crm.stage first head is not the only head"
        ))
    );
    assert_eq!(vault.get_claim(&second)?, None);
    assert_eq!(
        live_stage_heads(&vault, fresh_person, CAMPAIGN_SEED)?,
        vec![first]
    );
    Ok(())
}

/// Runs a stage CAS whose replacement head is ALREADY committed, in a txn of
/// its own. Only for the rejection arms, which write nothing.
fn cas_stage_head(
    vault: &Vault,
    new_claim_id: &EntityId,
    expected_current_head_id: Option<&EntityId>,
) -> Result<()> {
    vault.try_with_write_txn(|wtxn| {
        supersede_crm_stage_in_txn(vault, wtxn, new_claim_id, expected_current_head_id, 10)
    })
}

/// Live `crm.stage` heads for `(subject, campaign)`, read through a committed
/// txn — the torn-state oracle.
///
/// The exclusion argument is `subject` itself, which excludes nothing: a
/// PERSON's own id is never one of the CLAIM ids hanging off its `claim_of`
/// edges.
fn live_stage_heads(vault: &Vault, subject: EntityId, campaign_seed: u8) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    other_live_crm_stage_heads_in_txn(
        &vault.store,
        &rtxn,
        subject,
        &entity(campaign_seed),
        &subject,
    )
}

#[test]
fn campaign_pack_encoders_round_trip_through_their_decoders() -> Result<()> {
    // The encoder is pinned to the hand-written wire literal, not merely to the
    // decoder: a matched pair of codec bugs would still fail here.
    assert_eq!(
        encode_campaign_member_value(&decode_campaign_member_value(&canonical_member())?),
        canonical_member()
    );
    assert_eq!(
        encode_crm_stage_value(&decode_crm_stage_value(&canonical_stage())?),
        canonical_stage()
    );

    // Identity over every optional/variant arm, and every encoded value is
    // accepted by the same write door a ONE-1773/1775 writer goes through.
    let states = [
        CampaignMemberState::Enrolled,
        CampaignMemberState::Exited,
        CampaignMemberState::Suppressed,
        CampaignMemberState::Paused {
            until: Some(1_754_400_000),
            new_trigger: None,
        },
        CampaignMemberState::Paused {
            until: None,
            new_trigger: Some(true),
        },
        CampaignMemberState::Paused {
            until: Some(1_754_400_000),
            new_trigger: Some(false),
        },
    ];
    let derivations = [
        None,
        Some(CampaignMemberDerivation {
            source_query: entity(REF_SEED),
            evidence_hash: [0xAB; 32],
            epoch: 7,
        }),
    ];
    for state in states {
        for derivation in &derivations {
            let derivation = derivation.clone();
            let member = CampaignMemberValue {
                campaign: entity(CAMPAIGN_SEED),
                state,
                channels: vec![
                    CampaignMemberChannel {
                        channel: "email".to_owned(),
                        basis_evidence: entity(REF_SEED),
                        sender_ref: entity(CAMPAIGN_SEED),
                    },
                    CampaignMemberChannel {
                        channel: "sms".to_owned(),
                        basis_evidence: entity(REF_SEED),
                        sender_ref: entity(REF_SEED),
                    },
                ],
                derivation,
            };
            let encoded = encode_campaign_member_value(&member);
            assert_eq!(decode_campaign_member_value(&encoded)?, member);
            through_chokepoint(&body(PREDICATE_CAMPAIGN_MEMBER, encoded))?;
        }
    }

    for class in StageEvidenceClass::ALL {
        for basis in [EvidenceBasis::Machine, EvidenceBasis::OwnerAttested] {
            let stage = CrmStageValue {
                campaign_ref: entity(OTHER_CAMPAIGN_SEED),
                stage: StageKey("proposal_sent".to_owned()),
                evidence_class: class,
                evidence_refs: vec![entity(REF_SEED), entity(CAMPAIGN_SEED)],
                basis,
                recorded_at: 1_754_400_001,
            };
            let encoded = encode_crm_stage_value(&stage);
            assert_eq!(decode_crm_stage_value(&encoded)?, stage);
            through_chokepoint(&body(PREDICATE_CRM_STAGE, encoded))?;
        }
    }
    Ok(())
}

#[test]
fn descriptor_rows_are_complete_and_pinned() {
    let rows = claim_class_descriptors();
    let covered: BTreeSet<&str> = rows.iter().map(|row| row.predicate).collect();
    assert_eq!(
        covered,
        CAMPAIGN_PACK_CLAIM_PREDICATES.iter().copied().collect()
    );
    assert_eq!(rows.len(), 6);
    assert_eq!(rows.len(), covered.len());

    let expected = [
        (PREDICATE_CAMPAIGN_MEMBER, "ordinary", false, true, false),
        (PREDICATE_CRM_FIT, "human_ruled", false, true, false),
        (PREDICATE_CRM_STAGE, "recorded", false, false, true),
        (PREDICATE_COMM_DO_NOT_CONTACT, "ordinary", true, true, false),
        (PREDICATE_COMM_BOUNCE, "recorded", false, false, true),
        (PREDICATE_COMM_JURISDICTION, "recorded", true, false, true),
    ];
    for (row, (predicate, write_class, enforcement, restrictive, projector_only)) in
        rows.iter().zip(expected)
    {
        assert_eq!(row.predicate, predicate);
        assert_eq!(row.write_class, write_class, "{predicate}");
        assert_eq!(row.enforcement, enforcement, "{predicate}");
        assert_eq!(row.restrictive, restrictive, "{predicate}");
        assert_eq!(row.projector_only, projector_only, "{predicate}");
        assert!(
            matches!(row.write_class, "recorded" | "human_ruled" | "ordinary"),
            "{predicate} has a write_class outside the allowed tokens"
        );
    }
}

#[test]
fn bounce_and_jurisdiction_validate_projector_fact_shape() -> Result<()> {
    for kind in [BounceKind::Hard, BounceKind::Soft] {
        let value = with_key(&canonical_bounce(), KEY_BOUNCE, Value::from(kind.as_str()));
        through_chokepoint(&body(PREDICATE_COMM_BOUNCE, value.clone()))?;
        assert_eq!(
            decode_comm_bounce_value(&value)?,
            CommBounceValue {
                channel: "email".to_owned(),
                bounce: kind,
                sender_ref: entity(REF_SEED),
                occurred_at: 1_754_400_000,
            }
        );
    }
    // Only the closed set, and every field is required and well-typed.
    for (key, bad) in [
        (KEY_BOUNCE, Value::from("deferred")),
        (KEY_CHANNEL, Value::from("")),
        (KEY_CHANNEL, Value::from("EMAIL")),
        (KEY_SENDER_REF, Value::from("not-hex")),
        (KEY_OCCURRED_AT, Value::from("yesterday")),
    ] {
        reject(
            PREDICATE_COMM_BOUNCE,
            with_key(&canonical_bounce(), key, bad),
        );
    }

    // Jurisdiction requires evidence: a projector-written external fact with
    // no provenance cannot be re-derived or disputed.
    through_chokepoint(&jurisdiction_body(canonical_jurisdiction()))?;
    assert_matches!(
        through_chokepoint(&body(PREDICATE_COMM_JURISDICTION, canonical_jurisdiction())),
        Err(Error::InvalidClaimBody(
            "comm.jurisdiction requires claim evidence"
        ))
    );
    assert_eq!(
        decode_comm_jurisdiction_value(&canonical_jurisdiction())?,
        CommJurisdictionValue {
            jurisdiction: "us-ca".to_owned(),
            observed_at: 1_754_400_000,
        }
    );
    // Empty token, missing field, and confidence smuggled into the value —
    // confidence lives in `ClaimBody::confidence`, not here.
    for value in [
        with_key(&canonical_jurisdiction(), KEY_JURISDICTION, Value::from("")),
        map(&[(KEY_JURISDICTION, Value::from("us-ca"))]),
        map(&[
            (KEY_JURISDICTION, Value::from("us-ca")),
            (KEY_OBSERVED_AT, Value::from(1_u64)),
            ("confidence", Value::from(0.9)),
        ]),
    ] {
        assert_matches!(
            through_chokepoint(&jurisdiction_body(value)),
            Err(Error::InvalidClaimBody(_))
        );
    }
    Ok(())
}

#[test]
fn do_not_contact_channel_and_scope_are_exact() -> Result<()> {
    let all_channels = CommDoNotContactValue {
        channel: None,
        scope: DO_NOT_CONTACT_SCOPE_ALL.to_owned(),
    };
    let email_send = CommDoNotContactValue {
        channel: Some("email".to_owned()),
        scope: "send".to_owned(),
    };

    // Wildcards.
    assert!(do_not_contact_applies(&all_channels, Some("email"), "send"));
    assert!(do_not_contact_applies(&all_channels, Some("sms"), "notify"));
    assert!(do_not_contact_applies(&all_channels, None, "send"));

    // Exact matches, normalization-insensitive on the query side.
    assert!(do_not_contact_applies(&email_send, Some("email"), "send"));
    assert!(do_not_contact_applies(&email_send, Some(" EMAIL "), "SEND"));

    // A mismatched channel or a non-`all` mismatched scope does not apply.
    assert!(!do_not_contact_applies(&email_send, Some("sms"), "send"));
    assert!(!do_not_contact_applies(
        &email_send,
        Some("email"),
        "notify"
    ));
    assert!(!do_not_contact_applies(
        &CommDoNotContactValue {
            channel: None,
            scope: "send".to_owned(),
        },
        Some("email"),
        "notify"
    ));
    // An unknown query channel cannot prove the suppression irrelevant.
    assert!(do_not_contact_applies(&email_send, None, "send"));

    // Wire shape: `channel` optional, `scope` required, both stored normalized.
    assert_eq!(
        decode_do_not_contact_value(&do_not_contact_value(None, DO_NOT_CONTACT_SCOPE_ALL))?,
        all_channels
    );
    assert_eq!(
        decode_do_not_contact_value(&do_not_contact_value(Some("email"), "send"))?,
        email_send
    );
    for value in [
        do_not_contact_value(Some("EMAIL"), "send"),
        do_not_contact_value(Some(""), "send"),
        do_not_contact_value(Some("email"), ""),
        do_not_contact_value(Some("email"), "SEND"),
        map(&[(KEY_CHANNEL, Value::from("email"))]),
        map(&[
            (KEY_CHANNEL, Value::from("email")),
            (KEY_SCOPE, Value::from("send")),
            ("campaign", hex(CAMPAIGN_SEED)),
        ]),
    ] {
        reject(PREDICATE_COMM_DO_NOT_CONTACT, value);
    }
    Ok(())
}

#[test]
fn crm_stage_wire_tokens_match_serde() {
    // The rmpv codec and the serde surface must name the same tokens; a drift
    // here would let a claim decode one way and serialize another.
    for basis in [EvidenceBasis::Machine, EvidenceBasis::OwnerAttested] {
        assert_eq!(
            serde_json::to_string(&basis).expect("basis serializes"),
            format!("\"{}\"", basis.as_str())
        );
        assert_eq!(EvidenceBasis::parse(basis.as_str()), Some(basis));
    }
    for class in StageEvidenceClass::ALL {
        assert_eq!(
            serde_json::to_string(&class).expect("class serializes"),
            format!("\"{}\"", class.as_str())
        );
        assert_eq!(StageEvidenceClass::parse(class.as_str()), Some(class));
    }
    assert_eq!(EvidenceBasis::parse("owner-attested"), None);
    assert_eq!(StageEvidenceClass::parse("meaningfulreply"), None);
    assert_eq!(
        serde_json::to_string(&StageKey("replied".to_owned())).expect("stage key serializes"),
        "\"replied\""
    );
}

// ---------------------------------------------------------------------------
// Gate enforcement leg
// ---------------------------------------------------------------------------

/// Actor, verb, and channel the fixture manifest grants.
const GATE_ACTOR_REF: &str = "sender";
const GATE_VERB: &str = "send";
const GATE_CHANNEL: &str = "email";
const COUNTERPARTY: &str = "kenji@example.com";

/// A manifest granting exactly this actor/verb/channel, so the do-not-contact
/// leg is proven by flipping a genuine ALLOW into a DENY rather than by
/// decorating a decision that was refused for some other reason.
fn allow_external_effect_manifest() -> Vec<u8> {
    let manifest = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(POLICY_SCHEMA_VERSION),
        ),
        (Value::from("pack_id"), Value::from("campaign-claims-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(Vec::new())),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("first_party")),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
        (
            Value::from("scoped_grants"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_ref"), Value::from(GATE_ACTOR_REF)),
                (Value::from("effector"), Value::from(GATE_VERB)),
                (
                    Value::from("scope"),
                    Value::Map(vec![(Value::from("channel"), Value::from(GATE_CHANNEL))]),
                ),
            ])]),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &manifest).expect("manifest encode");
    out
}

/// A vault where only the fixture manifest resolves, plus a comm-owned PERSON
/// for [`COUNTERPARTY`] so the gate leg has a subject to resolve.
fn gate_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open_unseeded_for_test(dir.path(), VaultConfig::device()).expect("open");
    put_policy_manifest_bytes(&vault, entity(0x6B), &allow_external_effect_manifest())
        .expect("seed fixture manifest");
    let person =
        crate::comm::resolve_or_create_comm_party(&vault, COUNTERPARTY).expect("mint comm party");
    (dir, vault, person)
}

fn gate_effect(counterparty: Option<&str>) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: "first_party".to_owned(),
            actor_ref: Some(GATE_ACTOR_REF.to_owned()),
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(entity(0x6C)),
            ..GateProvenanceHandles::default()
        },
        verb: GATE_VERB.to_owned(),
        channel: GATE_CHANNEL.to_owned(),
        channel_identity_ref: None,
        counterparty: counterparty.map(str::to_owned),
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: true,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::Normal,
    }
}

/// Evaluates one external effect through the production gate transaction.
fn evaluate(vault: &Vault, effect: &ExternalEffectGateInput) -> Result<(GateOutcome, Vec<String>)> {
    let policy = {
        let rtxn = vault.store.env.read_txn()?;
        resolve_policy_manifest(&vault.store, &rtxn)?
    };
    let (_id, decision, _charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, effect, &policy, false)
    })?;
    let reasons = decision
        .reason_codes()
        .iter()
        .map(|code| (*code).as_str().to_owned())
        .collect();
    Ok((decision.outcome(), reasons))
}

fn write_do_not_contact(
    vault: &Vault,
    id: &EntityId,
    person: EntityId,
    channel: Option<&str>,
    scope: &str,
    approval: ClaimApprovalStatus,
) -> Result<()> {
    let mut claim = ClaimBody::new(
        PREDICATE_COMM_DO_NOT_CONTACT,
        ClaimSubject::Entity(person),
        do_not_contact_value(channel, scope),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    );
    // A validity window that closed long ago: staleness must not un-suppress.
    claim.valid_from = Some(1);
    claim.valid_to = Some(2);
    vault.put_claim(id, &claim, TimeRange { start: 1, end: 1 }, 1)
}

fn deny_opt_out() -> (GateOutcome, Vec<String>) {
    (
        GateOutcome::Deny,
        vec![GateReasonCode::DenyCounterpartyOptOut.as_str().to_owned()],
    )
}

#[test]
fn do_not_contact_matching_claim_denies_external_effect() -> Result<()> {
    let (_dir, vault, person) = gate_vault();

    // Baseline: the fixture manifest genuinely allows this effect.
    assert_eq!(
        evaluate(&vault, &gate_effect(Some(COUNTERPARTY)))?,
        (GateOutcome::Allow, vec!["gate.allow".to_owned()])
    );

    write_do_not_contact(
        &vault,
        &entity(0x6D),
        person,
        Some(GATE_CHANNEL),
        GATE_VERB,
        ClaimApprovalStatus::Approved,
    )?;

    // Starting from `counterparty_opted_out = false`, the DNC leg sets it.
    assert_eq!(
        evaluate(&vault, &gate_effect(Some(COUNTERPARTY)))?,
        deny_opt_out()
    );

    // A different counterparty resolves to no PERSON, so the leg contributes
    // nothing and the effect still passes.
    assert_eq!(
        evaluate(&vault, &gate_effect(Some("other@example.com")))?.0,
        GateOutcome::Allow
    );
    // An effect with no counterparty never reaches the leg at all.
    assert_eq!(evaluate(&vault, &gate_effect(None))?.0, GateOutcome::Allow);

    // Starting from pre-existing COUNTERPARTY_CONTACT truth, the leg cannot clear it: the
    // fold is `|=`, so a counterparty with no matching DNC head keeps the deny.
    let mut prehydrated = gate_effect(Some("other@example.com"));
    prehydrated.counterparty_opted_out = true;
    assert_eq!(evaluate(&vault, &prehydrated)?, deny_opt_out());
    Ok(())
}

#[test]
fn do_not_contact_restrictive_wins_until_authorized_clear() -> Result<()> {
    let (_dir, vault, person) = gate_vault();
    let claim_id = entity(0x6E);

    // A Proposed head suppresses exactly like an Approved one, and the closed
    // validity window proves staleness never un-suppresses.
    write_do_not_contact(
        &vault,
        &claim_id,
        person,
        None,
        DO_NOT_CONTACT_SCOPE_ALL,
        ClaimApprovalStatus::Proposed,
    )?;
    let stored = vault.get_claim(&claim_id)?.expect("dnc claim");
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(stored.valid_to, Some(2));
    assert_eq!(
        evaluate(&vault, &gate_effect(Some(COUNTERPARTY)))?.0,
        GateOutcome::Deny
    );

    // Only an authorized clear stamp — the claim-lifecycle retraction door —
    // removes the head from the fold.
    vault.retract_claim(&claim_id, 100)?;
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("dnc claim").lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert_eq!(
        evaluate(&vault, &gate_effect(Some(COUNTERPARTY)))?.0,
        GateOutcome::Allow
    );
    Ok(())
}

#[test]
fn do_not_contact_scope_and_channel_gate_the_deny() -> Result<()> {
    let (_dir, vault, person) = gate_vault();

    // A DNC row on another channel does not deny this one.
    write_do_not_contact(
        &vault,
        &entity(0x6F),
        person,
        Some("sms"),
        GATE_VERB,
        ClaimApprovalStatus::Approved,
    )?;
    assert_eq!(
        evaluate(&vault, &gate_effect(Some(COUNTERPARTY)))?.0,
        GateOutcome::Allow
    );

    // Nor does one scoped to a verb this effect is not performing.
    write_do_not_contact(
        &vault,
        &entity(0x70),
        person,
        Some(GATE_CHANNEL),
        "notify",
        ClaimApprovalStatus::Approved,
    )?;
    assert_eq!(
        evaluate(&vault, &gate_effect(Some(COUNTERPARTY)))?.0,
        GateOutcome::Allow
    );

    // The `all` scope covers every external-effect scope.
    write_do_not_contact(
        &vault,
        &entity(0x72),
        person,
        Some(GATE_CHANNEL),
        DO_NOT_CONTACT_SCOPE_ALL,
        ClaimApprovalStatus::Approved,
    )?;
    assert_eq!(
        evaluate(&vault, &gate_effect(Some(COUNTERPARTY)))?.0,
        GateOutcome::Deny
    );
    Ok(())
}
