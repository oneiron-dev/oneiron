//! Specialized doors: operation effect, fenced listing, and commitment projection.

use super::*;

/// The manifest these two pins run under: the Dreamer's `agent` actor is
/// granted `auto`, and the manifest carries NO signature block — so
/// `dreamer_auto_grant_requires_manifest_signature`, which fires ONLY when the
/// evaluator input carries a Dreamer run handle, is observable in the verdict.
fn operation_effect_vault() -> Result<(tempfile::TempDir, crate::Vault)> {
    let (tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Generated, 0)]);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &first_party_connector_actor_ref(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0x26), &data)?;
    Ok((tmp, vault))
}

/// The synthetic effect body a `self.memory.*` verb presents at the door:
/// host-typed predicate, `Approved`, a typed operand value, and envelope
/// evidence with NO candidate evidence — because there is no candidate. The
/// envelope is an ordinary Dreamer-admitted one, so the detector fires on it.
fn operation_effect_parts(vault: &crate::Vault) -> Result<(ClaimBody, WriteEnvelope)> {
    let actor = first_party_connector_actor_id();
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"dreamer operation actor",
    )?;
    let subject = test_id(0x27);
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"operation subject",
    )?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (
                Value::from(DREAMER_PROVENANCE_RUNNER_KEY),
                Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
            ),
            (
                Value::from(DREAMER_PROVENANCE_RUN_ID_KEY),
                Value::from(PRECOMMIT_RUN_ID),
            ),
        ]))?,
        ClaimApprovalStatus::Proposed,
    );
    let mut body = ClaimBody::new(
        "self.memory.supersede_claim",
        ClaimSubject::Entity(subject),
        Value::Binary(test_id(0x28).as_bytes().to_vec()),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.evidence = Some(crate::write_envelope::write_envelope_evidence(
        &envelope, None,
    ));
    body.source = Some(envelope.source());
    Ok((body, envelope))
}

/// The claim door as the code-run traps call it, with the host mode under test
/// as its ONLY variable.
fn attempt_operation_effect_write(
    vault: &crate::Vault,
    id: &EntityId,
    body: &ClaimBody,
    envelope: &WriteEnvelope,
    operation_effect_body: bool,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &wtxn)?;
    let result = check_claim_policy_for_write(
        &vault.store,
        &mut wtxn,
        id,
        body,
        Some(envelope),
        &policy,
        GateWriteMode {
            record_decision: true,
            persist_pending_consent: false,
            resolve_pending: false,
            can_resolve_pending_consent: false,
            include_source_in_gate_input: true,
        },
        operation_effect_body,
    );
    wtxn.commit()?;
    result
}

pub(super) fn gate_rejection_parts(err: Error) -> (&'static str, Vec<&'static str>) {
    match err {
        Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => (outcome, reason_codes),
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
}

/// A host-typed synthetic operation body is gate material for a memory VERB,
/// never a persisted claim candidate, so the pre-commit candidate checks do not
/// run on it — and everything else still does.
#[test]
fn door_operation_effect_skips_precommit() -> Result<()> {
    let (_tmp, vault) = operation_effect_vault()?;
    let (body, envelope) = operation_effect_parts(&vault)?;
    let gate_id = test_id(0x29);
    let before = vault.store.gate_decisions(100)?.len();

    let err = attempt_operation_effect_write(&vault, &gate_id, &body, &envelope, true)
        .expect_err("the unsigned manifest still refuses the Dreamer's Approved operation");
    let (outcome, reason_codes) = gate_rejection_parts(err);
    assert!(
        !reason_codes
            .iter()
            .any(|code| code.starts_with("gate.deny.dreamer_precommit.")),
        "an operation-effect body is not a candidate, so no pre-commit code may appear: \
         {reason_codes:?}"
    );
    // The verdict is the POLICY's, and it is one the evaluator could only reach
    // with the Dreamer run handle in its provenance input: the manifest
    // signature rule keys on exactly that handle.
    assert_eq!(outcome, "pending");
    let manifest_authority = "gate.pending.policy_manifest_authority";
    assert!(
        reason_codes.contains(&manifest_authority),
        "the Dreamer provenance handles must still reach policy evaluation: {reason_codes:?}"
    );

    // Detection, evaluation AND recording all still happened.
    let decisions = vault.store.gate_decisions(100)?;
    assert_eq!(decisions.len(), before + 1, "the decision is recorded");
    assert_eq!(decisions[0].claim_id, Some(*gate_id.as_bytes()));
    assert_eq!(decisions[0].outcome, "pending");
    assert!(
        !has_pending_gate_consent(&vault, &gate_id)?,
        "an Approved operation body mints no consent row"
    );
    Ok(())
}

/// The skip is bound to the HOST MODE, not to the body's shape.
///
/// Byte-identical predicate, value, approval, evidence and envelope — the only
/// difference from the pin above is that this write claims to be a persisted
/// candidate, and the evidence floor refuses it on the spot.
#[test]
fn door_operation_effect_flag_never_set_for_candidates() -> Result<()> {
    let (_tmp, vault) = operation_effect_vault()?;
    let (body, envelope) = operation_effect_parts(&vault)?;
    let claim_id = test_id(0x2A);

    let err = attempt_operation_effect_write(&vault, &claim_id, &body, &envelope, false)
        .expect_err("a candidate citing no resolving evidence is denied");
    let (outcome, reason_codes) = gate_rejection_parts(err);
    assert_eq!(outcome, "deny", "validity failures deny, never downgrade");
    assert_eq!(reason_codes, ["gate.deny.dreamer_precommit.no_evidence"]);
    assert!(
        vault.get_raw(&claim_id)?.is_none(),
        "a denied write lands no claim"
    );
    assert!(
        !has_pending_gate_consent(&vault, &claim_id)?,
        "a validity denial mints no pending-consent row"
    );
    Ok(())
}

#[test]
fn critical_confirm_fenced_listing_reaches_captured_rows_before_hostile_inserts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let now = crate::unix_seconds_now();
    let mut captured = Vec::new();
    vault.with_write_txn(|wtxn| {
        for ordinal in 0..257u16 {
            // Deliberately nonmonotonic caller IDs: encode the full ordinal so
            // every fixture row is unique, while progress follows the
            // store-owned sequence rather than these bytes.
            let high = (ordinal >> 8) as u8;
            let low = ordinal as u8;
            let claim = EntityId::from_bytes([
                !high, low, 0xc5, high, !low, high, 0xc5, low, !high, low, 0xc5, high, !low, high,
                0xc5, low,
            ])?;
            vault.store.put_pending_gate_consent_in_txn(
                wtxn,
                &critical_confirm_pending(claim, (ordinal % 250) as u8 + 1, now),
            )?;
            captured.push(claim);
        }
        Ok(())
    })?;
    let first = vault.pending_critical_write_confirms(1)?;
    assert_eq!(first.len(), 1);
    let hostile = sweep_id(0xc5, 0xfe);
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &critical_confirm_pending(hostile, 251, now))
    })?;
    let mut seen = first
        .into_iter()
        .map(|binding| binding.claim_id)
        .collect::<Vec<_>>();
    for _ in 1..257 {
        seen.push(vault.pending_critical_write_confirms(1)?[0].claim_id);
    }
    assert_eq!(seen.len(), captured.len());
    assert_eq!(
        seen, captured,
        "the captured fence reaches every pre-fence row"
    );
    assert!(seen.iter().all(|claim| *claim != hostile));
    vault.with_write_txn(|wtxn| {
        assert_eq!(
            vault
                .store
                .critical_confirm_list_sweep_state_in_txn(&*wtxn)?,
            (None, None),
            "reaching the fence completes the captured cycle before a new one begins",
        );
        Ok(())
    })?;
    let next_cycle_first = vault.pending_critical_write_confirms(256)?;
    assert_eq!(next_cycle_first.len(), 256);
    let mut next_cycle_first_ids = next_cycle_first
        .iter()
        .map(|binding| binding.claim_id)
        .collect::<Vec<_>>();
    let mut expected_first_ids = captured[..256].to_vec();
    next_cycle_first_ids.sort_by_key(|claim| *claim.as_bytes());
    expected_first_ids.sort_by_key(|claim| *claim.as_bytes());
    assert_eq!(
        next_cycle_first_ids, expected_first_ids,
        "the sorted page contains exactly the captured head membership",
    );
    let next_cycle_tail = vault.pending_critical_write_confirms(256)?;
    assert_eq!(
        next_cycle_tail
            .iter()
            .map(|binding| binding.claim_id)
            .collect::<Vec<_>>(),
        vec![captured[256], hostile],
        "the hostile row is reached on the bounded second page of the next cycle",
    );
    Ok(())
}

/// The band the projector's minted claims actually present to the gate: the
/// mint stamps no scope sensitivity, so `claim_sensitivity_band` reads them at
/// the unstamped floor. The `generated` source-trust row caps at exactly this.
const COMMITMENT_PROJECTION_CLAIM_BAND: u8 = crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND;

/// The gate input the commitment projector presents on every mint: System
/// actor at the derived projection id, `Generated` source, `content_kind`
/// `Claim`, at the `commitment.record` axes.
fn commitment_projection_gate_input(
    actor_ref: &str,
    sensitivity_band: u8,
    criticality: PolicyCriticality,
) -> GateEvaluatorInput {
    let mut input = gate_evaluator_input(
        EdgeActorClass::System.gate_actor_class(),
        Some(actor_ref),
        ClaimSource::Generated,
        criticality,
    );
    input.sensitivity_band = Some(sensitivity_band);
    input
}

fn resolved_default_policy_manifest(vault: &crate::Vault) -> Result<PolicyManifestResolution> {
    put_policy_manifest_bytes(vault, test_id(0xC9), &default_policy_manifest())?;
    resolve(vault)
}

fn commitment_record_criticality(policy: &PolicyManifestResolution) -> PolicyCriticality {
    policy.criticality_for_predicate(crate::commitment::PREDICATE_COMMITMENT_RECORD)
}

/// The pinned projection envelope resolves to auto under the DEFAULT manifest.
///
/// This is the whole point of the two rows: before them, every mint pended on
/// both `gate.pending.actor_ceiling` and `gate.pending.source_trust`.
#[test]
fn commitment_projection_envelope_reaches_auto_under_default_manifest() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolved_default_policy_manifest(&vault)?;

    let actor = crate::commitment_schedule::commitment_projection_actor();
    assert_eq!(
        actor.actor_class(),
        EdgeActorClass::System,
        "the projector writes under the pinned System class"
    );

    let input = commitment_projection_gate_input(
        &actor.entity_ref().to_hex(),
        COMMITMENT_PROJECTION_CLAIM_BAND,
        commitment_record_criticality(&policy),
    );
    let decision = policy.evaluate_gate(&input);

    assert_eq!(decision.outcome(), GateOutcome::Allow);
    // An allow decision carries the single `gate.allow` code and NO pending or
    // deny code: nothing about the projection envelope is left unresolved.
    assert_eq!(decision.reason_codes(), &[GateReasonCode::Allow]);
    assert!(
        !decision
            .reason_codes()
            .iter()
            .any(|code| code.as_str().starts_with("gate.pending.")
                || code.as_str().starts_with("gate.deny.")),
        "the pinned projection envelope must resolve with zero pending/deny codes"
    );
    Ok(())
}

/// BOTH shipped grants are keyed to ONE derived actor id, not to a class.
///
/// A different System actor presenting the identical write pends on the actor
/// ceiling (class-wide `system` keeps default-deny) AND on source trust: the
/// `generated` permit is actor-bound too (ONE-1749), so an unnamed writer reads
/// the class as carrying no row at all and `Generated`'s explicit-auto-permit
/// requirement holds.
#[test]
fn commitment_projection_grant_is_actor_keyed_not_class_wide() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolved_default_policy_manifest(&vault)?;

    let mut perturbed = *crate::commitment_schedule::commitment_projection_actor()
        .entity_ref()
        .as_bytes();
    perturbed[0] ^= 0x01;
    let other_system_actor = EntityId::from_bytes(perturbed).expect("perturbed system actor id");

    let input = commitment_projection_gate_input(
        &other_system_actor.to_hex(),
        COMMITMENT_PROJECTION_CLAIM_BAND,
        commitment_record_criticality(&policy),
    );
    let decision = policy.evaluate_gate(&input);

    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        decision.reason_codes(),
        &[
            GateReasonCode::PendingActorCeiling,
            GateReasonCode::PendingSourceTrust,
        ],
        "only the actor-keyed rows grant auto; every other system actor pends on both axes"
    );
    Ok(())
}

/// The sensitivity ladder stays intact above the granted band.
///
/// The `generated` row is parity with the minted band, not headroom: one band
/// above the cap pends on source trust even for the pinned projection actor.
#[test]
fn generated_source_trust_row_pends_one_band_above_the_cap() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolved_default_policy_manifest(&vault)?;

    let input = commitment_projection_gate_input(
        &crate::commitment_schedule::commitment_projection_actor()
            .entity_ref()
            .to_hex(),
        COMMITMENT_PROJECTION_CLAIM_BAND + 1,
        commitment_record_criticality(&policy),
    );
    let decision = policy.evaluate_gate(&input);

    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        decision.reason_codes(),
        &[GateReasonCode::PendingSourceTrust],
        "a Generated claim above the capped band pends; the actor ceiling still passes"
    );
    Ok(())
}

/// The shipped manifest row stays welded to the domain derivation.
///
/// If `commitment_projection_actor()` ever moves, this fails loudly instead of
/// leaving a dangling row that silently re-aims (or drops) the grant.
#[test]
fn default_manifest_system_row_pins_the_commitment_projection_actor() {
    let data = default_policy_manifest();
    let mut cursor = Cursor::new(data.as_slice());
    let Value::Map(entries) = rmpv::decode::read_value(&mut cursor).expect("decode") else {
        unreachable!("the default manifest is a map");
    };

    let ceilings = entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(POLICY_ACTOR_CEILINGS_KEY)).then_some(value))
        .expect("default manifest carries actor ceilings");
    let Value::Array(rows) = ceilings else {
        unreachable!("actor ceilings are an array");
    };

    let row_field = |row: &Value, field: &str| -> Option<String> {
        let Value::Map(fields) = row else {
            return None;
        };
        fields.iter().find_map(|(key, value)| {
            (key.as_str() == Some(field))
                .then(|| value.as_str().map(str::to_owned))
                .flatten()
        })
    };

    let system_rows = rows
        .iter()
        .filter(|row| {
            row_field(row, ACTOR_CLASS_KEY).as_deref()
                == Some(EdgeActorClass::System.gate_actor_class())
        })
        .collect::<Vec<_>>();

    assert_eq!(
        system_rows.len(),
        1,
        "exactly one system row ships: the actor-keyed projection grant"
    );
    let derived_actor_ref = crate::commitment_schedule::commitment_projection_actor()
        .entity_ref()
        .to_hex();
    assert_eq!(
        row_field(system_rows[0], ACTOR_REF_KEY).as_deref(),
        Some(derived_actor_ref.as_str()),
        "the system row must name the derived commitment projection actor"
    );
    assert_eq!(
        row_field(system_rows[0], ACTOR_CEILING_KEY).as_deref(),
        Some("auto")
    );
}

/// ONE-1749: the shipped `generated` permit is ACTOR-BOUND, not class-wide.
///
/// The cap cannot carry this on its own. It sits at
/// `UNSTAMPED_CLAIM_SENSITIVITY_BAND`, which is exactly the band every
/// unstamped claim reads, so an unbound row auto-approves the whole
/// `Generated` class instead of the one engine writer it was authored for —
/// silently retiring `gate.pending.source_trust` for code emissions, dreamer
/// output and every other generated write. Pinning the binding here keeps that
/// collapse from returning unnoticed.
#[test]
fn default_manifest_generated_source_trust_row_is_bound_to_the_projection_actor() -> Result<()> {
    fn field<'a>(fields: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
        fields
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
    }

    let data = default_policy_manifest();
    let mut cursor = Cursor::new(data.as_slice());
    let Value::Map(entries) = rmpv::decode::read_value(&mut cursor).expect("decode") else {
        unreachable!("the default manifest is a map");
    };

    let source_trust = entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(POLICY_SOURCE_TRUST_KEY)).then_some(value))
        .expect("default manifest carries a source-trust table");
    let Value::Map(rows) = source_trust else {
        unreachable!("source trust is a map keyed by claim source");
    };

    let generated = rows
        .iter()
        .find_map(|(key, value)| {
            (key.as_str() == Some(ClaimSource::Generated.as_str())).then_some(value)
        })
        .expect("the default manifest ships a generated source-trust row");
    let Value::Map(fields) = generated else {
        unreachable!("the generated row is a map");
    };

    let derived_actor_ref = crate::commitment_schedule::commitment_projection_actor()
        .entity_ref()
        .to_hex();
    let bound = field(fields, ACTOR_REF_KEY);
    assert_eq!(
        bound.and_then(Value::as_str),
        Some(derived_actor_ref.as_str()),
        "the generated permit must name the derived commitment projection actor"
    );
    let cap = field(fields, SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY);
    assert_eq!(
        cap.and_then(Value::as_u64),
        Some(u64::from(crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND)),
        "the cap stays parity with the minted band, with no headroom"
    );

    // And the binding is enforced, not merely recorded: the SAME `Generated`
    // write from any other actor pends on source trust.
    let (_tmp, vault) = temp_vault();
    let policy = resolved_default_policy_manifest(&vault)?;
    let mut other = *crate::commitment_schedule::commitment_projection_actor()
        .entity_ref()
        .as_bytes();
    other[0] ^= 0x01;
    let other_actor = EntityId::from_bytes(other).expect("perturbed actor id");
    let other_actor_ref = other_actor.to_hex();

    assert!(
        policy.source_trust_allows_auto(
            Some(ClaimSource::Generated),
            Some(COMMITMENT_PROJECTION_CLAIM_BAND),
            Some(derived_actor_ref.as_str()),
        ),
        "the named projection actor keeps its permit"
    );
    assert!(
        !policy.source_trust_allows_auto(
            Some(ClaimSource::Generated),
            Some(COMMITMENT_PROJECTION_CLAIM_BAND),
            Some(other_actor_ref.as_str()),
        ),
        "every other actor reads the class as carrying no row"
    );
    assert!(
        !policy.source_trust_allows_auto(
            Some(ClaimSource::Generated),
            Some(COMMITMENT_PROJECTION_CLAIM_BAND),
            None,
        ),
        "an unattributed write never rides an actor-bound permit"
    );
    Ok(())
}
