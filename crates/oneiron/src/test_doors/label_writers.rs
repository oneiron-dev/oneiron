//! Fixture vaults for the label-writer tests (OPUS-LEAKS, lead call G): the
//! shipped policy plus a `core:read` grant for each named member, so a test
//! reads as a member outside a relationship would, through the member's own
//! Memory lane.

use crate::error::{Error, Result};
use crate::vault::Vault;

/// The shipped policy (the Dreamer's rows included) plus a `core:read`
/// grant for each actor ref in `members`.
fn shipped_policy_with_members(vault: &Vault, members: &[String]) -> Result<()> {
    let rmpv::Value::Map(mut entries) =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest()?.as_slice())
            .map_err(|_| Error::InvalidConfig("default policy".into()))?
    else {
        return Err(Error::InvalidConfig("default policy is not a map".into()));
    };
    let mut grants = Vec::new();
    for member in members {
        grants.push(rmpv::Value::Map(vec![
            (
                rmpv::Value::from("actor_ref"),
                rmpv::Value::from(member.as_str()),
            ),
            (
                rmpv::Value::from("effector"),
                rmpv::Value::from("core:read"),
            ),
            (
                rmpv::Value::from("scope"),
                crate::federation::scope_codec::encode_scope_value(
                    &crate::federation::scope_codec::read_preset(),
                )?,
            ),
            (
                rmpv::Value::from("receipt_required"),
                rmpv::Value::Boolean(false),
            ),
        ]));
    }
    match entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("scoped_grants"))
    {
        Some((_, rmpv::Value::Array(rows))) => rows.extend(grants),
        _ => entries.push((
            rmpv::Value::from("scoped_grants"),
            rmpv::Value::Array(grants),
        )),
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(entries))
        .map_err(|_| Error::InvalidConfig("encode policy".into()))?;
    crate::test_fixtures::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

/// A fixture vault opened with `config`: engine machines provisioned, and
/// the shipped policy plus a `core:read` grant for each actor ref in
/// `members`.
///
/// # Errors
///
/// The vault's.
pub fn open_member_vault(
    path: &std::path::Path,
    config: crate::VaultConfig,
    members: &[String],
) -> Result<Vault> {
    let vault = Vault::open(path, config)?;
    crate::test_fixtures::provision_engine_machines(&vault);
    shipped_policy_with_members(&vault, members)?;
    Ok(vault)
}

/// The vault's embedded owner, bound under the test host root as a host
/// binds its owner, with his authenticated proof.
///
/// # Errors
///
/// The vault's, or a refused authentication.
pub fn embedded_owner(
    vault: &Vault,
) -> Result<(crate::EntityId, crate::consent::AuthenticatedOwner)> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| Error::InvalidConfig(format!("embedded owner: {error:?}")))?;
    vault.bind_host_owner_for_test(&crate::test_fixtures::test_host_issuer(), owner)?;
    let proof = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    Ok((owner, proof))
}

/// Runs one nightly stewardship pass at `now` (Unix seconds), as the wake
/// driver runs it: the maintenance attempt the nightly enqueue writes for
/// the facet, admitted on the maintenance lane and executed by the
/// maintenance dispatcher, under the Dreamer's authority stamp.
///
/// # Errors
///
/// The vault's, or a pass that is not admitted or does not complete.
pub fn run_stewardship_once(vault: &Vault, now: u64) -> Result<()> {
    use crate::dreamer_runner::{
        AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAttemptPayload, DreamerRunnerStore,
    };
    use crate::dreamer_wake::{WakeAttemptContext, WakePassDeadline};

    let store = DreamerRunnerStore::new(vault);
    vault.with_write_txn(|txn| {
        store
            .enqueue_kind_in_txn(
                txn,
                crate::dreamer_runner::maintenance::MAINTENANCE_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type:
                        crate::dreamer_runner::maintenance::stewardship::STEWARDSHIP_FACET
                            .to_owned(),
                    input: rmpv::Value::Nil,
                    parent_attempt: None,
                },
                Some(format!("opus-leaks.stewardship:{now}")),
                None,
                now,
            )
            .map(|_| ())
    })?;
    let DreamerAdmissionOutcome::Admitted(admitted) =
        store.admit_next_maintenance(AdmitDreamerAttempt {
            lease_owner: "test-door".to_owned(),
            now,
            budget_id: "wake".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        })?
    else {
        return Err(Error::InvalidConfig(
            "the stewardship attempt was not admitted".into(),
        ));
    };
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let outcome = crate::dreamer_runner::maintenance::execute(
        &admitted,
        &WakeAttemptContext {
            vault,
            deadline: &deadline,
            cancel: None,
            device_cancel: None,
            budget_id: "wake",
            now_ms: now.saturating_mul(1000),
            prepared_wake: None,
            prepared_attempt: None,
            spend_meter: None,
        },
        None,
    )?;
    if !matches!(
        outcome,
        crate::dreamer_wake::DreamerAttemptExecution::Completed { .. }
    ) {
        return Err(Error::InvalidConfig(
            "the stewardship pass did not complete".into(),
        ));
    }
    Ok(())
}

/// Gives the Dreamer a live grant to read the CLAIMs of `relationship`, as
/// an owner grants it today.
///
/// # Errors
///
/// The vault's.
pub fn grant_dreamer_relationship_claims(
    vault: &Vault,
    relationship: crate::EntityId,
) -> Result<()> {
    use crate::access_grant::{
        AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
    };
    vault.create_access_grant(
        &crate::EntityId::now(),
        &AccessGrant {
            principal_ref: vault.dreamer_authority()?.entity_ref(),
            scope: AccessGrantScope::RelationshipClaims {
                space_ref: relationship,
            },
            capability: AccessGrantCapability::RelationshipClaimsRead,
            status: AccessGrantStatus::Active,
            created_at: 1,
            revoked_at: None,
            expires_at: None,
            authority_scope: crate::federation::scope_codec::read_preset(),
            companion_bounds: None,
        },
    )
}
