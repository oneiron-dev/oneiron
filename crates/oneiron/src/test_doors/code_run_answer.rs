//! Doors for `tests/code_run_restricted_actor_answer.rs` (OPUS-E2E-1): the
//! actor-bound approval ceiling a restricted run's actor carries, and the
//! finished run's answer read back from its replay record.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// Installs an ARCH-0028 tier agent's stored authority for `actor` on the
/// vault's default policy manifest: a `core:read` scoped grant plus the
/// actor-bound approval ceiling row (`auto` or `proposed`), replacing any
/// earlier ceiling row bound to the same actor, so the owner's latest grant
/// holds. Mirrors what `Vault::grant_agent_principal` stores (the grant
/// carries read here; the tiers differ in ceiling and in the credential
/// scope the caller door mirrors).
///
/// The manifest is the shipped default with rows appended, rewritten over
/// the seeded default at its id: a local write there clears the seed mark,
/// so the policy fold sees one trusted, locally written manifest (the same
/// shape `gate::live_run_claim_put_fixture::checker_vault` relies on).
///
/// # Errors
///
/// A ceiling word other than `auto` or `proposed`, a default manifest that
/// does not decode, or the store's.
pub fn install_actor_ceiling(vault: &Vault, actor: &EntityId, ceiling: &str) -> Result<()> {
    if ceiling != "auto" && ceiling != "proposed" {
        return Err(Error::InvalidClaimBody(
            "an actor ceiling is auto or proposed",
        ));
    }
    let actor_ref = actor.to_hex();
    let bytes = crate::gate::default_policy_manifest()?;
    let mut cursor = std::io::Cursor::new(bytes);
    let rmpv::Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| {
            Error::InvalidConfig("the default policy manifest failed to decode".to_owned())
        })?
    else {
        return Err(Error::InvalidConfig(
            "the default policy manifest is not a map".to_owned(),
        ));
    };
    let ceilings = entries
        .iter_mut()
        .find_map(|(key, value)| {
            (key.as_str() == Some("actor_ceilings")).then_some(value)
        })
        .ok_or(Error::InvalidConfig(
            "the default policy manifest has no actor ceilings".to_owned(),
        ))?;
    let rmpv::Value::Array(rows) = ceilings else {
        return Err(Error::InvalidConfig(
            "the default policy actor ceilings are not an array".to_owned(),
        ));
    };
    rows.retain(|row| {
        let field = |key: &str| {
            row.as_map().and_then(|fields| {
                fields
                    .iter()
                    .find(|(name, _)| name.as_str() == Some(key))
                    .and_then(|(_, value)| value.as_str())
            })
        };
        field("actor_class") != Some("agent") || field("actor_ref") != Some(actor_ref.as_str())
    });
    rows.push(rmpv::Value::Map(vec![
        (rmpv::Value::from("actor_class"), rmpv::Value::from("agent")),
        (
            rmpv::Value::from("actor_ref"),
            rmpv::Value::from(actor_ref.clone()),
        ),
        (rmpv::Value::from("ceiling"), rmpv::Value::from(ceiling)),
    ]));
    let grant = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("actor_ref"),
            rmpv::Value::from(actor_ref),
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
    ]);
    match entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("scoped_grants"))
    {
        Some((_, rmpv::Value::Array(rows))) => rows.push(grant),
        _ => entries.push((
            rmpv::Value::from("scoped_grants"),
            rmpv::Value::Array(vec![grant]),
        )),
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &rmpv::Value::Map(entries)).map_err(|_| {
        Error::InvalidConfig("the actor ceiling manifest failed to encode".to_owned())
    })?;
    crate::test_support::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &data,
    )
}

/// The finished run's answer: the step-0 observation text as its replay
/// record holds it, which is what `execute_code` releases to its caller.
/// Reads the committed record from the vault, never the run's own response.
///
/// # Errors
///
/// A missing replay record or observation, or the store's.
pub fn finish_text(vault: &Vault, run_id: &EntityId) -> Result<String> {
    let record = vault
        .get_code_run_replay_record(run_id)?
        .ok_or(Error::CorruptedIndex("the run has no replay record"))?;
    let path = crate::engine_executor::observation_output_path(0);
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == path)
        .ok_or(Error::CorruptedIndex("the run has no step-0 observation"))?;
    let storage = crate::code_run::ExecutorStorage::Canonical(vault);
    let raw = storage
        .get_code_run_raw_output(output)?
        .ok_or(Error::CorruptedIndex(
            "the run has no step-0 observation bytes",
        ))?;
    String::from_utf8(raw)
        .map_err(|_| Error::InvalidClaimBody("executor replay output is not utf8"))
}
