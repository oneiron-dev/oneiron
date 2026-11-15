//! The policy a rung-2 first send meets in `tests/booking_rung2_thread.rs`
//! (INBOX-RESIDUE PR-3b-2): the native-mail recipient policy, whose cold
//! class holds a first send to a stranger for the owner's one-send press, and
//! an auto ceiling for the page's agent, so that press is all the send waits
//! on.
use crate::{EntityId, Error, Result, Vault};

/// Loads the vault's policy manifest that holds `agent`'s native-mail send to
/// a stranger for the owner's press: the default recipient policy row, the
/// agent's auto ceiling, and the self-held sender posture a loaded manifest
/// must spell (ONE-1970).
///
/// # Errors
///
/// The manifest does not encode or write.
pub fn hold_cold_mail_for_owner_press(vault: &Vault, agent: EntityId) -> Result<()> {
    let v = rmpv::Value::from;
    let manifest = rmpv::Value::Map(vec![
        (v("schema_version"), v("1.2")),
        (
            v("native_mail_policy"),
            rmpv::Value::Array(vec![crate::gate::mail_policy::default_row()]),
        ),
        (v("pack_id"), v("booking-rung2-thread")),
        (v("pack_version"), v("v1")),
        (v("min_engine_version"), v(env!("CARGO_PKG_VERSION"))),
        (
            v("defaults"),
            rmpv::Value::Map(vec![
                (v("criticality"), v("normal")),
                (v("sensitivity"), v("normal")),
            ]),
        ),
        (v("rules"), rmpv::Value::Array(vec![])),
        (
            v("actor_ceilings"),
            rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                (v("actor_class"), v("agent")),
                (v("actor_ref"), rmpv::Value::from(agent.to_hex())),
                (v("ceiling"), v("auto")),
            ])]),
        ),
        (v("scoped_grants"), rmpv::Value::Array(vec![])),
        (
            v("act_policy"),
            rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                (v("act_class"), v("channel_identity.outbound_send")),
                (v("subject_class"), v("self_held")),
                (v("posture"), v("require_capability")),
            ])]),
        ),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest).map_err(|_| {
        Error::InvalidConfig("the rung-2 policy manifest did not encode".to_owned())
    })?;
    crate::test_fixtures::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}
