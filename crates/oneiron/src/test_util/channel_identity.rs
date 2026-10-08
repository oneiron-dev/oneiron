//! Self-held ChannelIdentity fixtures: a row in a chosen state, reached by
//! walking its machine.

/// A self-held ChannelIdentity row standing in `state`, reached by WALKING
/// its machine from `Requested`.
///
/// Centralized because after ONE-1970 a row's state is not assignable: the
/// obvious `identity.state = Active` no longer compiles, and every module
/// whose fixture needs a live (or retiring, or closed) identity would
/// otherwise grow its own copy of the same three-to-five step walk. The
/// payload each state carries rides on the act that decides it, so this
/// helper picks the API lane and the minimum quarantine window; a test that
/// cares about a different lane or window steps the row itself.
///
/// # Panics
///
/// When a step is refused, which for a self-held row means the walk itself
/// is wrong rather than the caller's input.
pub(crate) fn self_held_identity_in_state(
    channel: &str,
    address_or_handle: &str,
    shape: crate::channel_identity::SelfHeldShape,
    binding: crate::channel_identity::ChannelIdentityBinding,
    state: crate::channel_identity::ChannelIdentityState,
    at: u64,
) -> crate::channel_identity::ChannelIdentity {
    use crate::channel_identity::{
        ChannelIdentity, ChannelIdentityFulfillment, ChannelIdentityState, ChannelIdentityStep,
        DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS,
    };

    let mut row = ChannelIdentity::requested(channel, address_or_handle, shape, binding, at);
    let walk: &[ChannelIdentityStep] = match state {
        ChannelIdentityState::Requested => &[],
        ChannelIdentityState::PendingFulfillment => {
            &[ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api)]
        }
        ChannelIdentityState::Active => &[
            ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
            ChannelIdentityStep::Fulfill,
        ],
        ChannelIdentityState::Rotating => &[
            ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
            ChannelIdentityStep::Fulfill,
            ChannelIdentityStep::Rotate,
        ],
        ChannelIdentityState::Released => &[
            ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
            ChannelIdentityStep::Fulfill,
            ChannelIdentityStep::Release,
        ],
        ChannelIdentityState::Quarantine => &[
            ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
            ChannelIdentityStep::Fulfill,
            ChannelIdentityStep::Release,
            ChannelIdentityStep::Quarantine {
                until: at + DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS,
            },
        ],
        ChannelIdentityState::Tombstone => &[
            ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
            ChannelIdentityStep::Fulfill,
            ChannelIdentityStep::Release,
            ChannelIdentityStep::Quarantine {
                until: at + DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS,
            },
            ChannelIdentityStep::Close,
        ],
    };
    for step in walk {
        row = row.step(*step, at).expect("self-held lifecycle walk");
    }
    row
}

/// A native-mail sender bound to agent `holder`, under a policy whose row for
/// `holder` knows a recipient only by the first touches in `known`: a
/// native-mail send to anyone else is held as cold.
pub(crate) fn put_native_mail_sender(
    vault: &crate::Vault,
    id: crate::EntityId,
    holder: crate::EntityId,
    known: &[crate::counterparty_contact::CounterpartyFirstTouch],
) -> crate::Result<()> {
    use rmpv::Value;
    let identity = self_held_identity_in_state(
        "email",
        &format!("mail-{}@mail.example.com", id.to_hex()),
        crate::channel_identity::SelfHeldShape::DedicatedAddress,
        crate::channel_identity::ChannelIdentityBinding::agent(holder),
        crate::channel_identity::ChannelIdentityState::Active,
        1,
    );
    vault.create_channel_identity(&id, &identity)?;
    let mut row = crate::gate::mail_policy::default_row();
    let Value::Map(axes) = &mut row else {
        unreachable!("a policy row is a map")
    };
    for (key, value) in axes {
        match key.as_str() {
            Some("scope") => *value = Value::from("holder"),
            Some("holder") => *value = Value::from(holder.to_hex()),
            Some("known_first_touch") => {
                *value = Value::Array(
                    known
                        .iter()
                        .map(|touch| Value::from(touch.as_str()))
                        .collect(),
                );
            }
            _ => {}
        }
    }
    let manifest = crate::gate::default_policy_manifest()?;
    let Ok(Value::Map(mut entries)) = rmpv::decode::read_value(&mut manifest.as_slice()) else {
        unreachable!("the default manifest is a map")
    };
    entries.retain(|(key, _)| key.as_str() != Some("native_mail_policy"));
    entries.push((
        Value::from("native_mail_policy"),
        Value::Array(vec![crate::gate::mail_policy::default_row(), row]),
    ));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries))
        .map_err(|error| crate::Error::InvalidConfig(error.to_string()))?;
    super::put_policy_manifest_bytes(vault, crate::gate::default_policy_manifest_id()?, &bytes)
}
