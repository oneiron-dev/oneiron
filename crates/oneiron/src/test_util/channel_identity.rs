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
