//! Shared fixture helpers for `oneiron` integration tests.
//!
//! Integration binaries cannot see the crate-internal `test_util` module, so
//! the pinned-byte deny-list and the canonical seed helper are mirrored here
//! against the public API. Canonical copy: `src/lib.rs::test_util` — keep the
//! two in sync.
#![allow(dead_code)] // each integration binary uses a subset of these helpers

/// Test-only-file classification for the source-scanning fences. One file,
/// mounted here and as `crate::test_util::source_scan`, so unit and
/// integration fences agree on what counts as test code.
#[path = "../../src/test_util/source_scan.rs"]
pub(crate) mod source_scan;

use oneiron::EntityId;

/// Mirror of `test_util::PINNED_ID_BYTES`; see the canonical doc comment.
pub(crate) const PINNED_ID_BYTES: [u8; 13] = [
    0x00, 0x11, 0x42, 0x47, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xD7, 0xE1, 0xFF,
];

/// Canonical test entity id: `[seed; 16]`. Panics on production-pinned seeds,
/// including `entity(0)`. See `test_util::entity` for the full contract.
pub(crate) fn entity(seed: u8) -> EntityId {
    assert!(
        !PINNED_ID_BYTES.contains(&seed),
        "test seed {seed:#04x} collides with a production-pinned id byte; \
         pick a byte outside PINNED_ID_BYTES or construct the pinned id explicitly"
    );
    EntityId::from_bytes([seed; 16]).expect("non-pinned seed byte forms a valid entity id")
}

/// Mirror of `test_util::provision_engine_machines`: roots the vault under a
/// test host and provisions the engine's MACHINE writers with host-held keys,
/// as a host does at bootstrap (ONE-1634).
pub(crate) fn provision_engine_machines(vault: &oneiron::Vault) {
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(b"oneiron integration test host")
        .expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
}

/// Mirror of `test_util::self_held_identity_in_state`; see the canonical doc
/// comment. A row's state is not assignable after ONE-1970, so an integration
/// fixture that needs a live identity walks the machine here.
pub(crate) fn self_held_identity_in_state(
    channel: &str,
    address_or_handle: &str,
    shape: oneiron::channel_identity::SelfHeldShape,
    binding: oneiron::channel_identity::ChannelIdentityBinding,
    state: oneiron::channel_identity::ChannelIdentityState,
    at: u64,
) -> oneiron::channel_identity::ChannelIdentity {
    use oneiron::channel_identity::{
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
        // `ChannelIdentityState` is `#[non_exhaustive]`, so an out-of-crate
        // match needs this arm even though the crate-internal twin does not.
        _ => panic!("unhandled channel identity state {state:?}"),
    };
    for step in walk {
        row = row.step(*step, at).expect("self-held lifecycle walk");
    }
    row
}
