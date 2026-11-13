//! The residence RPC lane's hello lists the codecs only, not the sealed
//! world-update frame kind (FIX RESIDENCE-RPC-HELLO-TAKES-SEALED-OFFER).
//!
//! Every hello listed `frame_kind_ids::SEALED_WORLD_UPDATES`, the RPC lane's
//! v12 hello too. At connect the home offers a proven machine of the owner's
//! its sealed-update queue when the socket's hello lists that kind, and the
//! offer goes out before the bind reply. The lane's opening loop refuses any
//! frame it does not expect, so every residence index fetch of a joined
//! device failed "opened-item RPC unavailable" about 10 ms after the lane
//! opened (E2E job 18, SYNC-01's device peer).
//!
//! `cargo test --locked -p oneiron --all-features --test residence_rpc_hello`.
#![cfg(feature = "sync")]
#![allow(clippy::expect_used)]

use oneiron::sync::transport;

#[test]
fn the_residence_rpc_hello_lists_no_sealed_world_updates() {
    let hello = transport::encode_residence_protocol_hello();
    assert_eq!(
        transport::decode_protocol_hello(&hello).expect("the RPC lane's hello decodes"),
        transport::RESIDENCE_PROTOCOL_VERSION,
    );
    let codecs = transport::decode_protocol_hello_codecs(&hello).expect("its codecs decode");
    assert!(codecs.decodes_zstd(), "the RPC lane lists zstd: {hello:?}");
    assert!(
        !codecs.decodes_sealed_world_updates(),
        "the RPC lane decodes no sealed world-update frame: {hello:?}"
    );
}

#[test]
fn the_residence_sync_hello_still_lists_sealed_world_updates() {
    let hello = transport::encode_replacement_residence_protocol_hello();
    let codecs = transport::decode_protocol_hello_codecs(&hello).expect("its codecs decode");
    assert!(
        codecs.decodes_zstd(),
        "the sync socket lists zstd: {hello:?}"
    );
    assert!(
        codecs.decodes_sealed_world_updates(),
        "the sync socket still takes the home's sealed updates: {hello:?}"
    );
}
