//! The residence RPC lane is no custody carrier leaf-key lane (FIX 11785,
//! FIX RESIDENCE-RPC-HELLO-TAKES-SEALED-OFFER).
//!
//! The home registers each live socket of a proven machine as a leaf-key
//! lane, and routes requests and its own pending ones to the machine's newest
//! socket. The RPC lane opens after the sync socket, so it was the newest, yet
//! it reads RPC frames alone: a leaf-key frame sent there ends its next call.
//! A v12 hello opens only that lane now, so the home registers a socket only
//! where `carries_leaf_keys` holds for its hello's version
//! (oneiron-server handler/connection/run/replication.rs).
//!
//! `cargo test --locked -p oneiron --all-features --test residence_rpc_leaf_key_lane`.
#![cfg(feature = "sync")]
#![allow(clippy::expect_used)]

use oneiron::sync::transport;

fn hello_version(hello: &[u8]) -> u8 {
    transport::decode_protocol_hello(hello).expect("a hello decodes")
}

#[test]
fn the_residence_rpc_lane_alone_carries_no_leaf_keys() {
    assert!(
        !transport::carries_leaf_keys(hello_version(&transport::encode_residence_protocol_hello())),
        "the residence RPC lane is no leaf-key lane"
    );
    for (socket, hello) in [
        (
            "residence sync",
            transport::encode_replacement_residence_protocol_hello(),
        ),
        (
            "owner full-window",
            transport::encode_replacement_full_window_protocol_hello(),
        ),
        (
            "owner chunk full-window",
            transport::encode_chunk_full_window_protocol_hello(),
        ),
        (
            "legacy full-window",
            transport::encode_legacy_full_window_protocol_hello(),
        ),
        ("selector", transport::encode_protocol_hello()),
    ] {
        assert!(
            transport::carries_leaf_keys(hello_version(&hello)),
            "the {socket} socket stays a leaf-key lane"
        );
    }
}
