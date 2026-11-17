//! A browser or desktop answer's typed manifest keeps the guest's pressure
//! (FIX [BROWSER-ANSWER-MIRROR-NO-GUEST-PRESSURE]): the run's door copies the
//! container's own session manifest into every answer, and since FIX 8013
//! that manifest names the pressure the guest showed before its container
//! went away. `SessionManifest` is the typed mirror of that manifest, and the
//! SDK answer types are generated from it, so a program that reads the answer
//! typed must read back the pressure the container wrote.
#![cfg(feature = "driver")]

use oneiron_browser::SessionManifest;
use oneiron_container::GuestPressure;
use serde_json::{Value, json};

const HITS: u64 = 5;
const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const IMAGE: &str = concat!(
    "example.invalid/guest@sha256:",
    "0000000000000000000000000000000000000000000000000000000000000000",
);

/// The manifest as the door sends it: the container's own type, encoded.
fn wire_manifest(pressure: Option<GuestPressure>) -> Value {
    let mut manifest: oneiron_container::SessionManifest = serde_json::from_value(json!({
        "backend": "docker",
        "runtime": "runc",
        "image": IMAGE,
        "argv_digest": DIGEST,
        "network": "relay",
        "seccomp": "guest_sandbox",
        "generation": "g1",
        "fence_unproven": true,
    }))
    .expect("the container decodes its own manifest");
    manifest.guest_pressure = pressure;
    serde_json::to_value(&manifest).expect("the container encodes its manifest")
}

/// The wire manifest read through the typed mirror and written again.
fn typed_round_trip(wire: &Value) -> Value {
    let typed: SessionManifest =
        serde_json::from_value(wire.clone()).expect("the mirror decodes the container's manifest");
    serde_json::to_value(&typed).expect("the mirror encodes the manifest")
}

#[test]
fn a_typed_manifest_keeps_the_pressure_the_container_wrote() {
    let wire = wire_manifest(Some(GuestPressure::Processes { hits: HITS }));
    let pressure = json!({ "processes": { "hits": HITS } });
    assert_eq!(wire["guest_pressure"], pressure, "wire manifest: {wire}");

    let typed = typed_round_trip(&wire);
    assert_eq!(
        typed["guest_pressure"], pressure,
        "the typed manifest dropped the guest's pressure: {typed}"
    );
    assert_eq!(typed, wire);
}

#[test]
fn a_manifest_without_pressure_writes_no_pressure_key() {
    let wire = wire_manifest(None);
    assert!(
        wire.get("guest_pressure").is_none(),
        "wire manifest: {wire}"
    );

    let typed = typed_round_trip(&wire);
    assert!(
        typed.get("guest_pressure").is_none(),
        "typed manifest: {typed}"
    );
    assert_eq!(typed, wire);
}

#[test]
fn the_manifest_schema_names_the_guest_pressure() {
    let schema = serde_json::to_value(schemars::schema_for!(SessionManifest))
        .expect("the manifest schema encodes");
    assert!(
        schema["properties"]["guest_pressure"].is_object(),
        "the manifest schema has no guest_pressure property: {}",
        schema["properties"]
    );
}
