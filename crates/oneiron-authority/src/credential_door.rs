//! Credential-door bounds the authority log's slip checks share with the door itself. The
//! door stays in `oneiron::credential_door`, which re-exports these. Public so both crates
//! apply one bound; constants and a name predicate only.

/// The hard ceiling on a one-shot credential's lifetime, in seconds.
pub const DOOR_ONE_SHOT_MAX_LIFETIME_SECS: u64 = 300;

/// Floor names, lowercased. A policy row, verb, record, or channel that names
/// one of these is trying to reach a floor from inside the lattice.
const DOOR_FLOOR_NAMES: [&str; 3] = [
    "door_scan_always_on",
    "door_max_lease_ttl_secs",
    "door_one_shot_max_lifetime_secs",
];

/// Reserved policy-key prefixes, lowercased: the floor namespace and the scan
/// namespace are not dial space.
const DOOR_FLOOR_KEY_PREFIXES: [&str; 2] = ["secret.door.floor.", "secret.door.scan"];

/// True when `token` names a catastrophe floor.
pub fn names_a_floor(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    let mut names = DOOR_FLOOR_NAMES.iter();
    let mut prefixes = DOOR_FLOOR_KEY_PREFIXES.iter();
    names.any(|name| lower.contains(name)) || prefixes.any(|p| lower.starts_with(p))
}
