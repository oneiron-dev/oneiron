//! Fix list row 15412, slice 3b: a federation peer's conversational TURN
//! speaks as a counterparty here. The peer's person and assistant are neither
//! this vault's own person nor its own companion: each speaker alias this
//! vault reads as its own user or assistant becomes `counterparty`, the
//! original kept inert as `import_speaker` and the peer's `actor` byline as
//! `import_actor`. A stamp the peer named itself does not skip this.
//!
//! Red on the PR's base (slice 3a): the admission only stamps the federation
//! import source, and returns a TURN that names its own source as it came.
//!
//! Reaches the crate-private admission through the test door
//! `oneiron::test_doors::guest_turn_counterparty`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test guest_turn_counterparty`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::test_doors::guest_turn_counterparty::admitted_peer_turn_body;
use oneiron::{EntityId, Vault, VaultConfig};
use rmpv::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AT: u64 = 1_800_000_000;

/// Any error the engine answers, boxed by its debug text.
fn boxed<E: std::fmt::Debug>(error: E) -> Box<dyn std::error::Error> {
    format!("{error:?}").into()
}

/// A peer TURN body: the peer's own user speaking, with its byline, and the
/// extra entries `extra`.
fn peer_turn(actor: EntityId, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut entries = vec![
        (Value::from("speaker"), Value::from("user")),
        (Value::from("spkr"), Value::from("user")),
        (Value::from("text"), Value::from("Lunch at noon?")),
        (Value::from("actor"), Value::from(actor.to_hex())),
    ];
    for (key, value) in extra {
        entries.push((Value::from(*key), Value::from(*value)));
    }
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &Value::Map(entries)).expect("encode a TURN body");
    body
}

/// The admitted body's entries, by key.
fn entries(body: &[u8]) -> Vec<(String, Value)> {
    let value = rmpv::decode::read_value(&mut &body[..]).expect("an admitted body decodes");
    value
        .as_map()
        .expect("an admitted TURN body is a map")
        .iter()
        .map(|(key, value)| {
            (
                key.as_str().expect("a string key").to_owned(),
                value.clone(),
            )
        })
        .collect()
}

fn field<'a>(entries: &'a [(String, Value)], key: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|(name, _)| name == key)
        .and_then(|(_, value)| value.as_str())
}

fn assert_speaks_as_counterparty(body: &[u8], actor: EntityId) {
    let entries = entries(body);
    assert_eq!(
        field(&entries, "speaker"),
        Some("counterparty"),
        "{entries:?}"
    );
    assert_eq!(field(&entries, "spkr"), Some("counterparty"), "{entries:?}");
    assert_eq!(
        field(&entries, "import_speaker"),
        Some("user"),
        "{entries:?}"
    );
    let byline = actor.to_hex();
    assert_eq!(
        field(&entries, "import_actor"),
        Some(byline.as_str()),
        "{entries:?}"
    );
    assert_eq!(field(&entries, "actor"), None, "{entries:?}");
}

#[test]
fn guest_turn_lands_counterparty() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault =
        Vault::open_unseeded_for_test(directory.path(), VaultConfig::default()).map_err(boxed)?;
    let actor = EntityId::now();
    let body = admitted_peer_turn_body(&vault, &peer_turn(actor, &[]), AT).map_err(boxed)?;
    assert_speaks_as_counterparty(&body, actor);
    assert_eq!(field(&entries(&body), "import_source"), Some("federation"));
    Ok(())
}

#[test]
fn guest_turn_with_its_own_import_stamp_still_lands_counterparty() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault =
        Vault::open_unseeded_for_test(directory.path(), VaultConfig::default()).map_err(boxed)?;
    let actor = EntityId::now();
    let body = admitted_peer_turn_body(
        &vault,
        &peer_turn(actor, &[("import_source", "chatgpt")]),
        AT,
    )
    .map_err(boxed)?;
    assert_speaks_as_counterparty(&body, actor);
    assert_eq!(field(&entries(&body), "import_source"), Some("chatgpt"));
    Ok(())
}
