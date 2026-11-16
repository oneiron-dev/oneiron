//! A context pack renders another entity's alias (its id or identity key) as
//! that entity's name at its first mention. The name, set beside the words
//! around the alias, must not finish a secret that no read of either string
//! saw (ARCH-0069 #readers-followups-open, "An alias that names a second
//! entity"; census L6-30): such a text keeps the alias as its short id.
//!
//! Here an ASSET's headline holds six words of a recovery phrase and then a
//! PERSON's identity key, and that PERSON's name holds the other six. Each
//! stored string reads clean; the joined render would be the whole phrase.
//! An ordinary second entity still renders by name.
//!
//! Public crate surface only: a hand-built `ContextPack` through
//! `serialize::serialize_pack`, no vault.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test context_pack_second_entity_alias_release`.

use std::collections::HashMap;

use oneiron::EntityId;
use oneiron::context_pack::{
    ContextEntity, ContextPack, FieldProfile, PackFormat, PackItemAccounting, PackStats,
    PackTokenStats, TokenAllocation,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::serialize::{SerializeConfig, serialize_pack};
use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The six words the headline ends with, before the PERSON's identity key.
const HEADLINE_WORDS: &str = "legal winner thank year wave sausage";
/// The PERSON's name: the phrase's other six words.
const PERSON_NAME: &str = "worth useful legal winner thank yellow";
/// The PERSON's identity key, as the headline mentions it.
const PERSON_KEY: &str = "zq9";

const FORMATS: [PackFormat; 5] = [
    PackFormat::Json,
    PackFormat::Yaml,
    PackFormat::Toon,
    PackFormat::Markdown,
    PackFormat::Plaintext,
];

fn entity(
    id: EntityId,
    short_id: &str,
    entity_type: u8,
    fields: &[(&str, String)],
) -> ContextEntity {
    ContextEntity {
        id,
        short_id: short_id.to_owned(),
        content_hash: 0x01,
        source_revision_ref: None,
        entity_type,
        score: 0.5,
        critical: false,
        fields: Some(
            fields
                .iter()
                .map(|(key, value)| ((*key).to_owned(), Value::String(value.clone())))
                .collect::<HashMap<_, _>>(),
        ),
        edges: None,
        vector: None,
    }
}

fn empty_stats() -> PackStats {
    PackStats {
        candidates_considered: 0,
        signals_used: Vec::new(),
        query_time_us: 0,
        entities_hydrated: 0,
        neighbors_hydrated: 0,
        cosine_ghosts_dampened: 0,
        claims_suppressed: 0,
        tokens: PackTokenStats::default(),
        items_truncated: PackItemAccounting::item_budget(),
        items_dropped: PackItemAccounting::token_budget(),
        critical_over_budget: false,
        critical_count: 0,
        deadline_exceeded: false,
    }
}

fn config(format: PackFormat) -> SerializeConfig {
    SerializeConfig {
        format,
        profile: FieldProfile::Full,
        budget: 0,
        allocation: TokenAllocation::default(),
        include_stats: false,
        // Results before neighbours: the headline is the alias's first mention.
        merge_neighbors: false,
        max_field_chars: 500,
        max_item_tokens: 0,
    }
}

#[test]
fn another_entitys_name_never_finishes_a_secret_beside_its_alias() -> TestResult {
    let asset = EntityId::from_bytes([0xa5; 16])?;
    let person = EntityId::from_bytes([0xb6; 16])?;
    let alice = EntityId::from_bytes([0xc7; 16])?;
    let headline = format!("{HEADLINE_WORDS} {PERSON_KEY}");
    let pack = ContextPack {
        capabilities: Vec::new(),
        l2_base: None,
        retrieval_quality: Default::default(),
        results: vec![entity(
            asset,
            "as01",
            ENTITY_TYPE_ASSET,
            &[
                ("headline", headline),
                ("name", "Shared notes".to_owned()),
                ("owner", alice.to_hex()),
            ],
        )],
        neighbors: vec![
            entity(
                person,
                "pe01",
                ENTITY_TYPE_PERSON,
                &[
                    ("name", PERSON_NAME.to_owned()),
                    ("identity_key", PERSON_KEY.to_owned()),
                ],
            ),
            entity(
                alice,
                "pe02",
                ENTITY_TYPE_PERSON,
                &[("name", "Alice".to_owned())],
            ),
        ],
        instruction_files: Vec::new(),
        stats: empty_stats(),
        empty: None,
    };

    let joined = format!("{HEADLINE_WORDS} {PERSON_NAME}");
    let mut failures = Vec::new();
    for format in FORMATS {
        let text = String::from_utf8_lossy(&serialize_pack(&pack, &config(format))).into_owned();
        if text.contains(&joined) {
            failures.push(format!(
                "{format:?}: the PERSON's name finished the phrase beside its key: {text}"
            ));
        }
        if !text.contains(&format!("{HEADLINE_WORDS} pe01")) {
            failures.push(format!(
                "{format:?}: the headline does not keep the PERSON's short id: {text}"
            ));
        }
        if !text.contains("Alice (pe02)") {
            failures.push(format!(
                "{format:?}: an ordinary second entity no longer renders by name: {text}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    Ok(())
}
