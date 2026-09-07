use core::assert_matches;

use rmpv::Value;

use super::*;
use crate::claim::{CLAIM_SCOPE_DEMOTION_RUNG_KEY, CLAIM_SCOPE_EVIDENCE_TAINT_KEY, ClaimSource};

fn corpus(byte: u8) -> CorpusId {
    CorpusId::from_entity_id(EntityId::from_bytes([byte; ENTITY_ID_LEN]).expect("valid entity id"))
}

fn entry<'a>(scope: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Map(entries) = scope else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

fn key_order(scope: &Value) -> Vec<String> {
    let Value::Map(entries) = scope else {
        return Vec::new();
    };
    entries
        .iter()
        .map(|(key, _)| key.as_str().unwrap_or("<non-string>").to_owned())
        .collect()
}

#[test]
fn corpus_id_round_trips_through_entity_id() {
    let id = EntityId::from_bytes([0x2A; ENTITY_ID_LEN]).expect("valid entity id");

    let wrapped = CorpusId::from_entity_id(id);

    assert_eq!(wrapped.entity_id(), id);
    assert_eq!(EntityId::from(wrapped), id);
    assert_eq!(CorpusId::from(id), wrapped);
}

#[test]
fn scope_with_corpus_id_starts_a_map_when_scope_is_absent() -> Result<()> {
    let scope = scope_with_corpus_id(None, corpus(0x12))?;

    assert_eq!(
        key_order(&scope),
        vec![CLAIM_SCOPE_CORPUS_ID_KEY.to_owned()]
    );
    assert_eq!(corpus_id_from_scope(Some(&scope))?, Some(corpus(0x12)));
    Ok(())
}

/// The corpus writer owns exactly one entry. Every sibling — the engine's own
/// provenance stamps and anything this crate does not recognize — survives
/// unchanged, in order.
#[test]
fn scope_with_corpus_id_preserves_every_sibling_entry() -> Result<()> {
    let existing = Value::Map(vec![
        (Value::from("sensitivity"), Value::from("internal")),
        (
            Value::from(CLAIM_SCOPE_EVIDENCE_TAINT_KEY),
            Value::from(ClaimSource::ToolOutput.as_str()),
        ),
        (
            Value::from("federated_original_source"),
            Value::from(ClaimSource::Generated.as_str()),
        ),
        (
            Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
            Value::from("weakened"),
        ),
        (Value::from("pre_restamp_scope"), Value::from("opaque")),
        (
            Value::from("unknown_future_key"),
            Value::Array(vec![Value::from(7), Value::from("payload")]),
        ),
    ]);

    let scope = scope_with_corpus_id(Some(existing.clone()), corpus(0x33))?;

    assert_eq!(
        key_order(&scope),
        vec![
            "sensitivity".to_owned(),
            CLAIM_SCOPE_EVIDENCE_TAINT_KEY.to_owned(),
            "federated_original_source".to_owned(),
            CLAIM_SCOPE_DEMOTION_RUNG_KEY.to_owned(),
            "pre_restamp_scope".to_owned(),
            "unknown_future_key".to_owned(),
            CLAIM_SCOPE_CORPUS_ID_KEY.to_owned(),
        ],
        "the corpus entry appends; no sibling is reordered or dropped"
    );
    for key in [
        "sensitivity",
        CLAIM_SCOPE_EVIDENCE_TAINT_KEY,
        "federated_original_source",
        CLAIM_SCOPE_DEMOTION_RUNG_KEY,
        "pre_restamp_scope",
        "unknown_future_key",
    ] {
        assert_eq!(
            entry(&scope, key),
            entry(&existing, key),
            "sibling {key} must survive byte-for-byte"
        );
    }
    assert_eq!(corpus_id_from_scope(Some(&scope))?, Some(corpus(0x33)));
    Ok(())
}

/// Re-stamping is a REPLACE: a second corpus entry would decode as an
/// ambiguous duplicate, so the writer must never append one.
#[test]
fn scope_with_corpus_id_replaces_an_existing_corpus_entry() -> Result<()> {
    let first = scope_with_corpus_id(None, corpus(0x44))?;

    let second = scope_with_corpus_id(Some(first), corpus(0x55))?;

    assert_eq!(
        key_order(&second),
        vec![CLAIM_SCOPE_CORPUS_ID_KEY.to_owned()]
    );
    assert_eq!(corpus_id_from_scope(Some(&second))?, Some(corpus(0x55)));
    Ok(())
}

/// A duplicated corpus entry already on disk collapses to ONE entry on the
/// next stamp, so a rewrite repairs the ambiguity instead of preserving it.
#[test]
fn scope_with_corpus_id_collapses_a_duplicated_corpus_entry() -> Result<()> {
    let duplicated = Value::Map(vec![
        (
            Value::from(CLAIM_SCOPE_CORPUS_ID_KEY),
            Value::Binary(corpus(0x61).entity_id().as_bytes().to_vec()),
        ),
        (Value::from("sensitivity"), Value::from("internal")),
        (
            Value::from(CLAIM_SCOPE_CORPUS_ID_KEY),
            Value::Binary(corpus(0x62).entity_id().as_bytes().to_vec()),
        ),
    ]);

    let scope = scope_with_corpus_id(Some(duplicated), corpus(0x63))?;

    assert_eq!(
        key_order(&scope),
        vec![
            "sensitivity".to_owned(),
            CLAIM_SCOPE_CORPUS_ID_KEY.to_owned()
        ]
    );
    assert_eq!(corpus_id_from_scope(Some(&scope))?, Some(corpus(0x63)));
    Ok(())
}

#[test]
fn scope_with_corpus_id_rejects_a_non_map_scope() {
    assert_matches!(
        scope_with_corpus_id(Some(Value::from("opaque")), corpus(0x12)),
        Err(Error::InvalidClaimBody(_))
    );
}

/// Absence is the unscoped/core answer, never an error.
#[test]
fn corpus_id_from_scope_reads_absence_as_unscoped() -> Result<()> {
    assert_eq!(corpus_id_from_scope(None)?, None);
    assert_eq!(corpus_id_from_scope(Some(&Value::Map(Vec::new())))?, None);
    assert_eq!(
        corpus_id_from_scope(Some(&Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from("internal"),
        )])))?,
        None
    );
    // A `scope` that is not a map carries no corpus entry; the corpus
    // dimension does not redefine the shape of the surrounding map.
    assert_eq!(corpus_id_from_scope(Some(&Value::from("opaque")))?, None);
    Ok(())
}

#[test]
fn corpus_id_from_scope_fails_closed_on_malformed_entries() {
    let table: Vec<(&str, Value)> = vec![
        (
            "duplicate corpus entries",
            Value::Map(vec![
                (
                    Value::from(CLAIM_SCOPE_CORPUS_ID_KEY),
                    Value::Binary(corpus(0x12).entity_id().as_bytes().to_vec()),
                ),
                (
                    Value::from(CLAIM_SCOPE_CORPUS_ID_KEY),
                    Value::Binary(corpus(0x22).entity_id().as_bytes().to_vec()),
                ),
            ]),
        ),
        (
            "non-binary value",
            Value::Map(vec![(
                Value::from(CLAIM_SCOPE_CORPUS_ID_KEY),
                Value::from("11111111111111111111111111111111"),
            )]),
        ),
        (
            "short binary",
            Value::Map(vec![(
                Value::from(CLAIM_SCOPE_CORPUS_ID_KEY),
                Value::Binary(vec![0x11; ENTITY_ID_LEN - 1]),
            )]),
        ),
        (
            "long binary",
            Value::Map(vec![(
                Value::from(CLAIM_SCOPE_CORPUS_ID_KEY),
                Value::Binary(vec![0x11; ENTITY_ID_LEN + 1]),
            )]),
        ),
        (
            "reserved all-zero id",
            Value::Map(vec![(
                Value::from(CLAIM_SCOPE_CORPUS_ID_KEY),
                Value::Binary(vec![0x00; ENTITY_ID_LEN]),
            )]),
        ),
        (
            "reserved all-ones id",
            Value::Map(vec![(
                Value::from(CLAIM_SCOPE_CORPUS_ID_KEY),
                Value::Binary(vec![0xFF; ENTITY_ID_LEN]),
            )]),
        ),
    ];

    for (label, scope) in table {
        assert_matches!(
            corpus_id_from_scope(Some(&scope)),
            Err(Error::InvalidClaimBody(_)),
            "{label} must fail closed"
        );
    }
}

#[test]
fn canonicalize_sorts_and_dedups_any_of() -> Result<()> {
    let scope = CorpusScope::AnyOf(vec![corpus(0x33), corpus(0x12), corpus(0x33), corpus(0x22)])
        .canonicalize()?;

    assert_eq!(
        scope,
        CorpusScope::AnyOf(vec![corpus(0x12), corpus(0x22), corpus(0x33)])
    );
    Ok(())
}

/// Naming zero corpora is a caller error, not a silent alias for
/// [`CorpusScope::Unscoped`].
#[test]
fn canonicalize_rejects_an_empty_any_of() {
    assert_matches!(
        CorpusScope::AnyOf(Vec::new()).canonicalize(),
        Err(Error::InvalidConfig(_))
    );
}

#[test]
fn canonicalize_leaves_the_other_scopes_untouched() -> Result<()> {
    assert_eq!(CorpusScope::All.canonicalize()?, CorpusScope::All);
    assert_eq!(CorpusScope::Unscoped.canonicalize()?, CorpusScope::Unscoped);
    assert_eq!(
        CorpusScope::Corpus(corpus(0x12)).canonicalize()?,
        CorpusScope::Corpus(corpus(0x12))
    );
    Ok(())
}

#[test]
fn corpus_scope_default_is_all() {
    assert_eq!(CorpusScope::default(), CorpusScope::All);
}

/// The full truth table. `None` covers both an unscoped claim and every
/// non-CLAIM entity, which is why non-claims pass every scope.
#[test]
fn corpus_scope_matches_truth_table() {
    let a = corpus(0x12);
    let b = corpus(0x22);
    let c = corpus(0x33);
    let table = [
        (CorpusScope::All, None, true),
        (CorpusScope::All, Some(a), true),
        (CorpusScope::All, Some(c), true),
        (CorpusScope::Unscoped, None, true),
        (CorpusScope::Unscoped, Some(a), false),
        (CorpusScope::Corpus(a), None, true),
        (CorpusScope::Corpus(a), Some(a), true),
        (CorpusScope::Corpus(a), Some(b), false),
        (CorpusScope::AnyOf(vec![a, b]), None, true),
        (CorpusScope::AnyOf(vec![a, b]), Some(a), true),
        (CorpusScope::AnyOf(vec![a, b]), Some(b), true),
        (CorpusScope::AnyOf(vec![a, b]), Some(c), false),
    ];

    for (scope, claim_scope, expected) in table {
        assert_eq!(
            scope.matches(claim_scope),
            expected,
            "{scope:?} against {claim_scope:?}"
        );
    }
}
