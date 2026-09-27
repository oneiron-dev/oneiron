//! Valid retired FACET bytes, used only to prove every old write/replay door refuses them.
use crate::EntityId;
use rmpv::Value;

pub(crate) fn retired_persona_facet_body(person: EntityId) -> Vec<u8> {
    let map = Value::Map(vec![
        ("schema_version".into(), 3u64.into()),
        ("kind".into(), "persona".into()),
        (
            "scope".into(),
            Value::Map(vec![("kind".into(), "neutral".into())]),
        ),
        (
            "subject".into(),
            Value::Map(vec![
                ("kind".into(), "persona".into()),
                (
                    "persona_ref".into(),
                    Value::Binary(person.as_bytes().to_vec()),
                ),
            ]),
        ),
        (
            "value".into(),
            Value::Map(vec![("tone".into(), "patient".into())]),
        ),
        (
            "provenance".into(),
            Value::Map(vec![
                (
                    "actor_ref".into(),
                    Value::Binary(person.as_bytes().to_vec()),
                ),
                ("actor_class".into(), 0u64.into()),
                ("source".into(), "user_stated".into()),
                ("approval".into(), "approved".into()),
                ("value".into(), "fixture".into()),
            ]),
        ),
        ("lifecycle".into(), "active".into()),
        ("sensitivity".into(), "public".into()),
        (
            "lifecycle_events".into(),
            Value::Array(vec![Value::Map(vec![
                ("kind".into(), "created".into()),
                ("at".into(), 1u64.into()),
            ])]),
        ),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &map).expect("retired fixture encodes");
    bytes
}
