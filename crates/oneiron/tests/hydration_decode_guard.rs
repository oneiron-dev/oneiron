//! Census L6-30b (ARCH-0069 #readers-followups-open: "an isolating check for
//! hydration's decode guard"): hydration's decode of one entity body, called
//! alone through its test door, with no write-door check or serializer in
//! front of it.
//!
//! A body that reads as a secret only whole gives no field: here a recovery
//! phrase split over a map's one key and its value. Neither part reads as a
//! secret alone (six words each); their text joined, one leaf per line, reads
//! as the twelve-word phrase. A clean body, and either half alone, give their
//! fields. Both hold whether or not the write door's scan has accepted the
//! bytes (`write_accepted`), since the joined leaves are read either way.
//!
//! The door is compiled only under the test command's
//! `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::hydration_decode_guard::decode_entity_fields;
use rmpv::Value;

/// The public BIP39 test vector's first six words.
const PHRASE_HEAD: &str = "legal winner thank year wave sausage";
/// Its last six words: with the first six, the whole twelve-word phrase.
const PHRASE_TAIL: &str = "worth useful legal winner thank yellow";

fn encode(value: &Value) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, value).expect("encode fixture");
    body
}

fn map(entries: &[(&str, &str)]) -> Vec<u8> {
    encode(&Value::Map(
        entries
            .iter()
            .map(|(key, value)| (Value::from(*key), Value::from(*value)))
            .collect(),
    ))
}

#[test]
fn a_clean_body_and_each_phrase_half_alone_give_their_fields() {
    let clean = map(&[("title", "Lunch with Owen"), ("place", "Kyoto station")]);
    let head_alone = map(&[("note", PHRASE_HEAD)]);
    let tail_alone = map(&[("note", PHRASE_TAIL)]);
    for write_accepted in [false, true] {
        let fields = decode_entity_fields(&clean, write_accepted)
            .expect("a MessagePack map decodes to fields");
        assert_eq!(
            fields.get("title").and_then(serde_json::Value::as_str),
            Some("Lunch with Owen"),
            "write_accepted {write_accepted}: a clean body gives its title",
        );
        assert_eq!(
            fields.get("place").and_then(serde_json::Value::as_str),
            Some("Kyoto station"),
            "write_accepted {write_accepted}: a clean body gives its place",
        );
        for (half, body) in [(PHRASE_HEAD, &head_alone), (PHRASE_TAIL, &tail_alone)] {
            let fields = decode_entity_fields(body, write_accepted)
                .expect("a MessagePack map decodes to fields");
            assert_eq!(
                fields.get("note").and_then(serde_json::Value::as_str),
                Some(half),
                "write_accepted {write_accepted}: six list words alone are no phrase",
            );
        }
    }
}

#[test]
fn a_body_that_reads_as_a_phrase_only_whole_gives_no_field() {
    let split = map(&[(PHRASE_HEAD, PHRASE_TAIL)]);
    for write_accepted in [false, true] {
        let fields = decode_entity_fields(&split, write_accepted)
            .expect("the guard answers an empty field map, not a decode failure");
        assert!(
            fields.is_empty(),
            "write_accepted {write_accepted}: a phrase split over a key and its value \
             hydrates no field, got keys {:?}",
            fields.keys().map(String::len).collect::<Vec<_>>(),
        );
    }
}
