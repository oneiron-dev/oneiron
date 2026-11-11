//! LABEL-04 (ARCH-0038 #promise-label-04; owner ruling G04 binary = C2,
//! ARCH-0069 #binary-secrets): a recovery phrase split over a file's parts,
//! one word per item, is masked on write like any file key. The write lands,
//! one custody record holds the phrase, the stored bytes stay the owner's,
//! and a masked reader is served each word overwritten.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON, ENTITY_TYPE_SECRET_CUSTODY};
use oneiron::secret_custody::SecretSight;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The public BIP39 test vector, as a recovery phrase's words.
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// A vault with the owner's scan switch at its default (on), a device
/// keystore, and its embedded owner.
fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_embedded_owner_actor()?;
    Ok((dir, vault))
}

fn put_asset(vault: &Vault, body: &[u8]) -> oneiron::Result<EntityId> {
    put(vault, ENTITY_TYPE_ASSET, body)
}

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> oneiron::Result<EntityId> {
    let id = EntityId::now();
    vault
        .batch()
        .put(&id, entity_type, TimeRange { start: 1, end: 1 }, 1, body)
        .commit()?;
    Ok(id)
}

/// Whether `bytes` carry a custody handle (`sc` plus digits), as mask on
/// write leaves it where the secret was.
fn carries_handle(bytes: &[u8]) -> bool {
    bytes
        .windows(3)
        .any(|window| window[0] == b's' && window[1] == b'c' && window[2].is_ascii_digit())
}

fn encode(value: &rmpv::Value) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, value).expect("encode fixture");
    body
}

/// The LABEL-04 bodies the door refuses today, and the two it lands with a
/// whole-phrase span: the phrase one word per item as MessagePack binary,
/// byte values, the two mixed, byte values each in an array of its own, the
/// phrase's byte values after a line break, a word per 64-bit number (each
/// bare and under a map key), and JSON byte values under a key.
fn bodies() -> Vec<(String, Vec<u8>)> {
    let words: Vec<&[u8]> = PHRASE.split(' ').map(str::as_bytes).collect();
    let binary = |word: &[u8]| rmpv::Value::Binary(word.to_vec());
    let numbers =
        |word: &[u8]| rmpv::Value::Array(word.iter().map(|&b| rmpv::Value::from(b)).collect());
    let padded = |word: &[u8]| {
        let mut padded = [b' '; 8];
        padded[..word.len()].copy_from_slice(word);
        u64::from_be_bytes(padded)
    };
    let items: [(&str, Vec<rmpv::Value>); 6] = [
        ("binary", words.iter().map(|word| binary(word)).collect()),
        (
            "byte values",
            words.iter().map(|word| numbers(word)).collect(),
        ),
        (
            "mixed",
            words
                .iter()
                .enumerate()
                .map(|(at, word)| if at == 6 { numbers(word) } else { binary(word) })
                .collect(),
        ),
        (
            "wrapped byte values",
            words
                .iter()
                .map(|word| rmpv::Value::Array(vec![numbers(word)]))
                .collect(),
        ),
        (
            "line break then byte values",
            std::iter::once(rmpv::Value::from("\n"))
                .chain(PHRASE.bytes().map(rmpv::Value::from))
                .collect(),
        ),
        (
            "64-bit numbers",
            words
                .iter()
                .map(|word| rmpv::Value::from(padded(word)))
                .collect(),
        ),
    ];
    let mut bodies = Vec::new();
    for (name, items) in &items {
        let value = rmpv::Value::Array(items.clone());
        bodies.push((format!("MessagePack {name}"), encode(&value)));
        let field = rmpv::Value::Map(vec![("notes:".into(), value)]);
        bodies.push((format!("MessagePack {name} under a key"), encode(&field)));
    }
    bodies.push((
        "JSON byte values under a key".to_owned(),
        serde_json::to_vec(&serde_json::json!({ "words": words })).expect("encode JSON fixture"),
    ));
    bodies
}

/// Whether `bytes` still carry a word of [`PHRASE`] ([`carries_a_word_of`]).
fn carries_a_word(bytes: &[u8]) -> bool {
    carries_a_word_of(bytes, PHRASE)
}

/// Whether `bytes` still carry a word of `phrase`, read as the release
/// doors read text: its lossy text, and each string, binary or extension
/// value and array of byte values a JSON or MessagePack decode of it holds.
fn carries_a_word_of(bytes: &[u8], phrase: &str) -> bool {
    fn texts(value: &rmpv::Value, out: &mut String) {
        use rmpv::Value as M;
        match value {
            M::String(text) => out.push_str(&String::from_utf8_lossy(text.as_bytes())),
            M::Binary(bytes) | M::Ext(_, bytes) => out.push_str(&String::from_utf8_lossy(bytes)),
            M::Array(items) => match items
                .iter()
                .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect::<Option<Vec<u8>>>()
            {
                Some(bytes) => out.push_str(&String::from_utf8_lossy(&bytes)),
                None => items.iter().for_each(|item| texts(item, out)),
            },
            M::Map(entries) => entries.iter().for_each(|(key, value)| {
                texts(key, out);
                texts(value, out);
            }),
            _ => {}
        }
        out.push('\n');
    }
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    let decoded = serde_json::from_slice::<rmpv::Value>(bytes)
        .ok()
        .or_else(|| {
            let mut cursor = std::io::Cursor::new(bytes);
            rmpv::decode::read_value(&mut cursor)
                .ok()
                .filter(|_| cursor.position() == bytes.len() as u64)
        });
    if let Some(value) = decoded {
        texts(&value, &mut text);
    }
    phrase.split(' ').any(|word| text.contains(word))
}

/// Each LABEL-04 body lands in a vault of its own: the stored bytes are the
/// owner's as written, one custody record holds the phrase, and a masked
/// reader is served the file with every word overwritten.
#[test]
fn a_split_phrase_in_a_file_lands_masked_word_by_word() -> TestResult {
    for (name, body) in bodies() {
        let (_dir, vault) = open_vault()?;
        assert!(
            carries_a_word(&body),
            "{name}: the fixture holds the phrase"
        );
        let before = vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?;
        let id = put_asset(&vault, &body)
            .unwrap_or_else(|error| panic!("{name}: a split-phrase write lands: {error:?}"));
        assert_eq!(
            vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
            before + 1,
            "{name}: one custody record holds the phrase"
        );
        let stored = vault.get(&id)?.expect("stored file");
        assert_eq!(stored, body, "{name}: the stored bytes stay as written");
        assert_eq!(
            vault.sighted_asset_bytes(stored.clone(), SecretSight::Owner)?,
            body,
            "{name}: the owner gets the real file"
        );
        let served = vault.sighted_asset_bytes(stored, SecretSight::Masked)?;
        assert_eq!(
            served.len(),
            body.len(),
            "{name}: the filler keeps each width"
        );
        assert!(
            !carries_a_word(&served),
            "{name}: a masked reader is served no word of the phrase: {served:?}"
        );
    }
    Ok(())
}

/// The same phrase split in a second file keeps the record that holds it
/// (OF-560 C): no second record is minted.
#[test]
fn a_split_phrase_custody_holds_keeps_its_record() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let bodies = bodies();
    let before = vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?;
    for (name, body) in &bodies {
        let id = put_asset(&vault, body)
            .unwrap_or_else(|error| panic!("{name}: a split-phrase write lands: {error:?}"));
        let served = vault
            .sighted_asset_bytes(vault.get(&id)?.expect("stored file"), SecretSight::Masked)?;
        assert!(
            !carries_a_word(&served),
            "{name}: served masked: {served:?}"
        );
    }
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
        before + 1,
        "one custody record holds the phrase across files"
    );
    Ok(())
}

/// LABEL-04 for a body that is no file (ARCH-0069 #handles-in-fields): the
/// smallest value that reads as the phrase (the array whose items are its
/// words, or the part whose MessagePack encoding holds them) takes the
/// handle whole in the stored body, as a credential field's value does.
#[test]
fn a_split_phrase_in_a_body_lands_with_its_handle() -> TestResult {
    for (name, body) in bodies() {
        let (_dir, vault) = open_vault()?;
        let before = vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?;
        let id = put(&vault, ENTITY_TYPE_PERSON, &body)
            .unwrap_or_else(|error| panic!("{name}: a split-phrase body lands: {error:?}"));
        assert_eq!(
            vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
            before + 1,
            "{name}: one custody record holds the phrase"
        );
        let stored = vault.get(&id)?.expect("stored body");
        assert!(
            !carries_a_word(&stored),
            "{name}: the stored body carries no word of the phrase: {stored:?}"
        );
        assert!(
            carries_handle(&stored),
            "{name}: the stored body carries the handle: {stored:?}"
        );
    }
    Ok(())
}

/// With the owner's switch off the door seeks no new secret, but a value
/// custody already holds keeps its handle wherever it comes back (OF-560 C,
/// FIX 8644): a phrase custody holds, put again split over a file's parts,
/// is marked word by word with its record, and no record is minted.
#[test]
fn a_held_phrase_split_in_a_file_is_marked_with_the_switch_off() -> TestResult {
    let bodies = bodies();
    let (_dir, vault) = open_vault()?;
    let (first, rest) = bodies.split_first().expect("bodies");
    put_asset(&vault, &first.1)?;
    let held = vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.set_secret_scan_mode(&owner, SecretScanMode::Off, 10)?;
    for (name, body) in rest {
        let id = put_asset(&vault, body)?;
        let stored = vault.get(&id)?.expect("stored file");
        assert_eq!(&stored, body, "{name}: the stored bytes stay as written");
        let served = vault.sighted_asset_bytes(stored, SecretSight::Masked)?;
        assert!(
            !carries_a_word(&served),
            "{name}: switch off, a masked reader is served no word: {served:?}"
        );
    }
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
        held,
        "the switch off mints no record"
    );
    Ok(())
}

/// A phrase the door finds in an array's text does not end its reading:
/// the same phrase again under a key in one of the array's items is marked
/// too, with the same record, so a masked reader is served neither copy
/// (REVIEW-7059 P1).
#[test]
fn a_phrase_nested_in_an_array_that_holds_one_is_marked_too() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let words: Vec<&[u8]> = PHRASE.split(' ').map(str::as_bytes).collect();
    let mut items: Vec<serde_json::Value> =
        words.iter().map(|word| serde_json::json!(word)).collect();
    items.push(serde_json::json!({ "notes": words }));
    let body = serde_json::to_vec(&items)?;
    let before = vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?;
    let id = put_asset(&vault, &body)
        .unwrap_or_else(|error| panic!("the nested-phrase write lands: {error:?}"));
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
        before + 1,
        "one custody record holds the phrase, both copies"
    );
    let served =
        vault.sighted_asset_bytes(vault.get(&id)?.expect("stored file"), SecretSight::Masked)?;
    let key = b"{\"notes\":";
    let notes = served
        .windows(key.len())
        .position(|window| window == key)
        .expect("the key is no word and stays as written");
    // The nested object alone, as a reader that decodes it reads it.
    let nested = served
        .get(notes..served.len() - 1)
        .expect("the nested object's bytes");
    assert!(
        !carries_a_word(nested),
        "the nested copy is served masked: {}",
        String::from_utf8_lossy(nested)
    );
    assert!(
        !carries_a_word(&served),
        "a masked reader is served no word: {}",
        String::from_utf8_lossy(&served)
    );
    Ok(())
}

/// A token the door's field walk reads in a file's parts, beside a phrase
/// split over its other parts, keeps the write refused. Each word's mark
/// covers the separators between its byte values, so the plan's filled
/// copy is no JSON; the door still reads the leaf's parts with each mark
/// filled in place, finds the token no span places, and leaves the phrase
/// unplaced (REVIEW-7059 P1).
#[test]
fn a_split_phrase_beside_an_unplaced_token_keeps_the_write_refused() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let token: &[u8] = b"TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    let notes = serde_json::json!({ "notes": token });
    assert!(
        put_asset(&vault, &serde_json::to_vec(&notes)?).is_err(),
        "the door refuses the token alone as byte values: no span places it"
    );
    let mut items: Vec<serde_json::Value> = PHRASE
        .split(' ')
        .map(|word| serde_json::json!(word.as_bytes()))
        .collect();
    items.push(notes);
    let body = serde_json::to_vec(&items)?;
    let before = vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?;
    let refused = put_asset(&vault, &body);
    assert!(
        refused.is_err(),
        "the unplaced token keeps the write refused: {refused:?}"
    );
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
        before,
        "a refused write mints no record"
    );
    Ok(())
}

/// Another public BIP39 test vector, as a recovery phrase's words.
const OTHER_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// A JSON array of [`OTHER_PHRASE`]'s words, then `zzzz`, then [`PHRASE`]'s
/// words: two phrases split over one array's items.
fn two_phrases_body() -> Result<Vec<u8>, serde_json::Error> {
    let items: Vec<&str> = OTHER_PHRASE
        .split(' ')
        .chain(["zzzz"])
        .chain(PHRASE.split(' '))
        .collect();
    serde_json::to_vec(&items)
}

/// The custody handles (`sc` plus digits) `bytes` carry, each once.
fn handles_in(bytes: &[u8]) -> BTreeSet<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut handles = BTreeSet::new();
    for (at, _) in text.match_indices("sc") {
        let digits: String = text
            .get(at + 2..)
            .unwrap_or_default()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if !digits.is_empty() {
            handles.insert(format!("sc{digits}"));
        }
    }
    handles
}

/// Each phrase split over one array's items takes a handle of its own, and
/// the item between them stays as written. Replacing the array whole by the
/// first phrase's handle would keep the second in neither the stored body
/// nor custody (REVIEW-7060 P1).
#[test]
fn two_split_phrases_in_one_array_each_take_a_handle() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let before = vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?;
    let id = put(&vault, ENTITY_TYPE_PERSON, &two_phrases_body()?)
        .unwrap_or_else(|error| panic!("a body with two split phrases lands: {error:?}"));
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
        before + 2,
        "a custody record holds each phrase"
    );
    let stored = vault.get(&id)?.expect("stored body");
    let text = String::from_utf8_lossy(&stored);
    assert!(
        !carries_a_word(&stored) && !carries_a_word_of(&stored, OTHER_PHRASE),
        "the stored body carries no word of either phrase: {text}"
    );
    assert!(
        text.contains("zzzz"),
        "the item between the phrases stays as written: {text}"
    );
    assert_eq!(
        handles_in(&stored).len(),
        2,
        "the stored body carries both handles: {text}"
    );
    Ok(())
}

/// With the switch off, a phrase no record holds stays as written and does
/// not keep a held phrase in the same array from its handle: the held one
/// takes the handle of the record that holds it, the other items stay, and
/// no record is minted (REVIEW-7060 P1; OF-560 C, FIX 8644).
#[test]
fn a_held_phrase_beside_an_unheld_one_takes_its_handle_with_the_switch_off() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let words: Vec<&str> = PHRASE.split(' ').collect();
    let first = put(&vault, ENTITY_TYPE_PERSON, &serde_json::to_vec(&words)?)?;
    let held_handles = handles_in(&vault.get(&first)?.expect("stored body"));
    assert_eq!(held_handles.len(), 1, "a record holds the phrase");
    let held = vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.set_secret_scan_mode(&owner, SecretScanMode::Off, 10)?;
    let id = put(&vault, ENTITY_TYPE_PERSON, &two_phrases_body()?)?;
    let stored = vault.get(&id)?.expect("stored body");
    let text = String::from_utf8_lossy(&stored);
    assert!(
        !carries_a_word(&stored),
        "the held phrase takes its handle: {text}"
    );
    assert_eq!(
        handles_in(&stored),
        held_handles,
        "the handle is the held record's: {text}"
    );
    assert!(
        carries_a_word_of(&stored, OTHER_PHRASE) && text.contains("zzzz"),
        "the unheld phrase and the item between stay as written: {text}"
    );
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
        held,
        "the switch off mints no record"
    );
    Ok(())
}

/// A phrase the owner kept as text in a record, put there again split over
/// an array's items, is no hit there: the write lands as written. The door
/// screens a kept value's contiguous spelling only, so it would still read
/// the words joined (REVIEW-7060 P1).
#[test]
fn a_kept_phrase_split_over_an_array_lands_as_written() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    // An owner act on this install needs its live machine profile.
    let issuer = HostSlipIssuer::from_secret(b"split phrase kept as text host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let words: Vec<&str> = PHRASE.split(' ').collect();
    let body = serde_json::to_vec(&words)?;
    let id = put(&vault, ENTITY_TYPE_PERSON, &body)?;
    let handle = vault
        .found_keys(&owner, true, 10)?
        .into_iter()
        .find(|notice| notice.record == id)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|key| key.handle)
        .expect("the phrase's found key");
    vault.keep_found_key_as_text(&owner, ActSurface::ThisInstall, &handle)?;
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            2,
            &body,
        )
        .commit()
        .unwrap_or_else(|error| panic!("the kept phrase, split again, lands: {error:?}"));
    assert_eq!(
        vault.get(&id)?.expect("stored body"),
        body,
        "the kept phrase is stored as written"
    );
    Ok(())
}

/// A carrier's stored text (an entity document's, a typed body's) and how a
/// lifted text reads back (REVIEW-7059, Fable P1).
#[cfg(oneiron_test_support)]
mod carrier {
    use oneiron::test_doors::split_phrase_carrier::{
        carrier_text_is_placeable, lifted_text_round_trip,
    };

    use super::{PHRASE, TestResult, carries_a_word, open_vault, put_asset};

    /// The phrase one word per JSON string under a key: the text rules miss
    /// it (each word reads alone), and the door's field walk reads the list
    /// whole and finds it.
    fn listed_phrase_text() -> String {
        let words: Vec<&str> = PHRASE.split(' ').collect();
        serde_json::json!({ "account": "main", "list": words }).to_string()
    }

    /// A carrier's text is placed as before: a phrase split over its parts
    /// leaves it unplaced, never marked word by word under one handle.
    #[test]
    fn a_split_phrase_in_a_carrier_text_stays_unplaced() -> TestResult {
        let text = listed_phrase_text();
        assert!(
            !carrier_text_is_placeable(text.as_bytes())?,
            "a carrier's split phrase stays unplaced: {text}"
        );
        Ok(())
    }

    /// A carrier's text with the bytes of a file whose split phrase is
    /// marked reads that file's marks: a masked reader is served each word
    /// as the phrase's handle, and a writer's copy that keeps those handles
    /// writes no other word in their place.
    #[test]
    fn a_split_phrase_handle_writes_back_no_wrong_word() -> TestResult {
        let (_dir, vault) = open_vault()?;
        let text = listed_phrase_text();
        put_asset(&vault, text.as_bytes())
            .unwrap_or_else(|error| panic!("the listed-phrase file lands: {error:?}"));
        let (masked, resolved) = lifted_text_round_trip(&vault, &text)?;
        let masked = masked.expect("the lifted text reads the file's marks");
        assert!(
            !carries_a_word(masked.as_bytes()),
            "a masked reader is served no word: {masked}"
        );
        assert!(
            resolved.as_ref().is_none_or(|back| *back == text),
            "kept handles write back the phrase as it was, or stay as written: {resolved:?}"
        );
        Ok(())
    }
}
