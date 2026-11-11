//! LABEL-04 (ARCH-0038 #promise-label-04; owner ruling G04 binary = C2,
//! ARCH-0069 #binary-secrets): a recovery phrase split over a file's parts,
//! one word per item, is masked on write like any file key. The write lands,
//! one custody record holds the phrase, the stored bytes stay the owner's,
//! and a masked reader is served each word overwritten.

use std::sync::Arc;

use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_SECRET_CUSTODY};
use oneiron::secret_custody::SecretSight;
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
    let id = EntityId::now();
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )
        .commit()?;
    Ok(id)
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

/// Whether `bytes` still carry a word of the phrase, read as the release
/// doors read text: its lossy text, and each string, binary or extension
/// value and array of byte values a JSON or MessagePack decode of it holds.
fn carries_a_word(bytes: &[u8]) -> bool {
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
    PHRASE.split(' ').any(|word| text.contains(word))
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
