//! L10-08 PR 2 (CROSS-ARCH-0013 `#ladder` rung 1, G2P → IPA → NPD): a query's
//! `ipa:` sound keys match every entity's stored sound keys by Normalized
//! Phonetic Distance (cut 0.2, keep within 1.2× the nearest, at most 10),
//! and a sound match only adds to an exact code's score. Every door here is
//! on main, so at the base the file builds and its reds are run-time reds.

use oneiron::batch::generate_phonetic_codes;
use oneiron::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    Fixture { _dir: dir, vault }
}

impl Fixture {
    /// An entity of `entity_type` named `name`; its birth publishes the
    /// name's phonetic codes.
    fn named(&self, entity_type: u8, name: &str) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                entity_type,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
            )
            .expect("put the entity");
        id
    }

    fn person(&self, name: &str) -> EntityId {
        self.named(ENTITY_TYPE_PERSON, name)
    }

    /// The ids a phonetic query for `codes` returns, best first. The limit
    /// is past the sound match's cap, so the cap is what a test sees.
    fn phonetic(&self, codes: &[String]) -> Vec<EntityId> {
        let codes: Vec<&str> = codes.iter().map(String::as_str).collect();
        self.vault
            .query()
            .search_phonetic(&codes)
            .limit(20)
            .run()
            .expect("phonetic query")
            .into_iter()
            .map(|row| row.id)
            .collect()
    }
}

/// Only the sound keys among the codes of `name`.
fn sound_keys(name: &str) -> Vec<String> {
    generate_phonetic_codes(name)
        .into_iter()
        .filter(|code| code.starts_with("ipa:"))
        .collect()
}

/// The fixture's control: an exact romaji code still finds its person.
#[test]
fn fixture_an_exact_romaji_code_finds_its_person() {
    let fixture = fixture();
    let sato = fixture.person("さとう");
    assert_eq!(fixture.phonetic(&["romaji:sato".to_owned()]), [sato]);
}

/// Canon `#test-accuracy` "Latin → Han (cross)": a Han name written with no
/// reading is found from its pinyin spelling.
#[test]
fn a_latin_query_finds_a_han_name_with_no_reading() {
    let fixture = fixture();
    let xiaoming = fixture.person("小明");
    let found = fixture.phonetic(&generate_phonetic_codes("Xiaoming"));
    assert_eq!(found.first(), Some(&xiaoming), "{found:?}");
}

/// A name heard with one sound off (t heard as d) shares no exact code with
/// the written one, and is found by its sound.
#[test]
fn a_misheard_name_matches_by_sound() {
    let fixture = fixture();
    let sato = fixture.person("さとう");
    let found = fixture.phonetic(&generate_phonetic_codes("Sadou"));
    assert_eq!(found, [sato]);
}

/// Canon `#test-accuracy` "Latin → Kana (cross)" with a company form: the
/// form carries no sound, so "Mirai Inc" finds 株式会社みらい.
#[test]
fn an_org_name_matches_without_its_suffix() {
    let fixture = fixture();
    let mirai = fixture.named(ENTITY_TYPE_ORG, "株式会社みらい");
    let found = fixture.phonetic(&generate_phonetic_codes("Mirai Inc"));
    assert_eq!(found.first(), Some(&mirai), "{found:?}");
}

/// Canon `#test-regression`: a phonetic match only boosts. The exact name
/// holds the query's exact codes and the nearest sound, so it ranks first.
#[test]
fn an_exact_code_outranks_a_sound_alike() {
    let fixture = fixture();
    let sato = fixture.person("Sato");
    fixture.person("Sado");
    let found = fixture.phonetic(&generate_phonetic_codes("Sato"));
    assert_eq!(found.first(), Some(&sato), "{found:?}");
}

/// Canon `#problem`: keep within 1.2× the nearest distance. The nearest is
/// an exact sound (0), so a near sound is not kept beside it.
#[test]
fn sound_alikes_drop_when_an_exact_sound_match_exists() {
    let fixture = fixture();
    let sato = fixture.person("さとう");
    fixture.person("さどう");
    assert_eq!(fixture.phonetic(&sound_keys("Satou")), [sato]);
}

/// Canon `#problem`: at most ten sound matches, however many are as near.
#[test]
fn the_scan_keeps_at_most_ten() {
    let fixture = fixture();
    for _ in 0..12 {
        fixture.person("さとう");
    }
    assert_eq!(fixture.phonetic(&sound_keys("Sadou")).len(), 10);
}

/// Canon `#test-regression`: the false-positive rate stays low. A name far
/// from every stored sound finds nothing.
#[test]
fn far_names_stay_out() {
    let fixture = fixture();
    fixture.person("さとう");
    assert_eq!(fixture.phonetic(&sound_keys("Takeshi")), []);
}
