//! L10-08 PR 2 (CROSS-ARCH-0013 `#ladder` rung 1, G2P → IPA → NPD): a query's
//! `ipa:` sound keys match every entity's stored sound keys by Normalized
//! Phonetic Distance (cut 0.2, keep within 1.2× the nearest, at most 10),
//! and a sound match only adds to an exact code's score. Every door here is
//! on main, so at the base the file builds and its reds are run-time reds.
//! The made_by case stamps births through a test door: run the file with
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test phonetic_g2p_npd`.

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
                &name_body(name),
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
        self.phonetic_of_types(codes, None)
    }

    /// [`Self::phonetic`], narrowed to `types` when given.
    fn phonetic_of_types(&self, codes: &[String], types: Option<&[u8]>) -> Vec<EntityId> {
        let codes: Vec<&str> = codes.iter().map(String::as_str).collect();
        let query = self.vault.query().search_phonetic(&codes).limit(20);
        let query = match types {
            Some(types) => query.filter_types(types),
            None => query,
        };
        query
            .run()
            .expect("phonetic query")
            .into_iter()
            .map(|row| row.id)
            .collect()
    }
}

/// An entity body named `name`.
fn name_body(name: &str) -> Vec<u8> {
    rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body")
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

/// Review #8107: the cut is taken among the rows the call may see. An ORG
/// holding the query's exact sound is outside a PERSON-only call, so it sets
/// no nearest distance, and the person one sound off is still found. Before,
/// the hidden exact sound cut the person, then left the call itself: no hit,
/// and an answer that told the hidden row was there.
#[test]
fn a_sound_the_call_cannot_see_sets_no_cut() {
    let fixture = fixture();
    let sato = fixture.person("さとう");
    let query = sound_keys("Sadou");
    let people = Some(&[ENTITY_TYPE_PERSON][..]);
    assert_eq!(fixture.phonetic_of_types(&query, people), [sato]);
    let sadou = fixture.named(ENTITY_TYPE_ORG, "Sadou");
    assert_eq!(
        fixture.phonetic(&query),
        [sadou],
        "the exact sound cuts a near one it can see"
    );
    assert_eq!(fixture.phonetic_of_types(&query, people), [sato]);
}

/// Review #8107 round 2: the call's made_by predicate decides inside the cut
/// too. A concluded PERSON holding the query's exact sound is outside a
/// stated-only call, so it sets no nearest distance, and the stated person
/// one sound off is still found. Before, the concluded exact sound cut the
/// stated person, then the post-blend made_by filter dropped it: no hit.
#[cfg(oneiron_test_support)]
#[test]
fn a_sound_the_made_by_predicate_drops_sets_no_cut() {
    use oneiron::test_doors::sound_match_birth::put_born;
    use oneiron::write_envelope::provenance::made_by::{MadeByClass, MadeByPredicate};

    let fixture = fixture();
    let born = |name: &str, class: MadeByClass, inputs: &[EntityId]| {
        put_born(
            &fixture.vault,
            ENTITY_TYPE_PERSON,
            &name_body(name),
            class,
            inputs,
        )
        .expect("put the born person")
    };
    let stated = |codes: &[String]| -> Vec<EntityId> {
        let codes: Vec<&str> = codes.iter().map(String::as_str).collect();
        fixture
            .vault
            .query()
            .search_phonetic(&codes)
            .made_by(MadeByPredicate::Stated)
            .limit(20)
            .run()
            .expect("phonetic query")
            .into_iter()
            .map(|row| row.id)
            .collect()
    };
    let sato = born("さとう", MadeByClass::Stated, &[]);
    let query = sound_keys("Sadou");
    assert_eq!(stated(&query), [sato]);
    let sadou = born("Sadou", MadeByClass::Concluded, &[sato]);
    assert_eq!(
        fixture.phonetic(&query),
        [sadou],
        "the exact sound cuts a near one the call keeps"
    );
    assert_eq!(stated(&query), [sato]);
}
