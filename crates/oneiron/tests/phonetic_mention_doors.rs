//! L10-08 PR 2 (CROSS-ARCH-0013 `#flow`: compute the phonetic key per
//! mention): a caller hands the engine names as heard or typed, and the
//! engine computes their codes, sound keys among them, as a write does. The
//! pipeline, the context pack and the hybrid search take them. The doors are
//! new, so at the base this file's red is a compile red.

use oneiron::memory::HybridSearchRequest;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

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
    /// A PERSON named `name`; its birth publishes the name's phonetic codes.
    fn person(&self, name: &str) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
            )
            .expect("put the person");
        id
    }

    /// The entity refs the owner's hybrid search returns for the phonetic
    /// channel's `codes` and `mentions`.
    fn hybrid(&self, codes: &[&str], mentions: &[&str]) -> Vec<String> {
        let owner = self.vault.ensure_embedded_owner_actor().expect("the owner");
        let request = HybridSearchRequest {
            query: None,
            query_vector: None,
            phonetic_codes: codes.iter().map(|code| (*code).to_owned()).collect(),
            phonetic_mentions: mentions.iter().map(|name| (*name).to_owned()).collect(),
            ppr: None,
            temporal: None,
            replay: None,
            limit: 10,
            filter: None,
        };
        self.vault
            .memory(owner, EdgeActorClass::Human)
            .query_hybrid(&request)
            .expect("hybrid search")
            .value
            .into_iter()
            .map(|hit| hit.entity_ref)
            .collect()
    }
}

#[test]
fn a_mention_runs_the_same_rung() {
    let fixture = fixture();
    let xiaoming = fixture.person("小明");
    let found: Vec<EntityId> = fixture
        .vault
        .query()
        .search_phonetic_mentions(&["Xiaoming"])
        .limit(10)
        .run()
        .expect("phonetic mention query")
        .into_iter()
        .map(|row| row.id)
        .collect();
    assert_eq!(found, [xiaoming]);
}

/// The control: the owner's hybrid search surfaces a person found by an
/// exact phonetic code, so a miss below is the mention's.
#[test]
fn fixture_a_hybrid_search_finds_a_person_by_code() {
    let fixture = fixture();
    let sato = fixture.person("さとう");
    assert_eq!(fixture.hybrid(&["romaji:sato"], &[]), [sato.to_hex()]);
}

#[test]
fn a_hybrid_search_takes_phonetic_mentions() {
    let fixture = fixture();
    let sato = fixture.person("さとう");
    assert_eq!(fixture.hybrid(&[], &["Sadou"]), [sato.to_hex()]);
}

#[test]
fn an_empty_phonetic_mention_is_refused() {
    let fixture = fixture();
    let owner = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("the owner");
    let request = HybridSearchRequest {
        query: None,
        query_vector: None,
        phonetic_codes: Vec::new(),
        phonetic_mentions: vec![" ".to_owned()],
        ppr: None,
        temporal: None,
        replay: None,
        limit: 10,
        filter: None,
    };
    assert!(
        fixture
            .vault
            .memory(owner, EdgeActorClass::Human)
            .query_hybrid(&request)
            .is_err()
    );
}
