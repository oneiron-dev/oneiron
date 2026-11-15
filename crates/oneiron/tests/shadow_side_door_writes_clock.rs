//! SHADOW-SIDE-DOOR-WRITES-CLOCK (FIX-LIST 23126): the Dreamer's
//! read-only side doors (gap scan, retrieval shadow) read TURN text through
//! a snapshot that persisted the authorization clock first. On a vault
//! opened with `Vault::open` that first read took the synchronous
//! lease-renew path and committed CLOCK_FLOOR into vault_meta, so data.mdb
//! changed inside the shadow interval and broke the zero-write shadow
//! promise. The side doors now judge grant expiry at the committed floor
//! without persisting. This mirrors the bench harness
//! (`oneiron-bench/src/oneironer_shadow.rs`, the same vault operations in
//! the same order) with an in-process stub tagger standing in for the
//! checkpoint subprocess; neither touches the vault.

use std::path::Path;

use oneiron::llm::tagger::{MentionTag, OneironerTagger, RetrievalTags, shadow_tag_turn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::{EntityId, ModelId, TimeRange, Vault, VaultConfig};

const TURN_TEXT: &str = "Ada works here";

/// The checkpoint proposes spans while the host maps known names to
/// existing vault entities. The stub stands in for the checkpoint: it
/// touches no vault state, as the subprocess never receives the vault path.
struct StubTagger {
    person: EntityId,
}

impl OneironerTagger for StubTagger {
    fn model(&self) -> ModelId {
        ModelId::new("test/stub-ner@v1").expect("stub model id")
    }

    fn tag(&self, text: &str) -> oneiron::Result<RetrievalTags> {
        assert_eq!(text, TURN_TEXT, "the shadow reads the fixture turn's words");
        let mentions = vec![MentionTag {
            start: 0,
            end: 3,
            entity: self.person,
            weight: 0.9,
        }];
        Ok(RetrievalTags {
            mentions,
            ..RetrievalTags::default()
        })
    }
}

fn vault_bytes(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(path.join("data.mdb"))
}

/// The retrieval shadow compares mentions and leaves the fixture vault
/// byte-identical: no write happens inside the shadow interval.
#[test]
fn side_door_read_writes_no_vault_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut cfg = VaultConfig::device();
    cfg.dimensions = 4;
    cfg.embedding_model = Some("test/shadow@v1".into());
    let vault = Vault::open(dir.path(), cfg)?;
    let person = EntityId::from_bytes([31; 16])?;
    let turn = EntityId::from_bytes([32; 16])?;
    let time = TimeRange { start: 1, end: 1 };
    let body =
        rmp_serde::to_vec_named(&serde_json::json!({"txt": TURN_TEXT, "spkr": "user"}))?;
    vault
        .batch()
        .put(&person, ENTITY_TYPE_PERSON, time, 1, b"Ada")
        .text(&person, &[("body", "Ada")])
        .put(&turn, ENTITY_TYPE_TURN, time, 1, &body)
        .text(&turn, &[("body", TURN_TEXT)])
        .commit()?;
    // Live retrieval occurs BEFORE the no-write baseline: the retrieval API
    // may write telemetry. Only the shadow interval has a zero-write contract.
    let live = vault
        .search_text("Ada", 10)?
        .into_iter()
        .map(|hit| hit.id)
        .collect::<Vec<_>>();
    assert!(live.contains(&turn), "fixture turn missing from live retrieval");
    let before = vault_bytes(dir.path())?;
    let tagger = StubTagger { person };
    let outcome = shadow_tag_turn(&vault, turn, &tagger, &live);
    let after = vault_bytes(dir.path())?;
    assert_eq!(before, after, "the shadow side door wrote to the fixture vault");
    let report = outcome?;
    assert_eq!(report.tags.mentions[0].entity, person);
    assert_eq!(report.common, vec![person]);
    assert!(report.tag_only.is_empty());
    assert_eq!(report.live_only, vec![turn]);
    Ok(())
}
