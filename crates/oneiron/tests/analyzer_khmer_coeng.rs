//! ONE-COENG (ARCH-0031 #deferred, L8-40): Khmer text reaches the index in
//! UTN #61 canonical order (the published L2/22-290).
//!
//! One Khmer word renders the same whichever order its subscripts and vowel
//! were typed in. Before the fix the analyzer folded only NFKC and case, so a
//! query typed in another order matched none of the NOTE's postings.

use oneiron::edge::EdgeActorClass;
use oneiron::write_envelope::WriteActor;
use oneiron::{Vault, VaultConfig};

/// ស្ត្រី ("woman") in canonical order: SA, COENG TA, COENG RO, vowel II.
const CANONICAL: &str = "\u{179F}\u{17D2}\u{178F}\u{17D2}\u{179A}\u{17B8}";
/// The same word typed COENG RO first.
const COENG_RO_FIRST: &str = "\u{179F}\u{17D2}\u{179A}\u{17D2}\u{178F}\u{17B8}";
/// The same word typed with its vowel before the subscripts.
const VOWEL_FIRST: &str = "\u{179F}\u{17B8}\u{17D2}\u{178F}\u{17D2}\u{179A}";
/// The same word typed with COENG DA, which renders as COENG TA.
const COENG_DA: &str = "\u{179F}\u{17D2}\u{178A}\u{17D2}\u{179A}\u{17B8}";

#[test]
fn coeng_order_variants_find_the_canonical_note() {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let actor = WriteActor::new(owner, EdgeActorClass::Human);

    let note = vault
        .create_note("research", CANONICAL, actor)
        .expect("Khmer NOTE");
    vault.set_indexed_idle_delay_ms(0).expect("idle delay row");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("idle publication");
    assert!(
        published.failed.is_empty(),
        "the NOTE publishes at idle: {published:?}"
    );

    let found = |query: &str| -> bool {
        vault
            .search_text(query, 10)
            .expect("text search")
            .iter()
            .any(|hit| hit.id == note)
    };
    assert!(found(CANONICAL), "the canonical query finds the NOTE");
    for (label, query) in [
        ("coeng RO first", COENG_RO_FIRST),
        ("vowel first", VOWEL_FIRST),
        ("coeng DA", COENG_DA),
    ] {
        assert!(
            found(query),
            "the {label} spelling finds the canonical NOTE"
        );
    }
}
