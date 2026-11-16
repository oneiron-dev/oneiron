//! ONE-ZAWGYI (ARCH-0031 #deferred, L8-40): Zawgyi queries reach the index
//! as Unicode.
//!
//! A note written in Unicode Burmese and a query typed in Zawgyi share no
//! tokens. Before the fix the analyzer folded only NFKC and case (plus Khmer
//! order), so a Zawgyi query matched none of the NOTE's postings.

use oneiron::edge::EdgeActorClass;
use oneiron::write_envelope::WriteActor;
use oneiron::{Vault, VaultConfig};

/// Naypyidaw in Zawgyi order (mmgov corpus): U+1031 1014 103B 1015 100A 1039
/// 1031 1010 102C 1039.
const ZAWGYI_NAYPYIDAW: &str =
    "\u{1031}\u{1014}\u{103B}\u{1015}\u{100A}\u{1039}\u{1031}\u{1010}\u{102C}\u{1039}";
/// The same word in Unicode order: U+1014 1031 1015 103C 100A 103A 1010 1031
/// 102C 103A.
const UNICODE_NAYPYIDAW: &str =
    "\u{1014}\u{1031}\u{1015}\u{103C}\u{100A}\u{103A}\u{1010}\u{1031}\u{102C}\u{103A}";

#[test]
fn zawgyi_query_finds_the_unicode_note() {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let actor = WriteActor::new(owner, EdgeActorClass::Human);

    let note = vault
        .create_note("research", UNICODE_NAYPYIDAW, actor)
        .expect("Unicode NOTE");
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
    assert!(found(UNICODE_NAYPYIDAW), "the Unicode query finds the NOTE");
    assert!(
        found(ZAWGYI_NAYPYIDAW),
        "the Zawgyi query finds the Unicode NOTE"
    );
}
