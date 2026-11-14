//! L10-08 (CROSS-ARCH-0013 `#ladder` rung 1, G2P → IPA → NPD): a Han name
//! and a kana name with a company-form word get sound keys. It names only
//! items main has, so on main it builds and its red is a run-time red: main
//! gives both names no code at all.

use oneiron_store::batch::phonetic_codes::generate_phonetic_codes;

#[test]
fn a_han_name_gets_a_mandarin_sound_key() {
    let codes = generate_phonetic_codes("小明");
    assert!(
        codes.iter().any(|code| code.starts_with("ipa:cmn:")),
        "{codes:?}"
    );
}

#[test]
fn a_name_with_an_org_suffix_gets_a_sound_key() {
    let codes = generate_phonetic_codes("株式会社みらい");
    assert!(
        codes.iter().any(|code| code.starts_with("ipa:jpn:")),
        "{codes:?}"
    );
}
