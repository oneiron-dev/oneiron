//! UC-07 PR 6, HEX-CASE-POLICY = A: stored and wire forms read lowercase-only;
//! typed or foreign input reads either case; no door trims.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test hex_input_policy_server`
#![cfg(oneiron_test_support)]

use oneiron_server::test_doors::hex_input_policy::{
    embedder_accounts_rows, linear_signature_reads,
};
use sha2::{Digest, Sha256};

fn accounts_toml(key_sha256: &str) -> String {
    format!("[[account]]\nid = \"acct-a\"\nkey_sha256 = \"{key_sha256}\"\n")
}

#[test]
fn an_accounts_file_digest_reads_either_case_untrimmed() {
    let lower = format!("{:x}", Sha256::digest(b"key-a"));
    let upper = lower.to_ascii_uppercase();
    let padded = format!(" {lower} ");
    assert_eq!(
        embedder_accounts_rows(&accounts_toml(&lower)),
        Ok(1),
        "a lowercase accounts digest reads one row"
    );
    assert_eq!(
        embedder_accounts_rows(&accounts_toml(&upper)),
        Ok(1),
        "an uppercase accounts digest reads one row"
    );
    assert!(
        embedder_accounts_rows(&accounts_toml(&padded)).is_err(),
        "a padded accounts digest is no file"
    );
}

#[test]
fn a_linear_signature_header_refuses_a_sign_digit_and_padding() {
    assert!(
        linear_signature_reads("0a0b"),
        "a lowercase signature reads"
    );
    assert!(
        linear_signature_reads("0A0B"),
        "an uppercase signature reads"
    );
    assert!(
        !linear_signature_reads("+a0b"),
        "a sign-led signature is no signature"
    );
    assert!(
        !linear_signature_reads(" 0a0b "),
        "a padded signature is no signature"
    );
}
