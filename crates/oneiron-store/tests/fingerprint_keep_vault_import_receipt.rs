//! K-proof (oracle) for PLAN-UC-04 stage 6.3c: the foreign vault import receipt id keeps its
//! bytes.
//!
//! A staged foreign vault import's receipt id (`purposes::vault_import::RECEIPT_ID`) now
//! starts through the fingerprint crate's K door. The stage keys its receipt and content rows
//! by it and dedupes on it, encoding a receipt and the engine's decode recompute it and refuse
//! another, and a sync peer's confirmation must carry it back. So it must give main's bytes
//! for every input, and refuse every source main refuses. The `base` module holds main's
//! lines at 3db42b3bc550, copied by range (each range is named above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them only
//! in indentation; it takes the source type from the head, whose definition is unchanged.
//!
//! The module is in sync builds only:
//! `cargo test --locked -p oneiron-store --all-features --test fingerprint_keep_vault_import_receipt`.
#![cfg(feature = "sync")]

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};
use oneiron_store::batch::export::foreign_stage::export_foreign_receipt::{
    ForeignVaultImportSource, VAULT_IMPORT_RECEIPT_ID_DOMAIN, receipt_id,
};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base {
    use oneiron_base::error::{Error, Result};
    use oneiron_store::batch::export::foreign_stage::export_foreign_receipt::ForeignVaultImportSource;

    // main 3db42b3bc550: crates/oneiron-store/src/batch/export/foreign_stage/export_foreign_receipt.rs:52-52
    pub const VAULT_IMPORT_RECEIPT_ID_DOMAIN: &[u8] = b"oneiron/vault-import-receipt/v1\0";

    // main 3db42b3bc550: crates/oneiron-store/src/batch/export/foreign_stage/export_foreign_receipt.rs:54-54
    pub const MAX_FOREIGN_PLATFORM_NAME_BYTES: usize = 128;

    // main 3db42b3bc550: crates/oneiron-store/src/batch/export/foreign_stage/export_foreign_receipt.rs:122-142
    pub fn source_bytes(s: &ForeignVaultImportSource) -> Result<Vec<u8>> {
        match s {
            ForeignVaultImportSource::AnotherPerson { peer_ref } => {
                let mut x = vec![1];
                x.extend_from_slice(peer_ref.as_bytes());
                Ok(x)
            }
            ForeignVaultImportSource::ForeignPlatform { platform } => {
                if platform.is_empty()
                    || platform != platform.trim()
                    || platform.len() > MAX_FOREIGN_PLATFORM_NAME_BYTES
                    || platform.chars().any(char::is_control)
                {
                    return Err(Error::InvalidConfig("invalid foreign platform".into()));
                }
                let mut x = vec![2];
                x.extend_from_slice(platform.as_bytes());
                Ok(x)
            }
        }
    }

    // main 3db42b3bc550: crates/oneiron-store/src/batch/export/foreign_stage/export_foreign_receipt.rs:158-171
    pub fn receipt_id(
        manifest: &[u8; 32],
        source: &ForeignVaultImportSource,
        window: &str,
        remote: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let mut h = blake3::Hasher::new();
        h.update(VAULT_IMPORT_RECEIPT_ID_DOMAIN);
        h.update(manifest);
        h.update(&source_bytes(source)?);
        h.update(window.as_bytes());
        h.update(remote);
        Ok(*h.finalize().as_bytes())
    }
}

fn peer(seed: u8) -> EntityId {
    EntityId::from_bytes(std::array::from_fn(|at| {
        seed.wrapping_add((at as u8).wrapping_mul(29))
    }))
    .expect("an unreserved id")
}

fn platform(name: &str) -> ForeignVaultImportSource {
    ForeignVaultImportSource::ForeignPlatform {
        platform: name.to_owned(),
    }
}

/// Sources of both kinds: two peers, and platforms of one byte, ASCII, Unicode, inner
/// spaces and the 128-byte limit.
fn sources() -> Vec<ForeignVaultImportSource> {
    vec![
        ForeignVaultImportSource::AnotherPerson { peer_ref: peer(3) },
        ForeignVaultImportSource::AnotherPerson {
            peer_ref: peer(201),
        },
        platform("x"),
        platform("ChatGPT export"),
        platform("Überplattform — 日本"),
        platform(&"p".repeat(128)),
        platform("a b\u{a0}c"),
    ]
}

/// Sources main refuses: an empty, padded, too long or control-bearing platform name.
fn invalid_sources() -> Vec<ForeignVaultImportSource> {
    vec![
        platform(""),
        platform(" leading"),
        platform("trailing "),
        platform(&"p".repeat(129)),
        platform("two\nlines"),
        platform("tab\tinside"),
    ]
}

/// Window keys as the stage writes them (`YYYY-MM`), and the `&str` edges the signature takes.
const WINDOWS: [&str; 5] = ["2026-11", "1999-01", "", "2026-11-extra", "窓"];

#[test]
fn the_vault_import_purpose_keeps_main_s_tag() {
    let purpose = purposes::vault_import::RECEIPT_ID;
    assert_eq!(
        purpose.tag().as_bytes(),
        base::VAULT_IMPORT_RECEIPT_ID_DOMAIN
    );
    assert_eq!(purpose.hash(), LegacyHash::Blake3);
    assert_eq!(purpose.tag_mode(), TagMode::HashedFirst);
    assert_eq!(
        VAULT_IMPORT_RECEIPT_ID_DOMAIN,
        base::VAULT_IMPORT_RECEIPT_ID_DOMAIN
    );
}

#[test]
fn the_receipt_id_keeps_its_bytes() {
    let manifests = [[0_u8; 32], [0xff; 32], std::array::from_fn(|at| at as u8)];
    let remotes = [
        [7_u8; 32],
        std::array::from_fn(|at| (at as u8).wrapping_mul(37)),
    ];
    let mut cases = 0;
    for manifest in &manifests {
        for source in &sources() {
            for window in WINDOWS {
                for remote in &remotes {
                    let main = base::receipt_id(manifest, source, window, remote)
                        .expect("main takes a valid source");
                    let head = receipt_id(manifest, source, window, remote)
                        .expect("the head takes a valid source");
                    assert_eq!(head, main, "{source:?} {window:?}");
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 210);
}

#[test]
fn an_invalid_source_has_no_receipt_id_on_either_side() {
    let invalid = invalid_sources();
    assert_eq!(invalid.len(), 6);
    for source in &invalid {
        let main = base::receipt_id(&[1; 32], source, "2026-11", &[2; 32]);
        let head = receipt_id(&[1; 32], source, "2026-11", &[2; 32]);
        assert!(main.is_err(), "main takes {source:?}");
        assert_eq!(format!("{head:?}"), format!("{main:?}"));
    }
}
