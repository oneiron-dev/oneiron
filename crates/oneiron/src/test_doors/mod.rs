//! Doors for integration tests to crate-private items (lead 9 Nov 19:2x,
//! TEST-DOORS-RULE). Compiled only with the custom cfg
//! `oneiron_test_support`, which only the fleet's test command sets
//! (`RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test <stem>`). Never a cargo feature, so no
//! `--all-features` release build reaches them; never API.

pub mod consolidation;
