//! Purposes for tests only. A production site never names one (a review finding).
//!
//! Not behind a cargo feature: `--all-features` is the release build (ARCH-0019), so a
//! feature gate would hide nothing there, and in the default build it would leave the
//! registry's constructors unused while no other area exists yet.

purposes! {
    /// A test purpose. Parts: whatever the test writes.
    ALPHA = "oneiron.testing.alpha.v1";

    /// A second test purpose, distinct from [`ALPHA`]. Parts: whatever the test writes.
    BETA = "oneiron.testing.beta.v1";
}

legacy_purposes! {
    /// BLAKE3 derive-key, the tag as the context.
    BLAKE3_DERIVE_KEY = (Blake3, DeriveKeyContext, "oneiron.testing.legacy.blake3_derive_key.v1");

    /// Plain BLAKE3, the tag hashed first. The tag ends in a NUL, as 166 tree literals do.
    BLAKE3_TAG_FIRST = (Blake3, HashedFirst, "oneiron.testing.legacy.blake3_tag_first.v1\0");

    /// Plain BLAKE3, no tag written.
    BLAKE3_NO_TAG = (Blake3, NotHashed, "oneiron.testing.legacy.blake3_no_tag.v1");

    /// SHA-256, the tag hashed first.
    SHA256_TAG_FIRST = (Sha256, HashedFirst, "oneiron.testing.legacy.sha256_tag_first.v1");

    /// SHA-256, no tag written.
    SHA256_NO_TAG = (Sha256, NotHashed, "oneiron.testing.legacy.sha256_no_tag.v1");
}
