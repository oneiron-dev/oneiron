//! Legacy blob-artifact digests that existing rows, ids and keys hold.
//!
//! An e-sign act's retry key derived from its call, a sealed PDF's SHA-256 that
//! every read of it compares, a QR capability's digest that keys its token row,
//! and a signature image's id retain their exact bytes through the K door (K,
//! PLAN-UC-04 stage 7).

purposes! {}

legacy_purposes! {
    /// No-key e-sign call: the tag with no length before it, then the actor's,
    /// the act's, the document's and the invocation's lowercase hex or name,
    /// each after its u64-LE byte length, then 1 and the principal after its
    /// u64-LE byte length, or 0 when none. The key is the first 16 bytes as 32
    /// lowercase hex digits: the retry key an e-sign act called with no key
    /// runs under, sent in its intent ref.
    ESIGN_NO_KEY_CALL = (Blake3, HashedFirst, "oneiron.esign.dispatch.no_key.call.v1");

    /// E-sign QR capability: the capability's 64 lowercase hex characters, no
    /// length or hashed tag (the tag is a registry name only). The key of the
    /// capability's QR token row, and what a lookup of it reads.
    ESIGN_QR_CAPABILITY = (Sha256, NotHashed, "oneiron.blob_artifact.esign_qr_capability.v1");

    /// E-sign signature image: the tag with no length before it, then the
    /// document's 16-byte id, the recipient's bytes and the canonical PNG
    /// bytes, none after a length. The id is the first 16 bytes: it names the
    /// stored image artifact and its binding row.
    ESIGN_SIGNATURE_IMAGE = (Blake3, HashedFirst, "esign.signature_image.v1");

    /// Sealed PDF: the sealed output's bytes, no length or hashed tag (the tag
    /// is a registry name only). A seal stores it with the output, and every
    /// read of the sealed PDF compares the bytes with it.
    SEALED_PDF_SHA256 = (Sha256, NotHashed, "oneiron.blob_artifact.sealed_pdf_sha256.v1");
}
