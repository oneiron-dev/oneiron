//! Purposes of the credential broker (`oneiron-broker`; ARCH-0069 `#broker-digest`).
//!
//! A request digest is not stored, but it crosses a process boundary: the daemon takes it
//! and sends it in the call's header, and the broker takes it again over the bytes it
//! received and sends nothing whose digest differs. A daemon and a broker on two builds
//! must agree on it, so each keeps its bytes (K, PLAN-UC-04 4.2). Every digest is BLAKE3
//! derive-key with the tag as the context; each field is framed by its length as a u64
//! little-endian, and each count and number is a bare u64 little-endian.

purposes! {}

legacy_purposes! {
    /// A model call's request digest (`digest::request_digest`, `CallHeader.digest`). The
    /// method; the path; the count of the non-auth headers; each header's lowercase name
    /// and its value, sorted; the body.
    REQUEST = (Blake3, DeriveKeyContext, "oneiron-broker 2026-10-11 request digest v1");

    /// A git exchange's request digest (`git_http::GitRequestDigest`). The repository's
    /// origin and path; the service; the exchange (`advertisement` or `rpc`); the method;
    /// the path and query; the count of the non-auth headers; each header's lowercase name
    /// and its value, sorted; the body's length; the body's bytes, unframed.
    GIT_REQUEST = (Blake3, DeriveKeyContext, "oneiron-broker 2026-11-06 git request digest v1");

    /// An LFS exchange's request digest (`lfs_http::LfsRequestDigest`). The target's kind;
    /// the repository's origin and path; a batch's operation, or an action's batch digest,
    /// object id and size; the method; the endpoint; the count of the headers; each
    /// header's name and value, in the order given; the body's length; the body's bytes,
    /// unframed.
    LFS_REQUEST = (Blake3, DeriveKeyContext, "oneiron-broker 2026-11-06 lfs request digest v1");
}
