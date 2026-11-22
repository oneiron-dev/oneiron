//! Purposes of repository mutations (`crates/oneiron/src/repo_mutation`).
//!
//! An owner's code proposal records one `repo.provenance` claim, which stores the request's
//! hash and the staged change's content hash. So both keep their bytes (K, PLAN-UC-04 stage
//! 6.4e).

purposes! {}

legacy_purposes! {
    /// A native bundle's content hash (`proposal::owner_request`, `StagedChange::bundle`):
    /// plain BLAKE3 of the sorted JSON of the bundle's paths in byte order, each as
    /// `{"path", "content_hash"}` with its new bytes' BLAKE3 hex or null for a removal, with
    /// no tag or length; lowercase hex. The claim's derivation envelope stores it, and the
    /// request's hash covers it.
    OWNER_BUNDLE = (Blake3, NotHashed, "oneiron.repo_mutation.owner_bundle.v1");

    /// An owner request's hash (`proposal::owner_request`, `attribute_owner_request`): plain
    /// BLAKE3 of the sorted JSON of its hash input (version, verb, actor, session, input,
    /// repository pointer, base commit and the staged content hash), with no tag or length;
    /// lowercase hex. The claim stores it as `request_hash`.
    OWNER_REQUEST = (Blake3, NotHashed, "oneiron.repo_mutation.owner_request.v1");
}
