//! Legacy sync digests stored, sent or compared by existing records and peers.
//!
//! Handoffs, peer origins, quota keys, quarantine identities, search revisions,
//! sealed-bundle work, settlement reviews and window-pad envelope ids retain
//! their exact bytes through the K door (K, PLAN-UC-04 stage 7).

purposes! {}

legacy_purposes! {
    /// Election basis: the tag (including its final NUL), 32-byte vault id,
    /// then from, to and home nodes, each None as `[0]` or Some as `[1]` and
    /// a u64-BE node; elected_at as u64-BE (zero without home), 16-byte target
    /// machine id, then target node as u64-BE. Stored in signed, sealed HomeMove.
    ELECTION_BASIS = (Blake3, HashedFirst, "oneiron/home-handoff/election-basis/v1\0");

    /// Quota peer: the tag, `[0]`, raw suite bytes, `[0]`, raw public-key bytes,
    /// without lengths. Stored in sync_queue's m:maintenance_ingest_quota:v1:
    /// key. Redaction uses ed25519 plus 32 bytes; topology uses
    /// identity-topology-stream plus the lease vault id as u64-BE.
    MAINTENANCE_INGEST_QUOTA_PEER = (Blake3, HashedFirst, "oneiron/maintenance-ingest-quota/v1/peer");

    /// Office divergence: under the derive-key context, the held and carried
    /// copies sorted by byte order, each as a u64-LE byte length then raw bytes.
    /// Compared as the dedup identity of the OfficeProposals quarantine row.
    OFFICE_PROPOSAL_DIVERGENCE = (Blake3, DeriveKeyContext, "oneiron.office_proposals.divergence.v1");

    /// ASSET origin: raw ENTITY_METADATA_HEADER_LEN header bytes, 32-byte body
    /// BLAKE3, body length as u64-BE, then xxh32 as u32-BE. No hashed tag or
    /// lengths before the header or digest; the tag is a registry name only. Stored in bytes
    /// 32..64 of the PEER_ORIGIN record, compared for peer-origin judgments.
    PEER_ASSET_ORIGIN = (Blake3, NotHashed, "oneiron.sync.peer_asset_origin.v1");

    /// Search page: the tag; query UTF-8, limit as u64-BE, selector wire bytes,
    /// recall-scope transcript, as_of as u64-BE, then optional filter transcript,
    /// each with a u64-BE byte length. Then each ranked hit's raw 16-byte id,
    /// window's u64-BE UTF-8 length and UTF-8 bytes. Lowercase hex is sent as
    /// page.revision and compared to detect search_changed; scores are excluded.
    RESIDENCE_SEARCH_PAGE = (Blake3, HashedFirst, "oneiron.residence.search.page.v1");

    /// Bundle work: under the derive-key context, home presence byte and optional
    /// raw 16-byte id, executor's raw 16-byte id, generation's u64-BE slot and
    /// 16-byte nonce (24 bytes), parent presence byte and optional generation
    /// in that same 24-byte layout; root then request, each a presence
    /// byte and optional 32 bytes; then bundle and pads, each u64-BE length and
    /// 32-byte digest. Stored as the durable WORK key and compared to known_id.
    SEALED_BUNDLE_WORK_ID = (Blake3, DeriveKeyContext, "oneiron sealed bundle commit work v1");

    /// Settlement uses one derive-key context for two existing layouts.
    /// Approval: 32-byte revision, replacement's u64-BE UTF-8 length and bytes;
    /// compared in the setter before writing. Revision: raw 16-byte source id,
    /// incarnation and source text each as u64-BE UTF-8 length then bytes,
    /// canonical source vector, 32-byte copy stamp, 32-byte blob, canonical
    /// lineage vector, submitted text and cause.as_str() each as u64-BE UTF-8
    /// length then bytes. Each vector is its u64-BE pair count and numerically
    /// sorted (peer, counter) pairs, written as u64-BE peer then i32-BE counter.
    /// Revision hex is sent to the owner and compared before settlement. Neither
    /// layout grants authority.
    SETTLEMENT_REVIEW = (Blake3, DeriveKeyContext, "oneiron.repo-sync-settlement.review.v1");

    /// Typed-body divergence: under the derive-key context, held and carried
    /// copies sorted by byte order, each as a u64-LE byte length then raw bytes.
    /// Compared as the TypedBodyRows quarantine dedup identity (its xxh64 is
    /// persisted in the quarantine key); not the office proposal context.
    TYPED_BODY_DIVERGENCE = (Blake3, DeriveKeyContext, "oneiron.typed_body_rows.divergence.v1");

    /// Envelope id: only raw window-pad header-prefix bytes (202 bytes at the
    /// production call), no tag or length. The tag is a registry name only.
    /// Stored in Pending.id and compared against continuation frame ids.
    WINDOW_PAD_ENVELOPE_ID = (Blake3, NotHashed, "oneiron.sync.window_pad_envelope_id.v1");
}
