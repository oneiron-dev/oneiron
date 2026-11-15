//! Moved from `crates/oneiron/src/store/open_gates/open_version_keys.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub const MAX_DBS: u32 = 32;

/// v29 (FIX FOREIGN-ANCHOR-CHAIN-COUNTS-IN-EVERY-CHAIN-PREDICATES, site S1):
/// stored authority-log rows keep their bytes and change meaning. An owner
/// act whose carrier some anchor chain, and not the roster's, marked
/// removed at the act's parents was refused; now it stands. A stored
/// checkpoint image written before it holds the old refusals and no longer
/// decodes (the authority fold schema moves with it). No old-meaning reader
/// or migration is provided (the lead's M-1 stored-change rule, path
/// "loud").
///
/// v28 (FIX 7114): attempt record version 5 distinguishes a workflow tool's
/// verb-hook pause from a person's pause and the other engine holds. The
/// hook invocation is retained on the pause; only that hold can auto-resume.
/// No old-format reader or migration is provided.
///
/// v26 (FIX 10898): attempt record v4 requires each requeue-history entry
/// to carry its failure count and latest instant. No old-format reader or
/// migration is provided.
///
/// v25 (FIX 7831, ARCH-0058): WORKFLOW moved from byte 18 to byte 43,
/// inside its declared AgentsAndSurfacing family (40-49); short-id prefix
/// `wf` is unchanged. ABI 24 vaults fail closed at the ABI gate — there is
/// no migration pass; rebuild the vault.
///
/// v23 (OF-190 B++ 2C): the `context:output:v1:` blob family is gone; a
/// context output is a body of the `code_run:raw_output:v1:` family, keyed by
/// its content. A step records its provider reply as evidence, and a verb
/// answer too large for one reply is a stored body whose handle the bridge
/// row carries. ABI 22 vaults fail closed at the ABI gate; there is no
/// migration.
///
/// v22 (OF-597, OF-190 B++): a code-mode result body past
/// `[limits] code_result_inline_bytes` is a file in `bodies/` beside
/// `data.mdb`, named by its BLAKE3; the `code_run:raw_output:v1:` row holds
/// the body inline or the length of that file, and the replay record's output
/// manifest carries the BLAKE3, kind, line count and completion. Checkpoint
/// images list and carry the body files. ABI 21 vaults fail closed at the ABI
/// gate; there is no migration.
///
/// v21: every deterministic id is derived by one rule, `EntityId::derive`
/// (BLAKE3 derive-key over the domain, length-prefixed parts, UUID version 8).
/// Ids derived before it (the owner PERSON and its facets, bootstrap skills,
/// projector claims, home rooms, ask records, calendar and connector actors)
/// no longer match what this engine derives. The same version writes a pact
/// world set holding only the base world as `base` (it had two spellings), so
/// an authority-log entry or slip carrying the old `worlds` spelling is
/// refused where its bytes are re-encoded and compared. ABI 20 vaults fail
/// closed at the ABI gate — there is no migration pass; rebuild the vault.
///
/// v20: the pairing link row stores an 8-character code hashed at rest with
/// the server origin and the intended holder in place of the 64-hex ticket,
/// and the replay table holds one row per admitted proof, bounded by the
/// request timestamp window. ABI 19 vaults fail closed at the ABI gate — there
/// is no migration pass; rebuild the vault.
///
/// v19 (Wave 7): stored meanings changed with no version move — SlipMint
/// authority rows, the esign `ResealRequested` event, `conversation.summary`
/// covers and old room threads, the append pin for unmigrated records, and
/// the new SESSION, ASSET and SUMMARY indexes, which have no backfill. Every
/// NOTE and ASSET now carries one birth `FacetOf` stamp, the vault default
/// facet is a `vault.default_facet` claim on the owner, and a NOTE's head
/// pointer and head sequence are stored beside its documents. ABI 18 vaults
/// fail closed at the ABI gate — there is no migration pass; rebuild the
/// vault.
///
/// v18 (OF-494, ARCH-0058): byte-space v3.1 family reflow. Exactly ABI 17
/// migrates, in one transaction over entity envelopes, type_index, sid_counter
/// and kind_reg. Sources are staged before any deletes; ABI 16 and older fail
/// closed. No v3 migration branch or pre-v3 registration decoder remains.
///
/// v16 (ONE-1732, ARCH-0052 P7): the off-record fence families were removed
/// from the vault contract. Off-record state is session-ephemeral — it lives
/// in a process-local overlay and reaches no named database or `vault_meta`
/// row — so the durable fence rows v11 introduced, and the open/recovery
/// semantics that read them, no longer exist. A v15 vault may still carry
/// those rows, and this engine has no code that understands them, so v15
/// vaults fail closed at the ABI gate — there is no migration pass; rebuild
/// the vault.
///
/// v15 (ONE-1743): IDENTITY_TOPOLOGY_EVENT was registered as a persistent,
/// delete-protected maintenance entity type byte 76 — the engine-authored
/// merge/split ledger (ARCH-0055). v14 readers do not know this persistent
/// entity kind and would not protect it from deletion, so v14 vaults fail closed
/// at the ABI gate — there is no silent migration; rebuild the vault.
///
/// v14 (ONE-1741): SKILL_CONTENT_ANCHOR was registered as persistent maintenance
/// entity type byte 138 — the immortal subject that content-global scan verdicts
/// anchor to. v13 readers do not know this persistent entity kind and would not
/// protect it from deletion, so v13 vaults fail closed at the ABI gate — there is
/// no silent migration; rebuild the vault.
///
/// v13 (ONE-1387): type-0 CLAIM bodies gained the optional `sess` key for
/// actor-bound session review bundles. v12 readers reject these bodies, so
/// vaults carrying session-tagged claims must fail closed at the ABI gate.
///
/// v11 (ONE-1576): off-record fence state became a supported vault contract.
/// v10 readers do not know the fence semantics, so v10 vaults fail closed at
/// the ABI gate — there is no silent downgrade that could expose fenced rows.
///
/// v10 (ONE-1443): AGENT_DEF was registered as a persistent CORE entity type
/// byte 17. v9 readers do not know this persistent entity kind, so v9 vaults
/// fail closed at the ABI gate — there is no silent migration; rebuild the
/// vault.
///
/// v9 (ONE-1530): OUTBOUND_GRANT was registered as persistent maintenance
/// entity type byte 133. v8 readers do not know this persistent entity kind,
/// so v8 vaults fail closed at the ABI gate — there is no silent migration;
/// rebuild the vault.
///
/// v8 (ONE-1213): attempt queue rows gained durable terminal states (`Completed`
/// and `Failed`) plus retry backoff metadata. v7 queue readers only understand
/// `Queued`/`Leased`, so v7 vaults fail closed at the ABI gate — there is no
/// silent migration; rebuild the vault.
///
/// v7 (ONE-1206): generic LMDB-backed attempt queue landed as three named DBs:
/// `job_records`, `job_ready`, and `job_dedupe`. v6 vaults fail closed at
/// the ABI gate — there is no silent migration; rebuild the vault.
///
/// v6 (ONE-1204): PSYCH_PROFILE was registered as persistent maintenance
/// entity type byte 129. v5 vaults fail closed at the ABI gate — there is no
/// silent migration; rebuild the vault.
///
/// v5 (ONE-1293): maintenance-band bytes were realigned so byte 122 is
/// reserved for AUTHORITY_LOG, POLICY_MANIFEST is 123, and FEDERATION_GRANT is
/// 124. v4 vaults fail closed at the ABI gate — there is no silent migration;
/// rebuild the vault.
///
/// v4 (ONE-299): `text_postings` became a DUP_SORT database holding one
/// posting entry per (term, entity) duplicate item, and `text_forward`
/// records dropped the dead `tf` u32.
///
/// Receipt-family ABI-pin rule: changing
/// `GATE_DECISION_LEDGER_VERSION`, `ATTEMPT_RECORD_VERSION`,
/// `PENDING_GATE_CONSENT_VERSION`,
/// `PENDING_GATE_CONSENT_INDEX_STATE_VERSION`, or
/// `RECEIPT_FAMILY_INDEX_VERSION` requires bumping this version too.
/// v27 hashes full run/group identifiers in their v2 secondary-index keys.
/// v26 is reserved for the separately landing attempt-record v4 format.
pub const STORAGE_ABI_VERSION: u16 = 29;

pub const STORAGE_SCHEMA_VERSION: u16 = 1;

/// Version of the pinned DB-manifest shape surfaced in whole-vault exports.
pub const DB_MANIFEST_VERSION: u16 = 2;

/// Oneiron DB manifest derived from the ARCH-0019 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbManifestEntry {
    pub n: u8,
    pub name: &'static str,
    pub group: &'static str,
}

pub const DB_MANIFEST: [DbManifestEntry; 28] = [
    DbManifestEntry {
        n: 1,
        name: "entities",
        group: "Core",
    },
    DbManifestEntry {
        n: 2,
        name: "type_index",
        group: "Core",
    },
    DbManifestEntry {
        n: 3,
        name: "short_ids",
        group: "Core",
    },
    DbManifestEntry {
        n: 4,
        name: "short_ids_reverse",
        group: "Core",
    },
    DbManifestEntry {
        n: 5,
        name: "vault_meta",
        group: "Core",
    },
    DbManifestEntry {
        n: 6,
        name: "vectors",
        group: "Vector",
    },
    DbManifestEntry {
        n: 7,
        name: "hnsw_neighbors",
        group: "Vector",
    },
    DbManifestEntry {
        n: 8,
        name: "hnsw_meta",
        group: "Vector",
    },
    DbManifestEntry {
        n: 9,
        name: "text_postings",
        group: "Text",
    },
    DbManifestEntry {
        n: 10,
        name: "text_meta",
        group: "Text",
    },
    DbManifestEntry {
        n: 11,
        name: "text_forward",
        group: "Text",
    },
    DbManifestEntry {
        n: 12,
        name: "text_bm25_field_stats",
        group: "Text",
    },
    DbManifestEntry {
        n: 13,
        name: "text_doc_field_lengths",
        group: "Text",
    },
    DbManifestEntry {
        n: 14,
        name: "edges_out",
        group: "Graph",
    },
    DbManifestEntry {
        n: 15,
        name: "edges_in",
        group: "Graph",
    },
    DbManifestEntry {
        n: 16,
        name: "ppr_cache",
        group: "Graph",
    },
    DbManifestEntry {
        n: 17,
        name: "ppr_cache_deps",
        group: "Graph",
    },
    DbManifestEntry {
        n: 18,
        name: "temporal_occurred_start",
        group: "Temporal",
    },
    DbManifestEntry {
        n: 19,
        name: "temporal_occurred_end",
        group: "Temporal",
    },
    DbManifestEntry {
        n: 20,
        name: "temporal_learned",
        group: "Temporal",
    },
    DbManifestEntry {
        n: 21,
        name: "temporal_long_intervals",
        group: "Temporal",
    },
    DbManifestEntry {
        n: 22,
        name: "phonetic_index",
        group: "Phonetic",
    },
    DbManifestEntry {
        n: 23,
        name: "phonetic_forward",
        group: "Phonetic",
    },
    DbManifestEntry {
        n: 24,
        name: "sync_state",
        group: "Sync",
    },
    DbManifestEntry {
        n: 25,
        name: "sync_queue",
        group: "Sync",
    },
    // Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code
    // only. Group strings are embedded in export manifests and validated
    // exactly on import, so they are wire too.
    DbManifestEntry {
        n: 26,
        name: "job_records",
        group: "Jobs",
    },
    DbManifestEntry {
        n: 27,
        name: "job_ready",
        group: "Jobs",
    },
    DbManifestEntry {
        n: 28,
        name: "job_dedupe",
        group: "Jobs",
    },
];
