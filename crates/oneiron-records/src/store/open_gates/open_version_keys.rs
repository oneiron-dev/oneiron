//! Moved from `crates/oneiron/src/store/open_gates/open_version_keys.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub const MAX_DBS: u32 = 32;

/// v41 (row SEQ-FLOOR-S-WITHHELD-COSIGN; RULING
/// SEQ-FLOOR-S-WITHHELD-COSIGN-SHAPE = A): stored authority-log rows keep
/// their bytes and change meaning. A granting row the fold counts as a fork
/// of its signer's sequence (its `SequenceFork` recorded) whose signer or
/// any cosigner the final roster holds revoked expires at once: a binding
/// or rebinding goes Revoked unless a live row renews the same tuple, a
/// federation confirm other than a revoke and a critical-write clearance
/// leave the live fold, and an owner handover or a residence directive
/// leaves the valid rows, so it is no handover evidence and no machine lists
/// it. A federation pact's Connect, Rescope or Promote leaves the valid rows
/// too, and the pact it still shapes (its ceiling, or a narrowing that
/// stands) is held suspended, its grant still bound to it. Before, a binding
/// or a confirm counted until the stale-roster window ended, and a handover,
/// a directive or a pact's row for ever. A stored checkpoint image
/// keeps its bytes and still decodes: it holds the fold before this
/// projection, which its adopter applies over the rows it carries whole, so
/// the authority fold schema stays 51. No old-meaning reader or migration is
/// provided (the lead's M-1 stored-change rule, path "loud").
///
/// v40 (row RESTORED-COPIES-ENROL-EACH-OTHER; RULING RESTORED-COPIES-JOIN-SCOPE
/// = A): a restore that drops its image's machine identity on a vault the
/// owner roots, and an archived vault's activation, write the install-local
/// row `m:restored_from`, and the install's machine profiles name that image
/// (a new optional `restored_from` key, signed under the v2 machine proof).
/// The authority fold holds such a machine's act-free enrolment, standing
/// for nothing, until an entry signed by a joined machine descends from it.
/// Stored authority-log rows keep their bytes and their meaning: a profile
/// without the key reads as a machine that never restored, as before. A
/// stored checkpoint image written before it no longer decodes (the
/// authority fold schema moves 50 -> 51 with it). No old-meaning reader or
/// migration is provided (the lead's M-1 stored-change rule, path "loud").
///
/// v39 (FIX FOREIGN-ANCHOR-CHAIN-COUNTS-IN-EVERY-CHAIN-PREDICATES, site S1,
/// and FIX FOREIGN-ANCHOR-ADMIT-SIDE): stored authority-log rows keep their
/// bytes and change meaning. Only the roster's chain admits or removes an
/// owner act's carrier: an act whose carrier an anchor chain, and not the
/// roster's, marked removed at the act's parents was refused and now
/// stands, and an act whose carrier only an anchor chain admitted stood and
/// is now refused. Every other judge all installs share reads the roster's
/// chain alone too (Fable pass 29, step K3): an owner key's enrolment, a
/// residence result's signer, a one-machine read pick, and the ten owner-act
/// gates that ask whether a machine's chain names the signing key no longer
/// count an anchor's chain, so such a row that only an anchor's chain
/// supported is now refused, and one an anchor's removal mark refused now
/// stands. A one-machine read pick now needs the target's live roster head
/// in any role, not "yours" in some chain: a pick of a linked machine the
/// owner has not answered "yours" was refused and now stands ("yours" is
/// the writer's check under its pin). A stored checkpoint image written
/// before it holds the old answers and no longer decodes (the authority fold
/// schema moves 49 -> 50 with it). No old-meaning reader or migration is
/// provided (the lead's M-1 stored-change rule, path "loud").
///
/// v37 (row OWNER-ANCHOR-ROOT-RECOVERY, FIX OWNER-ANCHOR-NO-ROOT-RECOVERY): the
/// authority fold schema moves 44 -> 45, and a stored checkpoint image
/// written before it no longer decodes. The fold names a roster with no live
/// root key (`NoRootKey`), and it counts a root appointment that the pinned
/// root's anchor signed: the appointment's line folds as its own ancestry's
/// fold did. Stored authority-log rows keep their bytes. No old-meaning
/// reader or migration is provided (the lead's M-1 stored-change rule, path
/// "loud").
///
/// v36 (row WEB-PASSKEY-OWNER-KEY, owner passkeys): stored authority-log rows
/// keep their bytes and meaning. The authority fold gains each enrolled
/// passkey's assertion contexts, each key a passkey vouched for and each such
/// key a second vouch confirmed, so the authority fold schema moves 43 -> 44
/// with it: a stored checkpoint image written before it no longer decodes,
/// and an older build refuses an image that carries them rather than dropping
/// the passkey limits. No old-meaning reader or migration is provided (the
/// lead's M-1 stored-change rule, path "loud").
///
/// v35 (FIX SEQUENCE-FLOOR-DELIVERY-ORDER, CHECKPOINT-RAW-FLOOR-CLEARED-ROW):
/// stored authority-log rows keep their bytes and can change meaning. A
/// row's sequence floor comes from its signer's rows in its scope, not from
/// the order they arrived in, and no row is refused for its floor: a granting
/// row below it counts in full and the fold records its signer's fork as a
/// `SequenceFork` issue. An install that already holds a forked signer's rows
/// can fold them differently than before. A stored checkpoint image written
/// before it no longer decodes (the authority fold schema moves with it). No
/// old-meaning reader or migration is provided (the lead's M-1 stored-change
/// rule, path "loud").
///
/// v34 (row HOSTED-ROOT-REVOKES-OWNER-KEY): stored authority-log rows keep
/// their bytes and change meaning. A `RevokeDevice` of an owner key counts
/// only with an owner key's proof, as its signer or a cosign, so a revoke the
/// custodial root signed alone (a hosted membership move's, or one written by
/// hand) is refused, the key stays live, and every row above the revoke is
/// refused with it (a refused revoke is no row the fold crosses). The
/// authority fold schema moves 41 -> 42 with it. No old-meaning reader or
/// migration is provided (the lead's M-1 stored-change rule, path "loud").
///
/// v33 (row CARRIER-OWNER-PROOF, FIX CARRIER-SELF-ANSWER-MINE): stored
/// authority-log rows keep their bytes and change meaning. A carried machine
/// answer that makes a machine the owner's stands only with an owner key's
/// proof cosign, so every such answer a vault already holds (each paired
/// machine) folds as held, not mine, until the owner confirms it on an owner
/// device. The authority fold schema moves 40 -> 41 with it. No old-meaning
/// reader or migration is provided (the lead's M-1 stored-change rule, path
/// "loud").
///
/// v32 (row REVOKE-FENCE, FIX REVOKED-OWNER-ROOT-SIBLING-ENROL): stored
/// authority-log rows keep their bytes and change meaning. A `RevokeDevice`
/// retires its key on every branch, so a row that key signed outside the
/// revocation's own ancestry (a withheld enrolment, say) stood and is now
/// refused with every row above it. The authority fold schema moves 39 -> 40
/// with it, and a stored checkpoint image written before it no longer
/// decodes. No old-meaning reader or migration is provided (the lead's M-1
/// stored-change rule, path "loud").
///
/// v31 (FIX ARRIVAL-FLOOR-SIBLING-DIVERGENCE): stored authority-log rows keep
/// their bytes and can change meaning. No arrival floor refuses a roster row,
/// and a roster row vouches for its own signer's rows below it that this
/// install's arrival floor refused, so an install that already holds a forked
/// signer's rows can fold more of them than before. No old-meaning reader or
/// migration is provided (the lead's M-1 stored-change rule, path "loud").
///
/// v30 (FIX CONFIRM-COLLISION-SUBTREE-ROLLBACK, federation confirmations):
/// stored authority-log rows keep their bytes and change meaning. Of two
/// concurrent federation confirmations that share an id or a nonce, the
/// higher hash and every row above it were refused; now both stand as spent
/// evidence and no row falls with either. A stored checkpoint image written
/// before it holds the old losses and no longer decodes (the authority fold
/// schema moves with it). No old-meaning reader or migration is provided
/// (the lead's M-1 stored-change rule, path "loud").
///
/// v29 (FIX CONFIRM-COLLISION-SUBTREE-ROLLBACK, device revocation): stored
/// authority-log rows keep their bytes and change meaning. A `RevokeDevice`
/// proved on its own signed branch now holds as a revoke fact when a
/// confirmation collision drops the branch it sits on, so the key it revoked
/// stays revoked. A stored checkpoint image written before it lacks those
/// facts and no longer decodes (the authority fold schema moves with it). No
/// old-meaning reader or migration is provided (the lead's M-1 stored-change
/// rule, path "loud").
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
pub const STORAGE_ABI_VERSION: u16 = 41;

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
