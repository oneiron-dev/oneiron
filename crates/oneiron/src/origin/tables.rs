//! The side tables `origin` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Owner-controlled origin residence/epoch/writer authority for one repository. Key: id16.
    ORIGIN_AUTHORITY: VaultMeta b"origin:authority:v1:" Named
        [restore: refuse "repository origin authority"] [family: unclassified] [tier: canonical]
        => crate::origin::residence::erase_origin_authority_writer_in_txn;
    /// Epoch-bound publication permit stamp (u64be epoch), authorizing one publication under the
    /// current authority epoch. Key: id16.
    ORIGIN_AUTHORITY_PERMIT: VaultMeta b"origin:authority_permit:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Compare-and-swap ownership claim binding one (repo, ref, old_oid, new_oid) triple to its
    /// owning publication id (value = id16): in flight while Prepared, consumed for good once
    /// Published. Key: id16 "\x00" string "\x00" string "\x00" string.
    ORIGIN_CAS_INTENT: VaultMeta b"origin:cas_intent:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Tamper-detection proof hash (32 bytes) pinning one repo.change claim's exact byte content at
    /// publication time, or its erased form once an actor's erase re-hashed it. Key: id16.
    ORIGIN_CHANGE_RECEIPT: VaultMeta b"origin:change_receipt:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Crash-idempotent receipt of the file operations one push landed against one ref, keyed by
    /// provenance then blake3(ref_name). Key: id16 ":" hash32.
    ORIGIN_CODE_OPERATIONS: VaultMeta b"origin:code_operations:v1:" LegacyCompact
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::origin::erase_code_operations_actor_in_txn;
    /// Marker (empty): one retained received ref of an object store that the candidate intake
    /// still reads, unresolved or resolved from a masked copy (FIX 7535). Key: hash32 (the store)
    /// + id16 (the push provenance) + hash32 (blake3 of the ref name).
    ORIGIN_CODE_PENDING: VaultMeta b"origin:code_pending:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Marker (empty): a received ref of an object store resolved to a candidate with this
    /// incoming tip (FIX 7535). Key: hash32 (the store) + string (the tip's hex).
    ORIGIN_CODE_RESOLVED_TIP: VaultMeta b"origin:code_resolved_tip:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Stable Git commit projection (oid hex text) of one finalized engine CodeRevision. Key: string
    /// ":" id16.
    ORIGIN_ENGINE_EXPORT: VaultMeta b"origin:engine_export:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One logical owner's reservation of a physical git keep-ref (value = u64be learned_at),
    /// reference-counting when the object may be released. Key: id16 "\x00" string "\x00" string
    /// "\x00" string.
    ORIGIN_KEEP_OWNER: VaultMeta b"origin:keep_owner:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Marks an ASSET entity as an internal LFS chunk and records its content hash (32 bytes). Key:
    /// id16.
    ORIGIN_LFS_CHUNK_MARK: VaultMeta b"origin:lfs:chunk:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Queue (empty marker) of upload owners whose chunk references are pending garbage collection.
    /// Key: id16.
    ORIGIN_LFS_GC_QUEUE: VaultMeta b"origin:lfs:gc:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Crash-recoverable heartbeat journal (oid32+timestamp8, 40 bytes) for one in-progress streamed
    /// LFS upload. Key: id16.
    ORIGIN_LFS_UPLOAD_JOURNAL: VaultMeta b"origin:lfs:upload:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The last finished Git-LFS census of one repository's mirror pushes (FIX
    /// 6331): the tips it walked, the commit each peels to, every LFS object
    /// under them in the order met, and whether the history needed pages. A
    /// cache: a miss walks the whole history again. Runtime-tier. Key: id16
    /// (repo id).
    ORIGIN_MIRROR_LFS_CENSUS: VaultMeta b"origin:mirror_lfs_census:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// The owner's outbound mirror of one served repository: its https URL, the custody record of
    /// its push token, the cadence and the last push. Key: id16 (repo id).
    ORIGIN_MIRROR_TARGET: VaultMeta b"origin:mirror_target:v1:" Named
        [restore: refuse "repository mirror targets"] [family: unclassified] [tier: canonical];
    /// One mirror's automatic push work (FIX 6866): its head (open plan, failed reconcile reads,
    /// kept plans) and each frozen MirrorPushPlan with its review pages and per-batch progress.
    /// LIVE. Key: id16 (repo id) + id16 (repo id again, then `head`; or a plan id, then nothing
    /// for the plan, `p` + u64be for a review page or `b` + u32be for a batch).
    ORIGIN_MIRROR_WORK: VaultMeta b"origin:mirror_work:v1:" Named
        // Restore class: A mirror's automatic push plans (FIX 6866) record what left the vault and
        // how far each plan got: they stay as the live vault holds them, so a restore never revives
        // an unsent batch or resends a settled one. A plan whose objects a restore took fails its
        // push, and its reconcile settles it.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::origin::publish::erase_mirror_work_actor_in_txn;
    /// Durable journal row for one origin ref-publication attempt, across its
    /// Prepared/Published/Failed/Conflicted lifecycle. Key: id16.
    ORIGIN_PUBLICATION_RECORD: VaultMeta b"origin:publication:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::origin::publication::erase_publication_actor_in_txn;
    /// One exact publish request to a repository's mirror (FIX 6866): its tuple, state, acts and
    /// refusal, and beside it the pages of its full-ancestry review. LIVE. Key: id16 (repo id) +
    /// id16 (request id), then nothing for the request or u64be for one review page.
    ORIGIN_PUBLISH_REQUEST: VaultMeta b"origin:publish_request:v1:" Named
        // Restore class: An exact publish request (FIX 6866) records an act whose effect left the
        // vault: it stays as the live vault holds it, so a request made after a checkpoint never
        // refuses that checkpoint's restore, and no restore unspends a push (CALLS "FIX 6866
        // restore class"). A request whose commit a restore took refuses at dispatch, not here.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::origin::publish::erase_publish_request_actor_in_txn;
    /// Producer receipt pinning the exact encoded admission/outcome evidence claim body for one
    /// receive-pack operation. Key: id16.
    ORIGIN_RECEIVE_PACK_EVIDENCE: VaultMeta b"origin:receive_pack_evidence:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::origin::smart_http::erase_receive_pack_evidence_actor_in_txn;
    /// Crash-durable per-push intent journal recording every proposed ref move before any effect
    /// lands, keyed by repo identity then operation id. Key: string + id16.
    ORIGIN_RECEIVE_PACK_INTENT: VaultMeta b"origin:receive_pack_intent:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::origin::smart_http::erase_receive_pack_intent_actor_in_txn;
    /// One batch of a push intent's per-ref progress, so settling a batch rewrites that batch
    /// alone. Key: string + id16 (the intent's key) + u64be (batch index).
    ORIGIN_RECEIVE_PACK_PROGRESS: VaultMeta b"origin:receive_pack_progress:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Index (empty marker) of each received ref update by its exact (store, ref, old, new),
    /// so an import finds its receive by key, never by a walk of the store's receipts (FIX
    /// 7595). Key: hash32 (the update) + id16 (the push provenance).
    ORIGIN_RECEIVED_UPDATE: VaultMeta b"origin:received_update:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The publication currently advertised for one repository's ref name (value = id16). Key: id16
    /// "\x00" string.
    ORIGIN_VISIBLE_REF: VaultMeta b"origin:visible_ref:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A source record a derived text was written from that a repo mark covered by its media
    /// bytes, not its id, bound to that blob's whole BLAKE3, so it stays marked once erased as a
    /// snapshot record does (FIX 10887). A hash, no value. Key: id16 (the source).
    REPO_DERIVED_SOURCE_BLOB: VaultMeta b"repo_index:derived_source_blob:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 6870: the portable repo id that stands for one CODE entity (value = 32 bytes). Key:
    /// id16 (CODE entity).
    REPO_MANIFEST_BY_CODE: VaultMeta b"repo_manifest:by_code:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 6870: a portable repo id this machine minted, the refs writer while no origin
    /// authority is held; empty value. Key: 32 bytes (portable id).
    REPO_MANIFEST_MINTED: VaultMeta b"repo_manifest:minted:v1:" Raw
        // Restore class: A restore never makes this machine a repo's refs writer again (FIX 6870).
        [restore: live] [family: unclassified] [tier: canonical];
    /// FIX 6870: one repo's portable manifest: its CODE entity, visible refs, LFS pointers and
    /// origin epoch. Key: 32 bytes (portable id).
    REPO_MANIFEST: VaultMeta b"repo_manifest:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
