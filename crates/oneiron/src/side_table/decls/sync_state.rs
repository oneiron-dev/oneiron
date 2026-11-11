// Declared `sync_state` tables (string keys), in prefix order.

side_tables! {
    /// A file-plane ASSET body this machine received from its home (FIX 14534): the home
    /// machine (16 bytes), the carrier's BLAKE3 (32), the body's BLAKE3 (32) and its length
    /// (u64be), written in the own-device client's landing commit. The owner's discard of a
    /// world copy releases the ASSET's file only while its manifest names that body and the
    /// row stands at the revision (16 bytes, last) the landing wrote. Runtime: never imaged,
    /// a restore drops it. Key: hex32 (ASSET id).
    SYNC_ASSET_BODY_FROM_HOME: SyncState b"ab:h:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Cached currency-converted spend budget limit for one owner/vault pair. Key: hex ":" hex
    /// (owner, vault).
    USAGE_BUDGET_LIMIT: SyncState b"budget:usage:rollup:vault:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// A sync window's document snapshot (document family). Key: yyyy-mm (window key).
    WINDOW_SNAPSHOT: SyncState b"d:w:" Raw
        [restore: content] [family: mixed WindowSnapshot] [tier: canonical];
    /// Deferred ChildOf candidate, keyed by window, source and target. Key: yyyy-mm ":" hex32 ":" hex32.
    DEFERRED_CHILD_OF: SyncState b"dc:w:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Endpoint index for a deferred ChildOf candidate. Key: hex32 ":" full dc:w: key.
    DEFERRED_CHILD_OF_ENDPOINT: SyncState b"de:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Owed `regenerates` link, keyed by window, source and target: the link's original encoded
    /// value (FIX 6204). Key: yyyy-mm ":" hex32 ":" hex32.
    DEFERRED_REGENERATES: SyncState b"dg:w:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Endpoint index for an owed `regenerates` link. Key: hex32 ":" full dg:w: key.
    DEFERRED_REGENERATES_ENDPOINT: SyncState b"dh:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Dependency index for a deferred Parent candidate. Key: kind ":" hex32 ":" full dp:w: key.
    DEFERRED_PARENT_DEPENDENCY: SyncState b"di:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Deferred Parent candidate, keyed by window, source and target. Key: yyyy-mm ":" hex32 ":" hex32.
    DEFERRED_PARENT: SyncState b"dp:w:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A row one federation pact's import brings, recorded before the import lands it, so the
    /// write that lands it after a crash (forward rematerialization) records it in
    /// `FEDERATION_DELIVERED_RECORD` (FIX 3498). It goes when its row lands or other bytes land
    /// there, and never expires. Local to this vault: never replicated or exported. Value: the
    /// pact id, its epoch and when it was recorded (u64 big-endian seconds each), then the blake3
    /// digest of the row's bytes. Key: hex32 (record id) ":" hex64 (pact id).
    FEDERATION_DELIVERY_INTENT: SyncState b"fedintent:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A sync window needs a full resync. Key: yyyy-mm.
    WINDOW_FULL_RESYNC_MARKER: SyncState b"fr:w:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable pin forcing a window to export as a history-free snapshot instead of ordinary Loro
    /// history. Key: yyyy-mm.
    SYNC_HISTORY_FREE_WINDOW: SyncState b"hfs:w:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Durable pending-mirror marker a local write leaves in its own transaction (FIX 7957, FIX
    /// 9599): the window owes the row's carrier, or the removal of the edge's key, until that
    /// change is durable there. Value: u64be stamp of the write. Key: window key ":" (hex32
    /// (entity id) | hex32 ":" kk ":" hex32 (edges-map key)).
    SYNC_PENDING_MIRROR: SyncState b"lm:w:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Local mirror of one device's REDACTION_AUDIT-stream lease-registry entry from the root doc's
    /// leases map. Key: hex16 (vault_id) ":" hex16 (client_id).
    SYNC_LEASE: SyncState b"ls:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Sweep refs a hard delete captured from a provenance Claim before its SoftErase emptied the
    /// body, and the ids of the rows an erase retired with the entity (FIX 7494), held until a
    /// purge queues its sweep; and the relayed ask intents a legal hold kept from the entity's
    /// erase, held until a due legal-hold pass retires them (FIX 20468). Key: hex32 (entity id).
    DELETION_PENDING_SWEEP_REFS: SyncState b"m:sr:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Configured thresholds for the wire call-volume observation counters. Key: ().
    RC42_WIRE_MANIFEST: SyncState b"manifest:rc42:wire-observation:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A target whose machine-claim history this machine is owed (FIX 3820): the windows its rows
    /// came in by, where the home's paging stopped and what the last try found. Key: hex32.
    SYNC_MACHINE_HISTORY_OWED: SyncState b"mh:owed:v1:" Named
        // Restore class: Owed history pairs with the `rm:w:` markers of the rows it holds.
        [restore: content] [family: unclassified] [tier: canonical];
    /// A model offer a provider refused for a quota or a limit, out of rotation until its reset
    /// (OF-305): this deployment's routing state, never replicated, and runtime to a checkpoint,
    /// which keeps none. Key: hex64 (blake3 of the offer's adapter, origin, key binding and wire
    /// model).
    MODEL_OFFER_COOLDOWN: SyncState b"models:offer-cooldown:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// The last response a provider kept (`store`, OF-602) for one conversation, and when it was
    /// written, so a reconnected Responses socket resumes the chain: this deployment's routing
    /// state, never replicated, and runtime to a checkpoint. Key: hex16 (blake3 of the provider's
    /// socket URL and key binding) ":" hex64 (blake3 of the conversation's item digests).
    MODEL_RESPONSES_CHAIN: SyncState b"models:responses-chain:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// One paired-machine mesh connection's path receipt (OF-535): direct or relayed, admitted,
    /// refused or failed; local only, never synced. Key: hex16 (open time, ms) hex32 (minted id).
    SYNC_MESH_PATH_RECEIPT: SyncState b"mp:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Digest of the project-depth birth contribution this vault minted locally. Key: hex32
    /// (contribution id).
    PROJECT_DEPTH_LOCAL_BIRTH: SyncState b"project:birth:local:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Source index for a deferred Parent candidate. Key: hex32 ":" full dp:w: key.
    DEFERRED_PARENT_SOURCE: SyncState b"ps:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable unacknowledged local text-document edit frame, cleared once the peer's VV proves
    /// receipt. Key: hex32 (entity id) ":" hex8 (sequence).
    SYNC_QD_E: SyncState b"qd:e:" Raw
        [restore: content] [family: mixed PendingEdit] [tier: canonical];
    /// Durable pending semantic NOTE-operation request, replayed until its receipt lands. Key: hex32
    /// (entity id) ":" hex32 (request id).
    SYNC_QN_E: SyncState b"qn:e:" Raw
        [restore: content] [family: mixed PendingNoteOperation] [tier: canonical];
    /// Late-joiner access to kept pad objects (FIX 4271): "q:" hex32 (machine) ":" hex64 (digest
    /// of its encryption key), an admission this vault queued for the home, no secret (0 queued,
    /// 1 acknowledged); and "g:" hex48 (generation) ":" hex32 ":" hex64, the home's custody of
    /// one grant of that generation's pad object outer key to that machine: 0 pending, or 1 ‖ the
    /// sealed grant. Key: string.
    SYNC_RESIDENCE_BUNDLE_ACCESS: SyncState b"rb:a:" Raw
        // Restore class: The sealed bundle's custody and cursors follow the live vault. So do the
        // late joiners' pad grants the home keeps with its generations, and the admissions queued
        // for it (FIX 4271). Request-bound publication pairs in the same table also stay LIVE,
        // sealed and generation-bound.
        [restore: live] [family: unclassified] [tier: canonical];
    /// A nonce the home's kit door took from a signed bundle fetch (FIX 922), kept a day past
    /// its signed time (empty marker). Key: u64hex16 (the signed time) ":" hex64 (the nonce).
    SYNC_RESIDENCE_BUNDLE_FETCH_NONCE: SyncState b"rb:n:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// The commit the home recorded for one owner's bundle publication request (FIX 4787), in the
    /// commit's own transaction, once the request counted here naming this home and the committing
    /// machine as its executor, or, while this home's fold had not seen the request, the commit's
    /// claim, checked when read (FIX 5554): 1 (checked) or 0 (claim) ‖ that machine (16) ‖ the
    /// generation (24) ‖ the bundle's digest (32), a ciphertext digest. It outlives the
    /// generation's retirement and goes once the request has its result here. Key: hex64 (the
    /// request's entry hash) ":" hex32 (the committing machine). Work records use
    /// "work:" hex64 with JSON immutable binding, detached source headers, phase,
    /// prepared/source/cleanup cursors and terminal receipt. "generation:" hex48
    /// stores the exact32-byte work id reserving unpublished stored parts.
    /// "stage-identity:" hex32 stores one zero byte until ordinary deletion
    /// or the work's whole cleanup finishes; an empty partial-cleanup prefix
    /// is not a reusable identity.
    SYNC_RESIDENCE_BUNDLE_COMMIT_RECEIPT: SyncState b"rb:r:" Raw
        // Restore class: So do the home's record of each asked commit and this machine's unresolved
        // publication attempts (FIX 4787).
        [restore: live] [family: unclassified] [tier: canonical];
    /// An upload of a bundle ("b") or pad object ("k") the home stages from parts until its
    /// commit: u64be vault second of its latest part ‖ generation (24) ‖ u64be total ‖ digest
    /// (32) ‖ u64be bytes staged ‖ immutable part identity (16),96 bytes total.
    /// Key: hex32 (the uploading machine) ":" b|k.
    SYNC_RESIDENCE_BUNDLE_STAGE: SyncState b"rb:s:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// The publisher turn of the vault's sealed bundle on the home (FIX 3351): u64be vault second
    /// the holder's turn runs from ‖ u64be count of machines whose turn lapsed ‖ each (FIX 4405):
    /// u64be slot it holds first ‖ that machine (16) ‖ each machine that asked for it (16), the
    /// holder first. Key: ().
    SYNC_RESIDENCE_BUNDLE_TURN: SyncState b"rb:t" Raw
        // Restore class: The publisher turn's queue is the home's record of whose turn is next
        // across slots, so it follows the live vault too (FIX 3351).
        [restore: live] [family: unclassified] [tier: canonical];
    /// One immutable upload part. Key: hex32 (the header's part identity) ":" hex16
    /// (offset). Detached work retains its parts independently of active handles.
    SYNC_RESIDENCE_BUNDLE_STAGE_PART: SyncState b"rb:u:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// The exact attempt this machine made to publish the vault's sealed bundle for one owner's
    /// request (FIX 4787), persisted before its commit: the home (16) ‖ this machine, the
    /// executor (16) ‖ the generation (24) ‖ the bundle's digest (32), a ciphertext digest. It
    /// stays, with no expiry and no count bound, until the request has its result here. Key:
    /// hex64 (the request's entry hash).
    SYNC_RESIDENCE_BUNDLE_ATTEMPT: SyncState b"rbc:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// This machine's sealed bundle cursor (FIX 922): the u64be UTC slot it last finished ‖ the
    /// generation (24) it last took in, when it took one. Key: ().
    SYNC_RESIDENCE_BUNDLE_CURSOR: SyncState b"rbt" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// A stored window's ready generation (fix list row 19634): u64 little-endian, one higher
    /// each time a policy wake persists the window again; an absent row is 0. Each live
    /// connection asks its peer to exchange the window once per generation it has not asked
    /// for; no send, export or receipt consumes it. Local to this vault. Key: window key.
    WINDOW_READY_GENERATION: SyncState b"ready:w:" Raw
        // Restore class: A window's ready generation is this vault's own record of the exchanges
        // its live connections owe, so it follows the live vault: a restore neither drops one owed
        // nor brings back an image's (FIX 19634).
        [restore: live] [family: unregistered] [tier: canonical];
    /// A retained federation or maintenance item that carries an entity's bytes, so the entity's
    /// erase scrubs it (FIX 7998). Empty value. Key: hex32 (entity id) then the item's reference.
    SYNC_RETAINED_WORK_CARRIER: SyncState b"retained:carrier:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The caller one retained-work queue served last, so its next pass starts after it (FIX
    /// 7997). Value: the caller's fair key. Key: string (the queue's code).
    SYNC_RETAINED_WORK_CURSOR: SyncState b"retained:cursor:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A signed maintenance operation kept for its turn instead of refused (FIX 8565, 8858): its
    /// arrival, deadline, window, lease vault and exact bytes, then a content-free receipt once it
    /// expires, is refused or is erased. Key: hex64 (signer key) then hex32 (entity id).
    SYNC_MAINTENANCE_RETAINED_WORK: SyncState b"retained:maintenance:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The owner's wait for one retained-work queue (u64 big-endian seconds). Key: string (the
    /// queue's code).
    SYNC_RETAINED_WORK_WAIT: SyncState b"retained:wait:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A room's host pin or platform handle this device changed while no open window carried the
    /// room, or a join or offer card it changed that its window does not hold yet (FIX 1794),
    /// mirrored as that window opens. Key: string (the row's `room_facts` map key).
    SYNC_ROOM_FACT_DIRTY: SyncState b"rfd:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A thin-residence item's opened entity blob. Key: hex32 (entity id).
    SYNC_RESIDENCE_ITEM_BLOB: SyncState b"ri:b:" Raw
        [restore: content] [family: mixed ResidenceItem] [tier: canonical];
    /// Where a thin-residence item's row sits, as the home witnessed it with the item's blob
    /// (FIX 14534): `ContentWorld`'s tag, then a world id for one in a single world. Key: hex32
    /// (entity id).
    SYNC_RESIDENCE_ITEM_CONTENT_WORLD: SyncState b"ri:c:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A thin-residence item's opened document state. Key: hex32 (entity id).
    SYNC_RESIDENCE_ITEM_DOCUMENT: SyncState b"ri:d:" Raw
        [restore: content] [family: mixed ResidenceItem] [tier: canonical];
    /// A thin item's source worlds and hashes of its exact cached blob and document, encoded
    /// as CachedItemWorlds. Provenance only, never read authority. Key: hex32 (entity id).
    SYNC_RESIDENCE_ITEM_SOURCES: SyncState b"ri:s:" Raw
        [restore: content] [family: mixed ResidenceItem] [tier: canonical];
    /// The thin-residence index rows fetched for one window. Key: window key ":" item tag.
    SYNC_RESIDENCE_INDEX: SyncState b"ri:w:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The window an opened thin-residence item came from. Key: hex32 (entity id).
    SYNC_RESIDENCE_OPENED_ITEM: SyncState b"ro:e:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A window promoted from thin to canonical residence; reconnect replays it. Key: window key.
    SYNC_RESIDENCE_PROMOTED_WINDOW: SyncState b"rp:w:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Recorded-clock seconds (u64be) of an opened thin item's last touch, which ages its read
    /// cache for pruning. Key: hex32 (entity id).
    SYNC_RESIDENCE_ITEM_TOUCH: SyncState b"rt:e:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Deferred SpawnedBy anchor, keyed by window, session and turn. Key: yyyy-mm ":" hex32 ":" hex32.
    DEFERRED_SPAWNED_BY: SyncState b"sa:w:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Endpoint index for a deferred SpawnedBy anchor. Key: hex32 ":" full sa:w: key.
    DEFERRED_SPAWNED_BY_ENDPOINT: SyncState b"se:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A left shared vault's owed orphan body collection (FIX 2413): when its env's purge finished
    /// and when the collection is due (unix seconds); local only, never synced. Key: ().
    SYNC_LEFT_ENV_BODY_COLLECT: SyncState b"sl-body-collect" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The home's version vector of a world window, as this device last
    /// exchanged it (FIX 14534): what a world eviction waits to see cover the
    /// window. Local only, never imaged; the next exchange writes it again.
    /// Key: window key.
    SYNC_HOME_WINDOW_VV: SyncState b"sv:hw:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// This machine's place in its home's queue of sealed world updates (DEC-0005 fix 8, FIX
    /// 12586): the queue epoch (16) ‖ u64be the last number it took. Key: ().
    SYNC_SEALED_UPDATE_CURSOR: SyncState b"swu:c" Raw
        // Restore class: The home's queue of sealed world updates and this machine's place in it
        // and its outbox follow the live vault, as the sealed bundle's custody and cursor do
        // (DEC-0005 fix 8, FIX 12586).
        [restore: live] [family: unclassified] [tier: canonical];
    /// One sealed world update the home keeps for the vault's machines (DEC-0005 fix 8, FIX
    /// 12586): u64be vault second it was stored ‖ its id (16) ‖ the sealed bytes, which the home
    /// cannot read. Kept 90 days. Key: u64hex16 (its number in the queue's epoch).
    SYNC_SEALED_UPDATE_ENTRY: SyncState b"swu:e:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The number the home gave one sealed world update's id, so one id is stored once: u64be.
    /// Key: hex32 (the id).
    SYNC_SEALED_UPDATE_ID: SyncState b"swu:i:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The home's queue of sealed world updates: its epoch (16), minted on first use ‖ u64be the
    /// last number it gave. Key: ().
    SYNC_SEALED_UPDATE_QUEUE: SyncState b"swu:m" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// One world update this machine sealed for its home, until the home says it is stored: its
    /// id (16) ‖ the world (16) ‖ u64be vault second it was sealed ‖ the sealed bytes. Key:
    /// u64hex16 (its place in the order the updates were made).
    SYNC_SEALED_UPDATE_OUTBOX: SyncState b"swu:o:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The place of one outbox update by its id, so one id is kept once: u64be. Key: hex32 (the
    /// id).
    SYNC_SEALED_UPDATE_OUTBOX_ID: SyncState b"swu:p:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Test-fixture row, never read or written by production code: a cached
    /// minted capability slip for one request-credential recipe id
    /// (`crates/oneiron-server/src/test_credentials.rs`, mounted only as
    /// `#[cfg(test)] mod test_credentials;`). Declared so the generic host
    /// door's declared-table check (`side_table::host_declared_sync_state`)
    /// does not refuse this well-known test fixture prefix. Key: hex64
    /// (blake3 of the fixture's request-recipe id).
    TEST_API_SLIP_CACHE: SyncState b"test:api:slip:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Test-fixture row, never read or written by production code: a cached
    /// minted MCP-paired capability-slip token for one pairing label
    /// (`crates/oneiron-server/src/api/tests/support_mcp_credentials.rs`,
    /// reached only from `#[cfg(test)]` code under `api/tests/`). Same
    /// rationale as `TEST_API_SLIP_CACHE`. Key: hex64 (blake3 of the label).
    TEST_MCP_PAIRED_CACHE: SyncState b"test:mcp:paired:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// ARCH-0023b document family: one durable pending CRDT update for a window, applied on top of
    /// d:w:. Key: yyyy-mm ":" hex8 (sequence).
    SYNC_U_W: SyncState b"u:w:" Raw
        [restore: content] [family: mixed WindowUpdate] [tier: canonical];
    /// One owner/vault/metric/day operational meter rollup, moved in each meter row's own write
    /// (ARCH-0011 `#meters`, FIX 7764). Key: hex ":" hex ":" metric ":" 20-digit period start.
    USAGE_METER_ROLLUP: SyncState b"usage:meter-rollup:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// One operational meter row for an owner/vault, kept once under its idempotency key
    /// (ARCH-0011 `#meters`, FIX 7764). Key: hex ":" hex ":" metric ":" hex (owner, vault,
    /// metric, idempotency key).
    USAGE_METER: SyncState b"usage:meter:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The receipt of one owner repair that removed a stored usage event that no longer decoded
    /// (FIX 6476): the scope, the row's ref, hash and length, and who removed it, when and where.
    /// Key: hex32 (receipt id).
    USAGE_REPAIR_RECEIPT: SyncState b"usage:repair:receipt:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Aggregated usage-metering rollup totals (cost/units) for one owner/vault pair. Key: hex ":"
    /// hex (owner, vault).
    USAGE_VAULT_ROLLUP: SyncState b"usage:rollup:vault:" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The newest withdrawn generation of a derived artifact whose historical sweep finished,
    /// and what stands in for it (FIX 931): nine bytes, the `learned_at` u64be, then the
    /// replacement's tag byte (1 an epoch keyframe, 2 a Shell, the header alone). Sync ingest
    /// refuses a body of that generation or older that is not that content-free form, and every
    /// sweep keeps rewriting such a carrier. Outlives the `hw:` row it replaces. Key: hex32
    /// (entity id).
    DELETION_WITHDRAWN_GENERATION_FENCE: SyncState b"wg:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// The serve health check past a threshold (OF-520): one check per crossing subject, and
    /// how far the check has read each kind of kept crossing. Key: "check:" string (the
    /// subject) | "cursor:" string (the crossing kind, and a limits row's key).
    WIRE_HEALTH_CHECK: SyncState b"wire:health:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
