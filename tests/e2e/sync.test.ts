import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 2 });
afterAll(suite.flush);

/*
 * Sync and federation: all eight full flows are blocked, not passing slices.
 * suite.todo registers Bun test.todo and a mandatory BLOCKED result per ID.
 * G01: a designed operation waits for its typed HTTP AND SDK call. Do not
 * cast a missing name to FacadeVerb, use execute_code, decode an opaque entity
 * body as a private storage type, or substitute another progress/trust lane.
 *
 * Binding read: c8c62bc0931c5b39210af19b45c420c0c3ed622d, also compared with
 * origin/main 0dcb431bb50d39b01d7bc222e2d28922bf59bc4d: no server/SDK/support
 * changes between those heads. Read the generated HTTP catalog/DTOs, public
 * Oneiron SDK, CLI, protocol, static OpenAPI assembly and route definitions.
 * This is source binding, not a captured live OpenAPI or a runtime result.
 * Canon/source hashes and authored inputs/expected results are in the
 * sync-scenarios fixture, fixtures/sync/scenarios.json. The shared loader
 * verifies this area fragment during preflight, including TODO-only files.
 *
 * Activation contract: EngineFixture.start({ id, profile, peers, ... }) with
 * fresh real processes, real actor pairing and public grants. peers creates
 * independent vaults, NOT owner replicas, federation pacts or permission.
 * Obtain same-vault copies through public export/restore/enrolment only.
 * token pair --machine yours and device enrol already exist; pass the link
 * on private stdin and never copy credentials, install keys or raw vault files.
 * Use loadFixtures() for authored content and ScriptedProviders only for
 * external inference/effects. Await receipts/events and bounded public reads.
 *
 * A byte-transparent TCP proxy may partition/order whole connections, not
 * manufacture CRDT operations, approvals or sync ACKs. A needed orchestration
 * helper belongs in THIS file, not support/. No unused proxy or counterfeit
 * EphemeralStore codec is installed while these prerequisites remain blocked.
 */

/* SYNC-01 — Concurrent document and ledger convergence should work.
 * Rows: OF-143, OF-475. Canon: ARCH-0023b #two-planes, #sequence;
 * ARCH-0032 #writers. Oracle: sync-scenarios / SYNC-01.
 *
 * Existing public shapes (HTTP wire is snake_case, not SDK camelCase):
 *   vault.notes.create({ kind, markdown }) -> EntityRefReceipt
 *   vault.notes.edit({ note_ref, edit }) -> NoteEditOutcome
 *   NoteAnchor = { note: string, head: string, cursor: number[] }
 *   NoteVersion = { note: string, head: string, frontier: number[] }
 *   edit = { kind: "replace_span", start: NoteAnchor, end: NoteAnchor,
 *            text: string }
 *   vault.claims.upsert(ClaimInput) -> CommitReceipt
 *   vault.claims.list({ subject_ref?, predicate?, lifecycle?, limit })
 *     -> ScopedReadResult<ClaimView[]>
 *   vault.rooms.messages / vault.witness provide message reads/births.
 *
 * Required typed reads: live note text with its NoteVersion and stable span
 * cursors; attributed operation ids/actors; ledger authors. These are read
 * contracts, NOT new verb spellings invented here. vault.get returns an
 * EntityView with body?: unknown, not a live text/cursor/history contract.
 *
 * On a fresh replica pair for EACH opposite delivery order, land the common
 * note, partition, edit the disjoint north/south spans with returned cursors,
 * and add one authored claim and message on each. Reconnect in the fixture's
 * order; compare BOTH replicas to the exact combined text and authored claim
 * set. Require original actors on edits/claims and one of each message id.
 * Reconnect again without writes; operation/message/claim identities must not
 * multiply. Equality between two replicas alone is not the oracle: both can
 * be equally wrong. No whole-text rewrite or private Loro edit substitutes
 * for anchored concurrent edits. WS app RPC alone does not establish sync.
 */
suite.todo(test, "SYNC-01", "waits on typed NOTE live text, stable cursor/version and actor-attributed operation reads");

/* SYNC-02 — One selector governs ledger and text should work.
 * Rows: OF-475, OF-152. Canon: ARCH-0023b #two-planes,
 * ARCH-0043 #guest-grants. Oracle: sync-scenarios / SYNC-02.
 *
 * Existing owner HTTP Connect doors: GET /v1/owner/federation/connect gives
 * {vault,host_key}; POST .../connect/grants takes
 * {peer_vault,authority_scope:Scope,expires_at?} and gives
 * {grant,guest_actor,resolved_scope,expires_at}. Offer and accept exchange
 * the hosts' signed Offer halves; they are not replica connection helpers.
 * vault.guests.mint_slip({grant_ref,holder_key,expires_at}) exists too.
 * A guest grant names worlds/facets/bands and read/propose, never widen;
 * an empty ceiling is bottom, an empty requested axis narrows nothing.
 *
 * Required typed observation: the allowed entity's ledger record AND current
 * document text/head, with its admission/history boundary. Use a bound guest
 * replica, not an unscoped owner request at the sharing vault. Admit only the
 * allowed fixture entity; link it to a private entity outside the ceiling.
 * Update both bodies, then inspect guest content, text search, neighbours,
 * counts/snippets/derived reads and document history through public clients.
 * Assert the allowed update appears on both planes. Private old/new markers,
 * title, endpoint identity and cross-boundary edge must appear on neither.
 * A state-only admission plus future updates must not disclose prior history.
 *
 * Note edits and scoped record/neighbour reads exist; typed grant-scoped live
 * NOTE/document-history reads do not. Do not use a second text-plane selector
 * or a public-looking call to a Rust federation admission function.
 */
suite.todo(test, "SYNC-02", "waits on typed grant-scoped NOTE live text and document-history reads on a federation replica");

/* SYNC-03 — Ephemeral progress expires without history should work.
 * Row: OF-144. Canon: ARCH-0023b #engine (EphemeralStore progress lane).
 * Oracle: sync-scenarios / SYNC-03.
 *
 * Shipped wire: tag 1 carries native Loro EphemeralStore bytes, conceptually
 * [{key:string,value:optional LoroValue,timestamp:i64}]. job:{job_id} and
 * presence:{device_id} are mutable live keys. A late joiner gets held state;
 * inactivity expiry removes values. The public serve configuration already
 * declares ephemeral_timeout_ms. Neither JSON nor MessagePack app RPC is
 * this native payload; no codec bytes/timestamps are fabricated from Rust.
 *
 * Required fixture/client: independently captured native records plus a public
 * client that can stamp a current live publication and read the tag-1 snapshot
 * and removals. Shared WsClient handles tags 30/31 only, deliberately dropping
 * sync frames; its send() cannot publish tag 1. A caller-owned authenticated
 * raw socket is allowed once the real native wire fixture/client is supplied.
 * This is a fixture/binding prerequisite, not a claim that tag 1 is unbuilt.
 *
 * Publish the fixture's two progress updates and presence. A second client
 * must observe both live BEFORE disconnect/expiry. Disconnect the publisher,
 * await declared expiry on real wall time, and join afresh to require absence.
 * Restart the real server and repeat. Export the real archive and take/read a
 * public backup; inspect decoded records and public history/recall for both
 * marker values. The durable control must survive, and no progress/presence
 * claim/message/history/backup row may exist. A raw compressed ZIP substring
 * scan is not that check. tasks.update progress and POST session presence are
 * different surfaces; using them would not test the EphemeralStore lane.
 */
suite.todo(test, "SYNC-03", "waits on an independent native EphemeralStore wire fixture/client for live progress, presence and expiry observations");

/* SYNC-04 — Opened-item sync and remote search should work.
 * Rows: OF-146, OF-534, OF-536. Canon: ARCH-0023b #partial-sync.
 * Oracle: sync-scenarios / SYNC-04.
 *
 * Existing HTTP/SDK residence shapes:
 *   index({machine}) -> {windows:[{window,items:[{entity_id,title?,learned_at}]}]}
 *   open({machine,window,item}) -> {item,window,residence:string,bytes:number}
 *   mode({machine,mode:"opened"|"all"})
 *     -> {mode,retained:string[],unsynced:string[],pruned_items:number}
 * Each is vault.residence.<name>; CLI typed api call is available.
 * GET /api/search/text?query=... already asks the home and can return
 * residence:{source:"home"|"localOnly",complete:boolean,
 *            hits:[{id,score,window}]}. Do not call home search missing.
 *
 * Required typed read: the opened NOTE body plus a local-versus-home residence
 * result, without secretly opening all the other bodies in the observation.
 * ResidenceOpened.bytes is a COUNT, not body bytes or a NoteVersion. Do not
 * decode a private Loro snapshot from a storage blob as the public body read.
 *
 * Populate the fixture's old/current items at home through public clients.
 * CLI-pair/enrol a real non-home replica; leave the default mode unchanged.
 * Assert current thin listing contains only permitted metadata and no bodies;
 * do not require a January item in the current-window index. Open exactly the
 * chosen item and verify its authored text. Disconnect the home link: that
 * body remains readable, the never-opened neighbour does not. Reconnect and
 * search unopened old/current text via the DEVICE's caller-bound home route.
 * Check authored hit sets and explicit source/completeness, not result scores.
 * Revoke the reader's grant; fresh remote search/open must not fetch new bytes.
 * Already disclosed copies are not asserted to disappear by cryptography.
 */
suite.todo(test, "SYNC-04", "waits on typed opened-item NOTE body reads that distinguish local residence from a home fetch");

/* SYNC-05 — Sync-all switch retains public semantics should work.
 * Rows: OF-534, OF-536. Canon: ARCH-0023b #partial-sync, #two-planes.
 * Oracle: sync-scenarios / SYNC-05.
 *
 * vault.residence.mode({machine,mode:"all"}) is a typed HTTP/SDK/CLI call,
 * not a missing mode switch. Its response is ResidenceModeChanged above.
 * vault.notes.edit and claims reads/writes also exist. Missing live NOTE
 * reads and NoteVersion/cursor reads still prevent the complete offline flow.
 * A whole_text write is not a safe substitute for a stable disjoint edit.
 *
 * Start an enrolled opened-item device with its own acknowledged offline
 * edit. Reconnect, enable all via its real CLI, and await public completion.
 * Cut only the home link: query both formerly unopened authorized bodies.
 * The fixture's private canary must remain absent to the same narrow reader,
 * both online and offline. Land the home writer's disjoint edit while cut,
 * rejoin, and require both clients to read the independently authored merged
 * note with original actor stamps. Compare claim source/approval and scoped
 * results across modes: residence never widens authority. Reconnect twice;
 * no extra record/message/effect is added. Do not infer residence or durable
 * settlement from a byte count, private sync queue, log line or sleep.
 */
suite.todo(test, "SYNC-05", "waits on typed NOTE live text and stable cursor/version reads for the offline sync-all merge");

/* SYNC-06 — Single Dreamer home leadership should work.
 * Rows: OF-147, OF-195. Canon: ARCH-0026 #wake-model and MACRO home-node
 * amendment; ARCH-0023b #two-planes. Oracle: sync-scenarios / SYNC-06.
 *
 * Existing typed consolidation shapes:
 *   enqueue({scope:string,input:unknown,run_id?,dedupe_key?,now?})
 *     -> {job_ref,state,existing}
 *   status({job_ref}) -> {job_ref,state,kind,lease_owner?,attempt_count,
 *                        run_id?,last_error?,created_at,updated_at} | null
 * GET /v1/ai/status and run-tree observation exist. Neither authorizes a
 * home transfer or exposes shared reserve/lease/settle budget accounting.
 * An unknown enqueue input is not a typed MACRO/handoff operation (G01).
 *
 * Required public contracts: owner/host transfer of the elected home;
 * transfer/status of durable attempt/checkpoint lineage; shared budget
 * reservations, usage and settlements. No endpoint spellings are invented.
 * Canon corrects the plan's shorthand: election is deterministic and has NO
 * TTL or automatic failover. A dead leader alone cannot authorize the survivor.
 * Private live leases/counters do not replicate just because the attempt has
 * durable effect/consent/checkpoint records. MACRO may parallelize disjoint
 * buckets; one active home does not mean one global job at a time.
 *
 * Connect two eligible nodes, submit ONE bucket's work, observe acceptance
 * and a scripted external provider barrier, then kill the elected home.
 * The second must not race the first. Explicitly transfer through the public
 * owner/host contract and resume on the survivor. Observe the same durable
 * lineage, one idempotent sink effect and usage within ONE original vault
 * budget, never one replenished budget per node. Retries may cost usage;
 * do not pretend every crash guarantees one provider request. A barrier
 * proves external request arrival, not a committed vault checkpoint.
 */
suite.todo(test, "SYNC-06", "waits on typed owner home-leadership transfer, durable attempt handoff and shared-budget observation");

/* SYNC-07 — Guest evidence remains foreign should work.
 * Rows: OF-149, OF-056. Canon: ARCH-0040 #memory-board-source-trust,
 * ARCH-0043 #guest-grants, ARCH-0023b #two-planes.
 * Oracle: sync-scenarios / SYNC-07.
 *
 * Existing ClaimView exposes source/approval/lifecycle, not the foreign
 * admission trust tier, accountable actor or generated evidence frontier.
 * MemoryProvenance = {source,source_revision_ids,evidence_turn_ids}; this is
 * not proof of source independence or the full foreign admission attribution.
 * Existing enqueue({scope,input:unknown,...}) cannot be used to smuggle a
 * private consolidation job. Require a typed consolidation of evidence refs
 * and a typed evidence/source read, rather than JSON.parse of entity bodies.
 * Canon evidence shape (ARCH-0032):
 *   EvidenceRef {kind:EvidenceKind,entity:EntityRef,doc:DocId,at:Frontier,
 *                span:Option<CursorSpan>,quote_sha256:Option<[u8;32]>}
 * Foreign attribution must also retain origin vault, connection, grant and
 * grant epoch on the vault-resident guest actor (ARCH-0043).
 *
 * Send equivalent fixture evidence from an owner clone and a foreign guest,
 * then run the named consolidation. Owner replay preserves its existing
 * identity/source/approval without a fresh approval ask. Foreign admission
 * remains foreign on each receiving device, never a trusted synced flag.
 * Inspect generated claim evidence, not only text equality: three citations
 * of one source remain one signal, a generated restatement adds no new one,
 * and foreign evidence contributes zero FIRST-PARTY corroboration. The
 * least-trusted slice stays inert; other foreign evidence need not disappear.
 * Do not conflate an in-vault peer_stated source with every foreign tier or
 * invent a universal numeric confidence down-weight/quality threshold.
 */
suite.todo(test, "SYNC-07", "waits on typed trust-graded consolidation input and generated-claim evidence with foreign actor attribution");

/* SYNC-08 — Mesh admission follows pairing should work.
 * Row: OF-535. Canon: ARCH-0023b #two-planes, identity #authority-log.
 * Oracle: sync-scenarios / SYNC-08.
 *
 * Main DOES have an optional mesh listener: server feature mesh plus explicit
 * ONEIRON_MESH_BIND, with ONEIRON_MESH_RELAYS absent for direct-only mode.
 * It is not an always-on dependency. token pair --machine and device enrol
 * are public CLI doors. vault.mesh.path_receipts({limit?}) is typed HTTP/SDK:
 *   {id,direction:"inbound"|"outbound",outcome:"admitted"|"refused"|"failed",
 *    machine?,endpoint_key?,alpn,opened_at_ms,closed_at_ms?,
 *    paths:"direct"|"relayed"|"mixed"|"none",used_direct,used_relay,
 *    direct_addr?,relay_url?,detail?,attempts}[]
 *
 * Missing caller contracts: bind the paired MACHINE's mesh address/transport
 * key and ALPN grant, and make an actual unpaired dial through a public client
 * or CLI. Listener environment and a receipt reader do not supply those acts.
 * Calling bind_mesh_machine/set_mesh_alpn_grant or constructing Rust
 * MeshTransport in the test would violate the public boundary. Shared engine
 * launch also strips inherited ONEIRON_* overrides: do not silently edit the
 * shared launcher or use inherited env as an opt-in implementation.
 *
 * With the public contracts present, run three real loopback-only peers.
 * Observe off by default, opt in explicitly, pair/bind two peers and transfer
 * the authored public flow over oneiron/sync/1. Compare scoped content with
 * ordinary HTTP/WS and deny the paired reader's private canary on both paths.
 * Attempt a real unpaired third-machine join: require refusal before any
 * application data plus its refusal path receipt. Require direct admitted
 * receipts and zero public discovery/relay contacts. Disable/restart without
 * mesh: it no longer accepts mesh, while ordinary HTTP/WS remains usable.
 * A refused arbitrary UDP packet or an HTTP 401 is not a mesh admission test.
 */
suite.todo(test, "SYNC-08", "waits on public typed mesh address/ALPN grant configuration and a caller-facing unpaired mesh dial");
