import { afterAll, expect, test } from "bun:test";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { PublicHttpError } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 2 });
afterAll(suite.flush);

/*
 * Sync and federation. A written case proves exactly the subset its name
 * states, and only when that subset keeps a promise of the planned title
 * (Engine E2E-PARTIAL = A, 9 Nov 2026); its comment lists what stays
 * unproved. Every other case is a TODO naming its missing door. suite.todo
 * registers Bun test.todo and a mandatory BLOCKED result per ID.
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
 * A link proxy may cut, drop, duplicate or reorder whole sync messages, never
 * manufacture CRDT operations, approvals or sync ACKs. Process orchestration
 * (a same-vault device peer, the link proxy) lives in support/, which
 * OPUS-E2E-1 owns (Engine 9 Nov: NOTE SYNC-PEER-OPTION). No unused proxy or
 * counterfeit EphemeralStore codec is installed while these remain blocked.
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
/* SYNC-01 — decision: TODO (Engine rulings 23:09 and 23:15; reason names NOTE SYNC-PEER-OPTION).
 * Promise: two replicas of ONE vault converge on the authored note text and
 *   claim set under partition, both delivery orders and redelivery, keeping
 *   the original paired writers as authors.
 * Doors that exist today: vault.notes.read / vault.notes.history (live text,
 *   stable anchors, actor-attributed operations), vault.notes.edit
 *   replace_span, vault.claims.upsert / list, and the sync door the Engine
 *   confirmed at 23:15: CLI token pair --machine yours, then device enrol on
 *   an EMPTY vault (empty-vault join merged), then serve.
 * Unproved and why: EngineFixture.start runs `token bootstrap` on every vault,
 *   peers included, so no fixture vault can be that empty enrolling device;
 *   and there is no support-side link relay to partition, reorder and
 *   duplicate the device's /ws traffic. Both are requested from OPUS-E2E-1
 *   as EngineFixture.startDevicePeer and SyncLinkProxy. Federation Connect
 *   export/rejoin, the only cross-vault door between independent fixture
 *   vaults, lands a FOREIGN world copy under the guest actor, ledger window
 *   only: it cannot show one vault's replicas converging with the paired
 *   writers as authors. A one-vault restart subset is excluded by the brief.
 */
suite.todo(test, "SYNC-01", "waits on EngineFixture.startDevicePeer and SyncLinkProxy (NOTE SYNC-PEER-OPTION) for a same-vault replica pair; independent peers and Connect copies are not replicas");

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
suite.todo(test, "SYNC-02", "waits on a receiving-vault door that admits a guest NOTE document envelope; Connect export/rejoin pairs the vaults but carries only the granted world's ledger window, not text");

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
/* SYNC-04 — decision: TODO (Engine rulings 23:09 and 23:15; reason names NOTE SYNC-PEER-OPTION).
 * Promise: a non-home device of the same vault holds only a thin index,
 *   opens exactly one item (readable offline afterwards, its neighbour not),
 *   searches unopened bodies through its caller-bound home route with an
 *   explicit source/completeness, and stops fetching after revocation.
 * Doors that exist today: vault.residence.index / open / mode (open returns
 *   typed NOTE text with source local|home), GET /api/search/text with its
 *   residence block, vault.notes.read, CLI token pair --machine yours and
 *   device enrol (empty-vault join merged).
 * Unproved and why: residence acts address an enrolled MACHINE of the same
 *   vault and act through its live sync connection; independent fixture
 *   peers are separately bootstrapped vaults with no machine link; the
 *   enrolled empty-vault device and its cuttable /ws link are requested from
 *   OPUS-E2E-1 as EngineFixture.startDevicePeer and SyncLinkProxy. Federation
 *   Connect moves a foreign world copy, which has no residence mode at all.
 *   Separately, vault.notes.create takes only {kind, markdown} and stamps the
 *   live clock, so the fixture's 2026-01 / 2026-10 windows cannot be authored
 *   without a fixture revision or a NOTE birth door that takes learned_at.
 *   Sol's subset (local note text plus residence target refusals on one
 *   vault) is a single-vault restart and an absence check: excluded.
 */
suite.todo(test, "SYNC-04", "waits on EngineFixture.startDevicePeer and SyncLinkProxy (NOTE SYNC-PEER-OPTION) for an enrolled non-home device, and on a NOTE birth door or fixture revision for the authored 2026-01/2026-10 windows");

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
/* SYNC-05 — decision: TODO (Engine ruling 23:15; reason names NOTE SYNC-PEER-OPTION).
 * Promise: switching an enrolled device to sync-all makes authorized
 *   unopened bodies readable with the home link cut, never the private
 *   canary, merges the device's offline edit with the home's disjoint edit
 *   under both writers, and leaves claim source/approval unchanged.
 * Doors that exist today: vault.residence.mode (applied when called on the
 *   device itself), vault.residence.open, vault.notes.read / history / edit
 *   replace_span, vault.claims.upsert / list, and the sync door the Engine
 *   confirmed: token pair --machine yours, device enrol on an empty vault,
 *   serve.
 * Unproved and why: (1) support: no fixture vault can be the empty enrolling
 *   device (EngineFixture always bootstraps) and nothing relays and cuts the
 *   device's home link; requested as EngineFixture.startDevicePeer and
 *   SyncLinkProxy. (2) engine: the canon's first offline edit lands on an
 *   opened (thin) NOTE, and only SyncConnection::edit_opened_item promotes a
 *   thin window before a write; it has no caller, and vault.notes.edit
 *   refuses thin ids. Sol's one-vault subset (two anchored edits survive a
 *   restart) is a single-vault restart: excluded.
 */
suite.todo(test, "SYNC-05", "waits on EngineFixture.startDevicePeer and SyncLinkProxy (NOTE SYNC-PEER-OPTION), and on a public door that promotes an opened thin NOTE for its first offline edit");

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

type Sync07Scope = FacadeInput<"vault.federation.connect.grants.mint">["authority_scope"];
type Sync07Direction = FacadeInput<"vault.federation.connect.offer">["outbound"];
type Sync07SourceTrust = NonNullable<FacadeInput<"vault.gate.policy.put">["manifest"]["source_trust"]>[string];
type Sync07Evidence = FacadeResult<"vault.consolidation.evidence">["value"][number];
interface Sync07Fixture {
  readonly scenarios: readonly { readonly id: string; readonly inputs: { readonly evidenceText?: unknown } }[];
}
interface Sync07Pact {
  readonly pact: string;
  readonly sharerVault: string;
  readonly receiverVault: string;
  readonly sharerWorld: string;
  readonly receiverGrant: FacadeResult<"vault.federation.connect.grants.mint">;
}

/** Test-authored learn time (2026-10-17T12:00:00Z): the claim's world window is
 * then known without reading a clock. Claims honour a supplied past learned_at. */
const SYNC07_LEARNED_AT = 1792238400;
const SYNC07_PREDICATE = "prototype.fastener";

/** A Connect guest grant over one named world: read only, at most private,
 * every other axis explicit (an omitted Scope axis deserializes as bottom). */
function sync07ShareScope(world: string): Sync07Scope {
  return {
    worlds: { kind: "some", values: [world] }, facets: { kind: "all" }, bands: { kind: "all" },
    audience: { kind: "all" }, verbs: { kind: "some", values: ["read"] },
    sensitivity: { kind: "at_most", value: "private" },
  };
}
/** The pact half a grant above projects to; offer/accept require it exactly. */
function sync07Direction(world: string): Sync07Direction {
  return { worlds: { kind: "some", values: [world] }, facets: { kind: "all" }, bands: { kind: "all" } };
}
/** "YYYY-MM@<world hex>": the world-scoped monthly window a CLAIM lives in. */
function sync07WindowKey(learnedAt: number, world: string): string {
  return `${new Date(learnedAt * 1000).toISOString().slice(0, 7)}@${world}`;
}
async function sync07Refusal(attempt: Promise<unknown>): Promise<PublicHttpError> {
  try {
    await attempt;
  } catch (error) {
    if (error instanceof PublicHttpError) return error;
    throw error;
  }
  throw new Error("expected a public refusal; the call succeeded");
}
async function sync07NamedWorld(engine: EngineFixture, name: string): Promise<string> {
  const world = await engine.client.call("vault.structural.put", {
    kind: "WORLD", body: { name, kind: "fictional" }, occurred_at: SYNC07_LEARNED_AT,
    text_fields: [{ field: "name", value: name }],
  });
  expect((await engine.client.call("vault.get", { entity_ref: world.entity_ref })).value?.kind).toBe("WORLD");
  return world.id_hex;
}
/** Both owners carry each signed half; each host sends nothing (FIX 323/3016). */
async function sync07ConnectPact(sharer: EngineFixture, receiver: EngineFixture): Promise<Sync07Pact> {
  const sharerId = await sharer.client.call("vault.federation.connect.identity", {});
  const receiverId = await receiver.client.call("vault.federation.connect.identity", {});
  expect(sharerId.vault).not.toBe(receiverId.vault);
  const sharerWorld = await sync07NamedWorld(sharer, "SYNC-07 shared workshop");
  const receiverWorld = await sync07NamedWorld(receiver, "SYNC-07 receiving workshop");
  const sharerGrant = await sharer.client.call("vault.federation.connect.grants.mint", {
    peer_vault: receiverId.vault, authority_scope: sync07ShareScope(sharerWorld),
  });
  const receiverGrant = await receiver.client.call("vault.federation.connect.grants.mint", {
    peer_vault: sharerId.vault, authority_scope: sync07ShareScope(receiverWorld),
  });
  const offer = await sharer.client.call("vault.federation.connect.offer", {
    peer_vault: receiverId.vault, grant: sharerGrant.grant,
    outbound: sync07Direction(sharerWorld), inbound: sync07Direction(receiverWorld),
  });
  const receiverAccepted = await receiver.client.call("vault.federation.connect.accept", {
    offer, grant: receiverGrant.grant,
  });
  expect(receiverAccepted.pact).toBe(offer.pact);
  expect(receiverAccepted.status).toBe("Active");
  const sharerAccepted = await sharer.client.call("vault.federation.connect.accept", {
    offer: receiverAccepted.counter, grant: sharerGrant.grant,
  });
  expect(sharerAccepted.pact).toBe(offer.pact);
  expect(sharerAccepted.status).toBe("Active");
  for (const side of [sharer, receiver]) {
    const status = await side.client.call("vault.federation.status", {});
    expect(status.pacts.filter(row => row.status === "Active" && row.epoch === 1)).toHaveLength(1);
  }
  return { pact: offer.pact, sharerVault: sharerId.vault, receiverVault: receiverId.vault, sharerWorld, receiverGrant };
}
async function sync07Evidence(engine: EngineFixture, claimRef: string): Promise<Sync07Evidence> {
  const read = await engine.client.call("vault.consolidation.evidence", { source_refs: [claimRef] });
  expect(read.value).toHaveLength(1);
  const [row] = read.value;
  if (!row) throw new Error(`No evidence row for ${claimRef}`);
  return row;
}

/* SYNC-07 — decision: WRITTEN (partial).
 * Promise: a claim delivered from a connected vault enters the receiving vault
 *   only under that vault's own source-trust rule, and there it stays foreign
 *   evidence: foreign world, imported source, zero first-party corroboration,
 *   origin vault + pact + grant + epoch on record. A same-text claim the
 *   receiver authors itself stays first-party. Forged deliveries are refused;
 *   a crash and a duplicate delivery change nothing.
 * Doors: vault.structural.put (WORLD), vault.federation.connect.identity /
 *   grants.mint / offer / accept / export / rejoin, vault.federation.status,
 *   vault.claims.upsert / list, vault.gate.policy.get / put (receiver's
 *   imported-source permit), vault.consolidation.evidence, kill + restart.
 * Unproved and why: owner-clone replay (needs EngineFixture.startDevicePeer,
 *   NOTE SYNC-PEER-OPTION); two foreign trust tiers and the least-trusted
 *   slice (no public per-tier admission input); a typed named consolidation
 *   of evidence refs (enqueue input is still `unknown`), so generated
 *   restatements and three-citation dedupe are not exercised; trust derived
 *   on a second receiving device (same missing device peer).
 */
suite.test(test, "SYNC-07", "A claim from a connected vault lands only under the receiver's own trust permit and stays foreign evidence, never first-party, through forgery, crash and redelivery", async () => {
  const catalog = await loadFixtures();
  const fixture = await catalog.readJson<Sync07Fixture>("sync-scenarios");
  const evidenceText = fixture.scenarios.find(row => row.id === "SYNC-07")?.inputs.evidenceText;
  if (typeof evidenceText !== "string") throw new Error("sync-scenarios has no SYNC-07 evidenceText");
  const engine = await EngineFixture.start({ id: "SYNC-07", profile, peers: 1 });
  const receiver = engine.peers[0];
  if (!receiver) throw new Error("SYNC-07 needs its peer vault");
  const pact = await sync07ConnectPact(engine, receiver);

  // The sharing owner's claim in the shared world. Sensitivity 1 (private)
  // keeps it inside the grant's private ceiling; an unannotated claim reads as
  // sensitive and the export filter would drop it.
  const sharerScope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
  const shared = await engine.client.call("vault.claims.upsert", {
    predicate: SYNC07_PREDICATE, subject_ref: engine.pairedActor.principalRef, value: evidenceText,
    confidence: 0.9, source: "user_stated", sensitivity: 1,
    scope: { ...sharerScope, world_id: pact.sharerWorld },
    occurred_at: SYNC07_LEARNED_AT, learned_at: SYNC07_LEARNED_AT,
  });
  expect(shared.claim_short_id.length).toBeGreaterThan(0);
  const delivery = await engine.client.call("vault.federation.connect.export", {
    pact: pact.pact, window_key: sync07WindowKey(SYNC07_LEARNED_AT, pact.sharerWorld), world_ref: pact.sharerWorld,
  });
  expect(delivery.body.pact).toBe(pact.pact);
  expect(delivery.body.source_vault).toBe(pact.sharerVault);
  expect(delivery.body.recipient_vault).toBe(pact.receiverVault);
  expect(delivery.body.epoch).toBe(1);
  expect(delivery.body.update.length).toBeGreaterThan(0);

  // Refusal: with no imported-source permit of its own, the receiver admits nothing.
  const untrusted = await sync07Refusal(receiver.client.call("vault.federation.connect.rejoin", delivery));
  expect(untrusted.reply.status).toBe(400);
  expect(untrusted.error?.code).toBe("BAD_REQUEST");
  expect((await receiver.client.call("vault.claims.list", { predicate: SYNC07_PREDICATE, limit: 10 })).value).toEqual([]);

  // The receiving owner's local trust decision: imported claims up to private may land.
  const policy = await receiver.client.call("vault.gate.policy.get", {});
  const manifest = policy.manifests.find(row => row.manifest_ref === policy.default_manifest_ref);
  if (!manifest) throw new Error("Receiving vault has no default policy manifest");
  const permit: Sync07SourceTrust = { max_auto_sensitivity: 1, receipted: true, warned: true };
  const put = await receiver.client.call("vault.gate.policy.put", {
    manifest_ref: manifest.manifest_ref, expected_body_hash: manifest.body_hash,
    manifest: { ...manifest.manifest, source_trust: { ...(manifest.manifest.source_trust ?? {}), imported: permit } },
  });
  expect(put.receipt_ref.length).toBeGreaterThan(0);
  const policyAfter = await receiver.client.call("vault.gate.policy.get", {});
  const manifestAfter = policyAfter.manifests.find(row => row.manifest_ref === policyAfter.default_manifest_ref);
  expect(manifestAfter?.trusted).toBe(true);
  expect(manifestAfter?.quarantined).toBe(false);
  expect(manifestAfter?.manifest.source_trust?.["imported"]).toBeDefined();

  const landed = await receiver.client.call("vault.federation.connect.rejoin", delivery);
  expect(landed.status).toBe("imported");
  expect(landed.pact).toBe(pact.pact);
  expect(landed.epoch).toBe(delivery.body.epoch);
  expect(landed.world_ref).not.toBe(pact.sharerWorld);
  const foreignWorld = landed.world_ref;
  const listed = await awaitPublic(
    () => receiver.client.call("vault.claims.list", { predicate: SYNC07_PREDICATE, limit: 10 }),
    page => page.value.some(row => row.world_ref === foreignWorld),
    { label: "delivered claim readable on the receiving vault" },
  );
  const [foreignClaim, ...extraForeign] = listed.value.filter(row => row.world_ref === foreignWorld);
  if (!foreignClaim) throw new Error("Delivered claim missing from the foreign world");
  expect(extraForeign).toEqual([]);
  expect(foreignClaim.value).toEqual(evidenceText);
  expect(foreignClaim.source).toBe("imported");

  // The receiver states the same text itself: equal text, different standing.
  const receiverScope = await ownerBaseClaimScope(receiver.client, receiver.pairedActor.principalRef);
  const own = await receiver.client.call("vault.claims.upsert", {
    predicate: SYNC07_PREDICATE, subject_ref: receiver.pairedActor.principalRef, value: evidenceText,
    confidence: 0.9, source: "user_stated", scope: receiverScope,
  });
  expect(own.approval).toBe("auto");
  const ownClaim = (await receiver.client.call("vault.claims.list", { predicate: SYNC07_PREDICATE, limit: 10 }))
    .value.find(row => row.claim_ref !== foreignClaim.claim_ref);
  if (!ownClaim) throw new Error("Receiver's own claim missing");

  const foreignEvidence = await sync07Evidence(receiver, foreignClaim.claim_ref);
  expect(foreignEvidence.foreign_world_ref).toBe(foreignWorld);
  expect(foreignEvidence.source).toBe("imported");
  expect(foreignEvidence.first_party_corroboration).toBe(false);
  expect(foreignEvidence.writer_ref ?? null).not.toBe(receiver.pairedActor.principalRef);
  const origin = (foreignEvidence.delivery_history ?? []).find(row => row.delivering_pact === pact.pact);
  expect(origin).toBeDefined();
  expect(origin?.source_vault).toBe(pact.sharerVault);
  expect(origin?.grant_ref).toBe(pact.receiverGrant.grant);
  expect(origin?.consent_epoch).toBe(delivery.body.epoch);
  const ownEvidence = await sync07Evidence(receiver, ownClaim.claim_ref);
  expect(ownEvidence.foreign_world_ref ?? null).toBeNull();
  expect(ownEvidence.source).toBe("user_stated");
  expect(ownEvidence.first_party_corroboration).toBe(true);
  expect(ownEvidence.delivery_history ?? []).toEqual([]);

  // Forged input: altered bytes, or a delivery relabelled as the receiver's own.
  const tampered = await sync07Refusal(receiver.client.call("vault.federation.connect.rejoin", {
    ...delivery, body: { ...delivery.body, update: delivery.body.update.map((byte, index) => index === 0 ? byte ^ 1 : byte) },
  }));
  expect(tampered.reply.status).toBe(400);
  expect(tampered.error?.code).toBe("BAD_REQUEST");
  const relabelled = await sync07Refusal(receiver.client.call("vault.federation.connect.rejoin", {
    ...delivery, body: { ...delivery.body, source_vault: pact.receiverVault },
  }));
  expect(relabelled.reply.status).toBe(400);
  expect(relabelled.error?.code).toBe("BAD_REQUEST");

  // Crash, then the same delivery again: still one foreign row, still foreign.
  await receiver.kill();
  await receiver.restart();
  const replayed = await receiver.client.call("vault.federation.connect.rejoin", delivery);
  expect(replayed.status).toBe("imported");
  expect(replayed.world_ref).toBe(foreignWorld);
  const afterReplay = await receiver.client.call("vault.claims.list", { predicate: SYNC07_PREDICATE, limit: 10 });
  expect(afterReplay.value.filter(row => row.world_ref === foreignWorld)).toHaveLength(1);
  expect(afterReplay.value).toHaveLength(2);
  const restarted = await sync07Evidence(receiver, foreignClaim.claim_ref);
  expect(restarted.foreign_world_ref).toBe(foreignWorld);
  expect(restarted.first_party_corroboration).toBe(false);
  expect((restarted.delivery_history ?? []).some(row => row.delivering_pact === pact.pact
    && row.source_vault === pact.sharerVault && row.grant_ref === pact.receiverGrant.grant)).toBe(true);
});

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
/* SYNC-08 — decision: TODO (reason string replaced).
 * Promise: the mesh is off by default; once opted in, only a paired machine
 *   with the sync ALPN grant reaches application data, an unpaired third
 *   machine is refused before any data with a refused path receipt, denied
 *   data stays denied on mesh and HTTP/WS alike, and disabling the mesh
 *   leaves ordinary HTTP/WS working.
 * Doors that exist today: vault.mesh.identity, bind_machine,
 *   set_alpn_grant, revoke_machine, dial (admission-only, returns a
 *   MeshPathReceipt), path_receipts; CLI token pair --machine yours and
 *   device enrol (which can auto-bind the mesh identity).
 * Unproved and why: the listener is enabled only by the ONEIRON_MESH_BIND
 *   environment variable (or managed-mode --mesh-bind, which requires
 *   managed_by_hypnos); EngineFixture deletes every inherited ONEIRON_*
 *   variable and launches plain `serve --config`, and serverConfig TOML has
 *   no mesh table, so no fixture vault can opt in. vault.mesh.dial opens no
 *   application stream, so the scoped transfer and the denied-canary read
 *   over oneiron/sync/1 also need a same-vault enrolled device syncing over
 *   the mesh. Sol's off-state subset (dial refused 409 INVALID_STATE, no
 *   path receipts, across restart) is an absence check: excluded.
 */
suite.todo(test, "SYNC-08", "waits on an EngineFixture opt-in that binds the mesh listener on loopback peers (ONEIRON_MESH_BIND is environment-only and the fixture strips ONEIRON_*) and an enrolled same-vault device syncing over oneiron/sync/1");
