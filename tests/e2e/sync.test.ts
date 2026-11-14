import { afterAll, expect, test } from "bun:test";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import type { DevicePeer } from "./support/engine.ts";
import { PublicHttpError, credentialParts } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { defineFile } from "./support/run.ts";
import { SyncLinkProxy } from "./support/sync_link.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 2 });
afterAll(suite.flush);

async function withWireReason<T>(label: string, call: Promise<T>): Promise<T> {
  try { return await call; } catch (error) {
    if (error instanceof PublicHttpError) {
      throw new Error(`${label}: HTTP ${error.reply.status} ${error.error?.code ?? "no-code"}: ${(error.error?.message ?? "").slice(0, 300)}`);
    }
    throw error;
  }
}

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
interface Sync01Scenario {
  readonly id: string;
  readonly inputs: {
    readonly note: { readonly base: string };
    readonly edits: readonly { readonly replace: string; readonly with: string }[];
    readonly claims: readonly { readonly label: string; readonly value: string }[];
  };
  readonly expected: { readonly noteText: string };
}
type Sync01Span = NonNullable<FacadeInput<"vault.notes.read">["spans"]>[number];
type Sync01Client = EngineFixture["client"];

async function sync01Scenario(): Promise<Sync01Scenario> {
  const fixture = await (await loadFixtures()).readJson<{ readonly scenarios: readonly Sync01Scenario[] }>("sync-scenarios");
  const scenario = fixture.scenarios.find(row => row.id === "SYNC-01");
  if (!scenario || scenario.inputs.edits.length !== 2 || scenario.inputs.claims.length !== 2)
    throw new Error("sync-scenarios has no two-edit, two-claim SYNC-01");
  return scenario;
}
/** The device's own MACHINE id: `device enrol` prints it as enrolment.machine. */
function sync01DeviceMachine(device: DevicePeer): string {
  const shown = device.enrolment["enrolment"];
  const machine = typeof shown === "object" && shown !== null && "machine" in shown ? shown.machine : undefined;
  if (typeof machine !== "string" || !/^[0-9a-f]{32}$/.test(machine)) throw new Error("device enrol printed no enrolment.machine");
  return machine;
}
/** One machine's answer as GET/POST /v1/owner/machines/answer show it. */
type HomeMachineAnswer = { readonly machine: string; readonly role: string | null; readonly revision: string };
/**
 * The owner answers his home "yours", as a surface asks him once the vault
 * first serves. Until he answers, the serving install's MACHINE stands in the
 * `unanswered` role, which proves no connection (MachineRole::answered): a
 * device he joins to it still takes his own-device grant and admits him, but
 * replays no grant withdrawal from it (Engine RULING SYNC-HOME-UNANSWERED = B,
 * 14 Nov). SYNC-01/04/05 answer it as the setup step a surface asks for;
 * SYNC-09 never does. Called right after the home starts, so the checkpoint
 * the device's pairing link pins already holds the answer. Read back on the
 * home.
 * Doors: GET /v1/owner/roots (this install's machine), GET and POST
 * /v1/owner/machines/answer.
 */
async function answerHomeYours(home: EngineFixture): Promise<void> {
  const roots = await home.client.request<{ machine?: string | null }>("GET", "/v1/owner/roots");
  const machine = roots.body.machine;
  if (typeof machine !== "string" || !/^[0-9a-f]{32}$/.test(machine)) throw new Error("GET /v1/owner/roots named no home machine");
  const path = `/v1/owner/machines/answer?machine=${machine}`;
  const before = (await home.client.request<HomeMachineAnswer>("GET", path)).body;
  if (before.role !== "unanswered") throw new Error(`the home's MACHINE stood as ${String(before.role)} before the owner answered, not unanswered`);
  await home.client.request<HomeMachineAnswer>("POST", "/v1/owner/machines/answer", { machine, answer: "yours", seen: before.revision });
  const after = (await home.client.request<HomeMachineAnswer>("GET", path)).body;
  expect(after.machine).toBe(machine);
  expect(after.role).toBe("yours");
  expect(after.revision).not.toBe(before.revision);
}
/** Half-open Unicode-scalar span of the one occurrence of `word` (the authored note is ASCII). */
function sync01Span(text: string, word: string): Sync01Span {
  const start = text.indexOf(word);
  if (start < 0 || text.indexOf(word, start + 1) >= 0) throw new Error(`"${word}" must occur exactly once in the authored note`);
  return { start, end: start + word.length };
}
function sync01Predicate(label: string): string {
  return `observatory.${label.replace(/-/g, "_")}`;
}
async function sync01Facts(client: Sync01Client, predicates: readonly string[]): Promise<FacadeResult<"vault.claims.list">["value"][]> {
  const out: FacadeResult<"vault.claims.list">["value"][] = [];
  for (const predicate of predicates) out.push((await client.call("vault.claims.list", { predicate, limit: 10 })).value);
  return out;
}

/* SYNC-01 — decision: WRITTEN (partial).
 * Promise: two machines of one vault, partitioned, each write; after the link
 *   heals and reconnects both machines hold the
 *   authored note text and the authored claim set, each claim once, authored
 *   by the owner, not by a machine.
 * Doors: EngineFixture.startDevicePeer + SyncLinkProxy (cut, heal,
 *   counts, awaitSeen); on the device vault.residence.mode (all),
 *   vault.notes.read, vault.get, vault.claims.upsert / list; on the home
 *   vault.notes.create / read / edit (replace_span) / history,
 *   vault.claims.upsert / list.
 * Unproved and why: anchored NOTE edits written ON THE DEVICE (vault.notes.edit
 *   on a device replica refuses "replica NOTE edits require authenticated
 *   authority", note/operations.rs:493-495; the replica request path
 *   DocumentRegistry::submit_note has no public door), so both edits are the
 *   home's and only the ledger is written on both sides; two distinct paired
 *   writers (both machines carry the one owner credential); messages; the
 *   two opposite delivery orders on fresh replica pairs (one pair per case
 *   fits the 30 s flow); a duplicated or dropped sync UPDATE (the link proxy
 *   counts whole messages per direction across sockets, so it cannot select
 *   an update over a session hello or a residence RPC; Sol review, 10 Nov);
 *   in-socket drop and reorder (no recovery promise).
 * DEFECT (red since E2E job 23, Fri 13 Nov 2026; FIX row
 *   REPLICA-NOTE-READ-400-BEFORE-DOCUMENT): the device is admitted now, but
 *   after its sync-all switch its notes.read of the home's note answers 400
 *   "invalid NOTE body: NOTE head document missing" about 3.8 s later: the
 *   replica holds the NOTE row without its head document (note/storage.rs
 *   load_stored_to). Earlier reds, fixed: the enrol join guard (#7172), the
 *   join proof and the own-device grant catch-up (this stack).
 */
suite.test(test, "SYNC-01", "Two machines of one vault converge on home's anchored note edits and on a claim written on each side, once each and authored by the owner, after a partition and a reconnect", async () => {
  const scenario = await sync01Scenario();
  const { note: authored, edits, claims } = scenario.inputs;
  const [northEdit, southEdit] = edits;
  const [northFact, southFact] = claims;
  if (!northEdit || !southEdit || !northFact || !southFact) throw new Error("SYNC-01 inputs are incomplete");
  const predicates = [sync01Predicate(northFact.label), sync01Predicate(southFact.label)] as const;

  const home = await EngineFixture.start({ id: "SYNC-01", profile });
  await answerHomeYours(home);
  const owner = home.pairedActor.principalRef;
  const link = await SyncLinkProxy.start({ target: home.url });
  // Fixture kind "annotation" is not a shipped NOTE kind; "research" is (vault-readable, durable).
  const note = await home.client.call("vault.notes.create", { kind: "research", markdown: authored.base });
  const device = await home.startDevicePeer({ id: "SYNC-01-device", homeOrigin: link.url });
  const machine = sync01DeviceMachine(device);
  // The device's own residence act, on the device: hold every body, so its claims can name local rows.
  const mode = await device.client.call("vault.residence.mode", { machine, mode: "all" });
  if (mode.state !== "applied") throw new Error(`device residence switch answered ${mode.state}`);
  expect(mode.mode).toBe("all");
  await awaitPublic(() => withWireReason("SYNC-01 device notes.read", device.client.call("vault.notes.read", { note_ref: note.id_hex })),
    read => read.value?.markdown === authored.base && read.value.source === "local",
    { label: "device holds the authored note", timeoutMs: 15_000 });
  const scope = await ownerBaseClaimScope(home.client, owner);
  await awaitPublic(() => device.client.call("vault.get", { entity_ref: scope.scope_facet_id }),
    read => read.value?.kind === "FACET", { label: "device holds the owner's substrate facet" });
  const born = await home.client.call("vault.notes.history", { note_ref: note.id_hex });
  const birthOperations = new Set((born.value?.operations ?? []).map(row => row.operation));

  // Failure step: partition. Each machine writes while the link is down.
  link.cut();
  const anchors = await home.client.call("vault.notes.read", {
    note_ref: note.id_hex, spans: [sync01Span(authored.base, northEdit.replace), sync01Span(authored.base, southEdit.replace)],
  });
  expect(anchors.value?.markdown).toBe(authored.base);
  const [northSpan, southSpan] = anchors.value?.spans ?? [];
  if (!northSpan || !southSpan) throw new Error("Home returned no stable anchors");
  for (const { span, text } of [{ span: northSpan, text: northEdit.with }, { span: southSpan, text: southEdit.with }]) {
    const edited = await home.client.call("vault.notes.edit", {
      note_ref: note.id_hex, edit: { kind: "replace_span", start: span.start, end: span.end, text },
    });
    expect(edited.outcome).toBe("edited");
  }
  const northWrite = await home.client.call("vault.claims.upsert", {
    predicate: predicates[0], subject_ref: note.id_hex, value: northFact.value, confidence: 0.9, source: "user_stated", scope,
  });
  const southWrite = await device.client.call("vault.claims.upsert", {
    predicate: predicates[1], subject_ref: note.id_hex, value: southFact.value, confidence: 0.9, source: "user_stated", scope,
  });
  expect(northWrite.approval).toBe("auto");
  expect(southWrite.approval).toBe("auto");
  // The partition is real: neither machine holds the other's write yet.
  expect((await device.client.call("vault.notes.read", { note_ref: note.id_hex })).value?.markdown).toBe(authored.base);
  expect((await home.client.call("vault.claims.list", { predicate: predicates[1], limit: 10 })).value).toEqual([]);
  expect((await device.client.call("vault.claims.list", { predicate: predicates[0], limit: 10 })).value).toEqual([]);

  // The partition ends: the device reconnects through the healed link.
  link.heal();

  for (const side of [home.client, device.client]) {
    await awaitPublic(() => side.call("vault.notes.read", { note_ref: note.id_hex }),
      read => read.value?.markdown === scenario.expected.noteText, { label: "converged note text", timeoutMs: 15_000 });
    await awaitPublic(() => sync01Facts(side, predicates), facts => facts.every(rows => rows.length === 1),
      { label: "both claims on this machine", timeoutMs: 15_000 });
  }
  // Barrier after the reconnect: a later home write reaching the device orders after it.
  await home.client.call("vault.claims.upsert", {
    predicate: "observatory.reconnect_witness", subject_ref: note.id_hex, value: "SYNC-01 reconnect witness",
    confidence: 0.9, source: "user_stated", scope,
  });
  await awaitPublic(() => device.client.call("vault.claims.list", { predicate: "observatory.reconnect_witness", limit: 10 }),
    page => page.value.length === 1, { label: "post-reconnect witness on the device", timeoutMs: 15_000 });

  const homeFacts = await sync01Facts(home.client, predicates);
  const deviceFacts = await sync01Facts(device.client, predicates);
  for (const [index, fact] of [northFact, southFact].entries()) {
    const onHome = homeFacts[index] ?? [];
    const onDevice = deviceFacts[index] ?? [];
    expect(onHome).toHaveLength(1);
    expect(onDevice).toHaveLength(1);
    expect(onDevice[0]?.claim_ref).toBe(onHome[0]?.claim_ref);
    for (const view of [...onHome, ...onDevice]) {
      expect(view.value).toEqual(fact.value);
      expect(view.made_by?.process.actor).toBe(owner);
    }
  }
  for (const side of [home.client, device.client]) {
    expect((await side.call("vault.notes.read", { note_ref: note.id_hex })).value?.markdown).toBe(scenario.expected.noteText);
  }
  const history = await home.client.call("vault.notes.history", { note_ref: note.id_hex });
  expect(history.value?.complete).toBe(true);
  const edited = (history.value?.operations ?? []).filter(row => !birthOperations.has(row.operation));
  expect(edited).toHaveLength(2);
  for (const row of edited) expect(row.actor).toBe(owner);
});

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
interface Sync04Scenario {
  readonly id: string;
  readonly inputs: {
    readonly items: readonly { readonly label: string; readonly text: string }[];
    readonly open: string;
    readonly searchQueries: readonly string[];
  };
  readonly expected: { readonly openedBody: string };
}
type Sync04Windows = Extract<FacadeResult<"vault.residence.index">, { state: "applied" }>["windows"];
/** The residence block GET /api/search/text adds for an opened machine. */
interface Sync04Search {
  readonly residence?: {
    readonly source: string; readonly complete: boolean;
    readonly hits: readonly { readonly id: string; readonly window: string }[];
  };
}

async function sync04Scenario(): Promise<Sync04Scenario> {
  const fixture = await (await loadFixtures()).readJson<{ readonly scenarios: readonly Sync04Scenario[] }>("sync-scenarios");
  const scenario = fixture.scenarios.find(row => row.id === "SYNC-04");
  if (!scenario) throw new Error("sync-scenarios has no SYNC-04");
  return scenario;
}
function sync04Text(scenario: Sync04Scenario, label: string): string {
  const item = scenario.inputs.items.find(row => row.label === label);
  if (!item) throw new Error(`SYNC-04 has no item ${label}`);
  return item.text;
}
/** The device's own MACHINE id: `device enrol` prints it as enrolment.machine. */
function sync04DeviceMachine(device: DevicePeer): string {
  const shown = device.enrolment["enrolment"];
  const machine = typeof shown === "object" && shown !== null && "machine" in shown ? shown.machine : undefined;
  if (typeof machine !== "string" || !/^[0-9a-f]{32}$/.test(machine)) throw new Error("device enrol printed no enrolment.machine");
  return machine;
}
async function sync04Refusal(attempt: Promise<unknown>): Promise<PublicHttpError> {
  try {
    await attempt;
  } catch (error) {
    if (error instanceof PublicHttpError) return error;
    throw error;
  }
  throw new Error("expected a public refusal; the call succeeded");
}
function sync04Lists(windows: Sync04Windows, ids: readonly string[]): boolean {
  return ids.every(id => windows.some(slot => slot.items.some(item => item.entity_id === id)));
}
async function sync04Search(device: DevicePeer, query: string): Promise<Sync04Search> {
  return (await device.client.request<Sync04Search>("GET", `/api/search/text?query=${encodeURIComponent(query)}`)).body;
}

/* SYNC-04 — decision: WRITTEN (partial).
 * Promise: a device in the default opened mode holds only metadata for the
 *   current window; opening one item fetches exactly that body from home,
 *   which then stays readable with the home link cut and across a device
 *   restart, while its never-opened neighbour is neither local nor fetchable
 *   offline; text search reaches unopened bodies through the device's
 *   caller-bound home route and says when it could not.
 * Doors: EngineFixture.startDevicePeer + SyncLinkProxy (cut, heal); on the
 *   device vault.residence.index / open, vault.notes.read and GET
 *   /api/search/text; on the home vault.notes.create; device kill + restart.
 * Unproved and why: the January ("old-unopened", quartz) window, because
 *   vault.notes.create takes {kind, markdown} only and stamps the live clock
 *   (a NOTE birth door with learned_at, or a fixture revision, is missing);
 *   the private-project canary and grant revocation, because the device
 *   carries only the owner's credential (a narrow reader paired on the home
 *   and a public own-device grant revocation are not set up); the exact hit
 *   set of "opal lantern" (lexical search may also rank other "lantern" items).
 * DEFECT (red since E2E job 23, Fri 13 Nov 2026; FIX row
 *   DEVICE-HOME-SEARCH-MISSES-UNOPENED-NOTE): the device is admitted and the
 *   open, offline and restart steps pass, but its search through home
 *   answers residence {source "home", complete true, hits []} for the
 *   unopened note for the whole 10 s poll. Earlier reds, fixed: the enrol
 *   join guard (#7172), the join proof and the own-device grant catch-up
 *   (this stack).
 */
suite.test(test, "SYNC-04", "A device in opened mode lists only metadata, opens one item from home that stays readable offline and across a restart while its unopened neighbour stays remote, and searches unopened text through home", async () => {
  const scenario = await sync04Scenario();
  const openedText = sync04Text(scenario, scenario.inputs.open);
  const unopenedText = sync04Text(scenario, "new-unopened");
  expect(openedText).toBe(scenario.expected.openedBody);
  const query = scenario.inputs.searchQueries.find(text => unopenedText.includes(text));
  if (!query) throw new Error("SYNC-04 has no query naming the unopened item");

  const home = await EngineFixture.start({ id: "SYNC-04", profile });
  await answerHomeYours(home);
  const link = await SyncLinkProxy.start({ target: home.url });
  // Created before the device joins: its first connection fetches the current
  // thin index. Fixture kind is not given; "research" is a shipped kind.
  const opened = await home.client.call("vault.notes.create", { kind: "research", markdown: openedText });
  const unopened = await home.client.call("vault.notes.create", { kind: "research", markdown: unopenedText });
  const device = await home.startDevicePeer({ id: "SYNC-04-device", homeOrigin: link.url });
  const machine = sync04DeviceMachine(device);

  // Thin listing: both current items, metadata only, no body on the device.
  const index = await awaitPublic(() => device.client.call("vault.residence.index", { machine }),
    answer => answer.state === "applied" && sync04Lists(answer.windows, [opened.id_hex, unopened.id_hex]),
    { label: "device thin index lists both items", timeoutMs: 15_000 });
  if (index.state !== "applied") throw new Error("thin index was not applied");
  const windowOf = new Map<string, string>();
  for (const slot of index.windows) {
    for (const item of slot.items) {
      expect(Object.keys(item).every(key => ["entity_id", "title", "learned_at"].includes(key))).toBe(true);
      windowOf.set(item.entity_id, slot.window);
    }
  }
  const openedWindow = windowOf.get(opened.id_hex);
  const unopenedWindow = windowOf.get(unopened.id_hex);
  if (!openedWindow || !unopenedWindow) throw new Error("thin index names no window for the items");
  for (const note of [opened, unopened]) {
    expect((await device.client.call("vault.notes.read", { note_ref: note.id_hex })).value).toBeNull();
  }

  // Open exactly one item: its body comes from home; the neighbour stays remote.
  const first = await device.client.call("vault.residence.open", { machine, window: openedWindow, item: opened.id_hex });
  if (first.state !== "applied") throw new Error(`first open answered ${first.state}`);
  expect(first.item).toBe(opened.id_hex);
  expect(first.source).toBe("home");
  expect(first.note?.markdown).toBe(openedText);
  expect((await device.client.call("vault.notes.read", { note_ref: unopened.id_hex })).value).toBeNull();

  // Search for unopened text goes to home through the device's own route.
  // Bounded poll: the home indexes the unopened body after vault.notes.create
  // answers; a deadline prints the last residence block (source, complete, hits).
  const remote = await awaitPublic(() => sync04Search(device, query),
    found => found.residence?.source === "home" && found.residence.hits.some(hit => hit.id === unopened.id_hex),
    { label: "device search through home finds the unopened item", timeoutMs: 10_000 });
  expect(remote.residence?.source).toBe("home");
  expect(typeof remote.residence?.complete).toBe("boolean");
  expect(remote.residence?.hits.map(hit => hit.id)).toContain(unopened.id_hex);

  // Failure step: cut the home link.
  link.cut();
  const offline = await device.client.call("vault.residence.open", { machine, window: openedWindow, item: opened.id_hex });
  if (offline.state !== "applied") throw new Error(`offline open answered ${offline.state}`);
  expect(offline.source).toBe("local");
  expect(offline.note?.markdown).toBe(openedText);
  const neighbour = await sync04Refusal(device.client.call("vault.residence.open", { machine, window: unopenedWindow, item: unopened.id_hex }));
  expect(neighbour.reply.status).toBe(400);
  expect(neighbour.error?.code).toBe("BAD_REQUEST");
  const cutSearch = await sync04Search(device, query);
  expect(cutSearch.residence?.source).toBe("localOnly");
  expect(cutSearch.residence?.complete).toBe(false);
  expect(cutSearch.residence?.hits.map(hit => hit.id) ?? []).not.toContain(unopened.id_hex);

  // Crash while cut: the opened copy is durable on the device, the neighbour still remote.
  await device.kill();
  await device.restart();
  const restarted = await device.client.call("vault.residence.open", { machine, window: openedWindow, item: opened.id_hex });
  if (restarted.state !== "applied") throw new Error(`open after restart answered ${restarted.state}`);
  expect(restarted.source).toBe("local");
  expect(restarted.note?.markdown).toBe(openedText);
  const stillRemote = await sync04Refusal(device.client.call("vault.residence.open", { machine, window: unopenedWindow, item: unopened.id_hex }));
  expect(stillRemote.reply.status).toBe(400);
  expect(stillRemote.error?.code).toBe("BAD_REQUEST");

  // Heal: the home route answers again.
  link.heal();
  const healed = await sync04Search(device, query);
  expect(healed.residence?.source).toBe("home");
  expect(healed.residence?.hits.map(hit => hit.id)).toContain(unopened.id_hex);
});

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
interface Sync05Scenario {
  readonly id: string;
  readonly inputs: {
    readonly base: string;
    readonly homeEdit: { readonly replace: string; readonly with: string };
    readonly otherAllowedBody: string;
  };
  readonly expected: { readonly offlineAllowedBody: string };
}
type Sync05Span = NonNullable<FacadeInput<"vault.notes.read">["spans"]>[number];

async function sync05Scenario(): Promise<Sync05Scenario> {
  const fixture = await (await loadFixtures()).readJson<{ readonly scenarios: readonly Sync05Scenario[] }>("sync-scenarios");
  const scenario = fixture.scenarios.find(row => row.id === "SYNC-05");
  if (!scenario) throw new Error("sync-scenarios has no SYNC-05");
  return scenario;
}
/** The device's own MACHINE id: `device enrol` prints it as enrolment.machine. */
function sync05DeviceMachine(device: DevicePeer): string {
  const shown = device.enrolment["enrolment"];
  const machine = typeof shown === "object" && shown !== null && "machine" in shown ? shown.machine : undefined;
  if (typeof machine !== "string" || !/^[0-9a-f]{32}$/.test(machine)) throw new Error("device enrol printed no enrolment.machine");
  return machine;
}
/** Half-open Unicode-scalar span of the one occurrence of `word` (the authored note is ASCII). */
function sync05Span(text: string, word: string): Sync05Span {
  const start = text.indexOf(word);
  if (start < 0 || text.indexOf(word, start + 1) >= 0) throw new Error(`"${word}" must occur exactly once in the authored note`);
  return { start, end: start + word.length };
}
async function sync05LocalBody(device: DevicePeer, noteRef: string): Promise<string | undefined> {
  const read = await withWireReason("SYNC-05 device notes.read", device.client.call("vault.notes.read", { note_ref: noteRef }));
  return read.value?.source === "local" ? read.value.markdown : undefined;
}
async function sync05Standing(client: EngineFixture["client"], predicate: string) {
  const [row, ...others] = (await client.call("vault.claims.list", { predicate, limit: 10 })).value;
  return { count: others.length + (row ? 1 : 0), claim_ref: row?.claim_ref, value: row?.value, source: row?.source, approval: row?.approval, lifecycle: row?.lifecycle };
}

/* SYNC-05 — decision: WRITTEN (partial).
 * Promise: switching an enrolled device from opened to sync-all (its own act,
 *   on the device) makes every authorized body local, so both bodies the
 *   device never opened are readable with the home link cut and after a
 *   device crash; the switch changes no claim's source or approval; and the
 *   home's disjoint edit made during the cut reaches the device on rejoin.
 * Doors: EngineFixture.startDevicePeer + SyncLinkProxy (cut, heal); on the
 *   device vault.residence.index / mode, vault.notes.read, vault.claims.list;
 *   on the home vault.notes.create / read / edit (replace_span),
 *   vault.claims.upsert / list; device kill + restart.
 * Unproved and why: the device's own acknowledged offline edit and the merged
 *   two-writer note: in opened mode the only thin-item promotion before a
 *   write, SyncConnection::edit_opened_item, has no caller, and in all mode
 *   vault.notes.edit on the device replica refuses "replica NOTE edits require
 *   authenticated authority" (note/operations.rs:493-495); the private canary
 *   for a narrow reader (the device carries only the owner credential);
 *   repeated reconnects adding nothing (not proved anywhere yet: SYNC-01 has one partition and one heal).
 * DEFECT (red since E2E job 23, Fri 13 Nov 2026; FIX row
 *   REPLICA-NOTE-READ-400-BEFORE-DOCUMENT): after the sync-all switch the
 *   device's notes.read of a note it never opened answers 400 "invalid NOTE
 *   body: NOTE head document missing", as in SYNC-01. Earlier reds, fixed:
 *   the NOTE subject reference (#7177), the join proof and the own-device
 *   grant catch-up (this stack).
 */
suite.test(test, "SYNC-05", "Switching a device to sync-all makes every authorized body local, readable with the home link cut and after a crash, leaves claim source and approval unchanged, and receives the home's offline-time edit on rejoin", async () => {
  const scenario = await sync05Scenario();
  const { base, homeEdit, otherAllowedBody } = scenario.inputs;
  expect(otherAllowedBody).toBe(scenario.expected.offlineAllowedBody);
  const homeEdited = base.replace(homeEdit.replace, homeEdit.with);
  const predicate = "inventory.crate_contents";

  const home = await EngineFixture.start({ id: "SYNC-05", profile });
  await answerHomeYours(home);
  const owner = home.pairedActor.principalRef;
  const link = await SyncLinkProxy.start({ target: home.url });
  // Fixture kind is not given; "research" is a shipped kind (vault-readable, durable).
  const inventory = await home.client.call("vault.notes.create", { kind: "research", markdown: base });
  const crate = await home.client.call("vault.notes.create", { kind: "research", markdown: otherAllowedBody });
  const scope = await ownerBaseClaimScope(home.client, owner);
  await withWireReason("SYNC-05 claims.upsert", home.client.call("vault.claims.upsert", {
    predicate, subject_ref: crate.id_hex, value: otherAllowedBody, confidence: 0.9, source: "user_stated", scope,
  }));
  const atHome = await sync05Standing(home.client, predicate);
  expect(atHome.count).toBe(1);
  expect(atHome.source).toBe("user_stated");

  const device = await home.startDevicePeer({ id: "SYNC-05-device", homeOrigin: link.url });
  const machine = sync05DeviceMachine(device);
  // Opened mode (the default): the device knows both items but holds neither body.
  await awaitPublic(() => device.client.call("vault.residence.index", { machine }),
    answer => answer.state === "applied"
      && answer.windows.flatMap(slot => slot.items.map(item => item.entity_id)).includes(inventory.id_hex)
      && answer.windows.flatMap(slot => slot.items.map(item => item.entity_id)).includes(crate.id_hex),
    { label: "opened device lists both items", timeoutMs: 15_000 });
  for (const note of [inventory, crate]) {
    expect((await device.client.call("vault.notes.read", { note_ref: note.id_hex })).value).toBeNull();
  }

  const switched = await device.client.call("vault.residence.mode", { machine, mode: "all" });
  if (switched.state !== "applied") throw new Error(`device residence switch answered ${switched.state}`);
  expect(switched.mode).toBe("all");
  await awaitPublic(() => sync05LocalBody(device, inventory.id_hex), body => body === base,
    { label: "inventory body local on the device", timeoutMs: 15_000 });
  await awaitPublic(() => sync05LocalBody(device, crate.id_hex), body => body === otherAllowedBody,
    { label: "crate body local on the device", timeoutMs: 15_000 });
  await awaitPublic(() => sync05Standing(device.client, predicate), standing => standing.count === 1,
    { label: "home claim held on the device" });
  expect(await sync05Standing(device.client, predicate)).toEqual(atHome);

  // Failure step: cut the home link. Every authorized body is still local.
  link.cut();
  expect(await sync05LocalBody(device, inventory.id_hex)).toBe(base);
  expect(await sync05LocalBody(device, crate.id_hex)).toBe(otherAllowedBody);
  // The home writes a disjoint anchored edit while the device is cut off.
  const anchors = await home.client.call("vault.notes.read", { note_ref: inventory.id_hex, spans: [sync05Span(base, homeEdit.replace)] });
  const [span] = anchors.value?.spans ?? [];
  if (!span) throw new Error("Home returned no stable anchor");
  const edited = await home.client.call("vault.notes.edit", {
    note_ref: inventory.id_hex, edit: { kind: "replace_span", start: span.start, end: span.end, text: homeEdit.with },
  });
  expect(edited.outcome).toBe("edited");
  expect(await sync05LocalBody(device, inventory.id_hex)).toBe(base);

  // Rejoin: the home's edit arrives; nothing about the claim changes.
  link.heal();
  await awaitPublic(() => sync05LocalBody(device, inventory.id_hex), body => body === homeEdited,
    { label: "home edit reached the device", timeoutMs: 15_000 });
  expect(await sync05Standing(device.client, predicate)).toEqual(atHome);

  // Crash while cut off again: the sync-all copies are durable, not a live view.
  link.cut();
  await device.kill();
  await device.restart();
  expect(await sync05LocalBody(device, inventory.id_hex)).toBe(homeEdited);
  expect(await sync05LocalBody(device, crate.id_hex)).toBe(otherAllowedBody);
  expect(await sync05Standing(device.client, predicate)).toEqual(atHome);
});

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

/** The foreign row's public standing: its listed claim fields, its evidence
 * verdict and its whole delivery history, read through two doors. */
interface Sync07ForeignState {
  readonly claim: {
    readonly claim_ref: string; readonly value: unknown; readonly source: string | null | undefined;
    readonly lifecycle: string; readonly world_ref: string | null | undefined;
  };
  readonly evidence: {
    readonly foreign_world_ref: string | null | undefined; readonly source: string | null | undefined;
    readonly first_party_corroboration: boolean; readonly writer_ref: string | null | undefined;
  };
  readonly history: readonly NonNullable<Sync07Evidence["delivery_history"]>[number][];
}
async function sync07ForeignState(engine: EngineFixture, claimRef: string): Promise<Sync07ForeignState> {
  const listed = await engine.client.call("vault.claims.list", { predicate: SYNC07_PREDICATE, limit: 10 });
  const [row, ...others] = listed.value.filter(claim => claim.claim_ref === claimRef);
  if (!row) throw new Error(`Claim ${claimRef} is not listed`);
  expect(others).toEqual([]);
  const evidence = await sync07Evidence(engine, claimRef);
  return {
    claim: { claim_ref: row.claim_ref, value: row.value, source: row.source, lifecycle: row.lifecycle, world_ref: row.world_ref },
    evidence: {
      foreign_world_ref: evidence.foreign_world_ref, source: evidence.source,
      first_party_corroboration: evidence.first_party_corroboration, writer_ref: evidence.writer_ref,
    },
    history: evidence.delivery_history ?? [],
  };
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
  const delivery = await withWireReason("SYNC-07 connect.export", engine.client.call("vault.federation.connect.export", {
    pact: pact.pact, window_key: sync07WindowKey(SYNC07_LEARNED_AT, pact.sharerWorld), world_ref: pact.sharerWorld,
  }));
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

  // The foreign row's public standing, saved once: every later check compares
  // the same claim ref against this whole snapshot, never a count or a match.
  const saved = await sync07ForeignState(receiver, foreignClaim.claim_ref);
  expect(saved.claim).toEqual({
    claim_ref: foreignClaim.claim_ref, value: evidenceText, source: "imported", lifecycle: "active", world_ref: foreignWorld,
  });
  expect(saved.evidence.foreign_world_ref).toBe(foreignWorld);
  expect(saved.evidence.source).toBe("imported");
  expect(saved.evidence.first_party_corroboration).toBe(false);
  // Independent vaults may bootstrap the same owner PERSON id; writer_ref
  // preserves the source author. Foreign standing is the world/source/history above and below.
  expect(saved.evidence.writer_ref).toBe(engine.pairedActor.principalRef);
  expect(saved.history).toHaveLength(1);
  const [origin] = saved.history;
  if (!origin) throw new Error("Delivered claim has no delivery origin");
  expect(origin.source_ref).toBe(foreignClaim.claim_ref);
  expect(origin.delivering_pact).toBe(pact.pact);
  expect(origin.consent_epoch).toBe(delivery.body.epoch);
  expect(origin.grant_ref).toBe(pact.receiverGrant.grant);
  expect(origin.source_vault).toBe(pact.sharerVault);
  expect(origin.delivered_row_hash).toMatch(/^[0-9a-f]{64}$/);
  const ownEvidence = await sync07Evidence(receiver, ownClaim.claim_ref);
  expect(ownEvidence.foreign_world_ref ?? null).toBeNull();
  expect(ownEvidence.source).toBe("user_stated");
  expect(ownEvidence.first_party_corroboration).toBe(true);
  expect(ownEvidence.writer_ref).toBe(receiver.pairedActor.principalRef);
  expect(ownEvidence.delivery_history ?? []).toEqual([]);

  // Forged input: altered bytes, or a delivery relabelled as the receiver's own.
  const tampered = await sync07Refusal(receiver.client.call("vault.federation.connect.rejoin", {
    ...delivery, body: { ...delivery.body, update: delivery.body.update.map((byte, index) => index === 0 ? byte ^ 1 : byte) },
  }));
  expect(tampered.reply.status).toBe(400);
  expect(tampered.error?.code).toBe("BAD_REQUEST");
  expect(await sync07ForeignState(receiver, foreignClaim.claim_ref)).toEqual(saved);
  const relabelled = await sync07Refusal(receiver.client.call("vault.federation.connect.rejoin", {
    ...delivery, body: { ...delivery.body, source_vault: pact.receiverVault },
  }));
  expect(relabelled.reply.status).toBe(400);
  expect(relabelled.error?.code).toBe("BAD_REQUEST");
  expect(await sync07ForeignState(receiver, foreignClaim.claim_ref)).toEqual(saved);

  // Crash: the landed row survives on its own, before any redelivery.
  await receiver.kill();
  await receiver.restart();
  expect(await sync07ForeignState(receiver, foreignClaim.claim_ref)).toEqual(saved);
  // The same delivery again: the same single row, the same single origin.
  const replayed = await receiver.client.call("vault.federation.connect.rejoin", delivery);
  expect(replayed.status).toBe("imported");
  expect(replayed.world_ref).toBe(foreignWorld);
  expect(await sync07ForeignState(receiver, foreignClaim.claim_ref)).toEqual(saved);
  const afterReplay = await receiver.client.call("vault.claims.list", { predicate: SYNC07_PREDICATE, limit: 10 });
  expect(afterReplay.value.map(row => row.claim_ref).sort()).toEqual([foreignClaim.claim_ref, ownClaim.claim_ref].sort());
});

/* SYNC-08 — Mesh admission follows pairing should work.
 * Row: OF-535. Canon: ARCH-0023b #two-planes, identity #authority-log.
 * Oracle: sync-scenarios / SYNC-08.
 *
 * Main DOES have an optional mesh listener: the default server build carries
 * feature mesh, and only an explicit ONEIRON_MESH_BIND starts it
 * (ONEIRON_MESH_RELAYS absent: direct-only). token pair --machine and device enrol
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

/* SYNC-09 — covers part of its promise (the runner sets its status). The ID
 *   is a placeholder until OPUS-E2E-1 names the plan row (Engine RULING 12 Nov
 *   2026 22:00).
 * Promise: a freshly enrolled device keeps its paired credential fresh. Its
 *   renewal at start comes before its first sync lands the vault's authority
 *   log, so it cannot sign a machine proof yet; once that log lands the device
 *   renews at once, keeps its holder key, and goes on syncing on the renewed
 *   credential.
 * Its home stays unanswered: the owner never answers it "yours", so the
 *   device joins a home that proves no machine of the vault yet, and still
 *   admits its owner with no 401 (Engine RULING SYNC-HOME-UNANSWERED = B,
 *   14 Nov; job 26 on set 15f8c6941c6 got the 401 here).
 * Doors: EngineFixture.startDevicePeer (DevicePeer.enrolledCredential, read
 *   before the first launch, and readCredential: the credential file that
 *   `device enrol` names and the renewal replaces); on the home
 *   vault.notes.create; on the device vault.residence.index.
 * Unproved and why: the home's record of the renewal (no public read of slip
 *   mints or of the `renews` lineage; the slip doors are renew and revoke
 *   only); a refusal that stays a refusal (a work_school or rented device is
 *   refused by the home for good, and its proof is an absence read); a
 *   renewal after a restart (30 s flow); the retry wait alone, when a
 *   catch-up takes no rows and signals nothing (no fixture serves a pinned
 *   checkpoint that holds every entry, and the first retry is 30 s).
 * DEFECT (FIX row DEVICE-RENEWAL-REFUSED-BEFORE-FIRST-SYNC, Thu 12 Nov 2026):
 *   the renewal at start found "this install is not a machine of the vault
 *   yet" (machine_connection_proof reads no vault id from the empty local
 *   authority log) and refused for the life of the process, so the enrolled
 *   credential was never renewed and the device stopped syncing once it ran
 *   out.
 */
suite.test(test, "SYNC-09", "A freshly enrolled device renews its paired credential once its first sync lands the vault's authority, keeps its holder key, and goes on syncing on the renewed credential", async () => {
  const home = await EngineFixture.start({ id: "SYNC-09", profile });
  const device = await home.startDevicePeer({ id: "SYNC-09-device" });
  const machine = sync01DeviceMachine(device);
  const enrolled = credentialParts(device.enrolledCredential);

  const renewed = await awaitPublic(() => device.readCredential(), credential => credential !== device.enrolledCredential,
    { label: "the device renews its enrolled credential", timeoutMs: 15_000 });
  const fresh = credentialParts(renewed);
  expect(fresh.seed).toBe(enrolled.seed);
  expect(fresh.bearer).not.toBe(enrolled.bearer);

  // Second door: the device syncs on the renewed credential. A note the home
  // creates after the renewal reaches the device's residence index.
  const note = await home.client.call("vault.notes.create", { kind: "research", markdown: "SYNC-09 written after the device renewed its credential" });
  await awaitPublic(() => device.client.call("vault.residence.index", { machine }),
    answer => answer.state === "applied" && answer.windows.some(slot => slot.items.some(item => item.entity_id === note.id_hex)),
    { label: "a home note made after the renewal reaches the device", timeoutMs: 15_000 });
  expect(await device.readCredential()).toBe(renewed);
});
