import { afterAll, expect, test } from "bun:test";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture } from "./support/engine.ts";
import { loadFixtures } from "./support/fixtures.ts";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * Context and room surfaces. Public bindings read at main
 * 0072f2bffa22ca3cacb6b719d26f8b13ba02e246: the generated HTTP SDK/catalog,
 * OpenAPI registrations and handlers, native SDK, and public CLI. Their hashes,
 * canon pins, registry rows, full journeys and independent inputs are in
 * fixtures/surfaces/scenarios.json (asset surfaces-scenarios).
 *
 * G01: missing typed doors are BLOCKED, never passing partial coverage. The
 * signatures beside TODOs describe canon design, not invented callable routes.
 * Existing generic batch/structural.put, execute_code and owner impersonation
 * cannot stand in for the missing operations. No Rust/storage seed or browser.
 * MCP activation uses generated tools with arguments.spec, preserving actual
 * RPC/isError refusals; it must not guess tool names or switch surface modes.
 * No engine constants, harness deadlines, profiles or slot counts are changed.
 */

interface SurfaceFixtures {
  ledger: {
    title: string;
    conversationName: string;
    predicate: string;
    firstName: string;
    currentName: string;
    dossierTitle: string;
    oldAt: number;
    currentAt: number;
    messages: [string, string];
    pageLimit: number;
    neighborLimit: number;
    expected: {
      approval: string;
      oldLifecycle: string;
      currentLifecycle: string;
      claimSource: string;
      claimKind: string;
      messageKind: string;
      conversationKind: string;
      claimEdge: string;
      messageConversationEdge: string;
      messageTurnEdge: string;
      turnCount: number;
      messageCount: number;
    };
  };
}

// SURFACES-01 — Generated card lowers to client capabilities should work.
// Canon: ARCH-0048 #g3, ARCH-0044 #part-a, ARCH-0078 #contract; OF-336/231.
// Design input: {protocolVersion, catalogVersion, root, nodes:[{id, type,
//   children?, fallbackText}], actions, $state, lifecycle}; capability profile
//   {catalogVersion, supportedTypes, features:{streaming,interactivity,media,
//   webArtifacts}}. HTTP sessions negotiate at open/surface change; stateless
// MCP sends clientCapabilities in each call's _meta, NOT initialize alone.
// Design result: the same card identity lowered to the declared catalog:
// expand prebuilts, unwrap unsupported containers, replace unsupported leaves
// with their own fallbackText; unknown protocol -> whole-card fallbackText.
// Emit the fixture card over HTTP and MCP, compare rich/text envelopes with
// fixture facts, submit the unknown type and finish pending -> submitted ->
// archived. Every node must have fallbackText; unsupported is not blank/error.
// Current vault.lenses.default and lens-frame events ARE typed, but accept
// neither an agent-emitted client-owned catalog nor a capability profile.
// GeneratedUiCatalog is currently only "lens_atom_kit"; those fixed-catalog
// calls cannot prove this contract or justify an engine-owned app component set.
suite.todo(test, "SURFACES-01",
  "waits on typed generated-card emit/capability-lowering HTTP and SDK calls — Generated card lowers to client capabilities should work");

// SURFACES-02 — Selection handle cannot grant access should work.
// Canon: ARCH-0004 #access, ARCH-0044 #part-a; OF-242/244/248/439.
// Design: select(frame, atom, span?:{start,end,version}) -> host-issued read
// handle; resolve(handle) -> scoped source/version/cursor span. Offsets count
// Unicode scalars (the fixture's compass emoji is ONE scalar). A result-set
// action names a declared verb plus the selected host-issued handles, never
// arbitrary entity ids, keys, author identities or a write-authority token.
// Render as a narrow viewer while the author has a wider key. Resolve the
// valid selection; act through its declared card action, then try the other
// principal/key, another frame's backing token, a hidden record and an unticked
// id. Require actual refusals and no extra reads/writes; hidden text must be
// absent from JSON, fallbackText, params and receipts. Revoke/narrow the live
// viewer grant and re-use the handle: it must not preserve the old access.
// Current public lens events validate a held card, and inspection.resolve
// reads an inspection link. Neither mints an OF-248 frame-bound span selection.
// LensAtomSelectionRequest/LensReadHandle are internal frame types, not a
// generated HTTP/SDK select/resolve door. Do not forge them in this test.
suite.todo(test, "SURFACES-02",
  "waits on typed frame-bound span-selection and result-set action HTTP and SDK calls — Selection handle cannot grant access should work");

// SURFACES-03 — Brief citation redaction at view time should work.
// Canon: ARCH-0078 #contract, ARCH-0004 #access; OF-225/069/235.
// Canon brief input: markdown plus claim refs for EACH load-bearing sentence;
// citation result re-resolves {claim_ref, stale, drifted, redacted, confidence?,
// lifecycle?, quote?} under the recipient's LIVE read scope, not stored HTML.
// Existing typed calls:
//   vault.shares.create({recipient,brief_ref,world_refs?,facet_refs?,
//     include_unscoped?,expires_at?,travel?}) -> ShareCreated
//   vault.shares.view({share_ref,narrowing?}) -> ScopedReadResult<SharedBriefView?>
//   vault.shares.revoke({share_ref}) -> ShareRevokeReceipt.
// Author the claim-citing fixture brief, share to the real recipient, view and
// follow its returned citation. Narrow source access, view the SAME share,
// and require redaction/no leaked quote. Delete the source and inspect its
// stale/confidence/lifecycle projection without retaining erased text. Revoke
// the share, then re-open the saved link with the original credential: no
// resolving content, not merely an absent row in a listing. Unrelated content
// remains readable as a positive control. Do not treat a static mode-A persona
// copy or uploaded text artifact as this live claim-citing brief.
// Main exposes share views/revocation, not typed brief authoring or a typed
// citation-follow handle. Generic Plugin/body JSON would bypass the prerequisite.
suite.todo(test, "SURFACES-03",
  "waits on typed claim-citing brief authoring and live citation-follow HTTP and SDK calls — Brief citation redaction at view time should work");

// SURFACES-04 — Renderer-neutral ledger, dossier, history and thread reads.
// Canon: ARCH-0044 #part-a, ARCH-0004 #access; OF-249/235.
// Uses an existing conversation as the entity whose name changes. All claims,
// DAG turns and MESSAGE sources are created publicly in this fresh vault.
// This asserts shared source identity/history, not app navigation or back/URL UI.
suite.test(test, "SURFACES-04", "Ledger dossier and thread inspection should work", async () => {
  const fixtures = await loadFixtures();
  const { ledger: data } = await fixtures.readJson<SurfaceFixtures>("surfaces-scenarios");
  const engine = await EngineFixture.start({ id: "SURFACES-04", profile });
  try {
    const conversation = await engine.client.call("vault.conversations.create", {
      body: { name: data.conversationName },
      occurred_start: data.oldAt, occurred_end: data.oldAt, learned_at: data.oldAt,
    });
    const oldClaim = await engine.client.call("vault.claims.upsert", {
      subject_ref: conversation.id, predicate: data.predicate, value: data.firstName,
      confidence: 1, source: data.expected.claimSource,
      occurred_at: data.oldAt, learned_at: data.oldAt, valid_from: data.oldAt,
    });
    const currentClaim = await engine.client.call("vault.claims.upsert", {
      subject_ref: conversation.id, predicate: data.predicate, value: data.currentName,
      confidence: 1, source: data.expected.claimSource,
      occurred_at: data.currentAt, learned_at: data.currentAt, valid_from: data.currentAt,
    });
    expect(oldClaim.approval).toBe(data.expected.approval);
    expect(currentClaim.approval).toBe(data.expected.approval);
    expect(oldClaim.claim).toBeDefined();
    expect(currentClaim.claim).toBeDefined();
    expect(currentClaim.superseded_short_id).toBe(oldClaim.claim_short_id);
    const oldId = oldClaim.claim!.id;
    const currentId = currentClaim.claim!.id;
    expect(currentId).not.toBe(oldId);

    const turns: string[] = [];
    const messages: NonNullable<FacadeResult<"vault.witness">["messages"]> = [];
    for (const [index, content] of data.messages.entries()) {
      const at = index === 0 ? data.oldAt : data.currentAt;
      const appended = await engine.client.call("vault.conversations.records.append", {
        conversation: conversation.id, parent: turns.at(-1) ?? null,
        advance: true, body: { txt: content, speaker: "user", at },
        occurred_start: at, occurred_end: at, learned_at: at,
      });
      expect(appended.head).toBe(appended.id);
      expect(appended.parent).toBe(turns.at(-1) ?? null);
      turns.push(appended.id);
      const witnessed = await engine.client.call("vault.witness", {
        conversation_ref: conversation.id, turn_ref: appended.id, occurred_at: at,
        messages: [{ author: "user", message_type: "text", content, is_visible: true, order: 0 }],
      });
      expect(witnessed.messages).toHaveLength(1);
      expect(witnessed.turn?.id).toBe(appended.id);
      messages.push(witnessed.messages![0]!);
    }
    expect(turns).toHaveLength(data.expected.turnCount);
    expect(messages).toHaveLength(data.expected.messageCount);

    const ledger = await engine.client.call("vault.claims.list", {
      subject_ref: conversation.id, predicate: data.predicate,
      lifecycle: data.expected.currentLifecycle, limit: data.pageLimit,
    });
    expect(ledger.value.map(row => ({ id: row.claim_ref, value: row.value, subject: row.subject_ref })))
      .toEqual([{ id: currentId, value: data.currentName, subject: conversation.id }]);
    const history = await engine.client.call("vault.claims.history", { claim_ref: currentClaim.claim_short_id });
    expect(history.value.map(row => ({ id: row.claim_ref, value: row.value, lifecycle: row.lifecycle, source: row.source })))
      .toEqual([
        { id: oldId, value: data.firstName, lifecycle: data.expected.oldLifecycle, source: data.expected.claimSource },
        { id: currentId, value: data.currentName, lifecycle: data.expected.currentLifecycle, source: data.expected.claimSource },
      ]);
    expect(history.value.every(row => row.subject_ref === conversation.id)).toBe(true);

    // Follow the actual refs returned by inspection reads, including the OLD row.
    for (const row of history.value) {
      expect(row.claim).toBeDefined();
      const resolved = await engine.client.call("vault.refs.resolve", { reference: row.claim!.id });
      expect(resolved.value.record.id).toBe(row.claim_ref);
      const hydrated = await engine.client.call("vault.hydrate", { refs: [row.claim!.id] });
      expect(hydrated.value).toHaveLength(1);
      expect(hydrated.value[0]?.id_hex).toBe(row.claim_ref);
      expect(hydrated.value[0]?.kind).toBe(data.expected.claimKind);
    }
    const dossier = await engine.client.call("vault.get", { entity_ref: conversation.id });
    expect(dossier.value?.kind).toBe(data.expected.conversationKind);
    expect(dossier.value?.body).toMatchObject({ name: data.conversationName });
    const connections = await engine.client.call("vault.neighbors", {
      entity_ref: conversation.id, opts: { edge_kind: data.expected.claimEdge, limit: data.pageLimit },
    });
    expect(connections.value.map(row => row.record?.id).sort()).toEqual([oldId, currentId].sort());
    const bounded = await engine.client.call("vault.neighbors", {
      entity_ref: conversation.id, opts: { edge_kind: data.expected.claimEdge, limit: data.neighborLimit },
    });
    expect(bounded.value).toHaveLength(data.neighborLimit);
    expect([oldId, currentId]).toContain(bounded.value[0]?.record?.id);

    // Existing DagPageResponse; a two-record fixture fits one explicit page.
    const dag = await engine.client.request<{
      head: string | null; root: string | null; main_line: string[]; page: { next: string | null };
    }>("GET", `/v1/core/conversations/${conversation.id}/records?limit=${data.pageLimit}`);
    expect(dag.body.main_line).toEqual(turns);
    expect(dag.body.head).toBe(turns[1]);
    expect(dag.body.root).toBe(turns[0]);
    expect(dag.body.page.next).toBeNull(); // No silently unconsumed page.
    for (const [index, message] of messages.entries()) {
      expect(message.kind).toBe(data.expected.messageKind);
      const hydrated = await engine.client.call("vault.hydrate", { refs: [message.id] });
      expect(hydrated.value[0]?.id_hex).toBe(message.id);
      expect(hydrated.value[0]?.body).toMatchObject({ content: data.messages[index] });
      const resolved = await engine.client.call("vault.refs.resolve", { reference: message.id });
      expect(resolved.value.record.id).toBe(message.id);
      const roomLink = await engine.client.call("vault.neighbors", {
        entity_ref: message.id,
        opts: { edge_kind: data.expected.messageConversationEdge, limit: data.pageLimit },
      });
      expect(roomLink.value.map(link => link.record?.id)).toEqual([conversation.id]);
      const turnLink = await engine.client.call("vault.neighbors", {
        entity_ref: message.id,
        opts: { edge_kind: data.expected.messageTurnEdge, limit: data.pageLimit },
      });
      expect(turnLink.value.map(link => link.record?.id)).toEqual([turns[index]]);
    }

    const input = {
      title: data.title, ledger: [currentId],
      dossiers: [{ entity_ref: conversation.id, title: data.dossierTitle }],
      threads: messages.map(message => message.id),
    } satisfies FacadeInput<"vault.lenses.default">;
    const projected = await engine.client.call("vault.lenses.default", input);
    const card = projected.value;
    expect(card.card_id).toBe(card.render.cardId);
    expect(card.render.actions).toEqual([]); // This projection is read-only.
    const ledgerRows = card.render.nodes.flatMap(node => node.atom.kind === "ledger_row" ? [node] : []);
    expect(ledgerRows).toHaveLength(1);
    const ledgerAtom = ledgerRows[0]!.atom;
    if (ledgerAtom.kind !== "ledger_row") throw new Error("Expected ledger row");
    expect(ledgerAtom.props.cells.some(cell => cell.value === currentId)).toBe(true);
    expect(ledgerAtom.props.cells.some(cell => cell.value.includes(data.currentName))).toBe(true);
    expect(ledgerRows[0]!.bindings?.length).toBeGreaterThan(0);
    const dossiers = card.render.nodes.flatMap(node => node.atom.kind === "dossier_section" ? [node.atom.props] : []);
    expect(dossiers).toHaveLength(1);
    expect(dossiers[0]?.title).toBe(data.dossierTitle);
    expect(dossiers[0]?.lines?.join("\n")).toContain(data.conversationName);
    const thread = card.render.nodes.flatMap(node => node.atom.kind === "thread_entry" ? [node] : []);
    expect(thread.map(node => node.atom.kind === "thread_entry" ? node.atom.props.body : null)).toEqual(data.messages);
    expect(thread.every(node => (node.bindings?.length ?? 0) > 0)).toBe(true);
    expect(card.render.nodes.filter(node => node.atom.kind === "meta_line").map(node => node.atom.props))
      .toEqual(expect.arrayContaining(messages.map(message => expect.objectContaining({ value: message.id }))));
    await engine.artifacts.json("inspection.json", {
      conversation: conversation.id, history: history.value, ledger: ledger.value,
      dag: dag.body, neighbors: connections.value, projection: projected,
    });
  } finally {
    await engine.close();
  }
});

// SURFACES-05 — Audience intersection and speaker identity should work.
// Canon: ARCH-0067 #room, ARCH-0004 #access; OF-365/293.
// Design: assemble(room, authenticated presence/speaker evidence, query) ->
// {admitted context, room Scope, disclosure receipt}. Scope is ordinary Scope,
// not a room-only permission model: PUBLIC union the common permitted scope
// of the non-owner audience, met with caller/allowed-set/turn ceilings.
// The fixture pins A={common,aOnly}, B={common,bOnly}. Owner+A -> public/common/A;
// owner+A+B and A+B -> public/common. Removing owner NEVER widens. Unknown or
// unverified speaker claiming owner -> public only; a verified session proof
// outranks a spoken label, but presence alone grants no extra clearance.
// Compare admitted context/ids and receipt with EVERY fixture presence set,
// not merely final model prose. Private diary text must never reach inference.
// Existing POST /v1/core/context-pack accepts interlocutor controls and the
// owner disclosure clearance doors exist. They do not create the required
// distinct human/contact principals or supply a typed authenticated speaker-
// evidence change contract. pairActor pairs an existing principal, never
// creates one; arbitrary PERSON rows and client owner_present=true are not proof.
suite.todo(test, "SURFACES-05",
  "waits on typed PERSON/contact onboarding and authenticated room-speaker evidence fixture doors — Audience intersection and speaker identity should work");

// SURFACES-06 — Persona snapshot under explicit access should work.
// Canon: ARCH-0004 #access, ARCH-0078 #contract; OF-325/042.
// Design request: {requester, capability:"companion_profile.read",
// scope:{kind:"companion_profile",person_ref,facet_ref?},reason} -> auditable
// pending request. Holder answer -> grant; revoke -> no further profile read.
// Existing HTTP/SDK request: self.grants.ask({pr,scope:{kind:"companion_profile",
// facet_ref?}}) -> {request,asked,status}; the host binds the requester.
// Existing HTTP: POST /v1/companion/access-grants
// {principal_ref,scope,created_at?,expires_at?} -> {id,capability,status,...};
// POST /v1/companion/access-grants/{id}/revoke {revoked_at?};
// GET /v1/owner/persona?subject= -> {subject,stamp,identity_line,rows:[{row_id,
// kind,text,provenance_refs,attribution,struck}],compiled_at,stale_after_secs};
// POST /v1/owner/persona/export {subject,stamp,strike,unstrike} ->
// {export_id,memory_pack,markdown,included_row_ids,struck_row_ids,...}.
// Request ONLY profile A's facet, approve/read/revoke, then prove denied reads
// while profile B/private unrelated diary remain absent throughout. Preview,
// strike the fixture row, export exactly that stamp, inspect source citations
// and owner edits on the accepted copy. A changed preview must not export old
// consent. Mode A is a handed copy: revoke means no re-issue, NOT remote erasure
// of an already exported file. Do not silently test designed mode B instead.
// The ask, pending-request list and grant create/revoke ARE present. A typed
// holder answer to THAT request and an editable accepted-persona-copy call
// are absent. Direct grant create does not resolve the pending request.
suite.todo(test, "SURFACES-06",
  "waits on typed companion profile-access request-answer and accepted persona-copy edit calls — Persona snapshot under explicit access should work");

// SURFACES-07 — Custom agents and saved workflow should work.
// Canon: ARCH-0079 #work, ARCH-0053 #r4-lifecycle; OF-334/417.
// Canon semantic input: define_agent({skills,connectors,mcps,model,scope,
// ceiling,prompt/preset blocks}) -> revisioned AgentDefinitionRef;
// save_workflow({name,steps:AgentDefinitionRef[]}) -> WorkflowRef;
// dispatch(agent|workflow,task) -> task/attempt refs with definition revisions,
// inherited read/write ceilings and provenance. These are design signatures,
// not guessed endpoint names. Current WorkflowDefinition stores
// {name,steps,revision,forked_from?}; AGENT_DEF is an existing core record.
// Create the fixture Reader and Proposer via HTTP/MCP, save/dispatch the ordered
// workflow and inspect both attempts: read/propose only in common scope, no
// hidden data or self-approved widening. Edit Reader to revision 2 with a
// narrower scope, dispatch again, and require new work uses the new revision;
// the earlier task/attempt keeps its original snapshot/provenance. Definition
// edits do not mutate running authority. Also attempt an explicit wider slice
// as the worker: held/refused, never secretly widened. Every task/attempt stays
// independently identified; a workflow is not itself a private memory scope.
// Main exposes task dispatch to EXISTING definitions, not typed public custom
// definition create/edit or saved-workflow save/dispatch. shape.actor toggles
// an existing agent_id. Raw AGENT_DEF/WORKFLOW batch writes are not substitutes.
suite.todo(test, "SURFACES-07",
  "waits on typed AGENT_DEF create/edit and saved-workflow save/dispatch HTTP and SDK calls — Custom agents and saved workflow should work");

// SURFACES-08 — Inbox and weave report respect reader scope should work.
// Canon: ARCH-0067 #what, ARCH-0003 #learning; OF-414/499.
// Existing SDK: vault.weave.report({sections:[{kind,predicates?,edge_kinds?}]})
// -> {sections,narrowing}; vault.weave.digest({scheduled_for?}) ->
// {scheduled_for,rendered_at,sections,narrowing,lens?,lens_refused?}|null;
// vault.weave.link.wrong({source_ref,kind,target_ref}) ->
// {label_ref,source_ref,kind,target_ref,actor_ref,recorded_at}.
// self.inbox.list lists delivered notifications; GET /v1/owner/inbox is the
// identity-filtered agent inbox lens. Those two projections are NOT synonyms.
// Publicly create two actors, the private project, concern/consent items and
// one completed weave, then drain each actor's inbox pages. Compare membership,
// grouping by run and identity, and absence of the other actor's private bytes.
// Render live and trigger the scheduled digest through the SAME scoped lens;
// compare semantic section/item membership, not volatile timestamps or layout.
// Label the fixture link wrong as its actual reader. Read the persisted label,
// require correct actor and source refs and the edge still present; the label
// is anchored evidence for learning, never a fabricated learning.* claim or
// an extra win. Neither correction nor digest may expose the private project.
// Main has report/digest READS, corrections and inbox projections. It lacks a
// typed complete-weave/scheduled-digest trigger and typed setup for these
// grouped concern/consent deliveries. Generic consolidation.enqueue's opaque
// payload and direct projector rows would not prove this end-to-end flow.
suite.todo(test, "SURFACES-08",
  "waits on typed completed-weave/digest trigger and grouped identity-inbox fixture doors — Inbox and weave report respect reader scope should work");

// SURFACES-09 — Memory injection proxy follows connector ceiling should work.
// Canon: ARCH-0044 #part-a, ARCH-0040 #mcp-actor-ceilings; OF-445/230.
// Main DOES serve POST /v1/chat/completions and owner POST
// /v1/owner/connectors/proxy {actor} -> {connector,key,slate}. Its handwritten
// Rust request is {model,messages:[{role,content}],stream?,n?,temperature?,...};
// reply is OpenAI {id,object:"chat.completion",choices,usage,
// oneiron:{injected,remembered:{claim,approval}|{error}}}. Holder proof and a
// live owner-stamped openai_proxy connector key are required. There is no
// generated SDK method or OpenAPI request/result contract for this route.
// Required typed setup also distinguishes revoking the connector's WRITE
// grant from deleting memory, withdrawing all read access or disabling the
// entire connector. A paired credential alone is not a stamped connector key.
// Use ScriptedProviders as the declared OpenAI downstream, not a fake engine.
// Create admitted/private memories with explicit scope, register/admit the
// connector, send the fixture chat, and capture downstream request bytes.
// Require admitted memory and original chat, private memory ABSENT from every
// role/field (not merely hidden from the final answer). The exact scripted
// reply/usage must return. Inspect the stored integration.exchange: actual
// connector author, tool_output, Proposed and only the connector's write scope.
// Revoke only its write grant; retry normal chat. Current design needs read
// AND propose/write at admission, so require refusal before any downstream
// call and no added exchange, while a separate authorised read still works.
// A client user/name field cannot change author or scope. No Convex migration,
// legacy dispatch wire, special-purpose product actor or live model is used.
// G01: preserve this typed requirement; do not wrap the unbound route in a
// local fake SDK, cast a verb, or use generic callVerb/execute_code to unlock it.
suite.todo(test, "SURFACES-09",
  "waits on typed OpenAPI/SDK memory-injection proxy and connector write-grant revocation contracts — Memory injection proxy follows connector ceiling should work");
