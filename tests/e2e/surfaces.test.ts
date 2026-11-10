import { afterAll, expect, test } from "bun:test";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, type PairedActor, awaitPublic } from "./support/engine.ts";
import { loadFixtures, ownerBaseClaimScope, requireAsset } from "./support/fixtures.ts";
import { defineFile, redactor, secretHex } from "./support/run.ts";
import { McpRpcError, PublicHttpError, PublicHttpClient, CliError, CliClient, McpClient, credentialParts, type SdkDriverResult } from "./support/clients.ts";
import { randomUUID } from "node:crypto";
import { ScriptedProviders, openaiText } from "./support/providers.ts";

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

/*
 * SURFACES-02 promise: selecting a rendered source never lends the author's
 * read or write authority. Resolve uses the selector's live key; a declared
 * result-set action acts only on the selected rows through its existing gate.
 * Wrong principal/key/frame, hidden source and unticked-row attempts refuse,
 * leave readable refusal receipts, and reveal no hidden text. A real owner's
 * grant revocation takes effect at the same reader's next selection use.
 *
 * Existing doors (not blockers): vault.lenses.select, vault.lenses.resolve,
 * vault.lenses.result_set.action. Compare REST facade, CLI api call, MCP
 * tool-first arguments.spec, and SDK facade paths vault.lenses.select,
 * vault.lenses.resolve and vault.lenses.result_set.action.
 *
 * Still missing: public owner revocation of the approved relationship data
 * grant. Also unproved: a positive Unicode-scalar document span and a hosted
 * result-set card declaring a real deterministic write. Do not manufacture
 * EntityDoc heads, connector-import metadata, frames, backing refs or grants.
 * vault.lenses.default is read-only; an undeclared-action refusal is not a
 * selected-row write. An owner-only select/resolve smoke case would omit the
 * mandatory ungranted-agent and same-agent-after-revocation checks.
 *
 * Restart coverage must read the durable source and revocation again, refuse
 * the old process-local card/selection, then re-render under the same reader's
 * live authority. It must not expect a selection locator to be durable, nor
 * count a restart refusal as proof of live grant revocation before restart.
 */
suite.todo(test, "SURFACES-02",
  "waits on public owner revocation of relationship data grants and a hosted result-set render door — Selection handle cannot grant access should work");

type surfaces03Verb = "vault.notes.author_brief" | "vault.notes.follow_citation"
  | "vault.shares.create" | "vault.shares.view" | "vault.shares.revoke";
type surfaces03Command = { [V in surfaces03Verb]: {
  verb: V; input: FacadeInput<V>; inputs?: FacadeInput<V>[];
  refusal?: { code: "INVENTED_REFERENCE" | "FORBIDDEN"; message?: string };
} }[surfaces03Verb];
type surfaces03Grant = NonNullable<FacadeInput<"vault.gate.policy.put">["manifest"]["scoped_grants"]>[number];
interface surfaces03Fixtures {
  ledger: { oldAt: number };
  cases: Array<{ id: string; fixture: {
    briefMarkdown: string; loadBearingSentence: string; sourceClaimValue: string; recipient: string;
    expected: {
      visible: { redacted: boolean; stale: boolean };
      permissionNarrowed: { redacted: boolean; sourceTextPresent: boolean };
      sourceDeleted: { sourceTextPresent: boolean };
      shareRevoked: { resolvesContent: boolean };
    };
  } }>;
}
interface surfaces03RefusalReceipt {
  ref: string; verb: surfaces03Verb; actorRef: string;
  transport: "http_facade" | "mcp"; code: string;
}
function surfaces03Object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("SURFACES-03 expected an object envelope");
  return value as Record<string, unknown>;
}
function surfaces03String(value: unknown): string {
  if (typeof value !== "string" || value.length === 0)
    throw new Error("SURFACES-03 expected a nonempty wire string");
  return value;
}
function surfaces03Contains(value: unknown, forbidden: readonly string[]): boolean {
  const bytes = Buffer.from(typeof value === "string" ? value : JSON.stringify(value) ?? "");
  return forbidden.some(text => bytes.includes(Buffer.from(text)));
}
async function surfaces03Versions(actor: PairedActor): Promise<ReadonlyMap<string, string>> {
  await actor.mcp.initialize();
  const catalog = surfaces03Object(await actor.mcp.listTools());
  if (!Array.isArray(catalog.tools)) throw new Error("SURFACES-03 tools/list has no tools");
  const versions = new Map<string, string>();
  const required = ["vault.notes.author_brief", "vault.notes.follow_citation",
    "vault.shares.create", "vault.shares.view", "vault.shares.revoke"];
  for (const entry of catalog.tools) {
    const tool = surfaces03Object(entry);
    if (typeof tool.name !== "string" || !required.includes(tool.name)) continue;
    const schema = surfaces03Object(tool.inputSchema);
    const properties = surfaces03Object(schema.properties);
    const version = surfaces03Object(properties.schema_version).const;
    if (typeof version === "string") versions.set(tool.name, version);
  }
  for (const verb of required) expect(versions.has(verb)).toBe(true);
  return versions;
}

// One SDK process per phase, not one process per verb. Only transport envelopes
// are removed here; read DTOs, including narrowing, are compared intact below.
async function surfaces03Run(
  engine: EngineFixture, actor: PairedActor, versions: ReadonlyMap<string, string>,
  commands: readonly surfaces03Command[], receipts: surfaces03RefusalReceipt[],
  observe: (label: string, value: unknown) => void,
): Promise<unknown[][]> {
  const columns: unknown[][] = commands.map(() => []);
  const inputFor = (command: surfaces03Command, index: number) => {
    if (!command.inputs) return command.input;
    expect(command.inputs).toHaveLength(4);
    const input = command.inputs[index];
    if (!input) throw new Error("SURFACES-03 missing distinct surface input");
    return input;
  };
  const remember = (ref: unknown, command: surfaces03Command, transport: "http_facade" | "mcp", code: string) => {
    const receiptRef = surfaces03String(ref);
    expect(/^call:[a-f0-9]{32}$/.test(receiptRef)).toBe(true);
    receipts.push({ ref: receiptRef, verb: command.verb, actorRef: actor.principalRef, transport, code });
  };
  const refusal = (value: unknown, command: surfaces03Command) => {
    if (!command.refusal) throw new Error("SURFACES-03 unexpected refusal");
    const error = surfaces03Object(value);
    expect(error.code).toBe(command.refusal.code);
    const message = surfaces03String(error.message);
    if (command.refusal.message !== undefined) expect(message).toBe(command.refusal.message);
    expect(Array.isArray(error.suggestions) && error.suggestions.length > 0).toBe(true);
    return { code: error.code, message };
  };
  for (const [index, command] of commands.entries()) {
    const column = columns[index];
    if (!column) throw new Error("SURFACES-03 missing command column");
    if (command.refusal) {
      const reply = await actor.client.raw("POST", `/v1/core/facade/${command.verb}`, inputFor(command, 0));
      observe(`REST ${command.verb}`, reply.raw);
      expect(reply.status).toBe(command.refusal.code === "INVENTED_REFERENCE" ? 422 : 403);
      const error = surfaces03Object(surfaces03Object(reply.body).error);
      expect(typeof error.requestId === "string" && error.requestId.length > 0).toBe(true);
      expect(error.receiptRef).toBe(reply.headers.get("x-oneiron-receipt-ref"));
      remember(error.receiptRef, command, "http_facade", command.refusal.code);
      column.push(refusal(error, command));
    } else {
      const value = await actor.client.call(command.verb, inputFor(command, 0));
      observe(`REST ${command.verb}`, value);
      column.push(value);
    }
    const cli = await actor.cli.run(["api", "call", command.verb, "--data", "-"], JSON.stringify(inputFor(command, 1)));
    observe(`CLI ${command.verb} stdout`, cli.stdout);
    observe(`CLI ${command.verb} stderr`, cli.stderr);
    expect(cli.exitCode).toBe(command.refusal ? 1 : 0);
    const cliBody: unknown = JSON.parse(cli.stdout);
    if (command.refusal) {
      const error = surfaces03Object(surfaces03Object(cliBody).error);
      expect(typeof error.requestId === "string" && error.requestId.length > 0).toBe(true);
      remember(error.receiptRef, command, "http_facade", command.refusal.code);
      column.push(refusal(error, command));
    } else column.push(cliBody);
    const version = versions.get(command.verb);
    if (!version) throw new Error("SURFACES-03 missing tool schema_version");
    try {
      const result = await actor.mcp.callTool(command.verb, {
        schema_version: version,
        consent: { policy_ref: "policy:surfaces-03", purpose: "brief citation parity" },
        arguments: { spec: inputFor(command, 2) },
      });
      observe(`MCP ${command.verb}`, result);
      expect(command.refusal === undefined).toBe(true);
      const body = surfaces03Object(result);
      expect(body.isError).toBe(false);
      const structured = surfaces03Object(body.structuredContent);
      expect(Object.hasOwn(structured, "output")).toBe(true);
      column.push(structured.output);
    } catch (error) {
      if (!(error instanceof McpRpcError) || !command.refusal) throw error;
      observe(`MCP ${command.verb} refusal`, error.response);
      if (!("error" in error.response)) throw new Error("SURFACES-03 missing RPC error");
      const rpc = error.response.error;
      expect(rpc.code).toBe(command.refusal.code === "INVENTED_REFERENCE" ? -32602 : -32020);
      const data = surfaces03Object(rpc.data);
      expect(data.kind).toBe("facade_error");
      expect(data.error_code).toBe("facade_error");
      expect(Array.isArray(data.recovery_suggestions) && data.recovery_suggestions.length > 0).toBe(true);
      remember(data.receipt_ref, command, "mcp", "facade_error");
      column.push({ code: command.refusal.code, message: rpc.message });
    }
  }
  const sdk = await engine.sdk.run("typescript", {
    mode: "remote", url: engine.url, credential: actor.credential,
  }, commands.map(command => ({ verb: "facade" as const, path: command.verb, input: inputFor(command, 3) })));
  observe("SDK stdout", sdk.process.stdout);
  observe("SDK stderr", sdk.process.stderr);
  expect(sdk.process.exitCode).toBe(0);
  expect(sdk.results).toHaveLength(commands.length);
  for (const [index, command] of commands.entries()) {
    const result = sdk.results[index];
    const column = columns[index];
    if (!result || !column) throw new Error("SURFACES-03 missing SDK operation result");
    expect(result.ok).toBe(command.refusal === undefined);
    if (result.ok) column.push(result.value);
    else {
      expect(surfaces03Object(result.error).name).toBe("OneironError");
      column.push(refusal(result.error, command));
    }
    expect(column).toHaveLength(4);
    if (command.refusal) for (const value of column) expect(value).toEqual(column[0]);
  }
  return columns;
}
function surfaces03Values<V extends surfaces03Verb>(matrix: unknown[][], index: number, _verb: V): FacadeResult<V>[] {
  const column = matrix[index];
  if (!column || column.length !== 4) throw new Error("SURFACES-03 missing four-surface result");
  // Unknown crosses only at the CLI/MCP/SDK JSON boundary, using the generated DTO.
  return column as FacadeResult<V>[];
}
function surfaces03Equal(values: readonly unknown[]): void {
  expect(values).toHaveLength(4);
  for (const value of values) expect(value).toEqual(values[0]);
}

/*
 * Promise: shared briefs and their saved citations recheck live source grants,
 * hide inaccessible/deleted source text, and stop resolving after share revoke,
 * identically through REST, CLI, MCP tool-first and the remote TypeScript SDK.
 * Public setup: PERSON/pairing, research notes, claim upsert, human kind blessing,
 * owner policy CAS grants, author_brief/share create; public observation uses
 * notes.read/defaults, claims.list/get, view/follow and call receipts. One restart.
 * No model, external HTTP, UI/link navigation, source-edit drift, exports/recall,
 * Python SDK or already-downloaded-copy erasure is claimed. Known prose leak is
 * asserted at the end, not accepted or allowed to skip the remaining journey.
 */
suite.test(test, "SURFACES-03", "Shared briefs redact inaccessible citations across REST CLI MCP and SDK and stay revoked after restart", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<surfaces03Fixtures>("surfaces-scenarios");
  const entry = data.cases.find(row => row.id === "SURFACES-03");
  if (!entry) throw new Error("SURFACES-03 fixture is absent");
  const spec = entry.fixture;
  const unrelatedText = "The unrelated opening time is noon.";
  for (const value of [spec.briefMarkdown, spec.loadBearingSentence, spec.sourceClaimValue, spec.recipient, unrelatedText])
    redactor.add(value, Buffer.from(value).toString("base64"));
  const forbidden = [spec.sourceClaimValue, Buffer.from(spec.sourceClaimValue).toString("base64")];
  const leaks: Array<{ label: string; found: boolean }> = [];
  const receipts: surfaces03RefusalReceipt[] = [];
  const observe = (stage: string, hidden: boolean) => (label: string, value: unknown) => {
    if (hidden) leaks.push({ label: `${stage}: ${label}`, found: surfaces03Contains(value, forbidden) });
  };
  const engine = await EngineFixture.start({ id: "SURFACES-03", profile, surface: "tool-first" });
  try {
    const owner = engine.pairedActor;
    redactor.add(owner.credential, Buffer.from(owner.credential).toString("base64"));
    const person = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: spec.recipient }, occurred_at: data.ledger.oldAt,
    });
    const personRead = await engine.client.call("vault.get", { entity_ref: person.id_hex });
    expect(personRead.value?.kind).toBe("PERSON");
    expect(personRead.value?.body).toMatchObject({ name: spec.recipient });
    const agent = await engine.pairActor({
      principalRef: person.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    redactor.add(agent.credential, Buffer.from(agent.credential).toString("base64"));
    const agentVersions = await surfaces03Versions(agent);
    const ownerVersions = await surfaces03Versions(owner);
    const source = await engine.client.call("vault.notes.create", { kind: "research", markdown: spec.loadBearingSentence });
    const unrelated = await engine.client.call("vault.notes.create", { kind: "research", markdown: unrelatedText });
    for (const [noteRef, text] of [[source.id_hex, spec.loadBearingSentence], [unrelated.id_hex, unrelatedText]] as const)
      expect((await engine.client.call("vault.notes.read", { note_ref: noteRef })).value?.markdown).toBe(text);
    const scope = await ownerBaseClaimScope(engine.client, owner.principalRef);
    const claim = await engine.client.call("vault.claims.upsert", {
      scope, subject_ref: source.id_hex, predicate: "identity.name", value: spec.sourceClaimValue,
      source: "user_stated", confidence: 1, occurred_at: data.ledger.oldAt,
    });
    expect(claim.approval).toBe("auto");
    if (!claim.claim) throw new Error("SURFACES-03 claim has no public reference");
    const claimRef = claim.claim.id;
    const claimRows = await engine.client.call("vault.claims.list", { subject_ref: source.id_hex, limit: 10 });
    expect(claimRows.value.map(row => ({ id: row.claim_ref, value: row.value, lifecycle: row.lifecycle, confidence: row.confidence })))
      .toEqual([{ id: claimRef, value: spec.sourceClaimValue, lifecycle: "active", confidence: 1 }]);
    const stamp = await engine.client.call("vault.notes.bless_brief_kind", {});
    expect(stamp.person_ref).toBe(owner.principalRef);
    const scalars = Array.from(spec.loadBearingSentence);
    const quoteScalars = Array.from(spec.sourceClaimValue);
    const start = scalars.findIndex((_value, index) => scalars.slice(index, index + quoteScalars.length).join("") === spec.sourceClaimValue);
    expect(start).toBeGreaterThanOrEqual(0);
    const authorInput = {
      markdown: spec.briefMarkdown,
      citations: [{ claim_ref: claimRef, document_ref: source.id_hex, start, end: start + quoteScalars.length }],
    } satisfies FacadeInput<"vault.notes.author_brief">;
    const authorInputs = ["REST", "CLI", "MCP", "SDK"].map(surface => ({
      ...authorInput, markdown: `# ${surface} brief\n\n${spec.briefMarkdown}`,
    }));
    for (const input of authorInputs) redactor.add(input.markdown, Buffer.from(input.markdown).toString("base64"));
    const canonicalBrief = await engine.client.call("vault.notes.author_brief", authorInput);
    expect((await engine.client.call("vault.notes.read", { note_ref: canonicalBrief.id_hex })).value?.markdown).toBe(spec.briefMarkdown);
    const kind = await engine.client.call("vault.notes.defaults", { note_ref: canonicalBrief.id_hex });
    expect({ extraction: kind.defaults.extraction, context: kind.defaults.context, retention: kind.defaults.retention })
      .toEqual({ extraction: stamp.extraction, context: stamp.context, retention: stamp.retention });

    const top: surfaces03Grant["scope"] = {
      worlds: { kind: "all" }, facets: { kind: "all" }, bands: { kind: "all" },
      audience: { kind: "all" }, verbs: { kind: "all" }, sensitivity: { kind: "all" },
    };
    const ownerShare: surfaces03Grant = {
      actor_class: "human", actor_ref: owner.principalRef, effector: "share_brief", scope: top, receipt_required: true,
    };
    const agentShare: surfaces03Grant = { ...ownerShare, actor_class: "agent", actor_ref: agent.principalRef };
    const noteRead: surfaces03Grant = {
      actor_class: "agent", actor_ref: agent.principalRef, effector: "core:read", receipt_required: false,
      scope: { ...top, bands: { kind: "some", values: [111] }, verbs: { kind: "some", values: ["read"] } },
    };
    const claimRead: surfaces03Grant = {
      ...noteRead, scope: { ...top, bands: { kind: "some", values: [0] }, verbs: { kind: "some", values: ["read"] } },
    };
    const initialPolicy = await engine.client.call("vault.gate.policy.get", {});
    const original = initialPolicy.manifests.find(row => row.manifest_ref === initialPolicy.default_manifest_ref);
    if (!original) throw new Error("SURFACES-03 default policy is absent");
    const originalGrants = original.manifest.scoped_grants ?? [];
    const setGrants = async (extra: surfaces03Grant[]) => {
      const before = await engine.client.call("vault.gate.policy.get", {});
      const current = before.manifests.find(row => row.manifest_ref === before.default_manifest_ref);
      if (!current) throw new Error("SURFACES-03 default policy disappeared");
      const written = await engine.client.call("vault.gate.policy.put", {
        manifest_ref: current.manifest_ref, expected_body_hash: current.body_hash,
        manifest: { ...current.manifest, scoped_grants: [...originalGrants, ...extra] },
      });
      const after = await engine.client.call("vault.gate.policy.get", { manifest_ref: current.manifest_ref });
      const saved = after.manifests.find(row => row.manifest_ref === current.manifest_ref);
      expect(saved?.trusted).toBe(true);
      expect(saved?.body_hash).toBe(written.manifest.body_hash);
      expect(saved?.manifest).toEqual(written.manifest.manifest);
      expect(saved?.manifest.scoped_grants?.length).toBe(originalGrants.length + extra.length);
      return written.manifest;
    };
    const positiveControl = async () => {
      const note = await agent.client.call("vault.notes.read", { note_ref: unrelated.id_hex });
      expect(note.value?.markdown).toBe(unrelatedText);
      expect(surfaces03Contains(note, forbidden)).toBe(false);
    };
    await setGrants([ownerShare, noteRead]);
    expect((await agent.client.call("vault.notes.read", { note_ref: source.id_hex })).value?.markdown).toBe(spec.loadBearingSentence);
    const createInput = {
      recipient: agent.principalRef, brief_ref: canonicalBrief.id_hex,
      world_refs: [scope.world_id], facet_refs: [scope.scope_facet_id], include_unscoped: true,
      travel: { born_with: [] },
    } satisfies FacadeInput<"vault.shares.create">;
    const shareInputs = ["REST", "CLI", "MCP", "SDK"].map(() => {
      const shareId = crypto.randomUUID().replaceAll("-", "");
      redactor.add(shareId, Buffer.from(shareId).toString("base64"));
      return { ...createInput, share_id: shareId };
    });
    const canonicalShare = await engine.client.call("vault.shares.create", createInput);
    const viewInput = { share_ref: canonicalShare.share_id } satisfies FacadeInput<"vault.shares.view">;
    const deniedAuthor: surfaces03Command = {
      verb: "vault.notes.author_brief", input: authorInput,
      refusal: { code: "INVENTED_REFERENCE",
        message: "the record named at `/citations/0/claim_ref` does not resolve for this writer; the write was refused and the refusal receipted" },
    };
    const deniedCreate: surfaces03Command = { verb: "vault.shares.create", input: createInput, refusal: { code: "FORBIDDEN" } };
    const absent = await surfaces03Run(engine, agent, agentVersions, [
      { verb: "vault.shares.view", input: viewInput }, deniedAuthor, deniedCreate,
    ], receipts, observe("without-source-grant", true));
    const redacted = (view: FacadeResult<"vault.shares.view">) => {
      expect(view.value === null).toBe(false);
      if (!view.value) throw new Error("SURFACES-03 valid share must still render a redacted view");
      expect(view.value.share_ref).toBe(canonicalShare.share_id);
      expect(view.value.citations).toHaveLength(1);
      const citation = view.value.citations[0];
      if (!citation) throw new Error("SURFACES-03 redacted citation is absent");
      expect(citation.redacted).toBe(spec.expected.permissionNarrowed.redacted);
      expect(citation.claim_ref === claimRef).toBe(false);
      expect({ quote: citation.quote, confidence: citation.confidence, lifecycle: citation.lifecycle,
        stale: citation.stale, drifted: citation.drifted })
        .toEqual({ quote: null, confidence: null, lifecycle: null, stale: false, drifted: false });
      expect(view.value.born_with).toEqual({});
      return citation;
    };
    const absentViews = surfaces03Values(absent, 0, "vault.shares.view");
    surfaces03Equal(absentViews);
    for (const view of absentViews) redacted(view);
    await positiveControl();

    await setGrants([ownerShare, noteRead, claimRead, agentShare]);
    const firstVisible = await agent.client.call("vault.shares.view", viewInput);
    const savedCitation = firstVisible.value?.citations[0];
    if (!firstVisible.value || !savedCitation) throw new Error("SURFACES-03 visible citation is absent");
    expect(savedCitation).toEqual({ claim_ref: claimRef, stale: spec.expected.visible.stale,
      drifted: false, redacted: spec.expected.visible.redacted, confidence: 1, lifecycle: "active", quote: spec.sourceClaimValue });
    expect(surfaces03Contains(firstVisible.value.html, [spec.loadBearingSentence])).toBe(true);
    const followInput = {
      share_ref: firstVisible.value.share_ref, claim_ref: savedCitation.claim_ref,
    } satisfies FacadeInput<"vault.notes.follow_citation">;
    const wrongRevoke: surfaces03Command = {
      verb: "vault.shares.revoke", input: viewInput,
      refusal: { code: "FORBIDDEN", message: "vault.shares.revoke: share revocation requires issuer or owner" },
    };
    const visible = await surfaces03Run(engine, agent, agentVersions, [
      { verb: "vault.shares.view", input: viewInput }, { verb: "vault.notes.follow_citation", input: followInput },
      { verb: "vault.notes.author_brief", input: authorInput, inputs: authorInputs },
      { verb: "vault.shares.create", input: createInput, inputs: shareInputs },
      wrongRevoke,
    ], receipts, observe("visible", false));
    const visibleViews = surfaces03Values(visible, 0, "vault.shares.view");
    const visibleFollows = surfaces03Values(visible, 1, "vault.notes.follow_citation");
    surfaces03Equal(visibleViews); surfaces03Equal(visibleFollows);
    for (const view of visibleViews) expect(view).toEqual(firstVisible);
    for (const follow of visibleFollows) expect(follow.value).toEqual(savedCitation);
    const authored = surfaces03Values(visible, 2, "vault.notes.author_brief");
    expect(new Set(authored.map(row => row.id_hex)).size).toBe(4);
    for (const [index, brief] of authored.entries()) {
      expect(brief.entity_ref.length > 0 && brief.receipt_ref.length > 0).toBe(true);
      const resolved = await engine.client.call("vault.refs.resolve", { reference: brief.entity_ref });
      expect(resolved.value.record.id).toBe(brief.id_hex);
      expect(resolved.value.record.kind).toBe("NOTE");
      if (brief.record) {
        expect(brief.record.id).toBe(brief.id_hex);
        expect(brief.record.kind).toBe("NOTE");
      }
      expect((await engine.client.call("vault.notes.read", { note_ref: brief.id_hex })).value?.markdown).toBe(authorInputs[index]?.markdown);
      // Reading text alone cannot prove each surface captured its citation pins.
      const witnessShare = await engine.client.call("vault.shares.create", { ...createInput, brief_ref: brief.id_hex });
      const witnessed = await agent.client.call("vault.shares.view", { share_ref: witnessShare.share_id });
      expect(witnessed.value?.share_ref).toBe(witnessShare.share_id);
      expect(witnessed.value?.citations).toEqual([savedCitation]);
    }
    // Each alias was resolved above; only allocation-dependent IDs/labels and
    // the facade write marker differ. Preserve the record kind/presence.
    surfaces03Equal(authored.map(row => ({
      entity_ref: "brief", id_hex: "brief", receipt_ref: row.receipt_ref.startsWith("put:") ? "put:brief" : row.receipt_ref,
      record: row.record ? { kind: row.record.kind, id: "brief", label: "brief" } : null,
    })));
    const shares = surfaces03Values(visible, 3, "vault.shares.create");
    expect(new Set(shares.map(row => row.share_id)).size).toBe(4);
    surfaces03Equal(shares.map(({ share_id: _id, created_at: _at, ...stable }) => stable));
    for (const [index, share] of shares.entries()) {
      expect(share.share_id).toBe<unknown>(shareInputs[index]?.share_id);
      expect(share.recipient).toBe(agent.principalRef);
      expect(share.brief_ref).toBe(canonicalBrief.id_hex);
      expect(share.travel).toEqual({ born_with: [] });
      const view = await agent.client.call("vault.shares.view", { share_ref: share.share_id });
      expect(view.value?.share_ref).toBe(share.share_id);
      expect(view.value?.citations).toEqual([savedCitation]);
    }
    // The refused revoke did not change the owner's share.
    expect(await agent.client.call("vault.shares.view", viewInput)).toEqual(firstVisible);

    // Keep NOTE-only read matched: deleting the last read row falls back to the
    // resident credential and is NOT a valid CLAIM-grant revocation fixture.
    const narrowedPolicy = await setGrants([ownerShare, noteRead]);
    await engine.client.call("vault.notes.set_overrides", { note_ref: source.id_hex, overrides: { context: "owner_only" } });
    const narrowed = await surfaces03Run(engine, agent, agentVersions, [
      { verb: "vault.shares.view", input: viewInput }, { verb: "vault.notes.follow_citation", input: followInput },
      deniedAuthor, deniedCreate,
    ], receipts, observe("permission-narrowed", true));
    const narrowedViews = surfaces03Values(narrowed, 0, "vault.shares.view");
    const narrowedFollows = surfaces03Values(narrowed, 1, "vault.notes.follow_citation");
    surfaces03Equal(narrowedViews); surfaces03Equal(narrowedFollows);
    for (const [index, view] of narrowedViews.entries()) expect(narrowedFollows[index]?.value).toEqual(redacted(view));
    expect((await engine.client.call("vault.notes.defaults", { note_ref: source.id_hex })).overrides.context).toBe("owner_only");
    const hiddenNote = await agent.client.call("vault.notes.read", { note_ref: source.id_hex });
    expect(hiddenNote.value).toBeNull();
    expect(surfaces03Contains(hiddenNote, forbidden)).toBe(false);
    const hiddenClaims = await agent.client.call("vault.claims.list", { subject_ref: source.id_hex, limit: 10 });
    expect(hiddenClaims.value).toEqual([]);
    expect(surfaces03Contains(hiddenClaims, forbidden)).toBe(false);
    await positiveControl();

    const deletion = await engine.client.call("vault.delete", { entity_ref: claimRef, reason: "user_hard_delete" });
    expect(deletion.existed).toBe(true);
    expect(["applied", "completion_pending"]).toContain(deletion.state);
    await awaitPublic(() => engine.client.call("vault.get", { entity_ref: claimRef }), row => row.value === null,
      { label: "SURFACES-03 source deletion readback" });
    await awaitPublic(() => agent.client.call("vault.shares.view", viewInput),
      row => row.value !== null && row.value.citations.length === 0,
      { label: "SURFACES-03 erased citation readback" });
    const deleted = await surfaces03Run(engine, agent, agentVersions, [
      { verb: "vault.shares.view", input: viewInput }, { verb: "vault.notes.follow_citation", input: followInput },
    ], receipts, observe("source-deleted", true));
    const deletedViews = surfaces03Values(deleted, 0, "vault.shares.view");
    const deletedFollows = surfaces03Values(deleted, 1, "vault.notes.follow_citation");
    surfaces03Equal(deletedViews); surfaces03Equal(deletedFollows);
    for (const view of deletedViews) {
      expect(view.value?.share_ref).toBe(canonicalShare.share_id);
      expect(view.value?.citations).toEqual([]);
    }
    for (const follow of deletedFollows) expect(follow.value).toBeNull();
    await positiveControl();
    const revokes = surfaces03Values(await surfaces03Run(engine, owner, ownerVersions, [
      { verb: "vault.shares.revoke", input: viewInput },
    ], receipts, observe("share-revoke", true)), 0, "vault.shares.revoke");
    surfaces03Equal(revokes);
    for (const revoke of revokes) {
      expect(revoke.share_ref).toBe(canonicalShare.share_id);
      expect(revoke.status).toBe("revoked");
      expect(typeof revoke.revoked_at).toBe("number");
    }
    expect((await agent.client.call("vault.shares.view", viewInput)).value).toBeNull();
    expect((await agent.client.call("vault.notes.follow_citation", followInput)).value).toBeNull();
    const readRefusalReceipt = async (expected: surfaces03RefusalReceipt) => {
      const receipt = await awaitPublic(() => engine.client.call("vault.receipts.get", { receipt_ref: expected.ref }),
        row => row !== null, { label: "SURFACES-03 refusal receipt readback" });
      if (!receipt) throw new Error("SURFACES-03 refusal receipt is absent");
      expect(receipt.receipt_ref).toBe(expected.ref);
      expect(receipt.verb.split("/").at(-1)).toBe(expected.verb);
      expect(receipt.actor_ref).toBe(expected.actorRef);
      expect(receipt.actor_class).toBe("agent");
      expect(receipt.transport).toBe(expected.transport);
      expect(receipt.outcome).toEqual({ refused: { code: expected.code } });
      expect(surfaces03Contains(receipt, forbidden)).toBe(false);
      return receipt;
    };
    expect(receipts).toHaveLength(15);
    for (const receipt of receipts) await readRefusalReceipt(receipt);
    const wrongActorReceipt = receipts.find(row => row.verb === "vault.shares.revoke" && row.transport === "http_facade");
    if (!wrongActorReceipt) throw new Error("SURFACES-03 wrong-actor refusal has no receipt");
    const savedReceipt = await readRefusalReceipt(wrongActorReceipt);

    await engine.restart();
    const restarted = await surfaces03Run(engine, agent, agentVersions, [
      { verb: "vault.shares.view", input: viewInput }, { verb: "vault.notes.follow_citation", input: followInput },
    ], receipts, observe("restarted-revoked-share", true));
    const restartedViews = surfaces03Values(restarted, 0, "vault.shares.view");
    const restartedFollows = surfaces03Values(restarted, 1, "vault.notes.follow_citation");
    surfaces03Equal(restartedViews); surfaces03Equal(restartedFollows);
    for (const value of [...restartedViews, ...restartedFollows])
      expect(value.value !== null).toBe(spec.expected.shareRevoked.resolvesContent);
    expect(await readRefusalReceipt(wrongActorReceipt)).toEqual(savedReceipt);
    expect((await engine.client.call("vault.get", { entity_ref: claimRef })).value).toBeNull();
    expect((await agent.client.call("vault.notes.read", { note_ref: source.id_hex })).value).toBeNull();
    expect((await engine.client.call("vault.notes.defaults", { note_ref: source.id_hex })).overrides.context).toBe("owner_only");
    expect((await engine.client.call("vault.notes.read", { note_ref: canonicalBrief.id_hex })).value !== null).toBe(true);
    const restartedPolicy = await engine.client.call("vault.gate.policy.get", { manifest_ref: narrowedPolicy.manifest_ref });
    const persisted = restartedPolicy.manifests.find(row => row.manifest_ref === narrowedPolicy.manifest_ref);
    expect(persisted?.body_hash).toBe(narrowedPolicy.body_hash);
    expect(persisted?.manifest).toEqual(narrowedPolicy.manifest);
    await positiveControl();
    // Fixture promise, not today's renderer: report only labels, never private bytes.
    expect(spec.expected.permissionNarrowed.sourceTextPresent).toBe(false);
    expect(spec.expected.sourceDeleted.sourceTextPresent).toBe(false);
    expect(leaks.filter(row => row.found).map(row => row.label)).toEqual([]);
  } finally {
    await engine.close();
  }
});

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
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const oldClaim = await engine.client.call("vault.claims.upsert", {
      scope,
      subject_ref: conversation.id, predicate: data.predicate, value: data.firstName,
      confidence: 1, source: data.expected.claimSource,
      occurred_at: data.oldAt, learned_at: data.oldAt, valid_from: data.oldAt,
    });
    const currentClaim = await engine.client.call("vault.claims.upsert", {
      scope,
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
    const boundedId = bounded.value[0]?.record?.id;
    if (boundedId === undefined) throw new Error("Neighbor has no record reference");
    expect([oldId, currentId]).toContain(boundedId);

    // Existing DagPageResponse; a two-record fixture fits one explicit page.
    const dag = await engine.client.request<{
      head: string | null; root: string | null; main_line: string[]; page: { next: string | null };
    }>("GET", `/v1/core/conversations/${conversation.id}/records?limit=${data.pageLimit}`);
    expect(dag.body.main_line).toEqual(turns);
    const [rootTurn, headTurn] = turns;
    if (rootTurn === undefined || headTurn === undefined) throw new Error("Expected two conversation turns");
    expect(dag.body.head).toBe(headTurn);
    expect(dag.body.root).toBe(rootTurn);
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

interface surfaces06Fixtures {
  ledger: { oldAt: number };
  cases: Array<{ id: string; fixture?: {
    profiles: [string, string]; requester: string; requestedFacet: string;
    identityLine: string; includedFact: string; struckFact: string;
    unrelatedDiary: string; ownerEdit: string;
  } }>;
}
function surfaces06Object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SURFACES-06 expected a public JSON object (body withheld)");
  }
  return value as Record<string, unknown>;
}
function surfaces06Absent(value: unknown, privateValues: readonly string[]): void {
  const bytes = Buffer.from(typeof value === "string" ? value : JSON.stringify(value) ?? "");
  expect(privateValues.every(value => !bytes.includes(Buffer.from(value))
    && !bytes.includes(Buffer.from(Buffer.from(value).toString("base64"))))).toBe(true);
}
function surfaces06Content(value: FacadeResult<"vault.personas.preview">) {
  // Only compile time is volatile. Keep the stamp, ordered rows and citations.
  const { compiled_at: _time, ...content } = value;
  return content;
}
function surfaces06McpArguments(input: FacadeInput<"vault.personas.preview">) {
  return {
    schema_version: "mcp_tool_args.v1",
    consent: { policy_ref: "policy:surfaces-06", purpose: "persona preview parity" },
    arguments: { spec: input },
  };
}
async function surfaces06Previews(
  engine: EngineFixture, input: FacadeInput<"vault.personas.preview">, privateValues: readonly string[],
): Promise<FacadeResult<"vault.personas.preview">> {
  const rest = await engine.client.call("vault.personas.preview", input);
  const cli = await engine.cli.run(["api", "call", "vault.personas.preview", "--data", "-"], JSON.stringify(input));
  surfaces06Absent([rest, cli.stdout, cli.stderr], privateValues);
  expect(cli.exitCode).toBe(0);
  const cliValue = JSON.parse(cli.stdout) as FacadeResult<"vault.personas.preview">;
  const mcp = await engine.mcp.callTool("vault.personas.preview", surfaces06McpArguments(input));
  surfaces06Absent(mcp, privateValues);
  expect(surfaces06Object(mcp).isError).toBe(false);
  const structured = surfaces06Object(surfaces06Object(mcp).structuredContent);
  expect(structured.tool).toBe("vault.personas.preview");
  const mcpValue = structured.output as FacadeResult<"vault.personas.preview">;
  const sdk = await engine.sdk.run("typescript", {
    mode: "remote", url: engine.url, credential: engine.pairedActor.credential,
  }, [{ verb: "facade", path: "vault.personas.preview", input }]);
  surfaces06Absent([sdk.process.stdout, sdk.process.stderr, sdk.results], privateValues);
  expect(sdk.process.exitCode).toBe(0);
  expect(sdk.results).toHaveLength(1);
  const sdkRow = sdk.results[0];
  if (sdkRow === undefined || !sdkRow.ok) throw new Error("SURFACES-06 SDK persona preview failed");
  const sdkValue = sdkRow.value as FacadeResult<"vault.personas.preview">;
  for (const value of [cliValue, mcpValue, sdkValue]) {
    expect(surfaces06Content(value)).toEqual(surfaces06Content(rest));
  }
  return rest;
}
async function surfaces06RefusalReceipt(
  engine: EngineFixture, reference: unknown, actor: PairedActor,
  transport: "http_facade" | "mcp", code: string, privateValues: readonly string[],
): Promise<NonNullable<FacadeResult<"vault.receipts.get">>> {
  expect(typeof reference === "string" && reference.startsWith("call:")).toBe(true);
  if (typeof reference !== "string") throw new Error("SURFACES-06 refusal omitted its public receipt ref");
  const read = await engine.client.call("vault.receipts.get", { receipt_ref: reference });
  surfaces06Absent(read, privateValues);
  if (read === null) throw new Error("SURFACES-06 refusal receipt did not read back");
  expect({ ref: read.receipt_ref, actor: read.actor_ref, actorClass: read.actor_class,
    verb: read.verb, transport: read.transport, outcome: read.outcome }).toEqual({
    ref: reference, actor: actor.principalRef, actorClass: "agent",
    verb: "vault.personas.preview", transport, outcome: { refused: { code } },
  });
  expect(read.request_digest.length > 0 && (read.result_digest?.length ?? 0) > 0).toBe(true);
  return read;
}

/*
 * PARTIAL: an owner-authored, nonempty, source-cited persona preview is the
 * same through REST / CLI / tool-first MCP / TypeScript SDK, refuses a paired
 * agent, and survives restart. Claims and diary are written through public
 * verbs and read through vault.get; preview observes those writes separately.
 * No profile grant is exercised: owner persona acts and grant-gated psych
 * profiles are different doors. Populated facet access, approve/revoke, copy
 * strikes/export/edit and stale export consent remain unproved. Accepted-copy
 * content has no public read-back door. All four refusal receipts are read
 * before restart and compared with their saved rows after restart.
 */
suite.test(test, "SURFACES-06", "Owner persona previews cite their sources across surfaces, refuse agents, and survive restart", async () => {
  const fixtures = await (await loadFixtures()).readJson<surfaces06Fixtures>("surfaces-scenarios");
  const data = fixtures.cases.find(row => row.id === "SURFACES-06")?.fixture;
  if (data === undefined) throw new Error("SURFACES-06 fixture missing");
  const privatePerson = `SURFACES-06-profile-b-${secretHex(12)}`;
  const privateDiary = `${data.unrelatedDiary} SURFACES-06-${secretHex(12)}`;
  for (const value of [privatePerson, privateDiary, data.identityLine, data.includedFact, data.struckFact]) {
    redactor.add(value, Buffer.from(value).toString("base64"));
  }
  const privateValues = [privatePerson, privateDiary];
  const engine = await EngineFixture.start({ id: "SURFACES-06", profile, surface: "tool-first" });
  try {
    const owner = engine.pairedActor.principalRef;
    const scope = await ownerBaseClaimScope(engine.client, owner);
    const readerPerson = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: data.requester }, occurred_at: fixtures.ledger.oldAt,
    });
    const otherPerson = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: data.profiles[1] }, occurred_at: fixtures.ledger.oldAt,
    });
    for (const person of [readerPerson, otherPerson]) {
      const read = await engine.client.call("vault.get", { entity_ref: person.id_hex });
      expect(read.value?.id_hex).toBe(person.id_hex);
      expect(read.value?.kind).toBe("PERSON");
      expect(surfaces06Object(read.value?.body).name).toBe(person === readerPerson ? data.requester : data.profiles[1]);
    }
    const reader = await engine.pairActor({
      principalRef: readerPerson.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    const claimInputs = [
      { subject: owner, predicate: "profile.name", value: data.identityLine, salience: 0.9 },
      { subject: owner, predicate: "profile.observation", value: data.includedFact, salience: 0.8 },
      { subject: owner, predicate: "profile.visits", value: data.struckFact, salience: 0.7 },
      { subject: otherPerson.id_hex, predicate: "profile.observation", value: privatePerson, salience: 0.8 },
    ];
    const claimIds: string[] = [];
    for (const input of claimInputs) {
      const result = await engine.client.call("vault.claims.upsert", {
        subject_ref: input.subject, predicate: input.predicate, value: input.value,
        confidence: 1, source: "user_stated", scope, salience: input.salience,
        occurred_at: fixtures.ledger.oldAt, learned_at: fixtures.ledger.oldAt,
      });
      expect(result.approval).toBe("auto");
      await engine.awaitReceipt(result.receipt_ref);
      const read = await engine.client.call("vault.get", { entity_ref: result.claim_short_id });
      if (read.value === null) throw new Error("SURFACES-06 written claim did not read back");
      expect(read.value.kind).toBe("CLAIM");
      expect((JSON.stringify(read.value.body) ?? "").includes(input.value)).toBe(true);
      claimIds.push(read.value.id_hex);
    }
    const [nameClaim, observationClaim, visitsClaim] = claimIds;
    if (nameClaim === undefined || observationClaim === undefined || visitsClaim === undefined) {
      throw new Error("SURFACES-06 missing setup claim refs");
    }
    const diary = await engine.client.call("self.memory.diary", { content: privateDiary });
    const diaryRead = await engine.client.call("vault.get", { entity_ref: diary.entry_ref });
    expect((JSON.stringify(diaryRead.value?.body) ?? "").includes(privateDiary)).toBe(true);

    const input = { subject: owner } satisfies FacadeInput<"vault.personas.preview">;
    const preview = await surfaces06Previews(engine, input, privateValues);
    expect(preview.subject).toBe(owner);
    expect(preview.identity_line).toBe(data.identityLine);
    const identity = preview.rows.find(row => row.kind === "identity" && row.text === data.identityLine);
    const observation = preview.rows.find(row => row.kind === "subject_claim" && row.text === `profile.observation: ${data.includedFact}`);
    const visits = preview.rows.find(row => row.kind === "subject_claim" && row.text === `profile.visits: ${data.struckFact}`);
    if (identity === undefined || observation === undefined || visits === undefined) throw new Error("SURFACES-06 cited fixture rows missing");
    for (const [row, citation] of [[identity, nameClaim], [observation, observationClaim], [visits, visitsClaim]] as const) {
      expect(row.provenance_refs).toEqual([`claim:${citation}`]);
      expect(row.struck).toBe(false);
    }

    const message = "vault.personas.preview is the vault owner's";
    const receipts: NonNullable<FacadeResult<"vault.receipts.get">>[] = [];
    let restError: PublicHttpError | undefined;
    try { await reader.client.call("vault.personas.preview", input); }
    catch (error) { if (!(error instanceof PublicHttpError)) throw error; restError = error; }
    if (restError === undefined) throw new Error("SURFACES-06 agent preview unexpectedly succeeded");
    surfaces06Absent(restError.reply.raw, privateValues);
    expect(restError.reply.status).toBe(403);
    const error = surfaces06Object(surfaces06Object(restError.reply.body).error);
    expect(error.code).toBe("FORBIDDEN");
    expect(error.message).toBe(message);
    expect(typeof error.requestId === "string" && error.requestId.length > 0).toBe(true);
    expect(Array.isArray(error.suggestions) && error.suggestions.length > 0).toBe(true);
    expect(restError.reply.headers.get("x-oneiron-receipt-ref")).toBe(error.receiptRef as string);
    receipts.push(await surfaces06RefusalReceipt(engine, error.receiptRef, reader, "http_facade", "FORBIDDEN", privateValues));

    const cli = await reader.cli.run(["api", "call", "vault.personas.preview", "--data", "-"], JSON.stringify(input));
    surfaces06Absent([cli.stdout, cli.stderr], privateValues);
    expect(cli.exitCode).not.toBe(0);
    const cliError = surfaces06Object(surfaces06Object(JSON.parse(cli.stdout)).error);
    expect(cliError.code).toBe("FORBIDDEN");
    expect(cliError.message).toBe(message);
    expect(typeof cliError.requestId === "string" && cliError.requestId.length > 0).toBe(true);
    expect(Array.isArray(cliError.suggestions) && cliError.suggestions.length > 0).toBe(true);
    receipts.push(await surfaces06RefusalReceipt(engine, cliError.receiptRef, reader, "http_facade", "FORBIDDEN", privateValues));

    let rpc: McpRpcError | undefined;
    try { await reader.mcp.callTool("vault.personas.preview", surfaces06McpArguments(input)); }
    catch (error) { if (!(error instanceof McpRpcError)) throw error; rpc = error; }
    if (rpc === undefined || !("error" in rpc.response)) throw new Error("SURFACES-06 expected a JSON-RPC refusal, not a tool result");
    surfaces06Absent(rpc.response, privateValues);
    const mcpError = rpc.response.error;
    const mcpData = surfaces06Object(mcpError.data);
    expect(mcpError.code).toBe(-32020);
    expect(mcpError.message).toBe(message);
    expect(mcpData.kind).toBe("facade_error");
    expect(mcpData.error_code).toBe("facade_error");
    expect(mcpData.human_message).toBe(message);
    expect(typeof mcpData.request_id === "string" && mcpData.request_id.length > 0).toBe(true);
    expect(Array.isArray(mcpData.recovery_suggestions) && mcpData.recovery_suggestions.length > 0).toBe(true);
    receipts.push(await surfaces06RefusalReceipt(engine, mcpData.receipt_ref, reader, "mcp", "facade_error", privateValues));

    const sdk = await engine.sdk.run("typescript", {
      mode: "remote", url: engine.url, credential: reader.credential,
    }, [{ verb: "facade", path: "vault.personas.preview", input }]);
    surfaces06Absent([sdk.process.stdout, sdk.process.stderr, sdk.results], privateValues);
    expect(sdk.process.exitCode).toBe(0); // Driver catches the operation's exception.
    expect(sdk.results).toHaveLength(1);
    const sdkRow = sdk.results[0];
    if (sdkRow === undefined || sdkRow.ok) throw new Error("SURFACES-06 SDK agent preview did not refuse");
    const sdkError = surfaces06Object(sdkRow.error);
    expect(sdkError.code).toBe("FORBIDDEN");
    expect(sdkError.message).toBe(message);
    expect(Array.isArray(sdkError.suggestions) && sdkError.suggestions.length > 0).toBe(true);
    receipts.push(await surfaces06RefusalReceipt(engine, sdkRow.receiptRef, reader, "http_facade", "FORBIDDEN", privateValues));

    await engine.restart();
    const restarted = await surfaces06Previews(engine, input, privateValues);
    expect(surfaces06Content(restarted)).toEqual(surfaces06Content(preview));
    for (const receipt of receipts) {
      const read = await engine.client.call("vault.receipts.get", { receipt_ref: receipt.receipt_ref });
      surfaces06Absent(read, privateValues);
      expect(read).toEqual(receipt);
    }
  } finally {
    await engine.close();
  }
});

type surfaces07ReadVerb = "vault.agents.get" | "vault.workflows.get" | "vault.workflows.status";
type surfaces07Read = {
  [V in surfaces07ReadVerb]: { verb: V; input: FacadeInput<V>; expected: FacadeResult<V> }
}[surfaces07ReadVerb];
type surfaces07DeniedVerb = "vault.agents.update" | "vault.workflows.update";
type surfaces07Denied = {
  [V in surfaces07DeniedVerb]: { verb: V; input: FacadeInput<V> }
}[surfaces07DeniedVerb];
interface surfaces07Fixtures {
  cases: { id: string; fixture?: {
    definitions: { name: string }[];
    workflow: { name: string; steps: string[] };
    edit: { name: string; revision: number };
  } }[];
}

function surfaces07Object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SURFACES-07 expected a public JSON object");
  }
  return value as Record<string, unknown>;
}
function surfaces07Id(): string {
  const value = secretHex(16);
  redactor.add(value, Buffer.from(value).toString("base64"));
  return value;
}
function surfaces07McpArguments(tools: unknown, verb: string, spec: unknown): Record<string, unknown> {
  const listing = surfaces07Object(tools);
  if (!Array.isArray(listing.tools)) throw new Error("SURFACES-07 tools/list has no tools");
  const tool: unknown = listing.tools.find((item: unknown) => surfaces07Object(item).name === verb);
  if (tool === undefined) throw new Error(`SURFACES-07 missing public MCP tool ${verb}`);
  const properties = surfaces07Object(surfaces07Object(surfaces07Object(tool).inputSchema).properties);
  const version = surfaces07Object(properties.schema_version).const;
  if (typeof version !== "string") throw new Error("SURFACES-07 missing MCP schema_version const");
  return { schema_version: version,
    consent: { policy_ref: "policy:surfaces-07", purpose: "saved workflow revision parity" },
    arguments: { spec } };
}
function surfaces07AssertRun(
  run: FacadeResult<"vault.workflows.status">,
  workflowRef: string,
  revision: number,
  definitions: readonly FacadeResult<"vault.agents.get">[],
): void {
  expect(run).toMatchObject({ workflow_ref: workflowRef, workflow_revision: revision,
    results: [], task_ref: null, release_refusal: null });
  expect(run.steps.length).toBe(definitions.length);
  expect(run.root_attempt_ref).toMatch(/^[a-f0-9]{32}$/);
  expect(run.active_attempt_ref).toMatch(/^[a-f0-9]{32}$/);
  expect(run.active_attempt_ref).not.toBe(run.root_attempt_ref);
  for (const [index, definition] of definitions.entries()) {
    const captured = run.steps[index];
    if (!captured) throw new Error("SURFACES-07 workflow omitted a captured step");
    expect(captured.requested_agent_ref).toBe(definition.agent_def_ref);
    expect(captured.agent_def_ref).toBe(definition.agent_def_ref);
    expect(captured.definition).toEqual(definition.definition);
    expect(captured.caller_origin).toHaveProperty("connection.locality");
  }
}
async function surfaces07Parity(engine: EngineFixture, tools: unknown, reads: readonly surfaces07Read[]): Promise<void> {
  for (const read of reads) {
    expect(await engine.client.call(read.verb, read.input)).toEqual(read.expected);
    expect(await engine.cli.call(read.verb, read.input)).toEqual(read.expected);
    const reply = surfaces07Object(await engine.mcp.callTool(read.verb,
      surfaces07McpArguments(tools, read.verb, read.input)));
    expect(reply.isError).toBe(false);
    const structured = surfaces07Object(reply.structuredContent);
    expect(structured.tool).toBe(read.verb);
    expect(structured.output).toEqual(read.expected);
  }
  const sdk = await engine.sdk.run("typescript", {
    mode: "remote", url: engine.url, credential: engine.pairedActor.credential,
  }, reads.map(read => ({ verb: "facade" as const, path: read.verb, input: read.input })));
  expect(sdk.process.exitCode).toBe(0);
  expect(sdk.results.length).toBe(reads.length);
  for (const [index, read] of reads.entries()) {
    const result = sdk.results[index];
    if (!result) throw new Error("SURFACES-07 SDK omitted a read result");
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("SURFACES-07 SDK refused an owner read");
    expect(result.value).toEqual(read.expected);
  }
}
async function surfaces07RefusalReceipt(
  engine: EngineFixture, ref: unknown, verb: surfaces07DeniedVerb,
  actorRef: string, transport: "http_facade" | "mcp", code: string,
): Promise<NonNullable<FacadeResult<"vault.receipts.get">>> {
  if (typeof ref !== "string" || !/^call:[a-f0-9]{32}$/.test(ref)) {
    throw new Error("SURFACES-07 refusal must carry its real public call receipt; SDK driver must retain lastReceiptRef()");
  }
  const receipt = await awaitPublic(
    () => engine.client.call("vault.receipts.get", { receipt_ref: ref }),
    row => row !== null, { label: "SURFACES-07 refusal receipt" },
  );
  if (receipt === null) throw new Error("SURFACES-07 refusal receipt did not persist");
  expect(receipt).toMatchObject({ receipt_ref: ref, verb: transport === "http_facade" ? `v1/core/facade/${verb}` : verb,
    actor_ref: actorRef, actor_class: "agent", transport, outcome: { refused: { code } } });
  return receipt;
}
async function surfaces07Refuse(
  engine: EngineFixture, actor: PairedActor, tools: unknown, denied: readonly surfaces07Denied[],
): Promise<NonNullable<FacadeResult<"vault.receipts.get">>[]> {
  const receipts: NonNullable<FacadeResult<"vault.receipts.get">>[] = [];
  const expectedErrors: Record<string, unknown>[] = [];
  await actor.mcp.initialize();
  for (const request of denied) {
    const message = `${request.verb} is the vault owner's`;
    const http = await actor.client.raw("POST", `/v1/core/facade/${request.verb}`, request.input);
    expect(http.status).toBe(403);
    const error = surfaces07Object(surfaces07Object(http.body).error);
    expect(error).toMatchObject({ code: "FORBIDDEN", message,
      requestId: expect.any(String), suggestions: ["Present the owner's own verified, unattenuated credential."] });
    expect(error.receiptRef).toBe(http.headers.get("x-oneiron-receipt-ref"));
    receipts.push(await surfaces07RefusalReceipt(engine, error.receiptRef,
      request.verb, actor.principalRef, "http_facade", "FORBIDDEN"));
    expectedErrors.push({ code: error.code, message: error.message, suggestions: error.suggestions });

    const cli = await actor.cli.run(["api", "call", request.verb, "--data", "-"], JSON.stringify(request.input));
    expect(cli.exitCode).toBe(1);
    expect(cli.stderr.length).toBeGreaterThan(0);
    const cliError = surfaces07Object(surfaces07Object(JSON.parse(cli.stdout)).error);
    expect({ code: cliError.code, message: cliError.message, suggestions: cliError.suggestions })
      .toEqual({ code: error.code, message: error.message, suggestions: error.suggestions });
    expect(cliError.requestId).toEqual(expect.any(String));
    receipts.push(await surfaces07RefusalReceipt(engine, cliError.receiptRef,
      request.verb, actor.principalRef, "http_facade", "FORBIDDEN"));

    const mcp = await actor.mcp.rpc("tools/call", { name: request.verb,
      arguments: surfaces07McpArguments(tools, request.verb, request.input),
      _meta: { "oneiron/invocation": surfaces07Id() } });
    if (!("error" in mcp)) throw new Error("SURFACES-07 MCP allowed an agent owner act");
    expect(mcp.error.code).toBe(-32020);
    const data = surfaces07Object(mcp.error.data);
    expect(data).toMatchObject({ kind: "facade_error", error_code: "facade_error",
      human_message: message, request_id: expect.any(String), recovery_suggestions: expect.any(Array) });
    // This is the explicit transport mapping, not acceptance of an unrelated refusal.
    expect({ code: "FORBIDDEN", message: data.human_message }).toEqual<unknown>({ code: error.code, message: error.message });
    receipts.push(await surfaces07RefusalReceipt(engine, data.receipt_ref,
      request.verb, actor.principalRef, "mcp", "facade_error"));
  }
  const sdk = await engine.sdk.run("typescript", {
    mode: "remote", url: engine.url, credential: actor.credential,
  }, denied.map(request => ({ verb: "facade" as const, path: request.verb, input: request.input })));
  expect(sdk.process.exitCode).toBe(0);
  expect(sdk.results.length).toBe(denied.length);
  for (const [index, request] of denied.entries()) {
    const result = sdk.results[index];
    if (!result) throw new Error("SURFACES-07 SDK omitted a refusal result");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("SURFACES-07 SDK allowed an agent owner act");
    const error = surfaces07Object(result.error);
    expect({ code: error.code, message: error.message, suggestions: error.suggestions }).toEqual<unknown>(expectedErrors[index]);
    // The SDK driver retains public m.lastReceiptRef() for each operation,
    // including refusals, before the next operation replaces that handle state.
    const metadata = surfaces07Object(result);
    receipts.push(await surfaces07RefusalReceipt(engine, metadata.receiptRef,
      request.verb, actor.principalRef, "http_facade", "FORBIDDEN"));
  }
  expect(new Set(receipts.map(receipt => receipt.receipt_ref)).size).toBe(denied.length * 4);
  return receipts;
}

/*
 * PARTIAL promise: owner-authored custom agents and ordered saved workflows are
 * read identically on REST, CLI, tool-first MCP and the remote TypeScript SDK.
 * Editing a definition/workflow changes the next run, never the earlier capture;
 * agents cannot perform the owner's edits, and state/refusal receipts survive restart.
 * Doors: typed agents.create/get/update and workflows.save/get/update/dispatch/status;
 * paired agent refusals through the same four public surfaces; receipts.get.
 * Unproved: executing both workers, common-world read/propose enforcement, TASK/funding,
 * installed skills, or delegated grants/revocation. The exercised controls are owner acts,
 * not grant-admitted agent substrate doors. No models, providers or private seed.
 */
suite.test(test, "SURFACES-07", "Custom agent and saved workflow revisions agree across REST, CLI, MCP and SDK after restart", async () => {
  const fixtures = await loadFixtures();
  const source = await fixtures.readJson<surfaces07Fixtures>("surfaces-scenarios");
  const data = source.cases.find(item => item.id === "SURFACES-07")?.fixture;
  if (!data) throw new Error("SURFACES-07 fixture is missing");
  const [readerName, proposerName] = data.workflow.steps;
  if (!readerName || !proposerName || data.workflow.steps.length !== 2 ||
      !data.definitions.some(item => item.name === readerName) ||
      !data.definitions.some(item => item.name === proposerName) || data.edit.name !== readerName) {
    throw new Error("SURFACES-07 fixture must name an ordered Reader and Proposer");
  }
  const engine = await EngineFixture.start({ id: "SURFACES-07", profile });
  try {
    redactor.add(engine.pairedActor.credential, Buffer.from(engine.pairedActor.credential).toString("base64"));
    const readerRef = surfaces07Id();
    const proposerRef = surfaces07Id();
    const workflowRef = surfaces07Id();
    const readerSpec: FacadeInput<"vault.agents.create">["definition"] = {
      agent_id: "surfaces07-reader", desc: readerName, version: "1",
      instructions: "Read the synthetic observation briefing.",
      skills: [], connectors: [], code_mode_mcps: [], models: [],
      scope: { kind: "all" }, ceiling: "proposed", enabled: true,
    };
    const proposerSpec: FacadeInput<"vault.agents.create">["definition"] = {
      ...readerSpec, agent_id: "surfaces07-proposer", desc: proposerName,
      instructions: "Propose a summary of the synthetic observations.",
    };
    const readerCreated = await engine.client.call("vault.agents.create", { agent_def_ref: readerRef, definition: readerSpec });
    const proposerCreated = await engine.client.call("vault.agents.create", { agent_def_ref: proposerRef, definition: proposerSpec });
    const readerV1 = await engine.client.call("vault.agents.get", { agent_def_ref: readerRef });
    const proposerV1 = await engine.client.call("vault.agents.get", { agent_def_ref: proposerRef });
    expect(readerV1).toEqual(readerCreated);
    expect(proposerV1).toEqual(proposerCreated);
    expect(readerV1).toMatchObject({ agent_def_ref: readerRef, definition: readerSpec, approval_status: "approved", lifecycle_status: "active" });
    expect(proposerV1).toMatchObject({ agent_def_ref: proposerRef, definition: proposerSpec, approval_status: "approved", lifecycle_status: "active" });

    const saved = await engine.client.call("vault.workflows.save", {
      workflow_ref: workflowRef, name: data.workflow.name, steps: [readerRef, proposerRef],
    });
    const workflowV1 = await engine.client.call("vault.workflows.get", { workflow_ref: workflowRef });
    expect(workflowV1).toEqual(saved);
    expect(workflowV1).toEqual({ workflow_ref: workflowRef, name: data.workflow.name,
      steps: [readerRef, proposerRef], revision: 1, forked_from: null });
    const dispatch: FacadeInput<"vault.workflows.dispatch"> = {
      workflow_ref: workflowRef, intent_key: "before-edit",
      briefing: "Review synthetic observations without external tools.",
      context_spec: { layers: [], memory: { mode: "exclude" }, chat: { mode: "exclude" } },
    };
    const admittedBefore = await engine.client.call("vault.workflows.dispatch", dispatch);
    const before = await engine.client.call("vault.workflows.status", { root_attempt_ref: admittedBefore.root_attempt_ref });
    expect(before).toEqual(admittedBefore);
    surfaces07AssertRun(before, workflowRef, 1, [readerV1, proposerV1]);

    const readerUpdated = await engine.client.call("vault.agents.update", {
      agent_def_ref: readerRef, expected_version: "1",
      definition: { ...readerV1.definition, version: String(data.edit.revision), scope: { kind: "base" } },
    });
    const readerV2 = await engine.client.call("vault.agents.get", { agent_def_ref: readerRef });
    expect(readerV2).toEqual(readerUpdated);
    expect(readerV2).toEqual({ ...readerV1,
      definition: { ...readerV1.definition, version: String(data.edit.revision), scope: { kind: "base" } } });
    const workflowUpdated = await engine.client.call("vault.workflows.update", {
      workflow_ref: workflowRef, expected_revision: workflowV1.revision,
      name: `${data.workflow.name} v2`, steps: [readerRef, proposerRef],
    });
    const workflowV2 = await engine.client.call("vault.workflows.get", { workflow_ref: workflowRef });
    expect(workflowV2).toEqual(workflowUpdated);
    expect(workflowV2).toEqual({ ...workflowV1, name: `${data.workflow.name} v2`, revision: 2 });
    const admittedAfter = await engine.client.call("vault.workflows.dispatch", { ...dispatch, intent_key: "after-edit" });
    const after = await engine.client.call("vault.workflows.status", { root_attempt_ref: admittedAfter.root_attempt_ref });
    expect(after).toEqual(admittedAfter);
    surfaces07AssertRun(after, workflowRef, 2, [readerV2, proposerV1]);
    expect(new Set([before.root_attempt_ref, before.active_attempt_ref, after.root_attempt_ref, after.active_attempt_ref]).size).toBe(4);
    expect(await engine.client.call("vault.workflows.status", { root_attempt_ref: before.root_attempt_ref })).toEqual(before);

    const actor = await engine.pairActor({ principalRef: readerRef, actorClass: "agent", scope: ["core:read", "core:write"] });
    redactor.add(actor.credential, Buffer.from(actor.credential).toString("base64"));
    await engine.mcp.initialize();
    const tools = await engine.mcp.listTools();
    const refused = await surfaces07Refuse(engine, actor, tools, [
      { verb: "vault.agents.update", input: { agent_def_ref: readerRef, expected_version: String(data.edit.revision),
        definition: { ...readerV2.definition, version: "3", scope: { kind: "all" } } } },
      { verb: "vault.workflows.update", input: { workflow_ref: workflowRef, expected_revision: workflowV2.revision,
        name: "Unapproved workflow edit", steps: [proposerRef, readerRef] } },
    ]);
    expect(await engine.client.call("vault.agents.get", { agent_def_ref: readerRef })).toEqual(readerV2);
    expect(await engine.client.call("vault.workflows.get", { workflow_ref: workflowRef })).toEqual(workflowV2);

    await engine.restart();
    await engine.mcp.initialize();
    const restartedTools = await engine.mcp.listTools();
    await surfaces07Parity(engine, restartedTools, [
      { verb: "vault.agents.get", input: { agent_def_ref: readerRef }, expected: readerV2 },
      { verb: "vault.agents.get", input: { agent_def_ref: proposerRef }, expected: proposerV1 },
      { verb: "vault.workflows.get", input: { workflow_ref: workflowRef }, expected: workflowV2 },
      { verb: "vault.workflows.status", input: { root_attempt_ref: before.root_attempt_ref }, expected: before },
      { verb: "vault.workflows.status", input: { root_attempt_ref: after.root_attempt_ref }, expected: after },
    ]);
    for (const receipt of refused) {
      expect(await engine.client.call("vault.receipts.get", { receipt_ref: receipt.receipt_ref })).toEqual(receipt);
    }
  } finally {
    await engine.close();
  }
});

// The fixture names related_to, which is not an engine EdgeKind. This partial
// exercises the registered mentions kind; it does not claim related_to support.
const surfaces08EdgeKind = "mentions";

interface surfaces08Fixtures {
  ledger: { oldAt: number };
  cases: {
    id: string;
    fixture?: {
      actors: string[];
      privateProject: string;
      privateText: string;
      commonText: string;
      wrongLink: { source: string; kind: string; target: string };
      expected: { foreignPrivateTextVisible: boolean; wrongLabelDeletesEdge: boolean; correctionActor: string };
    };
  }[];
}
interface surfaces08Read {
  verb: "vault.weave.report" | "vault.weave.link.corrections";
  input: FacadeInput<"vault.weave.report"> | FacadeInput<"vault.weave.link.corrections">;
  expected: unknown;
}
interface surfaces08Refusal {
  verb: "vault.weave.report" | "vault.weave.link.wrong";
  input: FacadeInput<"vault.weave.report"> | FacadeInput<"vault.weave.link.wrong">;
  status: number;
  code: "FORBIDDEN" | "BAD_REQUEST";
  rpcCode: number;
}
interface surfaces08Receipt {
  actor: PairedActor;
  row: NonNullable<FacadeResult<"vault.receipts.get">>;
}

function surfaces08Object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SURFACES-08 expected a public JSON object (body withheld)");
  }
  return value as Record<string, unknown>;
}
function surfaces08String(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("SURFACES-08 expected a nonempty public reference or sentence");
  }
  return value;
}
function surfaces08Value(prefix: string): string {
  const value = `${prefix} ${randomUUID()}`;
  redactor.add(value, Buffer.from(value).toString("base64"));
  return value;
}
function surfaces08NoValues(value: unknown, hidden: readonly string[]): void {
  const bytes = value instanceof Uint8Array ? Buffer.from(value)
    : Buffer.from(typeof value === "string" ? value : JSON.stringify(value) ?? "");
  expect(hidden.every(text => !bytes.includes(Buffer.from(text))
    && !bytes.includes(Buffer.from(Buffer.from(text).toString("base64"))))).toBe(true);
}
function surfaces08Arguments(input: unknown) {
  return {
    schema_version: "mcp_tool_args.v1",
    consent: { policy_ref: "policy:surfaces-08", purpose: "Compare reader-bound weave surfaces" },
    arguments: { spec: input },
  };
}
function surfaces08Claims(report: FacadeResult<"vault.weave.report">) {
  return report.sections.flatMap(section => section.items.flatMap(item => item.item === "claim"
    ? [{ ref: item.claim.claim_ref, subject: item.claim.subject_ref, value: item.claim.value }] : []))
    .sort((left, right) => left.ref.localeCompare(right.ref));
}
function surfaces08Projects(report: FacadeResult<"vault.weave.report">): string[] {
  return report.sections.flatMap(section => section.items.flatMap(item => item.item === "project"
    ? [item.project_ref] : [])).sort();
}
function surfaces08Links(report: FacadeResult<"vault.weave.report">): string[] {
  return report.sections.flatMap(section => section.items.flatMap(item => item.item === "link"
    ? [`${item.source_ref}/${item.kind}/${item.target_ref}`] : [])).sort();
}
async function surfaces08ReportRead(actor: PairedActor, input: FacadeInput<"vault.weave.report">,
  hidden: readonly string[]): Promise<FacadeResult<"vault.weave.report">> {
  const reply = await actor.client.raw<FacadeResult<"vault.weave.report">>(
    "POST", "/v1/core/facade/vault.weave.report", input);
  surfaces08NoValues(reply.bytes, hidden);
  expect(reply.status).toBe(200);
  return reply.body;
}
function surfaces08Error(body: unknown, code: string) {
  const error = surfaces08Object(surfaces08Object(body).error);
  expect(error.code).toBe(code);
  expect(typeof error.message === "string" && error.message.length > 0).toBe(true);
  expect(typeof error.requestId).toBe("string");
  expect(Array.isArray(error.suggestions) && error.suggestions.length > 0
    && error.suggestions.every((value: unknown) => typeof value === "string")).toBe(true);
  return error;
}
async function surfaces08ReceiptRead(actor: PairedActor, reference: unknown, verb: string,
  code: string, transport: "http_facade" | "mcp", hidden: readonly string[]): Promise<surfaces08Receipt> {
  const receiptRef = surfaces08String(reference);
  expect(/^call:[a-f0-9]{32}$/.test(receiptRef)).toBe(true);
  const row = await awaitPublic(() => actor.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null, { label: "SURFACES-08 refusal receipt" });
  if (row === null) throw new Error("SURFACES-08 refusal receipt did not become readable");
  surfaces08NoValues(row, hidden);
  expect({ ref: row.receipt_ref, verb: row.verb, actor: row.actor_ref, actorClass: row.actor_class,
    transport: row.transport, outcome: row.outcome }).toEqual({
    ref: receiptRef, verb, actor: actor.principalRef, actorClass: actor.actorClass,
    transport, outcome: { refused: { code } },
  });
  return { actor, row };
}

/** Compare saved DTOs, not surface envelopes. Reports and existing labels have
 * no per-invocation volatile fields; retain every actor, item, scope and time. */
async function surfaces08Parity(engine: EngineFixture, actor: PairedActor,
  reads: readonly surfaces08Read[], hidden: readonly string[],
  refusals: readonly surfaces08Refusal[] = []): Promise<surfaces08Receipt[]> {
  for (const read of reads) {
    const cli = await actor.cli.run(["api", "call", read.verb, "--data", "-"], JSON.stringify(read.input));
    surfaces08NoValues(cli.stdout, hidden);
    surfaces08NoValues(cli.stderr, hidden);
    expect(cli.exitCode).toBe(0);
    expect(JSON.parse(cli.stdout)).toEqual(read.expected);
    const mcp = await actor.mcp.callTool(read.verb, surfaces08Arguments(read.input));
    surfaces08NoValues(mcp, hidden);
    expect(surfaces08Object(mcp).isError === true).toBe(false);
    const structured = surfaces08Object(surfaces08Object(mcp).structuredContent);
    expect(structured.output).toEqual(read.expected);
  }
  const receipts: surfaces08Receipt[] = [];
  const expectedErrors: Record<string, unknown>[] = [];
  for (const refusal of refusals) {
    const rest = await actor.client.raw("POST", `/v1/core/facade/${refusal.verb}`, refusal.input);
    surfaces08NoValues(rest.bytes, hidden);
    expect(rest.status).toBe(refusal.status);
    const error = surfaces08Error(rest.body, refusal.code);
    expect(rest.headers.get("x-oneiron-receipt-ref")).toBe<unknown>(error.receiptRef);
    receipts.push(await surfaces08ReceiptRead(actor, error.receiptRef, refusal.verb,
      refusal.code, "http_facade", hidden));
    expectedErrors.push(error);

    const cli = await actor.cli.run(["api", "call", refusal.verb, "--data", "-"], JSON.stringify(refusal.input));
    surfaces08NoValues(cli.stdout, hidden);
    surfaces08NoValues(cli.stderr, hidden);
    expect(cli.exitCode === 0).toBe(false);
    const cliError = surfaces08Error(JSON.parse(cli.stdout), refusal.code);
    expect({ code: cliError.code, message: cliError.message, suggestions: cliError.suggestions })
      .toEqual({ code: error.code, message: error.message, suggestions: error.suggestions });
    receipts.push(await surfaces08ReceiptRead(actor, cliError.receiptRef, refusal.verb,
      refusal.code, "http_facade", hidden));

    const rpc = await actor.mcp.rpc("tools/call", {
      name: refusal.verb, arguments: surfaces08Arguments(refusal.input),
    });
    surfaces08NoValues(rpc, hidden);
    expect("error" in rpc).toBe(true);
    if (!("error" in rpc)) throw new Error("SURFACES-08 MCP accepted a refused act");
    expect(rpc.error.code).toBe(refusal.rpcCode);
    const data = surfaces08Object(rpc.error.data);
    expect({ kind: data.kind, code: data.error_code, message: data.human_message })
      .toEqual({ kind: "facade_error", code: "facade_error", message: error.message });
    expect(typeof data.request_id).toBe("string");
    expect(Array.isArray(data.recovery_suggestions) && data.recovery_suggestions.length > 0).toBe(true);
    // MCP records its own machine kind, not the HTTP facade's code.
    receipts.push(await surfaces08ReceiptRead(actor, data.receipt_ref, refusal.verb,
      "facade_error", "mcp", hidden));
  }
  const operations = [...reads, ...refusals].map(call => ({
    verb: "facade" as const, path: call.verb, input: call.input,
  }));
  const sdk = await engine.sdk.run("typescript", {
    mode: "remote", url: engine.url, credential: actor.credential,
  }, operations);
  surfaces08NoValues(sdk.process.stdout, hidden);
  surfaces08NoValues(sdk.process.stderr, hidden);
  expect(sdk.process.exitCode).toBe(0);
  expect(sdk.results.length).toBe(operations.length);
  for (const [index, read] of reads.entries()) {
    const result = sdk.results[index];
    if (result === undefined || !result.ok) throw new Error("SURFACES-08 SDK read failed");
    expect(result.value).toEqual(read.expected);
  }
  for (const [index, refusal] of refusals.entries()) {
    const result = sdk.results[reads.length + index];
    const expectedError = expectedErrors[index];
    if (result === undefined || expectedError === undefined || result.ok) {
      throw new Error("SURFACES-08 SDK did not return the expected refusal");
    }
    const error = surfaces08Object(result.error);
    expect({ code: error.code, message: error.message, suggestions: error.suggestions })
      .toEqual({ code: refusal.code, message: expectedError.message, suggestions: expectedError.suggestions });
    receipts.push(await surfaces08ReceiptRead(actor, result.receiptRef, refusal.verb,
      refusal.code, "http_facade", hidden));
  }
  return receipts;
}

/*
 * Promise (R1-claim-020): person reports contain only own/member-project rows
 * and admitted live links; owner-global and agent sections stay actor-bound.
 * Public doors: real init/pair, structural PERSON/PLACE, claims.upsert,
 * weave report/correction reads, owner HTTP report, CLI, MCP tool-first, SDK.
 * Partial: uses the actual init-created root project, not a fabricated PROJECT.
 * Does not prove a new private project, grouped inbox delivery, completed weave,
 * scheduled digest or generated lens. No model, private queue or clock is used.
 */
suite.test(test, "SURFACES-08", "Reader-bound weave reports and human link corrections agree across REST CLI MCP and SDK and persist through restart", async () => {
  const fixtures = await loadFixtures();
  const inputs = await fixtures.readJson<surfaces08Fixtures>("surfaces-scenarios");
  const data = inputs.cases.find(row => row.id === "SURFACES-08")?.fixture;
  if (data === undefined) throw new Error("SURFACES-08 fixture is missing");
  const [readerALabel, readerBLabel] = data.actors;
  if (readerALabel === undefined || readerBLabel === undefined) throw new Error("SURFACES-08 needs two reader labels");
  expect(data.expected.correctionActor).toBe(readerALabel);
  expect(data.expected.foreignPrivateTextVisible).toBe(false);
  expect(data.expected.wrongLabelDeletesEdge).toBe(false);
  const ownerText = surfaces08Value(data.privateText);
  const otherText = surfaces08Value(`${readerBLabel} private observation.`);
  const projectText = surfaces08Value(data.commonText);
  const agentText = surfaces08Value("The project leader recorded its own observation.");
  const otherName = surfaces08Value(readerBLabel);
  const placeName = surfaces08Value(data.wrongLink.target);
  const predicate = "e2e.surfaces08.observation";
  const at = inputs.ledger.oldAt;
  const engine = await EngineFixture.start({ id: "SURFACES-08", profile, surface: "tool-first",
    serverConfig: "[models.dreamer]\nenabled = false\n[models.workflows]\nenabled = false\n" });
  try {
    // Bind reader-a to the real owner, using its PERSON lens, NOT owner-global.
    const readerA = engine.pairedActor;
    const initial = await readerA.client.call("vault.weave.report", { sections: [{ kind: "projects" }] });
    const projectRefs = surfaces08Projects(initial);
    expect(projectRefs.length).toBe(1);
    const projectRef = projectRefs[0];
    if (projectRef === undefined) throw new Error("SURFACES-08 fresh root project is missing");
    const root = await engine.client.call("vault.get", { entity_ref: projectRef });
    expect(root.value?.id_hex).toBe(projectRef);
    const rootBody = surfaces08Object(root.value?.body);
    expect(rootBody.parents).toEqual([]);
    expect(Array.isArray(rootBody.board) && rootBody.board.includes(readerA.principalRef)).toBe(true);
    const leaderRef = surfaces08String(rootBody.leader);
    const leader = await engine.client.call("vault.get", { entity_ref: leaderRef });
    expect(leader.value?.kind).toBe("AGENT_DEF");

    // MCP requires an owner-authored actor ceiling even for read-only use.
    // Add only this existing leader, at Proposed; this is not an AgentGrant.
    const policies = await engine.client.call("vault.gate.policy.get", {});
    const policy = policies.manifests.find(row => row.manifest_ref === policies.default_manifest_ref);
    if (policy === undefined) throw new Error("SURFACES-08 default policy is missing");
    const actorCeiling = { actor_class: "agent", actor_ref: leaderRef, ceiling: "proposed" as const };
    const installedPolicy = await engine.client.call("vault.gate.policy.put", {
      manifest_ref: policy.manifest_ref, expected_body_hash: policy.body_hash,
      manifest: { ...policy.manifest, actor_ceilings: [...policy.manifest.actor_ceilings, actorCeiling] },
    });
    const policyRead = await engine.client.call("vault.gate.policy.get", { manifest_ref: policy.manifest_ref });
    expect(policyRead.manifests[0]?.manifest).toEqual(installedPolicy.manifest.manifest);
    expect(policyRead.manifests[0]?.manifest.actor_ceilings).toContainEqual(actorCeiling);

    const other = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: otherName }, occurred_at: at,
      edges: [{ edge_kind: surfaces08EdgeKind, target_ref: readerA.principalRef }],
    });
    const place = await engine.client.call("vault.structural.put", {
      kind: "PLACE", body: { name: placeName }, occurred_at: at,
      edges: [{ edge_kind: surfaces08EdgeKind, target_ref: projectRef }],
    });
    expect((await engine.client.call("vault.get", { entity_ref: other.id_hex })).value?.body)
      .toEqual({ name: otherName });
    expect((await engine.client.call("vault.get", { entity_ref: place.id_hex })).value?.body)
      .toEqual({ name: placeName });
    const readerB = await engine.pairActor({ principalRef: other.id_hex, actorClass: "human", scope: ["core:read", "core:write"] });
    const agent = await engine.pairActor({ principalRef: leaderRef, actorClass: "agent", scope: ["core:read", "core:write"] });
    for (const actor of [readerA, readerB, agent]) {
      const self = await actor.client.call("self.actor", {});
      expect({ ref: self.actor_ref, actorClass: self.actor_class })
        .toEqual({ ref: actor.principalRef, actorClass: actor.actorClass });
    }
    const scope = await ownerBaseClaimScope(engine.client, readerA.principalRef);
    const authored: { ref: string; subject: string; value: string }[] = [];
    for (const [subject, value] of [[readerA.principalRef, ownerText], [readerB.principalRef, otherText],
      [projectRef, projectText], [agent.principalRef, agentText]] as const) {
      const written = await engine.client.call("vault.claims.upsert", {
        scope, subject_ref: subject, predicate, value, confidence: 1, source: "user_stated", occurred_at: at,
      });
      const ref = written.claim?.id;
      if (ref === undefined) throw new Error("SURFACES-08 claim write returned no record reference");
      authored.push({ ref, subject, value });
    }
    const surfaces08ExpectedClaims = (subjects: readonly string[]) => authored.filter(row => subjects.includes(row.subject))
      .sort((left, right) => left.ref.localeCompare(right.ref));
    const personRecipe = { sections: [{ kind: "changes", predicates: [predicate] }, { kind: "projects" },
      { kind: "links", edge_kinds: [surfaces08EdgeKind] }] } satisfies FacadeInput<"vault.weave.report">;
    const agentRecipe = { sections: [{ kind: "digest", predicates: [predicate] }] } satisfies FacadeInput<"vault.weave.report">;
    const ownerRecipe = { sections: [{ kind: "conflicts", predicates: [predicate] },
      { kind: "links", edge_kinds: [surfaces08EdgeKind] }, { kind: "budgets" }] } satisfies FacadeInput<"vault.weave.report">;
    const reportA = await surfaces08ReportRead(readerA, personRecipe, [otherText, agentText]);
    const reportB = await surfaces08ReportRead(readerB, personRecipe, [ownerText, projectText, agentText]);
    const reportAgent = await surfaces08ReportRead(agent, agentRecipe, [ownerText, otherText]);
    expect(reportA.sections.map(section => section.kind)).toEqual(["changes", "projects", "links"]);
    expect(reportB.sections.map(section => section.kind)).toEqual(["changes", "projects", "links"]);
    expect(reportAgent.sections.map(section => section.kind)).toEqual(["digest"]);
    expect(surfaces08Claims(reportA)).toEqual(surfaces08ExpectedClaims([readerA.principalRef, projectRef]));
    expect(surfaces08Claims(reportB)).toEqual(surfaces08ExpectedClaims([readerB.principalRef]));
    expect(surfaces08Claims(reportAgent)).toEqual(surfaces08ExpectedClaims([agent.principalRef, projectRef]));
    expect(surfaces08Projects(reportA)).toEqual([projectRef]);
    expect(surfaces08Projects(reportB)).toEqual([]);
    const sharedLink = `${readerB.principalRef}/${surfaces08EdgeKind}/${readerA.principalRef}`;
    const memberLink = `${place.id_hex}/${surfaces08EdgeKind}/${projectRef}`;
    expect(surfaces08Links(reportA)).toEqual([sharedLink, memberLink].sort());
    expect(surfaces08Links(reportB)).toEqual([sharedLink]);
    const ownerReport = await engine.client.request<FacadeResult<"vault.weave.report">>("POST", "/v1/owner/weave/report", ownerRecipe);
    expect(ownerReport.body.sections.map(section => section.kind)).toEqual(["conflicts", "links", "budgets"]);
    expect(surfaces08Claims(ownerReport.body)).toEqual(surfaces08ExpectedClaims(authored.map(row => row.subject)));
    expect(surfaces08Links(ownerReport.body)).toEqual([sharedLink, memberLink].sort());

    const link = { source_ref: readerB.principalRef, kind: surfaces08EdgeKind,
      target_ref: readerA.principalRef } satisfies FacadeInput<"vault.weave.link.wrong">;
    expect(await readerA.client.call("vault.weave.link.corrections", link)).toEqual([]);
    const label = await readerA.client.call("vault.weave.link.wrong", link);
    const labels = await readerA.client.call("vault.weave.link.corrections", link);
    expect(labels).toEqual([label]);
    expect(labels[0]).toMatchObject({ ...link, actor_ref: readerA.principalRef });
    expect(surfaces08Links(await surfaces08ReportRead(readerA, personRecipe, [otherText, agentText])))
      .toEqual([sharedLink, memberLink].sort());
    const neighbors = await readerB.client.call("vault.neighbors", {
      entity_ref: readerB.principalRef, opts: { edge_kind: surfaces08EdgeKind, limit: 20 },
    });
    surfaces08NoValues(neighbors, [ownerText, projectText, agentText]);
    expect(neighbors.value.some(row => row.record?.id === readerA.principalRef)).toBe(true);

    await surfaces08Parity(engine, readerA, [
      { verb: "vault.weave.report", input: personRecipe, expected: reportA },
      { verb: "vault.weave.link.corrections", input: link, expected: labels },
    ], [otherText, agentText]);
    await surfaces08Parity(engine, readerB, [
      { verb: "vault.weave.report", input: personRecipe, expected: reportB },
    ], [ownerText, projectText, agentText]);
    const receipts = await surfaces08Parity(engine, agent, [
      { verb: "vault.weave.report", input: agentRecipe, expected: reportAgent },
    ], [ownerText, otherText], [
      { verb: "vault.weave.link.wrong", input: link, status: 403, code: "FORBIDDEN", rpcCode: -32020 },
      { verb: "vault.weave.report", input: { sections: [{ kind: "conflicts", predicates: [predicate] }] },
        status: 400, code: "BAD_REQUEST", rpcCode: -32602 },
    ]);
    // The refused label attempts, including the SDK call, created no extra label.
    expect(await readerA.client.call("vault.weave.link.corrections", link)).toEqual(labels);
    await engine.restart();
    for (const [actor, recipe, expected, hidden] of [
      [readerA, personRecipe, reportA, [otherText, agentText]],
      [readerB, personRecipe, reportB, [ownerText, projectText, agentText]],
      [agent, agentRecipe, reportAgent, [ownerText, otherText]],
    ] as const) {
      const persisted = await surfaces08ReportRead(actor, recipe, hidden);
      expect(persisted).toEqual(expected);
    }
    expect((await engine.client.request<FacadeResult<"vault.weave.report">>("POST", "/v1/owner/weave/report", ownerRecipe)).body)
      .toEqual(ownerReport.body);
    expect(await readerA.client.call("vault.weave.link.corrections", link)).toEqual(labels);
    expect((await engine.client.call("vault.gate.policy.get", { manifest_ref: policy.manifest_ref })).manifests[0]?.manifest)
      .toEqual(installedPolicy.manifest.manifest);
    for (const receipt of receipts) {
      const persisted = await receipt.actor.client.call("vault.receipts.get", { receipt_ref: receipt.row.receipt_ref });
      surfaces08NoValues(persisted, [ownerText, otherText]);
      expect(persisted).toEqual(receipt.row);
    }
  } finally {
    await engine.close();
  }
});

type surfaces09Registration = FacadeResult<"vault.connectors.proxy.admit">;
type surfaces09Verb = "ai.chat.completions" | "vault.connectors.proxy.admit" | "vault.connectors.proxy.revoke_write";
interface surfaces09Fixtures {
  cases: { id: string; fixture?: {
    connector: string; model: string; query: string; admittedMemory: string;
    privateMemory: string; assistantReply: string;
    usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
    request: { stream: boolean; n: number; messages: { role: "user"; content: string }[] };
    expected: { exchangePredicate: string; approval: string; source: string };
  } }[];
}
interface surfaces09PairingLink {
  code: string; pin?: { challenge: number[]; digest: number[] } | null;
}
interface surfaces09Failure { code: string; receipt: string }
function surfaces09Protect(value: string): string {
  redactor.add(value, Buffer.from(value).toString("base64"));
  return value;
}
function surfaces09Object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("SURFACES-09 expected a public object");
  return value as Record<string, unknown>;
}
function surfaces09String(value: unknown): string {
  if (typeof value !== "string" || value.length === 0)
    throw new Error("SURFACES-09 expected a public string");
  return value;
}
function surfaces09Absent(value: unknown, privateValue: string): void {
  const bytes = Buffer.from(JSON.stringify(value) ?? "null");
  expect(!bytes.includes(Buffer.from(privateValue)) &&
    !bytes.includes(Buffer.from(Buffer.from(privateValue).toString("base64")))).toBe(true);
}
function surfaces09McpOutput(value: unknown): unknown {
  const result = surfaces09Object(value);
  expect(result.isError).toBe(false);
  return surfaces09Object(result.structuredContent).output;
}
function surfaces09SdkValue(result: SdkDriverResult, index = 0): unknown {
  expect(result.process.exitCode).toBe(0);
  const row = result.results[index];
  if (row === undefined || !row.ok) throw new Error("SURFACES-09 SDK success was refused");
  return row.value;
}
function surfaces09SdkFailure(result: SdkDriverResult, index = 0): surfaces09Failure {
  expect(result.process.exitCode).toBe(0);
  const row = result.results[index];
  if (row === undefined || row.ok) throw new Error("SURFACES-09 SDK refusal was not returned");
  const error = surfaces09Object(row.error);
  expect(typeof error.message === "string" && Array.isArray(error.suggestions)).toBe(true);
  // The driver captures the public SDK receipt getter after success and refusal.
  return { code: surfaces09String(error.code), receipt: surfaces09String(row.receiptRef) };
}
async function surfaces09HttpFailure<V extends surfaces09Verb>(
  client: PublicHttpClient, verb: V, input: FacadeInput<V>,
): Promise<surfaces09Failure> {
  let caught: unknown;
  try { await client.call(verb, input); } catch (error) { caught = error; }
  if (!(caught instanceof PublicHttpError)) throw new Error("SURFACES-09 expected an HTTP refusal");
  expect(caught.reply.status).toBe(403);
  const error = surfaces09Object(surfaces09Object(caught.reply.body).error);
  expect(typeof error.message === "string" && typeof error.requestId === "string" &&
    Array.isArray(error.suggestions)).toBe(true);
  const receipt = surfaces09String(error.receiptRef);
  expect(caught.reply.headers.get("x-oneiron-receipt-ref")).toBe(receipt);
  return { code: surfaces09String(error.code), receipt };
}
async function surfaces09CliFailure<V extends surfaces09Verb>(
  actor: PairedActor, verb: V, input: FacadeInput<V>,
): Promise<surfaces09Failure> {
  let caught: unknown;
  try { await actor.cli.call(verb, input); } catch (error) { caught = error; }
  if (!(caught instanceof CliError)) throw new Error("SURFACES-09 expected a CLI refusal");
  expect(caught.result.exitCode).toBe(1);
  expect(caught.result.stderr.length > 0).toBe(true);
  const error = surfaces09Object(surfaces09Object(JSON.parse(caught.result.stdout)).error);
  expect(typeof error.message === "string" && typeof error.requestId === "string" &&
    Array.isArray(error.suggestions)).toBe(true);
  return { code: surfaces09String(error.code), receipt: surfaces09String(error.receiptRef) };
}
async function surfaces09McpFailure<V extends surfaces09Verb>(
  actor: PairedActor, verb: V, input: FacadeInput<V>,
): Promise<surfaces09Failure> {
  let caught: unknown;
  try { await actor.mcp.callTool(verb, { spec: input }); } catch (error) { caught = error; }
  if (!(caught instanceof McpRpcError) || !("error" in caught.response))
    throw new Error("SURFACES-09 expected a JSON-RPC refusal");
  const error = caught.response.error;
  expect(error.code < 0).toBe(true);
  const data = surfaces09Object(error.data);
  expect(typeof data.human_message === "string" && typeof data.request_id === "string" &&
    Array.isArray(data.recovery_suggestions)).toBe(true);
  return { code: surfaces09String(data.error_code), receipt: surfaces09String(data.receipt_ref) };
}
async function surfaces09PairScoped(
  engine: EngineFixture, principalRef: string, world: string, facet: string, verbs: string[],
  privateValues: readonly string[],
): Promise<PairedActor> {
  const reply = await engine.client.request<surfaces09PairingLink>("POST", "/v1/core/pairing/links", {
    scope: {
      worlds: { kind: "some", values: [world] }, facets: { kind: "some", values: [facet] },
      bands: { kind: "all" }, audience: { kind: "all" },
      verbs: { kind: "some", values: verbs }, sensitivity: { kind: "all" },
    },
    lifetime_secs: 3600,
    principal: { holder_ref: principalRef, actor_class: "agent", write_facet: facet },
  });
  const issued = reply.body;
  surfaces09Protect(issued.code);
  const pin = issued.pin;
  const suffix = pin == null ? "" :
    `.${Buffer.from(pin.challenge).toString("hex")}.${Buffer.from(pin.digest).toString("hex")}`;
  const link = surfaces09Protect(`${engine.url}/pair#${issued.code}.${principalRef}${suffix}`);
  const paired = await engine.sdk.pair(link);
  surfaces09Protect(paired.credential);
  const { bearer, seed } = credentialParts(paired.credential);
  surfaces09Protect(bearer); surfaces09Protect(seed);
  const client = new PublicHttpClient(engine.url, {
    credential: paired.credential, artifacts: engine.artifacts, label: "surfaces09-scoped-agent",
  });
  const cli = new CliClient(requireAsset(engine.build, "cli"), engine.root, {
    ...engine.env, ONEIRON_URL: engine.url, ONEIRON_TOKEN: bearer,
    ONEIRON_SECRET: bearer, ONEIRON_BINDING_KEY: seed,
  }, engine.artifacts);
  const actor: PairedActor = {
    principalRef, actorClass: "agent", ...paired, client, cli, mcp: new McpClient(client, "tool-first"),
  };
  const readInput: FacadeInput<"vault.claims.list"> = { limit: 1 };
  const scopedRead = await client.request<FacadeResult<"vault.claims.list">>(
    "POST", "/v1/core/facade/vault.claims.list", readInput, { "x-oneiron-invocation": secretHex(16) });
  expect(scopedRead.status).toBe(200);
  const receiptRef = surfaces09String(scopedRead.headers.get("x-oneiron-receipt-ref"));
  expect(receiptRef.startsWith("call:")).toBe(true);
  const receipt = await awaitPublic(
    () => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    row => row !== null, { label: "SURFACES-09 scoped pairing receipt" });
  if (receipt === null) throw new Error("SURFACES-09 scoped pairing receipt is missing");
  expect(receipt).toMatchObject({ actor_ref: principalRef, actor_class: "agent",
    verb: "vault.claims.list", transport: "http_facade", outcome: "ok" });
  for (const privateValue of privateValues) surfaces09Absent([scopedRead.body, receipt], privateValue);
  return actor;
}
async function surfaces09Setup(engine: EngineFixture, expected: surfaces09Registration): Promise<void> {
  const reply = await engine.client.request<{
    connector: string; key: surfaces09Registration["key"]; slate: surfaces09Registration["slate"] | null;
  }>("GET", `/v1/owner/connectors/setup?connector=${encodeURIComponent(expected.connector)}`);
  expect({ connector: reply.body.connector, key: reply.body.key, slate: reply.body.slate }).toEqual(expected);
}
function surfaces09Setting(registration: surfaces09Registration, tool: string): string {
  const row = registration.slate.rows.find(item => item.draft.tool === tool);
  if (row === undefined) throw new Error("SURFACES-09 proxy slate is missing a capability");
  return row.holder_narrow?.disposition ?? row.owner_override?.disposition ?? row.draft.disposition;
}

/*
 * Promise: the same proxy family on REST, CLI, MCP tool-first and the SDK keeps
 * admitted memory and Proposed exchanges inside the paired connector's ceiling;
 * owner-only controls refuse an agent, and selective write revocation survives restart.
 * Second doors: owner setup GET, claims.list/history, recall and receipts.get.
 * SDK result rows expose the actual per-operation Oneiron.lastReceiptRef().
 * Literal upload encoding is unproved: provider bodies are decoded. Native refusal-code parity remains asserted,
 * including the known MCP projection reds, rather than weakened to today's codes.
 */
suite.test(test, "SURFACES-09",
  "Memory injection stays scoped and write revocation agrees across REST CLI MCP and SDK, then persists after restart",
  async () => {
    const fixtures = await loadFixtures();
    const scenarios = await fixtures.readJson<surfaces09Fixtures>("surfaces-scenarios");
    const data = scenarios.cases.find(item => item.id === "SURFACES-09")?.fixture;
    if (data === undefined) throw new Error("SURFACES-09 fixture is missing");
    const privateValue = surfaces09Protect(`${data.privateMemory} ${secretHex(16)}`);
    surfaces09Protect(data.privateMemory);
    const falseAuthor = surfaces09Protect(`surfaces09-untrusted-author-${secretHex(8)}`);
    const carriers = ["REST", "CLI", "MCP", "SDK"] as const;
    const providers = await ScriptedProviders.start({
      id: "SURFACES-09", steps: carriers.map(carrier => ({
        id: `surfaces09-${carrier}`, origin: "model", role: "proxy", purpose: "answer",
        request: { method: "POST" as const, path: "/v1/chat/completions", model: "surfaces-proxy", fields: { stream: false } },
        response: openaiText(`surfaces09-answer-${carrier}`, "surfaces-proxy", data.assistantReply, {
          inputTokens: data.usage.prompt_tokens, outputTokens: data.usage.completion_tokens,
        }),
      })),
    });
    let engine: EngineFixture | undefined;
    try {
      const modelOrigin = providers.urls.model;
      if (modelOrigin === undefined) throw new Error("SURFACES-09 model origin is missing");
      engine = await EngineFixture.start({ id: "SURFACES-09", profile, surface: "tool-first", serverConfig: `
[models.providers.fixture]
kind = "local-openai-compat"
base_url = ${JSON.stringify(modelOrigin)}
revision = "1"
[models.roles.generative_reasoner]
model = "fixture:surfaces-proxy"
[models.dreamer]
enabled = false
[models.workflows]
enabled = false
` });
      const fixture = engine;
      surfaces09Protect(fixture.pairedActor.credential);
      const base = await fixture.client.call("vault.agents.base", {});
      const principal = base.agents.find(item => item.name === "coach");
      if (principal === undefined) throw new Error("SURFACES-09 base agent is missing");
      const principalRef = principal.id;
      const policies = await fixture.client.call("vault.gate.policy.get", {});
      const policy = policies.manifests.find(item => item.manifest_ref === policies.default_manifest_ref);
      if (policy === undefined) throw new Error("SURFACES-09 default policy is missing");
      const ceilings = policy.manifest.actor_ceilings.filter(row =>
        !(row.actor_class === "agent" && row.actor_ref === principalRef));
      ceilings.push({ actor_class: "agent", actor_ref: principalRef, ceiling: "proposed" });
      const policyWrite = await fixture.client.call("vault.gate.policy.put", {
        manifest_ref: policy.manifest_ref, expected_body_hash: policy.body_hash,
        manifest: { ...policy.manifest, actor_ceilings: ceilings },
      });
      expect(policyWrite.approval).toBe("auto");
      await fixture.awaitReceipt(policyWrite.receipt_ref);
      const policyRead = await fixture.client.call("vault.gate.policy.get", { manifest_ref: policy.manifest_ref });
      expect(policyRead.manifests.find(item => item.manifest_ref === policy.manifest_ref)?.manifest.actor_ceilings)
        .toEqual(ceilings);
      const facets = await fixture.client.call("vault.identity.facet", {
        entity: fixture.pairedActor.principalRef,
        facets: [{ label: "surfaces09-admitted" }, { label: "surfaces09-private" }], reassignment_map: [],
        evidence: { refs: [], rationale: "Keep admitted and private proxy fixture memories separate" },
      });
      if (facets.outcome !== "applied" || facets.receipt.action.op !== "facet")
        throw new Error("SURFACES-09 facet operation was not applied");
      expect(facets.receipt.action.facets).toHaveLength(2);
      const [admittedFacet, privateFacet] = facets.receipt.action.facets;
      if (admittedFacet === undefined || privateFacet === undefined) throw new Error("SURFACES-09 facets are missing");
      expect(admittedFacet).not.toBe(privateFacet);
      for (const [id, label] of [[admittedFacet, "surfaces09-admitted"], [privateFacet, "surfaces09-private"]] as const) {
        const row = await fixture.client.call("vault.get", { entity_ref: id });
        expect(row.value?.kind).toBe("FACET");
        expect(row.value?.body).toMatchObject({ label });
      }
      const baseScope = await ownerBaseClaimScope(fixture.client, fixture.pairedActor.principalRef);
      const admittedScope = { ...baseScope, scope_facet_id: admittedFacet };
      const privateScope = { ...baseScope, scope_facet_id: privateFacet };
      const saved: { id: string; predicate: string; value: string; scope: typeof baseScope }[] = [];
      for (const [predicate, value, scope] of [
        ["observation.opening_time", data.admittedMemory, admittedScope],
        ["observation.access_phrase", privateValue, privateScope],
      ] as const) {
        const write = await fixture.client.call("vault.claims.upsert", {
          subject_ref: fixture.pairedActor.principalRef, predicate, value, confidence: 1,
          source: "user_stated", evidence_turn_refs: [], scope,
        });
        if (write.claim == null) throw new Error("SURFACES-09 authored claim has no record reference");
        await fixture.awaitReceipt(write.receipt_ref);
        const read = await fixture.client.call("vault.claims.list", {
          subject_ref: fixture.pairedActor.principalRef, predicate, limit: 16,
        });
        expect(read.value.map(row => ({ id: row.claim_ref, value: row.value, scope: row.claim_scope })))
          .toEqual([{ id: write.claim.id, value, scope }]);
        saved.push({ id: write.claim.id, predicate, value, scope });
      }
      const admitted = saved[0], privateClaim = saved[1];
      if (admitted === undefined || privateClaim === undefined) throw new Error("SURFACES-09 setup claims are missing");
      const readOnly = await surfaces09PairScoped(fixture, principalRef, baseScope.world_id, admittedFacet,
        ["core:read"], [privateValue, data.privateMemory]);
      const chat: FacadeInput<"ai.chat.completions"> = {
        model: data.model, stream: data.request.stream, n: data.request.n, user: falseAuthor,
        messages: data.request.messages.map(message => ({ ...message, name: falseAuthor })),
      };
      const parity: { stage: string; carrier: string; actual: string; expected: string }[] = [];
      const receiptSnapshots: NonNullable<FacadeResult<"vault.receipts.get">>[] = [];
      const surfaces09ObserveRefusal = async (stage: string, carrier: string, verb: surfaces09Verb,
        failure: surfaces09Failure, expected: string): Promise<void> => {
        parity.push({ stage, carrier, actual: failure.code, expected });
        expect(failure.receipt.startsWith("call:")).toBe(true);
        const receipt = await awaitPublic(
          () => fixture.client.call("vault.receipts.get", { receipt_ref: failure.receipt }),
          row => row !== null, { label: "SURFACES-09 refusal receipt" });
        if (receipt === null) throw new Error("SURFACES-09 refusal receipt is missing");
        expect(receipt.actor_ref).toBe(principalRef);
        expect(receipt.actor_class).toBe("agent");
        expect(receipt.verb).toBe(verb);
        expect(receipt.transport).toBe(carrier === "MCP" ? "mcp" : "http_facade");
        expect(receipt.outcome).toEqual({ refused: { code: failure.code } });
        surfaces09Absent(receipt, privateValue);
        receiptSnapshots.push(receipt);
        const actual = typeof receipt.outcome === "object" ? receipt.outcome.refused.code : "ok";
        parity.push({ stage: `${stage} receipt`, carrier, actual, expected });
      };
      // The generated facade grant check runs before the proxy's own scope check.
      const noGrant = [
        await surfaces09HttpFailure(readOnly.client, "ai.chat.completions", chat),
        await surfaces09CliFailure(readOnly, "ai.chat.completions", chat),
        await surfaces09McpFailure(readOnly, "ai.chat.completions", chat),
      ];
      for (const [index, failure] of noGrant.entries())
        await surfaces09ObserveRefusal("missing write grant", carriers[index]!, "ai.chat.completions", failure, "FORBIDDEN");
      const noGrantSdk = await fixture.sdk.run("typescript", { mode: "remote", url: fixture.url, credential: readOnly.credential },
        [{ verb: "facade", path: "ai.chat.completions", input: chat }]);
      await surfaces09ObserveRefusal("missing write grant", "SDK", "ai.chat.completions",
        surfaces09SdkFailure(noGrantSdk), "FORBIDDEN");
      expect(providers.seenFixtureCalls).toHaveLength(0);
      const exchangeInput: FacadeInput<"vault.claims.list"> = {
        subject_ref: principalRef, predicate: data.expected.exchangePredicate, limit: 16,
      };
      expect((await fixture.client.call("vault.claims.list", exchangeInput)).value).toEqual([]);
      const agent = await surfaces09PairScoped(fixture, principalRef, baseScope.world_id, admittedFacet,
        ["core:read", "core:write"], [privateValue, data.privateMemory]);
      const admitInput: FacadeInput<"vault.connectors.proxy.admit"> = { actor: principalRef };
      const registration = await fixture.client.call("vault.connectors.proxy.admit", admitInput);
      expect(registration.key.status).toBe("active");
      expect(registration.key.consent_required).toBe(false);
      expect(registration.slate.stamped).toBe(true);
      expect(surfaces09Setting(registration, "vault.recall")).toBe("auto");
      expect(surfaces09Setting(registration, "vault.remember")).toBe("auto");
      await surfaces09Setup(fixture, registration);
      expect(await fixture.cli.call("vault.connectors.proxy.admit", admitInput)).toEqual(registration);
      await surfaces09Setup(fixture, registration);
      expect(surfaces09McpOutput(await fixture.mcp.callTool("vault.connectors.proxy.admit", { spec: admitInput }))).toEqual(registration);
      await surfaces09Setup(fixture, registration);
      const ownerTarget = { mode: "remote", url: fixture.url, credential: fixture.pairedActor.credential } as const;
      expect(surfaces09SdkValue(await fixture.sdk.run("typescript", ownerTarget,
        [{ verb: "facade", path: "vault.connectors.proxy.admit", input: admitInput }]))).toEqual(registration);
      await surfaces09Setup(fixture, registration);
      // This unrestricted instrument isolates actor kind from record-bound refusal.
      const unprivileged = await fixture.pairActor({ principalRef, actorClass: "agent", scope: ["core:read", "core:write"] });
      surfaces09Protect(unprivileged.credential);
      const revokeInput: FacadeInput<"vault.connectors.proxy.revoke_write"> = {
        actor: principalRef, key: registration.key.id, revision: registration.slate.revision,
      };
      for (const [verb, input] of [["vault.connectors.proxy.admit", admitInput],
        ["vault.connectors.proxy.revoke_write", revokeInput]] as const) {
        await surfaces09ObserveRefusal("agent cannot control grants", "REST", verb,
          await surfaces09HttpFailure(unprivileged.client, verb, input), "FORBIDDEN");
        await surfaces09ObserveRefusal("agent cannot control grants", "CLI", verb,
          await surfaces09CliFailure(unprivileged, verb, input), "FORBIDDEN");
        await surfaces09ObserveRefusal("agent cannot control grants", "MCP", verb,
          await surfaces09McpFailure(unprivileged, verb, input), "FORBIDDEN");
      }
      const controlsSdk = await fixture.sdk.run("typescript", {
        mode: "remote", url: fixture.url, credential: unprivileged.credential,
      }, [
        { verb: "facade", path: "vault.connectors.proxy.admit", input: admitInput },
        { verb: "facade", path: "vault.connectors.proxy.revoke_write", input: revokeInput },
      ]);
      for (const [index, verb] of (["vault.connectors.proxy.admit", "vault.connectors.proxy.revoke_write"] as const).entries())
        await surfaces09ObserveRefusal("agent cannot control grants", "SDK", verb,
          surfaces09SdkFailure(controlsSdk, index), "FORBIDDEN");
      await surfaces09Setup(fixture, registration);
      expect(providers.seenFixtureCalls).toHaveLength(0);
      const chatResults: FacadeResult<"ai.chat.completions">[] = [];
      const exchangeRefs: string[] = [];
      const normalized: unknown[] = [];
      for (const [index, carrier] of carriers.entries()) {
        let reply: FacadeResult<"ai.chat.completions">;
        if (carrier === "REST") reply = await agent.client.call("ai.chat.completions", chat);
        else if (carrier === "CLI") reply = await agent.cli.call("ai.chat.completions", chat);
        else if (carrier === "MCP") reply = surfaces09McpOutput(
          await agent.mcp.callTool("ai.chat.completions", { spec: chat })) as FacadeResult<"ai.chat.completions">;
        else reply = surfaces09SdkValue(await fixture.sdk.run("typescript", {
          mode: "remote", url: fixture.url, credential: agent.credential,
        }, [{ verb: "facade", path: "ai.chat.completions", input: chat }])) as FacadeResult<"ai.chat.completions">;
        expect(reply.id).toMatch(/^chatcmpl-[a-f0-9]{32}$/);
        expect(Number.isInteger(reply.created)).toBe(true);
        const remembered = reply.oneiron.remembered;
        if (!("claim" in remembered)) throw new Error("SURFACES-09 proxy did not save its exchange");
        expect(remembered.approval).toBe(data.expected.approval);
        const semantic = { ...reply, id: "<chat-id>", created: 0,
          oneiron: { ...reply.oneiron, remembered: { ...remembered, claim: "<claim-ref>" } } };
        expect(semantic).toMatchObject({
          object: "chat.completion", model: data.model,
          choices: [{ index: 0, message: { role: "assistant", content: data.assistantReply }, finish_reason: "stop" }],
          usage: data.usage, oneiron: { injected: true },
        });
        expect(reply.choices).toHaveLength(1);
        expect(reply.oneiron.recall_skipped == null).toBe(true);
        if (normalized.length > 0) expect(semantic).toEqual<unknown>(normalized[0]);
        normalized.push(semantic); chatResults.push(reply); exchangeRefs.push(remembered.claim);
        const calls = providers.seenFixtureCalls;
        expect(calls).toHaveLength(index + 1);
        const call = calls[index];
        if (call === undefined) throw new Error("SURFACES-09 downstream call is missing");
        expect(call.fixtureId).toBe(`surfaces09-${carrier}`);
        expect(call.method).toBe("POST"); expect(call.path).toBe("/v1/chat/completions");
        const bytes = Buffer.from(JSON.stringify(call.body));
        expect(bytes.includes(Buffer.from(data.admittedMemory)) && bytes.includes(Buffer.from(data.query))).toBe(true);
        surfaces09Absent(call.body, privateValue); surfaces09Absent(call.body, data.privateMemory);
        expect(call.headers?.authorization === undefined && call.headers?.["x-oneiron-binding"] === undefined).toBe(true);
        const rows = await awaitPublic(() => fixture.client.call("vault.claims.list", exchangeInput),
          page => page.value.some(row => row.short_ref === remembered.claim), { label: "SURFACES-09 proposed exchange" });
        const row = rows.value.find(item => item.short_ref === remembered.claim);
        if (row === undefined) throw new Error("SURFACES-09 stored exchange is missing");
        expect(row).toMatchObject({ subject_ref: principalRef, predicate: data.expected.exchangePredicate,
          source: data.expected.source, approval: data.expected.approval, lifecycle: "active" });
        expect(row.value).toEqual({ user: data.query, assistant: data.assistantReply, model: data.model });
        expect(row.claim_scope).toEqual(admittedScope);
        expect(row.made_by?.process.actor).toBe(principalRef);
        expect(row.made_by?.process.identity).toBe("ai.chat.completions");
        expect(row.made_by?.inputs.some(input => input.row === admitted.id && input.role === "prompt")).toBe(true);
        expect(row.made_by?.inputs.some(input => input.row === privateClaim.id)).toBe(false);
        surfaces09Absent(row, privateValue);
        const history = await agent.client.call("vault.claims.history", { claim_ref: remembered.claim });
        expect(history.value.some(item => item.claim_ref === row.claim_ref && item.approval === "proposed")).toBe(true);
      }
      expect(new Set(chatResults.map(reply => reply.id)).size).toBe(4);
      expect(new Set(exchangeRefs).size).toBe(4);
      const before = (await fixture.client.call("vault.claims.list", exchangeInput)).value;
      expect(before).toHaveLength(4);
      const revoked = await fixture.client.call("vault.connectors.proxy.revoke_write", revokeInput);
      expect(revoked.key.id).toBe(registration.key.id);
      expect(revoked.key.status).toBe("active"); expect(revoked.slate.stamped).toBe(true);
      expect(revoked.slate.revision).toBeGreaterThan(registration.slate.revision);
      expect(revoked.key.accepted_slate_revision).toBe(revoked.slate.revision);
      expect(surfaces09Setting(revoked, "vault.remember")).toBe("never_allow");
      expect(revoked.slate.rows.find(row => row.draft.tool === "vault.recall"))
        .toEqual(registration.slate.rows.find(row => row.draft.tool === "vault.recall"));
      await surfaces09Setup(fixture, revoked);
      const currentRevoke = { ...revokeInput, revision: revoked.slate.revision };
      expect(await fixture.cli.call("vault.connectors.proxy.revoke_write", currentRevoke)).toEqual(revoked);
      await surfaces09Setup(fixture, revoked);
      expect(surfaces09McpOutput(await fixture.mcp.callTool("vault.connectors.proxy.revoke_write", { spec: currentRevoke }))).toEqual(revoked);
      await surfaces09Setup(fixture, revoked);
      expect(surfaces09SdkValue(await fixture.sdk.run("typescript", ownerTarget,
        [{ verb: "facade", path: "vault.connectors.proxy.revoke_write", input: currentRevoke }]))).toEqual(revoked);
      await surfaces09Setup(fixture, revoked);
      const afterRevoke = [
        await surfaces09HttpFailure(agent.client, "ai.chat.completions", chat),
        await surfaces09CliFailure(agent, "ai.chat.completions", chat),
        await surfaces09McpFailure(agent, "ai.chat.completions", chat),
      ];
      for (const [index, failure] of afterRevoke.entries()) await surfaces09ObserveRefusal("write grant revoked", carriers[index]!,
        "ai.chat.completions", failure, "connector_grant_revoked");
      const revokedSdk = await fixture.sdk.run("typescript", { mode: "remote", url: fixture.url, credential: agent.credential },
        [{ verb: "facade", path: "ai.chat.completions", input: chat }]);
      await surfaces09ObserveRefusal("write grant revoked", "SDK", "ai.chat.completions",
        surfaces09SdkFailure(revokedSdk), "connector_grant_revoked");
      expect(providers.seenFixtureCalls).toHaveLength(4);
      const surfaces09ReadAndCheck = async (): Promise<void> => {
        const rows = await fixture.client.call("vault.claims.list", exchangeInput);
        expect(rows.value.map(row => row.claim_ref).sort()).toEqual(before.map(row => row.claim_ref).sort());
        for (const row of rows.value) {
          const original = before.find(item => item.claim_ref === row.claim_ref);
          expect(row).toEqual<unknown>(original); surfaces09Absent(row, privateValue);
        }
        const recall = await agent.client.call("vault.recall", { query: data.query, effort: "light", limit: 8, format: "md" });
        expect(Buffer.from(JSON.stringify(recall)).includes(Buffer.from(data.admittedMemory))).toBe(true);
        surfaces09Absent(recall, privateValue); surfaces09Absent(recall, data.privateMemory);
        const privateRows = await fixture.client.call("vault.claims.list", {
          subject_ref: fixture.pairedActor.principalRef, predicate: privateClaim.predicate, limit: 16,
        });
        expect(privateRows.value.map(row => ({ id: row.claim_ref, value: row.value, scope: row.claim_scope })))
          .toEqual([{ id: privateClaim.id, value: privateValue, scope: privateScope }]);
      };
      await surfaces09ReadAndCheck();
      await fixture.restart();
      await surfaces09Setup(fixture, revoked);
      await surfaces09ReadAndCheck();
      for (const receipt of receiptSnapshots)
        expect(await fixture.client.call("vault.receipts.get", { receipt_ref: receipt.receipt_ref })).toEqual(receipt);
      await surfaces09ObserveRefusal("revocation after restart", "REST", "ai.chat.completions",
        await surfaces09HttpFailure(agent.client, "ai.chat.completions", chat), "connector_grant_revoked");
      expect(providers.seenFixtureCalls).toHaveLength(4);
      expect((await fixture.client.call("vault.claims.list", exchangeInput)).value.map(row => row.claim_ref).sort())
        .toEqual(before.map(row => row.claim_ref).sort());
      // Delay known parity reds until every state/readback/restart leg has run.
      expect(parity.map(row => ({ stage: row.stage, carrier: row.carrier, code: row.actual })))
        .toEqual(parity.map(row => ({ stage: row.stage, carrier: row.carrier, code: row.expected })));
    } finally {
      try { if (engine !== undefined) await engine.close(); }
      finally { await providers.close(); }
    }
  });
