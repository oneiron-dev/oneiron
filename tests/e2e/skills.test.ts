import { afterAll, test, expect } from "bun:test";
import { defineFile, runProcess } from "./support/run.ts";
import type { FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { PublicHttpError, type PublicHttpClient } from "./support/clients.ts";
import { loadFixtures } from "./support/fixtures.ts";
import { ScriptedProviders } from "./support/providers.ts";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { SkillLibraryView, GraduationScope } from "@oneiron/client/facade-types";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * Skills and improvement. All eight complete journeys currently wait on G01.
 * suite.todo emits Bun test.todo plus a mandatory BLOCKED report row, never
 * passing coverage. Do not replace a missing typed verb with execute_code,
 * vault.batch, an opaque entity body, a Rust fixture, or a fabricated receipt.
 *
 * Binding readback: worktree head 3a829fe65a7282da4a5e44733ba35cc36fa36b80;
 * generated HTTP facade inputs/results and the public Oneiron SDK; server
 * OpenAPI registry/owner paths, owner pack handlers and CLI command enum.
 * The owner's HTTP pack routes exist, even where SDK/library doors do not.
 * self.skills.save/fork/callables exist; self.skills.call is a typed live-run
 * Callable door, not a stored prose-Workflow executor. skills-pack prints the
 * static API guide, not the vault's skill library. Neither replaces the missing flows.
 *
 * Independent inputs, expected facts and canon SHA-256 pins: skills-scenarios
 * in fixtures/skills/manifest.json. Hub aliases refer to immutable folder
 * assets, not invented vault ids or a fabricated wire index. The bootstrap
 * four are unmodified Apache-2.0 source snapshots, not private seed records.
 *
 * When the doors land, use a fresh EngineFixture.start({ id, profile }) for
 * each journey, loadFixtures(), authenticated public owner/actor setup, and
 * ScriptedProviders behind production wire adapters. MCP calls use the
 * generated tool's arguments.spec. Await public receipts/events, never a
 * private clock, queue drain, sleep, automatic mutation retry or direct store.
 * Canon below defines semantic types where no HTTP/SDK DTO exists yet; it
 * does not invent endpoint names, cursor encodings or model response DTOs.
 */

/* SKILLS-01 — Message to reusable skill should work. OF-206, OF-215.
 * Canon: ARCH-0053 #r4-lifecycle. Oracle: skills-scenarios / SKILLS-01.
 * Conversion/get/list now exist, but this fixture is a stored prose Workflow,
 * not a Callable. Wait for public converted-Candidate admission and a public
 * stored-Workflow execution verb behind its live-run Grant, yielding the actual
 * used-version terminal pack receipt.
 * Preserve conversion dedup, both message refs, [3,1,2] -> [1,2,3], and
 * R5-skill_convert-005: deleting a source must retain and stale the skill,
 * mark that evidence unavailable, and stop trusted loading. Today's converted
 * Candidate does not stale on deletion; that is not a passing substitute.
 * Future full journey also refuses a paired agent with receiptRef and reads
 * conversion, execution and deletion state through second doors after restart.
 */
suite.todo(test, "SKILLS-01", "waits on public converted-Candidate admission and a public stored-Workflow execution verb behind the live-run Grant that returns its used-version terminal pack receipt; retain source-deletion-to-stale assertion R5-skill_convert-005");

/* SKILLS-02 — Hub content identity and pinned update should work.
 * OF-213, OF-396. Canon: ARCH-0053 #r4b-hubs, ARCH-0040 #mcp-actor-ceilings,
 * ARCH-0076 #escalation-doors-built. Oracle: SKILLS-02, skills-hub-aliases.
 *
 * Register two loopback hubs with different aliases serving the SAME v1 tree.
 * Canon SKILL_HUB = {kind, endpoint, trust_tier, sync_policy}; hub_ref =
 * {hub_id, ref_string, pin:{type:semver|tag|commit|content_hash|none,value}}.
 * Import both: one content identity, exactly two distinct source rows, the
 * same tree digest, and scan evidence keyed by (content_hash, provider, time),
 * never by alias. No dependency inherits the importing hub's trust.
 * Move hub A's alias to v2 without changing v1's immutable bytes. Sync its
 * content-hash-frozen pin: it must not silently adopt v2. A refusal on drift
 * is acceptable; the trusted v1 pin/content and both source rows must remain.
 * Explicitly offer v2 with fixture-mcp:lookup widening allowed-tools. Require
 * a pending re-consent proposal/receipt, unchanged effective capabilities and
 * trusted version until the OWNER accepts. An agent cannot accept for them.
 *
 * Separately fork a local improvement and request useful-upstream review.
 * Use a supported System One OR escalation first pin, with pinned model and
 * revision, not a hardcoded vendor. Inspect the review's own providers and
 * paired rows: one per measuring provider, nonzero question_version,
 * probability in [0,1], auxiliary question != answered question. No invented
 * zero row for a missing pair. A supported yes still needs held-out admission;
 * no keeps the resident fork without deleting it. Reject mismatched-provider
 * evidence through the real provider protocol, not a forged internal verdict.
 *
 * Existing owner HTTP (prefix /v1/owner/packs):
 * POST /skills/import {hub,folder,pin_type,pin_value,publisher} -> {entity};
 * PUT /ref-sync {hub,ref,sync_policy,pin_type,pin_value} -> stored ref view;
 * POST /skills/{entity}/sync -> {outcome:applied|proposed|refused_by_policy,
 *                              proposal?,approval?};
 * GET /skills/{entity}/receipts -> {imports:HubImportReceipt[],admission?}.
 * Hub registration/inspection, matching SDK skill doors and useful-upstream
 * review/evidence are missing. Do not fabricate a configured hub entity.
 */
suite.todo(test, "SKILLS-02", "waits on typed SKILL_HUB register/read, skill import/sync SDK calls and useful-upstream review with paired evidence");

const skills03Pins = {
  clean: "652b4548b9147c1a41cb2bc80aa452726b05c465ab4bfdfa0a6fe87a5393a347",
  suspicious: "08c1b2d54fb85b230d8b3186ee5abb107ba498123148779a45cfe8f150a7eeb9",
  pack: "380efdb34d7e13358b3894edb111f9574b5bb605e1c0fe8ac2d895bd03148f10",
  custom: "e23543d64c43fa7ac3f18bd0e6008084b3d1d453f6be6d64bcd44e7c79b70d8c",
} as const;
function skills03QueueTree(providers: ScriptedProviders, id: string,
  metadata: { name: string; description: string; version: string; ref_string: string },
  content_hash: string, files: { path: string; bytes: Uint8Array }[]): string[] {
  const ids = [`${id}-index`, ...files.map((_, index) => `${id}-file-${index}`)];
  providers.enqueue({ id: ids[0]!, origin: "hub", role: "skill-hub", purpose: "pinned-tree",
    request: { method: "GET", path: "/index.json" },
    response: { kind: "json", body: { schema: 1, packages: [{ ...metadata, content_hash,
      files: files.map(file => ({ path: file.path, url: `/${id}/${file.path}` })) }] } } });
  for (const [index, file] of files.entries()) providers.enqueue({
    id: ids[index + 1]!, origin: "hub", role: "skill-hub", purpose: "pinned-tree-file",
    request: { method: "GET", path: `/${id}/${file.path}` },
    response: { kind: "bytes", contentType: "text/plain", body: file.bytes },
  });
  return ids;
}
async function skills03Refusal<V extends FacadeVerb>(engine: EngineFixture, caller: PublicHttpClient,
  actor: string, verb: V, input: FacadeInput<V>, status = 403, code = "FORBIDDEN", message?: string): Promise<string> {
  let refused: PublicHttpError | undefined;
  try { await caller.call(verb, input) }
  catch (error) { if (!(error instanceof PublicHttpError)) throw error; refused = error }
  expect(refused).toBeDefined();
  if (!refused) throw new Error(`${verb} unexpectedly succeeded`);
  expect(refused.reply.status).toBe(status);
  expect(refused.error?.code).toBe(code);
  if (message !== undefined) expect(refused.error?.message).toBe(message);
  const receiptRef = refused.error?.receiptRef;
  expect(typeof receiptRef).toBe("string");
  if (typeof receiptRef !== "string") throw new Error("Refusal omitted receiptRef");
  expect(refused.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
  const receipt = await engine.client.call("vault.receipts.get", { receipt_ref: receiptRef });
  expect(receipt).not.toBeNull();
  expect(receipt?.receipt_ref).toBe(receiptRef);
  expect(receipt?.actor_ref).toBe(actor);
  expect(receipt?.verb.endsWith(verb)).toBe(true);
  expect(receipt?.outcome).toEqual({ refused: { code } });
  return receiptRef;
}
function skills03File(view: FacadeResult<"vault.skills.get">): number[] | undefined {
  return view.files?.find(file => file.path === "SKILL.md")?.content;
}
function skills03Origin(receipt: FacadeResult<"vault.skills.receipts">["imports"][number]) {
  const { installed_as: _lifecycle, disposition: _disposition, ...origin } = receipt;
  return origin;
}

/* SKILLS-03 — Skill admission and soft retirement should work. OF-213, OF-215.
 * Canon: ARCH-0053 #r4-lifecycle, #r4b-hubs. Oracle: SKILLS-03.
 * Proves pinned clean admission, blocked-hash and code-pack holds, retained
 * archive evidence, refusal of restore without replay, and a candidate fork's
 * document/frontier/hub ancestry (R5-skill-008). The fork's exact custom source
 * must save and survive restart; keep that promise even if today's save fails.
 * Successful held-out re-admission/supersession needs a public replay-evidence
 * producer behind the owner's Grant; never supply fabricated evidence_skill.
 */
suite.test(test, "SKILLS-03", "Pinned skill admission and soft archive retain evidence and a custom candidate fork across restart", async () => {
  const fixtures = await loadFixtures();
  const clean = await fixtures.readArchive("skills-clean-v1");
  const suspicious = await fixtures.readArchive("skills-suspicious");
  // Author the scoped-identity correction here; the external fixture stays hash-checked and unchanged.
  const packSource = new TextDecoder().decode(await fixtures.readArchive("skills-code-pack"));
  const pack = new TextEncoder().encode(packSource.replace("name: local-number-helper\n", "name: e2e.local-number-helper\n"));
  expect(createHash("sha256").update(pack).digest("hex")).toBe("20516cc6ab5e1394cedf5e74a8d1ce3ba90d33e90112bc692754dc1b73193e36");
  const helper = await fixtures.readArchive("skills-code-pack-helper");
  const custom = await fixtures.readArchive("skills-custom-fork");
  const engine = await EngineFixture.start({ id: "SKILLS-03", profile });
  const providers = await ScriptedProviders.start({ id: "SKILLS-03", origins: ["hub"], steps: [], artifacts: engine.artifacts });
  const owner = engine.pairedActor.principalRef;
  const hub = "73030000000000000000000000000001";
  const publisher = "e2e-skills-admission";
  const configured = await engine.client.call("vault.skill_hubs.put", { hub, kind: "http-index",
    endpoint: `${providers.urls.hub}/index.json`, trust_tier: "untrusted", sync_policy: "content-hash-frozen" });
  expect(configured.consent.outcome).toBe("approved");
  expect((await engine.client.call("vault.skill_hubs.get", { hub })).endpoint).toBe(`${providers.urls.hub}/index.json`);
  const fit = await engine.client.call("vault.skills.fit.set", { setting: "rule_fit" });
  const codePolicy = await engine.client.call("vault.skills.code_auto_install.set", { enabled: false });
  const hashPolicy = await engine.client.call("vault.skills.rules.set", { content_hash: skills03Pins.suspicious, blocked: true });
  for (const policy of [fit, codePolicy, hashPolicy]) {
    expect(policy.outcome).toBe("approved");
    expect(policy.decision.length).toBeGreaterThan(0);
    await engine.awaitReceipt(`gate:${policy.decision}`);
  }
  const source = (ref_string: string, value: string) => ({ hub_id: hub, ref_string,
    pin: { type: "content_hash" as const, value } });
  const cleanRef = source("skills/normalize-numbers", skills03Pins.clean);
  const suspiciousRef = source("skills/suspicious", skills03Pins.suspicious);
  const packRef = source("packs/local-number-helper", skills03Pins.pack);
  const expectedCalls = skills03QueueTree(providers, "clean", {
    name: "normalize-numbers", description: "Sort a supplied finite integer list without network access.",
    version: "1.0.0", ref_string: cleanRef.ref_string,
  }, skills03Pins.clean, [{ path: "SKILL.md", bytes: clean }]);
  const imported = await engine.client.call("vault.skills.import", { hub_ref: cleanRef, publisher });
  const active = await engine.client.call("vault.skills.get", { entity: imported.entity });
  expect(active.lifecycle).toBe("active");
  expect(active.loadable).toBe(true);
  expect(active.content_hash).toBe(skills03Pins.clean);
  expect(skills03File(active)).toEqual(Array.from(clean));
  expect(active.capabilities).toEqual({ bins: [], env: [], mcp: [], allowed_tools: [] });
  expect(active.receipts.sources).toContainEqual(cleanRef);
  expect(active.scans.length).toBeGreaterThan(0);
  for (const scan of active.scans) {
    expect(scan.contentHash).toBe(skills03Pins.clean);
    expect(scan.provider.length).toBeGreaterThan(0);
    expect(Number.isSafeInteger(scan.scannedAt)).toBe(true);
  }
  const activeReceipts = await engine.client.call("vault.skills.receipts", { entity: imported.entity });
  expect(activeReceipts.imports).toEqual(active.receipts.imports);
  const origin = activeReceipts.imports.find(row => row.hub_id === hub && row.ref_string === cleanRef.ref_string);
  expect(origin).toBeDefined();
  if (!origin) throw new Error("Missing clean import origin");
  expect(origin).toMatchObject({ entity: imported.entity, content_hash: skills03Pins.clean, hub_id: hub,
    pin_type: "content_hash", pin_value: skills03Pins.clean, publisher, installed_as: "active",
    disposition: "installed", requested_permissions: [] });

  expectedCalls.push(...skills03QueueTree(providers, "suspicious", {
    name: "unsafe-sandbox-escape", description: "Deliberately suspicious admission fixture, never execute it.",
    version: "1.0.0", ref_string: suspiciousRef.ref_string,
  }, skills03Pins.suspicious, [{ path: "SKILL.md", bytes: suspicious }]));
  const blocked = await engine.client.call("vault.skills.import", { hub_ref: suspiciousRef, publisher });
  const candidate = await engine.client.call("vault.skills.get", { entity: blocked.entity });
  expect(candidate.lifecycle).toBe("candidate");
  expect(candidate.loadable).toBe(false);
  expect(candidate.content_hash).toBe(skills03Pins.suspicious);
  expect(skills03File(candidate)).toEqual(Array.from(suspicious));
  expect(candidate.receipts.sources).toContainEqual(suspiciousRef);
  expect(candidate.receipts.imports).toEqual(expect.arrayContaining([expect.objectContaining({
    hub_id: hub, content_hash: skills03Pins.suspicious, installed_as: "candidate",
    disposition: { not_installed: "rules_hit" },
  })]));

  expectedCalls.push(...skills03QueueTree(providers, "code-pack", {
    name: "e2e.local-number-helper", description: "A harmless code-bearing pack for admission with code auto-install off.",
    version: "1.0.0", ref_string: packRef.ref_string,
  }, skills03Pins.pack, [{ path: "PACK.md", bytes: pack }, { path: "scripts/helper.js", bytes: helper }]));
  const heldPack = await engine.client.call("vault.packs.install", { hub_ref: packRef, publisher });
  expect(heldPack.outcome).toBe("candidate");
  expect(heldPack.receipt).toMatchObject({ content_hash: skills03Pins.pack, status: "candidate",
    candidate_reason: "code_auto_install_off", hub_id: hub, hub_ref: packRef.ref_string,
    pin_type: "content_hash", pin_value: skills03Pins.pack });
  // The held pack is not an Active installation; this fixture declares no guided setup.
  // Coverage is the immediate Candidate result and no Active installation, not a durable Candidate receipt read.
  expect(await engine.client.call("vault.packs.get", { name: "e2e.local-number-helper" })).toBeNull();

  await engine.client.call("vault.skills.archive", { entity: imported.entity });
  const archived = await engine.client.call("vault.skills.get", { entity: imported.entity });
  expect(archived.lifecycle).toBe("archived");
  expect(archived.loadable).toBe(false);
  expect(archived.content_hash).toBe(active.content_hash);
  expect(archived.files).toEqual(active.files);
  expect(archived.provenance).toEqual(active.provenance);
  expect(archived.scans).toEqual(active.scans);
  const archiveReceipts = await engine.client.call("vault.skills.receipts", { entity: imported.entity });
  expect(archiveReceipts.imports.map(skills03Origin)).toEqual(activeReceipts.imports.map(skills03Origin));
  expect(archiveReceipts.imports[0]?.disposition).toBe("installed");
  expect(archiveReceipts.imports[0]?.installed_as).toBe("active");
  await skills03Refusal(engine, engine.client, owner, "vault.skills.restore", { entity: imported.entity },
    400, "BAD_REQUEST", "invalid SKILL body: hub or fork activation requires local consent and held-out replay");
  expect((await engine.client.call("vault.skills.get", { entity: imported.entity })).lifecycle).toBe("archived");

  const fork = await engine.client.call("self.skills.fork", { parent: imported.entity, skill_id: "normalize-numbers-custom" });
  const forkView = await engine.client.call("vault.skills.get", { entity: fork.skill_id });
  expect(forkView.entity).not.toBe(imported.entity);
  expect(forkView.lifecycle).toBe("candidate");
  expect(forkView.loadable).toBe(false);
  expect(forkView.content_hash).not.toBe(active.content_hash);
  const lineage = forkView.lineage.find(row => row.parent === imported.entity);
  expect(lineage).toBeDefined();
  expect(lineage?.parent_version).toBe(active.version);
  expect(lineage?.parent_available).toBe(true);
  expect(lineage?.parent_document).toMatch(/^[a-f0-9]{32}$/);
  expect(lineage?.parent_frontier?.length).toBeGreaterThan(0);
  expect(lineage?.hub_sources).toContainEqual(cleanRef);
  await engine.awaitReceipt(fork.author_receipt);

  const agentRef = "73030000000000000000000000000002";
  await engine.client.call("vault.agents.create", { agent_def_ref: agentRef, definition: {
    agent_id: "skills-admission-observer", desc: "Non-owner skill admission control", version: "1" } });
  expect((await engine.client.call("vault.agents.get", { agent_def_ref: agentRef })).agent_def_ref).toBe(agentRef);
  const agent = await engine.pairActor({ principalRef: agentRef, actorClass: "agent" });
  expect(await agent.client.call("self.actor", {})).toMatchObject({ actor_ref: agentRef, actor_class: "agent" });
  const agentRefusals: string[] = [];
  const denied = async <V extends FacadeVerb>(verb: V, input: FacadeInput<V>) => {
    agentRefusals.push(await skills03Refusal(engine, agent.client, agentRef, verb, input,
      403, "FORBIDDEN", `${verb} is the vault owner's`));
  };
  await denied("vault.skills.rules.set", { content_hash: skills03Pins.suspicious, blocked: false });
  await denied("vault.skills.code_auto_install.set", { enabled: true });
  await denied("vault.skills.fit.set", { setting: "owner_asked" });
  await denied("vault.skills.archive", { entity: imported.entity });
  await denied("vault.skills.restore", { entity: imported.entity });
  await denied("vault.skills.get", { entity: imported.entity });
  await denied("vault.skills.receipts", { entity: imported.entity });
  await denied("vault.skills.list", { limit: 100 });
  await denied("vault.skills.import", { hub_ref: cleanRef, publisher });
  await denied("vault.packs.install", { hub_ref: packRef, publisher });
  expect((await engine.client.call("vault.skills.get", { entity: imported.entity })).lifecycle).toBe("archived");
  expect((await engine.client.call("vault.skills.get", { entity: blocked.entity })).loadable).toBe(false);
  // This existing public source-edit door must accept its own author's revision.
  await engine.client.call("self.skills.save", { id: fork.skill_id, expected_version: fork.version,
    files: [{ path: "SKILL.md", content: new TextDecoder().decode(custom) }] });
  const customized = await engine.client.call("vault.skills.get", { entity: fork.skill_id });
  expect(skills03File(customized)).toEqual(Array.from(custom));
  expect(customized.content_hash).toBe(skills03Pins.custom);
  expect(customized.lifecycle).toBe("candidate");
  expect(customized.loadable).toBe(false);
  expect(customized.lineage).toEqual(forkView.lineage);

  // The unavailable hub must not undo archive, leak a source, or replace the fork.
  providers.enqueue({ id: "hub-down", origin: "hub", role: "skill-hub", purpose: "import-refusal",
    request: { method: "GET", path: "/index.json" },
    response: { kind: "json", status: 503, body: { error: "fixture-unavailable" } } });
  expectedCalls.push("hub-down");
  await skills03Refusal(engine, engine.client, owner, "vault.skills.import", { hub_ref: cleanRef, publisher }, 400, "BAD_REQUEST");
  expect((await engine.client.call("vault.skills.get", { entity: fork.skill_id })).files).toEqual(customized.files);
  expect(providers.seenFixtureCalls.map(call => call.fixtureId)).toEqual(expectedCalls);

  await engine.restart();
  const durableArchive = await engine.client.call("vault.skills.get", { entity: imported.entity });
  expect(durableArchive.lifecycle).toBe("archived");
  expect(durableArchive.loadable).toBe(false);
  expect(durableArchive.files).toEqual(active.files);
  expect(durableArchive.scans).toEqual(active.scans);
  const durableOrigins = await engine.client.call("vault.skills.receipts", { entity: imported.entity });
  expect(durableOrigins.imports.map(skills03Origin)).toEqual(activeReceipts.imports.map(skills03Origin));
  const durableFork = await engine.client.call("vault.skills.get", { entity: fork.skill_id });
  expect(durableFork.files).toEqual(customized.files);
  expect(durableFork.content_hash).toBe(skills03Pins.custom);
  expect(durableFork.lineage).toEqual(forkView.lineage);
  expect(durableFork.lifecycle).toBe("candidate");
  expect(durableFork.loadable).toBe(false);
  expect((await engine.client.call("vault.skills.get", { entity: blocked.entity })).lifecycle).toBe("candidate");
  expect(await engine.client.call("vault.packs.get", { name: "e2e.local-number-helper" })).toBeNull();
  for (const receiptRef of agentRefusals) {
    expect((await engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }))?.actor_ref).toBe(agentRef);
  }
  expect(providers.seenFixtureCalls.map(call => call.fixtureId)).toEqual(expectedCalls);
  await providers.close();
});

const skills04Pins = {
  clean: "652b4548b9147c1a41cb2bc80aa452726b05c465ab4bfdfa0a6fe87a5393a347",
  custom: "e23543d64c43fa7ac3f18bd0e6008084b3d1d453f6be6d64bcd44e7c79b70d8c",
} as const;
function skills04File(view: FacadeResult<"vault.skills.get">): number[] | undefined {
  return view.files?.find(file => file.path === "SKILL.md")?.content;
}
async function skills04Refusal<V extends FacadeVerb>(engine: EngineFixture, caller: PublicHttpClient,
  actor: string, verb: V, input: FacadeInput<V>, status = 403, code = "FORBIDDEN", message?: string): Promise<string> {
  let refused: PublicHttpError | undefined;
  try { await caller.call(verb, input) }
  catch (error) { if (!(error instanceof PublicHttpError)) throw error; refused = error }
  expect(refused).toBeDefined();
  if (!refused) throw new Error(`${verb} unexpectedly succeeded`);
  expect(refused.reply.status).toBe(status);
  expect(refused.error?.code).toBe(code);
  if (message !== undefined) expect(refused.error?.message).toBe(message);
  const receiptRef = refused.error?.receiptRef;
  expect(typeof receiptRef).toBe("string");
  if (typeof receiptRef !== "string") throw new Error("Refusal omitted receiptRef");
  expect(refused.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
  const receipt = await engine.client.call("vault.receipts.get", { receipt_ref: receiptRef });
  expect(receipt).not.toBeNull();
  expect(receipt?.receipt_ref).toBe(receiptRef);
  expect(receipt?.actor_ref).toBe(actor);
  expect(receipt?.verb.endsWith(verb)).toBe(true);
  expect(receipt?.outcome).toEqual({ refused: { code } });
  return receiptRef;
}
async function skills04Library(engine: EngineFixture): Promise<FacadeResult<"vault.skills.list">["skills"]> {
  const rows: FacadeResult<"vault.skills.list">["skills"] = [];
  let after: string | undefined;
  for (;;) {
    const page = await engine.client.call("vault.skills.list",
      after === undefined ? { limit: 100 } : { after, limit: 100 });
    rows.push(...page.skills);
    if (page.next_after === null || page.next_after === undefined) return rows;
    after = page.next_after;
    if (rows.length > 500) throw new Error("Skill library paging did not terminate");
  }
}
async function skills04Git(args: string[], cwd: string, engine: EngineFixture): Promise<string> {
  const result = await runProcess(["git", ...args], { cwd, env: engine.env,
    label: "skills04-fixture-git", artifacts: engine.artifacts });
  if (result.exitCode !== 0) throw new Error(`git ${args[0]} exited ${result.exitCode}: ${result.stderr.slice(0, 2000)}`);
  return result.stdout;
}
function skills04FrontmatterName(text: string): string {
  const name = text.split("\n").find(row => row.startsWith("name: "))?.slice("name: ".length).trim();
  if (!name) throw new Error("Fixture SKILL.md declares no name");
  return name;
}

/* SKILLS-04 — Bootstrap skills and restore defaults should work. OF-518.
 * Canon: ARCH-0053 #r4b-hubs, #r4-lifecycle. Oracle: SKILLS-04.
 * Proves the required embedded four ship byte-exact from pinned sources,
 * every other shipped skill carries first-hub import provenance at an
 * immutable pin, a signed local mirror becomes the first hub through owner
 * setup, one pinned default is customized to the fixture's exact custom
 * body through the common fork law plus the author's own save, the shipped
 * source deletes with a receipt and never silently restores, explicit
 * restore re-imports the pinned original as a fresh Candidate, and all of
 * it survives restart before and after the explicit restore. Three promised assertions stay red against
 * today's engine: the exact bootstrap four (a fifth skill is embedded),
 * hub-one provenance for that fifth skill, and the author's save of the
 * custom revision. The bootstrap reds run after the green legs so one run
 * still proves import, fork and refusal before the first red.
 */
suite.test(test, "SKILLS-04", "Bootstrap skills and pinned defaults restore explicitly while a custom fork survives restart", async () => {
  const fixtures = await loadFixtures();
  const scenarios = await fixtures.readJson<{ scenarios: { id: string; inputs: { requiredBootstrapNames: string[] } }[] }>("skills-scenarios");
  const required = scenarios.scenarios.find(row => row.id === "SKILLS-04")?.inputs.requiredBootstrapNames;
  if (!required || required.length !== 4) throw new Error("SKILLS-04 needs four required bootstrap names");
  const clean = await fixtures.readArchive("skills-clean-v1");
  const custom = await fixtures.readArchive("skills-custom-fork");
  const cleanText = new TextDecoder().decode(clean);
  const customText = new TextDecoder().decode(custom);
  const cleanSkillId = skills04FrontmatterName(cleanText);
  const forkSkillId = skills04FrontmatterName(customText);
  expect(forkSkillId).not.toBe(cleanSkillId);
  const bootstrapSnapshotId: Record<string, string> = {
    "skill-optimize": "skills-bootstrap-improver",
    judge: "skills-bootstrap-judge",
    "goal-intake": "skills-bootstrap-goal-intake",
    wake: "skills-bootstrap-wake",
  };

  const engine = await EngineFixture.start({ id: "SKILLS-04", profile });
  const owner = engine.pairedActor.principalRef;

  // The required four ship active, loadable and byte-exact; every row's
  // resident hash matches its expected source hash.
  const bootstrap = await engine.client.call("vault.skills.bootstrap", {});
  for (const name of required) {
    const row = bootstrap.find(entry => entry.skill_id === name);
    if (!row) throw new Error(`Missing bootstrap skill ${name}`);
    const snapshotId = bootstrapSnapshotId[name];
    if (!snapshotId) throw new Error(`SKILLS-04 has no pinned snapshot for ${name}`);
    const snapshot = await fixtures.readArchive(snapshotId);
    const resident = row.resident;
    if (!resident) throw new Error(`Missing bootstrap resident ${name}`);
    expect(resident.skill_id).toBe(name);
    expect(resident.lifecycle).toBe("active");
    expect(resident.loadable).toBe(true);
    expect(resident.content_hash).toBe(row.content_hash);
    expect(skills04File(resident)).toEqual(Array.from(snapshot));
  }
  const bootstrapEntities = bootstrap.map(row => row.resident?.entity);

  const firstHub = await engine.client.call("vault.skill_hubs.default.get", {});
  const hub = firstHub.hub;
  const publisher = "e2e-skills-defaults";
  const refString = `skills/${cleanSkillId}`;

  // Offline first-hub mirror beside the vault, never inside it: the exact
  // clean tree at the default's alias in one commit (the hub reads trees;
  // it verifies no commit signature, as HOOKS-05's foreign mirror shows).
  const mirrorDir = resolve(engine.root, "skills04-hub");
  const skillFile = resolve(mirrorDir, refString, "SKILL.md");
  await mkdir(dirname(skillFile), { recursive: true });
  await writeFile(skillFile, clean);
  await skills04Git(["init"], mirrorDir, engine);
  await skills04Git(["add", "-A"], mirrorDir, engine);
  await skills04Git(["-c", "user.name=skills04", "-c", "user.email=skills04@local",
    "commit", "-m", "skills04 pinned fixture mirror"], mirrorDir, engine);
  const commitOid = (await skills04Git(["rev-parse", "HEAD"], mirrorDir, engine)).trim().toLowerCase();
  expect(commitOid).toMatch(/^[a-f0-9]{40}$|^[a-f0-9]{64}$/);

  const hubRow = { hub, kind: "local-dir" as const, endpoint: mirrorDir,
    trust_tier: "community" as const, sync_policy: "pinned-commit" as const };
  const skillsRoot = { hub_id: hub, ref_string: "skills", pin: { type: "commit" as const, value: commitOid } };
  const source = { hub_id: hub, ref_string: refString, pin: { type: "commit" as const, value: commitOid } };
  const put = await engine.client.call("vault.skill_hubs.put", hubRow);
  expect(put.hub).toBe(hub);
  expect(put.consent.outcome).toBe("approved");
  expect(put.consent.decision.length).toBeGreaterThan(0);
  await engine.awaitReceipt(`gate:${put.consent.decision}`);
  const configured = await engine.client.call("vault.skill_hubs.get", { hub });
  expect(configured.kind).toBe("local-dir");
  expect(configured.trust_tier).toBe("community");
  expect(configured.sync_policy).toBe("pinned-commit");
  expect(configured.endpoint.endsWith("skills04-hub")).toBe(true);
  const tracked = await engine.client.call("vault.skill_hubs.refs.set",
    { hub_ref: skillsRoot, sync_policy: "pinned-commit" });
  expect(tracked.hub_ref).toEqual(skillsRoot);
  expect(tracked.sync_policy).toBe("pinned-commit");
  expect(await engine.client.call("vault.skill_hubs.refs.get", { hub, ref_string: "skills" })).toEqual(tracked);
  const pointed = await engine.client.call("vault.skill_hubs.default.get", {});
  expect(pointed.hub).toBe(hub);
  expect(pointed.skills.hub_ref.pin).toEqual({ type: "commit", value: commitOid });

  // One pinned default initializes through the ordinary import door.
  const imported = await engine.client.call("vault.skills.import", { hub_ref: source, publisher });
  const original = await engine.client.call("vault.skills.get", { entity: imported.entity });
  expect(original.skill_id).toBe(cleanSkillId);
  expect(original.lifecycle).toBe("active");
  expect(original.loadable).toBe(true);
  expect(original.content_hash).toBe(skills04Pins.clean);
  expect(skills04File(original)).toEqual(Array.from(clean));
  expect(original.capabilities).toEqual({ bins: [], env: [], mcp: [], allowed_tools: [] });
  expect(original.receipts.sources).toContainEqual(source);
  expect(original.scans.length).toBeGreaterThan(0);
  for (const scan of original.scans) {
    expect(scan.contentHash).toBe(skills04Pins.clean);
    expect(scan.provider.length).toBeGreaterThan(0);
    expect(Number.isSafeInteger(scan.scannedAt)).toBe(true);
  }
  const originalReceipts = await engine.client.call("vault.skills.receipts", { entity: imported.entity });
  expect(originalReceipts.imports).toEqual(original.receipts.imports);
  const originReceipt = originalReceipts.imports.find(row => row.hub_id === hub && row.ref_string === refString);
  expect(originReceipt).toBeDefined();
  if (!originReceipt) throw new Error("Missing default import origin");
  expect(originReceipt).toMatchObject({ entity: imported.entity, content_hash: skills04Pins.clean,
    pin_type: "commit", pin_value: commitOid, publisher, installed_as: "active",
    disposition: "installed", requested_permissions: [] });

  // Customize through the common fork law under the fixture's declared name.
  const fork = await engine.client.call("self.skills.fork", { parent: imported.entity, skill_id: forkSkillId });
  const forkView = await engine.client.call("vault.skills.get", { entity: fork.skill_id });
  expect(forkView.entity).not.toBe(imported.entity);
  expect(forkView.skill_id).toBe(forkSkillId);
  expect(forkView.lifecycle).toBe("candidate");
  expect(forkView.loadable).toBe(false);
  expect(forkView.content_hash).not.toBe(original.content_hash);
  const lineage = forkView.lineage.find(row => row.parent === imported.entity);
  expect(lineage).toBeDefined();
  expect(lineage?.parent_version).toBe(original.version);
  expect(lineage?.parent_available).toBe(true);
  expect(lineage?.parent_document).toMatch(/^[a-f0-9]{32}$/);
  expect(lineage?.parent_frontier?.length).toBeGreaterThan(0);
  expect(lineage?.hub_sources).toContainEqual(source);
  await engine.awaitReceipt(fork.author_receipt);

  // Wrong-actor refusals with their receipts, before the kept reds below.
  const agentRef = "73040000000000000000000000000001";
  await engine.client.call("vault.agents.create", { agent_def_ref: agentRef, definition: {
    agent_id: "skills04-non-owner", desc: "Non-owner bootstrap/default control", version: "1" } });
  expect((await engine.client.call("vault.agents.get", { agent_def_ref: agentRef })).agent_def_ref).toBe(agentRef);
  const agent = await engine.pairActor({ principalRef: agentRef, actorClass: "agent" });
  expect(await agent.client.call("self.actor", {})).toMatchObject({ actor_ref: agentRef, actor_class: "agent" });
  const agentRefusals: string[] = [];
  const denied = async <V extends FacadeVerb>(verb: V, input: FacadeInput<V>) => {
    agentRefusals.push(await skills04Refusal(engine, agent.client, agentRef, verb, input,
      403, "FORBIDDEN", `${verb} is the vault owner's`));
  };
  await denied("vault.skills.bootstrap", {});
  await denied("vault.skill_hubs.default.get", {});
  await denied("vault.skill_hubs.get", { hub });
  await denied("vault.skill_hubs.put", hubRow);
  await denied("vault.skill_hubs.refs.set", { hub_ref: skillsRoot, sync_policy: "pinned-commit" });
  await denied("vault.skills.import", { hub_ref: source, publisher });
  await denied("vault.skills.get", { entity: imported.entity });
  await denied("vault.skills.receipts", { entity: imported.entity });
  await denied("vault.skills.list", { limit: 100 });
  await denied("vault.skills.restoreDefaults", {});
  agentRefusals.push(await skills04Refusal(engine, agent.client, agentRef, "vault.delete",
    { entity_ref: imported.entity, reason: "user_delete" }, 403, "FORBIDDEN",
    "actor class agent may not delete entities; deletion is an owner verb"));

  // Kept promised assertions: no shipped skill outside the required four may
  // lack hub-one provenance at an immutable pin, and bootstrap is exactly
  // the required four. Both stay red while a fifth skill is embedded.
  const shipped = await engine.client.call("vault.skills.bootstrap", {});
  for (const row of shipped.filter(entry => !required.includes(entry.skill_id))) {
    const resident = row.resident;
    if (!resident) throw new Error(`Shipped skill ${row.skill_id} has no resident to prove provenance`);
    const hubSources = resident.receipts.sources.filter(entry => entry.hub_id === hub);
    expect(hubSources.length).toBeGreaterThan(0);
    for (const provenance of hubSources) {
      expect(provenance.pin.type).not.toBe("none");
      if (provenance.pin.type !== "none") expect(provenance.pin.value.length).toBeGreaterThan(0);
    }
  }
  expect(shipped.map(row => row.skill_id).sort()).toEqual([...required].sort());

  // Kept promised assertion: the author's own save lands the exact custom revision.
  await engine.client.call("self.skills.save", { id: fork.skill_id, expected_version: fork.version,
    files: [{ path: "SKILL.md", content: customText }] });
  const customized = await engine.client.call("vault.skills.get", { entity: fork.skill_id });
  expect(skills04File(customized)).toEqual(Array.from(custom));
  expect(customized.content_hash).toBe(skills04Pins.custom);
  expect(customized.skill_id).toBe(forkSkillId);
  expect(customized.lifecycle).toBe("candidate");
  expect(customized.loadable).toBe(false);
  expect(customized.lineage).toEqual(forkView.lineage);

  // Owner-delete the shipped source; no read may silently restore it.
  const deleted = await engine.client.call("vault.delete", { entity_ref: imported.entity, reason: "user_delete" });
  expect(deleted).toMatchObject({ existed: true, state: "applied" });
  await skills04Refusal(engine, engine.client, owner, "vault.skills.get", { entity: imported.entity }, 404, "NOT_FOUND");
  expect((await skills04Library(engine)).some(row => row.entity === imported.entity)).toBe(false);
  const orphaned = await engine.client.call("vault.skills.get", { entity: fork.skill_id });
  expect(skills04File(orphaned)).toEqual(Array.from(custom));
  expect(orphaned.content_hash).toBe(skills04Pins.custom);
  const orphanLineage = orphaned.lineage.find(row => row.parent === imported.entity);
  expect(orphanLineage?.parent_available).toBe(false);
  expect(orphanLineage?.parent_version).toBe(original.version);
  expect(orphanLineage?.parent_document).toBe(lineage?.parent_document);
  expect(orphanLineage?.parent_frontier).toEqual(lineage?.parent_frontier);
  expect(orphanLineage?.hub_sources).toContainEqual(source);

  // Reopen before restore: deletion cannot silently seed the original again.
  await engine.restart();
  await skills04Refusal(engine, engine.client, owner, "vault.skills.get", { entity: imported.entity }, 404, "NOT_FOUND");
  expect((await skills04Library(engine)).filter(row => row.content_hash === skills04Pins.clean)).toEqual([]);
  const afterDeletedRestart = await engine.client.call("vault.skills.get", { entity: fork.skill_id });
  expect(skills04File(afterDeletedRestart)).toEqual(Array.from(custom));
  expect(afterDeletedRestart.lineage).toEqual(orphaned.lineage);
  expect(await engine.client.call("vault.skills.bootstrap", {})).toEqual(bootstrap);

  // Explicit restore re-imports the pinned original as a fresh Candidate.
  const restored = await engine.client.call("vault.skills.restoreDefaults", {});
  expect(restored).toHaveLength(1);
  const fresh = restored[0]!;
  expect(fresh.entity).not.toBe(imported.entity);
  expect(fresh).toMatchObject({ content_hash: skills04Pins.clean, hub_id: hub, ref_string: refString,
    pin_type: "commit", pin_value: commitOid, installed_as: "candidate",
    disposition: { not_installed: "source_only" }, requested_permissions: [] });
  expect(fresh.publisher ?? null).toBeNull();
  expect(fresh.fit_analysis ?? null).toBeNull();
  const renewed = await engine.client.call("vault.skills.get", { entity: fresh.entity });
  expect(renewed.skill_id).toBe(cleanSkillId);
  expect(renewed.lifecycle).toBe("candidate");
  expect(renewed.loadable).toBe(false);
  expect(renewed.content_hash).toBe(skills04Pins.clean);
  expect(skills04File(renewed)).toEqual(Array.from(clean));
  expect(renewed.receipts.sources).toContainEqual(source);
  const kept = await engine.client.call("vault.skills.get", { entity: fork.skill_id });
  expect(skills04File(kept)).toEqual(Array.from(custom));
  expect(kept.content_hash).toBe(skills04Pins.custom);
  expect(kept.lineage.find(row => row.parent === imported.entity)?.parent_available).toBe(false);
  expect((await engine.client.call("vault.skills.bootstrap", {})).map(row => row.resident?.entity)).toEqual(bootstrapEntities);

  // Reopen again: the explicit restore persists, nothing else changes.
  await engine.restart();
  const durableNew = await engine.client.call("vault.skills.get", { entity: fresh.entity });
  expect(durableNew.content_hash).toBe(skills04Pins.clean);
  expect(skills04File(durableNew)).toEqual(Array.from(clean));
  expect(durableNew.lifecycle).toBe("candidate");
  expect(durableNew.loadable).toBe(false);
  const durableFork = await engine.client.call("vault.skills.get", { entity: fork.skill_id });
  expect(skills04File(durableFork)).toEqual(Array.from(custom));
  expect(durableFork.content_hash).toBe(skills04Pins.custom);
  expect(durableFork.lineage).toEqual(orphaned.lineage);
  expect(await engine.client.call("vault.skills.bootstrap", {})).toEqual(bootstrap);
  expect((await skills04Library(engine)).filter(row => row.content_hash === skills04Pins.clean).map(row => row.entity))
    .toEqual([fresh.entity]);
  expect(await engine.client.call("vault.skills.restoreDefaults", {})).toEqual([]);
  for (const receiptRef of agentRefusals) {
    expect((await engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }))?.actor_ref).toBe(agentRef);
  }
});

/* SKILLS-05 — Skill receipt attribution and reliability should work.
 * OF-184, OF-395, OF-397, OF-394. Canon: ARCH-0053 #r4-lifecycle,
 * #r3-reliability and ARCH-0003 #learning. Oracle: SKILLS-05.
 *
 * Publicly create two versions and two distinct actors, then pair the actors;
 * pairActor creates credentials for existing principals, never an actor.
 * Execute via MCP with scripted anchored success, skill-defect failure and
 * execution-lapse failure. Include a loaded-but-unused skill, an unanchored
 * self-reported win, an environment failure and an unclear judgment control.
 * Settle through public outcome doors, await the projector's public receipt,
 * then inspect next retrieval through HTTP/MCP. Pack manifests are append-only
 * across mid-run pulls. Each receipt names loaded vs actually used versions,
 * actor, executor/judge revisions, outcome anchor and required
 * typeRef={node_id,tree_version}. Superseded versions never load as current.
 *
 * learning.reliability is one states-only, projector-only estimate keyed by
 * subject, executor, typeRef and axis. Its value is {form:beta,value:{alpha,beta},
 * runs,prior:{origin,value,weight_runs,from?},untested,of,labels,window,ver}.
 * Own runs count only anchored attributed evidence: used contribution earns
 * wins, skill defect charges skill, lapse charges actor prose/actor lane,
 * environment/unclear blame nobody. No success from load alone, agreement or
 * self-report. Provider reliability uses the same family, not a second score.
 * The next retrieval must expose its reliability/UCB evidence without a fixed
 * randomized rank or locally reimplemented posterior formula. Judge identity
 * is evidence, never part of the reliability cell key.
 *
 * Existing call receipts prove a transport invocation, NOT its task outcome.
 * vault.settings.learning reads knob seeds/pins, NOT skill effectiveness.
 * vault.claims.list has an opaque value leaf, not a substitute typed learning
 * projection. Never hand-write a learning.* claim to manufacture this flow.
 */
suite.todo(test, "SKILLS-05", "waits on typed MCP skill execution/pack outcomes, attributed learning projection and retrieval evidence");

interface Skills06Scenario {
  id: string;
  inputs: { excludedTiers: string[] };
  expectedFacts: { identityAutoEdited: boolean; alignmentAutoEdited: boolean };
}
// Source, content version, lifecycle and capabilities must not change with a tier mark.
function skills06Content(view: SkillLibraryView) {
  return { desc: view.desc, version: view.version, content_hash: view.content_hash ?? null,
    lifecycle: view.lifecycle, files: view.files, capabilities: view.capabilities };
}
async function skills06HttpRefusal<V extends FacadeVerb>(
  engine: EngineFixture, client: PublicHttpClient, verb: V, input: FacadeInput<V>,
  status: number, code: string, actorRef: string, actorClass: string,
) {
  let failure: unknown;
  try { await client.call(verb, input); } catch (error) { failure = error; }
  if (!(failure instanceof PublicHttpError)) throw new Error(`Expected public refusal for ${verb}`);
  expect(failure.reply.status).toBe(status);
  expect(failure.error?.code).toBe(code);
  expect(failure.error?.message).toBe(`${verb} is the vault owner's`);
  const receiptRef = failure.error?.receiptRef;
  expect(receiptRef).toEqual(expect.stringMatching(/^call:[a-f0-9]{32}$/));
  if (typeof receiptRef !== "string") throw new Error(`Missing refusal receipt for ${verb}`);
  expect(failure.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
  const receipt = await awaitPublic(
    () => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null, { label: `skills06 refusal receipt ${verb}` });
  expect(receipt?.receipt_ref).toBe(receiptRef);
  expect(receipt?.transport).toBe("http_facade");
  expect(receipt?.verb.endsWith(verb)).toBe(true);
  expect(receipt?.actor_ref).toBe(actorRef);
  expect(receipt?.actor_class).toBe(actorClass);
  expect(receipt?.outcome).toEqual({ refused: { code } });
  return { failure, receipt };
}

/* SKILLS-06 — Held-out skill optimization should work. OF-214, OF-379.
 * Partial: protected governance tiers never enter automatic editing. Identity
 * and alignment skills are excluded before enqueue with content, version and
 * lifecycle unchanged (a standard skill still enqueues as the selectivity
 * control); every write is read back through governance/library/result doors;
 * non-owner calls to all four doors are refused with call receipts; marks and
 * content survive restart. Unproved: overfit rejection, held-out sealing and
 * leakage, winner admission, goal/cost dominance, lineage. waits on an
 * owner-authorized skill optimization input binding authored DEV/sealed
 * families to real outcome evidence (a stored-workflow execution plus
 * attributed held-out outcome producer), with explicit admission and
 * lineage/goal readback.
 */
suite.test(test, "SKILLS-06", "Identity and alignment skills stay out of automatic optimization while standard skills still enqueue, with content unchanged across restart and non-owner calls refused", async () => {
  const catalog = await loadFixtures();
  const document = await catalog.readJson<{ scenarios: Skills06Scenario[] }>("skills-scenarios");
  const facts = document.scenarios.find(row => row.id === "SKILLS-06");
  if (!facts) throw new Error("Missing SKILLS-06 fixture");
  expect(facts.inputs.excludedTiers).toEqual(["identity", "alignment"]);
  expect(facts.expectedFacts.identityAutoEdited).toBe(false);
  expect(facts.expectedFacts.alignmentAutoEdited).toBe(false);

  const engine = await EngineFixture.start({ id: "SKILLS-06", profile });
  try {
    const owner = engine.client;
    // Setup through plain owner library reads: two real seeded active skills.
    const page = await owner.call("vault.skills.list", { limit: 100 });
    const actives = page.skills.filter(skill => skill.lifecycle === "active");
    const first = actives.find(skill => skill.skill_id === "skill-optimize") ?? actives[0];
    if (!first) throw new Error("Fresh vault lists no active skill");
    const second = actives.find(skill => skill.entity !== first.entity);
    if (!second) throw new Error("Fresh vault lists only one active skill");
    const s1 = first.entity;
    const s2 = second.entity;
    const s1Before = skills06Content(await owner.call("vault.skills.get", { entity: s1 }));
    const s2Before = skills06Content(await owner.call("vault.skills.get", { entity: s2 }));

    // Act 1: mark S1 identity; read back through governance.get (second door).
    const s1Set = await owner.call("vault.skills.governance.set", { entity: s1, tier: "identity" });
    expect(s1Set).toMatchObject({ entity: s1, verdict: "marked", tier: "identity",
      protected: true, optimizable: false });
    const s1Gov = await owner.call("vault.skills.governance.get", { entity: s1 });
    expect(s1Gov).toEqual(s1Set);
    expect(s1Gov.version).toBe(s1Before.version);
    expect(s1Gov.lifecycle).toBe("active");
    // Excluded before enqueue: no job, no state, exact skill echo.
    const s1Start = await owner.call("vault.skills.optimize.start", { skill: s1, dedupe_key: "skills-06-identity" });
    expect(s1Start.outcome).toBe("excluded");
    expect(s1Start.job_ref ?? null).toBeNull();
    expect(s1Start.state ?? null).toBeNull();
    expect(s1Start.skill).toBe(s1);
    expect(s1Start.governance).toEqual(s1Gov);

    // Act 2: mark S2 alignment; same exclusion.
    const s2Set = await owner.call("vault.skills.governance.set", { entity: s2, tier: "alignment" });
    expect(s2Set).toMatchObject({ entity: s2, verdict: "marked", tier: "alignment",
      protected: true, optimizable: false });
    const s2Gov = await owner.call("vault.skills.governance.get", { entity: s2 });
    expect(s2Gov).toEqual(s2Set);
    const s2Start = await owner.call("vault.skills.optimize.start", { skill: s2, dedupe_key: "skills-06-alignment" });
    expect(s2Start.outcome).toBe("excluded");
    expect(s2Start.job_ref ?? null).toBeNull();
    expect(s2Start.state ?? null).toBeNull();
    expect(s2Start.skill).toBe(s2);
    expect(s2Start.governance).toEqual(s2Gov);

    // Second-door content readback: no edit happened; only the tier mark changed.
    expect(skills06Content(await owner.call("vault.skills.get", { entity: s1 }))).toEqual(s1Before);
    expect(skills06Content(await owner.call("vault.skills.get", { entity: s2 }))).toEqual(s2Before);
    expect((await owner.call("vault.skills.get", { entity: s1 })).governance_tier).toBe("identity");
    expect((await owner.call("vault.skills.get", { entity: s2 })).governance_tier).toBe("alignment");

    // Wrong actor: inert agent, paired with real credentials.
    const agentRef = "06060606060606060606060606060606";
    const created = await owner.call("vault.agents.create", { agent_def_ref: agentRef, definition: {
      agent_id: "skills06-observer", display_name: "Skills optimize observer",
      desc: "Inert principal for owner-only optimize/governance refusals", version: "1" } });
    expect(created.agent_def_ref).toBe(agentRef);
    expect((await owner.call("vault.get", { entity_ref: agentRef })).value?.kind).toBe("AGENT_DEF");
    const agent = await engine.pairActor({ principalRef: agentRef, actorClass: "agent" });
    expect(await agent.client.call("self.actor", {})).toMatchObject({ actor_ref: agentRef, actor_class: "agent" });

    await skills06HttpRefusal(engine, agent.client, "vault.skills.governance.get", { entity: s1 }, 403, "FORBIDDEN", agentRef, "agent");
    await skills06HttpRefusal(engine, agent.client, "vault.skills.governance.set", { entity: s1, tier: "standard" }, 403, "FORBIDDEN", agentRef, "agent");
    await skills06HttpRefusal(engine, agent.client, "vault.skills.optimize.start", { skill: s1, dedupe_key: "skills-06-agent" }, 403, "FORBIDDEN", agentRef, "agent");
    await skills06HttpRefusal(engine, agent.client, "vault.skills.optimize.result", { proposal: s1 }, 403, "FORBIDDEN", agentRef, "agent");
    // Denied mutations changed nothing owner-visible.
    expect(await owner.call("vault.skills.governance.get", { entity: s1 })).toEqual(s1Gov);
    expect(skills06Content(await owner.call("vault.skills.get", { entity: s1 }))).toEqual(s1Before);

    // Owner input refusal (not a job-execution claim).
    let emptyResult: unknown;
    try { await owner.call("vault.skills.optimize.result", {}); } catch (error) { emptyResult = error; }
    if (!(emptyResult instanceof PublicHttpError)) throw new Error("Expected 400 for empty optimize result");
    expect(emptyResult.reply.status).toBe(400);
    expect(emptyResult.error?.code).toBe("BAD_REQUEST");
    expect(emptyResult.error?.message).toBe("optimize result needs a job_ref or a proposal");
    const emptyResultReceiptRef = emptyResult.error?.receiptRef;
    expect(typeof emptyResultReceiptRef).toBe("string");
    if (typeof emptyResultReceiptRef !== "string") throw new Error("Empty optimize result refusal omitted receiptRef");
    expect(emptyResult.reply.headers.get("x-oneiron-receipt-ref")).toBe(emptyResultReceiptRef);
    const emptyResultReceipt = await awaitPublic(
      () => owner.call("vault.receipts.get", { receipt_ref: emptyResultReceiptRef }),
      value => value !== null, { label: "skills06 owner input-refusal receipt" });
    expect(emptyResultReceipt?.receipt_ref).toBe(emptyResultReceiptRef);
    expect(emptyResultReceipt?.actor_ref).toBe(engine.pairedActor.principalRef);
    expect(emptyResultReceipt?.verb.endsWith("vault.skills.optimize.result")).toBe(true);
    expect(emptyResultReceipt?.outcome).toEqual({ refused: { code: "BAD_REQUEST" } });

    // Restart: protected marks and untouched content survive.
    await engine.restart();
    expect(await owner.call("vault.skills.governance.get", { entity: s1 })).toEqual(s1Gov);
    expect(await owner.call("vault.skills.governance.get", { entity: s2 })).toEqual(s2Gov);
    expect(skills06Content(await owner.call("vault.skills.get", { entity: s1 }))).toEqual(s1Before);
    expect(skills06Content(await owner.call("vault.skills.get", { entity: s2 }))).toEqual(s2Before);

    // Selectivity control: standard tier enqueues instead of excluding.
    const s1Std = await owner.call("vault.skills.governance.set", { entity: s1, tier: "standard" });
    expect(s1Std).toMatchObject({ entity: s1, verdict: "marked", tier: "standard",
      protected: false, optimizable: true });
    const s1Enqueue = await owner.call("vault.skills.optimize.start", { skill: s1, dedupe_key: "skills-06-standard" });
    expect(s1Enqueue.outcome).toBe("enqueued");
    expect(s1Enqueue.job_ref).toEqual(expect.stringMatching(/^[a-f0-9]{32}$/));
    expect(s1Enqueue.state).toBe("queued");
    expect(s1Enqueue.skill).toBe(s1);
    expect(s1Enqueue.governance).toEqual(s1Std);
    if (typeof s1Enqueue.job_ref !== "string") throw new Error("Missing enqueued job ref");
    const queued = await owner.call("vault.skills.optimize.result", { job_ref: s1Enqueue.job_ref });
    expect(queued.job_ref).toBe(s1Enqueue.job_ref);
    expect(queued.state).toBe("queued");
    expect(queued.kind).toBe("dreamer.skill_optimize");
    expect(queued.proposal ?? null).toBeNull();
    expect(queued.verdicts).toEqual([]);
  } finally {
    await engine.close();
  }
});

/* SKILLS-07 — Edit-delta attribution split should work. OF-400, OF-379.
 * Canon: ARCH-0056 #attribution-split, ARCH-0053 #r4-lifecycle,
 * ARCH-0003 #learning. Oracle: SKILLS-07.
 * Wait for public proposal-text open/edit/finalize verbs behind the owner's
 * Grant, preserving the actual actor-bound operations before settlement.
 * Endpoint reconstruction is not that record. Preserve the 7:3 hunk split,
 * exact qualified reliability/edit-cost and preference evidence, malformed
 * sum-0.9 refusal, zero whitespace mass, and R5-skill_attribution-004:
 * one unclear note with an already-grounded reliability cell unchanged.
 * self.skills.call and pack_receipt exist; do not invent an attached run,
 * attempt/type stamp or loaded/used pack to make the reliability join pass.
 * Future full journey reads projections through second doors, refuses a
 * paired agent with receiptRef, and retains evidence across restart.
 */
suite.todo(test, "SKILLS-07", "waits on public proposal-text open/edit/finalize verbs behind the owner's Grant, plus a genuine skill/actor-bound terminal attempt and outcome for the unchanged-reliability control R5-skill_attribution-004");

interface Skills08Scenario {
  id: string;
  inputs: {
    policyIntent: { streakUntouched: number; untouchedProbabilityGuard: number; snoozeBackoffSeconds: number };
    initialEvidence: string[];
    decline: string;
    reEarnedEvidence: string[];
  };
}
function skills08ScopeOf(actor: string): GraduationScope {
  return { op_kind: "send_email", target_class: "client_followup", actor };
}
function skills08ScopeMatches(scope: GraduationScope, actor: string): boolean {
  return scope.op_kind === "send_email" && scope.target_class === "client_followup" && scope.actor === actor;
}
function skills08Offers(offers: FacadeResult<"vault.consent.graduation.offers">, actor: string) {
  return offers.filter(offer => skills08ScopeMatches(offer.scope, actor));
}
function skills08TrustRow(rows: FacadeResult<"vault.consent.graduation.trust_table">, actor: string) {
  return rows.find(row => skills08ScopeMatches(row.scope, actor));
}
// Exact action bound only: this scope's live grant, never whole-vault row counts.
function skills08ActiveGrantsFor(registry: FacadeResult<"vault.consent.registry">, actor: string) {
  return registry.rows.filter(row => row.subject === actor && row.class === "send_email"
    && row.selectors.length === 1 && row.selectors[0] === "client_followup" && row.status === "active");
}
async function skills08HttpRefusal<V extends FacadeVerb>(
  engine: EngineFixture, client: PublicHttpClient, verb: V, input: FacadeInput<V>,
  status: number, code: string, actorRef: string, actorClass: string,
) {
  let failure: unknown;
  try { await client.call(verb, input); } catch (error) { failure = error; }
  if (!(failure instanceof PublicHttpError)) throw new Error(`Expected public refusal for ${verb}`);
  expect(failure.reply.status).toBe(status);
  expect(failure.error?.code).toBe(code);
  expect(failure.error?.message).toBe(`${verb} is the vault owner's`);
  const receiptRef = failure.error?.receiptRef;
  expect(receiptRef).toEqual(expect.stringMatching(/^call:[a-f0-9]{32}$/));
  if (typeof receiptRef !== "string") throw new Error(`Missing refusal receipt for ${verb}`);
  expect(failure.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
  const receipt = await awaitPublic(
    () => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null, { label: `skills08 refusal receipt ${verb}` });
  expect(receipt?.receipt_ref).toBe(receiptRef);
  expect(receipt?.transport).toBe("http_facade");
  expect(receipt?.verb.endsWith(verb)).toBe(true);
  expect(receipt?.actor_ref).toBe(actorRef);
  expect(receipt?.actor_class).toBe(actorClass);
  expect(receipt?.outcome).toEqual({ refused: { code } });
  return { failure, receipt };
}

/* SKILLS-08 — Consent graduation is an offer should work. OF-399.
 * Partial: a short streak plus posterior guard earns one derived offer that
 * grants nothing by itself (R2-consent_graduation-001, R6-tests-it-061);
 * not-now decline resets the streak and needs the whole streak re-earned;
 * owner accept mints exactly one standing grant, durable across restart;
 * demotion returns the scope to propose with history kept and a gate receipt;
 * non-owner answers are refused with call receipts. The fixture's four clean
 * approvals are a negative guard control at 0.5 after two same-scope corrections;
 * extend each earned streak to seven approvals to satisfy both policy axes.
 * This explicitly extends the fixture's four-entry reEarnedEvidence. Unproved: sample/edit-cost
 * policy axes, literal undo demotion, exact audience/budget on the grant, a
 * stored offer identity. waits on owner-authorized graduation policy/read
 * axes for sample/edit-cost evidence, an undo outcome with thresholded
 * demotion, and the requested audience/budget/offer-identity contract.
 */
suite.test(test, "SKILLS-08", "Consent graduation offers grant nothing until owner acceptance; decline requires a fresh streak and demotion is receipted", async () => {
  const catalog = await loadFixtures();
  const document = await catalog.readJson<{ scenarios: Skills08Scenario[] }>("skills-scenarios");
  const facts = document.scenarios.find(row => row.id === "SKILLS-08");
  if (!facts) throw new Error("Missing SKILLS-08 fixture");
  // Promised policy inputs: short streak, guard 0.5, zero backoff. Kept as promised.
  expect(facts.inputs.policyIntent.streakUntouched).toBe(4);
  expect(facts.inputs.policyIntent.untouchedProbabilityGuard).toBe(0.5);
  expect(facts.inputs.policyIntent.snoozeBackoffSeconds).toBe(0);
  expect(facts.inputs.initialEvidence).toEqual(["approved_amended", "rejected",
    "approved_untouched", "approved_untouched", "approved_untouched", "approved_untouched"]);
  expect(facts.inputs.decline).toBe("not-now");
  expect(facts.inputs.reEarnedEvidence).toEqual(["approved_untouched",
    "approved_untouched", "approved_untouched", "approved_untouched"]);

  const engine = await EngineFixture.start({ id: "SKILLS-08", profile });
  try {
    const owner = engine.client;
    // Wrong-actor principal doubles as the graduation scope actor.
    const agentRef = "08080808080808080808080808080808";
    const created = await owner.call("vault.agents.create", { agent_def_ref: agentRef, definition: {
      agent_id: "skills08-actor", display_name: "Skills graduation actor",
      desc: "Inert principal for graduation scope and refusals", version: "1" } });
    expect(created.agent_def_ref).toBe(agentRef);
    expect((await owner.call("vault.get", { entity_ref: agentRef })).value?.kind).toBe("AGENT_DEF");
    const agent = await engine.pairActor({ principalRef: agentRef, actorClass: "agent" });
    expect(await agent.client.call("self.actor", {})).toMatchObject({ actor_ref: agentRef, actor_class: "agent" });

    const scope = skills08ScopeOf(agentRef);
    const pattern = `send_email/client_followup/${agentRef}`;

    // Act: promised short policy. Read back effective row plus rows (second door).
    expect(await owner.call("vault.consent.graduation.policy.set", { policy: {
      scope_pattern: pattern, required_streak: 4, posterior_guard: 0.5, snooze_backoff_seconds: [0, 0] } }))
      .toEqual({ changed: true });
    const policy = await owner.call("vault.consent.graduation.policy", { scope });
    expect(policy.effective).toEqual({ scope_pattern: pattern, required_streak: 4,
      posterior_guard: 0.5, snooze_backoff_seconds: [0, 0] });
    expect(policy.rows).toContainEqual<unknown>(policy.effective);
    // Baseline: no history, no offer, no grant.
    expect(await owner.call("vault.consent.graduation.stats", { scope })).toBeNull();
    expect(skills08TrustRow(await owner.call("vault.consent.graduation.trust_table", {}), agentRef)).toBeUndefined();
    expect(skills08Offers(await owner.call("vault.consent.graduation.offers", {}), agentRef)).toEqual([]);
    expect(skills08ActiveGrantsFor(await owner.call("vault.consent.registry", { limit: 100 }), agentRef)).toEqual([]);

    // Same-scope correction history, then the streak.
    expect((await owner.call("vault.consent.graduation.outcome", { scope, outcome: "approved_amended" })).amended).toBe(1);
    const afterReject = await owner.call("vault.consent.graduation.outcome", { scope, outcome: "rejected" });
    expect(afterReject).toMatchObject({ untouched_streak: 0, amended: 1, rejected: 1, state: "propose" });
    expect(skills08Offers(await owner.call("vault.consent.graduation.offers", {}), agentRef)).toEqual([]);

    // Refusals run before the streak completes and must not alter correction history.
    await skills08HttpRefusal(engine, agent.client, "vault.consent.graduation.policy", { scope }, 403, "FORBIDDEN", agentRef, "agent");
    await skills08HttpRefusal(engine, agent.client, "vault.consent.graduation.policy.set", { policy: {
      scope_pattern: pattern, required_streak: 4, posterior_guard: 0.5, snooze_backoff_seconds: [0, 0] } }, 403, "FORBIDDEN", agentRef, "agent");
    await skills08HttpRefusal(engine, agent.client, "vault.consent.graduation.stats", { scope }, 403, "FORBIDDEN", agentRef, "agent");
    await skills08HttpRefusal(engine, agent.client, "vault.consent.graduation.outcome", { scope, outcome: "approved_untouched" }, 403, "FORBIDDEN", agentRef, "agent");
    await skills08HttpRefusal(engine, agent.client, "vault.consent.graduation.offers", {}, 403, "FORBIDDEN", agentRef, "agent");
    await skills08HttpRefusal(engine, agent.client, "vault.consent.graduation.answer", { scope, answer: "auto" }, 403, "FORBIDDEN", agentRef, "agent");
    await skills08HttpRefusal(engine, agent.client, "vault.consent.graduation.trust_table", {}, 403, "FORBIDDEN", agentRef, "agent");
    await skills08HttpRefusal(engine, agent.client, "vault.consent.graduation.demote", { scope, reason: "amended" }, 403, "FORBIDDEN", agentRef, "agent");
    // Denied outcome/policy writes changed nothing.
    expect(await owner.call("vault.consent.graduation.stats", { scope })).toMatchObject({ untouched_streak: 0, amended: 1, rejected: 1 });
    expect((await owner.call("vault.consent.graduation.policy", { scope })).effective?.posterior_guard).toBe(0.5);

    // Policy and correction history remain intact; reserve the single restart for grant durability.
    expect((await owner.call("vault.consent.graduation.policy", { scope })).effective).toEqual({
      scope_pattern: pattern, required_streak: 4, posterior_guard: 0.5, snooze_backoff_seconds: [0, 0] });
    expect(await owner.call("vault.consent.graduation.stats", { scope })).toMatchObject({ untouched_streak: 0, amended: 1, rejected: 1, state: "propose" });
    expect(skills08ActiveGrantsFor(await owner.call("vault.consent.registry", { limit: 100 }), agentRef)).toEqual([]);

    // The streak floor alone does not waive the posterior guard after two corrections.
    for (let i = 1; i <= 3; i++) {
      const stats = await owner.call("vault.consent.graduation.outcome", { scope, outcome: "approved_untouched" });
      expect(stats.untouched_streak).toBe(i);
      expect(stats.state).toBe("propose");
      expect(skills08Offers(await owner.call("vault.consent.graduation.offers", {}), agentRef)).toEqual([]);
    }
    // Extend the fixture's four clean outcomes by three; keep the guard at 0.5 and streak floor at four.
    const fourth = await owner.call("vault.consent.graduation.outcome", { scope, outcome: "approved_untouched" });
    expect(fourth).toMatchObject({ untouched_streak: 4, amended: 1, rejected: 1, state: "propose" });
    expect(skills08Offers(await owner.call("vault.consent.graduation.offers", {}), agentRef)).toEqual([]);
    for (let i = 5; i <= 6; i++) {
      const stats = await owner.call("vault.consent.graduation.outcome", { scope, outcome: "approved_untouched" });
      expect(stats).toMatchObject({ untouched_streak: i, state: "propose" });
      expect(skills08Offers(await owner.call("vault.consent.graduation.offers", {}), agentRef)).toEqual([]);
    }
    const earned = await owner.call("vault.consent.graduation.outcome", { scope, outcome: "approved_untouched" });
    expect(earned).toMatchObject({ untouched_streak: 7, amended: 1, rejected: 1, state: "offered" });
    const offers = skills08Offers(await owner.call("vault.consent.graduation.offers", {}), agentRef);
    expect(offers).toHaveLength(1);
    const offer = offers[0]!;
    expect(offer.scope).toEqual(scope);
    expect(offer.stats).toMatchObject({ untouched_streak: 7, amended: 1, rejected: 1, state: "offered" });
    expect(offer.threshold).toEqual({ scope_pattern: pattern, required_streak: 4,
      posterior_guard: 0.5, snooze_backoff_seconds: [0, 0] });
    expect(offer.reach.line).toEqual(expect.any(String));
    expect(offer.reach.line.length).toBeGreaterThan(0);
    // Reading twice still shows exactly one offer; reading grants nothing (R2/R6).
    expect(skills08Offers(await owner.call("vault.consent.graduation.offers", {}), agentRef)).toHaveLength(1);
    const trust = skills08TrustRow(await owner.call("vault.consent.graduation.trust_table", {}), agentRef);
    if (!trust) throw new Error("Missing trust row for earned scope");
    expect(trust.stats.state).toBe("offered");
    expect(trust.offer_is_earned).toBe(true);
    expect(trust.grant_ref ?? null).toBeNull();
    expect(skills08ActiveGrantsFor(await owner.call("vault.consent.registry", { limit: 100 }), agentRef)).toEqual([]);
    // The agent's own answer attempt is refused and grants nothing.
    await skills08HttpRefusal(engine, agent.client, "vault.consent.graduation.answer", { scope, answer: "auto" }, 403, "FORBIDDEN", agentRef, "agent");
    expect(skills08ActiveGrantsFor(await owner.call("vault.consent.registry", { limit: 100 }), agentRef)).toEqual([]);

    // Decline: streak resets; no immediate repeat even with zero backoff.
    const declined = await owner.call("vault.consent.graduation.answer", { scope, answer: "not-now" });
    expect(declined.answer).toBe("not-now");
    expect(declined.grant ?? null).toBeNull();
    expect(declined.snooze).toMatchObject({ state: "snoozed", count: 1 });
    expect(await owner.call("vault.consent.graduation.stats", { scope })).toMatchObject({ untouched_streak: 0, amended: 1, rejected: 1, state: "propose" });
    expect(skills08Offers(await owner.call("vault.consent.graduation.offers", {}), agentRef)).toEqual([]);
    let repeatDecline: unknown;
    try { await owner.call("vault.consent.graduation.answer", { scope, answer: "not-now" }); } catch (error) { repeatDecline = error; }
    if (!(repeatDecline instanceof PublicHttpError)) throw new Error("Expected 400 for repeat decline with no standing offer");
    expect(repeatDecline.reply.status).toBe(400);
    expect(repeatDecline.error?.code).toBe("BAD_REQUEST");
    expect(repeatDecline.error?.message).toBe("invalid consent bound: no graduation offer is standing for this scope");
    const repeatDeclineReceiptRef = repeatDecline.error?.receiptRef;
    expect(typeof repeatDeclineReceiptRef).toBe("string");
    if (typeof repeatDeclineReceiptRef !== "string") throw new Error("Repeat decline refusal omitted receiptRef");
    expect(repeatDecline.reply.headers.get("x-oneiron-receipt-ref")).toBe(repeatDeclineReceiptRef);
    const repeatDeclineReceipt = await awaitPublic(
      () => owner.call("vault.receipts.get", { receipt_ref: repeatDeclineReceiptRef }),
      value => value !== null, { label: "skills08 repeat-decline refusal receipt" });
    expect(repeatDeclineReceipt?.receipt_ref).toBe(repeatDeclineReceiptRef);
    expect(repeatDeclineReceipt?.actor_ref).toBe(engine.pairedActor.principalRef);
    expect(repeatDeclineReceipt?.verb.endsWith("vault.consent.graduation.answer")).toBe(true);
    expect(repeatDeclineReceipt?.outcome).toEqual({ refused: { code: "BAD_REQUEST" } });

    // Re-earn seven clean outcomes, extending the fixture's four-entry evidence; owner accepts once.
    for (let i = 1; i <= 6; i++) {
      const stats = await owner.call("vault.consent.graduation.outcome", { scope, outcome: "approved_untouched" });
      expect(stats.untouched_streak).toBe(i);
      expect(skills08Offers(await owner.call("vault.consent.graduation.offers", {}), agentRef)).toEqual([]);
    }
    const reEarned = await owner.call("vault.consent.graduation.outcome", { scope, outcome: "approved_untouched" });
    expect(reEarned).toMatchObject({ untouched_streak: 7, state: "offered" });
    expect(skills08Offers(await owner.call("vault.consent.graduation.offers", {}), agentRef)).toHaveLength(1);
    const accepted = await owner.call("vault.consent.graduation.answer", { scope, answer: "auto" });
    expect(accepted.answer).toBe("auto");
    if (!accepted.grant) throw new Error("Missing standing-grant receipt on accept");
    expect(accepted.grant.outcome).toBe("approved");
    expect(accepted.grant.reason_code).toBe("gate.consent.standing_created");
    expect(accepted.grant.grant_ref).toEqual(expect.stringMatching(/^[a-f0-9]{64}$/));
    const grantRef = accepted.grant.grant_ref!;
    const granted = skills08TrustRow(await owner.call("vault.consent.graduation.trust_table", {}), agentRef);
    expect(granted?.stats.state).toBe("auto");
    expect(granted?.grant_ref).toBe(grantRef);
    const rows = skills08ActiveGrantsFor(await owner.call("vault.consent.registry", { limit: 100 }), agentRef);
    expect(rows).toHaveLength(1);
    expect(rows[0]!).toMatchObject({ grant_ref: grantRef, domain: "action", subject: agentRef,
      class: "send_email", selectors: ["client_followup"], status: "active" });
    expect(skills08Offers(await owner.call("vault.consent.graduation.offers", {}), agentRef)).toEqual([]);

    // Grant survives restart with no duplicate offer.
    await engine.restart();
    expect(skills08TrustRow(await owner.call("vault.consent.graduation.trust_table", {}), agentRef)?.grant_ref).toBe(grantRef);
    expect(skills08ActiveGrantsFor(await owner.call("vault.consent.registry", { limit: 100 }), agentRef)).toHaveLength(1);
    expect(skills08Offers(await owner.call("vault.consent.graduation.offers", {}), agentRef)).toEqual([]);

    // Receipted demotion: scope back to propose, history kept, grant revoked.
    expect(await owner.call("vault.consent.graduation.demote", { scope, reason: "amended" })).toEqual({ changed: true });
    expect(await owner.call("vault.consent.graduation.stats", { scope })).toMatchObject({ untouched_streak: 0, amended: 1, rejected: 1, state: "propose" });
    expect(skills08TrustRow(await owner.call("vault.consent.graduation.trust_table", {}), agentRef)?.grant_ref ?? null).toBeNull();
    expect(skills08ActiveGrantsFor(await owner.call("vault.consent.registry", { limit: 100 }), agentRef)).toEqual([]);
    const revoked = (await owner.call("vault.consent.registry", { limit: 100, include_revoked: true })).rows
      .find(row => row.grant_ref === grantRef);
    expect(revoked?.status).toBe("revoked");
    const demotions = (await owner.call("vault.receipts", { limit: 1000, kinds: ["gate"] })).receipts
      .filter(row => row.receipt_ref.startsWith("ramp_demotion:"));
    const demotion = demotions.find(row => row.fields?.["grant_ref"] === grantRef);
    if (!demotion) throw new Error("Missing ramp demotion receipt for revoked grant");
    expect(demotion.outcome).toBe("demoted");
    expect(demotion.fields).toMatchObject({ op_kind: "send_email", target_class: "client_followup",
      actor: agentRef, demotion_reason: "amended", grant_ref: grantRef });

    // Owner reverses the demotion by re-earning and accepting again.
    for (let i = 0; i < 7; i++) await owner.call("vault.consent.graduation.outcome", { scope, outcome: "approved_untouched" });
    const reversed = await owner.call("vault.consent.graduation.answer", { scope, answer: "auto" });
    expect(reversed.grant?.grant_ref).toEqual(expect.stringMatching(/^[a-f0-9]{64}$/));
    expect(skills08ActiveGrantsFor(await owner.call("vault.consent.registry", { limit: 100 }), agentRef)).toHaveLength(1);
  } finally {
    await engine.close();
  }
});
