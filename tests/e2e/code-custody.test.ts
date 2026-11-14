import { afterAll, test } from "bun:test";
import type { FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { defineFile, expect, runProcess } from "./support/run.ts";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { blake3 } from "@noble/hashes/blake3";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { PublicHttpClient, PublicHttpError, credentialParts } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 2 });
afterAll(suite.flush);

/*
 * Code execution and custody, in plan order. Complete-flow TODOs: no passing
 * substitute for an unavailable setup or mutation door. suite.todo registers
 * Bun test.todo and the shared runner's mandatory BLOCKED report row.
 *
 * Written cases are partial subsets (Engine ruling E2E-PARTIAL = A, E2E rules v2):
 * each test name states exactly the promise it proves, and the comment above it
 * names what of the planned title stays unproved and the public door that is
 * missing. Unwritten cases stay suite.todo (BLOCKED) with the real missing door.
 *
 * Binding read: main cf8d4ce473ddffb6bf278f11263ae0cf84461117, this worktree's
 * HEAD and origin/main. code-custody-scenarios pins the catalog, generated SDKs,
 * OpenAPI assembly, CLI, Git/LFS routes, canon and registry bytes read here.
 * The shared harness's older binding pin is left alone.
 *
 * Types below are CANON DESIGN NOTES, not new SDK methods or proposed URLs.
 * PublicCall refers only to EXISTING generated HTTP/SDK DTOs. Canon specifies
 * semantics but does not pin wire spellings for the missing operations. G01
 * requires their typed HTTP and SDK calls before activation. Do not cast verbs,
 * use execute_code, structural.put, kv.put, batch or Rust/private vault seeding
 * to manufacture repo, lease, queue, cache, publication or conflict records.
 * /api/lease/revoke revokes a device binding, not a checkout lease.
 *
 * Activation uses EngineFixture.start({ id, profile }) for a fresh authenticated
 * vault per ID and loadFixtures() for this fragment. A second account/vault in
 * 06/07 uses peers: 1 and explicit public policy; it gains no automatic grants.
 * Every generated reference comes from public setup; fixture labels are not
 * entity ids. Use the fixture's real paired HTTP/CLI clients, awaitReceipt and
 * owned runProcess/ManagedProcess for Linux git/node clients. All helpers and
 * servers share this file's two slots. Do not build/install/download in a flow.
 *
 * Observe wall-clock lease expiry via public state, receipts and bounded
 * observation, never a private clock/tick or fixed sleep. Zero automatic
 * mutation retries; case 02 covers expiry and stale-publication refusals only.
 * Any future kill() must follow a full public publication ACK, never a log message.
 * Credentials go through private env/stdin; a git transport needs a holder proof
 * for EACH request, not one static extraHeader reused across an exchange.
 * No upstream value belongs in checkout files, remotes, git config or argv.
 *
 * Independent fixtures retain all eight names, steps and expected facts, a tiny
 * source tree and real contract-check command, and a >16 MiB byte/digest recipe.
 * Recipes are data, not fabricated server records. The shared manifest loader
 * checks these files even while the full flows remain blocked. No helper is
 * added to stand in for a missing production door.
 */
type Ref = string;
type Sha256 = string;
type PublicCall<V extends FacadeVerb> = {
  request: FacadeInput<V>;
  result: FacadeResult<V>;
};
type VersionedFile = {
  document: Ref;
  version: Ref;
  path: string;
  text_sha256: Sha256;
};
type TestedTree = {
  revision: Ref;
  parent: Ref | null;
  file_frontiers: VersionedFile[];
  provenance_receipt: Ref;
};
type LeaseEpoch = { checkout: Ref; holder: Ref; epoch: number };
type ActionDigest = { hash: Sha256; size_bytes: number };

// CODE-CUSTODY-01 — Repository scope and pointer ingest should work.
type CodeCustody01ScenarioData = {
  patches: Record<string, { path: string; before: string; after: string }>;
  tests: { id: string; inputs: { disk_change: string }; facts: {
    pinned_file: string; pinned_text_sha256: string; call_neighbor: string;
  } }[];
};

async function codeCustody01Refused<V extends FacadeVerb>(
  engine: EngineFixture, client: PublicHttpClient, actorRef: string,
  verb: V, input: FacadeInput<V>,
): Promise<string> {
  try {
    await client.call(verb, input);
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    expect(error.reply.status).toBe(403);
    expect(error.error?.code).toBe("FORBIDDEN");
    const receiptRef = error.error?.receiptRef;
    if (typeof receiptRef !== "string") throw new Error("Owner-only refusal omitted its call receipt");
    expect(receiptRef).toMatch(/^call:[a-f0-9]{32}$/);
    expect(error.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
    const receipt = await engine.client.call("vault.receipts.get", { receipt_ref: receiptRef });
    if (!receipt) throw new Error("Owner cannot read the non-owner refusal receipt");
    expect(receipt.actor_ref).toBe(actorRef);
    expect(receipt.actor_class).toBe("agent");
    expect(receipt.verb).toBe(verb);
    expect(receipt.outcome).toEqual({ refused: { code: "FORBIDDEN" } });
    expect(receipt.served).toEqual([]);
    return receiptRef;
  }
  throw new Error(`Non-owner agent unexpectedly entered ${verb}`);
}

function codeCustody01CallCitation(
  view: FacadeResult<"vault.code.symbols.neighbors">, repo: string,
  snapshot: string, mathBlake3: string, callee: string,
): void {
  expect(view.repo).toBe(repo);
  expect(view.snapshot).toBe(snapshot);
  expect(view.seed.definition.name).toBe("increment");
  expect(view.seed.definition.path).toBe("math.cjs");
  expect(view.seed.definition.start_line).toBe(10);
  expect(view.seed.definition.end_line).toBe(12);
  expect(view.seed.content_hash_blake3).toBe(mathBlake3);
  const call = view.neighbors.find(row => row.kind === "calls"
    && row.source.definition.symbol === view.seed.definition.symbol
    && row.target.definition.name === callee);
  if (!call) throw new Error("Pinned increment citation omitted its call to add");
  expect(call.source).toEqual(view.seed);
  expect(call.target.definition.path).toBe("math.cjs");
  expect(call.target.definition.start_line).toBe(3);
  expect(call.target.definition.end_line).toBe(8);
  expect(call.target.content_hash_blake3).toBe(mathBlake3);
}

/*
 * Promise: Captured repository source and call citations stay pinned after disk edits and restart, and non-owner agents are refused.
 * Doors: snapshots.capture -> snapshots.get/read; symbols.definitions/neighbors; agents.create/get; self.actor; receipts.get; restart.
 * Unproved: committed-pointer registration/whitelist and grant-backed repo-member reads, cross-file exported-symbol refs and revocation; this is owner-only current-folder capture, not committed ingest.
 */
suite.test(test, "CODE-CUSTODY-01", "Captured repository source and call citations stay pinned after disk edits and restart, and non-owner agents are refused", async () => {
  const fixtures = await loadFixtures();
  const data = await fixtures.readJson<CodeCustody01ScenarioData>("code-custody-scenarios");
  const scenario = data.tests.find(row => row.id === "CODE-CUSTODY-01");
  if (!scenario) throw new Error("Missing CODE-CUSTODY-01 fixture scenario");
  const patch = data.patches[scenario.inputs.disk_change];
  if (!patch) throw new Error("Missing authored dirty-disk patch");
  const engine = await EngineFixture.start({ id: "CODE-CUSTODY-01", profile });
  try {
    const sourceRoot = resolve(engine.root, "code-custody-01-source");
    await mkdir(sourceRoot, { mode: 0o700 });
    for (const [asset, path] of [
      ["code-custody-math-cjs", "math.cjs"],
      ["code-custody-label-cjs", "label.cjs"],
      ["code-custody-main-cjs", "main.cjs"],
    ] as const) {
      await writeFile(resolve(sourceRoot, path), await fixtures.readArchive(asset), { mode: 0o600 });
    }
    const mathBytes = await fixtures.readArchive("code-custody-math-cjs");
    const mathText = new TextDecoder().decode(mathBytes);
    const mathSha256 = createHash("sha256").update(mathBytes).digest("hex");
    const mathBlake3 = Buffer.from(blake3(mathBytes)).toString("hex");
    expect(mathSha256).toBe(scenario.facts.pinned_text_sha256);
    expect(patch.path).toBe(scenario.facts.pinned_file);
    expect(mathText.split(patch.before)).toHaveLength(2);

    // An unregistered capture takes an index key, not an invented PROJECT id or membership grant.
    const captureInput: FacadeInput<"vault.code.snapshots.capture"> = {
      project_id: "CODE-CUSTODY-01", local_folder: sourceRoot,
    };
    const captured = await engine.client.call("vault.code.snapshots.capture", captureInput);
    const pinned: FacadeInput<"vault.code.snapshots.get"> = { repo: captured.repo, snapshot: captured.snapshot };
    const readInput: FacadeInput<"vault.code.snapshots.read"> = { ...pinned, path: scenario.facts.pinned_file };
    const manifest = await engine.client.call("vault.code.snapshots.get", pinned);
    if (!manifest) throw new Error("Captured snapshot is absent through the manifest door");
    expect(manifest.project_id).toBe(captureInput.project_id);
    expect(manifest.files.map(file => file.path).sort()).toEqual(["label.cjs", "main.cjs", "math.cjs"]);
    const frozen = await engine.client.call("vault.code.snapshots.read", readInput);
    if (!frozen) throw new Error("Captured math source is absent through the pinned-read door");
    expect(frozen.repo).toBe(pinned.repo);
    expect(frozen.snapshot).toBe(pinned.snapshot);
    expect(frozen.content).toBe(mathText);
    expect(frozen.text_sha256).toBe(scenario.facts.pinned_text_sha256);
    expect(frozen.file.path).toBe(scenario.facts.pinned_file);
    expect(frozen.file.content_hash_blake3).toBe(mathBlake3);
    expect(frozen.file.size_bytes).toBe(mathBytes.byteLength);
    expect(manifest.files.find(file => file.path === scenario.facts.pinned_file)).toEqual(frozen.file);
    const definitions = await engine.client.call("vault.code.symbols.definitions", { ...pinned, name: "increment" });
    const increment = definitions.definitions.find(row => row.path === "math.cjs" && row.kind === "function");
    if (!increment) throw new Error("Captured fixture has no increment function definition");
    const neighborInput: FacadeInput<"vault.code.symbols.neighbors"> = {
      ...pinned, symbol: increment.symbol, path: increment.path, kinds: ["calls"], direction: "out",
    };
    const calls = await engine.client.call("vault.code.symbols.neighbors", neighborInput);
    codeCustody01CallCitation(calls, pinned.repo, pinned.snapshot, mathBlake3, scenario.facts.call_neighbor);

    const agentRef = createHash("sha256").update("CODE-CUSTODY-01:excluded-agent").digest("hex").slice(0, 32);
    const agentInput: FacadeInput<"vault.agents.create"> = { agent_def_ref: agentRef, definition: {
      agent_id: "code-custody-01-excluded-agent", display_name: "Excluded repository agent",
      desc: "Non-owner caller for the captured-source access boundary", version: "1",
    } };
    await engine.client.call("vault.agents.create", agentInput);
    const storedAgent = await engine.client.call("vault.agents.get", { agent_def_ref: agentRef });
    expect(storedAgent.agent_def_ref).toBe(agentRef);
    expect(storedAgent.definition.agent_id).toBe(agentInput.definition.agent_id);
    const excluded = await engine.pairActor({ principalRef: agentRef, actorClass: "agent" });
    const identity = await excluded.client.call("self.actor", {});
    expect(identity.actor_ref).toBe(agentRef);
    expect(identity.actor_class).toBe("agent");
    const refusalRef = await codeCustody01Refused(engine, excluded.client, agentRef, "vault.code.snapshots.read", readInput);
    await codeCustody01Refused(engine, excluded.client, agentRef, "vault.code.symbols.neighbors", neighborInput);
    await codeCustody01Refused(engine, excluded.client, agentRef, "vault.code.snapshots.capture", captureInput);

    await writeFile(resolve(sourceRoot, patch.path), mathText.replace(patch.before, patch.after), { mode: 0o600 });
    expect(await engine.client.call("vault.code.snapshots.read", readInput)).toEqual(frozen);
    expect(await engine.client.call("vault.code.symbols.neighbors", neighborInput)).toEqual(calls);
    await engine.restart();
    expect(await engine.client.call("vault.code.snapshots.get", pinned)).toEqual(manifest);
    expect(await engine.client.call("vault.code.snapshots.read", readInput)).toEqual(frozen);
    const restoredCalls = await engine.client.call("vault.code.symbols.neighbors", neighborInput);
    codeCustody01CallCitation(restoredCalls, pinned.repo, pinned.snapshot, mathBlake3, scenario.facts.call_neighbor);
    expect(restoredCalls).toEqual(calls);
    const refusal = await engine.client.call("vault.receipts.get", { receipt_ref: refusalRef });
    expect(refusal?.actor_ref).toBe(agentRef);
    expect(refusal?.outcome).toEqual({ refused: { code: "FORBIDDEN" } });
    await codeCustody01Refused(engine, excluded.client, agentRef, "vault.code.snapshots.read", readInput);
  } finally {
    await engine.close();
  }
});

// CODE-CUSTODY-02 — Lease expiry prevents stale publication should work.
type CodeCustody02Fixture = { tests: { id: string; inputs: {
  holders: string[]; lease_ttl_seconds: number;
} }[] };

function codeCustody02InputId(label: string): string {
  return createHash("sha256").update(`CODE-CUSTODY-02:${label}`).digest("hex").slice(0, 32);
}

async function codeCustody02Lease(client: PublicHttpClient, checkout: string) {
  const result = await client.call("vault.code.checkout.get", { checkout });
  if (!result.value) throw new Error("Checkout is not readable through the independent get door");
  return result.value;
}

async function codeCustody02Refused<V extends FacadeVerb>(
  engine: EngineFixture, client: PublicHttpClient, actorRef: string,
  actorClass: "human" | "agent", verb: V, input: FacadeInput<V>, status: number, code: string,
): Promise<string> {
  try {
    await client.call(verb, input);
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    expect(error.reply.status).toBe(status);
    expect(error.error?.code).toBe(code);
    const receiptRef = error.error?.receiptRef;
    if (typeof receiptRef !== "string") throw new Error("Refusal omitted the public call receipt");
    expect(receiptRef).toMatch(/^call:[a-f0-9]{32}$/);
    expect(error.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
    const receipt = await engine.client.call("vault.receipts.get", { receipt_ref: receiptRef });
    if (!receipt) throw new Error("Refusal receipt cannot be read back by the owner");
    expect(receipt.actor_ref).toBe(actorRef);
    expect(receipt.actor_class).toBe(actorClass);
    expect(receipt.verb).toBe(verb);
    expect(receipt.outcome).toEqual({ refused: { code } });
    return receiptRef;
  }
  throw new Error(`Expected ${status} ${code} from ${verb}`);
}

/*
 * Promise: an expired checkout refuses publication, and its old holder stays fenced after an authorized owner reclaims a newer epoch and restarts.
 * Doors: repo.anchor.bind -> vault.get/neighbors; people.create -> vault.get; tasks.create -> vault.get; checkout.claim/reclaim -> checkout.get; refused publish -> receipts.get; restart.
 * Unproved: successful publication, consume-once settlement, Git-head promotion, effect takeover and teardown. The real local Git repository is registered but uncommitted; no commit witness is claimed.
 */
suite.test(test, "CODE-CUSTODY-02", "An expired checkout refuses publication and its old holder stays fenced after owner reclaim and restart", async () => {
  const fixtures = await loadFixtures();
  const scenarios = await fixtures.readJson<CodeCustody02Fixture>("code-custody-scenarios");
  const scenario = scenarios.tests.find(row => row.id === "CODE-CUSTODY-02");
  if (!scenario) throw new Error("Missing CODE-CUSTODY-02 fixture");
  const holderName = scenario.inputs.holders[0];
  if (!holderName) throw new Error("Missing authored first-holder label");
  const engine = await EngineFixture.start({ id: "CODE-CUSTODY-02", profile });
  try {
    const ownerRef = engine.pairedActor.principalRef;
    // The claim scope's default project id is a reserved value, not a stored PROJECT; find the seeded
    // root project through public reads (role project, no parents, its own claims scope).
    const mount: FacadeInput<"graph_fs.readdir">["mount"] = { ref: { kind: "live_head" } };
    let cursor: string | undefined = undefined;
    let rootProjectRef: string | undefined = undefined;
    do {
      const directory: FacadeResult<"graph_fs.readdir"> = await engine.client.call("graph_fs.readdir", {
        mount, path: "/entities", ...(cursor === undefined ? {} : { cursor }),
      });
      const refs = directory.entries.filter(entry => entry.kind === "directory").map(entry => entry.name);
      const rows = await engine.client.call("vault.hydrate", { refs });
      rootProjectRef = rows.value.find(row => {
        const body = row.body;
        return typeof body === "object" && body !== null
          && "role" in body && body.role === "project"
          && "parents" in body && Array.isArray(body.parents) && body.parents.length === 0
          && "claims_scope_ref" in body && body.claims_scope_ref === row.id_hex;
      })?.id_hex;
      cursor = directory.next_cursor ?? undefined;
    } while (rootProjectRef === undefined && cursor !== undefined);
    if (rootProjectRef === undefined) throw new Error("Fresh vault has no publicly readable root project");
    const project = await engine.client.call("vault.get", { entity_ref: rootProjectRef });
    if (!project.value) throw new Error("Discovered root project is not readable through vault.get");
    const sourceRoot = resolve(engine.root, "code-custody-02-source");
    await mkdir(sourceRoot, { mode: 0o700 });
    for (const [asset, path] of [
      ["code-custody-math-cjs", "math.cjs"], ["code-custody-label-cjs", "label.cjs"],
      ["code-custody-main-cjs", "main.cjs"],
    ] as const) await writeFile(resolve(sourceRoot, path), await fixtures.readArchive(asset), { mode: 0o600 });
    // Only initialize Git. No unsigned commit, made-up commit or private repository state.
    const initialized = await runProcess(["git", "init", "--quiet", "--template=", sourceRoot], {
      cwd: engine.root, env: engine.env, artifacts: engine.artifacts, label: "code-custody-02-git-init",
    });
    expect(initialized.exitCode).toBe(0);
    const bound = await engine.client.call("vault.repo.anchor.bind", {
      local_folder: sourceRoot, project: project.value.id_hex, editable: [],
    });
    const repo = bound.anchor.repo;
    const registered = await engine.client.call("vault.get", { entity_ref: repo });
    expect(registered.value?.kind).toBe("CODE_ARTIFACT");
    const projects = await engine.client.call("vault.neighbors", {
      entity_ref: repo, opts: { edge_kind: "belongs_to", limit: 100 },
    });
    const projectIds: string[] = [];
    for (const neighbor of projects.value) {
      const row = await engine.client.call("vault.get", { entity_ref: neighbor.short_id });
      if (row.value) projectIds.push(row.value.id_hex);
    }
    expect(projectIds).toContain(project.value.id_hex);

    const conversation = await engine.client.call("vault.conversations.create", { body: {} });
    expect((await engine.client.call("vault.get", { entity_ref: conversation.id })).value?.kind).toBe("CONVERSATION");
    const witness = await engine.client.call("vault.witness", {
      conversation_ref: conversation.id, occurred_at: conversation.learned_at,
      messages: [{ author: "user", message_type: "text", content: `The distinct checkout holder is ${holderName}.`, is_visible: true, order: 0 }],
    });
    const evidence = await engine.client.call("vault.get", { entity_ref: witness.turn_short_id });
    if (!evidence.value || evidence.value.kind !== "TURN") throw new Error("Holder identity evidence did not land");
    const person = await engine.client.call("vault.people.create", {
      identity: { name: holderName }, identity_evidence_refs: [evidence.value.id_hex], occurred_at: evidence.value.occurred_start,
    });
    const holderRef = person.person.id_hex;
    expect(holderRef).not.toBe(ownerRef);
    expect((await engine.client.call("vault.get", { entity_ref: holderRef })).value?.kind).toBe("PERSON");
    const holder = await engine.pairActor({ principalRef: holderRef, actorClass: "human" });
    expect((await holder.client.call("self.actor", {})).actor_ref).toBe(holderRef);
    const task = await engine.client.call("tasks.create", {
      spec: { title: "Checkout build with explicit expiry", description: "Deterministic checkout lease fencing", lane: "code-custody-02" },
      label: "code-custody-02-build", assignee: { peer: { actor_ref: holderRef } },
    });
    if (!task.effected || !task.task_ref) throw new Error("Owner task assignment did not create a TASK");
    expect((await engine.client.call("vault.get", { entity_ref: task.task_ref })).value?.kind).toBe("TASK");

    const agentRef = codeCustody02InputId("excluded-agent");
    await engine.client.call("vault.agents.create", { agent_def_ref: agentRef, definition: {
      agent_id: "code-custody-02-excluded-agent", desc: "Unassigned checkout caller", version: "1",
    } });
    expect((await engine.client.call("vault.agents.get", { agent_def_ref: agentRef })).agent_def_ref).toBe(agentRef);
    const excluded = await engine.pairActor({ principalRef: agentRef, actorClass: "agent" });
    const identity = await excluded.client.call("self.actor", {});
    expect(identity.actor_ref).toBe(agentRef);
    expect(identity.actor_class).toBe("agent");

    const checkout = codeCustody02InputId("checkout");
    const claimed = await holder.client.call("vault.code.checkout.claim", {
      checkout, repo, task: task.task_ref, task_class: "build",
      ttl_seconds: scenario.inputs.lease_ttl_seconds, declared_idempotent: true,
    });
    const initial = await codeCustody02Lease(holder.client, checkout);
    expect(initial.checkout).toBe(checkout);
    expect(initial.epoch).toBe(1);
    expect(initial.epoch).toBe(claimed.epoch);
    expect(initial.holder).toBe(holderRef);
    expect(initial.task).toBe(task.task_ref);
    expect(initial.ticket).toBe(`${checkout}.1`);
    expect(initial.state).toBe("active");
    const publishInput: FacadeInput<"vault.code.checkout.publish"> = {
      checkout, epoch: initial.epoch, observed_ref: initial.repo_ref, candidate: repo,
    };
    // This candidate is an actual publicly registered CODE artifact.
    // Expired publication checks candidate readability before rejecting the lease;
    // after reclaim, the stale-epoch fence rejects before candidate readability.
    await codeCustody02Refused(engine, excluded.client, agentRef, "agent", "vault.code.checkout.reclaim",
      { checkout, expired_epoch: initial.epoch }, 404, "NOT_FOUND");
    const expired = await awaitPublic(() => holder.client.call("vault.code.checkout.get", { checkout }),
      result => result.value?.expired === true, { label: "checkout lease expiry" });
    if (!expired.value) throw new Error("Expired holder lost its public checkout observation");
    expect(expired.value.epoch).toBe(initial.epoch);
    expect(expired.value.holder).toBe(holderRef);
    const expiryRefusal = await codeCustody02Refused(engine, holder.client, holderRef, "human",
      "vault.code.checkout.publish", publishInput, 409, "INVALID_STATE");
    expect((await codeCustody02Lease(holder.client, checkout)).state).toBe("active");

    const reclaimed = await engine.client.call("vault.code.checkout.reclaim", { checkout, expired_epoch: initial.epoch });
    const current = await codeCustody02Lease(engine.client, checkout);
    expect(current.epoch).toBeGreaterThan(initial.epoch);
    expect(current.epoch).toBe(reclaimed.epoch);
    expect(current.holder).toBe(ownerRef);
    expect(current.ticket).toBe(`${checkout}.${current.epoch}`);
    expect(current.state).toBe("active");
    await codeCustody02Refused(engine, holder.client, holderRef, "human", "vault.code.checkout.publish", publishInput, 409, "INVALID_STATE");
    expect((await codeCustody02Lease(engine.client, checkout)).epoch).toBe(current.epoch);
    await engine.restart();
    const restored = await codeCustody02Lease(engine.client, checkout);
    expect(restored.epoch).toBe(current.epoch);
    expect(restored.holder).toBe(ownerRef);
    expect(restored.state).toBe("active");
    expect(restored.ticket).toBe(current.ticket);
    const oldReceipt = await engine.client.call("vault.receipts.get", { receipt_ref: expiryRefusal });
    expect(oldReceipt?.actor_ref).toBe(holderRef);
    expect(oldReceipt?.outcome).toEqual({ refused: { code: "INVALID_STATE" } });
    await codeCustody02Refused(engine, holder.client, holderRef, "human", "vault.code.checkout.publish", publishInput, 409, "INVALID_STATE");
  } finally {
    await engine.close();
  }
});

// CODE-CUSTODY-03 — Symbol overlap schedules rather than drops should work.
/*
 * Promise: overlapping proposals wait without being dropped while independent work completes.
 * Available doors: symbol declare/renew/release and proposal/merge-queue verbs exist, but renewal mutates the lease and owner batches bypass run-order blockers.
 * Missing: a grant-controlled public symbol-lease read-back and proposal-to-declaration queue binding; renew is not an independent read door.
 */
suite.todo(test, "CODE-CUSTODY-03", "waits on a public symbol-lease observation verb and proposal-to-declaration queue binding behind a revocable repository grant");

// CODE-CUSTODY-04 — Merge queue isolates failed batch should work.
// Promise: one batch of good-math + bad-api + good-label is bisected on red,
// the valid subset lands under declared policy, the failed proposal stays
// retained with its checker evidence, repair re-greens, and prior failure
// evidence survives.
// Doors used: none yet (todo). Landed merge-queue verbs exist and are typed
// (proposal_submit, merge_queue init/enqueue/stage/check/check_status/
// observe/diagnose/requeue_survivors/land_reviewed/settle_slow/recover/
// export_green, review_policy get/set), but the flow cannot start: every
// proposal_submit needs a caller-supplied SESSION plus an active
// repo.provenance CLAIM, and no permitted direct code-attribution setup was
// found; repo.provenance is engine-reserved (see report, UNSURE survey).
// Unproved: everything (act, second-door read-back, wrong-actor refusal,
// restart). Reason: waits on typed code-proposal attribution behind the
// owner code grant (see CODE-CUSTODY-04.report.md).
suite.todo(test, "CODE-CUSTODY-04", "waits on typed code-proposal attribution (session + repo.provenance claim) behind the owner code grant");

// CODE-CUSTODY-05 — Git export and crash-safe origin publication should work.
// Promise: Git export and crash-safe origin publication should work (canon: commit a
// tested frontier, export via the real origin, clone with stock git smart-HTTP, push the
// next fixture change through the credential door, kill only after the per-ref
// receive-pack status plus public publication receipt, restart on the same build/vault,
// fresh clone keeps every acknowledged ref with provenance to tested file frontiers, and
// no upstream credential value in the owned checkout).
// Doors: none driven; the case stays todo. The export, queue-seal and project-mint doors
// exist; proposals have no publicly drivable attribution binding (see report).
// Unproved: everything. vault.code.export needs a queue-sealed CodeRevision, which needs
// proposals, which need SESSION + repo.provenance attribution minted only inside code-run
// dispatch. A push-only publication-durability subset would not keep the title's export
// promise (E2E-PARTIAL=A; lead steer).
suite.todo(test, "CODE-CUSTODY-05", "waits on a public proposal-attribution binding (SESSION + repo.provenance claim) behind the code write grant to reach the checked queue seal and export");

// CODE-CUSTODY-06 — LFS large blob fidelity and deletion should work.
type LfsObject = { oid: Sha256; size: number };
type LfsBatchResponse = {
  transfer: "basic";
  objects: (LfsObject & {
    authenticated: boolean;
    actions?: Partial<Record<"upload" | "download" | "verify", { href: string }>>;
    error?: { code: number; message: string };
  })[];
};
// (Reuses this file's canon LFS wire types LfsObject/LfsBatchResponse; no new wire DTOs.)
// (PublicHttpClient joins the clients.ts import union as a value: the transfer client below
//  constructs it. Case-local wrappers retain status/code/message/suggestion/body on unexpected refusals.)

const codeCustody06Occurred = 1769947200;
const codeCustody06Repo = "custody06";
// Nightly-tier: keep the authored >16 MiB fixture and every full-byte read-back.
// Job 5b expired at 30.005 s during the first read after a successful append.
// Nine full-size transfers retain 25 s request limits; the 5 min flow cap also
// covers two vault starts, one restart and the authority/erase control calls.
// This is a bounded allowance, not a measured completion time.
const codeCustody06TransferTimeoutMs = 25_000;
const codeCustody06FlowTimeoutMs = 300_000;

function codeCustody06Sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function codeCustody06Materialize(pattern: string, byteLength: number): Buffer {
  const piece = Buffer.from(pattern, "utf8");
  const out = Buffer.alloc(byteLength);
  let at = 0;
  while (at < byteLength) {
    const take = Math.min(piece.length, byteLength - at);
    piece.copy(out, at, 0, take);
    at += take;
  }
  return out;
}

function codeCustody06AgentId(): string {
  return createHash("sha256").update("code-custody-e2e:CODE-CUSTODY-06:agent").digest("hex").slice(0, 32);
}

function codeCustody06LfsPaths(repo: string, oid: string): { batch: string; object: string; verify: string } {
  return {
    batch: `/git/${repo}/info/lfs/objects/batch`,
    object: `/git/${repo}/info/lfs/objects/${oid}`,
    verify: `/git/${repo}/info/lfs/objects/${oid}/verify`,
  };
}

function codeCustody06SlipId(credential: string): number[] {
  const slipHex = credentialParts(credential).bearer.slice("v2.slip.".length);
  const slip = JSON.parse(Buffer.from(slipHex, "hex").toString("utf8")) as { claims?: { slip_id?: unknown } };
  const slipId = slip.claims?.slip_id;
  if (!Array.isArray(slipId) || slipId.length !== 32 || !slipId.every((n): n is number => typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= 255))
    throw new Error("Credential carries no 32-byte slip id");
  return slipId;
}

function codeCustody06ErrorBody(reply: { body: unknown; status?: number; headers?: Headers }): Record<string, unknown> {
  const body = reply.body as { error?: unknown };
  if (!body || typeof body !== "object" || !body.error || typeof body.error !== "object") {
    // Shape only (status, media type, top-level keys), never values.
    const shape = body && typeof body === "object" ? `keys=${JSON.stringify(Object.keys(body).sort())}` : `body_type=${typeof body}`;
    throw new Error(`Expected an error envelope; status=${reply.status ?? "<none>"} content_type=${reply.headers?.get("content-type") ?? "<none>"} ${shape}`);
  }
  return body.error as Record<string, unknown>;
}

// Use the same owner credential and doors. The client has no per-request timeout argument,
// and each artifact append lands a whole version, not an accumulated chunk.
function codeCustody06TransferClient(engine: EngineFixture): PublicHttpClient {
  return new PublicHttpClient(engine.url, {
    credential: engine.pairedActor.credential,
    artifacts: engine.artifacts,
    label: "CODE-CUSTODY-06:transfers",
    timeoutMs: codeCustody06TransferTimeoutMs,
  });
}

async function codeCustody06ExpectedSuccess<T>(context: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof PublicHttpError) {
      const wire = error.error;
      throw new Error(
        `CODE-CUSTODY-06 ${context}: status=${error.reply.status} code=${wire?.code ?? "unavailable"} message=${wire?.message ?? error.message} suggestion=${wire?.suggestions?.[0] ?? "<none>"} body=${error.reply.raw.slice(0, 500)}`,
        { cause: error },
      );
    }
    const code = error instanceof Error ? error.name : "unknown";
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`CODE-CUSTODY-06 ${context}: status=unavailable (no HTTP reply retained) code=${code} message=${message}`, { cause: error });
  }
}

async function codeCustody06Transfer<T>(context: string, run: () => Promise<T>): Promise<T> {
  return codeCustody06ExpectedSuccess(
    `${context}; request_timeout_ms=${codeCustody06TransferTimeoutMs}; flow_deadline_ms=${codeCustody06FlowTimeoutMs}`,
    run,
  );
}

// CODE-CUSTODY-06 — Large blob fidelity and scoped deletion should work.
// Promise: a >16 MiB blob round-trips byte-exact through two same-byte artifact owners and LFS basic batch/PUT/verify/download; erasing owner A keeps owner B and LFS bytes exact; a read-scoped actor is refused with receipts; a revoked capability slip's next use is refused; another vault discloses nothing.
// Doors: vault.artifacts.put/append/read, vault.records.erase_preview/confirm, vault.code.origin.register, vault.code.origin.mirror.get, vault.agents.create, self.actor, vault.get, vault.receipts.get, LFS batch/upload/download/verify routes, POST /v1/core/slips/revoke, engine.restart().
// Budget: nightly-tier, 300 s flow cap via suite.test; full-size requests remain capped at 25 s.
// Stays unproved: the mirror half (build-required asset publication, mirror clone/smudge with the original disconnected, mirror_check run): no public door classifies repo paths build-required and no HTTPS mirror fixture is provided (see report).
suite.test(test, "CODE-CUSTODY-06", "Large blob fidelity and scoped deletion should work", async () => {
  const fixtures = await loadFixtures();
  const recipe = await fixtures.readJson<{ pattern: string; byte_length: number; sha256: string }>("code-custody-large-blob");
  const facts = fixtures.expected<{ byte_length: number; sha256: string; above_16_mib: boolean; transfer: string }>("code-custody-large-blob");
  expect(facts.above_16_mib).toBe(true);
  expect(facts.transfer).toBe("basic");
  expect(recipe.byte_length).toBe(facts.byte_length);
  expect(recipe.sha256).toBe(facts.sha256);
  const bytes = codeCustody06Materialize(recipe.pattern, recipe.byte_length);
  const oid = facts.sha256;
  const size = facts.byte_length;
  expect(bytes.length).toBe(size);
  expect(codeCustody06Sha256(bytes)).toBe(oid);
  const engine = await EngineFixture.start({ id: "CODE-CUSTODY-06", profile, peers: 1 });
  try {
    const peer = engine.peers[0];
    if (!peer) throw new Error("Missing peer vault");
    const contentBase64 = bytes.toString("base64");
    const transfers = codeCustody06TransferClient(engine);
    const transferBytes = `bytes=${size} base64=${contentBase64.length}`;
    const putA = await engine.client.call("vault.artifacts.put", {
      name: "custody-06-owner-a", media_type: "application/octet-stream", occurred_at: codeCustody06Occurred,
    });
    const appendA = await codeCustody06Transfer(`owner A append vault.artifacts.append ${transferBytes}`, () =>
      transfers.call("vault.artifacts.append", {
        artifact_ref: putA.id_hex, content_base64: contentBase64, occurred_at: codeCustody06Occurred,
      }));
    if (!("landed" in appendA)) throw new Error("Owner A append did not land");
    expect(appendA.landed.version).toBe(1);
    const readA = await codeCustody06Transfer(`owner A read vault.artifacts.read ${transferBytes}`, () =>
      transfers.call("vault.artifacts.read", {
        artifact_ref: putA.id_hex, version: appendA.landed.version,
      }));
    if (readA === null) throw new Error("Owner A's pinned artifact version is absent");
    const bytesA = Buffer.from(readA.content_base64, "base64");
    expect(bytesA.length).toBe(size);
    expect(codeCustody06Sha256(bytesA)).toBe(oid);
    // Owner B's put queues behind owner A's 16 MiB landing (3.3 s and 3.6 s in two
    // runs on set bd95597c, over 10 s on a loaded host), so it takes the transfer budget.
    const putB = await codeCustody06Transfer("owner B put vault.artifacts.put", () =>
      transfers.call("vault.artifacts.put", {
        name: "custody-06-owner-b", media_type: "application/octet-stream", occurred_at: codeCustody06Occurred,
      }));
    const appendB = await codeCustody06Transfer(`owner B append vault.artifacts.append ${transferBytes}`, () =>
      transfers.call("vault.artifacts.append", {
        artifact_ref: putB.id_hex, content_base64: contentBase64, occurred_at: codeCustody06Occurred,
      }));
    if (!("landed" in appendB)) throw new Error("Owner B append did not land");
    expect(appendB.landed.version).toBe(1);
    const versionB = appendB.landed.version;
    // Register accepts a served name without .git and a short branch name.
    const registered = await codeCustody06ExpectedSuccess(`CODE-CUSTODY-06 owner register (FIX [ORIGIN-REGISTER-GIT-REF-FORMAT-UNSUPPORTED], fixed by #7052) vault.code.origin.register repo=${codeCustody06Repo} default_branch=main`, () =>
      engine.client.call("vault.code.origin.register", {
        repo: codeCustody06Repo, default_branch: "main",
      }));
    expect(registered.repo).toBe(codeCustody06Repo);
    expect(registered.default_branch).toBe("main");
    expect(registered.repo_id).toMatch(/^[a-f0-9]{32}$/);
    const mirrorView = await codeCustody06ExpectedSuccess("registration read-back vault.code.origin.mirror.get", () =>
      engine.client.call("vault.code.origin.mirror.get", { repo: codeCustody06Repo }));
    expect(mirrorView.repo).toBe(codeCustody06Repo);
    expect(mirrorView.mirror ?? null).toBeNull();
    const paths = codeCustody06LfsPaths(codeCustody06Repo, oid);
    const uploadBatch = await codeCustody06ExpectedSuccess(`LFS upload batch POST ${paths.batch}`, () =>
      engine.client.request<LfsBatchResponse>("POST", paths.batch, {
        operation: "upload", transfers: ["basic"], objects: [{ oid, size }],
      }));
    expect(uploadBatch.body.transfer).toBe("basic");
    const uploadEntry = uploadBatch.body.objects[0];
    if (!uploadEntry) throw new Error("Empty LFS upload batch answer");
    expect(uploadEntry.oid).toBe(oid);
    expect(uploadEntry.size).toBe(size);
    expect(uploadEntry.authenticated).toBe(true);
    expect(uploadEntry.error).toBeUndefined();
    const uploadHref = uploadEntry.actions?.upload?.href;
    const verifyHref = uploadEntry.actions?.verify?.href;
    if (!uploadHref || !verifyHref) throw new Error("LFS upload batch offered no actions");
    expect(uploadHref.endsWith(paths.object)).toBe(true);
    expect(verifyHref.endsWith(paths.verify)).toBe(true);
    const put = await codeCustody06Transfer(`LFS PUT ${paths.object} ${transferBytes}`, () =>
      transfers.request<LfsObject>("PUT", paths.object, bytes, {
        "content-type": "application/octet-stream",
      }));
    expect(put.body.oid).toBe(oid);
    expect(put.body.size).toBe(size);
    const verify = await codeCustody06ExpectedSuccess(`LFS verify POST ${paths.verify}`, () =>
      engine.client.request<{ oid: string; size: number; ok: boolean }>("POST", paths.verify, { oid, size }));
    expect(verify.body.oid).toBe(oid);
    expect(verify.body.size).toBe(size);
    expect(verify.body.ok).toBe(true);
    const downloadBatch = await codeCustody06ExpectedSuccess(`LFS download batch POST ${paths.batch}`, () =>
      engine.client.request<LfsBatchResponse>("POST", paths.batch, {
        operation: "download", transfers: ["basic"], objects: [{ oid, size }],
      }));
    const downloadEntry = downloadBatch.body.objects[0];
    if (!downloadEntry) throw new Error("Empty LFS download batch answer");
    expect(downloadEntry.error).toBeUndefined();
    const downloadHref = downloadEntry.actions?.download?.href;
    if (!downloadHref) throw new Error("LFS download batch offered no action");
    expect(downloadHref.endsWith(paths.object)).toBe(true);
    const download = await codeCustody06Transfer(`LFS GET ${paths.object} ${transferBytes}`, () =>
      transfers.request<unknown>("GET", paths.object));
    expect(download.bytes.length).toBe(size);
    expect(download.headers.get("content-length")).toBe(String(size));
    expect(download.headers.get("content-type")).toBe("application/octet-stream");
    expect(codeCustody06Sha256(download.bytes)).toBe(oid);
    const agentId = codeCustody06AgentId();
    const created = await codeCustody06ExpectedSuccess("create authority probe vault.agents.create", () =>
      engine.client.call("vault.agents.create", {
        agent_def_ref: agentId,
        definition: {
          agent_id: "custody-06-reader", display_name: "custody-06-reader",
          desc: "Custody case read-scoped agent", version: "1",
        },
      }));
    expect(created.agent_def_ref).toBe(agentId);
    const agentRow = await codeCustody06ExpectedSuccess("agent definition read-back vault.get", () =>
      engine.client.call("vault.get", { entity_ref: agentId }));
    if (!agentRow.value) throw new Error("Agent definition unreadable");
    expect(agentRow.value.kind).toBe("AGENT_DEF");
    expect(agentRow.value.id_hex).toBe(agentId);
    const full = await codeCustody06ExpectedSuccess("pair full-scope authority probe", () =>
      engine.pairActor({ principalRef: agentId, actorClass: "agent" }));
    const fullIdentity = await codeCustody06ExpectedSuccess("full-scope credential read-back self.actor", () =>
      full.client.call("self.actor", {}));
    expect(fullIdentity.actor_ref).toBe(agentId);
    expect(fullIdentity.actor_class).toBe("agent");
    const fullBatch = await codeCustody06ExpectedSuccess(`full-scope LFS download batch POST ${paths.batch}`, () =>
      full.client.request<LfsBatchResponse>("POST", paths.batch, {
        operation: "download", transfers: ["basic"], objects: [{ oid, size }],
      }));
    const fullEntry = fullBatch.body.objects[0];
    if (!fullEntry || !fullEntry.actions?.download?.href) throw new Error("Live grant reads no LFS action");
    const agent = await codeCustody06ExpectedSuccess("pair read-scoped authority probe", () =>
      engine.pairActor({ principalRef: agentId, actorClass: "agent", scope: ["core:read"] }));
    const identity = await codeCustody06ExpectedSuccess("read-scoped credential read-back self.actor", () =>
      agent.client.call("self.actor", {}));
    expect(identity.actor_ref).toBe(agentId);
    expect(identity.actor_class).toBe("agent");
    const refusedAppend = await agent.client.raw("POST", "/v1/core/facade/vault.artifacts.append", {
      artifact_ref: putA.id_hex,
      content_base64: Buffer.from("no", "utf8").toString("base64"),
      occurred_at: codeCustody06Occurred,
    });
    expect(refusedAppend.status).toBe(403);
    const refusedBody = codeCustody06ErrorBody(refusedAppend);
    expect(refusedBody.code).toBe("FORBIDDEN");
    expect(refusedBody.message).toBe("request does not have the required scope");
    const refusalReceipt = refusedBody.receiptRef;
    if (typeof refusalReceipt !== "string" || !refusalReceipt.startsWith("call:"))
      throw new Error("Scope refusal wrote no call receipt");
    const refusalRecord = await codeCustody06ExpectedSuccess("scope refusal receipt vault.receipts.get", () =>
      engine.client.call("vault.receipts.get", { receipt_ref: refusalReceipt }));
    if (!refusalRecord) throw new Error("Scope refusal receipt unreadable");
    expect(refusedAppend.headers.get("x-oneiron-receipt-ref")).toBe(refusalReceipt);
    expect(refusalRecord.verb).toBe("vault.artifacts.append");
    expect(refusalRecord.actor_ref).toBe(agentId);
    expect(refusalRecord.actor_class).toBe("agent");
    expect(refusalRecord.outcome).toEqual({ refused: { code: "FORBIDDEN" } });
    const refusedLfs = await agent.client.raw("POST", paths.batch, {
      operation: "upload", transfers: ["basic"], objects: [{ oid, size }],
    });
    expect(refusedLfs.status).toBe(403);
    const refusedLfsBody = codeCustody06ErrorBody(refusedLfs);
    expect(refusedLfsBody.code).toBe("FORBIDDEN");
    expect(refusedLfsBody.message).toBe("request does not have the required scope");
    expect("receiptRef" in refusedLfsBody).toBe(false);
    const refusedDetails = refusedLfsBody.details as Record<string, unknown> | undefined;
    expect(refusedDetails?.code).toBe("FORBIDDEN");
    expect(refusedDetails?.requiredScope).toBe("core:write");
    // The full-scope (still live) agent passes the Write grant, so the refusal comes from the owner-only door.
    const refusedRegister = await full.client.raw("POST", "/v1/core/facade/vault.code.origin.register", {
      repo: "custody06-guest", default_branch: "main",
    });
    expect(refusedRegister.status).toBe(403);
    const refusedRegisterBody = codeCustody06ErrorBody(refusedRegister);
    expect(refusedRegisterBody.code).toBe("FORBIDDEN");
    expect(refusedRegisterBody.message).toBe("vault.code.origin.register is the vault owner's");
    const registerReceipt = refusedRegisterBody.receiptRef;
    if (typeof registerReceipt !== "string" || !registerReceipt.startsWith("call:"))
      throw new Error("Owner-door refusal wrote no call receipt");
    const registerRecord = await codeCustody06ExpectedSuccess("owner-door refusal receipt vault.receipts.get", () =>
      engine.client.call("vault.receipts.get", { receipt_ref: registerReceipt }));
    if (!registerRecord) throw new Error("Owner-door refusal receipt unreadable");
    expect(refusedRegister.headers.get("x-oneiron-receipt-ref")).toBe(registerReceipt);
    expect(registerRecord.verb).toBe("vault.code.origin.register");
    expect(registerRecord.actor_ref).toBe(agentId);
    expect(registerRecord.actor_class).toBe("agent");
    expect(registerRecord.outcome).toEqual({ refused: { code: "FORBIDDEN" } });
    const revoked = await codeCustody06ExpectedSuccess("revoke full-scope slip POST /v1/core/slips/revoke", () =>
      engine.client.request<{ revoked: boolean }>("POST", "/v1/core/slips/revoke", {
        slip_id: codeCustody06SlipId(full.credential),
      }));
    expect(revoked.body.revoked).toBe(true);
    const deadPut = await full.client.raw("POST", "/v1/core/facade/vault.artifacts.put", {
      name: "custody-06-after-revoke", media_type: "application/octet-stream", occurred_at: codeCustody06Occurred,
    });
    expect(deadPut.status).toBe(401);
    const deadPutBody = codeCustody06ErrorBody(deadPut);
    expect(deadPutBody.code).toBe("UNAUTHORIZED");
    expect("receiptRef" in deadPutBody).toBe(false);
    const deadSelf = await full.client.raw("POST", "/v1/core/facade/self.actor", {});
    expect(deadSelf.status).toBe(401);
    expect(codeCustody06ErrorBody(deadSelf).code).toBe("UNAUTHORIZED");
    const deadLfs = await full.client.raw("POST", paths.batch, {
      operation: "download", transfers: ["basic"], objects: [{ oid, size }],
    });
    expect(deadLfs.status).toBe(401);
    // FIX [GIT-LFS-PREHANDLER-REFUSAL-BARE-BODY], fixed by #7201: the binding
    // door envelopes its pre-route refusal on the LFS paths too.
    expect(codeCustody06ErrorBody(deadLfs).code).toBe("UNAUTHORIZED");
    const stillLive = await codeCustody06ExpectedSuccess("independent read-scoped slip self.actor", () =>
      agent.client.call("self.actor", {}));
    expect(stillLive.actor_ref).toBe(agentId);
    const peerBatch = await codeCustody06ExpectedSuccess(`peer LFS isolation batch POST ${paths.batch}`, () =>
      peer.client.request<LfsBatchResponse>("POST", paths.batch, {
        operation: "download", transfers: ["basic"], objects: [{ oid, size }],
      }));
    const peerEntry = peerBatch.body.objects[0];
    if (!peerEntry) throw new Error("Empty peer LFS batch answer");
    expect(peerEntry.actions).toBeUndefined();
    if (!peerEntry.error) throw new Error("Peer vault disclosed foreign bytes");
    expect(peerEntry.error.code).toBe(404);
    expect(peerEntry.error.message).toBe("object is not stored in this vault");
    const preview = await codeCustody06ExpectedSuccess("owner A erase preview vault.records.erase_preview", () =>
      engine.client.call("vault.records.erase_preview", { record: putA.id_hex }));
    expect(preview.record).toBe(putA.id_hex);
    expect(preview.lfs_chunks).toEqual([]);
    expect(preview.same_bytes).toContain(putB.id_hex);
    const held = preview.held_bytes.find((row) => row.other_holders.includes(putB.id_hex));
    if (!held) throw new Error("Erase preview names no surviving holder");
    expect(held.content_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(preview.preview_digest).toMatch(/^[a-f0-9]{64}$/);
    const confirmed = await codeCustody06ExpectedSuccess("owner A erase vault.records.erase_confirm", () =>
      engine.client.call("vault.records.erase_confirm", {
        record: putA.id_hex, preview_digest: preview.preview_digest, also_same_bytes: false,
      }));
    if (!("first" in confirmed)) throw new Error("Erase confirm did not settle");
    expect(confirmed.first.existed).toBe(true);
    expect(confirmed.same_bytes).toEqual([]);
    const eraseReceipt = confirmed.first.receipt_ref;
    if (typeof eraseReceipt !== "string" || eraseReceipt.length === 0) throw new Error("Erase wrote no receipt");
    const goneA = await engine.client.raw("POST", "/v1/core/facade/vault.artifacts.read", {
      artifact_ref: putA.id_hex, version: 1,
    });
    expect(goneA.status).toBe(404);
    expect(codeCustody06ErrorBody(goneA).code).toBe("NOT_FOUND");
    const readB = await codeCustody06Transfer(`owner B read vault.artifacts.read ${transferBytes}`, () =>
      transfers.call("vault.artifacts.read", { artifact_ref: putB.id_hex, version: versionB }));
    if (readB === null) throw new Error("Owner B's pinned artifact version is absent after erasing A");
    const bytesB = Buffer.from(readB.content_base64, "base64");
    expect(bytesB.length).toBe(size);
    expect(codeCustody06Sha256(bytesB)).toBe(oid);
    const downloadAfter = await codeCustody06Transfer(`LFS GET after erase ${paths.object} ${transferBytes}`, () =>
      transfers.request<unknown>("GET", paths.object));
    expect(downloadAfter.bytes.length).toBe(size);
    expect(codeCustody06Sha256(downloadAfter.bytes)).toBe(oid);
    await codeCustody06ExpectedSuccess("restart before durability read-backs", () => engine.restart());
    const goneAAfter = await engine.client.raw("POST", "/v1/core/facade/vault.artifacts.read", {
      artifact_ref: putA.id_hex, version: 1,
    });
    expect(goneAAfter.status).toBe(404);
    expect(codeCustody06ErrorBody(goneAAfter).code).toBe("NOT_FOUND");
    const readBAfter = await codeCustody06Transfer(`owner B read after restart vault.artifacts.read ${transferBytes}`, () =>
      transfers.call("vault.artifacts.read", { artifact_ref: putB.id_hex, version: versionB }));
    if (readBAfter === null) throw new Error("Owner B's pinned artifact version is absent after restart");
    expect(codeCustody06Sha256(Buffer.from(readBAfter.content_base64, "base64"))).toBe(oid);
    const downloadRestart = await codeCustody06Transfer(`LFS GET after restart ${paths.object} ${transferBytes}`, () =>
      transfers.request<unknown>("GET", paths.object));
    expect(downloadRestart.bytes.length).toBe(size);
    expect(codeCustody06Sha256(downloadRestart.bytes)).toBe(oid);
    await engine.artifacts.json("code-custody-06.json", {
      byteLength: size, sha256: oid, ownerA: putA.id_hex, ownerB: putB.id_hex, agent: agentId, repo: registered.repo_id,
    });
  } finally {
    await engine.close();
  }
}, codeCustody06FlowTimeoutMs);

// CODE-CUSTODY-07 — Working views and cache isolate authority should work.
/*
 * Promise: Working views and cache isolate authority.
 * Doors: the typed views/cache doors exist, but no scenario is driven.
 * Unproved: the full scenario needs a fleet checker fixture to produce a
 * finalized tested tree, plus a granted working-view edit door. See the report.
 */
suite.todo(test, "CODE-CUSTODY-07", "waits on a fleet checker binding for vault.code.views.materialize and a granted working-view edit door");

// CODE-CUSTODY-08 — TODO, not written.
// Promise: a real merge overlap becomes reviewable work: typed conflict plus
//   linked reconciliation task, both proposals retained, receipted resolution.
// Doors used: none; setup is not publicly constructible (see report).
// Stays unproved: everything; vault.code.proposal_submit needs an existing
//   SESSION and an active repo.provenance CLAIM, and no permitted direct
//   code-attribution setup was found; repo.provenance is reserved.
suite.todo(test, "CODE-CUSTODY-08", "waits on a public owner code-attribution verb behind the code-proposal grant to mint proposal_submit's SESSION and repo.provenance CLAIM");
