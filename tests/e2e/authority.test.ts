import { afterAll, expect, test } from "bun:test";
import { resolve } from "node:path";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { CliClient, PublicHttpClient, WsClient, credentialParts } from "./support/clients.ts";
import { loadFixtures, requireAsset } from "./support/fixtures.ts";
import { defineFile, LIMITS, ManagedProcess, ownResource, redactor, runProcess, secretHex } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

type AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type PythonPair = { ok: true; credential: string } | { ok: false; code: string | null };
type ReRootReport = {
  vault_id: string;
  retired_credentials: { slip_id: string; holder_ref: string; actor_class: string | null }[];
};

// The shared driver pairs only through JS. This uses the installed public Python
// package in its prepared Linux interpreter, with the link on private stdin.
const PYTHON_PAIR = String.raw`
import json, sys
from oneiron import Oneiron
request = json.load(sys.stdin)
try:
    paired = Oneiron.pair(request["link"])
    json.dump({"ok": True, "credential": paired["credential"]}, sys.stdout)
except Exception as error:
    json.dump({"ok": False, "code": getattr(error, "code", None)}, sys.stdout)
`;

async function pythonPair(engine: EngineFixture, link: string): Promise<PythonPair> {
  redactor.add(link);
  const result = await runProcess([requireAsset(engine.build, "python"), "-c", PYTHON_PAIR], {
    cwd: engine.root, env: engine.env, input: JSON.stringify({ link }),
    label: "authority-python-pair", privateOutput: true,
  });
  // Never give an assertion the raw process output or a credential.
  expect(result.exitCode).toBe(0);
  const paired = JSON.parse(result.stdout) as PythonPair;
  if (paired.ok) credentialParts(paired.credential);
  return paired;
}

async function auditRows(client: PublicHttpClient): Promise<AuditRow[]> {
  const rows: AuditRow[] = [];
  let after: string | undefined;
  const cursors = new Set<string>();
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = { limit: 500, ...(after ? { after } : {}) };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    // These fixtures never adopt an externally attested checkpoint image.
    expect(page.cold_attested ?? []).toHaveLength(0);
    if (!page.next_after) return rows;
    expect(cursors.has(page.next_after)).toBe(false);
    cursors.add(page.next_after);
    after = page.next_after;
  }
}

function mintedSlip(before: readonly AuditRow[], after: readonly AuditRow[], holder: string): AuditRow {
  const existing = new Set(before.map(row => row.entry_hash));
  const minted = after.filter(row => !existing.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === holder);
  expect(minted).toHaveLength(1);
  const row = minted[0]!;
  expect(row.fold_valid).toBe(true);
  expect(row.subject_ref).toMatch(/^[a-f0-9]{64}$/);
  return row;
}

async function refusedUpgrade(url: string, credential: string): Promise<void> {
  // Send a real upgrade handshake and inspect its HTTP refusal before any
  // socket exists. A DNS error, timeout or protocol error must not count as
  // denial. The live-credential control below also opens an actual socket.
  const reply = await new PublicHttpClient(url, { credential }).raw("GET", "/ws", undefined, {
    connection: "Upgrade", upgrade: "websocket", "sec-websocket-version": "13",
    "sec-websocket-key": Buffer.from(secretHex(16), "hex").toString("base64"),
  });
  expect(reply.status).toBe(401);
}

// EngineFixture.restart deliberately keeps its issuer and credential. This
// file-local orchestration instead runs the shipped stopped-vault command and
// hands that same vault to a fresh serve process with an independent host key.
// Only one server runs at a time, matching this file's one scheduled slot.
async function handoffHost(engine: EngineFixture): Promise<{
  client: PublicHttpClient; credential: string; report: ReRootReport;
}> {
  const config = resolve(engine.root, "oneiron.toml");
  const nextSecret = secretHex();
  redactor.add(nextSecret);
  // Observe a public response before stopping the owned source process.
  await engine.client.call("vault.receipts", { limit: 1 });
  await engine.kill();
  const transitionCli = new CliClient(requireAsset(engine.build, "cli"), engine.root,
    { ...engine.env, ONEIRON_NEW_AUTH_SECRET: nextSecret }, engine.artifacts);
  const moved = await transitionCli.run(["host", "re-root", "--config", config],
    undefined, LIMITS.requestMs, true);
  expect(moved.exitCode).toBe(0);
  const report = JSON.parse(moved.stdout) as ReRootReport;

  const nextEnv = { ...engine.env, ONEIRON_AUTH_SECRET: nextSecret };
  const destinationCli = new CliClient(requireAsset(engine.build, "cli"), engine.root, nextEnv, engine.artifacts);
  const bootstrap = await destinationCli.run(["token", "bootstrap", "--config", config, "--url", engine.url],
    undefined, LIMITS.requestMs, true);
  expect(bootstrap.exitCode).toBe(0);
  const link = bootstrap.stdout.trim();
  redactor.add(link);
  const destination = await ManagedProcess.start([requireAsset(engine.build, "server"), "serve", "--config", config], {
    cwd: engine.root, env: nextEnv, label: "authority-destination-host", artifacts: engine.artifacts,
  });
  ownResource(() => destination.stop());
  const health = new PublicHttpClient(engine.url, { timeoutMs: 1000 });
  await awaitPublic(async () => {
    if (!destination.running) throw new Error("Destination host exited before readiness");
    return health.raw("GET", "/api/health");
  }, reply => destination.running && reply.status === 200,
  { label: "re-root destination health", timeoutMs: LIMITS.readyMs, readiness: true });
  const paired = await engine.sdk.pair(link);
  return {
    client: new PublicHttpClient(engine.url, { credential: paired.credential, artifacts: engine.artifacts }),
    credential: paired.credential, report,
  };
}

// AUTHORITY-01 — Vault-bound slip and request proof should work.
// OF-176/452/454/168; identity#authority-log and ARCH-0043#guest-grants.
// Design: a paired credential carries a vault-bound slip and a holder seed;
// HTTP/WS admission spends {timestamp, nonce, signature}. Replay the exact
// proof, not another fresh boundHeaders() result. Check a wrong holder and
// a second vault, then an offline child narrowed by Scope meet (never a new
// owner-minted pairing standing in for attenuation). Scope has explicit
// {kind:"bottom"|"all"|"some", values?} axes and a sensitivity ceiling.
// Missing: neither shipped JS/Python SDK nor HTTP catalog exposes the
// holder's shrink-only credential attenuation/transfer call. Do not hand-roll
// slip signing, call Rust's CapabilitySlip.attenuate, or silently omit that leg.
suite.todo(test, "AUTHORITY-01", "waits on typed public holder credential attenuation and transfer");

// AUTHORITY-02 — Signed history determines live authority should work.
// OF-160/175/039/056/155/469; identity#authority-log.
// Design input: SAME-BUILD captured signed grant/revoke envelopes with vault_id,
// signer sequence, parent hashes, entry hash, advisory ts and signatures. Replay
// their original bytes in opposite orders (including a signer-created backdated
// grant), revoke the parent/child, replay the older grant, restart, then attempt
// the child's HTTP read and WS sync. Same bytes and observation inputs must
// produce the same denial; a plain synced roster assertion grants nothing.
// The audit DTO is not an envelope and contains no signature or signed payload.
// Missing: a typed signed-history capture/import door and a public same-vault
// sync fixture. EngineFixture.peers creates different vaults, not authorized
// replicas. The pinned one-slot schedule also cannot run simultaneous peers.
suite.todo(test, "AUTHORITY-02", "waits on typed signed authority history transfer and same-vault sync fixture");

// AUTHORITY-03 — Public authority history is append-only should work.
// OF-224/165/167; identity#authority-log.
// Available read: vault.authority.audit({after?, limit?, kinds?}) ->
// {rows:[{entry_ref,entry_hash,signer_key,cosigner_keys,seq,vault_ref,
//         source_op,fold_valid,issue_codes,...}], next_after, order, scanned}.
// Design: pair an owner and retain a foreign vault's credential; capture a real
// signed entry through a public signed-history export, corrupt its signature,
// then submit both a new forged entry and a replacement at the existing hash.
// Reload the audit/receipts and verify unchanged entry bytes, attribution and
// effective access. Invalid Ed25519/P-256 signatures confer no standing.
// Missing: the typed signed-envelope submission/export contract. Sending a
// made-up authority body through vault.batch/structural.put would only test a
// generic malformed write, not the signed append-only protocol (G01).
suite.todo(test, "AUTHORITY-03", "waits on typed public signed authority envelope export and submission");

// AUTHORITY-04 — Conflicting signed authority is not a grant should work.
// OF-166/291; identity#authority-log, including the host-root amendments.
// Design: isolated public-protocol signers author conflicting current ReRoot
// envelopes on the same source ancestry; deliver both through supported ingress.
// Read effective access over HTTP/WS and attempt the wider action. Never select
// the permissive fork, revive SetCeiling, or use the deleted device quorum.
// Existing diagnostics: vault.authority.handoff_alarms({}) ->
// [{signer,refused,handoffs,raised_at,acknowledged,seen}], and
// .acknowledge({signer}) -> that alarm. A retired signer refusal saves the alarm;
// owner acknowledgement, not a quorum revoke, clears its unacknowledged state.
// Missing: public isolated fixture signing and typed signed-history ingress;
// minting internal AUTHORITY_LOG records is not a fixture substitute.
suite.todo(test, "AUTHORITY-04", "waits on public conflicting root-handoff signers and typed authority ingress");

suite.test(test, "AUTHORITY-05", "Pairing and revoke should work", async () => {
  const engine = await EngineFixture.start({ id: "AUTHORITY-05", profile });
  const catalog = await loadFixtures();
  const facts = catalog.expected<{ lifetimeSeconds: number; unauthorizedCode: string }>("authority-pairing-law");
  const before = await auditRows(engine.client);
  const linkResult = await engine.cli.run([
    "token", "pair", "--url", engine.url,
    "--principal-ref", engine.pairedActor.principalRef, "--actor-class", "human",
    "--lifetime-secs", String(facts.lifetimeSeconds),
  ], undefined, LIMITS.requestMs, true);
  expect(linkResult.exitCode).toBe(0);
  const link = linkResult.stdout.trim();
  redactor.add(link);

  const paired = await pythonPair(engine, link);
  expect(paired.ok).toBe(true);
  if (!paired.ok) throw new Error("First Python redemption refused");
  const reused = await pythonPair(engine, link);
  expect(reused.ok).toBe(false);
  if (reused.ok) throw new Error("One-use link redeemed a second time");
  expect(reused.code).toBe(facts.unauthorizedCode);

  const client = new PublicHttpClient(engine.url, { credential: paired.credential, artifacts: engine.artifacts });
  expect(Array.isArray(await client.call("vault.receipts", { limit: 1 }))).toBe(true);
  const pythonRead = await engine.sdk.run("python", {
    mode: "remote", url: engine.url, credential: paired.credential,
  }, [{ verb: "receipts", limit: 1 }]);
  expect(pythonRead.results).toHaveLength(1);
  expect(pythonRead.results[0]?.ok).toBe(true);
  const socket = await WsClient.connect(engine.url, paired.credential);
  try { expect(Array.isArray((await socket.call("vault.receipts", { limit: 1 })).value)).toBe(true) }
  finally { socket.close() }

  const issued = mintedSlip(before, await auditRows(engine.client), engine.pairedActor.principalRef);
  const slipId = issued.subject_ref!;
  // pairing.rs: RevokeSlip {slip_id:[u8;32]} -> {revoked:bool}.
  // No static issuer secret or old device-lease ceremony is sent over HTTP.
  const revoked = await engine.client.request<{ revoked: boolean }>("POST", "/v1/core/slips/revoke", {
    slip_id: Array.from(Buffer.from(slipId, "hex")),
  });
  expect(revoked.status).toBe(200);
  expect(revoked.body.revoked).toBe(true);
  const denied = await client.raw<{ error: { code: string } }>("POST", "/v1/core/facade/vault.receipts", { limit: 1 });
  expect(denied.status).toBe(401);
  expect(denied.body.error.code).toBe(facts.unauthorizedCode);
  await refusedUpgrade(engine.url, paired.credential);

  const deniedPython = await engine.sdk.run("python", {
    mode: "remote", url: engine.url, credential: paired.credential,
  }, [{ verb: "receipts", limit: 1 }]);
  expect(deniedPython.results[0]?.ok).toBe(false);
  const finalAudit = await auditRows(engine.client);
  expect(finalAudit.some(row => row.source_op === "slip_revoke"
    && row.subject_ref === slipId && row.fold_valid)).toBe(true);
  // Same principal, independent pairing: revoking the issued slip does not
  // revoke the original owner, nor confuse a dead server with an auth refusal.
  const control = await engine.websocket();
  try { expect(Array.isArray((await control.call("vault.receipts", { limit: 1 })).value)).toBe(true) }
  finally { control.close() }
});

// AUTHORITY-06 — Scope position and ceiling should work.
// OF-453/471; ARCH-0043#guest-grants and ARCH-0004#access.
// Design input: records at allowed/disallowed/bottom positions, an explicit
// grant ceiling and a narrower channel. Compare query, hydrate and export
// against the independent fixture's visible IDs. Position bottom passes every
// authorized ceiling; ceiling bottom grants nothing. An empty requested axis
// narrows nothing but cannot widen that ceiling. A position is never accepted
// in the credential-ceiling slot; channel scope meets rather than replaces it.
// Available: vault.recall({query,scope?:{world_ref?,facet?,kinds?}}),
// vault.hydrate({refs}) -> {value,narrowing}, and vault.export({format?,
// include_secrets?}) -> {format,archive,digest} (whole-vault owner export).
// Missing: typed position/ceiling public fixture setup and a channel-bound
// scoped export contract. The owner-only full archive is NOT a scoped export;
// RecallScope is NOT a grant ceiling. Do not cast one into the other.
suite.todo(test, "AUTHORITY-06", "waits on typed Scope position/ceiling setup and channel-bound scoped export");

// AUTHORITY-07 — Owner recovery stays vault-local should work.
// OF-169/173; identity#cloud-agent-recovery and #authority-log.
// Design: two independent genesis roots; sanctioned recovery material for A
// only. Restore A's signing ability through its recovery chain, read A, refuse
// the recovered credential on B, and audit a new in-chain epoch/key without a
// wider scope. No person-wide secret, second genesis, or device-quorum ceremony.
// Missing: the supported lost-owner host-authority recovery CLI/HTTP contract
// and its recovery-material fixture. World recovery-kit restore is for world
// encryption roots, not restoration of a lost host's slip-minting authority;
// host re-root below requires the CURRENT secret and cannot stand in for loss.
suite.todo(test, "AUTHORITY-07", "waits on public vault-local lost-owner authority recovery and sanctioned material");

suite.test(test, "AUTHORITY-08", "Same-build re-root handoff should work", async () => {
  const engine = await EngineFixture.start({ id: "AUTHORITY-08", profile });
  const catalog = await loadFixtures();
  const facts = catalog.expected<{ namespace: string[]; key: string; value: string; requestId: string }>("authority-host-note");
  const address = { namespace: facts.namespace, key: facts.key };
  const written = await engine.client.call("vault.kv.put", {
    ...address, value: facts.value, request_id: facts.requestId,
  });
  expect(written.item.value).toBe(facts.value);
  expect((await engine.client.call("vault.kv.get", address))?.value).toBe(facts.value);
  const before = await auditRows(engine.client);
  const genesis = before.filter(row => row.source_op === "genesis");
  expect(genesis).toHaveLength(1);
  expect(genesis[0]!.fold_valid).toBe(true);
  const ownerMints = before.filter(row => row.source_op === "slip_mint"
    && row.holder_ref === engine.pairedActor.principalRef);
  expect(ownerMints.length).toBeGreaterThan(0);
  const vaultId = ownerMints[0]!.vault_ref;
  expect(vaultId).toMatch(/^[a-f0-9]{64}$/);

  const destination = await handoffHost(engine);
  expect(destination.report.vault_id).toBe(vaultId);
  for (const mint of ownerMints) {
    expect(destination.report.retired_credentials.some(row => row.slip_id === mint.subject_ref)).toBe(true);
  }
  expect(destination.credential === engine.pairedActor.credential).toBe(false);
  expect((await destination.client.call("vault.kv.get", address))?.value).toBe(facts.value);
  const oldRead = await engine.client.raw<{ error: { code: string } }>("POST", "/v1/core/facade/vault.kv.get", address);
  expect(oldRead.status).toBe(401);
  expect(oldRead.body.error.code).toBe("UNAUTHORIZED");
  await refusedUpgrade(engine.url, engine.pairedActor.credential);
  const newSocket = await WsClient.connect(engine.url, destination.credential);
  try { expect((await newSocket.call("vault.kv.get", address)).value?.value).toBe(facts.value) }
  finally { newSocket.close() }

  const after = await auditRows(destination.client);
  const retainedGenesis = after.filter(row => row.source_op === "genesis");
  expect(retainedGenesis).toHaveLength(1);
  expect(retainedGenesis[0]!.entry_hash).toBe(genesis[0]!.entry_hash);
  const handoffs = after.filter(row => row.source_op === "re_root");
  expect(handoffs).toHaveLength(1);
  expect(handoffs[0]!.fold_valid).toBe(true);
  expect(handoffs[0]!.signer_key).toBe(genesis[0]!.signer_key);
  expect(handoffs[0]!.vault_ref).toBe(vaultId);
  const newMints = after.filter(row => row.source_op === "slip_mint"
    && row.holder_ref === engine.pairedActor.principalRef
    && !before.some(old => old.entry_hash === row.entry_hash));
  expect(newMints.length).toBeGreaterThan(0);
  for (const mint of newMints) {
    expect(mint.fold_valid).toBe(true);
    expect(mint.vault_ref).toBe(vaultId);
    expect(mint.signer_key === genesis[0]!.signer_key).toBe(false);
  }
  // Append-only lineage, not an old-format reader or a second Genesis.
  for (const row of before) {
    const retained = after.find(candidate => candidate.entry_ref === row.entry_ref);
    expect(retained?.entry_hash).toBe(row.entry_hash);
    expect(retained?.signer_key).toBe(row.signer_key);
    expect(retained?.seq).toBe(row.seq);
  }
});
