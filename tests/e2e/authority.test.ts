import { afterAll, expect, test } from "bun:test";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { resolve } from "node:path";
import { decode } from "@msgpack/msgpack";
import { blake3 } from "@noble/hashes/blake3";
import type { Facade, FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { CliClient, PublicHttpClient, WsClient, boundHeaders, credentialParts } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope, requireAsset } from "./support/fixtures.ts";
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

const upgradeHeaders = (): Record<string, string> => ({
  connection: "Upgrade", upgrade: "websocket", "sec-websocket-version": "13",
  "sec-websocket-key": Buffer.from(secretHex(16), "hex").toString("base64"),
});

async function refusedUpgrade(url: string, credential: string): Promise<void> {
  // Send a real upgrade handshake and inspect its HTTP refusal before any
  // socket exists. A DNS error, timeout or protocol error must not count as
  // denial. The live-credential control below also opens an actual socket.
  const reply = await new PublicHttpClient(url, { credential }).raw("GET", "/ws", undefined, upgradeHeaders());
  expect(reply.status).toBe(401);
}

type Refusal = { error: { code: string } };
const SLIP_PREFIX = "v2.slip.";
// PKCS#8 DER prefix of a raw 32-byte Ed25519 seed, as clients.ts signs with.
const ED25519_PKCS8_PREFIX = "302e020100300506032b657004220420";
const seedBytes = (seed: string): number[] => [...Buffer.from(seed, "hex")];

/** The public key of a holder seed: what a transfer names, never the seed. */
function holderPublicKey(seed: string): number[] {
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from(ED25519_PKCS8_PREFIX, "hex"), Buffer.from(seed, "hex")]),
    format: "der", type: "pkcs8",
  });
  const spki = createPublicKey(key).export({ format: "der", type: "spki" });
  return [...spki.subarray(spki.length - 32)];
}

/** The paired credential format: the returned slip beside the holder's own seed. */
function holderCredential(token: string, seed: string): string {
  expect(token.startsWith(SLIP_PREFIX)).toBe(true);
  const credential = `v2.cred.${token.slice(SLIP_PREFIX.length)}.${seed}`;
  credentialParts(credential);
  return credential;
}

/** A typed facade call the server must refuse: the status and code, nothing else. */
async function refusal(client: PublicHttpClient, verb: string, input: unknown,
  headers?: HeadersInit): Promise<{ status: number; code: string }> {
  const reply = await client.raw<Refusal>("POST", `/v1/core/facade/${verb}`, input, headers);
  expect(reply.status).toBeGreaterThanOrEqual(400);
  expect(reply.status).toBeLessThan(500);
  return { status: reply.status, code: reply.body.error.code };
}

/** BLAKE3 of the original envelope bytes: the audit's entry_hash for that row. */
const envelopeHash = (entry: string): string => Buffer.from(blake3(Buffer.from(entry, "base64"))).toString("hex");

/** One bit flipped inside the primary signature, in place: still canonical
 * MessagePack, same op, same signer, but a signature that verifies nothing. */
function corruptedSignature(entry: string): string {
  const bytes = Buffer.from(entry, "base64");
  const envelope = decode(bytes) as { signer: { signature: Uint8Array } };
  const signature = Buffer.from(envelope.signer.signature);
  expect(signature.length).toBe(64);
  const at = bytes.indexOf(signature);
  expect(at).toBeGreaterThan(0);
  expect(bytes.indexOf(signature, at + 1)).toBe(-1);
  const forged = Buffer.from(bytes);
  forged[at + 7] = forged[at + 7]! ^ 0x01;
  return forged.toString("base64");
}

/** The same signed envelope with its advisory timestamp moved back a day.
 * ts is the last field, a canonical u32; the original signature covers it. */
function backdated(entry: string): string {
  const bytes = Buffer.from(entry, "base64");
  const envelope = decode(bytes) as { ts: number };
  const field = bytes.length - 8;
  expect([...bytes.subarray(field, field + 4)]).toEqual([0xa2, 0x74, 0x73, 0xce]);
  expect(bytes.readUInt32BE(field + 4)).toBe(envelope.ts);
  expect(envelope.ts).toBeGreaterThan(86_400);
  const forged = Buffer.from(bytes);
  forged.writeUInt32BE(envelope.ts - 86_400, field + 4);
  return forged.toString("base64");
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
// Door: self.credential.attenuate({holder_seed, caveat, next_binding_key?})
// -> {token, binding_key}. The host appends the holder's caveat to the slip
// this request presented; no slip signing is hand-rolled here.
suite.test(test, "AUTHORITY-01", "Vault-bound slip and request proof should work", async () => {
  const engine = await EngineFixture.start({ id: "AUTHORITY-01", profile });
  const owner = engine.pairedActor;
  const { bearer, seed } = credentialParts(owner.credential);
  const address = { namespace: ["authority-01"], key: "slip-proof" };
  const seeded = { text: "vault-bound" };
  // The owner states each value, so the gate admits it without review; an
  // unsourced keyed write would wait on review and never land.
  const stated = { source: "user_stated" };
  await engine.client.call("vault.kv.put", { ...address, value: seeded, request_id: "authority-01-seed", ...stated });
  const unauthorized = { status: 401, code: "UNAUTHORIZED" };

  // One holder proof admits one request. The identical replay, header for
  // header, is refused over HTTP and again at the WS upgrade.
  const proof = Object.fromEntries(boundHeaders(owner.credential));
  const replay = { ...proof, "x-oneiron-invocation": secretHex(16) };
  const anonymous = new PublicHttpClient(engine.url, { artifacts: engine.artifacts });
  const admitted = await anonymous.raw<FacadeResult<"vault.kv.get">>("POST", "/v1/core/facade/vault.kv.get", address, replay);
  expect(admitted.status).toBe(200);
  // RED since 2026-11-10 (run on main e79eb76df3e): engine defect [E2E-KV-GET-PREFILTER].
  // The committed put reads back null, because vault.kv.get filters its head through a
  // generic claim admission that always excludes core.memory.key_value.
  expect(admitted.body?.value).toEqual(seeded);
  expect(await refusal(anonymous, "vault.kv.get", address, replay)).toEqual(unauthorized);
  const replayedUpgrade = await anonymous.raw("GET", "/ws", undefined, { ...proof, ...upgradeHeaders() });
  expect(replayedUpgrade.status).toBe(401);
  // A fresh proof from the same holder is still admitted.
  expect((await engine.client.call("vault.kv.get", address))?.value).toEqual(seeded);

  // The slip alone proves nothing: the same bearer under another holder key.
  const strangerSeed = secretHex();
  redactor.add(strangerSeed);
  const strangerCredential = `v2.cred.${bearer.slice(SLIP_PREFIX.length)}.${strangerSeed}`;
  credentialParts(strangerCredential);
  const stranger = new PublicHttpClient(engine.url, { credential: strangerCredential, artifacts: engine.artifacts });
  expect(await refusal(stranger, "vault.kv.get", address)).toEqual(unauthorized);
  await refusedUpgrade(engine.url, strangerCredential);
  // Nor can the slip's presenter attenuate it with a seed that is not its
  // holder's: the engine refuses the narrowing as invalid authority.
  const wrongSeed = await refusal(engine.client, "self.credential.attenuate",
    { holder_seed: seedBytes(strangerSeed), caveat: {} });
  expect(wrongSeed).toEqual({ status: 400, code: "BAD_REQUEST" });

  // Holder attenuation narrows by Scope meet; it mints no actor, grant or slip.
  const before = await auditRows(engine.client);
  const readOnly: Facade.Scope = {
    worlds: { kind: "all" }, facets: { kind: "all" }, bands: { kind: "all" }, audience: { kind: "all" },
    verbs: { kind: "some", values: ["core:read"] }, sensitivity: { kind: "all" },
  };
  const child = await engine.client.call("self.credential.attenuate", {
    holder_seed: seedBytes(seed), caveat: { scope: { kind: "ceiling", scope: readOnly } },
  });
  // No transfer was asked for: the child stays with the same holder key.
  expect(child.binding_key).toEqual(holderPublicKey(seed));
  const childCredential = holderCredential(child.token, seed);
  const childClient = new PublicHttpClient(engine.url, { credential: childCredential, artifacts: engine.artifacts });
  expect((await childClient.call("vault.kv.get", address))?.value).toEqual(seeded);
  expect((await childClient.call("vault.scope.ceiling", {})).scope.verbs).toEqual(readOnly.verbs);
  const childWrite = { ...address, value: { text: "child-widened" }, request_id: "authority-01-child-write", ...stated };
  expect(await refusal(childClient, "vault.kv.put", childWrite)).toEqual({ status: 403, code: "FORBIDDEN" });

  // The child asks for every verb back. The meet keeps it read-only.
  const widened = await childClient.call("self.credential.attenuate", {
    holder_seed: seedBytes(seed), caveat: { scope: { kind: "ceiling", scope: { ...readOnly, verbs: { kind: "all" } } } },
  });
  const widenedClient = new PublicHttpClient(engine.url,
    { credential: holderCredential(widened.token, seed), artifacts: engine.artifacts });
  expect((await widenedClient.call("vault.scope.ceiling", {})).scope.verbs).toEqual(readOnly.verbs);
  expect(await refusal(widenedClient, "vault.kv.put", { ...childWrite, request_id: "authority-01-widened-write" }))
    .toEqual({ status: 403, code: "FORBIDDEN" });

  // Transfer names only the recipient's public key. The recipient's own seed
  // proves the moved slip; the former holder's seed no longer does.
  const recipientSeed = secretHex();
  redactor.add(recipientSeed);
  const moved = await childClient.call("self.credential.attenuate", {
    holder_seed: seedBytes(seed), caveat: {}, next_binding_key: holderPublicKey(recipientSeed),
  });
  expect(moved.binding_key).toEqual(holderPublicKey(recipientSeed));
  const recipient = new PublicHttpClient(engine.url,
    { credential: holderCredential(moved.token, recipientSeed), artifacts: engine.artifacts });
  expect((await recipient.call("vault.kv.get", address))?.value).toEqual(seeded);
  expect((await recipient.call("vault.scope.ceiling", {})).scope.verbs).toEqual(readOnly.verbs);
  const formerHolder = new PublicHttpClient(engine.url,
    { credential: holderCredential(moved.token, seed), artifacts: engine.artifacts });
  expect(await refusal(formerHolder, "vault.kv.get", address)).toEqual(unauthorized);

  const after = await auditRows(engine.client);
  expect(after.map(row => row.entry_hash).sort()).toEqual(before.map(row => row.entry_hash).sort());
  // The parent credential keeps its own authority.
  const ownerWrite = { text: "owner-writes" };
  await engine.client.call("vault.kv.put", { ...address, value: ownerWrite, request_id: "authority-01-owner-write", ...stated });
  expect((await recipient.call("vault.kv.get", address))?.value).toEqual(ownerWrite);

  // A slip is bound to the vault that minted it. One server at a time, as
  // this file's one slot schedules: stop this vault, then present both
  // credentials to an independent second vault.
  await engine.close();
  const second = await EngineFixture.start({ id: "AUTHORITY-01-second-vault", profile });
  for (const credential of [owner.credential, childCredential]) {
    const foreign = new PublicHttpClient(second.url, { credential, artifacts: second.artifacts });
    expect(await refusal(foreign, "vault.kv.get", address)).toEqual(unauthorized);
    await refusedUpgrade(second.url, credential);
  }
  // A live control: the refusal is the binding, not a dead server.
  expect(await second.client.call("vault.kv.get", address)).toBeNull();
});

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
// Doors: vault.authority.history.export({}) -> {entries: base64[]} and
// vault.authority.history.import({entries}) -> {entry_refs}. Every forgery
// below starts from a real exported envelope; none is a made-up body.
suite.test(test, "AUTHORITY-03", "Public authority history is append-only should work", async () => {
  // A foreign vault's own signed history and owner credential, kept after it stops.
  const foreign = await EngineFixture.start({ id: "AUTHORITY-03-foreign", profile });
  const foreignHistory = await foreign.client.call("vault.authority.history.export", {});
  const foreignCredential = foreign.pairedActor.credential;
  await foreign.close();

  const engine = await EngineFixture.start({ id: "AUTHORITY-03", profile });
  const history = await engine.client.call("vault.authority.history.export", {});
  const audit = await auditRows(engine.client);
  // The export is the log itself: each original envelope hashes to exactly one audit row.
  expect(history.entries.map(envelopeHash).sort()).toEqual(audit.map(row => row.entry_hash).sort());
  expect(audit.filter(row => row.source_op === "genesis")).toHaveLength(1);
  expect(audit.every(row => row.fold_valid)).toBe(true);
  const ownHashes = new Set(history.entries.map(envelopeHash));
  expect(foreignHistory.entries.some(entry => ownHashes.has(envelopeHash(entry)))).toBe(false);
  const unchanged = async (): Promise<void> => {
    expect((await engine.client.call("vault.authority.history.export", {})).entries).toEqual(history.entries);
    const rows = await auditRows(engine.client);
    expect(rows.map(row => [row.entry_hash, row.signer_key, row.seq, row.fold_valid]))
      .toEqual(audit.map(row => [row.entry_hash, row.signer_key, row.seq, row.fold_valid]));
  };

  // Importing the vault's own history again changes nothing. Each submitted
  // envelope answers with its content-addressed log id: its hash's first 16 bytes.
  const again = await engine.client.call("vault.authority.history.import", history);
  expect([...again.entry_refs].sort()).toEqual(history.entries.map(entry => envelopeHash(entry).slice(0, 32)).sort());
  expect([...again.entry_refs].sort()).toEqual(audit.map(row => row.entry_ref).sort());
  await unchanged();

  // Forgeries of the owner's real slip mint: a broken signature, a backdated
  // copy, and a truncated body. Alone or inside the full real history, each
  // is refused and the import writes nothing.
  const mint = audit.find(row => row.source_op === "slip_mint" && row.holder_ref === engine.pairedActor.principalRef);
  if (!mint) throw new Error("Owner pairing left no slip mint in the audit");
  const original = history.entries.find(entry => envelopeHash(entry) === mint.entry_hash)!;
  const forgeries = [
    corruptedSignature(original),
    backdated(original),
    Buffer.from(original, "base64").subarray(0, -1).toString("base64"),
  ];
  const invalidBody = { status: 400, code: "BAD_REQUEST" };
  for (const forged of forgeries) {
    expect(ownHashes.has(envelopeHash(forged))).toBe(false);
    expect(await refusal(engine.client, "vault.authority.history.import", { entries: [forged] })).toEqual(invalidBody);
    expect(await refusal(engine.client, "vault.authority.history.import", { entries: [...history.entries, forged] }))
      .toEqual(invalidBody);
  }
  expect(await refusal(engine.client, "vault.authority.history.import", { entries: ["not base64 at all"] }))
    .toEqual(invalidBody);
  // A different genesis is not this vault's history.
  expect(await refusal(engine.client, "vault.authority.history.import", foreignHistory)).toEqual(invalidBody);
  await unchanged();

  // The foreign vault's owner has no standing here, to read or to write the log.
  const stranger = new PublicHttpClient(engine.url, { credential: foreignCredential, artifacts: engine.artifacts });
  const unauthorized = { status: 401, code: "UNAUTHORIZED" };
  expect(await refusal(stranger, "vault.authority.history.export", {})).toEqual(unauthorized);
  expect(await refusal(stranger, "vault.authority.history.import", foreignHistory)).toEqual(unauthorized);

  // The log survives a restart byte for byte, and the owner's access with it.
  await engine.restart();
  await unchanged();

  // A real append extends the log. Every earlier envelope stays, unchanged.
  const paired = await engine.pairActor({ principalRef: engine.pairedActor.principalRef, actorClass: "human" });
  const grown = await engine.client.call("vault.authority.history.export", {});
  const added = grown.entries.filter(entry => !ownHashes.has(envelopeHash(entry)));
  expect(grown.entries.filter(entry => ownHashes.has(envelopeHash(entry)))).toEqual(history.entries);
  expect(added.length).toBeGreaterThan(0);
  const grownAudit = await auditRows(engine.client);
  const addedRows = grownAudit.filter(row => !ownHashes.has(row.entry_hash));
  expect(addedRows.map(row => row.entry_hash).sort()).toEqual(added.map(envelopeHash).sort());
  expect(addedRows.every(row => row.fold_valid)).toBe(true);
  expect(addedRows.some(row => row.source_op === "slip_mint" && row.holder_ref === paired.principalRef)).toBe(true);
  expect((await paired.client.call("vault.kv.get", { namespace: ["authority-03"], key: "absent" }))).toBeNull();
});

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
  expect(Array.isArray((await client.call("vault.receipts", { limit: 1 })).receipts)).toBe(true);
  const pythonRead = await engine.sdk.run("python", {
    mode: "remote", url: engine.url, credential: paired.credential,
  }, [{ verb: "receipts", limit: 1 }]);
  expect(pythonRead.results).toHaveLength(1);
  expect(pythonRead.results[0]?.ok).toBe(true);
  const socket = await WsClient.connect(engine.url, paired.credential);
  try { expect(Array.isArray((await socket.call("vault.receipts", { limit: 1 })).value.receipts)).toBe(true) }
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
  try { expect(Array.isArray((await control.call("vault.receipts", { limit: 1 })).value.receipts)).toBe(true) }
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
// Doors: vault.scope.position({record_ref}) -> {value: {kind:"position",scope}|null},
// vault.scope.ceiling({}) -> {kind:"ceiling",scope}, vault.export.scoped({selector,
// channel}) -> {credential, applied, records}, and self.credential.attenuate for
// a narrower ceiling. A record's band is its kind, so a claim and a message
// sit at two distinct positions without any extra world or facet setup.
// Not proved here: a record stamped at a bottom position (no public writer
// makes one), and the same comparison through recall and hydrate.
suite.test(test, "AUTHORITY-06", "Scope position and ceiling should work", async () => {
  const engine = await EngineFixture.start({ id: "AUTHORITY-06", profile });
  const at = Date.parse("2026-10-01T09:00:00Z") / 1000;
  const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
  const claimed = await engine.client.call("vault.claims.upsert", {
    scope, subject_ref: engine.pairedActor.principalRef, source: "user_stated", confidence: 0.875,
    predicate: "profile.authority_06_harbour_key", value: "The harbour key hangs by the north door.",
    occurred_at: at, learned_at: at,
  });
  await engine.awaitReceipt(claimed.receipt_ref);
  const claimRow = (await engine.client.call("vault.hydrate", { refs: [claimed.claim_short_id] })).value[0];
  const conversation = await engine.client.call("vault.conversations.create", {
    body: {}, occurred_start: at, occurred_end: at, learned_at: at,
  });
  const witnessed = await engine.client.call("vault.witness", {
    conversation_ref: conversation.id, occurred_at: at,
    messages: [{ author: "user", message_type: "text", content: "The ferry leaves at seven.", is_visible: true, order: 0 }],
  });
  const messageRow = (await engine.client.call("vault.get", { entity_ref: witnessed.message_short_ids[0]! })).value;
  if (!claimRow || !messageRow) throw new Error("Fixture rows were not readable by their owner");
  const ids = { claim: claimRow.id_hex, message: messageRow.id_hex };

  type Position = FacadeResult<"vault.scope.position">["value"];
  const position = async (client: PublicHttpClient, id: string): Promise<Position> =>
    (await client.call("vault.scope.position", { record_ref: id })).value;
  const band = (stamp: Position): number => {
    if (!stamp) throw new Error("Stamped row has no readable position");
    expect(stamp.kind).toBe("position");
    // The generated axis type is optional and not narrowed by kind: read it by shape.
    const bands = stamp.scope.bands as unknown as { kind: string; values?: number[] } | undefined;
    if (bands?.kind !== "some" || !bands.values) throw new Error("A record position names its band");
    expect(bands.values).toHaveLength(1);
    return bands.values[0]!;
  };
  const claimPosition = await position(engine.client, ids.claim);
  const messagePosition = await position(engine.client, ids.message);
  const claimBand = band(claimPosition);
  const messageBand = band(messagePosition);
  expect(claimBand === messageBand).toBe(false);
  expect(claimPosition!.scope.worlds).toEqual({ kind: "some", values: [scope.world_id] });
  // An id with no row has no position; that is an answer, not an error.
  expect(await position(engine.client, secretHex(16))).toBeNull();

  // Narrower ceilings are held by attenuating the owner's own slip.
  const { seed } = credentialParts(engine.pairedActor.credential);
  const top: Facade.Scope = {
    worlds: { kind: "all" }, facets: { kind: "all" }, bands: { kind: "all" }, audience: { kind: "all" },
    verbs: { kind: "all" }, sensitivity: { kind: "all" },
  };
  const holding = async (ceiling: Facade.Scope): Promise<PublicHttpClient> => {
    const narrowed = await engine.client.call("self.credential.attenuate", {
      holder_seed: seedBytes(seed), caveat: { scope: { kind: "ceiling", scope: ceiling } },
    });
    return new PublicHttpClient(engine.url, { credential: holderCredential(narrowed.token, seed), artifacts: engine.artifacts });
  };
  const claimsOnly = await holding({ ...top, bands: { kind: "some", values: [claimBand] },
    verbs: { kind: "some", values: ["core:read", "export"] } });
  const ceiling = await claimsOnly.call("vault.scope.ceiling", {});
  expect(ceiling.kind).toBe("ceiling");
  expect(ceiling.scope.bands).toEqual({ kind: "some", values: [claimBand] });
  expect(ceiling.scope.verbs).toEqual({ kind: "some", values: ["core:read", "export"] });
  // The ceiling admits the claim's position and withholds the message's.
  expect(await position(claimsOnly, ids.claim)).toEqual(claimPosition);
  expect(await position(claimsOnly, ids.message)).toBeNull();
  expect((await claimsOnly.call("vault.get", { entity_ref: ids.claim })).value?.id_hex).toBe(ids.claim);
  expect((await claimsOnly.call("vault.get", { entity_ref: ids.message })).value).toBeNull();

  // Scoped export: selector, credential and channel meet. A channel can
  // narrow the credential but never stand in for it.
  type ChannelScope = FacadeInput<"vault.export.scoped">["channel"]["scope"];
  const allChannel: ChannelScope = {
    worlds: { kind: "all" }, facets: { kind: "all" }, bands: { kind: "all" }, audience: { kind: "all" },
    verbs: { kind: "all" }, sensitivity: { kind: "all" },
  };
  const exported = (client: PublicHttpClient, channel: ChannelScope,
    selector: FacadeInput<"vault.export.scoped">["selector"] = {}) =>
    client.call("vault.export.scoped", { selector, channel: { channel_ref: "authority-06", scope: channel } });
  const fixtureRows = (result: FacadeResult<"vault.export.scoped">): string[] => result.records
    .map(row => row.record.id).filter(id => id === ids.claim || id === ids.message).sort();
  const ownerAll = await exported(engine.client, allChannel);
  expect(fixtureRows(ownerAll)).toEqual([ids.claim, ids.message].sort());
  const exportedClaim = ownerAll.records.find(row => row.record.id === ids.claim)!;
  expect(exportedClaim.position).toEqual(claimPosition!);
  expect(exportedClaim.bytes.length).toBeGreaterThan(0);
  const readerAll = await exported(claimsOnly, allChannel);
  expect(fixtureRows(readerAll)).toEqual([ids.claim]);
  expect(readerAll.credential).toEqual(ceiling);
  const messageChannel: ChannelScope = { ...allChannel, bands: { kind: "some", values: [messageBand] } };
  expect(fixtureRows(await exported(engine.client, messageChannel))).toEqual([ids.message]);
  expect(fixtureRows(await exported(claimsOnly, messageChannel))).toEqual([]);
  // Empty requested selector lists narrow nothing, and cannot widen the ceiling.
  expect(fixtureRows(await exported(claimsOnly, allChannel, { facet_refs: [], kinds: [], project_refs: [] })))
    .toEqual([ids.claim]);
  // An omitted channel axis is bottom: it grants nothing, even to the owner.
  expect((await exported(engine.client, {})).records).toEqual([]);

  // A bottom ceiling grants nothing on any door.
  const nothing = await holding({ ...top, bands: { kind: "bottom" } });
  expect((await nothing.call("vault.scope.ceiling", {})).scope.bands).toEqual({ kind: "bottom" });
  expect(await position(nothing, ids.claim)).toBeNull();
  expect((await nothing.call("vault.get", { entity_ref: ids.claim })).value).toBeNull();
  expect((await exported(nothing, allChannel)).records).toEqual([]);

  // Refusals: a position offered as a ceiling, export without the export
  // verb, and an unnamed channel.
  expect(await refusal(engine.client, "self.credential.attenuate",
    { holder_seed: seedBytes(seed), caveat: { scope: claimPosition } })).toEqual({ status: 400, code: "BAD_REQUEST" });
  const readOnly = await holding({ ...top, verbs: { kind: "some", values: ["core:read"] } });
  const scopedExport = { selector: {}, channel: { channel_ref: "authority-06", scope: allChannel } };
  expect(await refusal(readOnly, "vault.export.scoped", scopedExport)).toEqual({ status: 403, code: "FORBIDDEN" });
  expect(await refusal(engine.client, "vault.export.scoped",
    { ...scopedExport, channel: { ...scopedExport.channel, channel_ref: "" } })).toEqual({ status: 403, code: "FORBIDDEN" });
});

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
  // A keyed value is a JSON object, and the owner states it (an unsourced write waits on review).
  const noted = { text: facts.value };
  const written = await engine.client.call("vault.kv.put", {
    ...address, value: noted, request_id: facts.requestId, source: "user_stated",
  });
  expect(written.item.value).toEqual(noted);
  expect((await engine.client.call("vault.kv.get", address))?.value).toEqual(noted);
  const before = await auditRows(engine.client);
  const genesis = before.filter(row => row.source_op === "genesis");
  expect(genesis).toHaveLength(1);
  expect(genesis[0]!.fold_valid).toBe(true);
  const ownerMints = before.filter(row => row.source_op === "slip_mint"
    && row.holder_ref === engine.pairedActor.principalRef);
  expect(ownerMints.length).toBeGreaterThan(0);
  const vaultId = ownerMints[0]!.vault_ref;
  if (typeof vaultId !== "string") throw new Error("Minted owner slip has no vault reference");
  expect(vaultId).toMatch(/^[a-f0-9]{64}$/);

  const destination = await handoffHost(engine);
  expect(destination.report.vault_id).toBe(vaultId);
  for (const mint of ownerMints) {
    expect(destination.report.retired_credentials.some(row => row.slip_id === mint.subject_ref)).toBe(true);
  }
  expect(destination.credential === engine.pairedActor.credential).toBe(false);
  expect((await destination.client.call("vault.kv.get", address))?.value).toEqual(noted);
  const oldRead = await engine.client.raw<{ error: { code: string } }>("POST", "/v1/core/facade/vault.kv.get", address);
  expect(oldRead.status).toBe(401);
  expect(oldRead.body.error.code).toBe("UNAUTHORIZED");
  await refusedUpgrade(engine.url, engine.pairedActor.credential);
  const newSocket = await WsClient.connect(engine.url, destination.credential);
  try { expect((await newSocket.call("vault.kv.get", address)).value?.value).toEqual(noted) }
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
