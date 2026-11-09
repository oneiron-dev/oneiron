import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { inflateRawSync } from "node:zlib";
import { blake3 } from "@noble/hashes/blake3";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { PublicHttpClient, credentialParts } from "./support/clients.ts";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { defineFile, ownResource, redactor, secretHex } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

// Public binding read: main 5ecd5af5bea2c70e25760f0583f276790f49fba4.
// Expectations: ARCH-0027 ingest/export, ARCH-0038 two-exports, G01/G02,
// ARCH-0019 storage-invariants, ARCH-0040 memory-board-source-trust.
// A TODO blocks its entire planned ID, including otherwise available substeps.

type Counts = Readonly<Record<string, number>>;
interface Facts {
  owner: { query: string; afterBackup: string; afterBackupQuery: string };
  attachment: { name: string; mediaType: string; sha256: string; bytes: number };
  folder: {
    firstQuery: string; secondQuery: string; editedQuery: string; thirdQuery: string;
    trust: string; initialFiles: number; finalFiles: number;
    attach: Counts; add: Counts; edit: Counts; remove: Counts; restore: Counts;
  };
}
interface BackupOutcome {
  backup: { file: string; path: string; bytes: number };
  checkpoint_id: string;
  pruned: string[];
}
interface SignerPin { install: string; ed25519: string; slhdsa: string }
interface FreshRestore {
  checkpoint_id: string; vault: string; unlocked_with: string;
}
interface OwnerStatus {
  location: { vault: string; backups: { restores: {
    checkpoint_id: string; restored_at: string; reason: string;
  }[] } };
}
interface FolderSource {
  folder: string; trust: string; last_rescan_at: number | null;
}
interface FolderScan { folder: string; report?: Counts; error?: string }
interface FolderListing extends FolderSource {
  files: number; retracted: number; proposed: number;
}
type MemoryItem = FacadeResult<"vault.recall">["items"][number];

const configPath = (engine: EngineFixture): string => resolve(engine.root, "oneiron.toml");
const ownerArgs = (engine: EngineFixture): string[] => ["--config", configPath(engine)];

async function stopForOwnerCli(engine: EngineFixture): Promise<void> {
  // Observe a real public ACK before killing the owned process. No fake drain.
  await engine.client.call("vault.receipts", { limit: 1 });
  await engine.kill();
}

// The shared fixture has no stopped-vault config/restore hook. This helper
// changes only public TOML, never vault files, private rows or signing records.
async function configureStoppedFixture(
  engine: EngineFixture, options: { platformKeystore?: boolean; vaultPath?: string },
): Promise<void> {
  const parts = (await readFile(configPath(engine), "utf8")).split(/(?=^\[)/m);
  if (options.vaultPath) {
    const setting = `vault_path = ${JSON.stringify(options.vaultPath)}\n`;
    const root = parts[0]!;
    parts[0] = /^vault_path\s*=/m.test(root)
      ? root.replace(/^vault_path\s*=.*\n?/m, setting) : setting + root;
  }
  if (options.platformKeystore) {
    const index = parts.findIndex(part => part.startsWith("[keystore]"));
    if (index < 0) throw new Error("Fixture public config has no keystore table");
    parts[index] = `[keystore]\nbackend = "platform"\ndir = ${JSON.stringify(resolve(engine.root, "keys"))}\n\n`;
  }
  await writeFile(configPath(engine), parts.join(""), { mode: 0o600 });
}

async function recallItem(engine: EngineFixture, query: string): Promise<MemoryItem> {
  const pack = await awaitPublic(
    () => engine.client.call("vault.recall", { query, effort: "light", limit: 20 }),
    value => value.items.some(item => item.value_text.includes(query)),
    { label: `recall fixture ${query}` },
  );
  return pack.items.find(item => item.value_text.includes(query))!;
}

function sourceId(item: MemoryItem): string {
  if (!item.record) throw new Error("Recalled source has no public record reference");
  expect(item.provenance.source_revision_ids).toContain(item.record.id);
  return item.record.id;
}

async function expectDiary(
  engine: EngineFixture, query: string, entryId: string, content: string,
): Promise<void> {
  const item = await recallItem(engine, query);
  expect(item.provenance.source_revision_ids).toContain(entryId);
  expect(item.value_text).toContain(query);
  const read = await engine.client.call("vault.get", { entity_ref: entryId });
  expect(read.value?.body).toMatchObject({ markdown: content });
}

async function expectBlob(engine: EngineFixture, artifact: string, expected: Uint8Array): Promise<void> {
  const download = await engine.client.raw("GET", `/v1/core/artifacts/${artifact}/versions/1/export`);
  expect(download.status).toBe(200);
  expect(download.bytes).toEqual(expected);
}

function expectScan(scan: FolderScan, expected: Counts): void {
  expect(scan.error).toBeUndefined();
  expect(scan.report).toBeDefined();
  expect(scan.report).toMatchObject(expected);
}

async function rescanFolder(engine: EngineFixture, folder: string, expected: Counts): Promise<void> {
  const scans = await engine.cli.json<FolderScan[]>([
    "import", "folder", "rescan", folder, ...ownerArgs(engine),
  ]);
  expect(scans).toHaveLength(1);
  expect(scans[0]!.folder).toBe(folder);
  expectScan(scans[0]!, expected);
}

// PORTABILITY-01 — Whole-vault five-format ownership export should work.
// G02 supersedes the title's five-format premise: one complete open archive,
// JSONL per kind, attached files once by hash, contents manifest; OKF is a
// separate lossy target, not five independent lossless import formats.
// Existing typed calls: vault.export({format:"archive"|"okf",include_secrets})
// -> {format,archive,digest}; CLI export --format archive|okf --out <new-file>.
// Required fixture: publicly create evidence, claims, pack source, SKILL.md +
// scripts, AGENT_PACK and derivation envelopes, a >1 MiB on-record run result,
// an off-record counterpart, an attachment and custody sentinel. Export from
// that real vault (never invent a ZIP); check every family, file/body hash,
// occurrence binding and exclusion against authored facts, then download blobs.
// Main's include_secrets default is true; the requested never-export-credentials
// assertion must NOT be weakened to match it (recorded on the fix list).
// Written by OPUS-E2E-2 on main e79eb76df3e. Families covered: diary NOTE,
// message, claim, attachment, masked credentials (message and claim field)
// and a LIVE off-record overlay. Not proved here: pack source, SKILL.md and
// scripts, AGENT_PACK and derivation envelopes, and a >1 MiB on-record run
// result with its off-record counterpart (no deterministic public producer).
// Doors: vault.export({format, include_secrets, delivery}) -> inline
// {format, archive, digest} or transfer {transfer_ref, bytes, digest}, and
// vault.export.transfer.read({transfer_ref, offset, length}) for the pieces.
// Credentials come from the secrets mask fixture, written through witness and
// a claim field; the live off-record note through vault.off_record.notes.create.
const ownershipExport: FacadeInput<"vault.export"> = { format: "archive", include_secrets: false };
interface MaskedSecrets {
  occurredAt: number; prefix: string; suffix: string; credential: string; fieldCredential: string;
  fieldNote: string; fieldTail: string; predicate: string;
}

/** Single-disk ZIP members, stored or deflated: the public archive as a reader sees it. */
function zipMembers(bytes: Buffer): Map<string, Buffer> {
  let end = bytes.length - 22;
  while (end >= Math.max(0, bytes.length - 65_557) && bytes.readUInt32LE(end) !== 0x06054b50) end--;
  if (end < 0 || bytes.readUInt32LE(end) !== 0x06054b50) throw new Error("Missing ZIP directory");
  const count = bytes.readUInt16LE(end + 10);
  let cursor = bytes.readUInt32LE(end + 16);
  const members = new Map<string, Buffer>();
  for (let index = 0; index < count; index++) {
    expect(bytes.readUInt32LE(cursor)).toBe(0x02014b50);
    const method = bytes.readUInt16LE(cursor + 10);
    const size = bytes.readUInt32LE(cursor + 20);
    const nameSize = bytes.readUInt16LE(cursor + 28);
    const local = bytes.readUInt32LE(cursor + 42);
    const name = bytes.subarray(cursor + 46, cursor + 46 + nameSize).toString("utf8");
    const start = local + 30 + bytes.readUInt16LE(local + 26) + bytes.readUInt16LE(local + 28);
    const stored = bytes.subarray(start, start + size);
    expect([0, 8]).toContain(method);
    expect(members.has(name)).toBe(false);
    members.set(name, method === 8 ? inflateRawSync(stored) : Buffer.from(stored));
    cursor += 46 + nameSize + bytes.readUInt16LE(cursor + 30) + bytes.readUInt16LE(cursor + 32);
  }
  return members;
}

suite.test(test, "PORTABILITY-01", "Whole-vault five-format ownership export should work", async () => {
  const catalog = await loadFixtures();
  const facts = await catalog.readJson<Facts>("portability-facts");
  const note = new TextDecoder().decode(await catalog.readArchive("portability-owner-note"));
  const blob = Buffer.from(await catalog.readArchive("portability-attachment"));
  const mask = await catalog.readJson<MaskedSecrets>("secrets-mask-on-write");
  const secrets = [mask.credential, mask.fieldCredential];
  for (const secret of secrets) redactor.add(secret, Buffer.from(secret).toString("base64"));
  const engine = await EngineFixture.start({ id: "PORTABILITY-01", profile });

  // On-record content: a diary entry, an attachment, a credential in a
  // message and another in a claim field.
  // Diary and witness answer write markers, not gate receipts: observe the rows instead.
  const saved = await engine.client.call("self.memory.diary", { content: note });
  expect((await engine.client.call("vault.get", { entity_ref: saved.entry_id })).value).not.toBeNull();
  const artifact = await engine.client.call("vault.artifacts.create", {
    name: facts.attachment.name, media_type: facts.attachment.mediaType, content_base64: blob.toString("base64"),
  });
  if (!artifact) throw new Error("Fixture attachment was not created");
  const conversation = await engine.client.call("vault.conversations.create", {
    body: {}, occurred_start: mask.occurredAt, occurred_end: mask.occurredAt, learned_at: mask.occurredAt,
  });
  const witnessed = await engine.client.call("vault.witness", {
    conversation_ref: conversation.id, occurred_at: mask.occurredAt,
    messages: [{ author: "user", message_type: "text", is_visible: true, order: 0,
      content: mask.prefix + mask.credential + mask.suffix }],
  });
  expect(witnessed.message_short_ids).toHaveLength(1);
  expect((await engine.client.call("vault.get", { entity_ref: witnessed.message_short_ids[0]! })).value).not.toBeNull();
  const claim = await engine.client.call("vault.claims.upsert", {
    scope: await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef),
    predicate: mask.predicate, subject_ref: conversation.id,
    value: { note: mask.fieldNote, access: mask.fieldCredential, tail: mask.fieldTail },
    source: "user_stated", confidence: 1, occurred_at: mask.occurredAt,
  });
  await engine.awaitReceipt(claim.receipt_ref);

  // A LIVE off-record session holds its own note while the owner exports.
  const session = "portability-01-live";
  await engine.client.call("vault.off_record.start", { session_ref: session, mode: "off_record", backend: "local" });
  const overlayText = "Overlay only: the lighthouse keeper keeps the spare key under the third step.";
  const overlay = await engine.client.call("vault.off_record.notes.create", {
    session_ref: session, note: { kind: "observation", markdown: overlayText },
  });

  // Inline archive, credentials withheld. Nothing secret, encoded or not, and
  // nothing from the live overlay is in any member; the export is not refused.
  const forbidden = [...secrets.flatMap(secret => [secret, Buffer.from(secret).toString("base64"),
    Buffer.from(secret).toString("hex")]), overlayText, overlay.id_hex];
  const checkArchive = (archive: Buffer, digest: string): Map<string, Buffer> => {
    expect(Buffer.from(blake3(archive)).toString("hex")).toBe(digest);
    const members = zipMembers(archive);
    const manifest = JSON.parse(members.get("manifest.json")!.toString("utf8")) as Record<string, unknown>;
    expect(manifest.secrets_included).toBe(false);
    expect(manifest.secrets_nulled).toBe(true);
    const text = [...members.values()].map(bytes => bytes.toString("utf8")).join("\n");
    expect(text).toContain(facts.owner.query);
    for (const value of forbidden) expect(text.includes(value)).toBe(false);
    for (const secret of secrets) {
      for (const bytes of members.values()) expect(bytes.includes(Buffer.from(secret))).toBe(false);
    }
    // The attachment travels once, as its exact bytes.
    expect([...members.values()].filter(bytes => bytes.equals(blob))).toHaveLength(1);
    return members;
  };
  const inline = await engine.client.call("vault.export", { ...ownershipExport, delivery: "inline" });
  if (!("archive" in inline)) throw new Error("Unexpected export transfer for an inline request");
  // The answer names the archive format the manifest records, not the request word.
  expect(inline.format.length).toBeGreaterThan(0);
  checkArchive(Buffer.from(inline.archive, "base64"), inline.digest);

  // The same archive by transfer, read back in three pieces.
  const transfer = await engine.client.call("vault.export", { ...ownershipExport, delivery: "transfer" });
  if (!("transfer_ref" in transfer)) throw new Error("Unexpected inline answer for a transfer request");
  expect(transfer.transfer_ref).toMatch(/^export_transfer:[a-f0-9]{32}$/);
  expect(transfer.format).toBe(inline.format);
  const pieceLength = Math.ceil(transfer.bytes / 3);
  const pieces: Buffer[] = [];
  for (let offset = 0; ;) {
    const piece = await engine.client.call("vault.export.transfer.read",
      { transfer_ref: transfer.transfer_ref, offset, length: pieceLength });
    expect(piece).toMatchObject({ transfer_ref: transfer.transfer_ref, offset, total_bytes: transfer.bytes, digest: transfer.digest });
    const bytes = Buffer.from(piece.bytes_base64, "base64");
    expect(bytes.length).toBe(piece.length);
    pieces.push(bytes);
    offset += piece.length;
    if (piece.end) break;
    expect(piece.length).toBe(pieceLength);
  }
  expect(pieces).toHaveLength(3);
  checkArchive(Buffer.concat(pieces), transfer.digest);

  // The OKF target is a separate, lossy format, still credential-free.
  const okf = await engine.client.call("vault.export", { format: "okf", include_secrets: false, delivery: "inline" });
  if (!("archive" in okf)) throw new Error("Unexpected export transfer for an inline OKF request");
  expect(okf.format === inline.format).toBe(false);
  const okfText = [...zipMembers(Buffer.from(okf.archive, "base64")).values()].map(bytes => bytes.toString("utf8")).join("\n");
  for (const value of forbidden) expect(okfText.includes(value)).toBe(false);

  // Refusals. An unknown format; a read past the archive's end; an owner slip
  // that carries any caveat is not owner grade, for the export or its pieces;
  // and a released transfer is gone.
  const refused = async (client: PublicHttpClient, verb: string, input: unknown) => {
    const reply = await client.raw<{ error: { code: string } }>("POST", `/v1/core/facade/${verb}`, input);
    return { status: reply.status, code: reply.body.error.code };
  };
  expect(await refused(engine.client, "vault.export", { format: "ARCHIVE" })).toEqual({ status: 400, code: "BAD_REQUEST" });
  expect(await refused(engine.client, "vault.export.transfer.read",
    { transfer_ref: transfer.transfer_ref, offset: transfer.bytes + 1 })).toEqual({ status: 400, code: "BAD_REQUEST" });
  const { seed } = credentialParts(engine.pairedActor.credential);
  const caveated = await engine.client.call("self.credential.attenuate", {
    holder_seed: [...Buffer.from(seed, "hex")], caveat: { ttl_secs: 3600 },
  });
  const caveatedOwner = new PublicHttpClient(engine.url,
    { credential: `v2.cred.${caveated.token.slice("v2.slip.".length)}.${seed}`, artifacts: engine.artifacts });
  const notOwnerGrade = { status: 403, code: "FORBIDDEN" };
  expect(await refused(caveatedOwner, "vault.export", ownershipExport)).toEqual(notOwnerGrade);
  expect(await refused(caveatedOwner, "vault.export.transfer.read", { transfer_ref: transfer.transfer_ref })).toEqual(notOwnerGrade);
  const released = await engine.client.raw("DELETE", `/v1/core/export-transfers/${transfer.transfer_ref}`);
  expect(released.status).toBe(204);
  expect(await refused(engine.client, "vault.export.transfer.read", { transfer_ref: transfer.transfer_ref }))
    .toEqual({ status: 404, code: "NOT_FOUND" });

  // Closing the session without saving leaves the next export as clean.
  await engine.client.call("vault.off_record.discard", { session_ref: session });
  const after = await engine.client.call("vault.export", { ...ownershipExport, delivery: "inline" });
  if (!("archive" in after)) throw new Error("Unexpected export transfer for an inline request");
  checkArchive(Buffer.from(after.archive, "base64"), after.digest);
});

// PORTABILITY-02 — Owner same-build restore should work.
// Available typed public shapes are BackupOutcome, FreshRestore, SignerPin,
// OwnerStatus above, plus vault.recall and the artifact download route.
// Required flow: populate, spend a local runner budget, back up; stop, restore
// into an absent destination, serve with the same owner, recall known text and
// download the exact fixture bytes; observe rebuilt retrieval and a matching
// RESTORE epoch. The budget must demonstrably reset, not merely be omitted
// from export. vault.budgets.local now reads that local counter.
// Written by OPUS-E2E-2 on main e79eb76df3e: the counter is filled with
// vault.sieve.lease.refill. Not proved here: spending it first, since no
// public door reserves or spends a wake budget outside the host runtime.
// Doors: vault.sieve.lease.refill fills a device-local wake budget,
// vault.budgets.local and vault.runners.seats.quotas read it back.
suite.test(test, "PORTABILITY-02", "Owner same-build restore should work", async () => {
  const catalog = await loadFixtures();
  const facts = await catalog.readJson<Facts>("portability-facts");
  const note = new TextDecoder().decode(await catalog.readArchive("portability-owner-note"));
  const blob = await catalog.readArchive("portability-attachment");

  const engine = await EngineFixture.start({ id: "PORTABILITY-02", profile });
  await stopForOwnerCli(engine);
  await configureStoppedFixture(engine, { platformKeystore: true });
  await engine.restart();
  const saved = await engine.client.call("self.memory.diary", { content: note });
  expect((await engine.client.call("vault.get", { entity_ref: saved.entry_id })).value).not.toBeNull();
  const artifact = await engine.client.call("vault.artifacts.create", {
    name: facts.attachment.name, media_type: facts.attachment.mediaType,
    content_base64: Buffer.from(blob).toString("base64"),
  });
  if (!artifact) throw new Error("Fixture attachment was not created");

  // A device-local runner budget, filled and read back on the source vault.
  const budget = { budget_id: "portability-02-local" };
  const filled = await engine.client.call("vault.sieve.lease.refill", { ...budget, total_units: 100 });
  expect(filled.counter).toMatchObject({ total_units: 100, remaining_units: 100, reserved_units: 0 });
  const sourceCounter = { total_units: 100, remaining_units: 100, reserved_units: 0, spent_units: 0,
    overdraft_units: 0, owed_calls: 0 };
  expect((await engine.client.call("vault.budgets.local", budget)).counter).toMatchObject(sourceCounter);
  const seats: FacadeInput<"vault.runners.seats.quotas"> = {
    seats: [{ runner: "claude-code", auth: "vendor_login", egress_profile_ref: "portability-02" }],
  };
  const neverRecorded = { seat: 0, runner: "claude-code", spent: null, observed_at: null, back_at: null,
    available: true, last_capture: null, topped_up_at: null };
  expect((await engine.client.call("vault.runners.seats.quotas", seats)).quotas).toEqual([neverRecorded]);

  const key = secretHex();
  redactor.add(key);
  const credential = "portability-02-passkey"; // A label, not secret key material.
  await engine.client.request("POST", "/v1/owner/vault-key/passkeys", { credential, prf: key });
  const signer = (await engine.client.request<SignerPin>("GET", "/v1/owner/vault-key/signer")).body;
  const trustFile = resolve(engine.root, "checkpoint-signers.json");
  await writeFile(trustFile, JSON.stringify(signer), { mode: 0o600 });
  const backup = (await engine.client.request<BackupOutcome>("POST", "/v1/owner/backups")).body;
  expect(backup.backup.bytes).toBeGreaterThan(0);

  // Restore into an absent destination with the same build and the same owner.
  await stopForOwnerCli(engine);
  const destination = resolve(engine.root, "restored-vault");
  const restoreArgs = ["restore", backup.backup.path, "--unlock", "passkey", "--credential", credential,
    "--trust", trustFile, "--vault-path", destination, ...ownerArgs(engine)];
  const restored = await engine.cli.run(restoreArgs, key, undefined, true);
  expect(restored.exitCode).toBe(0);
  const receipt = JSON.parse(restored.stdout) as FreshRestore;
  expect(receipt.checkpoint_id).toBe(backup.checkpoint_id);
  expect(receipt.vault).toBe(destination);
  // The destination now exists: the same restore is refused rather than overwriting it.
  const overwrite = await engine.cli.run(restoreArgs, key, undefined, true);
  expect(overwrite.exitCode).not.toBe(0);
  expect(overwrite.signal).toBeNull();

  await configureStoppedFixture(engine, { vaultPath: destination });
  await engine.restart();
  // Content and retrieval are rebuilt for the same owner.
  await expectDiary(engine, facts.owner.query, saved.entry_id, note);
  await expectBlob(engine, artifact.artifact_id, blob);
  const status = (await engine.client.request<OwnerStatus>("GET", "/v1/owner/status")).body;
  expect(status.location.vault).toBe(destination);
  expect(status.location.backups.restores).toEqual(expect.arrayContaining([
    expect.objectContaining({ checkpoint_id: backup.checkpoint_id, reason: "restore" }),
  ]));
  // The device-local budget does not travel: the restored vault starts with none.
  expect((await engine.client.call("vault.budgets.local", budget)).counter).toBeNull();
  expect((await engine.client.call("vault.sieve.lease", budget)).counter).toBeNull();
  expect((await engine.client.call("vault.runners.seats.quotas", seats)).quotas).toEqual([neverRecorded]);

  // The source vault keeps its own counter: a reset on restore, not a loss.
  await stopForOwnerCli(engine);
  await configureStoppedFixture(engine, { vaultPath: resolve(engine.root, "vault") });
  await engine.restart();
  expect((await engine.client.call("vault.budgets.local", budget)).counter).toMatchObject(sourceCounter);
  await engine.close();
});

// PORTABILITY-03 — Import trust and review should work.
// G02: use actual archive exports, not a hand-made JSON vault document. Own,
// foreign and synthetic platform inputs need separate destination vaults.
// Canon's verdict distinguishes ByteFaithfulOwnerRestore, ForeignAuthorityChain
// and ReviewRequired, with mismatches, provenance and a receipted decision.
// Main's same-chain manifest is unsigned (UnauthenticatedProvenance), and
// `import archive <path>` exposes neither that verdict nor a review handle.
// Platform import has review.run_id/run_ref; runs show/approve/decline uses
// the exact bundle id, but it cannot authenticate an owner archive. Wait for
// the typed archive admission/classification/review call, then verify Imported
// + Proposed before review, approval/decline receipts, recall isolation, and
// no reproposal after the same declined evidence is imported again.
suite.todo(test, "PORTABILITY-03", "waits on signed owner-export provenance and typed archive import classification/review HTTP and SDK calls");

// PORTABILITY-04 — Partial import recovery should work.
// Required typed workflow: start(source,input) -> import/run reference;
// observe -> acknowledged stage, explicit failed stage and checkpoint;
// resume(checkpoint) -> same source identities and one pending review bundle.
// These are semantic shape requirements, NOT invented route/verb names.
// Use shared-notes-archive plus a scripted parser failure and a provider
// barrier; interrupt only after the public stage ACK, restart and resume.
// Compare source/native ids and authored counts before/after, and require
// imported claims to remain Proposed. consolidation.status/enqueue are not
// import stage status/resume and cannot substitute for the missing doors.
suite.todo(test, "PORTABILITY-04", "waits on typed import stage acknowledgement, parser-failure status, checkpoint and resume calls");

// PORTABILITY-05 — Canonical recovery from supplied snapshot should work.
// Required input: an authorized, same-build canonical snapshot + destination;
// result: validated integrity, rebuilt authoritative records/redactions and a
// recovery receipt. A damaged copy must leave existing good state unchanged.
// Main's `recover-window <YYYY-MM[@world]> [--rebootstrap]` returns
// {window,tier,manifest,quarantined,rebuilt}; it captures the stopped vault's
// own CRDT state in memory. It accepts no supplied snapshot or destination.
// Do not seed a snapshot by reading LMDB/Loro, corrupt private files, or turn
// this into an old-format migration test. No on-disk fake snapshot is supplied.
suite.todo(test, "PORTABILITY-05", "waits on authorized supplied canonical snapshot input and destination for recover-window");

suite.test(test, "PORTABILITY-06", "Encrypted backup and wrong-key refusal should work", async () => {
  const catalog = await loadFixtures();
  const facts = await catalog.readJson<Facts>("portability-facts");
  const note = new TextDecoder().decode(await catalog.readArchive("portability-owner-note"));
  const blob = await catalog.readArchive("portability-attachment");
  expect(createHash("sha256").update(blob).digest("hex")).toBe(facts.attachment.sha256);
  expect(blob.byteLength).toBe(facts.attachment.bytes);

  const engine = await EngineFixture.start({ id: "PORTABILITY-06", profile });
  await stopForOwnerCli(engine);
  // Linux platform keystore is isolated under this fixture, outside the vault.
  await configureStoppedFixture(engine, { platformKeystore: true });
  await engine.restart();

  const key = secretHex();
  const wrongKey = secretHex();
  redactor.add(key); redactor.add(wrongKey);
  expect(wrongKey === key).toBe(false);
  const credential = "portability-fixture-passkey"; // A label, not secret key material.
  const saved = await engine.client.call("self.memory.diary", { content: note });
  // The diary answers a write marker, not a gate receipt: read the entry back.
  expect((await engine.client.call("vault.get", { entity_ref: saved.entry_id })).value).not.toBeNull();
  const artifact = await engine.client.call("vault.artifacts.create", {
    name: facts.attachment.name, media_type: facts.attachment.mediaType,
    content_base64: Buffer.from(blob).toString("base64"),
  });
  if (!artifact) throw new Error("Fixture attachment was not created");
  await expectDiary(engine, facts.owner.query, saved.entry_id, note);
  await expectBlob(engine, artifact.artifact_id, blob);

  await engine.client.request("POST", "/v1/owner/vault-key/passkeys", { credential, prf: key });
  const signer = (await engine.client.request<SignerPin>("GET", "/v1/owner/vault-key/signer")).body;
  const trustFile = resolve(engine.root, "checkpoint-signers.json");
  await writeFile(trustFile, JSON.stringify(signer), { mode: 0o600 });
  const backup = (await engine.client.request<BackupOutcome>("POST", "/v1/owner/backups")).body;
  expect(backup.backup.bytes).toBeGreaterThan(0);
  const carrier = await readFile(backup.backup.path);
  expect(carrier.includes(Buffer.from(facts.owner.query))).toBe(false);
  expect(carrier.includes(Buffer.from(key))).toBe(false);
  expect(carrier.includes(Buffer.from(key, "hex"))).toBe(false);
  const carrierDigest = createHash("sha256").update(carrier).digest("hex");

  // This later, acknowledged write distinguishes refusal from an unnoticed
  // replacement by the older backup. No private storage inspection is needed.
  const later = await engine.client.call("self.memory.diary", { content: facts.owner.afterBackup });
  expect((await engine.client.call("vault.get", { entity_ref: later.entry_id })).value).not.toBeNull();
  await stopForOwnerCli(engine);
  const unlockArgs = ["--unlock", "passkey", "--credential", credential, "--trust", trustFile];
  const refused = await engine.cli.run([
    "restore", backup.backup.path, ...unlockArgs, ...ownerArgs(engine),
  ], wrongKey, undefined, true);
  expect(refused.exitCode).not.toBe(0);
  expect(refused.signal).toBeNull();
  await engine.restart();
  await expectDiary(engine, facts.owner.query, saved.entry_id, note);
  await expectDiary(engine, facts.owner.afterBackupQuery, later.entry_id, facts.owner.afterBackup);
  await expectBlob(engine, artifact.artifact_id, blob);

  await stopForOwnerCli(engine);
  const destination = resolve(engine.root, "restored-vault");
  const restoreArgs = ["restore", backup.backup.path, ...unlockArgs,
    "--vault-path", destination, ...ownerArgs(engine)];
  const refusedFresh = await engine.cli.run(restoreArgs, wrongKey, undefined, true);
  expect(refusedFresh.exitCode).not.toBe(0);
  expect(refusedFresh.signal).toBeNull();
  expect(await readdir(engine.root)).not.toContain("restored-vault");
  // Identical command and destination, only the private PRF input changes.
  const restored = await engine.cli.run(restoreArgs, key, undefined, true);
  expect(restored.exitCode).toBe(0);
  expect(restored.signal).toBeNull();
  const receipt = JSON.parse(restored.stdout) as FreshRestore;
  expect(receipt.checkpoint_id).toBe(backup.checkpoint_id);
  expect(receipt.vault).toBe(destination);
  expect(receipt.unlocked_with).toBe(`passkey:${credential}`);
  const identity = await engine.cli.json<{ owner_principal: string }>([
    "whoami", destination, ...ownerArgs(engine),
  ]);
  expect(identity.owner_principal).toBe(engine.pairedActor.principalRef);

  await configureStoppedFixture(engine, { vaultPath: destination });
  await engine.restart(); // The original paired owner must authenticate the restored vault.
  await expectDiary(engine, facts.owner.query, saved.entry_id, note);
  await expectBlob(engine, artifact.artifact_id, blob);
  const notBackedUp = await engine.client.call("vault.recall", {
    query: facts.owner.afterBackupQuery, effort: "light", limit: 20,
  });
  expect(notBackedUp.items.some(item => item.value_text.includes(facts.owner.afterBackupQuery))).toBe(false);
  const status = (await engine.client.request<OwnerStatus>("GET", "/v1/owner/status")).body;
  expect(status.location.vault).toBe(destination);
  expect(status.location.backups.restores).toEqual(expect.arrayContaining([
    expect.objectContaining({ checkpoint_id: backup.checkpoint_id, reason: "restore" }),
  ]));
  expect(createHash("sha256").update(await readFile(backup.backup.path)).digest("hex")).toBe(carrierDigest);
  await engine.close();
});

suite.test(test, "PORTABILITY-07", "Folder source rescan lifecycle should work", async () => {
  const catalog = await loadFixtures();
  const facts = (await catalog.readJson<Facts>("portability-facts")).folder;
  const firstText = await catalog.readArchive("portability-folder-first");
  const secondText = await catalog.readArchive("portability-folder-second");
  const editedText = await catalog.readArchive("portability-folder-second-edited");
  const thirdText = await catalog.readArchive("portability-folder-third");
  const engine = await EngineFixture.start({ id: "PORTABILITY-07", profile });
  const folder = resolve(engine.root, "attached-notes");
  await mkdir(folder, { mode: 0o700 });
  const firstPath = resolve(folder, "first.md");
  const secondPath = resolve(folder, "second.md");
  const thirdPath = resolve(folder, "third.md");
  await writeFile(firstPath, firstText); await writeFile(secondPath, secondText);
  await stopForOwnerCli(engine);
  const [source, attached] = await engine.cli.json<[FolderSource, FolderScan]>([
    "import", "folder", "attach", folder, ...ownerArgs(engine),
  ]);
  expect(source.folder).toBe(folder);
  expect(source.trust).toBe(facts.trust);
  expectScan(attached, facts.attach);
  await engine.restart();
  const first = sourceId(await recallItem(engine, facts.firstQuery));
  const secondItem = await recallItem(engine, facts.secondQuery);
  const second = sourceId(secondItem);
  if (!secondItem.source_revision_ref) throw new Error("Source version has no public revision pin");
  const previousRef = `${secondItem.short_id}@${secondItem.source_revision_ref}`;

  await writeFile(thirdPath, thirdText);
  await stopForOwnerCli(engine);
  await rescanFolder(engine, folder, facts.add);
  await engine.restart();
  const third = sourceId(await recallItem(engine, facts.thirdQuery));
  expect(new Set([first, second, third]).size).toBe(facts.finalFiles);

  await writeFile(secondPath, editedText);
  await stopForOwnerCli(engine);
  await rescanFolder(engine, folder, facts.edit);
  await engine.restart();
  expect(sourceId(await recallItem(engine, facts.editedQuery))).toBe(second);
  const current = await engine.client.call("vault.get", { entity_ref: second });
  expect(current.value?.body).toMatchObject({ markdown: new TextDecoder().decode(editedText) });
  // Read the old source through its actual public revision pin, not a saved
  // response, derived id, direct document store or an invented history API.
  const history = (await engine.client.request<{
    status: string; id?: string; item?: { markdown: string };
  }>("POST", "/v1/core/hydrate", { ref: previousRef, view: "full" })).body;
  expect(history.status).toBe("live");
  expect(history.id).toBe(second);
  expect(history.item?.markdown).toBe(new TextDecoder().decode(secondText));

  await rm(firstPath);
  await stopForOwnerCli(engine);
  await rescanFolder(engine, folder, facts.remove);
  const listing = await engine.cli.json<FolderListing[]>(["import", "folder", "list", ...ownerArgs(engine)]);
  expect(listing).toHaveLength(1);
  expect(listing[0]).toMatchObject({ folder, trust: facts.trust, files: facts.finalFiles, retracted: 1, proposed: 0 });
  expect(listing[0]!.last_rescan_at).not.toBeNull();
  await engine.restart();
  expect((await engine.client.call("vault.notes.lifecycle", { note_ref: first })).status).toBe("archived");
  const removed = await engine.client.call("vault.recall", { query: facts.firstQuery, effort: "light", limit: 20 });
  expect(removed.items.some(item => item.provenance.source_revision_ids.includes(first))).toBe(false);
  expect(sourceId(await recallItem(engine, facts.editedQuery))).toBe(second);
  expect(sourceId(await recallItem(engine, facts.thirdQuery))).toBe(third);

  // Bringing back the source proves retraction retained the original note;
  // an erase-and-mint implementation cannot pass this identity/lifecycle check.
  await writeFile(firstPath, firstText);
  await stopForOwnerCli(engine);
  await rescanFolder(engine, folder, facts.restore);
  await engine.restart();
  expect(sourceId(await recallItem(engine, facts.firstQuery))).toBe(first);
  expect((await engine.client.call("vault.notes.lifecycle", { note_ref: first })).status).toBe("active");
  expect((await readdir(folder)).sort()).toEqual(["first.md", "second.md", "third.md"]);
  const firstBytes: Uint8Array = new Uint8Array(await readFile(firstPath));
  expect(firstBytes).toEqual(firstText);
  const secondBytes: Uint8Array = new Uint8Array(await readFile(secondPath));
  expect(secondBytes).toEqual(editedText);
  const thirdBytes: Uint8Array = new Uint8Array(await readFile(thirdPath));
  expect(thirdBytes).toEqual(thirdText);
  await engine.close();
});

// PORTABILITY-08 — Web fetch and bounded crawl should work.
// Canon's FetchResult = {markdown:string,title:string,canonical_url:string,
// fetched_at:number,content_hash:string,renderer:string}. Crawl is a DISTINCT
// typed call with seed_url + explicit page_budget (fixture: 2), same-site by
// default, returning pages:FetchResult[], failures and a completion marker.
// Required fixture: two loopback origins; root links to same-origin pages,
// an off-origin page and duplicate source URLs; a scripted parser supplies
// independently authored markdown. Assert fetch touches one page, crawl's
// bound and origin fence, retained canonical identity/hash across retry, and
// Imported/Proposed claims with no new authority. Do not route them
// through execute_code, connector.call or an engine import as an escape hatch.
// Written by OPUS-E2E-2 on main e79eb76df3e. Not proved here: reading the
// Imported/Proposed web.page claims back, and the MCP tools.
// Doors: fetch({url}) -> FetchResult and crawl({seed_url, page_budget, scope?})
// -> {pages, failed, completion}. A self-hosted node fetches loopback origins
// like any other; each page carries well over the 256-byte extraction floor.
type WebPage = { title: string; body: string; links?: string[]; redirect?: string; status?: number };
interface WebOrigin { url: string; seen: string[] }

function pageHtml(page: WebPage): string {
  const links = (page.links ?? []).map(href => `<a href="${href}">${href}</a>`).join(", ");
  // A page with no body is deliberately thin: under the extraction floor.
  const text = page.body ? [0, 1, 2].map(n => `<p>${page.body} Paragraph ${n} keeps the readable text above the extraction floor.</p>`).join("")
    + `<p>Further reading: ${links}.</p>` : "";
  return `<!doctype html><html><head><title>${page.title}</title></head><body><article><h1>${page.title}</h1>${text}</article></body></html>`;
}

/** One loopback origin on an ephemeral port that logs every path it is asked for. */
function webOrigin(pages: Record<string, WebPage>): WebOrigin {
  const seen: string[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1", port: 0,
    fetch: request => {
      const path = new URL(request.url).pathname;
      seen.push(path);
      const page = pages[path];
      if (!page) return new Response("missing", { status: 404 });
      if (page.redirect) return new Response(null, { status: 302, headers: { location: page.redirect } });
      return new Response(pageHtml(page), { status: page.status ?? 200, headers: { "content-type": "text/html; charset=utf-8" } });
    },
  });
  ownResource(() => server.stop(true));
  if (!server.port) throw new Error("Loopback web origin bound no port");
  return { url: `http://127.0.0.1:${server.port}`, seen };
}

function fetchedPage(result: FacadeResult<"fetch">, url: string, page: WebPage): void {
  expect(Object.keys(result).sort()).toEqual(["canonical_url", "content_hash", "fetched_at", "markdown", "renderer", "title"]);
  expect(result.canonical_url).toBe(url);
  expect(result.title).toBe(page.title);
  // Readability markdown escapes punctuation (`.` as `\\.`); compare the text it carries.
  expect(result.markdown.replace(/\\(.)/g, "$1")).toContain(page.body);
  expect(result.content_hash).toMatch(/^[a-f0-9]{64}$/);
  expect(result.renderer).toBe("readability");
}

suite.test(test, "PORTABILITY-08", "Web fetch and bounded crawl should work", async () => {
  const offSite = webOrigin({
    "/elsewhere": { title: "Elsewhere", body: "The off-site page a same-site crawl must never contact." },
  });
  const pages: Record<string, WebPage> = {
    "/": { title: "Harbour index", body: "The harbour index lists the tide tables and the ferry notes.",
      links: ["/tides", "/ferry", "/tides#today", `${offSite.url}/elsewhere`, "/moved"] },
    "/tides": { title: "Tide tables", body: "High water at the north quay comes forty minutes after the south quay.",
      links: ["/charts", "/"] },
    "/ferry": { title: "Ferry notes", body: "The morning ferry leaves from the south quay and carries no cars.",
      links: ["/tides"] },
    "/charts": { title: "Harbour charts", body: "The charts mark the sand bar that shifts with each spring tide." },
    "/moved": { title: "Moved", body: "", redirect: `${offSite.url}/elsewhere` },
    "/thin": { title: "Thin", body: "" },
  };
  const site = webOrigin(pages);
  const engine = await EngineFixture.start({ id: "PORTABILITY-08", profile });
  const auditBefore = await engine.client.call("vault.authority.audit", { limit: 500 });

  // fetch touches exactly the one page it names, and a retry keeps its identity.
  const tidesUrl = `${site.url}/tides`;
  const first = await engine.client.call("fetch", { url: tidesUrl });
  fetchedPage(first, tidesUrl, pages["/tides"]!);
  expect(site.seen).toEqual(["/tides"]);
  const retried = await engine.client.call("fetch", { url: `${tidesUrl}#again` });
  fetchedPage(retried, tidesUrl, pages["/tides"]!);
  expect(retried.content_hash).toBe(first.content_hash);
  expect(retried.markdown).toBe(first.markdown);
  expect(site.seen).toEqual(["/tides", "/tides"]);

  // crawl spends exactly its page budget and names what it left unvisited.
  // Its frontier is breadth-first over each page's sorted, de-duplicated
  // same-site links: after "/" come /ferry, /moved and /tides.
  site.seen.length = 0;
  const bounded = await engine.client.call("crawl", { seed_url: `${site.url}/`, page_budget: 2 });
  expect(bounded.pages.map(page => page.canonical_url)).toEqual([`${site.url}/`, `${site.url}/ferry`]);
  expect(bounded.failed).toEqual([]);
  expect(bounded.completion.status).toBe("budget_exhausted");
  if (bounded.completion.status !== "budget_exhausted") throw new Error("Expected an exhausted crawl budget");
  expect([...bounded.completion.unvisited_urls].sort()).toEqual([`${site.url}/moved`, tidesUrl].sort());
  expect(site.seen).toEqual(["/", "/ferry"]);

  // With room to finish, every same-site page lands once despite duplicate
  // links. The off-site link and the cross-site redirect never reach the other origin.
  site.seen.length = 0;
  const complete = await engine.client.call("crawl", { seed_url: `${site.url}/`, page_budget: 10 });
  expect(complete.completion).toEqual({ status: "complete" });
  expect(complete.pages.map(page => page.canonical_url).sort())
    .toEqual(["/", "/charts", "/ferry", "/tides"].map(path => `${site.url}${path}`).sort());
  for (const page of complete.pages) fetchedPage(page, page.canonical_url, pages[new URL(page.canonical_url).pathname]!);
  expect(complete.pages.find(page => page.canonical_url === tidesUrl)?.content_hash).toBe(first.content_hash);
  expect(complete.failed).toEqual([{ url: `${site.url}/moved`, reason: "cross_site_redirect" }]);
  expect([...site.seen].sort()).toEqual(["/", "/charts", "/ferry", "/moved", "/tides"]);
  expect(offSite.seen).toEqual([]);

  // Refusals: no budget, a non-web scheme, embedded credentials, a page with
  // nothing readable and a missing page. None of them writes authority.
  const refused = async (verb: "fetch" | "crawl", input: unknown) => {
    const reply = await engine.client.raw<{ error: { code: string } }>("POST", `/v1/core/facade/${verb}`, input);
    return { status: reply.status, code: reply.body.error.code };
  };
  const badRequest = { status: 400, code: "BAD_REQUEST" };
  expect(await refused("crawl", { seed_url: `${site.url}/`, page_budget: 0 })).toEqual(badRequest);
  expect(await refused("fetch", { url: `ftp://127.0.0.1/${secretHex(4)}` })).toEqual(badRequest);
  expect(await refused("fetch", { url: tidesUrl.replace("http://", "http://reader:secret@") })).toEqual(badRequest);
  const unreadable = { status: 500, code: "WEB_FETCH_FAILED" };
  expect(await refused("fetch", { url: `${site.url}/thin` })).toEqual(unreadable);
  expect(await refused("fetch", { url: `${site.url}/absent` })).toEqual(unreadable);
  expect(offSite.seen).toEqual([]);

  // Imported web pages are evidence, not authority: the signed log is unchanged.
  const auditAfter = await engine.client.call("vault.authority.audit", { limit: 500 });
  expect(auditAfter.rows.map(row => row.entry_hash)).toEqual(auditBefore.rows.map(row => row.entry_hash));
});
