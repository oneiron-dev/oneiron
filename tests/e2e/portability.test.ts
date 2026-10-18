import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { loadFixtures } from "./support/fixtures.ts";
import { defineFile, redactor, secretHex } from "./support/run.ts";

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
const ownershipExport: FacadeInput<"vault.export"> = { format: "archive", include_secrets: false };
void ownershipExport;
suite.todo(test, "PORTABILITY-01", "waits on deterministic public all-family vault fixture with on-record/off-record result bodies and custody sentinel");

// PORTABILITY-02 — Owner same-build restore should work.
// Available typed public shapes are BackupOutcome, FreshRestore, SignerPin,
// OwnerStatus above, plus vault.recall and the artifact download route.
// Required flow: populate, spend a local runner budget, back up; stop, restore
// into an absent destination, serve with the same owner, recall known text and
// download the exact fixture bytes; observe rebuilt retrieval and a matching
// RESTORE epoch. The budget must demonstrably reset, not merely be omitted
// from export. Neither owner/status nor run-tree exposes that local counter.
// PORTABILITY-06 exercises the available backup/restore/content portion; that
// does not make this ID's missing budget assertion passing coverage.
suite.todo(test, "PORTABILITY-02", "waits on typed public local runner budget observation for restore-reset verification");

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
  await engine.awaitReceipt(saved.receipt_ref);
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
  await engine.awaitReceipt(later.receipt_ref);
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
  expect(new Uint8Array(await readFile(firstPath))).toEqual(firstText);
  expect(new Uint8Array(await readFile(secondPath))).toEqual(editedText);
  expect(new Uint8Array(await readFile(thirdPath))).toEqual(thirdText);
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
// Imported/Proposed claims with no new authority. Main's web_fetch.rs types
// have no server use, generated facade verb or MCP tool. Do not route them
// through execute_code, connector.call or an engine import as an escape hatch.
suite.todo(test, "PORTABILITY-08", "waits on distinct typed web fetch and bounded crawl HTTP/SDK calls and MCP tools");
