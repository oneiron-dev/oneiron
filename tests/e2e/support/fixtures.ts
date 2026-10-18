/** Hash-checked external facts. No vault or engine implementation is imported here. */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, readdir, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import type { Facade } from "@oneiron/client";
import type { PublicHttpClient } from "./clients.ts";

export type Profile = "deterministic" | "real-small-model";
export interface SourcePin { readonly uri: string; readonly revision?: string }
export interface DataFixture<T = unknown> {
  readonly id: string;
  /** Relative to the manifest containing this entry. Symlinks cannot escape fixtures/. */
  readonly path: string;
  readonly source: SourcePin;
  readonly licence: string;
  readonly sha256: string;
  readonly expectedFacts: T;
  readonly scenarios: readonly string[];
  /** Public door names, not implementation feature flags. */
  readonly requires: readonly string[];
}
export interface BinaryRequirement {
  readonly id: string;
  readonly source: SourcePin;
  readonly licence: string;
  readonly pin: "external-build-manifest";
  readonly requiredFor: readonly Profile[];
  readonly expectedFacts: unknown;
}
export interface FixtureManifest {
  readonly version: 1;
  readonly area: string;
  readonly assets: readonly DataFixture[];
  readonly binaries?: readonly BinaryRequirement[];
}
export interface BuildAsset {
  readonly path: string;
  readonly sha256: string;
  readonly source: SourcePin;
  readonly licence: string;
  readonly expectedFacts: unknown;
}
/** Produced off-host by the build/asset lane, never by the suite runner. */
export interface BuildManifest {
  readonly version: 1;
  readonly head: string;
  readonly profile: Profile;
  /** Absolute executable/package/organ paths. Every file is checked before launch. */
  readonly assets: Readonly<Record<string, BuildAsset>>;
  readonly capabilities: readonly string[];
  readonly environment: Readonly<Record<string, string>>;
  /** Linux containment launcher; must exec its argv in this file's CPU/memory/network budget. */
  readonly launcher: readonly string[];
  readonly realModel?: {
    readonly revision: string;
    readonly weights: readonly string[];
    readonly tokenizer: string;
    readonly config: string;
    readonly quantization: string;
    readonly threads: number;
    readonly sampling: Readonly<Record<string, unknown>>;
    readonly bindings: Readonly<Record<string, "real" | "stub">>;
  };
}
export interface PlannedTest { readonly id: string; readonly name: string; readonly rows: readonly string[]; readonly source: readonly string[] }
export interface PlannedFile {
  readonly file: string; readonly area: string; readonly slots: 1 | 2;
  readonly estimatedSeconds: number; readonly tests: readonly PlannedTest[];
}
export interface SuitePlan {
  readonly version: 1;
  readonly source: { readonly bindingHead: string; readonly [key: string]: unknown };
  readonly files: readonly PlannedFile[];
  readonly coverage: readonly { readonly row: string; readonly tests: readonly string[]; readonly disposition: string; readonly limit: string | null }[];
  readonly excludedRows: readonly { readonly row: string; readonly reason: string }[];
  readonly optionalIds: readonly string[];
}
export class FixturePinError extends Error { override name = "FixturePinError" }
const SHA256 = /^[a-f0-9]{64}$/;
export const FIXTURE_ROOT = fileURLToPath(new URL("../fixtures/", import.meta.url));
export const E2E_ROOT = dirname(FIXTURE_ROOT);
export async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}
export async function verifyFile(path: string, digest: string): Promise<void> {
  if (!SHA256.test(digest)) throw new FixturePinError(`Unpinned file: ${path}`);
  if (!(await stat(path)).isFile() || await sha256File(path) !== digest)
    throw new FixturePinError(`Fixture digest mismatch: ${path}`);
}
function inside(base: string, path: string): boolean {
  const rel = relative(base, path);
  return rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}
function assertData(entry: DataFixture): void {
  if (!entry.id || !entry.path || !entry.source?.uri || !entry.licence ||
      !SHA256.test(entry.sha256) || !("expectedFacts" in entry) ||
      !Array.isArray(entry.scenarios) || !Array.isArray(entry.requires))
    throw new FixturePinError("Fixture must declare source, licence, digest, expectedFacts, scenarios and requires");
}
export class FixtureCatalog {
  private constructor(
    readonly manifests: readonly { path: string; sha256: string; value: FixtureManifest }[],
    private readonly entries: ReadonlyMap<string, { entry: DataFixture; path: string }>,
  ) {}
  static async load(base = FIXTURE_ROOT): Promise<FixtureCatalog> {
    const canonicalRoot = await realpath(base);
    const manifests: { path: string; sha256: string; value: FixtureManifest }[] = [];
    const entries = new Map<string, { entry: DataFixture; path: string }>();
    const paths: string[] = [];
    async function walk(dir: string): Promise<void> {
      for (const item of (await readdir(dir, { withFileTypes: true })).sort((a,b) => a.name.localeCompare(b.name))) {
        const path = resolve(dir, item.name);
        if (item.isDirectory()) await walk(path);
        else if (item.name === "manifest.json") paths.push(path);
      }
    }
    await walk(canonicalRoot);
    if (!paths.includes(resolve(canonicalRoot, "manifest.json"))) throw new FixturePinError("Missing shared manifest");
    for (const path of paths) {
      const value = JSON.parse(await readFile(path, "utf8")) as FixtureManifest;
      if (value.version !== 1 || !value.area || !Array.isArray(value.assets)) throw new FixturePinError(`Invalid manifest: ${path}`);
      manifests.push({ path, sha256: await sha256File(path), value });
      for (const entry of value.assets) {
        assertData(entry);
        if (isAbsolute(entry.path)) throw new FixturePinError(`Fixture path must be relative: ${entry.id}`);
        const assetPath = await realpath(resolve(dirname(path), entry.path));
        if (!inside(canonicalRoot, assetPath) || entries.has(entry.id)) throw new FixturePinError(`Escaping or duplicate fixture: ${entry.id}`);
        await verifyFile(assetPath, entry.sha256);
        entries.set(entry.id, { entry, path: assetPath });
      }
    }
    // Refuse forgotten fixture files, not just entries with bad digests.
    async function checkAll(dir: string): Promise<void> {
      for (const item of await readdir(dir, { withFileTypes: true })) {
        const path = resolve(dir, item.name);
        if (item.isDirectory()) await checkAll(path);
        else if (item.name !== "manifest.json" && ![...entries.values()].some(e => e.path === path))
          throw new FixturePinError(`Unlisted fixture file: ${path}`);
      }
    }
    await checkAll(canonicalRoot);
    return new FixtureCatalog(manifests, entries);
  }
  fixture<T = unknown>(id: string): DataFixture<T> {
    const found = this.entries.get(id);
    if (!found) throw new FixturePinError(`Unknown fixture: ${id}`);
    return found.entry as DataFixture<T>;
  }
  /** Facts are independently authored in the area fragment, never inferred from server output. */
  expected<T = unknown>(id: string): T { return this.fixture<T>(id).expectedFacts }
  async readArchive(id: string): Promise<Uint8Array> {
    const found = this.entries.get(id);
    if (!found) throw new FixturePinError(`Unknown fixture: ${id}`);
    await verifyFile(found.path, found.entry.sha256);
    return new Uint8Array(await readFile(found.path));
  }
  async readJson<T = unknown>(id: string): Promise<T> {
    return JSON.parse(new TextDecoder().decode(await this.readArchive(id))) as T;
  }
  scenarioFixtures(testId: string): readonly DataFixture[] {
    return [...this.entries.values()].filter(e => e.entry.scenarios.includes(testId)).map(e => e.entry);
  }
}
export const loadFixtures = FixtureCatalog.load;

/** Fresh-vault claims use base reality, the owner's substrate, all relationships and the default project. */
export async function ownerBaseClaimScope(client: PublicHttpClient, ownerRef: string): Promise<Facade.ClaimScope> {
  const facets = await client.call("vault.neighbors", {
    entity_ref: ownerRef, opts: { edge_kind: "has_facet", limit: 100 },
  });
  for (const facet of facets.value) {
    const { value: row } = await client.call("vault.get", { entity_ref: facet.short_id });
    const body = row?.body;
    if (row?.kind === "FACET" && typeof body === "object" && body !== null
      && "kind" in body && body.kind === "substrate") {
      return {
        world_id: "00000000000000000000000000000001",
        scope_facet_id: row.id_hex,
        scope_relationship_id: "all",
        scope_project_id: "00000000000000000000000000000002",
      };
    }
  }
  throw new FixturePinError("Fresh vault has no readable owner substrate facet");
}

export async function loadBuildManifest(profile: Profile): Promise<BuildManifest> {
  const path = process.env.E2E_BUILD_MANIFEST;
  const digest = process.env.E2E_BUILD_MANIFEST_SHA256;
  if (!path || !isAbsolute(path) || !digest) throw new FixturePinError("Set absolute E2E_BUILD_MANIFEST and its E2E_BUILD_MANIFEST_SHA256 from the build lane");
  await verifyFile(path, digest);
  const value = JSON.parse(await readFile(path, "utf8")) as BuildManifest;
  if (value.version !== 1 || value.profile !== profile || !/^[a-f0-9]{40}$/.test(value.head) ||
      !value.assets || !Array.isArray(value.capabilities) || !Array.isArray(value.launcher) ||
      !value.environment) throw new FixturePinError("Invalid build manifest");
  for (const [id, asset] of Object.entries(value.assets)) {
    if (!isAbsolute(asset.path) || !asset.source?.uri || !asset.source.revision || !asset.licence || !("expectedFacts" in asset))
      throw new FixturePinError(`Missing binary provenance: ${id}`);
    await verifyFile(asset.path, asset.sha256);
  }
  return value;
}
export function requireAsset(build: BuildManifest, id: string): string {
  const asset = build.assets[id];
  if (!asset) throw new FixturePinError(`waits on pinned build asset ${id}`);
  return asset.path;
}
