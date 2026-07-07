/**
 * Version scrubber over an artifact's version chain (OF-368 D1 + D7).
 *
 * The chain and the between-version edit-manifests live engine-side; this
 * controller navigates them and projects the selected version's diff against
 * its predecessor using {@link diffManifest} — manifest ops only, never a
 * binary re-parse. Like the comment overlay, it holds no engine state of its
 * own beyond a render snapshot pulled from the {@link VersionChainClient}.
 *
 * RECONCILIATION SEAM: bind {@link VersionChainClient} to the engine's blob
 * artifact + LEDGER surface (OF-320 version chain; ARTL-3 `EditProposal.run_ref`
 * / `BlobVersionProvenance::AgentRun`). {@link InMemoryVersionChainClient}
 * stands in for the engine in tests and the MVP.
 */
import { diffManifest, type ManifestDiff } from "../manifest/diff";
import type { EditManifest } from "../manifest/types";
import type { EntityId } from "../annotations/types";

/** OF-368 D1 per-version provenance: user upload OR agent run. */
export type VersionProvenance =
  | { readonly kind: "user-upload" }
  | { readonly kind: "agent-run"; readonly runRef: string };

/** One node in the artifact's version chain. */
export interface ArtifactVersion {
  readonly version: number;
  /** Content hash of the blob at this version. */
  readonly hash: string;
  readonly provenance: VersionProvenance;
  /** Engine clock (u64) the version was committed at. */
  readonly committedAt: number;
}

export interface VersionChainClient {
  /** Versions in ascending order (1..N). */
  versions(artifactId: EntityId): Promise<ArtifactVersion[]>;
  /**
   * The edit-manifest that produced `toVersion` from `fromVersion`, or null if
   * the step has no manifest (e.g. a user re-upload rather than an agent run).
   */
  manifestBetween(
    artifactId: EntityId,
    fromVersion: number,
    toVersion: number,
  ): Promise<EditManifest | null>;
  /** The blob bytes at a version (for the bridge to parse). */
  blobBytes(artifactId: EntityId, version: number): Promise<Uint8Array>;
}

export class VersionScrubber {
  private chain: ArtifactVersion[] = [];
  private cursor = -1;

  constructor(
    private readonly client: VersionChainClient,
    private readonly artifactId: EntityId,
  ) {}

  /** Load the chain and position the cursor at the latest version. */
  async load(): Promise<ArtifactVersion[]> {
    this.chain = [...(await this.client.versions(this.artifactId))].sort((a, b) => a.version - b.version);
    this.cursor = this.chain.length - 1;
    return this.chain;
  }

  versions(): readonly ArtifactVersion[] {
    return this.chain;
  }

  count(): number {
    return this.chain.length;
  }

  index(): number {
    return this.cursor;
  }

  current(): ArtifactVersion | null {
    return this.chain[this.cursor] ?? null;
  }

  previous(): ArtifactVersion | null {
    return this.cursor > 0 ? (this.chain[this.cursor - 1] ?? null) : null;
  }

  select(version: number): ArtifactVersion | null {
    const idx = this.chain.findIndex((v) => v.version === version);
    if (idx >= 0) {
      this.cursor = idx;
    }
    return this.current();
  }

  selectIndex(index: number): ArtifactVersion | null {
    if (index >= 0 && index < this.chain.length) {
      this.cursor = index;
    }
    return this.current();
  }

  next(): ArtifactVersion | null {
    if (this.cursor < this.chain.length - 1) {
      this.cursor += 1;
    }
    return this.current();
  }

  prev(): ArtifactVersion | null {
    if (this.cursor > 0) {
      this.cursor -= 1;
    }
    return this.current();
  }

  first(): ArtifactVersion | null {
    this.cursor = this.chain.length > 0 ? 0 : -1;
    return this.current();
  }

  last(): ArtifactVersion | null {
    this.cursor = this.chain.length - 1;
    return this.current();
  }

  /** Bytes for the selected version, for the bridge to mount. */
  currentBytes(): Promise<Uint8Array> {
    const cur = this.current();
    if (!cur) {
      return Promise.reject(new Error("no version selected"));
    }
    return this.client.blobBytes(this.artifactId, cur.version);
  }

  /**
   * Diff of the selected version against its predecessor, computed from the
   * edit-manifest only. Null at the first version or when the step has no
   * manifest (e.g. a plain re-upload).
   */
  async diffToPrevious(): Promise<ManifestDiff | null> {
    const cur = this.current();
    const prev = this.previous();
    if (!cur || !prev) {
      return null;
    }
    const manifest = await this.client.manifestBetween(this.artifactId, prev.version, cur.version);
    return manifest ? diffManifest(manifest) : null;
  }
}

/** In-memory engine stand-in for the version chain (tests + MVP). */
export class InMemoryVersionChainClient implements VersionChainClient {
  private readonly chains = new Map<EntityId, ArtifactVersion[]>();
  private readonly manifests = new Map<string, EditManifest>();
  private readonly blobs = new Map<string, Uint8Array>();

  addVersion(artifactId: EntityId, version: ArtifactVersion, bytes: Uint8Array): void {
    const chain = this.chains.get(artifactId) ?? [];
    chain.push(version);
    this.chains.set(artifactId, chain);
    this.blobs.set(`${artifactId}@${version.version}`, bytes);
  }

  setManifest(artifactId: EntityId, fromVersion: number, toVersion: number, manifest: EditManifest): void {
    this.manifests.set(`${artifactId}:${fromVersion}->${toVersion}`, manifest);
  }

  versions(artifactId: EntityId): Promise<ArtifactVersion[]> {
    return Promise.resolve([...(this.chains.get(artifactId) ?? [])]);
  }

  manifestBetween(artifactId: EntityId, fromVersion: number, toVersion: number): Promise<EditManifest | null> {
    return Promise.resolve(this.manifests.get(`${artifactId}:${fromVersion}->${toVersion}`) ?? null);
  }

  blobBytes(artifactId: EntityId, version: number): Promise<Uint8Array> {
    const bytes = this.blobs.get(`${artifactId}@${version}`);
    return bytes ? Promise.resolve(bytes) : Promise.reject(new Error(`no blob for ${artifactId}@${version}`));
  }
}
