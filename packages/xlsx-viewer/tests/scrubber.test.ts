import { describe, expect, it } from "bun:test";
import { entityId } from "../src/annotations/types";
import { InMemoryVersionChainClient, VersionScrubber } from "../src/versions/scrubber";
import { makeXlsxBytes, sampleManifest } from "./helpers";

const ARTIFACT = entityId("d".repeat(32));

function seededClient(): InMemoryVersionChainClient {
  const client = new InMemoryVersionChainClient();
  const bytes = makeXlsxBytes({ sheets: 1, rows: 4, cols: 3 });
  client.addVersion(ARTIFACT, { version: 1, hash: "h1", provenance: { kind: "user-upload" }, committedAt: 10 }, bytes);
  client.addVersion(
    ARTIFACT,
    { version: 2, hash: "h2", provenance: { kind: "agent-run", runRef: "run:abc" }, committedAt: 20 },
    bytes,
  );
  client.setManifest(ARTIFACT, 1, 2, sampleManifest());
  return client;
}

describe("version scrubber", () => {
  it("loads the chain and positions the cursor at the latest version", async () => {
    const scrubber = new VersionScrubber(seededClient(), ARTIFACT);
    await scrubber.load();
    expect(scrubber.count()).toBe(2);
    expect(scrubber.current()?.version).toBe(2);
    expect(scrubber.previous()?.version).toBe(1);
    expect(scrubber.current()?.provenance).toEqual({ kind: "agent-run", runRef: "run:abc" });
  });

  it("diffs the selected version against its predecessor from the manifest only", async () => {
    const scrubber = new VersionScrubber(seededClient(), ARTIFACT);
    await scrubber.load();
    const diff = await scrubber.diffToPrevious();
    expect(diff).not.toBeNull();
    expect(diff!.lines[0]).toBe("set Sheet1!A1: 5 -> 3.5");
  });

  it("has no diff at the first version", async () => {
    const scrubber = new VersionScrubber(seededClient(), ARTIFACT);
    await scrubber.load();
    scrubber.first();
    expect(scrubber.current()?.version).toBe(1);
    expect(await scrubber.diffToPrevious()).toBeNull();
  });

  it("navigates the chain", async () => {
    const scrubber = new VersionScrubber(seededClient(), ARTIFACT);
    await scrubber.load();
    expect(scrubber.prev()?.version).toBe(1);
    expect(scrubber.prev()?.version).toBe(1); // clamped at start
    expect(scrubber.next()?.version).toBe(2);
    expect(scrubber.next()?.version).toBe(2); // clamped at end
    expect(scrubber.select(1)?.version).toBe(1);
    expect(scrubber.selectIndex(1)?.version).toBe(2);
    expect(scrubber.last()?.version).toBe(2);
  });

  it("returns the blob bytes for the selected version", async () => {
    const scrubber = new VersionScrubber(seededClient(), ARTIFACT);
    await scrubber.load();
    const bytes = await scrubber.currentBytes();
    expect(bytes.byteLength).toBeGreaterThan(0);
  });
});
