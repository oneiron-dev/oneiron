import { describe, expect, it } from "bun:test";
import { InMemoryAnnotationClient, threadsAtVersion } from "../src/annotations/client";
import { CommentOverlayController } from "../src/annotations/overlay";
import { entityId, type AnnotationThread, type WriteActor } from "../src/annotations/types";

const ARTIFACT = entityId("a".repeat(32));
const HUMAN: WriteActor = { entityRef: entityId("b".repeat(32)), actorClass: "human" };
const AGENT: WriteActor = { entityRef: entityId("c".repeat(32)), actorClass: "agent" };

function anchor(version: number, sheet: string, range: string) {
  return CommentOverlayController.xlsxAnchor(ARTIFACT, version, sheet, range);
}

describe("acceptance 2: comments persist engine-side across viewer restart", () => {
  it("a restarted viewer recovers all threads/comments from the engine", async () => {
    const engine = new InMemoryAnnotationClient();

    // Viewer session 1 authors a thread + reply.
    const viewer1 = new CommentOverlayController(engine, ARTIFACT);
    const thread = await viewer1.openThread(anchor(1, "S1", "B2:C4"), HUMAN, "Q3 column looks off");
    await viewer1.addComment(thread.threadId, AGENT, "agreed, recomputing");
    viewer1.dispose(); // viewer dies

    // Viewer session 2 (restart) over the SAME engine.
    const viewer2 = new CommentOverlayController(engine, ARTIFACT);
    expect(viewer2.threads()).toHaveLength(0); // holds nothing until it asks the engine
    await viewer2.loadThreads();
    expect(viewer2.threads()).toHaveLength(1);

    const comments = await viewer2.comments(thread.threadId);
    expect(comments.map((c) => c.text)).toEqual(["Q3 column looks off", "agreed, recomputing"]);
  });

  it("the viewer holds ZERO comment state of its own", async () => {
    const engine = new InMemoryAnnotationClient();
    const viewer = new CommentOverlayController(engine, ARTIFACT);
    const thread = await viewer.openThread(anchor(1, "S1", "B2"), HUMAN, "secret body text");
    await viewer.addComment(thread.threadId, AGENT, "another secret");
    await viewer.loadThreads();

    // Nothing is buffered locally.
    expect(viewer.pendingLocalComments()).toEqual([]);
    // Comment bodies never live in the controller — only in the engine.
    const serialized = JSON.stringify(viewer);
    expect(serialized).not.toContain("secret body text");
    expect(serialized).not.toContain("another secret");

    // A fresh viewer over a DIFFERENT (empty) engine sees nothing.
    const fresh = new CommentOverlayController(new InMemoryAnnotationClient(), ARTIFACT);
    await fresh.loadThreads();
    expect(fresh.threads()).toHaveLength(0);
  });

  it("projects xlsx anchors onto grid pins and reflects state", async () => {
    const engine = new InMemoryAnnotationClient();
    const viewer = new CommentOverlayController(engine, ARTIFACT);
    const t = await viewer.openThread(anchor(1, "S1", "B2:C4"), HUMAN, "hi");
    await viewer.openThread(anchor(1, "S2", "A1"), HUMAN, "other sheet");
    await viewer.loadThreads();

    const pins = viewer.pinsForSheet("S1");
    expect(pins).toHaveLength(1);
    expect(pins[0]!.range).toEqual({ colStart: 2, colEnd: 3, rowStart: 2, rowEnd: 4 });
    expect(pins[0]!.state).toBe("open");
    expect(pins[0]!.drifted).toBe(false);

    await viewer.resolve(t.threadId, HUMAN);
    const resolved = viewer.pinsForSheet("S1");
    expect(resolved[0]!.state).toBe("resolved");
  });

  it("assigns a thread to a task-brief carrying the joined thread text", async () => {
    const engine = new InMemoryAnnotationClient();
    const viewer = new CommentOverlayController(engine, ARTIFACT);
    const t = await viewer.openThread(anchor(2, "S1", "B2"), HUMAN, "please fix");
    await viewer.addComment(t.threadId, HUMAN, "by EOD");
    const brief = await viewer.assign(t.threadId, AGENT.entityRef, HUMAN);
    expect(brief.threadText).toBe("please fix\nby EOD");
    expect(brief.artifactVersion).toBe(2);
    expect(brief.assignee).toBe(AGENT.entityRef);
    expect(brief.briefRef).toContain("brief:");
  });

  it("enforces the comment size ceiling", async () => {
    const engine = new InMemoryAnnotationClient();
    const viewer = new CommentOverlayController(engine, ARTIFACT);
    const tooBig = "x".repeat(16 * 1024 + 1);
    await expect(viewer.openThread(anchor(1, "S1", "A1"), HUMAN, tooBig)).rejects.toThrow();
  });
});

describe("drift-aware version filter (#6)", () => {
  it("still shows a drifted thread at the version it drifted at", () => {
    const drifted: AnnotationThread = {
      threadId: entityId("1".repeat(32)),
      anchor: { artifactId: ARTIFACT, version: 1, locator: { format: "xlsx", sheet: "S1", range: "B2" } },
      originVersion: 1,
      state: "open",
      drift: { driftedAtVersion: 2, pinnedVersion: 1 },
      headClaimId: entityId("2".repeat(32)),
    };
    // anchor.version stays at the origin (1); a naive equality filter would hide
    // it from v2, the very version it drifted at.
    expect(threadsAtVersion([drifted], 1)).toHaveLength(1);
    expect(threadsAtVersion([drifted], 2)).toHaveLength(1);
    expect(threadsAtVersion([drifted], 3)).toHaveLength(0);
  });
});
