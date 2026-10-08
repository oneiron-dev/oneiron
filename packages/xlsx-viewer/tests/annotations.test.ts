import { describe, expect, it } from "bun:test";
import { threadsAtVersion } from "../src/annotations/client";
import { CommentOverlayController } from "../src/annotations/overlay";
import { entityId, type AnnotationThread, type WriteActor } from "../src/annotations/types";

const ARTIFACT = entityId("a".repeat(32));
const HUMAN: WriteActor = { entityRef: entityId("b".repeat(32)), actorClass: "human" };
const AGENT: WriteActor = { entityRef: entityId("c".repeat(32)), actorClass: "agent" };

function anchor(version: number, sheet: string, range: string) {
  return CommentOverlayController.xlsxAnchor(ARTIFACT, version, sheet, range);
}

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
