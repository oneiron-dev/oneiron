/**
 * `CommentOverlayController` — binds a viewer session to an artifact's comment
 * threads and projects them onto grid cells. It is the D3 guarantee made
 * concrete: it holds NO comment state of its own. Every read is served from the
 * {@link AnnotationClient} (the engine); the only thing kept in memory is a
 * render snapshot of thread *heads* returned by the client, refreshed after
 * each mutation. A "restarted" viewer is just a new controller over the same
 * client, and it recovers everything from the engine.
 */
import { parseA1Range, type CellRange } from "../a1";
import type { AnnotationClient } from "./client";
import { threadsAtVersion } from "./client";
import { isDrifted } from "./types";
import type {
  Anchor,
  AnnotationComment,
  AnnotationThread,
  EntityId,
  Locator,
  TaskBrief,
  ThreadState,
  WriteActor,
} from "./types";

/** A thread pinned to a grid region on a specific sheet. */
export interface CommentAnchorPin {
  readonly threadId: EntityId;
  readonly sheet: string;
  readonly range: CellRange;
  readonly state: ThreadState;
  readonly drifted: boolean;
}

export class CommentOverlayController {
  /** Render snapshot of thread HEADS (engine-owned data), not authored state. */
  private snapshot: AnnotationThread[] = [];

  constructor(
    private readonly client: AnnotationClient,
    private readonly artifactId: EntityId,
  ) {}

  /** Refresh the head snapshot from the engine. Returns the current heads. */
  async loadThreads(): Promise<AnnotationThread[]> {
    this.snapshot = await this.client.listThreads(this.artifactId);
    return this.snapshot;
  }

  /** Heads snapshot (may be stale until {@link loadThreads}). Never authored locally. */
  threads(): readonly AnnotationThread[] {
    return this.snapshot;
  }

  /**
   * The viewer buffers no comments; there is nothing to flush. Present so the
   * "zero local state" contract is explicit and testable.
   */
  pendingLocalComments(): readonly AnnotationComment[] {
    return [];
  }

  /** Comment bodies always come straight from the engine, never a local cache. */
  comments(threadId: EntityId): Promise<AnnotationComment[]> {
    return this.client.threadComments(this.artifactId, threadId);
  }

  /** Threads whose xlsx locator lands on `sheetName`, projected to grid pins. */
  pinsForSheet(sheetName: string, version?: number): CommentAnchorPin[] {
    const scoped = version === undefined ? this.snapshot : threadsAtVersion(this.snapshot, version);
    const pins: CommentAnchorPin[] = [];
    for (const thread of scoped) {
      const loc = thread.anchor.locator;
      if (loc.format !== "xlsx" || loc.sheet !== sheetName) {
        continue;
      }
      pins.push({
        threadId: thread.threadId,
        sheet: loc.sheet,
        range: parseA1Range(loc.range),
        state: thread.state,
        drifted: isDrifted(thread),
      });
    }
    return pins;
  }

  async openThread(anchor: Anchor, author: WriteActor, firstComment: string): Promise<AnnotationThread> {
    const thread = await this.client.openThread(anchor, author, firstComment);
    await this.loadThreads();
    return thread;
  }

  async addComment(threadId: EntityId, author: WriteActor, text: string): Promise<AnnotationComment> {
    const comment = await this.client.addComment(this.artifactId, threadId, author, text);
    await this.loadThreads();
    return comment;
  }

  async resolve(threadId: EntityId, actor: WriteActor): Promise<AnnotationThread> {
    return this.setState(threadId, "resolved", actor);
  }

  async reopen(threadId: EntityId, actor: WriteActor): Promise<AnnotationThread> {
    return this.setState(threadId, "open", actor);
  }

  private async setState(
    threadId: EntityId,
    state: ThreadState,
    actor: WriteActor,
  ): Promise<AnnotationThread> {
    const head = await this.client.setThreadState(this.artifactId, threadId, state, actor);
    await this.loadThreads();
    return head;
  }

  assign(threadId: EntityId, assignee: EntityId | undefined, actor: WriteActor): Promise<TaskBrief> {
    return this.client.assignThreadToBrief(this.artifactId, threadId, assignee, actor);
  }

  /** Build an xlsx anchor for a selection on the active version. */
  static xlsxAnchor(artifactId: EntityId, version: number, sheet: string, a1Range: string): Anchor {
    const locator: Locator = { format: "xlsx", sheet, range: a1Range };
    return { artifactId, version, locator };
  }

  /** Drop the render snapshot; the engine keeps the data. */
  dispose(): void {
    this.snapshot = [];
  }
}
