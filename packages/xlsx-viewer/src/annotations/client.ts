/**
 * `AnnotationClient` — the thin engine-client seam for ARTL-2 comment threads.
 *
 * D3 law: annotations are engine objects (claims), NEVER viewer-local. Every
 * method here maps to a `Vault` call in ONE-1552's `anchored_annotation` module
 * (`open_annotation_thread`, `add_annotation_comment`,
 * `set_annotation_thread_state`, `annotation_threads_for_artifact`,
 * `annotation_thread_comments`, `assign_annotation_thread_to_brief`). The engine
 * supplies provenance, timestamps (`occurred` / `learned_at`), and claim ids;
 * this surface deliberately omits them.
 *
 * RECONCILIATION SEAM: wire the concrete implementation to the engine
 * (napi/FFI) once ONE-1552 merges. {@link InMemoryAnnotationClient} stands in
 * for the engine in tests and in the engine-optional MVP.
 */
import type {
  Anchor,
  AnnotationComment,
  AnnotationThread,
  EntityId,
  TaskBrief,
  ThreadState,
  WriteActor,
} from "./types";
import { ANNOTATION_COMMENT_TEXT_MAX_BYTES } from "./types";

export interface AnnotationClient {
  /** All thread heads for an artifact (engine keys threads by artifact id). */
  listThreads(artifactId: EntityId): Promise<AnnotationThread[]>;
  getThread(artifactId: EntityId, threadId: EntityId): Promise<AnnotationThread | null>;
  /** Comments in a thread, ordered by (`at`, `claimId`). */
  threadComments(artifactId: EntityId, threadId: EntityId): Promise<AnnotationComment[]>;
  openThread(anchor: Anchor, author: WriteActor, firstComment: string): Promise<AnnotationThread>;
  addComment(
    artifactId: EntityId,
    threadId: EntityId,
    author: WriteActor,
    text: string,
  ): Promise<AnnotationComment>;
  setThreadState(
    artifactId: EntityId,
    threadId: EntityId,
    state: ThreadState,
    actor: WriteActor,
  ): Promise<AnnotationThread>;
  assignThreadToBrief(
    artifactId: EntityId,
    threadId: EntityId,
    assignee: EntityId | undefined,
    actor: WriteActor,
  ): Promise<TaskBrief>;
}

/** There is no native "list at version" call — filter heads client-side. */
export function threadsAtVersion(threads: AnnotationThread[], version: number): AnnotationThread[] {
  return threads.filter((t) => t.anchor.version === version);
}

function assertCommentFits(text: string): void {
  const bytes = new TextEncoder().encode(text).length;
  if (bytes === 0) {
    throw new Error("annotation comment text must not be empty");
  }
  if (bytes > ANNOTATION_COMMENT_TEXT_MAX_BYTES) {
    throw new Error(
      `annotation comment text ${bytes}B exceeds ${ANNOTATION_COMMENT_TEXT_MAX_BYTES}B limit`,
    );
  }
}

interface StoredThread {
  head: AnnotationThread;
  comments: AnnotationComment[];
}

/**
 * In-memory engine stand-in. It owns ALL thread/comment state — the viewer owns
 * none — so a "restarted" viewer (new controller over the same client) sees the
 * same threads. Not a persistence layer; a faithful stub of the engine's
 * claim-backed behaviour for tests and the standalone MVP.
 */
export class InMemoryAnnotationClient implements AnnotationClient {
  private readonly byArtifact = new Map<EntityId, Map<EntityId, StoredThread>>();
  private clock = 0;
  private counter = 0;

  constructor(private readonly idFactory: () => EntityId = defaultIdFactory()) {}

  private tick(): number {
    this.clock += 1;
    return this.clock;
  }

  private threadsFor(artifactId: EntityId): Map<EntityId, StoredThread> {
    let m = this.byArtifact.get(artifactId);
    if (!m) {
      m = new Map();
      this.byArtifact.set(artifactId, m);
    }
    return m;
  }

  listThreads(artifactId: EntityId): Promise<AnnotationThread[]> {
    const m = this.byArtifact.get(artifactId);
    return Promise.resolve(m ? [...m.values()].map((s) => s.head) : []);
  }

  getThread(artifactId: EntityId, threadId: EntityId): Promise<AnnotationThread | null> {
    return Promise.resolve(this.byArtifact.get(artifactId)?.get(threadId)?.head ?? null);
  }

  threadComments(artifactId: EntityId, threadId: EntityId): Promise<AnnotationComment[]> {
    const stored = this.byArtifact.get(artifactId)?.get(threadId);
    if (!stored) {
      return Promise.resolve([]);
    }
    const ordered = [...stored.comments].sort((a, b) => a.at - b.at || a.claimId.localeCompare(b.claimId));
    return Promise.resolve(ordered);
  }

  openThread(anchor: Anchor, author: WriteActor, firstComment: string): Promise<AnnotationThread> {
    assertCommentFits(firstComment);
    const threadId = this.idFactory();
    const headClaimId = this.idFactory();
    const head: AnnotationThread = {
      threadId,
      anchor,
      originVersion: anchor.version,
      state: "open",
      headClaimId,
    };
    const at = this.tick();
    const comment: AnnotationComment = {
      threadId,
      author: author.entityRef,
      text: firstComment,
      at,
      claimId: this.idFactory(),
    };
    this.threadsFor(anchor.artifactId).set(threadId, { head, comments: [comment] });
    return Promise.resolve(head);
  }

  addComment(
    artifactId: EntityId,
    threadId: EntityId,
    author: WriteActor,
    text: string,
  ): Promise<AnnotationComment> {
    assertCommentFits(text);
    const stored = this.threadsFor(artifactId).get(threadId);
    if (!stored) {
      return Promise.reject(new Error(`annotation thread not found: ${threadId}`));
    }
    const comment: AnnotationComment = {
      threadId,
      author: author.entityRef,
      text,
      at: this.tick(),
      claimId: this.idFactory(),
    };
    stored.comments.push(comment);
    return Promise.resolve(comment);
  }

  setThreadState(
    artifactId: EntityId,
    threadId: EntityId,
    state: ThreadState,
    _actor: WriteActor,
  ): Promise<AnnotationThread> {
    const stored = this.threadsFor(artifactId).get(threadId);
    if (!stored) {
      return Promise.reject(new Error(`annotation thread not found: ${threadId}`));
    }
    // Supersede the head (new head claim id), exactly one Active head per thread.
    stored.head = { ...stored.head, state, headClaimId: this.idFactory() };
    return Promise.resolve(stored.head);
  }

  assignThreadToBrief(
    artifactId: EntityId,
    threadId: EntityId,
    assignee: EntityId | undefined,
    _actor: WriteActor,
  ): Promise<TaskBrief> {
    const stored = this.threadsFor(artifactId).get(threadId);
    if (!stored) {
      return Promise.reject(new Error(`annotation thread not found: ${threadId}`));
    }
    const threadText = stored.comments.map((c) => c.text).join("\n");
    const brief: TaskBrief = {
      briefRef: `brief:${threadId}`,
      taskId: this.idFactory(),
      threadId,
      anchor: stored.head.anchor,
      artifactVersion: stored.head.anchor.version,
      threadText,
      ...(assignee !== undefined ? { assignee } : {}),
    };
    return Promise.resolve(brief);
  }
}

function defaultIdFactory(): () => EntityId {
  let n = 0;
  return () => {
    n += 1;
    return n.toString(16).padStart(32, "0") as EntityId;
  };
}
