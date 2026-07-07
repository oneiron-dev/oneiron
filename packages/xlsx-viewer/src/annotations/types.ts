/**
 * TypeScript mirror of ARTL-2 (ONE-1552) `anchored_annotation` shapes.
 *
 * RECONCILIATION SEAM — these types mirror the Rust `anchored_annotation`
 * module as of the ONE-1552 worktree; ONE-1552's PR is not merged yet. They are
 * the wire contract for {@link AnnotationClient}. When ONE-1552 lands, bind the
 * client to the real engine (napi/FFI) surface and re-derive these against the
 * generated bindings.
 *
 * Engine identity fields (`EntityId`) are 16 raw bytes on the MessagePack wire;
 * on this side we carry them as lowercase-hex strings and let the concrete
 * client (napi/JSON) decide the encoding at the boundary.
 */

/** 32-char lowercase hex of a 16-byte engine `EntityId`. */
export type EntityId = string & { readonly __brand: "EntityId" };

export function entityId(hex: string): EntityId {
  if (!/^[0-9a-f]{32}$/.test(hex)) {
    throw new Error(`invalid EntityId (want 32 lowercase hex chars): ${JSON.stringify(hex)}`);
  }
  return hex as EntityId;
}

/** ARTL-2 `Locator` — format-typed position within an artifact version. */
export type Locator =
  | { readonly format: "xlsx"; readonly sheet: string; readonly range: string }
  | {
      readonly format: "docx";
      readonly paraPath: string;
      readonly charStart: number;
      readonly charEnd: number;
    }
  | { readonly format: "pptx"; readonly slide: number; readonly shapeId: string };

/** ARTL-2 `Anchor` — binds (artifact_id, version, locator). */
export interface Anchor {
  readonly artifactId: EntityId;
  readonly version: number;
  readonly locator: Locator;
}

export type ThreadState = "open" | "resolved";

/** ARTL-2 `DriftMarker` — present when a thread's anchor could not be re-mapped. */
export interface DriftMarker {
  readonly driftedAtVersion: number;
  readonly pinnedVersion: number;
}

/** ARTL-2 thread head (`annotation.thread`). */
export interface AnnotationThread {
  readonly threadId: EntityId;
  readonly anchor: Anchor;
  readonly originVersion: number;
  readonly state: ThreadState;
  /** Present iff the thread is drifted; then `anchor.version` is the origin. */
  readonly drift?: DriftMarker;
  readonly headClaimId: EntityId;
}

export function isDrifted(thread: AnnotationThread): boolean {
  return thread.drift !== undefined;
}

/** ARTL-2 comment (`annotation.comment`, append-only). */
export interface AnnotationComment {
  readonly threadId: EntityId;
  readonly author: EntityId;
  readonly text: string;
  /** Engine clock (u64) at authoring time. */
  readonly at: number;
  readonly claimId: EntityId;
}

/** ARTL-2 task-brief (`annotation.brief`) minted when a thread is assigned. */
export interface TaskBrief {
  readonly briefRef: string;
  readonly taskId: EntityId;
  readonly threadId: EntityId;
  readonly anchor: Anchor;
  readonly artifactVersion: number;
  readonly threadText: string;
  readonly assignee?: EntityId;
}

export type ActorClass = "human" | "agent" | "system";

/** ARTL-2 `WriteActor` — the actor stamped onto an annotation write. */
export interface WriteActor {
  readonly entityRef: EntityId;
  readonly actorClass: ActorClass;
}

/** ARTL-2 comment-size ceiling (`ANNOTATION_COMMENT_TEXT_MAX_BYTES`). */
export const ANNOTATION_COMMENT_TEXT_MAX_BYTES = 16 * 1024;
