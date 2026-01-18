/**
 * Message Types
 *
 * Messages are the ground truth - what actually happened.
 * Everything else is derived from messages.
 */

import type {
  ULID,
  ISO8601,
  MessageId,
  ConversationId,
  SessionId,
  TurnId,
  TenantId,
} from "./primitives";
import type { BaseEntity, EntityType } from "./entities";

// ═══════════════════════════════════════════════════════════════
// MESSAGE TYPE
// ═══════════════════════════════════════════════════════════════

export type MessageType =
  // Text-primary
  | "dialogue"
  | "description"
  | "technical"
  | "thinking"
  // Media-primary
  | "image"
  | "voice"
  | "song"
  | "music"
  | "video";

export type MediaMetadata = {
  durationSeconds?: number;
  lyrics?: string;
  genre?: string;
  mood?: string;
  bpm?: number;
  resolution?: string;
  generator?:
    | "suno"
    | "elevenlabs"
    | "sora"
    | "veo3"
    | "dalle"
    | "midjourney"
    | string;
  generationPrompt?: string;
};

// ═══════════════════════════════════════════════════════════════
// MESSAGE (GROUND TRUTH)
// ═══════════════════════════════════════════════════════════════

export type Message = BaseEntity & {
  conversationId: ConversationId;
  sessionId?: SessionId;
  turnId: TurnId;

  speaker: "user" | "eiri";
  type: MessageType;

  // Current content (may be edited)
  currentRevisionId: ULID;

  // For arc detection
  arcDescription?: string;

  // Media references
  storageId?: string;
  audioStorageId?: string;

  // Visibility for thinking
  isVisible?: boolean;

  // When it happened in the real world
  occurredAt: number;
  editedAt?: number;

  // Inclusion flags
  includeInArcContent: boolean;
  includeInRetrieval: boolean;

  // Media metadata
  mediaMeta?: MediaMetadata;

  // Client context
  seqInTurn?: number;
  clientMeta?: {
    deviceId?: string;
    appVersion?: string;
    locale?: string;
  };

  replyToMessageId?: MessageId;
};

// ═══════════════════════════════════════════════════════════════
// MESSAGE REVISION (EDIT HISTORY)
// ═══════════════════════════════════════════════════════════════

export type MessageRevision = {
  tenantId: TenantId;
  id: ULID;
  messageId: MessageId;

  content: string; // empty string if deleted
  contentHash: string; // for dedup/determinism

  editedAt: number;
  createdAt: number;
};

// ═══════════════════════════════════════════════════════════════
// MESSAGE SYNC OPERATIONS
// ═══════════════════════════════════════════════════════════════

export type MessageDeleteReason = "user_delete" | "gdpr_delete" | "policy_delete";

export type MessagePayload = {
  messageId: MessageId;
  conversationId: ConversationId;
  sessionId?: SessionId;
  turnId: TurnId;

  speaker: "user" | "eiri";
  type: MessageType;
  content: string;
  arcDescription?: string;

  storageId?: string;
  audioStorageId?: string;
  isVisible?: boolean;

  timestamp: ISO8601; // occurredAt
  editedAt?: ISO8601;

  includeInArcContent: boolean;
  includeInRetrieval: boolean;

  mediaMeta?: MediaMetadata;
  seqInTurn?: number;
  clientMeta?: {
    deviceId?: string;
    appVersion?: string;
    locale?: string;
  };

  replyToMessageId?: MessageId;
};

export type MessageSyncOp =
  | { op: "append"; message: MessagePayload }
  | { op: "edit"; messageId: MessageId; newContent: string; editedAt: ISO8601 }
  | {
      op: "delete";
      messageId: MessageId;
      reason: MessageDeleteReason;
      deletedAt: ISO8601;
    };

// ═══════════════════════════════════════════════════════════════
// TURN (DERIVED FROM MESSAGES)
// ═══════════════════════════════════════════════════════════════

export type Turn = BaseEntity & {
  sessionId: SessionId;
  sequence: number;
  speaker: "user" | "eiri";

  messageIds: MessageId[];

  // Derived content
  combinedContent: string;
  summary?: string;
  embedding?: number[];

  // Deletion guarantee tracking
  sourceRevisionIds: ULID[];
  sourceVersion: string;
  stale: boolean;

  // Timestamps
  occurredAt: number;
};

// ═══════════════════════════════════════════════════════════════
// MENTION HINTS (NER)
// ═══════════════════════════════════════════════════════════════

export type MentionHint = {
  surface: string;
  span?: { start: number; end: number };
  typeHint?: EntityType;
  resolvedEntityIdHint?: ULID;
  source: "eiri_coref" | "user_explicit";
  confidence?: number;
};
