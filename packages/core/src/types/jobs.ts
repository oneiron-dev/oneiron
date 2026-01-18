/**
 * Job Types
 *
 * Jobs handle async work: ingestion, compaction, retrieval, etc.
 */

import type { ULID, ISO8601, JobId, PersonId, PersonaId, ConversationId, SessionId } from "./primitives";

// ═══════════════════════════════════════════════════════════════
// JOB STATUS & TYPES
// ═══════════════════════════════════════════════════════════════

export type JobStatus = "queued" | "running" | "succeeded" | "failed" | "canceled";

export type JobType =
  | "message_ingest"
  | "compaction"
  | "deep_memory"
  | "autonomous"
  | "mirror_refresh"
  | "export"
  | "import";

// ═══════════════════════════════════════════════════════════════
// JOB ENTITY
// ═══════════════════════════════════════════════════════════════

export type Job = {
  jobId: JobId;
  type: JobType;

  userPersonId: PersonId;
  personaId?: PersonaId;
  conversationId?: ConversationId;
  sessionId?: SessionId;

  status: JobStatus;
  createdAt: ISO8601;
  startedAt?: ISO8601;
  finishedAt?: ISO8601;

  progress?: { pct?: number; stage?: string };
  error?: { code: string; message: string; details?: unknown };
};

// ═══════════════════════════════════════════════════════════════
// AUTONOMOUS JOBS
// ═══════════════════════════════════════════════════════════════

export type AutonomousJobType =
  | "research"
  | "reflection"
  | "reminder"
  | "creative"
  | "analysis";

export type AutonomousJobIntent = "for_user" | "for_self" | "both";

export type AutonomyNotificationPolicy = {
  channel: "none" | "in_app" | "push";
  maxPerDay?: number;
};

export type QuietHours = {
  startLocal: string; // "22:00"
  endLocal: string; // "07:00"
  timezone?: string; // IANA optional
};

export type AutonomySettings = {
  id: ULID;
  userPersonId: PersonId;

  enabled: boolean;
  allowedJobTypes: AutonomousJobType[];
  dailyBudgetCents: number;

  notificationQuietHours?: QuietHours;
  notificationPolicy: Record<
    AutonomousJobType | "export" | "import",
    AutonomyNotificationPolicy
  >;

  consentVersion: string;
  enabledAt?: ISO8601;
  updatedAt: ISO8601;
};
