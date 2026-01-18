/**
 * Oneiron Core Primitives
 *
 * These are the foundational types used throughout Oneiron.
 */

/** ISO 8601 formatted date string */
export type ISO8601 = string;

/** Universally Unique Lexicographically Sortable Identifier */
export type ULID = string;

// ═══════════════════════════════════════════════════════════════
// IDENTITY TYPES
// ═══════════════════════════════════════════════════════════════

export type TenantId = ULID;
export type PersonId = ULID;
export type PersonaId = ULID;
export type ConversationId = ULID;
export type SessionId = ULID;
export type TurnId = ULID;
export type MessageId = ULID;
export type JobId = ULID;
export type ClaimId = ULID;
export type RelationshipId = ULID;

// ═══════════════════════════════════════════════════════════════
// ACCESS POLICY
// ═══════════════════════════════════════════════════════════════

/**
 * AccessPolicy controls who can read an entity.
 *
 * - tenant: Anyone in the tenant (admin use)
 * - private: Only the subject (owner-only)
 * - shared: Specific subjects
 * - relationship: Participants in a relationship
 * - public: Anyone (rare, for system entities)
 */
export type AccessPolicy =
  | { kind: "tenant"; tenantId: string }
  | { kind: "private"; subjectId: string }
  | { kind: "shared"; subjectIds: string[] }
  | { kind: "relationship"; relationshipId: string }
  | { kind: "public" };

/**
 * Three spaces for memory organization.
 */
export type MemorySpace = "user" | "relationship" | "private";

/**
 * Sensitivity levels within relationship space.
 */
export type Sensitivity = "normal" | "intimate";

// ═══════════════════════════════════════════════════════════════
// TIMESTAMPS (TWO CLOCKS)
// ═══════════════════════════════════════════════════════════════

/**
 * The Two Clocks principle:
 *
 * - occurredAt: When it happened in the real world
 * - recordedAt: When Oneiron stored it
 *
 * Always store both. Query by occurredAt for user-facing timelines.
 */
export type TwoClocks = {
  occurredAt: number; // epoch ms - when it happened
  recordedAt: number; // epoch ms - when Oneiron stored it
};
