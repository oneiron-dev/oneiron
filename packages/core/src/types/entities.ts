/**
 * Oneiron Entity Types
 *
 * Everything in Oneiron is either a thing (entity) or a connection between things (edge).
 */

import type { AccessPolicy, ULID, TenantId } from "./primitives";

// ═══════════════════════════════════════════════════════════════
// ENTITY TYPE ENUM
// ═══════════════════════════════════════════════════════════════

/**
 * Core entity types (built-in, always available).
 */
export type CoreEntityType =
  // People & Relationships
  | "PERSON"
  | "RELATIONSHIP"
  // Conversation
  | "MESSAGE"
  | "TURN"
  | "SESSION"
  // Knowledge
  | "SUMMARY"
  | "EVENT"
  | "SKILL"
  // Location
  | "PLACE"
  // Media
  | "ASSET"
  | "ASSET_TEXT"
  // System
  | "NOTIFICATION"
  // Semantic
  | "CLAIM";

/**
 * EntityType is extensible - plugins can register additional types.
 * Validated at runtime against the registry.
 */
export type EntityType = string;

// ═══════════════════════════════════════════════════════════════
// BASE STRUCTURES
// ═══════════════════════════════════════════════════════════════

/**
 * BaseEntity - the foundation for all entities.
 */
export type BaseEntity = {
  tenantId: TenantId;
  id: ULID;
  access: AccessPolicy;
  createdAt: number;
  updatedAt: number;
};

/**
 * EdgeKind describes the type of connection between entities.
 */
export type EdgeKind =
  // Structural
  | "authored_by"
  | "belongs_to"
  | "part_of"
  | "mentions"
  // Semantic
  | "derived_from"
  | "supersedes"
  | "claim_of"
  | "supports"
  // Graph traversal
  | "related_to";

/**
 * BaseEdge - connections between entities for graph traversal.
 */
export type BaseEdge = {
  tenantId: TenantId;
  id: ULID;

  srcId: ULID;
  srcType: EntityType;
  dstId: ULID;
  dstType: EntityType;

  kind: EdgeKind;
  weight: number; // default 1.0, for PPR

  createdAt: number;
  staleAt?: number; // set when source entity edited/deleted
};

// ═══════════════════════════════════════════════════════════════
// PERSON & RELATIONSHIP
// ═══════════════════════════════════════════════════════════════

export type PersonType = "human" | "agent" | "system";

export type Person = BaseEntity & {
  name: string;
  type: PersonType;
  metadata?: Record<string, unknown>;
};

export type Relationship = BaseEntity & {
  personIds: ULID[];
  kind: "user_companion" | "user_user" | "companion_companion";
  status: "active" | "archived";
  metadata?: Record<string, unknown>;
};

// ═══════════════════════════════════════════════════════════════
// CONVERSATION ENTITIES
// ═══════════════════════════════════════════════════════════════

export type Session = BaseEntity & {
  relationshipId: ULID;
  conversationId: ULID;
  startedAt: number;
  endedAt?: number;
  summaryRevision?: number;
  behavioralSignals?: {
    totalTimeSeconds?: number;
    messageCount?: number;
    avgResponseTimeSeconds?: number;
    avgMessageLength?: number;
    longPausesCount?: number;
  };
};
