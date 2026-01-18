/**
 * Retrieval Types
 *
 * Types for the retrieval system: search, RAG, activated memory.
 */

import type {
  ULID,
  ISO8601,
  TenantId,
  MemorySpace,
  Sensitivity,
} from "./primitives";
import type { EntityType } from "./entities";

// ═══════════════════════════════════════════════════════════════
// RETRIEVAL INDEX ROW
// ═══════════════════════════════════════════════════════════════

export type RetrievalIndexRow = {
  tenantId: TenantId;
  id: ULID;

  entityId: ULID;
  entityType: EntityType;

  // Access control (pre-computed for filtering)
  space: MemorySpace;
  relationshipId?: string;
  sensitivity: Sensitivity;

  // For claims
  predicateNamespace?: string;

  // Searchable content
  text: string;
  embedding?: number[];

  // Ranking signals
  salience?: number;
  confidence?: number;
  recencyScore?: number;

  // Deletion guarantee
  sourceRevisionIds: ULID[];
  sourceVersion: string;
  stale: boolean;

  createdAt: number;
  updatedAt: number;
};

// ═══════════════════════════════════════════════════════════════
// RETRIEVAL FILTER
// ═══════════════════════════════════════════════════════════════

export type RetrievalFilter = {
  entityTypes?: EntityType[];
  predicatePatterns?: string[]; // e.g., ["goal.*", "preference.*"]
  relationshipId?: string;
  space?: MemorySpace;
  sensitivity?: Sensitivity;
  minConfidence?: number;
  minSalience?: number;
  includeStale?: boolean; // default false
};

// ═══════════════════════════════════════════════════════════════
// ACTIVATED MEMORY (SESSION RAG STATE)
// ═══════════════════════════════════════════════════════════════

export type ActiveEntityStackItem = {
  id: ULID;
  type: EntityType;
  mentionedAt: ISO8601;
  mentionCount: number;
  lastTurnSeq: number;
};

export type ActiveEntityStack = ActiveEntityStackItem[];

export type ActivatedMemoryMode = "snippet" | "index";

export type ActivatedMemory = {
  memoryId: ULID;
  type: EntityType;
  title: string;
  snippet?: string;
  mode: ActivatedMemoryMode;
  addedAt: ISO8601;
};

export type SessionRagState = {
  epoch: number; // increments on compaction
  activated: Record<string, ActivatedMemory>; // keyed by memoryId
  activatedOrder: ULID[];
  injectedMemoryIdsEpoch: ULID[];
  rehydrationNeeded?: boolean;
};

// ═══════════════════════════════════════════════════════════════
// SEARCH RESULTS
// ═══════════════════════════════════════════════════════════════

export type SearchHit = {
  id: ULID;
  type: EntityType;
  title: string;
  snippet?: string;
  score?: number;
  // Claim-specific
  predicate?: string;
  valueText?: string;
  confidence?: number;
  salience?: number;
  scopeRelationshipId?: string;
};
