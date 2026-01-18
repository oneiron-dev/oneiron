/**
 * Claim Types
 *
 * Claims are semantic beliefs about entities.
 * They replace the old PREFERENCE/BOUNDARY/COMMITMENT/GOAL entity types.
 */

import type {
  ULID,
  ISO8601,
  ClaimId,
  TurnId,
  TenantId,
} from "./primitives";
import type { BaseEntity, EntityType } from "./entities";

// ═══════════════════════════════════════════════════════════════
// CLAIM STATUS TYPES
// ═══════════════════════════════════════════════════════════════

/** Did the user consent to storing this claim? */
export type ClaimApprovalStatus = "auto" | "proposed" | "approved" | "rejected";

/** Is this the current version of the claim? */
export type ClaimLifecycleStatus = "active" | "superseded" | "retracted";

/** How did we learn this? */
export type ClaimSource = "user_stated" | "observed" | "inferred" | "imported";

/** Real vs fiction (don't mix roleplay into profile) */
export type WorldTag = "real" | "roleplay" | "hypothetical";

// ═══════════════════════════════════════════════════════════════
// CLAIM VALUE (TYPED)
// ═══════════════════════════════════════════════════════════════

export type ClaimValue =
  | { kind: "string"; value: string }
  | { kind: "number"; value: number; unit?: string }
  | { kind: "boolean"; value: boolean }
  | {
      kind: "date";
      value: string;
      precision: "day" | "month" | "year" | "unknown";
    }
  | { kind: "entity_ref"; entityType: EntityType; entityId: string };

// ═══════════════════════════════════════════════════════════════
// CLAIM ENTITY
// ═══════════════════════════════════════════════════════════════

export type Claim = BaseEntity & {
  // Subject (what this claim is about)
  subjectType: EntityType;
  subjectId: string;

  // Scope (null = global, else relationship-scoped)
  scopeRelationshipId?: string;

  // Predicate and value
  predicate: string; // namespaced: "goal.learning", "profile.lives_in"
  value: ClaimValue;
  valueKey: string; // canonical equality key
  valueText: string; // human-readable display

  // Type-specific fields (schema defined by predicate registry)
  fields?: Record<string, unknown>;

  // Confidence and evidence
  confidence: number; // 0-1
  evidenceTurnIds: TurnId[];

  // Temporal validity
  validFrom: number; // when this became true (occurredAt)
  validTo?: number; // when superseded (null = still valid)

  // Lifecycle and approval
  approvalStatus: ClaimApprovalStatus;
  lifecycleStatus: ClaimLifecycleStatus;
  supersedesId?: ClaimId;
  lastVerifiedAt?: number;

  // Provenance
  source: ClaimSource;
  worldTag?: WorldTag;

  // Deletion guarantee (derived data tracking)
  sourceRevisionIds: string[];
  sourceVersion: string;
  stale: boolean;

  // Ranking
  salience?: number; // 0-1, affects retrieval ranking
};

// ═══════════════════════════════════════════════════════════════
// PREDICATE DEFINITION
// ═══════════════════════════════════════════════════════════════

export type PredicateCardinality = "single" | "multi";

export type PredicateDef = {
  predicate: string; // e.g., "preference.food"
  namespace: string; // e.g., "preference"
  displayName: string;
  description: string;

  // Value constraints
  valueKind: ClaimValue["kind"];
  allowedEntityTypes?: EntityType[]; // for entity_ref values

  // Cardinality
  cardinality: PredicateCardinality;

  // Defaults
  defaultConfidence: number;
  defaultSensitivity: "normal" | "intimate";
  defaultApproval: ClaimApprovalStatus;

  // Plugin info
  source: "core" | "companion" | "eiri" | string;
};
