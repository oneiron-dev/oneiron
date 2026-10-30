/** Google ADK tools over a caller-supplied, actor-bound Oneiron client. */
import { FunctionTool, type RunAsyncToolRequest, type ToolExecuteArgument } from "@google/adk"
import { z } from "zod"
import type { ClaimInput, Oneiron, RecallOptions } from "oneiron"

/** Keeps the SDK's result and error intact, including engine receipts. */
export class MemoryFunctionTool<Parameters extends z.ZodObject<z.ZodRawShape>, Result>
  extends FunctionTool<Parameters> {
  readonly #schema: Parameters
  readonly #invoke: (input: ToolExecuteArgument<Parameters>) => Result | Promise<Result>

  constructor(options: {
    name: string
    description: string
    parameters: Parameters
    execute: (input: ToolExecuteArgument<Parameters>) => Result | Promise<Result>
  }) {
    super(options)
    this.#schema = options.parameters
    this.#invoke = options.execute
  }

  // ADK's default runAsync replaces typed client errors with a plain Error.
  override async runAsync(request: RunAsyncToolRequest): Promise<Result> {
    return this.#invoke(this.#schema.parse(request.args) as ToolExecuteArgument<Parameters>)
  }
}

export const recallOptions = z.object({
  effort: z.enum(["light", "medium", "high", "xhigh", "max", "call"]).optional(),
  scope: z.object({
    worldRef: z.string().optional(),
    facet: z.string().optional(),
    kinds: z.array(z.string()).optional(),
    conversationRefs: z.array(z.string()).optional(),
    personRef: z.string().optional(),
  }).strict().optional(),
  limit: z.number().optional(),
  format: z.enum(["json", "yaml", "toon", "md", "txt"]).optional(),
  asOf: z.number().optional(),
  deadlineMs: z.number().optional(),
}).strict() satisfies z.ZodType<RecallOptions>

export const claimInput = z.object({
  id: z.string().optional(),
  predicate: z.string(),
  subjectRef: z.string(),
  value: z.unknown(),
  confidence: z.number(),
  source: z.string(),
  worldRef: z.string().optional(),
  scope: z.unknown().optional(),
  validFrom: z.number().optional(),
  validTo: z.number().optional(),
  occurredAt: z.number().optional(),
  learnedAt: z.number().optional(),
  salience: z.number().optional(),
}).strict() satisfies z.ZodType<ClaimInput>

/** Request-shaped facade verbs retain the SDK's wire field spelling. */
export const claimListInput = z.object({
  subject_ref: z.string().nullable().optional(),
  predicate: z.string().nullable().optional(),
  lifecycle: z.string().nullable().optional(),
  limit: z.number(),
}).strict() satisfies z.ZodType<Parameters<Oneiron["claimList"]>[0]>

export const claimRefInput = z.object({
  claim_ref: z.string(),
}).strict() satisfies z.ZodType<Parameters<Oneiron["claimRetract"]>[0]>

export const entityInput = z.object({
  entity_ref: z.string(),
}).strict() satisfies z.ZodType<Parameters<Oneiron["getEntity"]>[0]>

export const keywordInput = z.object({
  query: z.string(),
  limit: z.number(),
}).strict() satisfies z.ZodType<Parameters<Oneiron["queryBm25"]>[0]>

export const neighborsInput = z.object({
  entity_ref: z.string(),
  opts: z.object({
    edge_kind: z.string().nullable().optional(),
    min_weight: z.number().nullable().optional(),
    limit: z.number(),
  }).strict(),
}).strict() satisfies z.ZodType<Parameters<Oneiron["neighbors"]>[0]>

export const hydrateInput = z.object({
  refs: z.array(z.string()),
}).strict() satisfies z.ZodType<Parameters<Oneiron["hydrate"]>[0]>

export const structuralInput = z.object({
  id: z.string().nullable().optional(),
  kind: z.string(),
  body: z.unknown(),
  text_fields: z.array(z.object({ field: z.string(), value: z.string() }).strict()).nullable().optional(),
  edges: z.array(z.object({
    edge_kind: z.string(),
    target_ref: z.string(),
    weight: z.number().nullable().optional(),
  }).strict()).nullable().optional(),
  occurred_at: z.number(),
  learned_at: z.number().nullable().optional(),
}).strict() satisfies z.ZodType<Parameters<Oneiron["putStructural"]>[0]>

export type CoreMemoryClient = Pick<Oneiron,
  "recall" | "claimUpsert" | "claimList" | "claimRetract" | "getEntity">
export type ExtendedMemoryClient = Pick<Oneiron,
  "queryBm25" | "neighbors" | "claimHistory" | "hydrate" | "putStructural">

/**
 * Core belief CRUD and retrieval. claimUpsert handles both create and update;
 * no second tool invents a different update policy. Select tools by name or
 * pass Object.values(memoryTools(memory)) to an ADK agent.
 *
 * The host supplies the bound client. These tools never open a vault, rebind
 * an actor, or read or write ADK session state. Defaults and limits remain
 * the engine's, and results are returned whole, including read/write receipts.
 */
export function memoryTools(memory: CoreMemoryClient) {
  return {
    recall: new MemoryFunctionTool({
      name: "recall",
      description: "Recall memory within the bound actor's scope. Returns the engine memory pack and read receipt.",
      parameters: z.object({ query: z.string(), options: recallOptions.optional() }).strict(),
      execute: ({ query, options }) => memory.recall(query, options),
    }),
    claimUpsert: new MemoryFunctionTool({
      name: "claim_upsert",
      description: "Create or supersede a belief. The engine decides approval and returns its commit receipt.",
      parameters: claimInput,
      execute: (input) => memory.claimUpsert(input),
    }),
    claimList: new MemoryFunctionTool({
      name: "claim_list",
      description: "Read beliefs by subject, predicate or lifecycle within the bound scope. Returns the engine read receipt.",
      parameters: claimListInput,
      execute: (input) => memory.claimList(input),
    }),
    getEntity: new MemoryFunctionTool({
      name: "get_entity",
      description: "Read one entity within the bound scope. Returns the engine view and read receipt.",
      parameters: entityInput,
      execute: (input) => memory.getEntity(input),
    }),
    claimRetract: new MemoryFunctionTool({
      name: "claim_retract",
      description: "Withdraw a belief without deleting its history. Returns the engine commit receipt.",
      parameters: claimRefInput,
      execute: (input) => memory.claimRetract(input),
    }),
  }
}

/** Opt-in specialized tools over the same actor-bound public verbs. */
export function extendedMemoryTools(memory: ExtendedMemoryClient) {
  return {
    queryBm25: new MemoryFunctionTool({
      name: "query_bm25",
      description: "Search the engine text index by keyword within the bound scope. Returns scored hits and the read receipt.",
      parameters: keywordInput,
      execute: (input) => memory.queryBm25(input),
    }),
    neighbors: new MemoryFunctionTool({
      name: "neighbors",
      description: "Explore an entity's graph neighbors within the bound scope. Returns engine edges and the read receipt.",
      parameters: neighborsInput,
      execute: (input) => memory.neighbors(input),
    }),
    claimHistory: new MemoryFunctionTool({
      name: "claim_history",
      description: "Read a belief's supersession history within the bound scope. Returns the engine timeline and read receipt.",
      parameters: claimRefInput,
      execute: (input) => memory.claimHistory(input),
    }),
    hydrate: new MemoryFunctionTool({
      name: "hydrate",
      description: "Read entity references, including retained revision pins, within the bound scope. Returns full views and the read receipt.",
      parameters: hydrateInput,
      execute: (input) => memory.hydrate(input),
    }),
    putStructural: new MemoryFunctionTool({
      name: "put_structural",
      description: "Write a structural entity, including a place, with index fields and links through the bound public client. Returns the engine receipt.",
      parameters: structuralInput,
      execute: (input) => memory.putStructural(input),
    }),
  }
}
