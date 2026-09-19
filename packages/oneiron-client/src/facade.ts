/** Engine DTO calls shared by connected and embedded host handles. */
import { FACADE_CATALOG } from "./catalog";
import type { FacadeSdkName, FacadeWireName } from "./catalog";

export interface SearchRequest { readonly query: string; readonly limit?: number }
export interface AskRequest {
  readonly question: string;
  readonly scope?: { readonly world_ref?: string; readonly facet?: string };
  readonly limit?: number;
  readonly format?: string;
}
export interface FacadeInstruction { readonly verb: FacadeWireName; readonly body: unknown }
export interface ExecuteRequest { readonly calls: readonly FacadeInstruction[] }
export interface QueryPlan {
  readonly query?: string;
  readonly query_vector?: readonly number[];
  readonly limit?: number;
  readonly view?: "summary" | "standard" | "full";
  readonly countMode?: "none" | "estimate" | "exact";
}
export interface ContextPackDepth { readonly edge_hop?: number; readonly max_neighbors?: number }
export interface ContextPackBudget {
  readonly token_budget?: number; readonly max_item_tokens?: number; readonly max_field_chars?: number;
  readonly retrieval?: {
    readonly claims?: number; readonly turns?: number; readonly summaries?: number;
    readonly facets?: number; readonly other?: number; readonly selected_edges?: number;
  };
}
export interface ContextPackPlan {
  readonly query?: string;
  readonly query_vector?: readonly number[];
  readonly limit?: number;
  readonly depth?: ContextPackDepth;
  readonly budget?: ContextPackBudget;
}

/** One boundary per call. Embedded hosts bind native handles here, not HTTP. */
export interface FacadeHost<R> { call(verb: FacadeWireName, body: unknown): R }
export type FacadeMethods<R> = { readonly [K in FacadeSdkName]: (body: unknown) => R };

export class FacadeClient<R> {
  readonly verbs: FacadeMethods<R>;
  constructor(private readonly host: FacadeHost<R>) {
    this.verbs = Object.freeze(Object.fromEntries(FACADE_CATALOG.map(row =>
      [row.sdk, (body: unknown) => this.host.call(row.wire, body)]
    ))) as FacadeMethods<R>;
  }
  search(request: SearchRequest): R { return this.verbs.search(request); }
  execute(request: ExecuteRequest): R { return this.verbs.execute(request); }
  ask(request: AskRequest): R { return this.verbs.ask(request); }
  query(): QueryBuilder<R> { return new QueryBuilder(this.host); }
  contextPack(): ContextPackBuilder<R> { return new ContextPackBuilder(this.host); }
}

/** Immutable builder. Setters never enter the host. Each run is one call. */
export class QueryBuilder<R> {
  constructor(private readonly host: FacadeHost<R>, private readonly plan: QueryPlan = {}) {}
  text(query: string): QueryBuilder<R> { return new QueryBuilder(this.host, { ...this.plan, query }); }
  vector(query_vector: readonly number[]): QueryBuilder<R> { return new QueryBuilder(this.host, { ...this.plan, query_vector: [...query_vector] }); }
  limit(limit: number): QueryBuilder<R> { return new QueryBuilder(this.host, { ...this.plan, limit }); }
  view(view: NonNullable<QueryPlan["view"]>): QueryBuilder<R> { return new QueryBuilder(this.host, { ...this.plan, view }); }
  countMode(countMode: NonNullable<QueryPlan["countMode"]>): QueryBuilder<R> { return new QueryBuilder(this.host, { ...this.plan, countMode }); }
  run(): R { return this.host.call("query", this.plan); }
}
export class ContextPackBuilder<R> {
  constructor(private readonly host: FacadeHost<R>, private readonly plan: ContextPackPlan = {}) {}
  text(query: string): ContextPackBuilder<R> { return new ContextPackBuilder(this.host, { ...this.plan, query }); }
  vector(query_vector: readonly number[]): ContextPackBuilder<R> { return new ContextPackBuilder(this.host, { ...this.plan, query_vector: [...query_vector] }); }
  limit(limit: number): ContextPackBuilder<R> { return new ContextPackBuilder(this.host, { ...this.plan, limit }); }
  depth(depth: ContextPackDepth): ContextPackBuilder<R> { return new ContextPackBuilder(this.host, { ...this.plan, depth: { ...depth } }); }
  budget(budget: ContextPackBudget): ContextPackBuilder<R> {
    const copy = { ...budget, ...(budget.retrieval ? { retrieval: { ...budget.retrieval } } : {}) };
    return new ContextPackBuilder(this.host, { ...this.plan, budget: copy });
  }
  run(): R { return this.host.call("context_pack", this.plan); }
}
