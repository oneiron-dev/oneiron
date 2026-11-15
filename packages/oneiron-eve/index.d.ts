// Types for @oneiron/eve. The eve shapes below mirror eve 1.0.0-rc.18
// (`eve/memory`, packages/eve/src/public/memory/index.ts) structurally, so
// this package imports nothing from eve: the provider is a plain object an
// eve slot takes.

/** eve's partition of one memory slot. */
export interface MemoryScope {
  readonly key: string;
  readonly namespace: string;
  readonly value: string | readonly string[];
}

/** One message of an eve history, as far as this provider reads it. */
export interface HistoryMessage {
  readonly role: "system" | "user" | "assistant" | "tool";
  readonly content: string | readonly ({ readonly type: string; readonly text?: string })[];
}

export interface MemoryTurnContext {
  readonly id: string;
  readonly input: readonly HistoryMessage[];
  readonly sequence: number;
}

export interface MemoryOperationContext {
  readonly abortSignal: AbortSignal;
  readonly messages: readonly HistoryMessage[];
  readonly operationId: string;
  readonly memory: { readonly scope: MemoryScope; readonly slot: string };
}

export interface MemoryTurnStartedContext extends MemoryOperationContext {
  readonly turn: MemoryTurnContext;
}

export interface MemoryTurnCompletedContext extends MemoryOperationContext {
  readonly turn: MemoryTurnContext;
}

export interface MemoryRecallMessage {
  readonly content: string;
  readonly id?: string;
}

export type MemoryRecallResult = { readonly messages: readonly MemoryRecallMessage[] } | null | undefined;

/** The facade calls this provider makes, as `@oneiron/client`'s `HttpBaseClient.facade` spells them. */
export interface OneironFacadeClient {
  readonly facade: {
    readonly vault: {
      recall(input: object, init?: RequestInit): Promise<Response | object>;
      witness(input: object, init?: RequestInit): Promise<Response | object>;
      get(input: { entity_ref: string }, init?: RequestInit): Promise<Response | object>;
      readonly claims: {
        history(input: { claim_ref: string }, init?: RequestInit): Promise<Response | object>;
      };
    };
  };
}

/** `vault.recall`'s scope, as the wire spells it (snake_case). */
export interface RecallScope {
  readonly world_ref?: string;
  readonly facet?: string;
  readonly kinds?: readonly string[];
  readonly project_refs?: readonly string[];
  readonly conversation_refs?: readonly string[];
  readonly person_ref?: string;
}

export interface OneironMemoryProviderOptions {
  /**
   * The client bound to one eve partition, or null to disable the slot for
   * that scope (nothing is recalled or witnessed).
   */
  connect(
    scope: MemoryScope,
    slot: string,
  ): OneironFacadeClient | null | undefined | Promise<OneironFacadeClient | null | undefined>;
  /** A recall scope for the partition, e.g. the world the deploy keeps for it. */
  recallScope?(scope: MemoryScope, slot: string): RecallScope | null | undefined | Promise<RecallScope | null | undefined>;
  /** Items one recall asks for; default {@link RECALL_LIMIT_DEFAULT}. */
  limit?: number;
  /** Witness each settled turn (`capture["turn.completed"]`); default true. */
  capture?: boolean;
}

export interface OneironMemoryProvider {
  readonly recall: {
    readonly "turn.started": (context: MemoryTurnStartedContext) => Promise<MemoryRecallResult>;
  };
  readonly capture?: {
    readonly "turn.completed": (context: MemoryTurnCompletedContext) => Promise<void>;
  };
}

export declare const RECALL_LIMIT_DEFAULT: number;
export declare const REMOVAL_CHECKS_PER_TURN: number;
export declare const SERVED_IDS_PER_SLOT: number;

export declare function oneironMemoryProvider(options: OneironMemoryProviderOptions): OneironMemoryProvider;
export declare function recallOperationId(operationId: string): string;
export declare function messageId(item: { short_id?: string; record?: { id?: string } }): string | null;
export declare function itemContent(item: { predicate?: string; value_text?: string }): string;
export declare function conversationRef(scope: MemoryScope, slot: string): string;
