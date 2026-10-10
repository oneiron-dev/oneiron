declare namespace self {
  const memory: {
    board: {
      expand(input: { frame_epoch?: number | null; key: string }): Promise<unknown>;
      refresh(input: { frame_epoch?: number | null }): Promise<unknown>;
      subscribe(input: { scopes: ("my_tasks" | "my_children" | "consults_to_me" | "memories" | "worlds" | "presence" | "counts")[] }): Promise<unknown>;
      unsubscribe(input: { scopes: ("my_tasks" | "my_children" | "consults_to_me" | "memories" | "worlds" | "presence" | "counts")[] }): Promise<unknown>;
    };
    can(input: { ask: object }): Promise<unknown>;
    cancel(input: { task_ref: string }): Promise<unknown>;
    claim_upsert(input: { confidence: number; id?: string | null; learned_at?: number | null; occurred_at?: number | null; predicate: string; relationship_ref?: string | null; salience?: number | null; scope?: unknown; source: string; subject_ref: string; valid_from?: number | null; valid_to?: number | null; value: unknown; world_ref?: string | null }): Promise<unknown>;
    describe(input: { self?: boolean; session_id?: string | null; task_ref?: string | null }): Promise<unknown>;
    export(input: { format?: string | null }): Promise<unknown>;
    key_value_delete(input: { key: string; namespace: string[] }): Promise<unknown>;
    key_value_get(input: { key: string; namespace: string[] }): Promise<unknown>;
    key_value_namespaces(input: { limit?: number; max_depth?: number | null; offset?: number; prefix?: string[]; suffix?: string[] }): Promise<unknown>;
    key_value_put(input: { key: string; namespace: string[]; request_id: string; source?: string; value: unknown }): Promise<unknown>;
    key_value_search(input: { filter?: object | null; limit?: number; namespace_prefix?: string[]; offset?: number }): Promise<unknown>;
    peek(input: { group_ref: string }): Promise<unknown>;
    put_claim(input: { confidence?: number | null; id: string; learnedAt?: number | null; occurred?: object | null; predicate: string; subject: string; value: unknown }): Promise<unknown>;
    put_edge(input: { kind: string; src: string; tgt: string; weight?: number | null }): Promise<unknown>;
    recall(input: { as_of?: number | null; effort?: "light" | "medium" | "high" | "xhigh" | "max" | null; format?: string | null; limit?: number | null; query: string; scope?: object | null }): Promise<unknown>;
    receipts(input: { limit?: number | null }): Promise<unknown>;
    rooms: {
      claim(input: { room_ref: string; turn_ref: string }): Promise<unknown>;
      find(input: { after?: string | null; limit?: number | null; room_ref: string }): Promise<unknown>;
      get(input: { room_ref: string; turn_ref: string }): Promise<unknown>;
      list(input: object): Promise<unknown>;
      messages(input: { after?: string | null; limit?: number | null; room_ref: string }): Promise<unknown>;
      render(input: { room_ref: string }): Promise<unknown>;
      speak(input: { conversation_ref: string; messages: object[]; occurred_at: number; turn_ref?: string | null }): Promise<unknown>;
      trunk(input: { room_ref: string; turn_ref: string }): Promise<unknown>;
    };
    search(input: { limit?: number | null; query: string }): Promise<unknown>;
    supersede_claim(input: { newId: string; now: number; oldId: string }): Promise<unknown>;
    tasks: {
      answer(input: { handle: object; word: object }): Promise<unknown>;
      ask(input: object): Promise<unknown>;
      create(input: { label?: string | null; spec: unknown }): Promise<unknown>;
      outcomes(input: { group_ref: string }): Promise<unknown>;
      update(input: { task_ref: string }): Promise<unknown>;
      wait(input: { handle: object; step_key: string }): Promise<unknown>;
    };
    witness(input: { conversation_ref: string; messages: object[]; occurred_at: number; turn_ref?: string | null }): Promise<unknown>;
  };
}
