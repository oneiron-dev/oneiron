declare const ai: {
  embed(input: { input?: object[]; model?: string | null; params?: object; prompt?: string | null; references?: object[] }): Promise<unknown>;
  image(input: { input?: object[]; model?: string | null; params?: object; prompt?: string | null; references?: object[] }): Promise<unknown>;
  options(input: { inputs?: string[]; operation?: string | null }): Promise<unknown>;
  speech(input: { input?: object[]; model?: string | null; params?: object; prompt?: string | null; references?: object[] }): Promise<unknown>;
  transcribe(input: { input?: object[]; model?: string | null; params?: object; prompt?: string | null; references?: object[] }): Promise<unknown>;
  video: ((input: { input?: object[]; model?: string | null; params?: object; prompt?: string | null; references?: object[] }) => Promise<unknown>) & {
    cancel(input: { job: string }): Promise<unknown>;
    poll(input: { job: string }): Promise<unknown>;
  };
};
declare function ask(input: object): Promise<unknown>;
declare function can(input: { ask: object }): Promise<unknown>;
declare function cancel(input: { task_ref: string }): Promise<unknown>;
declare const connector: {
  list(input: { query?: string | null }): Promise<unknown>;
  outbound: {
    schedule(input: { channel: string; content_ref?: string | null; dedupe_key?: string | null; idempotency_key?: string | null; job_ref?: string | null; occurred_at?: number | null; on_behalf_of?: string | null; target: string; trigger: string; trigger_ref: string; verb: string }): Promise<unknown>;
  };
  status(input: { name: string }): Promise<unknown>;
};
declare function describe(input: { frame_epoch?: number | null; key?: string | null; self?: boolean; session_id?: string | null; task_ref?: string | null }): Promise<unknown>;
declare function peek(input: { group_ref: string }): Promise<unknown>;
declare namespace self {
  const browser: {
    click(input: { ref: string }): Promise<unknown>;
    expect(input: { absent?: boolean; name?: string | null; ref?: string | null; role?: string | null; value?: string | null }): Promise<unknown>;
    find(input: { name?: string | null; role?: string | null }): Promise<unknown>;
    observe(input: { since?: number | null }): Promise<unknown>;
    open(input: { url: string }): Promise<unknown>;
    screenshot(input: object): Promise<unknown>;
    select(input: { option: string; ref: string }): Promise<unknown>;
    type(input: { clear?: boolean; ref: string; text: string }): Promise<unknown>;
    wait_for(input: { name?: string | null; role?: string | null; timeout_ms?: number | null }): Promise<unknown>;
  };
  const focus: {
    refresh(input: { frame_epoch?: number | null }): Promise<unknown>;
    subscribe(input: { scopes: ("my_tasks" | "my_children" | "consults_to_me" | "memories" | "worlds" | "presence" | "counts")[] }): Promise<unknown>;
    unsubscribe(input: { scopes: ("my_tasks" | "my_children" | "consults_to_me" | "memories" | "worlds" | "presence" | "counts")[] }): Promise<unknown>;
  };
  const memory: {
    diary(input: { content: string; kind?: string | null }): Promise<unknown>;
  };
}
declare function steer(input: { instruction: string; key: string; task_ref: string }): Promise<unknown>;
declare const tasks: {
  answer(input: { handle: object; word: object }): Promise<unknown>;
  create(input: { label?: string | null; spec: unknown }): Promise<unknown>;
  outcomes(input: { group_ref: string }): Promise<unknown>;
  update(input: { task_ref: string }): Promise<unknown>;
};
declare const vault: {
  claims: {
    put(input: { confidence?: number | null; id: string; learnedAt?: number | null; occurred?: object | null; predicate: string; subject: string; value: unknown }): Promise<unknown>;
    supersede(input: { newId: string; now: number; oldId: string }): Promise<unknown>;
    upsert(input: { confidence: number; id?: string | null; learned_at?: number | null; occurred_at?: number | null; predicate: string; relationship_ref?: string | null; salience?: number | null; scope?: unknown; source: string; subject_ref: string; valid_from?: number | null; valid_to?: number | null; value: unknown; world_ref?: string | null }): Promise<unknown>;
  };
  edges: {
    put(input: { kind: string; src: string; tgt: string; weight?: number | null }): Promise<unknown>;
  };
  export(input: { format?: string | null }): Promise<unknown>;
  kv: {
    delete(input: { key: string; namespace: string[] }): Promise<unknown>;
    get(input: { key: string; namespace: string[] }): Promise<unknown>;
    namespaces(input: { limit?: number; max_depth?: number | null; offset?: number; prefix?: string[]; suffix?: string[] }): Promise<unknown>;
    put(input: { key: string; namespace: string[]; request_id: string; source?: string; value: unknown }): Promise<unknown>;
    search(input: { filter?: object | null; limit?: number; namespace_prefix?: string[]; offset?: number }): Promise<unknown>;
  };
  packs: {
    put(input: { files: object[] }): Promise<unknown>;
  };
  recall(input: { as_of?: number | null; deadline_ms?: number | null; effort?: "light" | "medium" | "high" | "xhigh" | "max" | "call" | null; format?: string | null; limit?: number | null; query: string; scope?: object | null }): Promise<unknown>;
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
  witness(input: { conversation_ref: string; messages: object[]; occurred_at: number; turn_ref?: string | null }): Promise<unknown>;
};
declare function wait(input: { handle: object; step_key: string }): Promise<unknown>;
