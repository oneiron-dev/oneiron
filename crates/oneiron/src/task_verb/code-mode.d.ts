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
declare function describe(input: { fold?: string | null; frame_epoch?: number | null; key?: string | null; self?: boolean; session_id?: string | null; task_ref?: string | null }): Promise<unknown>;
declare function peek(input: { group_ref: string }): Promise<unknown>;
declare function report(input: { category: "skill_defect" | "execution_lapse" | "discovery" | "environment" | "preference_shift" | "unclear"; evidence_refs?: string[]; kind?: "problem" | "proposal"; note?: string | null; proposal?: object | null; subject_ref: string; why?: string | null }): Promise<unknown>;
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
  const compact: (input: { note?: string | null }) => Promise<unknown>;
  const focus: {
    refresh(input: { frame_epoch?: number | null }): Promise<unknown>;
    subscribe(input: { scopes: ("my_tasks" | "my_children" | "consults_to_me" | "memories" | "worlds" | "presence" | "counts")[] }): Promise<unknown>;
    unsubscribe(input: { scopes: ("my_tasks" | "my_children" | "consults_to_me" | "memories" | "worlds" | "presence" | "counts")[] }): Promise<unknown>;
  };
  const fold: (input: { from: number; note?: string | null; through: number }) => Promise<unknown>;
  const folds: (input: object) => Promise<unknown>;
  const memory: {
    diary(input: { content: string; kind?: string | null }): Promise<unknown>;
  };
  const skills: {
    call(input: { args: unknown; skill: string }): Promise<unknown>;
    callables(input: object): Promise<unknown>;
    fork(input: { id?: string | null; parent: string; skill_id: string }): Promise<unknown>;
    save(input: { expected_version?: string | null; files: { content: string; path: string }[]; id?: string | null }): Promise<unknown>;
  };
  const unfold: (input: { fold: string }) => Promise<unknown>;
}
declare function steer(input: { instruction: string; key: string; task_ref: string }): Promise<unknown>;
declare const tasks: {
  answer(input: { handle: object; word: object }): Promise<unknown>;
  create(input: { label?: string | null; spec: unknown }): Promise<unknown>;
  outcomes(input: { group_ref: string }): Promise<unknown>;
  refuse(input: { at?: number | null; domain: "bond" | "logistics"; reasonRef: string; taskRef?: string | null }): Promise<unknown>;
  update(input: { task_ref: string }): Promise<unknown>;
};
declare const vault: {
  artifacts: {
    born_from(input: { agent_run?: string | null; ask_ref?: string | null; run_ref?: string | null; skill_ref?: string | null; task_ref?: string | null }): Promise<unknown>;
    discard(input: { artifact_ref: string; brief_ref?: string | null; proposal_ref: string; reason?: string | null }): Promise<unknown>;
    export(input: { artifact_ref: string; version?: number | null }): Promise<unknown>;
    keep(input: { artifact_ref: string; brief_ref?: string | null; proposal_ref: string; reason?: string | null }): Promise<unknown>;
    proposals(input: { artifact_ref: string }): Promise<unknown>;
    propose_deck(input: { artifact_ref: string; context?: unknown; made_by?: unknown; run_ref: string; transaction: unknown }): Promise<unknown>;
    propose_output(input: { artifact_ref: string; content_base64: string; made_by?: unknown; media_type: string; name: string; report?: unknown; run_ref: string }): Promise<unknown>;
    undo(input: { artifact_ref: string; brief_ref?: string | null; proposal_ref: string; reason?: string | null }): Promise<unknown>;
    view(input: { artifact_ref: string }): Promise<unknown>;
  };
  claims: {
    put(input: { confidence?: number | null; id: string; learnedAt?: number | null; occurred?: object | null; predicate: string; subject: string; value: unknown }): Promise<unknown>;
    supersede(input: { newId: string; now: number; oldId: string }): Promise<unknown>;
    upsert(input: { confidence: number; id?: string | null; learned_at?: number | null; occurred_at?: number | null; predicate: string; relationship_ref?: string | null; salience?: number | null; scope?: unknown; source: string; subject_ref: string; valid_from?: number | null; valid_to?: number | null; value: unknown; world_ref?: string | null }): Promise<unknown>;
  };
  companions: {
    sharing: {
      get(input: { companion_ref: string; contact_ref: string }): Promise<unknown>;
    };
  };
  conversations: {
    turn: {
      continue(input: { turn_id: string }): Promise<unknown>;
      retry(input: { turn_id: string }): Promise<unknown>;
    };
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
  receipts: ((input: { limit?: number | null }) => Promise<unknown>) & {
    get(input: { receipt_ref: string }): Promise<unknown>;
  };
  rooms: {
    claim(input: { room_ref: string; turn_ref: string }): Promise<unknown>;
    consent(input: { grant: boolean; join_ref: string; part: "spend" | "membership" | "admission"; spend_scope?: string | null }): Promise<unknown>;
    find(input: { after?: string | null; limit?: number | null; room_ref: string }): Promise<unknown>;
    get(input: { room_ref: string; turn_ref: string }): Promise<unknown>;
    host: ((input: { room_ref: string; session_ref?: string | null }) => Promise<unknown>) & {
      hand(input: { room: string; session?: string | null; to: string }): Promise<unknown>;
      pin(input: { agent?: string | null; room: string }): Promise<unknown>;
    };
    join(input: { branch?: string | null; intent_key: string; paid: boolean; room: string; spend_scope?: string | null; subject: object | object }): Promise<unknown>;
    list(input: object): Promise<unknown>;
    messages(input: { after?: string | null; limit?: number | null; room_ref: string }): Promise<unknown>;
    participants(input: { after?: string | null; branch?: string | null; limit?: number | null; room: string }): Promise<unknown>;
    render(input: { room_ref: string }): Promise<unknown>;
    sharing(input: { room_ref: string }): Promise<unknown>;
    speak(input: { conversation_ref: string; messages: object[]; occurred_at: number; turn_ref?: string | null }): Promise<unknown>;
    trunk(input: { room_ref: string; turn_ref: string }): Promise<unknown>;
  };
  search(input: { limit?: number | null; query: string }): Promise<unknown>;
  witness(input: { conversation_ref: string; messages: object[]; occurred_at: number; turn_ref?: string | null }): Promise<unknown>;
  workspace: {
    work_companion: {
      get(input: { workspace_ref: string }): Promise<unknown>;
      set(input: { policy: "choose" | "suggest" | "require"; workspace_ref: string }): Promise<unknown>;
    };
  };
};
declare function wait(input: { handle: object; step_key: string }): Promise<unknown>;
