declare namespace self {
  const memory: {
    admit_imported_claim(input: { id?: string | null; learned_at?: number | null; occurred_at: number; predicate: string; source_id: string; source_record_id: string; subject_ref: string; value: unknown }): Promise<unknown>;
    append_blob_version(input: { artifact_ref: string; content_base64: string; learned_at?: number | null; occurred_at: number; run_ref?: string | null }): Promise<unknown>;
    board: {
      expand(input: { frame_epoch?: number | null; key: string }): Promise<unknown>;
      refresh(input: { frame_epoch?: number | null }): Promise<unknown>;
      subscribe(input: { scopes: ("my_tasks" | "my_children" | "consults_to_me" | "memories" | "worlds" | "presence" | "counts")[] }): Promise<unknown>;
      unsubscribe(input: { scopes: ("my_tasks" | "my_children" | "consults_to_me" | "memories" | "worlds" | "presence" | "counts")[] }): Promise<unknown>;
    };
    browser: {
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
    can(input: { ask: object }): Promise<unknown>;
    cancel(input: { task_ref: string }): Promise<unknown>;
    claim_history(input: { claim_ref: string }): Promise<unknown>;
    claim_list(input: { lifecycle?: string | null; limit: number; predicate?: string | null; subject_ref?: string | null }): Promise<unknown>;
    claim_retract(input: { claim_ref: string }): Promise<unknown>;
    claim_upsert(input: { confidence: number; id?: string | null; learned_at?: number | null; occurred_at?: number | null; predicate: string; relationship_ref?: string | null; salience?: number | null; scope?: unknown; source: string; subject_ref: string; valid_from?: number | null; valid_to?: number | null; value: unknown; world_ref?: string | null }): Promise<unknown>;
    commit(input: { claims: object[] }): Promise<unknown>;
    create_note(input: { kind: string; markdown: string }): Promise<unknown>;
    create_note_from_entity(input: { kind: string; source_ref: string }): Promise<unknown>;
    describe(input: { self?: boolean; session_id?: string | null; task_ref?: string | null }): Promise<unknown>;
    edit_note(input: { edit: object; note_ref: string }): Promise<unknown>;
    export(input: { format?: string | null }): Promise<unknown>;
    forget(input: object): Promise<unknown>;
    get_entity(input: { entity_ref: string }): Promise<unknown>;
    hydrate(input: { refs: string[] }): Promise<unknown>;
    key_value_delete(input: { key: string; namespace: string[] }): Promise<unknown>;
    key_value_get(input: { key: string; namespace: string[] }): Promise<unknown>;
    key_value_namespaces(input: { limit?: number; max_depth?: number | null; offset?: number; prefix?: string[]; suffix?: string[] }): Promise<unknown>;
    key_value_put(input: { key: string; namespace: string[]; request_id: string; source?: string; value: unknown }): Promise<unknown>;
    key_value_search(input: { filter?: object | null; limit?: number; namespace_prefix?: string[]; offset?: number }): Promise<unknown>;
    neighbors(input: { entity_ref: string; opts: object }): Promise<unknown>;
    peek(input: { group_ref: string }): Promise<unknown>;
    pending_writes(input: { limit?: number | null }): Promise<unknown>;
    put_blob_artifact(input: { id?: string | null; learned_at?: number | null; media_type: string; name: string; occurred_at: number }): Promise<unknown>;
    put_claim(input: { confidence?: number | null; id: string; learnedAt?: number | null; occurred?: object | null; predicate: string; subject: string; value: unknown }): Promise<unknown>;
    put_edge(input: { kind: string; src: string; tgt: string; weight?: number | null }): Promise<unknown>;
    put_habit_checkin(input: { data?: unknown; habit_ref: string; id?: string | null; learned_at?: number | null; occurred_at: number }): Promise<unknown>;
    put_structural(input: { body: unknown; edges?: object[] | null; id?: string | null; kind: string; learned_at?: number | null; occurred_at: number; text_fields?: object[] | null }): Promise<unknown>;
    query_bm25(input: { limit: number; query: string }): Promise<unknown>;
    read_blob_version(input: { artifact_ref: string; version: number }): Promise<unknown>;
    recall(input: { as_of?: number | null; deadline_ms?: number | null; effort?: "light" | "medium" | "high" | "xhigh" | "max" | "call" | null; format?: string | null; limit?: number | null; query: string; scope?: object | null }): Promise<unknown>;
    receipts(input: { limit?: number | null }): Promise<unknown>;
    remember(input: { confidence: number; id?: string | null; learned_at?: number | null; occurred_at?: number | null; predicate: string; relationship_ref?: string | null; salience?: number | null; scope?: unknown; source: string; subject_ref: string; valid_from?: number | null; valid_to?: number | null; value: unknown; world_ref?: string | null }): Promise<unknown>;
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
    safe_delete(input: { entity_ref: string; reason: "user_delete" | "user_hard_delete" | "gdpr_delete" | "policy_delete" }): Promise<unknown>;
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
