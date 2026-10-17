declare const ai: {
  embed(input: { input?: object[]; model?: string | null; params?: object; prompt?: string | null; references?: object[] }): Promise<unknown>;
  image(input: { input?: object[]; model?: string | null; params?: object; prompt?: string | null; references?: object[] }): Promise<unknown>;
  options(input: { inputs?: string[]; operation?: string | null }): Promise<unknown>;
  speech(input: { input?: object[]; model?: string | null; params?: object; prompt?: string | null; references?: object[] }): Promise<unknown>;
  transcribe(input: { input?: object[]; model?: string | null; params?: object; prompt?: string | null; references?: object[] }): Promise<unknown>;
  verdict(input: { ceiling?: "rule" | "local" | "system_one" | "big" | "human" | "escalation" | null; deadline_ms?: number | null; evidence?: string[]; image?: string | null; locate?: boolean; misses?: number; options?: string[]; question: string; reversibility?: "reversible_read" | "outbound_effect"; routine?: boolean; state?: unknown; until_ms?: number | null }): Promise<unknown>;
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
    schedule(input: { channel: string; content_ref?: string | null; dedupe_key?: string | null; idempotency_key?: string | null; job_ref?: string | null; mention?: { end: number; message: string; start: number; turn: string } | null; occurred_at?: number | null; on_behalf_of?: string | null; target: string; trigger: string; trigger_ref: string; verb: string }): Promise<unknown>;
  };
  status(input: { name: string }): Promise<unknown>;
};
declare function describe(input: { fold?: string | null; frame_epoch?: number | null; key?: string | null; self?: boolean; session_id?: string | null; task_ref?: string | null }): Promise<unknown>;
declare function peek(input: { group_ref: string }): Promise<unknown>;
declare function report(input: { category: "skill_defect" | "execution_lapse" | "discovery" | "environment" | "preference_shift" | "unclear"; evidence_refs?: string[]; kind?: "problem" | "proposal"; note?: string | null; proposal?: object | null; subject_ref: string; why?: string | null }): Promise<unknown>;
declare namespace self {
  const browser: {
    batch(input: { no_model?: boolean; steps: (object | object | object | object | object | object | object | object | object | object | object)[]; subgoal?: string | null; until_ms?: number | null }): Promise<unknown>;
    click(input: { ref: string }): Promise<unknown>;
    click_at(input: { image: string; x: number; y: number }): Promise<unknown>;
    crop(input: { height: number; image: string; width: number; x: number; y: number }): Promise<unknown>;
    expect(input: { absent?: boolean; name?: string | null; ref?: string | null; role?: string | null; value?: string | null }): Promise<unknown>;
    find(input: { name?: string | null; role?: string | null }): Promise<unknown>;
    library: {
      find(input: { site?: string | null; subgoal?: string | null }): Promise<unknown>;
      propose(input: { args?: object; params?: string[]; postcondition: object[]; steps: (object | object | object | object | object | object | object | object | object | object | object)[]; subgoal: string }): Promise<unknown>;
      run(input: { args?: object; workflow: string }): Promise<unknown>;
    };
    observe(input: { since?: number | null }): Promise<unknown>;
    open(input: { url: string }): Promise<unknown>;
    screenshot(input: { trigger: "outline_thin" | "no_postcondition" | "decider_reobserve" | "no_accessibility_tree" | "effect_receipt" }): Promise<unknown>;
    select(input: { option: string; ref: string }): Promise<unknown>;
    type(input: { clear?: boolean; ref: string; text: string }): Promise<unknown>;
    view(input: { image: string }): Promise<unknown>;
    wait_for(input: { name?: string | null; role?: string | null; timeout_ms?: number | null }): Promise<unknown>;
    zoom(input: { height: number; image: string; scale?: number | null; width: number; x: number; y: number }): Promise<unknown>;
  };
  const compact: (input: { note?: string | null }) => Promise<unknown>;
  const decisions: {
    asks(input: object): Promise<unknown>;
  };
  const desktop: {
    batch(input: { no_model?: boolean; steps: (object | object | object | object | object | object | object | object | object | object | object)[]; subgoal?: string | null; until_ms?: number | null }): Promise<unknown>;
    click(input: { ref: string }): Promise<unknown>;
    click_at(input: { image: string; x: number; y: number }): Promise<unknown>;
    crop(input: { height: number; image: string; width: number; x: number; y: number }): Promise<unknown>;
    expect(input: { absent?: boolean; name?: string | null; ref?: string | null; role?: string | null; value?: string | null }): Promise<unknown>;
    find(input: { name?: string | null; role?: string | null }): Promise<unknown>;
    hotkey(input: { keys: string[] }): Promise<unknown>;
    key(input: { key: string; modifiers?: string[]; ref?: string | null }): Promise<unknown>;
    observe(input: { since?: number | null }): Promise<unknown>;
    open(input: { url: string }): Promise<unknown>;
    screenshot(input: { trigger: "outline_thin" | "no_postcondition" | "decider_reobserve" | "no_accessibility_tree" | "effect_receipt" }): Promise<unknown>;
    scroll(input: { amount?: number | null; direction: "up" | "down" | "left" | "right"; ref?: string | null }): Promise<unknown>;
    select(input: { option: string; ref: string }): Promise<unknown>;
    type(input: { clear?: boolean; ref: string; text: string }): Promise<unknown>;
    view(input: { image: string }): Promise<unknown>;
    wait_for(input: { name?: string | null; role?: string | null; timeout_ms?: number | null }): Promise<unknown>;
    window(input: { window: string }): Promise<unknown>;
    windows(input: { app?: string | null }): Promise<unknown>;
    zoom(input: { height: number; image: string; scale?: number | null; width: number; x: number; y: number }): Promise<unknown>;
  };
  const focus: {
    refresh(input: { frame_epoch?: number | null }): Promise<unknown>;
    subscribe(input: { scopes: ("my_tasks" | "my_children" | "consults_to_me" | "memories" | "worlds" | "presence" | "counts")[] }): Promise<unknown>;
    unsubscribe(input: { scopes: ("my_tasks" | "my_children" | "consults_to_me" | "memories" | "worlds" | "presence" | "counts")[] }): Promise<unknown>;
  };
  const fold: (span: readonly [number, number], options?: { note?: string | null }) => Promise<unknown>;
  const folds: (input: object) => Promise<unknown>;
  const grants: {
    ask(input: { pr: string; scope: { kind: 'messages' | 'summaries' | 'relationship_claims'; space_ref: string } | { kind: 'companion_profile'; facet_ref?: string | null } }): Promise<unknown>;
  };
  const identity: {
    answer(input: { ask: string; choice: string }): Promise<unknown>;
    settle(input: { conversation?: string | null; effect: "send" | "pay" | "invite" | "share"; name: string; prompt: string; someone_new: string }): Promise<unknown>;
  };
  const inbox: {
    concern: ((input: { card: string }) => Promise<unknown>) & {
      move(input: { card: string; move: "ask_coach" }): Promise<unknown>;
      outcome(input: { card: string; outcome: "confirmed" | "dismissed" | "unresolved" }): Promise<unknown>;
    };
  };
  const memory: {
    diary: ((input: { content: string; kind?: string | null }) => Promise<unknown>) & {
      query(input: { agent: string; reason: string }): Promise<unknown>;
      reads(input: { limit?: number | null }): Promise<unknown>;
      review(input: { request: string; approve: boolean }): Promise<unknown>;
    };
  };
  const message: (input: { mention?: { end: number; message: string; start: number; turn: string } | null; pr: string; text: string }) => Promise<unknown>;
  const skills: {
    call(input: { args: unknown; skill: string }): Promise<unknown>;
    callables(input: object): Promise<unknown>;
    fork(input: { id?: string | null; parent: string; skill_id: string }): Promise<unknown>;
    save(input: { expected_version?: string | null; files: { content: string; path: string }[]; id?: string | null }): Promise<unknown>;
  };
  const spawn: (input: { ask: string; intent_key: string; source: unknown }) => Promise<unknown>;
  const team: {
    record(input: { axis: "converge" | "diverge"; calls?: number | null; confessions?: number | null; coverage?: { cellsFilled: number; cellsTotal: number } | null; decidedBy: { kind: "leader" } | { kind: "chair" } | { kind: "vote"; tally: Record<string, number> } | { kind: "referee"; rule: string; signedAt: number }; members: string[]; roles?: Record<string, number> | null; spend?: number | null; spendCap?: number | null; teamRef: string }): Promise<unknown>;
    start(input: { intentKey: string; members: { agent: string; briefing?: string | null; intentKey: string }[]; pattern: string; tournament?: string | null }): Promise<unknown>;
  };
  const unfold: (input: { fold: string }) => Promise<unknown>;
}
declare function steer(input: { instruction: string; key: string; task_ref: string }): Promise<unknown>;
declare const tasks: {
  answer(input: { handle: object; word: object }): Promise<unknown>;
  create(input: { assignee?: "dreamer" | object | object | object | object | null; label?: string | null; spec: unknown }): Promise<unknown>;
  outcomes(input: { group_ref: string }): Promise<unknown>;
  refuse(input: { at?: number | null; domain: "bond" | "logistics"; reasonRef: string; taskRef?: string | null }): Promise<unknown>;
  update(input: { resultRef?: string | null; task_ref: string }): Promise<unknown>;
  wait(input: { all?: boolean | null; n_of?: number | null; step_key: string; tasks: string[]; until?: number | null }): Promise<unknown>;
};
declare const vault: {
  artifacts: {
    append(input: { artifact_ref: string; content_base64: string; learned_at?: number | null; occurred_at: number; run_ref?: string | null }): Promise<unknown>;
    born_from(input: { agent_run?: string | null; ask_ref?: string | null; run_ref?: string | null; skill_ref?: string | null; task_ref?: string | null }): Promise<unknown>;
    discard(input: { artifact_ref: string; brief_ref?: string | null; proposal_ref: string; reason?: string | null }): Promise<unknown>;
    export(input: { artifact_ref: string; version?: number | null }): Promise<unknown>;
    keep(input: { artifact_ref: string; brief_ref?: string | null; proposal_ref: string; reason?: string | null }): Promise<unknown>;
    proposals(input: { artifact_ref: string }): Promise<unknown>;
    propose_deck(input: { artifact_ref: string; context?: unknown; made_by?: unknown; run_ref: string; transaction: unknown }): Promise<unknown>;
    propose_output(input: { artifact_ref: string; content_base64: string; made_by?: unknown; media_type: string; name: string; report?: unknown; run_ref: string }): Promise<unknown>;
    put(input: { id?: string | null; learned_at?: number | null; media_type: string; name: string; occurred_at: number }): Promise<unknown>;
    read(input: { artifact_ref: string; version: number }): Promise<unknown>;
    release_wait(input: { artifact_ref: string; brief_ref?: string | null; proposal_ref: string; reason?: string | null }): Promise<unknown>;
    review_slides(input: { artifact_ref: string; author: unknown; deadline_ms?: number | null; evidence_refs?: string[]; labels: unknown; made_by?: unknown; question: unknown; reversibility?: unknown; run_ref: string; unit_budget_ms?: number | null; units: { renderer: string; review_image?: string | null; review_image_ref?: string | null; target: unknown }[] }): Promise<unknown>;
    undo(input: { artifact_ref: string; brief_ref?: string | null; proposal_ref: string; reason?: string | null }): Promise<unknown>;
    view(input: { artifact_ref: string }): Promise<unknown>;
    waits(input: { artifact_ref: string }): Promise<unknown>;
  };
  authority: {
    audit(input: { after?: string | null; kinds?: ("grant" | "revoke" | "confirm" | "other")[]; limit?: number | null }): Promise<unknown>;
    handoff_alarms: ((input: object) => Promise<unknown>) & {
      acknowledge(input: { signer: string }): Promise<unknown>;
    };
  };
  claims: {
    admit(input: { id?: string | null; learned_at?: number | null; occurred_at: number; predicate: string; source_id: string; source_record_id: string; subject_ref: string; value: unknown }): Promise<unknown>;
    history(input: { claim_ref: string }): Promise<unknown>;
    list(input: { lifecycle?: string | null; limit: number; predicate?: string | null; subject_ref?: string | null }): Promise<unknown>;
    put(input: { confidence?: number | null; id: string; learnedAt?: number | null; occurred?: object | null; predicate: string; subject: string; value: unknown }): Promise<unknown>;
    retract(input: { claim_ref: string }): Promise<unknown>;
    supersede(input: { newId: string; now: number; oldId: string }): Promise<unknown>;
    upsert(input: { confidence: number; id?: string | null; learned_at?: number | null; occurred_at?: number | null; predicate: string; relationship_ref?: string | null; salience?: number | null; scope?: unknown; source: string; subject_ref: string; valid_from?: number | null; valid_to?: number | null; value: unknown; world_ref?: string | null }): Promise<unknown>;
  };
  commit(input: { claims: object[] }): Promise<unknown>;
  companions: {
    sharing: {
      get(input: { companion_ref: string; contact_ref: string }): Promise<unknown>;
      set(input: { companion_ref: string; contact_ref: string; expected_delta: string; proposal_ref: string }): Promise<unknown>;
    };
  };
  conversations: {
    turn: {
      continue(input: { turn_id: string }): Promise<unknown>;
      retry(input: { turn_id: string }): Promise<unknown>;
    };
  };
  decisions: {
    asks: {
      answer(input: { answer: unknown; seq: number }): Promise<unknown>;
      climb(input: { seq: number }): Promise<unknown>;
    };
  };
  delete(input: { entity_ref: string; reason: "user_delete" | "user_hard_delete" | "gdpr_delete" | "policy_delete" }): Promise<unknown>;
  disclosure: {
    offer(input: { ask?: string | null; beneficiary: string; channel: string; contact: string; expires_at: number; owner_ref: string; purpose: string; scope: unknown }): Promise<unknown>;
  };
  edges: {
    put(input: { kind: string; src: string; tgt: string; weight?: number | null }): Promise<unknown>;
  };
  export(input: { format?: string | null }): Promise<unknown>;
  forget(input: object): Promise<unknown>;
  get(input: { entity_ref: string }): Promise<unknown>;
  graph: {
    ask(input: { ceiling?: "rule" | "local" | "system_one" | "big" | "human" | "escalation" | null; question: unknown; select?: object | null; unit_deadline_ms?: number | null; units?: string[] }): Promise<unknown>;
  };
  guests: {
    revoke(input: { grant_ref: string }): Promise<unknown>;
  };
  habits: {
    checkin(input: { data?: unknown; habit_ref: string; id?: string | null; learned_at?: number | null; occurred_at: number }): Promise<unknown>;
  };
  hooks: {
    replay(input: { binding: string; limit?: number | null; since?: string | null }): Promise<unknown>;
  };
  hydrate(input: { refs: string[] }): Promise<unknown>;
  images: {
    view(input: { edge?: number | null; handle: string; region?: { height: number; width: number; x: number; y: number } | null }): Promise<unknown>;
  };
  inspection: {
    resolve(input: { handle: string }): Promise<unknown>;
  };
  kv: {
    delete(input: { key: string; namespace: string[] }): Promise<unknown>;
    get(input: { key: string; namespace: string[] }): Promise<unknown>;
    namespaces(input: { limit?: number; max_depth?: number | null; offset?: number; prefix?: string[]; suffix?: string[] }): Promise<unknown>;
    put(input: { key: string; namespace: string[]; request_id: string; source?: string; value: unknown }): Promise<unknown>;
    search(input: { filter?: object | null; limit?: number; namespace_prefix?: string[]; offset?: number }): Promise<unknown>;
  };
  legal_holds: {
    lift_and_erase(input: { records: string[] }): Promise<unknown>;
    list(input: object): Promise<unknown>;
    log(input: object): Promise<unknown>;
    place(input: { matter_ref?: string | null; targets: unknown[] }): Promise<unknown>;
    widen(input: { hold_id: string; targets: unknown[] }): Promise<unknown>;
  };
  lenses: {
    activate(input: { compiled_hash: string; expected_active_ref?: string | null; lens_ref: string }): Promise<unknown>;
    deactivate(input: { expected_active_ref: string; slot: object }): Promise<unknown>;
    default(input: { dossiers?: object[]; ledger?: string[]; threads?: string[]; title: string }): Promise<unknown>;
    list(input: { after?: string | null; limit?: number | null; pack_name?: string | null; with_compiled?: boolean }): Promise<unknown>;
    propose(input: { compiled: unknown; intent_prompt: string; pack_content_hash: string; slot: object }): Promise<unknown>;
  };
  members: {
    accept(input: { invitation: string; vault_id: number }): Promise<unknown>;
    add(input: { member: string; role?: string | null; vault_id: number }): Promise<unknown>;
    change(input: { member: string; role: string; vault_id: number }): Promise<unknown>;
    decline(input: { invitation: string; vault_id: number }): Promise<unknown>;
    invitations(input: { vault_id: number }): Promise<unknown>;
    leave(input: { vault_id: number }): Promise<unknown>;
    remove(input: { member: string; vault_id: number }): Promise<unknown>;
    withdraw_invitation(input: { invitation: string; member: string; vault_id: number }): Promise<unknown>;
  };
  neighbors(input: { entity_ref: string; opts: object }): Promise<unknown>;
  notes: {
    create(input: { kind: string; markdown: string }): Promise<unknown>;
    edit(input: { edit: object; note_ref: string }): Promise<unknown>;
    from_entity(input: { kind: string; source_ref: string }): Promise<unknown>;
  };
  packs: {
    put(input: { files: object[] }): Promise<unknown>;
    setup: {
      answer(input: { answer?: object | null; card_action?: object | null; pack: string; source?: string | null }): Promise<unknown>;
      get(input: { pack: string; source?: string | null }): Promise<unknown>;
      prepare(input: { pack: string; source?: string | null }): Promise<unknown>;
      verify(input: { connection: string; pack: string; source?: string | null }): Promise<unknown>;
    };
  };
  people: {
    get(input: { pr: string }): Promise<unknown>;
    list(input: { vault?: string | null; page?: number | null }): Promise<unknown>;
  };
  projects: {
    confirm(input: { action_id: string; card_id: string; occurred_at: number }): Promise<unknown>;
    dismiss_card(input: { card_id: string }): Promise<unknown>;
    goal: {
      dismiss(input: { expected_goal_ref: string; project_ref: string; question_digest: string }): Promise<unknown>;
      intake(input: { project_ref: string }): Promise<unknown>;
      revisions(input: { project_ref: string }): Promise<unknown>;
    };
    proposals(input: { conversation_ref: string }): Promise<unknown>;
    propose(input: { card_id: string; goal: object; picks: object; source_message_ref: string }): Promise<unknown>;
    route_tradeoff(input: { proposal_ref: string; task_ref: string }): Promise<unknown>;
  };
  questions: {
    answers(input: { id: string }): Promise<unknown>;
    create(input: { definition: unknown }): Promise<unknown>;
    edit(input: { definition: unknown; expected_version: number; id: string }): Promise<unknown>;
    pause(input: { id: string; paused: boolean }): Promise<unknown>;
    read(input: { id: string; version?: number | null }): Promise<unknown>;
  };
  recall(input: { as_of?: number | null; deadline_ms?: number | null; effort?: "light" | "medium" | "high" | "xhigh" | "max" | "call" | null; format?: string | null; limit?: number | null; query: string; scope?: object | null }): Promise<unknown>;
  receipts: ((input: { kinds?: string[]; limit?: number | null }) => Promise<unknown>) & {
    get(input: { receipt_ref: string }): Promise<unknown>;
  };
  refs: {
    links(input: { after?: string | null; limit?: number | null; text?: string | null; turn_ref?: string | null }): Promise<unknown>;
    resolve(input: { reference: string }): Promise<unknown>;
  };
  remember(input: { confidence: number; id?: string | null; learned_at?: number | null; occurred_at?: number | null; predicate: string; relationship_ref?: string | null; salience?: number | null; scope?: unknown; source: string; subject_ref: string; valid_from?: number | null; valid_to?: number | null; value: unknown; world_ref?: string | null }): Promise<unknown>;
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
    offer: ((input: { agent: string; artifact_ref?: string | null; branch?: string | null; intent_key: string; room: string; spend_scope?: string | null; what: string }) => Promise<unknown>) & {
      answer(input: { action: "join" | "not_now"; intent_key: string; offer_id: string }): Promise<unknown>;
    };
    offers(input: { after?: string | null; branch?: string | null; limit?: number | null; room: string }): Promise<unknown>;
    participants(input: { after?: string | null; branch?: string | null; limit?: number | null; room: string }): Promise<unknown>;
    render(input: { room_ref: string }): Promise<unknown>;
    reply_strips(input: { after?: string | null; limit?: number | null; room_ref: string; thread_ref: string }): Promise<unknown>;
    sharing(input: { room_ref: string }): Promise<unknown>;
    speak(input: { conversation_ref: string; messages: object[]; occurred_at: number; quote?: object | null; turn_ref?: string | null }): Promise<unknown>;
    trunk(input: { room_ref: string; turn_ref: string }): Promise<unknown>;
  };
  search: ((input: { limit?: number | null; query: string }) => Promise<unknown>) & {
    bm25(input: { limit: number; query: string }): Promise<unknown>;
  };
  shared: {
    deletion(input: object): Promise<unknown>;
    execute(input: { act_id: string }): Promise<unknown>;
    outcomes(input: { vault_id: number }): Promise<unknown>;
    propose_delete(input: { vault_id: number }): Promise<unknown>;
    propose_remove_owner(input: { export_first: boolean; successor?: string | null; target: string; target_keeps?: string | null; vault_id: number }): Promise<unknown>;
    propose_transfer(input: { from_keeps?: string | null; to: string; vault_id: number }): Promise<unknown>;
    receipt(input: { receipt_id: string }): Promise<unknown>;
  };
  shares: {
    create(input: { brief_ref: string; expires_at?: number | null; facet_refs?: string[]; include_unscoped?: boolean; mention?: { end: number; message: string; start: number; turn: string } | null; recipient: string; share_id?: string | null; travel?: { born_with?: ("prompt" | "why" | "keep" | "intent_prompt")[] } | null; world_refs?: string[] }): Promise<unknown>;
    revoke(input: { share_ref: string }): Promise<unknown>;
    view(input: { narrowing?: { facet_refs?: string[]; include_unscoped?: boolean; world_refs?: string[] } | null; share_ref: string }): Promise<unknown>;
  };
  structural: {
    put(input: { body: unknown; edges?: object[] | null; id?: string | null; kind: string; learned_at?: number | null; occurred_at: number; text_fields?: object[] | null }): Promise<unknown>;
  };
  weave: {
    digest(input: { scheduled_for?: number | null }): Promise<unknown>;
    lens(input: { sections: Array<{ kind: string; predicates?: string[]; edge_kinds?: string[] }> }): Promise<unknown>;
    link: {
      wrong(input: { source_ref: string; kind: string; target_ref: string }): Promise<unknown>;
    };
    report(input: { sections: Array<{ kind: string; predicates?: string[]; edge_kinds?: string[] }> }): Promise<unknown>;
  };
  witness(input: { conversation_ref: string; messages: object[]; occurred_at: number; quote?: object | null; turn_ref?: string | null }): Promise<unknown>;
  workspace: {
    work_companion: {
      get(input: { workspace_ref: string }): Promise<unknown>;
      set(input: { policy: "choose" | "suggest" | "require"; workspace_ref: string }): Promise<unknown>;
    };
  };
  writes: {
    pending(input: { limit?: number | null }): Promise<unknown>;
  };
};
declare function wait(input: { handle: object; step_key: string }): Promise<unknown>;
