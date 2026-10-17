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
declare const connector: { readonly [name: string]: { readonly [tool: string]: (args?: object) => Promise<unknown> } } & {
  call(input: { arguments?: unknown; mutation?: "preview" | "explicit_mutation"; name: string; tool: string }): Promise<unknown>;
  list(input: { query?: string | null }): Promise<unknown>;
  outbound: {
    schedule(input: { channel: string; content_ref?: string | null; dedupe_key?: string | null; idempotency_key?: string | null; job_ref?: string | null; mention?: { end: number; message: string; start: number; turn: string } | null; occurred_at?: number | null; on_behalf_of?: string | null; target: string; trigger: string; trigger_ref: string; verb: string }): Promise<unknown>;
  };
  schema(input: { name: string; tool: string }): Promise<unknown>;
  status(input: { name: string }): Promise<unknown>;
};
declare function describe(input: { fold?: string | null; frame_epoch?: number | null; key?: string | null; self?: boolean; session_id?: string | null; task_ref?: string | null }): Promise<unknown>;
declare function peek(input: { group_ref: string }): Promise<unknown>;
declare function report(input: { category: "skill_defect" | "execution_lapse" | "discovery" | "environment" | "preference_shift" | "unclear"; evidence_refs?: string[]; kind?: "problem" | "proposal"; note?: string | null; proposal?: object | null; subject_ref: string; why?: string | null }): Promise<unknown>;
declare const reveal: ((input: { handle: string; why: string }) => Promise<unknown>) & {
  describe(input: { handle: string }): Promise<unknown>;
  wait(input: { reveal: string }): Promise<unknown>;
};
declare namespace self {
  const agents: {
    spawn(input: { agent?: string | null; budget?: object | object | null; care?: "light" | "medium" | "high" | "xhigh" | "max" | null; context?: unknown; context_from?: string[] | null; depth?: number | null; intent_key: string; model?: object | object | null; need: string; notes?: string | null; pattern?: object | object | null; project?: string | null; prompt: string; width?: object | object | null }): Promise<unknown>;
  };
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
      retire(input: { workflow: string }): Promise<unknown>;
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
    scratchpad: {
      recall(input: { query: string; session_id: string }): Promise<unknown>;
    };
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
    list(input: { after?: string | null; limit?: number | null }): Promise<unknown>;
    mark(input: { mark: "seen" | "acked"; notification_ref: string }): Promise<unknown>;
  };
  const leader: {
    advice(input: { top?: number | null }): Promise<unknown>;
    pattern(input: { skill: string }): Promise<unknown>;
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
    record(input: { axis: "converge" | "diverge"; coverage?: { cellsFilled: number; cellsTotal: number } | null; decidedBy: { kind: "leader" } | { kind: "chair" } | { kind: "vote"; tally: Record<string, number> } | { kind: "referee"; rule: string; signedAt: number }; members: string[]; roles?: Record<string, number> | null; teamRef: string }): Promise<unknown>;
    start(input: { intentKey: string; members: { agent: string; briefing?: string | null; intentKey: string }[]; pattern: string; tournament?: string | null }): Promise<unknown>;
  };
  const unfold: (input: { fold: string }) => Promise<unknown>;
  const use: (input: { arguments?: unknown; handle: string; operation: string }) => Promise<unknown>;
}
declare function steer(input: { instruction: string; key: string; task_ref: string }): Promise<unknown>;
declare function summarize(input: { ref: string; effort?: "low" | "medium" | "high"; group?: string[]; defer?: true }): Promise<unknown>;
declare const tasks: {
  answer(input: { handle: object; word: object }): Promise<unknown>;
  create(input: { assignee?: "dreamer" | object | object | object | object | null; label?: string | null; spec: unknown }): Promise<unknown>;
  outcomes(input: { group_ref: string }): Promise<unknown>;
  refuse(input: { at?: number | null; domain: "bond" | "logistics"; reasonRef: string; taskRef?: string | null }): Promise<unknown>;
  update(input: { attempt?: object | null; report?: "ack" | object | object | object | object | object | object | null; report_key?: string | null; resultRef?: string | null; task_ref: string }): Promise<unknown>;
  wait(input: { all?: boolean | null; n_of?: number | null; step_key: string; tasks: string[]; until?: number | null }): Promise<unknown>;
  wave(input: { constraints?: unknown; epic_task_ref: string; objective: string; planner_ref: string }): Promise<unknown>;
};
declare const vault: {
  artifacts: {
    append(input: { artifact_ref: string; content_base64: string; learned_at?: number | null; occurred_at: number; run_ref?: string | null }): Promise<unknown>;
    body: {
      commits(input: { artifact_ref: string }): Promise<unknown>;
      deck: {
        export(input: { artifact_ref: string; run_ref: string; made_by?: unknown }): Promise<unknown>;
        gate(input: { profile?: string | null }): Promise<unknown>;
        merge(input: { artifact_ref: string; fork_ref: string; reviewed_head: number[]; scope?: object | null; landing?: "merge" | "switch" | null; made_by?: unknown }): Promise<unknown>;
        oracle(input: { receipt: object }): Promise<unknown>;
        preview(input: { artifact_ref: string; slides: number[] }): Promise<unknown>;
        review(input: { artifact_ref: string; fork_ref: string }): Promise<unknown>;
      };
      edit(input: { artifact_ref: string; base?: number[] | null; ops: { format: "docx"; ops: object[] } | { format: "xlsx"; ops: object[] } | { format: "pptx"; ops: object[] }; made_by?: unknown }): Promise<unknown>;
      export(input: { artifact_ref: string; run_ref: string; author?: string | null; made_by?: unknown }): Promise<unknown>;
      fork: {
        diff(input: { artifact_ref: string; fork_ref: string }): Promise<unknown>;
        discard(input: { artifact_ref: string; fork_ref: string }): Promise<unknown>;
        edit(input: { artifact_ref: string; fork_ref: string; ops: { format: "docx"; ops: object[] } | { format: "xlsx"; ops: object[] } | { format: "pptx"; ops: object[] }; made_by?: unknown }): Promise<unknown>;
        merge(input: { artifact_ref: string; fork_ref: string; reviewed_head: number[]; reviewed_fork: number[] }): Promise<unknown>;
        open(input: { artifact_ref: string; run_root_ref?: string | null; proposal_ref?: string | null }): Promise<unknown>;
      };
      head(input: { artifact_ref: string }): Promise<unknown>;
      import(input: { artifact_ref: string; version?: number | null; made_by?: unknown }): Promise<unknown>;
      preview(input: { artifact_ref: string }): Promise<unknown>;
      proposal: {
        read(input: { artifact_ref: string; proposal_ref: string }): Promise<unknown>;
        settle(input: { artifact_ref: string; proposal_ref: string; verdict: "accept" | "reject"; scope?: object | null; reviewed_head: number[]; reviewed: { fork_ref: string; reviewed_fork: number[] }[]; reason?: string | null }): Promise<unknown>;
      };
      read(input: { artifact_ref: string; at?: number[] | null }): Promise<unknown>;
    };
    born_from(input: { agent_run?: string | null; ask_ref?: string | null; run_ref?: string | null; skill_ref?: string | null; task_ref?: string | null }): Promise<unknown>;
    create(input: { name: string; media_type: string; content_base64: string; run_ref?: string | null; made_by?: unknown | null }): Promise<unknown>;
    discard(input: { artifact_ref: string; brief_ref?: string | null; proposal_ref: string; reason?: string | null }): Promise<unknown>;
    export(input: { artifact_ref: string; version?: number | null; why?: string | null }): Promise<unknown>;
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
  batch(input: { entities: { entity_type: number; id?: string | null; occurred_start?: number | null; occurred_end?: number | null; learned_at?: number | null; body: unknown; text?: { field: string; value: string }[] | null }[] }): Promise<unknown>;
  campaign: {
    program: {
      archive(input: { campaign_ref: string; expected_definition_version: number; program_ref: string }): Promise<unknown>;
      create(input: { audience?: object | null; campaign_ref: string; name: string; schema_version?: number; steps?: object[] }): Promise<unknown>;
      read(input: { campaign_ref: string; program_ref: string }): Promise<unknown>;
      update(input: { audience?: object | null; campaign_ref: string; expected_definition_version: number; name: string; program_ref: string; steps: object[] }): Promise<unknown>;
    };
  };
  claims: {
    admit(input: { id?: string | null; learned_at?: number | null; occurred_at: number; predicate: string; source_id: string; source_record_id: string; subject_ref: string; value: unknown }): Promise<unknown>;
    history(input: { claim_ref: string }): Promise<unknown>;
    list(input: { lifecycle?: string | null; limit: number; predicate?: string | null; subject_ref?: string | null }): Promise<unknown>;
    put(input: { confidence?: number | null; id: string; learnedAt?: number | null; occurred?: object | null; predicate: string; subject: string; value: unknown }): Promise<unknown>;
    retract(input: { claim_ref: string }): Promise<unknown>;
    seed(input: { claims: object[] }): Promise<unknown>;
    supersede(input: { newId: string; now: number; oldId: string }): Promise<unknown>;
    upsert(input: { confidence: number; id?: string | null; learned_at?: number | null; occurred_at?: number | null; predicate: string; relationship_ref?: string | null; salience?: number | null; scope?: unknown; source: string; subject_ref: string; valid_from?: number | null; valid_to?: number | null; value: unknown; world_ref?: string | null }): Promise<unknown>;
  };
  code: {
    blame(input: { path: string; repo: string; revision_ref?: string | null }): Promise<unknown>;
    diff(input: { after: { path: string; repo: string; revision_ref?: string | null }; before: { path: string; repo: string; revision_ref?: string | null } }): Promise<unknown>;
    proposal_view(input: { proposal_ref: string }): Promise<unknown>;
    repo_diff(input: { after: { repo?: string | null; revision_ref?: string | null; snapshot_ref?: string | null }; before: { repo?: string | null; revision_ref?: string | null; snapshot_ref?: string | null } }): Promise<unknown>;
  };
  commit(input: { claims: object[] }): Promise<unknown>;
  companions: {
    sharing: {
      get(input: { companion_ref: string; contact_ref: string }): Promise<unknown>;
      set(input: { companion_ref: string; contact_ref: string; expected_delta: string; proposal_ref: string }): Promise<unknown>;
    };
  };
  consolidation: {
    enqueue(input: { dedupe_key?: string | null; input: unknown; now?: number | null; run_id?: string | null; scope: string }): Promise<unknown>;
    status(input: { job_ref: string }): Promise<unknown>;
  };
  conversations: {
    create(input: { id?: string | null; occurred_start?: number | null; occurred_end?: number | null; learned_at?: number | null; body: unknown; text?: { field: string; value: string }[] | null }): Promise<unknown>;
    records: {
      append(input: { conversation: string; parent?: string | null; reply_to?: string | null; addr?: "broadcast" | "direct" | null; to?: string[] | null; advance: boolean; body: unknown; text?: { field: string; value: string }[] | null; occurred_start?: number | null; occurred_end?: number | null; learned_at?: number | null; session?: string | null; quote?: { message: string; start: number; end: number } | null }): Promise<unknown>;
    };
    turn: {
      continue(input: { turn_id: string }): Promise<unknown>;
      retry(input: { turn_id: string }): Promise<unknown>;
    };
    turns: {
      create(input: { conversation: string; id?: string | null; occurred_start?: number | null; occurred_end?: number | null; learned_at?: number | null; body: unknown; text?: { field: string; value: string }[] | null }): Promise<unknown>;
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
  embedding_spaces: {
    bind(input: { kind: string; space?: string | null }): Promise<unknown>;
    declare(input: object): Promise<unknown>;
    list(input: object): Promise<unknown>;
    move(input: { candidate: string; incumbent?: string | null; margin?: number | null }): Promise<unknown>;
    move_abandon(input: { candidate: string }): Promise<unknown>;
    move_approve(input: { candidate: string }): Promise<unknown>;
    move_check(input: { candidate: string }): Promise<unknown>;
    move_undo(input: { candidate: string }): Promise<unknown>;
    one_space(input: { space: string }): Promise<unknown>;
    probes: {
      delete(input: { id: string }): Promise<unknown>;
      list(input: object): Promise<unknown>;
      put(input: { author: string; family: string; kind: string; query: string; targets?: string[] }): Promise<unknown>;
    };
    retire(input: { space: string }): Promise<unknown>;
  };
  export(input: { format?: string | null }): Promise<unknown>;
  fanout: {
    ack(input: { answer: "ack" | "ack_and_remember"; launch_ref: string; plan_digest: string; remembered_cap?: number | null }): Promise<unknown>;
    launch(input: { launch_ref: string }): Promise<unknown>;
    resume(input: { launch_ref: string; plan_digest: string; remembered_cap?: number | null; ruling: "approve_once" | "approve_and_remember" | "deny" }): Promise<unknown>;
  };
  forget(input: object): Promise<unknown>;
  get(input: { entity_ref: string }): Promise<unknown>;
  graph: {
    ask(input: { ceiling?: "rule" | "local" | "system_one" | "big" | "human" | "escalation" | null; criteria?: object | null; posture?: string | null; question: unknown; select?: object | null; unit_deadline_ms?: number | null; units?: string[] }): Promise<unknown>;
  };
  guests: {
    mint_slip(input: { expires_at: number; grant_ref: string; holder_key: string }): Promise<unknown>;
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
    add(input: { holder_key?: string | null; member: string; role?: string | null; vault_id: number }): Promise<unknown>;
    change(input: { member: string; role: string; vault_id: number }): Promise<unknown>;
    decline(input: { invitation: string; vault_id: number }): Promise<unknown>;
    invitation_slip(input: { holder_key: string; invitation: string; member: string; vault_id: number }): Promise<unknown>;
    invitations(input: { vault_id: number }): Promise<unknown>;
    leave(input: { vault_id: number }): Promise<unknown>;
    remove(input: { member: string; vault_id: number }): Promise<unknown>;
    withdraw_invitation(input: { invitation: string; member: string; vault_id: number }): Promise<unknown>;
  };
  messages: {
    react(input: { message: string; by: string; glyph: string; occurred_at?: number | null; remove?: boolean; external?: { connector: string; id: string; origin?: string | null } | null }): Promise<unknown>;
  };
  neighbors(input: { entity_ref: string; opts: object }): Promise<unknown>;
  notes: {
    create(input: { kind: string; markdown: string }): Promise<unknown>;
    edit(input: { edit: object; note_ref: string }): Promise<unknown>;
    from_entity(input: { kind: string; source_ref: string }): Promise<unknown>;
    lifecycle(input: { note_ref: string }): Promise<unknown>;
    seal(input: { note_ref: string }): Promise<unknown>;
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
    roster: {
      write(input: { project: string; record: unknown }): Promise<unknown>;
    };
    route_tradeoff(input: { proposal_ref: string; task_ref: string }): Promise<unknown>;
  };
  questions: {
    answers(input: { id: string }): Promise<unknown>;
    backfill(input: { at?: number | null; expected_version: number; id: string }): Promise<unknown>;
    create(input: { definition: unknown }): Promise<unknown>;
    edit(input: { definition: unknown; expected_version: number; id: string }): Promise<unknown>;
    pause(input: { id: string; paused: boolean }): Promise<unknown>;
    read(input: { id: string; version?: number | null }): Promise<unknown>;
  };
  recall(input: { as_of?: number | null; deadline_ms?: number | null; effort?: "light" | "medium" | "high" | "xhigh" | "max" | "call" | null; format?: string | null; limit?: number | null; media?: { bytes_b64: string; kinds?: ("text" | "image" | "audio")[]; mime: string; space: string } | null; query: string; scope?: object | null }): Promise<unknown>;
  receipts: ((input: { kinds?: string[]; limit?: number | null }) => Promise<unknown>) & {
    get(input: { receipt_ref: string }): Promise<unknown>;
  };
  records: {
    erase_confirm(input: { also_same_bytes?: boolean; preview_digest: string; record: string }): Promise<unknown>;
    erase_preview(input: { record: string }): Promise<unknown>;
  };
  refs: {
    links(input: { after?: string | null; limit?: number | null; text?: string | null; turn_ref?: string | null }): Promise<unknown>;
    resolve(input: { reference: string }): Promise<unknown>;
  };
  remember(input: { confidence: number; id?: string | null; learned_at?: number | null; occurred_at?: number | null; predicate: string; relationship_ref?: string | null; salience?: number | null; scope?: unknown; source: string; subject_ref: string; valid_from?: number | null; valid_to?: number | null; value: unknown; world_ref?: string | null }): Promise<unknown>;
  rooms: {
    claim(input: { room_ref: string; turn_ref: string }): Promise<unknown>;
    consent(input: { grant: boolean; join_ref: string; part: "subject" | "spend" | "membership" | "admission"; spend_scope?: string | null }): Promise<unknown>;
    find(input: { after?: string | null; limit?: number | null; room_ref: string }): Promise<unknown>;
    get(input: { room_ref: string; turn_ref: string }): Promise<unknown>;
    host: ((input: { room_ref: string; session_ref?: string | null }) => Promise<unknown>) & {
      hand(input: { room: string; session?: string | null; to: string }): Promise<unknown>;
      pin(input: { agent?: string | null; room: string }): Promise<unknown>;
    };
    join(input: { branch?: string | null; intent_key: string; paid: boolean; room: string; spend_scope?: string | null; subject: object | object }): Promise<unknown>;
    list(input: object): Promise<unknown>;
    messages(input: { after?: string | null; limit?: number | null; room_ref: string }): Promise<unknown>;
    offer: ((input: { agent: string; artifact_ref?: string | null; branch?: string | null; intent_key: string; room: string; spend_scope?: string | null; until?: number | null; what: string }) => Promise<unknown>) & {
      answer(input: { action: "join" | "not_now"; intent_key: string; offer_id: string }): Promise<unknown>;
      reopen(input: { expected_last_engaged_at: number; offer_id: string; until?: number | null }): Promise<unknown>;
      vote(input: { action: "join" | "not_now"; offer_id: string }): Promise<unknown>;
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
  secrets: {
    lift_history(input: { start?: boolean }): Promise<unknown>;
  };
  settings: {
    inference_defaults: ((input: object) => Promise<unknown>) & {
      replace(input: { defaults: unknown; idempotency_key: string }): Promise<unknown>;
    };
    learning: ((input: { key?: string | null }) => Promise<unknown>) & {
      clear(input: { key: string; mode: "seed" | "pin"; project?: string | null; task_type?: string | null }): Promise<unknown>;
      put(input: { key: string; mode: "seed" | "pin"; value: number; weight_runs?: number | null; why: string; project?: string | null; task_type?: string | null }): Promise<unknown>;
    };
    wake_policy: {
      set(input: { policy: unknown; idempotency_key: string }): Promise<unknown>;
    };
  };
  shape: {
    apply(input: { approve?: number[]; plan: object }): Promise<unknown>;
    plan(input: { seed?: object | null }): Promise<unknown>;
    read(input: object): Promise<unknown>;
  };
  shared: {
    close_erase_ask(input: { act_id?: string | null; ask_id: string; erased: boolean }): Promise<unknown>;
    deletion(input: object): Promise<unknown>;
    erase_ask(input: { record: string; vault_id: number }): Promise<unknown>;
    erase_asks(input: { vault_id: number }): Promise<unknown>;
    execute(input: { act_id: string }): Promise<unknown>;
    matured(input: { vault_id: number }): Promise<unknown>;
    object(input: { act_id: string }): Promise<unknown>;
    outcomes(input: { vault_id: number }): Promise<unknown>;
    propose_delete(input: { vault_id: number }): Promise<unknown>;
    propose_remove_owner(input: { export_first: boolean; successor?: string | null; target: string; target_keeps?: string | null; vault_id: number }): Promise<unknown>;
    propose_transfer(input: { from_keeps?: string | null; to: string; vault_id: number }): Promise<unknown>;
    receipt(input: { receipt_id: string }): Promise<unknown>;
    started(input: { vault_id: number }): Promise<unknown>;
    withdraw_objection(input: { act_id: string }): Promise<unknown>;
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
  widen_proposals: ((input: { state?: 'pending' | 'approved' | 'declined' | null }) => Promise<unknown>) & {
    approve(input: { proposal_id: string }): Promise<unknown>;
    decline(input: { proposal_id: string }): Promise<unknown>;
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
