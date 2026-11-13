//! The resolved system and per-turn prompt sites of the executor.
//! Entry: `executor_system_prompt`.
//! Declaration texts are selected by `engine_executor::host::executor_declarations`.

use super::*;

/// The system and per-turn sites render the SAME resolved prompt-package
/// block. The prose lives outside Rust so agent-facing instructions cannot
/// drift from prompt tooling or be hand-copied between call sites.
pub(crate) fn executor_system_prompt(wire: &str) -> String {
    let wire = wire.trim_end();
    let declarations = executor_declarations_block();
    let revision = crate::task_verb::sdk::code_mode_catalog_fragment().revision;
    // FIX 15011: the wake opener's protocol, once, in the stable grammar.
    let wake = crate::context_board::TURN_WAKE_GRAMMAR;
    format!(
        "You are Oneiron's engine-native executor.\n{wire}\n\
         The guest runs inside the CODE-1 Wasmtime WIT component boundary.\n\
         Clock and random values are host-controlled imports for replay determinism.\n\
         {wake}\n\
         Use the prompt-side host verb types below as documentation only; runtime effects arrive \
         as typed host imports. The verb catalog is revision {revision}:\n\n\
         {declarations}"
    )
}

/// The end of the executor's system prompt: every declaration text the
/// build carries (the host verbs, the code-mode catalog, the runtime types),
/// about 1.1 MB, compiled in. A step's replay capture keeps it out of the
/// request it stores and names it by digest (FIX row
/// [AGENT-RUN-START-LATENCY-4S]).
pub(crate) fn executor_declarations_block() -> &'static str {
    static BLOCK: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BLOCK.get_or_init(|| {
        let [host_verbs, verbs, runtime_types] = executor_declarations().map(|file| file.text);
        format!("{host_verbs}\n{verbs}\n{runtime_types}")
    })
}

/// The per-turn trailing instruction: the SAME canonical wire teaching, bound
/// to the durable step the model is being asked for.
pub(in crate::engine_executor) fn executor_turn_instruction(step_seq: u64, wire: &str) -> String {
    let wire = wire.trim_end();
    format!("Emit the source for durable step {step_seq}.\n{wire}")
}
