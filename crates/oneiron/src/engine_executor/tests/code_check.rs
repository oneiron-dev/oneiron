//! The checked-in `src/task_verb/code-mode.d.ts`, which a shadow check's
//! oracle fixtures read, is the verb table's rendering of `self.memory`.

/// Substrate invariant (ARCH-0028, one table): the checked-in code-mode
/// declarations are exactly what the verb table renders. A row added, dropped
/// or retyped in `scripts/sdk/agent-verbs.json` fails here until the file is
/// regenerated with `ONEIRON_UPDATE_TEST_FIXTURES=1`.
#[test]
fn code_mode_declarations_file_is_the_verb_table() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/task_verb/code-mode.d.ts");
    let rendered = crate::task_verb::sdk::code_mode_declarations();
    if std::env::var_os("ONEIRON_UPDATE_TEST_FIXTURES").is_some() {
        std::fs::write(path, rendered).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        rendered,
        "regenerate with ONEIRON_UPDATE_TEST_FIXTURES=1"
    );
}
