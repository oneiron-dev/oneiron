//! The memory rows a run answers itself (`search`, `put_claim`,
//! `supersede_claim`, `put_edge`) are verb-table rows (ARCH-0028: one table):
//! the executor prompt declares them from the table, and a guest call through
//! each keeps the typed call, answer and refusal it had as a hand-written
//! import.
use super::*;

const MEMORY_ROWS: [&str; 4] = ["search", "put_claim", "supersede_claim", "put_edge"];

/// The one declaration the executor prompt gives `name`.
fn declaration<'a>(prompt: &'a str, name: &str) -> &'a str {
    let needle = format!("{name}(input: ");
    let mut lines = prompt
        .lines()
        .filter(|line| line.trim_start().starts_with(&needle));
    let line = lines
        .next()
        .unwrap_or_else(|| panic!("{name} is not declared"));
    assert!(lines.next().is_none(), "{name} is declared twice");
    line
}

/// Done-means: the rendered table lists the memory rows from their verb
/// definitions, each once, typed from the row's own input.
#[test]
fn the_executor_prompt_declares_the_memory_rows_from_the_verb_table() {
    let table = crate::task_verb::sdk::code_mode_declarations();
    let prompt = host::executor_system_prompt("wire");
    for name in MEMORY_ROWS {
        let declared = declaration(table, name);
        assert_eq!(declared, declaration(&prompt, name), "{name}");
    }
    for (name, fields) in [
        ("search", &["query: string", "limit?: "][..]),
        (
            "put_claim",
            &[
                "id: string",
                "predicate: string",
                "subject: string",
                "value: unknown",
                "confidence?: ",
                "occurred?: ",
                "learnedAt?: ",
            ],
        ),
        (
            "supersede_claim",
            &["newId: string", "oldId: string", "now: number"],
        ),
        (
            "put_edge",
            &["src: string", "kind: string", "tgt: string", "weight?: "],
        ),
    ] {
        let declared = declaration(table, name);
        for field in fields {
            assert!(declared.contains(field), "{name} lacks {field}: {declared}");
        }
    }
}
