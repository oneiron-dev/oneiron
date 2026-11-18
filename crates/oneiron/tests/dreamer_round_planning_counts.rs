//! Witness-run replay input fixtures for the round-planning counting target.
//!
//! Only Part 1 is present: vault replay and counting cannot yet preserve both
//! source occurrence times and write-order scans through the ordinary witness.

#[allow(dead_code)]
#[path = "dreamer_round_planning_counts/replay.rs"]
mod replay;

use std::collections::BTreeSet;
use std::io;

use replay::{ReplayAuthor, read_replay_dir, synthetic_conversations};

/// A wrong reader order would plan world/day conversations lexically by day,
/// or merge multiple speaker runs into one TURN instead of retaining each run.
#[test]
fn replay_reader_orders_numeric_days_and_preserves_runs() -> io::Result<()> {
    let directory = tempfile::tempdir()?;
    let user = r#"{"author":"user","occurred_at":100,"texts":["owen walks with yuki.","yuki records the route."]}"#;
    let companion =
        r#"{"author":"companion","occurred_at":101,"texts":["owen measures the garden."]}"#;
    for filename in ["yuki.2.jsonl", "owen.10.jsonl", "owen.2.jsonl"] {
        std::fs::write(
            directory.path().join(filename),
            format!("\n{user}\n\n{companion}\n"),
        )?;
    }
    let conversations = read_replay_dir(directory.path())?;
    let keys: Vec<_> = conversations
        .iter()
        .map(|conversation| (conversation.world.as_str(), conversation.day))
        .collect();
    assert_eq!(keys, [("owen", 2), ("owen", 10), ("yuki", 2)]);
    for conversation in conversations {
        assert_eq!(conversation.runs.len(), 2);
        assert_eq!(conversation.runs[0].author, ReplayAuthor::User);
        assert_eq!(conversation.runs[1].author, ReplayAuthor::Companion);
        assert_eq!(conversation.runs[0].occurred_at, 100);
        assert_eq!(conversation.runs[1].occurred_at, 101);
        assert_eq!(conversation.runs[0].texts.len(), 2);
        assert_eq!(conversation.runs[1].texts.len(), 1);
    }
    Ok(())
}

/// A parser error that includes source values could leak private text during a
/// fleet run. Each malformed run must fail with only filename, line and reason.
#[test]
fn replay_reader_errors_locate_runs_without_quoting_values() -> io::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("owen.1.jsonl");
    let malformed = [
        r#"{"author":"user","occurred_at":1,"texts":["private-marker"]"#,
        r#"{"author":"private-marker","occurred_at":1,"texts":["private-marker"]}"#,
        r#"{"occurred_at":1,"texts":["private-marker"]}"#,
        r#"{"author":"user","texts":["private-marker"]}"#,
        r#"{"author":"user","occurred_at":"private-marker","texts":["private-marker"]}"#,
        r#"{"author":"user","occurred_at":1}"#,
        r#"{"author":"user","occurred_at":1,"texts":[]}"#,
        r#"{"author":"user","occurred_at":1,"texts":[{"content":"private-marker"}]}"#,
    ];
    for input in malformed {
        std::fs::write(&path, format!("\n{input}\n"))?;
        let error = read_replay_dir(directory.path()).expect_err("malformed run must fail");
        let diagnostic = error.to_string();
        assert!(diagnostic.starts_with(&format!("{}:2: ", path.display())));
        assert!(!diagnostic.contains("private-marker"));
    }
    Ok(())
}

/// A permissive filename parser or an empty input would silently change the
/// conversation count. Both must be rejected before any vault is created.
#[test]
fn replay_reader_rejects_invalid_filenames_and_empty_inputs() -> io::Result<()> {
    let directory = tempfile::tempdir()?;
    let error = read_replay_dir(directory.path()).expect_err("empty directory must fail");
    assert!(
        error
            .to_string()
            .starts_with(&format!("{}:0: ", directory.path().display()))
    );
    for filename in [
        "Owen.1.jsonl",
        "owen.+1.jsonl",
        "owen.day.jsonl",
        "owen.1.extra.jsonl",
        "owen.1.txt",
    ] {
        let path = directory.path().join(filename);
        std::fs::write(&path, "{}")?;
        let error = read_replay_dir(directory.path()).expect_err("invalid filename must fail");
        assert!(
            error
                .to_string()
                .starts_with(&format!("{}:0: ", path.display()))
        );
        std::fs::remove_file(path)?;
    }
    let path = directory.path().join("owen.1.jsonl");
    std::fs::write(&path, "\n\n")?;
    let error = read_replay_dir(directory.path()).expect_err("empty file must fail");
    assert!(
        error
            .to_string()
            .starts_with(&format!("{}:0: ", path.display()))
    );
    Ok(())
}

/// Duplicate numeric days under different spellings would make the arithmetic
/// model's conversation identity ambiguous, so the reader rejects them.
#[test]
fn replay_reader_rejects_duplicate_numeric_days() -> io::Result<()> {
    let directory = tempfile::tempdir()?;
    let input =
        r#"{"author":"user","occurred_at":1,"texts":["owen records the route with yuki."]}"#;
    for filename in ["owen.1.jsonl", "owen.01.jsonl"] {
        std::fs::write(directory.path().join(filename), input)?;
    }
    let error = read_replay_dir(directory.path()).expect_err("duplicate conversation must fail");
    assert!(
        error
            .to_string()
            .contains(":0: duplicate world and numeric day")
    );
    Ok(())
}

/// A reused sentence in two synthetic conversations would confound the window
/// comparison. Regeneration must also preserve authors, occurrence and texts.
#[test]
fn synthetic_replay_is_deterministic_and_conversation_sentences_are_disjoint() {
    let counts = [("yuki", 2, 3), ("owen", 2, 4), ("owen", 1, 5)];
    let conversations = synthetic_conversations(&counts);
    assert_eq!(conversations, synthetic_conversations(&counts));
    assert_eq!(
        conversations
            .iter()
            .map(|conversation| conversation.runs.len())
            .collect::<Vec<_>>(),
        [5, 4, 3]
    );
    let mut seen = BTreeSet::new();
    for conversation in &conversations {
        for (index, run) in conversation.runs.iter().enumerate() {
            assert_eq!(
                run.author,
                if index % 2 == 0 {
                    ReplayAuthor::User
                } else {
                    ReplayAuthor::Companion
                }
            );
            assert!(!run.texts.is_empty());
            for text in &run.texts {
                assert!(seen.insert(text));
            }
        }
    }
}
