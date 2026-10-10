//! The queue's passes on a vault held as `serve` holds it, one pass at a
//! time, over invented Claude Code sessions.

use oneiron::registry::ENTITY_TYPE_MESSAGE;
use oneiron::{Vault, VaultConfig};

use super::*;

const PROJECT: &str = "-Users-ana-code-garden-planner";

/// A queue folder, a vault and a Claude Code root, all fresh.
struct Bench {
    _dir: tempfile::TempDir,
    root: PathBuf,
    queue: ImportQueue,
}

impl Bench {
    fn new(budget: Decoded) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("projects");
        fs::create_dir_all(root.join(PROJECT)).unwrap();
        let queue = ImportQueue {
            dir: dir.path().join("queue"),
            vault_path: dir.path().join("vault"),
            config: ImportConfig {
                queue: true,
                claude_code_root: Some(root.clone()),
                ..ImportConfig::default()
            },
            budget,
        };
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&queue.dir)
            .unwrap();
        Self {
            _dir: dir,
            root,
            queue,
        }
    }

    /// The vault, held by this process as a running `serve` holds it.
    fn vault(&self) -> Vault {
        Vault::open_owned(&self.queue.vault_path, VaultConfig::server()).unwrap()
    }

    /// Session `log`'s file under the root.
    fn log(&self, log: u32) -> PathBuf {
        self.root
            .join(PROJECT)
            .join(format!("{}.jsonl", session_id(log)))
    }

    /// Writes messages `from..to` of session `log` at the end of `path`.
    fn write(&self, path: &Path, log: u32, messages: std::ops::Range<usize>) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        for message in messages {
            file.write_all(record(log, message).as_bytes()).unwrap();
        }
    }

    /// `oneiron import claude-code <log> --queue`, as the hooks run it.
    fn hand_over(&self, log: &Path) {
        self.put(log, None, "json");
    }

    /// A claim an earlier pass kept, saying `place`.
    fn kept(&self, log: &Path, place: Place) {
        self.put(log, Some(place), "taking");
    }

    fn put(&self, log: &Path, place: Option<Place>, suffix: &str) {
        let name = entry_name(HistorySource::ClaudeCode, log);
        let entry = Entry {
            source: HistorySource::ClaudeCode.source_id().to_owned(),
            path: log.to_path_buf(),
            passes: 0,
            place,
        };
        fs::write(
            self.queue.dir.join(format!("{name}.{suffix}")),
            serde_json::to_vec(&entry).unwrap(),
        )
        .unwrap();
    }

    /// The entries waiting, claimed or not.
    fn waiting(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.queue.dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| !name.starts_with('.'))
            .map(|name| name.split('.').next().unwrap().to_owned())
            .collect();
        names.sort();
        names
    }

    /// One pass, and the logs it read.
    fn pass(&self, vault: &Vault) -> (anyhow::Result<Landed>, Vec<PathBuf>) {
        READS.with_borrow_mut(Vec::clear);
        let landed = self.queue.pass(vault);
        (landed, READS.with_borrow_mut(std::mem::take))
    }
}

fn session_id(log: u32) -> String {
    format!("5d0c0a7e-1111-4222-8333-9444555566{log:02}")
}

/// Message `message` of session `log`, one whole record: said on day `log`
/// of the month, a minute after the one before.
fn record(log: u32, message: usize) -> String {
    let role = if message.is_multiple_of(2) {
        "user"
    } else {
        "assistant"
    };
    let uuid = |message: usize| format!("c10000{log:02}-0000-4000-8000-{message:012}");
    let parent = match message {
        0 => "null".to_owned(),
        _ => format!("\"{}\"", uuid(message - 1)),
    };
    format!(
        "{{\"parentUuid\":{parent},\"isSidechain\":false,\"type\":\"{role}\",\"uuid\":\"{}\",\
         \"sessionId\":\"{}\",\"timestamp\":\"2026-09-{log:02}T08:{message:02}:00.000Z\",\
         \"message\":{{\"role\":\"{role}\",\"content\":\"note {message} of session {log}\"}}}}\n",
        uuid(message),
        session_id(log),
    )
}

fn messages(vault: &Vault) -> u64 {
    vault.count_entities_by_type(ENTITY_TYPE_MESSAGE).unwrap()
}

fn names(logs: &[&PathBuf]) -> Vec<String> {
    let mut names: Vec<String> = logs
        .iter()
        .map(|log| entry_name(HistorySource::ClaudeCode, log))
        .collect();
    names.sort();
    names
}

/// Greptile 1347 (queue.rs:202): past the decoded budget, a pass read every
/// waiting log before it chose what lands, read the chosen ones again, and
/// every later pass read the waiting ones again. Now a log is read once to
/// place it, and a log that waits is read next only by the pass that lands
/// it: six sessions of four messages, two sessions' worth a pass.
#[test]
fn a_backlog_past_the_budget_reads_each_log_once_per_landing() {
    let bench = Bench::new(Decoded {
        messages: 8,
        bytes: usize::MAX,
    });
    let vault = bench.vault();
    let logs: Vec<PathBuf> = (1..=6).map(|log| bench.log(log)).collect();
    for (log, path) in (1..=6).zip(&logs) {
        bench.write(path, log, 0..4);
        bench.hand_over(path);
    }

    let (landed, mut reads) = bench.pass(&vault);
    landed.unwrap();
    reads.sort();
    assert_eq!(
        reads, logs,
        "the first pass reads each log once, to place it"
    );
    assert_eq!(messages(&vault), 8, "the two earliest sessions land");
    let later: Vec<&PathBuf> = logs[2..].iter().collect();
    assert_eq!(bench.waiting(), names(&later));

    for landing in [&logs[2..4], &logs[4..6]] {
        let (landed, mut reads) = bench.pass(&vault);
        landed.unwrap();
        reads.sort();
        assert_eq!(reads, landing, "a pass reads only the logs it lands");
    }
    assert_eq!(messages(&vault), 24);
    assert!(bench.waiting().is_empty());
    let (_, reads) = bench.pass(&vault);
    assert!(reads.is_empty());
}

/// Sol 1354 F1: a claim's kept place is only a hint. One that says its log
/// holds more than any pass may hold does not stop the queue: the earliest
/// claim is always read, placed anew, and lands.
#[test]
fn a_claim_that_says_it_holds_more_than_a_pass_does_not_stop_the_queue() {
    let bench = Bench::new(Decoded {
        messages: 4,
        bytes: usize::MAX,
    });
    let vault = bench.vault();
    let (first, second) = (bench.log(1), bench.log(2));
    bench.write(&first, 1, 0..2);
    bench.kept(
        &first,
        Place {
            first: (0, 0),
            size: Decoded {
                messages: usize::MAX,
                bytes: usize::MAX,
            },
        },
    );
    bench.write(&second, 2, 0..2);
    bench.hand_over(&second);

    for _ in 0..2 {
        let (landed, mut reads) = bench.pass(&vault);
        landed.unwrap();
        let read = reads.len();
        reads.sort();
        reads.dedup();
        assert_eq!(reads.len(), read, "a log is read once a pass");
    }
    assert_eq!(messages(&vault), 4, "both land");
    assert!(bench.waiting().is_empty());
}

/// Sol 1354 F3: a log read once in a pass is not read again in it, even when
/// the claim that sorted before it and spent the budget is gone by the time
/// it would land. It lands on the next pass.
#[test]
fn a_pass_reads_a_log_once_even_when_what_sorted_before_it_is_gone() {
    let bench = Bench::new(Decoded {
        messages: 4,
        bytes: usize::MAX,
    });
    let vault = bench.vault();
    let logs: Vec<PathBuf> = (1..=3).map(|log| bench.log(log)).collect();
    for (log, path) in (1..=2).zip(&logs) {
        bench.write(path, log, 0..4);
        bench.hand_over(path);
    }
    bench.pass(&vault).0.unwrap();
    assert_eq!(messages(&vault), 4, "the first lands; the second waits");

    fs::remove_file(&logs[1]).unwrap();
    bench.write(&logs[2], 3, 0..2);
    bench.hand_over(&logs[2]);
    let (landed, reads) = bench.pass(&vault);
    landed.unwrap();
    assert_eq!(
        reads.iter().filter(|read| **read == logs[2]).count(),
        1,
        "{reads:?}"
    );
    let (landed, reads) = bench.pass(&vault);
    landed.unwrap();
    assert_eq!(reads, [logs[2].clone()]);
    assert_eq!(messages(&vault), 6);
    assert!(bench.waiting().is_empty());
}

/// A live session's last record still being written lands whole on a later
/// pass, once the log has it.
#[test]
fn a_record_cut_mid_line_lands_on_a_later_pass() {
    let bench = Bench::new(Decoded::LIMIT);
    let vault = bench.vault();
    let log = bench.log(1);
    bench.write(&log, 1, 0..3);
    let last = record(1, 3);
    let (written, rest) = last.split_at(last.len() / 2);
    fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .unwrap()
        .write_all(written.as_bytes())
        .unwrap();
    bench.hand_over(&log);

    bench.pass(&vault).0.unwrap();
    assert_eq!(messages(&vault), 3, "the whole records land");
    assert_eq!(bench.waiting().len(), 1, "the claim waits for the rest");

    fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .unwrap()
        .write_all(rest.as_bytes())
        .unwrap();
    bench.pass(&vault).0.unwrap();
    assert_eq!(messages(&vault), 4, "the finished record lands");
    assert!(bench.waiting().is_empty());
}

/// A claim kept for a log cut mid-line is given up after a few passes, but a
/// hand-over queued while it waits replaces it and starts over, so what the
/// session wrote since lands.
#[test]
fn a_hand_over_queued_while_an_older_claim_waits_is_not_lost() {
    let bench = Bench::new(Decoded::LIMIT);
    let vault = bench.vault();
    let log = bench.log(1);
    let append = |text: &str| {
        fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    };
    bench.write(&log, 1, 0..3);
    let cut = record(1, 3);
    let (head, tail) = cut.split_at(cut.len() / 2);
    append(head);
    bench.hand_over(&log);
    // The first pass and its retries but the last.
    for _ in 0..MID_LINE_PASSES {
        bench.pass(&vault).0.unwrap();
    }
    assert_eq!(messages(&vault), 3);
    assert_eq!(bench.waiting().len(), 1, "the older claim still waits");

    // The session writes on, the newest record cut again, and hands over.
    append(tail);
    bench.write(&log, 1, 4..5);
    let cut = record(1, 5);
    let (head, tail) = cut.split_at(cut.len() / 2);
    append(head);
    bench.hand_over(&log);
    bench.pass(&vault).0.unwrap();
    assert_eq!(messages(&vault), 5, "the newer hand-over lands");
    assert_eq!(bench.waiting().len(), 1, "and waits for its cut record");

    append(tail);
    bench.pass(&vault).0.unwrap();
    assert_eq!(messages(&vault), 6);
    assert!(bench.waiting().is_empty());
}

/// A pass whose landing fails keeps its claims; a later pass lands them.
/// Here the vault is open without its writer lease, so no owner can land.
#[test]
fn a_landing_error_keeps_the_entry_and_a_later_pass_lands_it() {
    let bench = Bench::new(Decoded::LIMIT);
    drop(bench.vault());
    let log = bench.log(1);
    bench.write(&log, 1, 0..4);
    bench.hand_over(&log);

    let unleased = Vault::open(&bench.queue.vault_path, VaultConfig::server()).unwrap();
    assert!(bench.pass(&unleased).0.is_err(), "nothing can land");
    assert_eq!(messages(&unleased), 0);
    assert_eq!(bench.waiting().len(), 1, "the entry stays queued");
    drop(unleased);

    let vault = bench.vault();
    bench.pass(&vault).0.unwrap();
    assert_eq!(messages(&vault), 4, "a later pass lands it");
    assert!(bench.waiting().is_empty());
}

/// #1348 in the queue: a session whose subagent log is over the per-log
/// limit lands everything else, and the pass says which log it left out,
/// as `oneiron import` does. The entry is done; no pass takes it up again.
/// The big log is sparse: no disk.
#[test]
fn a_subagent_log_over_the_limit_is_left_out_and_the_rest_of_the_session_lands() {
    let bench = Bench::new(Decoded::LIMIT);
    let vault = bench.vault();
    let log = bench.log(1);
    bench.write(&log, 1, 0..2);
    let subagents = bench
        .root
        .join(PROJECT)
        .join(session_id(1))
        .join("subagents");
    fs::create_dir_all(&subagents).unwrap();
    bench.write(&subagents.join("agent-a7f3.jsonl"), 2, 0..2);
    let big = subagents.join("agent-b9c8.jsonl");
    let limit = super::super::MAX_LOG_BYTES;
    fs::File::create(&big).unwrap().set_len(limit + 1).unwrap();
    bench.hand_over(&log);

    let landed = bench.pass(&vault).0.unwrap();
    assert_eq!(messages(&vault), 4, "the session and its other subagent");
    assert_eq!(
        serde_json::to_value(&landed.left_out).unwrap(),
        serde_json::json!([{
            "warning": "log_too_large",
            "path": big,
            "bytes": limit + 1,
            "limit": limit,
        }])
    );
    assert!(bench.waiting().is_empty(), "the entry is done");
    let (landed, reads) = bench.pass(&vault);
    assert!(landed.unwrap().left_out.is_empty() && reads.is_empty());
}
