//! The queue's passes on a vault held as `serve` holds it, one pass at a
//! time, over invented Claude Code sessions and Codex rollouts.

use oneiron::registry::ENTITY_TYPE_MESSAGE;
use oneiron::{Vault, VaultConfig};

use super::*;

const PROJECT: &str = "-Users-ana-code-garden-planner";

/// A queue folder, a vault, a Claude Code root and a Codex one, all fresh.
struct Bench {
    _dir: tempfile::TempDir,
    root: PathBuf,
    codex: PathBuf,
    queue: ImportQueue,
}

impl Bench {
    fn new(budget: Decoded) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("projects");
        fs::create_dir_all(root.join(PROJECT)).unwrap();
        let codex = dir.path().join("sessions");
        fs::create_dir_all(&codex).unwrap();
        let queue = ImportQueue {
            dir: dir.path().join("queue"),
            vault_path: dir.path().join("vault"),
            config: ImportConfig {
                queue: true,
                claude_code_root: Some(root.clone()),
                codex_root: Some(codex.clone()),
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
            codex,
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
        self.put(HistorySource::ClaudeCode, log, None, "json");
    }

    /// `oneiron import codex <rollout> --queue`.
    fn hand_over_rollout(&self, rollout: &Path) {
        self.put(HistorySource::Codex, rollout, None, "json");
    }

    /// A claim an earlier pass kept, saying `place`.
    fn kept(&self, log: &Path, place: Place) {
        self.put(HistorySource::ClaudeCode, log, Some(place), "taking");
    }

    fn put(&self, source: HistorySource, log: &Path, place: Option<Place>, suffix: &str) {
        let name = entry_name(source, log);
        let entry = Entry {
            source: source.source_id().to_owned(),
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
    said(log, message, log)
}

/// Message `message` of session `log`, said on `day` of the month.
fn said(log: u32, message: usize, day: u32) -> String {
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
         \"sessionId\":\"{}\",\"timestamp\":\"2026-09-{day:02}T08:{message:02}:00.000Z\",\
         \"message\":{{\"role\":\"{role}\",\"content\":\"note {message} of session {log}\"}}}}\n",
        uuid(message),
        session_id(log),
    )
}

/// One Claude Code record by hand: a user message, in an inline sidechain
/// or the session's own thread, said at `minute` past 08:00 on 1 September,
/// or with no time at all.
fn line(uuid: &str, parent: Option<&str>, sidechain: bool, minute: Option<u32>) -> String {
    let mut record = serde_json::json!({
        "parentUuid": parent,
        "isSidechain": sidechain,
        "type": "user",
        "uuid": format!("c1000000-0000-4000-8000-{uuid}"),
        "message": {"role": "user", "content": format!("note {uuid}")},
    });
    if let Some(minute) = minute {
        record["timestamp"] = format!("2026-09-01T08:{minute:02}:00.000Z").into();
    }
    format!("{record}\n")
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

/// Sol 1354 R3-2: a resumed copy starts with its original's first line, here
/// an inline sidechain said before the session's own first message, which
/// the copy carries too. The original still lands first, whatever the
/// queue's names say: the copy ends later.
#[test]
fn a_resumed_copy_that_carries_its_originals_sidechain_lands_after_it() {
    let bench = Bench::new(Decoded {
        messages: 3,
        bytes: usize::MAX,
    });
    let vault = bench.vault();
    // The copy gets the name that sorts first, so a tie on names would land
    // it first.
    let (mut original, mut copy) = (bench.log(1), bench.log(2));
    if entry_name(HistorySource::ClaudeCode, &copy)
        > entry_name(HistorySource::ClaudeCode, &original)
    {
        std::mem::swap(&mut original, &mut copy);
    }
    let carried =
        line("000000000001", None, true, Some(0)) + &line("000000000002", None, false, Some(10));
    fs::write(&original, &carried).unwrap();
    let parent = "c1000000-0000-4000-8000-000000000002";
    fs::write(
        &copy,
        carried + &line("000000000003", Some(parent), false, Some(20)),
    )
    .unwrap();
    bench.hand_over(&copy);
    bench.hand_over(&original);

    bench.pass(&vault).0.unwrap();
    assert_eq!(bench.waiting(), names(&[&copy]), "the original lands first");
    bench.pass(&vault).0.unwrap();
    assert_eq!(messages(&vault), 3, "the copy adds only its own message");
    assert!(bench.waiting().is_empty());
}

/// Sol 1354 R5-1: the session's own thread decides where it ends, even when
/// its messages carry no time and one of its subagents ran on after it. Its
/// resumed copy, whose new prompt is timed, still lands after it.
#[test]
fn an_original_whose_own_thread_has_no_times_lands_before_its_resumed_copy() {
    let bench = Bench::new(Decoded {
        messages: 4,
        bytes: usize::MAX,
    });
    let vault = bench.vault();
    let (original, copy) = (bench.log(1), bench.log(2));
    let carried =
        line("000000000001", None, true, Some(0)) + &line("000000000002", None, false, None);
    fs::write(&original, &carried).unwrap();
    let subagents = bench
        .root
        .join(PROJECT)
        .join(session_id(1))
        .join("subagents");
    fs::create_dir_all(&subagents).unwrap();
    fs::write(
        subagents.join("agent-a7f3.jsonl"),
        line("000000000011", None, false, Some(20)) + &line("000000000012", None, false, Some(50)),
    )
    .unwrap();
    let parent = "c1000000-0000-4000-8000-000000000002";
    fs::write(
        &copy,
        carried + &line("000000000003", Some(parent), false, Some(30)),
    )
    .unwrap();
    bench.hand_over(&copy);
    bench.hand_over(&original);

    bench.pass(&vault).0.unwrap();
    assert_eq!(bench.waiting(), names(&[&copy]), "the original lands first");
    bench.pass(&vault).0.unwrap();
    assert_eq!(messages(&vault), 5, "the copy adds only its own message");
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
    // MAX_LOG_BYTES, ImportWarning::LogTooLarge and Landed.left_out are gone
    // (#2608, a8d1d88e1bc): the limit keeps its value here, and the asserts
    // on the left-out list have nothing left to read (rule D).
    let limit: u64 = 1 << 30;
    fs::File::create(&big).unwrap().set_len(limit + 1).unwrap();
    bench.hand_over(&log);

    bench.pass(&vault).0.unwrap();
    assert_eq!(messages(&vault), 4, "the session and its other subagent");
    assert!(bench.waiting().is_empty(), "the entry is done");
    let (landed, reads) = bench.pass(&vault);
    landed.unwrap();
    assert!(reads.is_empty());
}
