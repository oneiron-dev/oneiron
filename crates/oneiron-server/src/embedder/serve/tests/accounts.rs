//! Census L10-10 (CROSS-ARCH-0019 #dm-xaccount-embedder): "One bearer key
//! covers every caller. Not built: per-account keys, per-account quotas".
//! Each account in the accounts file has its own key, any other key is
//! refused, and a re-read of the file revokes an account without a restart.
//! An account past its soft daily quota is still served, and its first
//! crossing in a UTC day asks (RULING L10-10-QUOTA = A, ARCH-0044 C5).

use std::path::Path;

use super::super::accounts::{QuotaCrossing, digest_hex};
use super::*;

/// One account's own key in the fixtures.
const OWEN_KEY: &str = "owen-account-key";
/// Another account's own key.
const YUKI_KEY: &str = "yuki-account-key";
/// A key of digits only, which TOML reads as a number when it is written
/// unquoted where its digest belongs.
const DIGITS_KEY: &str = "173928406581736492";

/// One `[[account]]` row, with its soft quota if `daily_input_tokens` is set.
fn account_row(id: &str, key: &str, daily_input_tokens: Option<u64>) -> String {
    let quota = daily_input_tokens.map_or_else(String::new, |tokens| {
        format!("daily_input_tokens = {tokens}\n")
    });
    format!(
        "[[account]]\nid = \"{id}\"\nkey_sha256 = \"{}\"\n{quota}\n",
        digest_hex(key)
    )
}

fn accounts_text(rows: &[(&str, &str)]) -> String {
    rows.iter()
        .map(|(id, key)| account_row(id, key, None))
        .collect()
}

fn write_accounts(path: &Path, rows: &[(&str, &str)]) {
    std::fs::write(path, accounts_text(rows)).expect("accounts file written");
}

/// A synthetic server with the operator's `key`, if any, and the accounts
/// file at `path`.
fn served_with_accounts(key: Option<&str>, path: &Path) -> (Arc<Served>, Arc<AccountKeys>) {
    let accounts = Arc::new(AccountKeys::load(path).expect("the accounts file loads"));
    let served = Served::new(
        synthetic(),
        Vec::new(),
        key.map(|key| Zeroizing::new(key.to_owned())),
        &crate::config::LimitsConfig::default(),
    )
    .expect("served")
    .with_accounts(Arc::clone(&accounts));
    (Arc::new(served), accounts)
}

/// The status of one embeddings request sent with `key` as its bearer, or
/// with none.
fn status_with(addr: SocketAddr, key: Option<&str>) -> u16 {
    status_with_inputs(addr, key, 1)
}

/// The status of one request of `inputs` texts, each one token to the
/// synthetic model.
fn status_with_inputs(addr: SocketAddr, key: Option<&str>, inputs: usize) -> u16 {
    let request = reqwest::blocking::Client::new()
        .post(format!("http://{addr}/v1/embeddings"))
        .json(&serde_json::json!({ "model": SYNTHETIC_MODEL, "input": vec!["one text"; inputs] }));
    let request = match key {
        Some(key) => request.bearer_auth(key),
        None => request,
    };
    request.send().expect("answered").status().as_u16()
}

#[test]
fn accounts_own_keys_are_served_beside_the_operator_key_and_no_other_key_is() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("accounts.toml");
    write_accounts(&path, &[("acct-owen", OWEN_KEY), ("acct-yuki", YUKI_KEY)]);
    let (served, accounts) = served_with_accounts(Some(KEY), &path);
    assert_eq!(accounts.count(), 2);
    let (addr, _runtime) = on_loopback(routes(served));

    assert_eq!(status_with(addr, Some(OWEN_KEY)), 200, "owen's own key");
    assert_eq!(status_with(addr, Some(YUKI_KEY)), 200, "yuki's own key");
    assert_eq!(status_with(addr, Some(KEY)), 200, "the operator's key");
    assert_eq!(status_with(addr, Some("a key in no row")), 401);
    assert_eq!(
        status_with(addr, Some(&digest_hex(OWEN_KEY))),
        401,
        "the digest the file holds is not a key"
    );
    assert_eq!(status_with(addr, None), 401);
}

#[test]
fn accounts_file_alone_guards_the_endpoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("accounts.toml");
    write_accounts(&path, &[("acct-owen", OWEN_KEY)]);
    let (served, _accounts) = served_with_accounts(None, &path);
    let (addr, _runtime) = on_loopback(routes(served));

    assert_eq!(status_with(addr, Some(OWEN_KEY)), 200);
    assert_eq!(
        status_with(addr, None),
        401,
        "with no operator key, an accounts file still closes the endpoint"
    );
    assert_eq!(status_with(addr, Some(KEY)), 401, "no operator key is set");
}

#[test]
fn accounts_dropped_from_the_file_are_refused_after_a_reload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("accounts.toml");
    write_accounts(&path, &[("acct-owen", OWEN_KEY), ("acct-yuki", YUKI_KEY)]);
    let (served, accounts) = served_with_accounts(Some(KEY), &path);
    let (addr, _runtime) = on_loopback(routes(served));
    assert_eq!(status_with(addr, Some(OWEN_KEY)), 200);

    write_accounts(&path, &[("acct-yuki", YUKI_KEY)]);
    assert_eq!(accounts.reload().expect("re-read"), 1);
    assert_eq!(
        status_with(addr, Some(OWEN_KEY)),
        401,
        "owen's account is revoked"
    );
    assert_eq!(status_with(addr, Some(YUKI_KEY)), 200, "yuki's stays");
    assert_eq!(status_with(addr, Some(KEY)), 200, "the operator's stays");

    std::fs::write(&path, "[[account]]\nid = \"acct-owen\"\n").expect("written");
    assert!(
        accounts.reload().is_err(),
        "a row with no key_sha256 does not parse"
    );
    assert_eq!(
        status_with(addr, Some(YUKI_KEY)),
        200,
        "a file that does not parse leaves the table as it was"
    );
    assert_eq!(status_with(addr, Some(OWEN_KEY)), 401);
}

#[test]
fn accounts_file_rows_that_cannot_name_one_key_each_do_not_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("accounts.toml");
    let digest = digest_hex(OWEN_KEY);
    let refused = [
        (
            "an id named twice",
            accounts_text(&[("acct-owen", OWEN_KEY), ("acct-owen", YUKI_KEY)]),
        ),
        (
            "one key for two accounts",
            accounts_text(&[("acct-owen", OWEN_KEY), ("acct-yuki", OWEN_KEY)]),
        ),
        (
            "an empty id",
            format!("[[account]]\nid = \" \"\nkey_sha256 = \"{digest}\"\n"),
        ),
        (
            "a digest that is not 64 hex digits",
            format!(
                "[[account]]\nid = \"acct-owen\"\nkey_sha256 = \"{}\"\n",
                &digest[..63]
            ),
        ),
        (
            "the digest of an empty key, which a request without a key would match",
            accounts_text(&[("acct-owen", "")]),
        ),
        (
            "a key in place of its digest",
            format!("[[account]]\nid = \"acct-owen\"\nkey_sha256 = \"{OWEN_KEY}\"\n"),
        ),
        (
            "an unquoted key of digits in place of its digest",
            format!("[[account]]\nid = \"acct-owen\"\nkey_sha256 = {DIGITS_KEY}\n"),
        ),
        (
            "a field the file does not have",
            format!(
                "[[account]]\nid = \"acct-owen\"\nkey_sha256 = \"{digest}\"\nkey = \"{OWEN_KEY}\"\n"
            ),
        ),
    ];
    for (case, text) in refused {
        std::fs::write(&path, text).expect("written");
        let refusal = AccountKeys::load(&path)
            .err()
            .unwrap_or_else(|| panic!("{case} loads"));
        // The reload after SIGHUP logs this text and keeps the old table, so
        // a key quoted here would stay valid in the log.
        let refusal = format!("{refusal:#}");
        for key in [OWEN_KEY, DIGITS_KEY] {
            assert!(
                !refusal.contains(key),
                "{case}: the refusal quotes a key: {refusal}"
            );
        }
    }
    std::fs::write(&path, "").expect("written");
    assert_eq!(
        AccountKeys::load(&path)
            .expect("an empty file is no accounts")
            .count(),
        0
    );
    assert!(
        AccountKeys::load(&dir.path().join("missing.toml")).is_err(),
        "a missing file"
    );
}

/// The question the account day row has asked on `served`, if any.
fn account_day_question(served: &Served) -> Option<crate::wire_telemetry::WireLimitQuestion> {
    served
        .questions
        .latest(LimitRow::EmbedderAccountDailyInputTokens)
}

#[test]
fn accounts_past_their_daily_input_tokens_are_served_and_asked_about_once() {
    // One UTC day holds every request below.
    let into_day = oneiron_vault_contract::now_ts() % 86_400;
    if into_day > 86_400 - 30 {
        std::thread::sleep(std::time::Duration::from_secs(86_401 - into_day));
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("accounts.toml");
    let text =
        account_row("acct-owen", OWEN_KEY, Some(3)) + &account_row("acct-yuki", YUKI_KEY, None);
    std::fs::write(&path, text).expect("written");
    let (served, _accounts) = served_with_accounts(Some(KEY), &path);
    let (addr, _runtime) = on_loopback(routes(Arc::clone(&served)));

    assert_eq!(status_with_inputs(addr, Some(OWEN_KEY), 2), 200);
    assert_eq!(account_day_question(&served), None, "2 of 3 tokens");

    assert_eq!(
        status_with_inputs(addr, Some(OWEN_KEY), 2),
        200,
        "past the quota the request is still served"
    );
    let asked = account_day_question(&served).expect("the crossing asks");
    assert_eq!(asked.row, "embedder.serve:account_daily_input_tokens");
    assert_eq!((asked.bound, asked.observed, asked.crossings), (3, 4, 1));

    assert_eq!(status_with_inputs(addr, Some(OWEN_KEY), 2), 200);
    assert_eq!(
        status_with_inputs(addr, Some(YUKI_KEY), 10),
        200,
        "no quota"
    );
    assert_eq!(status_with_inputs(addr, Some(KEY), 10), 200, "the operator");
    assert_eq!(
        account_day_question(&served).expect("asked").crossings,
        1,
        "one question a day for the account; none for an account with no quota or the operator"
    );
}

#[test]
fn accounts_daily_input_tokens_start_again_each_utc_day() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("accounts.toml");
    std::fs::write(&path, account_row("acct-owen", OWEN_KEY, Some(3))).expect("written");
    let accounts = AccountKeys::load(&path).expect("loads");
    let owen: Arc<str> = Arc::from("acct-owen");
    let midnight = 20_000 * 86_400;

    assert_eq!(
        accounts.count_input_tokens(&owen, 3, midnight),
        None,
        "at the quota, not past it"
    );
    assert_eq!(
        accounts.count_input_tokens(&owen, 1, midnight + 86_399),
        Some(QuotaCrossing {
            bound: 3,
            observed: 4
        })
    );
    assert_eq!(
        accounts.count_input_tokens(&owen, 5, midnight + 86_399),
        None,
        "asked once a day"
    );
    assert_eq!(
        accounts.count_input_tokens(&owen, 3, midnight + 86_400),
        None,
        "the next UTC day starts at zero"
    );
    assert_eq!(
        accounts.count_input_tokens(&owen, 1, midnight + 86_401),
        Some(QuotaCrossing {
            bound: 3,
            observed: 4
        })
    );

    std::fs::write(&path, account_row("acct-owen", OWEN_KEY, None)).expect("written");
    assert_eq!(accounts.reload().expect("re-read"), 1);
    assert_eq!(
        accounts.count_input_tokens(&owen, 1_000, midnight + 2 * 86_400),
        None,
        "with the quota taken out, use is counted and never asks"
    );
    std::fs::write(&path, account_row("acct-owen", OWEN_KEY, Some(0))).expect("written");
    assert!(accounts.reload().is_err(), "a quota of 0 tokens");
}

#[test]
fn accounts_use_today_survives_a_reload_and_a_changed_quota_asks_again() {
    // One UTC day holds every count below, as it holds the re-reads'.
    let into_day = oneiron_vault_contract::now_ts() % 86_400;
    if into_day > 86_400 - 30 {
        std::thread::sleep(Duration::from_secs(86_401 - into_day));
    }
    let now = oneiron_vault_contract::now_ts();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("accounts.toml");
    std::fs::write(&path, account_row("acct-owen", OWEN_KEY, Some(3))).expect("written");
    let accounts = AccountKeys::load(&path).expect("loads");
    let owen: Arc<str> = Arc::from("acct-owen");
    assert_eq!(
        accounts.count_input_tokens(&owen, 4, now),
        Some(QuotaCrossing {
            bound: 3,
            observed: 4
        })
    );

    write_accounts(&path, &[("acct-yuki", YUKI_KEY)]);
    assert_eq!(accounts.reload().expect("re-read"), 1);
    std::fs::write(&path, account_row("acct-owen", OWEN_KEY, Some(3))).expect("written");
    assert_eq!(accounts.reload().expect("re-read"), 1);
    assert_eq!(
        accounts.count_input_tokens(&owen, 1, now),
        None,
        "revoked and listed again today: the day's use stays, and it does not ask twice"
    );

    std::fs::write(&path, account_row("acct-owen", OWEN_KEY, Some(10))).expect("written");
    assert_eq!(accounts.reload().expect("re-read"), 1);
    assert_eq!(accounts.count_input_tokens(&owen, 5, now), None, "10 of 10");
    assert_eq!(
        accounts.count_input_tokens(&owen, 1, now),
        Some(QuotaCrossing {
            bound: 10,
            observed: 11
        }),
        "a raised quota asks again when it is crossed"
    );
}

/// A model that holds each call until the test lets it go, and says when
/// one has started.
struct Gated {
    inner: Arc<dyn ServedModel>,
    started: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl ServedModel for Gated {
    fn model_id(&self) -> &str {
        self.inner.model_id()
    }

    fn dimensions(&self) -> usize {
        self.inner.dimensions()
    }

    fn transform(&self) -> &str {
        self.inner.transform()
    }

    fn profile(&self) -> &RunProfile {
        self.inner.profile()
    }

    fn provenance(&self) -> EmbeddingProvenance {
        self.inner.provenance()
    }

    fn embed_raw(
        &self,
        texts: &[String],
        side: Side,
        instruction: Option<&str>,
        priority: Priority,
    ) -> oneiron::Result<Embedded> {
        let _ = self.started.try_send(());
        let _ = self
            .release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv_timeout(Duration::from_secs(30));
        self.inner.embed_raw(texts, side, instruction, priority)
    }
}

/// Review P1 (#7422): the count ran in the request's future after the
/// model's task, so a client that hung up while the model worked dropped
/// the future and its tokens were never counted, though the model did the
/// work.
#[test]
fn accounts_count_the_models_work_after_its_client_hung_up() {
    use std::io::Write;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("accounts.toml");
    std::fs::write(&path, account_row("acct-owen", OWEN_KEY, Some(1))).expect("written");
    let (started, started_rx) = std::sync::mpsc::sync_channel(1);
    let (release, release_rx) = std::sync::mpsc::channel();
    let model = Arc::new(Gated {
        inner: synthetic(),
        started,
        release: std::sync::Mutex::new(release_rx),
    });
    let accounts = Arc::new(AccountKeys::load(&path).expect("loads"));
    let served = Arc::new(
        Served::new(
            model,
            Vec::new(),
            None,
            &crate::config::LimitsConfig::default(),
        )
        .expect("served")
        .with_accounts(accounts),
    );
    let (addr, _runtime) = on_loopback(routes(Arc::clone(&served)));
    let body = serde_json::json!({ "model": SYNTHETIC_MODEL, "input": ["one", "two"] }).to_string();
    let mut client = post_head(addr, Some(OWEN_KEY), body.len());
    client.write_all(body.as_bytes()).expect("body sent");
    started_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the model took the request");
    drop(client);
    // The server sees the hang-up and drops the request's future while the
    // model still works.
    std::thread::sleep(Duration::from_millis(300));
    release.send(()).expect("the model let go");
    let asked = (0..500).any(|_| {
        std::thread::sleep(Duration::from_millis(10));
        account_day_question(&served).is_some()
    });
    assert!(
        asked,
        "the model's 2 tokens count toward the account's day of 1 after its client hung up"
    );
}

#[tokio::test]
async fn accounts_file_or_key_is_needed_off_loopback() {
    let refused = run(
        EmbedderConfig {
            provider: EmbedderProvider::Local,
            ..EmbedderConfig::default()
        },
        Listen {
            addr: "0.0.0.0:0".parse().expect("an address"),
            key: None,
            accounts: None,
            aliases: Vec::new(),
            limits: crate::config::LimitsConfig::default(),
        },
    )
    .await
    .expect_err("refused before any model loads");
    assert!(refused.to_string().contains("--accounts-file"), "{refused}");
}

/// Rule five at the account day row: `callers` requests from one account
/// past a soft quota of one token all answer, and the row asks.
pub(crate) fn cross_the_account_day(callers: usize) -> crate::admission::Crossing {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("accounts.toml");
    std::fs::write(&path, account_row("acct-owen", OWEN_KEY, Some(1))).expect("written");
    let (served, _accounts) = served_with_accounts(Some(KEY), &path);
    let (addr, _runtime) = on_loopback(routes(Arc::clone(&served)));
    let calls: Vec<_> = (0..callers)
        .map(|_| std::thread::spawn(move || status_with_inputs(addr, Some(OWEN_KEY), 2)))
        .collect();
    crate::admission::Crossing {
        refused: unanswered(calls),
        asked: account_day_question(&served).is_some(),
    }
}
