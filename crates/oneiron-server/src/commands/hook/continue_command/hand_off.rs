//! The workspace half of `oneiron continue --cloud` (census L10-17): a
//! hand-off commit of the working tree as git sees it, built in an index of
//! its own, and its push to the hosted vault's custody repo.

use std::ffi::{OsStr, OsString};
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use oneiron_vault_contract::BINDING_HEADER;

use crate::commands::api::signed_binding_for_seed;

/// Who a hand-off commit names when the repo names no one: git refuses a
/// commit with no identity, and the hand-off is this command's own commit.
const FALLBACK_NAME: &str = "oneiron continue";
const FALLBACK_EMAIL: &str = "continue@oneiron.invalid";

/// A hand-off commit of one repo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandOff {
    /// The repo's top directory, where git ran.
    pub(crate) top: PathBuf,
    /// The commit, 40 lower hex.
    pub(crate) commit: String,
    /// HEAD when the commit was built, its one parent; `None` on a branch
    /// with no commit yet.
    pub(crate) parent: Option<String>,
}

/// The hand-off commit of the repo that holds `dir`: its tracked files and
/// its untracked files that are not ignored, as `git add -A` sees them (ASK
/// L10-17-FILES = A), with HEAD as the parent. Ignored files stay on the
/// machine. It is built in a copy of the repo's index, so the user's HEAD,
/// index and files stay as they were; only git's object store gains the
/// commit's objects, which the push sends.
pub(crate) fn hand_off_commit(dir: &Path, message: &str) -> anyhow::Result<HandOff> {
    let top = PathBuf::from(git(dir, ["rev-parse", "--show-toplevel"], &[])?);
    // The repo's own index, wherever a worktree keeps it; relative to `top`.
    let index = top.join(git(&top, ["rev-parse", "--git-path", "index"], &[])?);
    let scratch = tempfile::Builder::new()
        .prefix("oneiron-continue-")
        .tempdir()?;
    let own_index = scratch.path().join("index");
    if index.is_file() {
        std::fs::copy(&index, &own_index)?;
    }
    let in_own_index = [(OsString::from("GIT_INDEX_FILE"), own_index.into_os_string())];
    git(&top, ["add", "-A"], &in_own_index)?;
    let tree = git(&top, ["write-tree"], &in_own_index)?;
    let parent = head(&top)?;
    let mut args = vec![
        OsString::from("commit-tree"),
        tree.into(),
        "-m".into(),
        message.into(),
    ];
    if let Some(parent) = &parent {
        args.extend(["-p".into(), parent.into()]);
    }
    let commit = git(&top, args, &identity(&top))?;
    Ok(HandOff {
        top,
        commit,
        parent,
    })
}

/// The custody repo a hand-off goes to, and the paired slip that pushes it.
pub(crate) struct CustodyRepo<'a> {
    /// The hosted vault's origin, e.g. `https://vault.example`.
    pub(crate) origin: &'a str,
    /// The repo's served name, as the push URL's `{repo}`.
    pub(crate) repo: &'a str,
    /// The slip, `v2.slip.…`.
    pub(crate) token: &'a str,
    /// The slip's holder seed, 64 hex.
    pub(crate) seed: &'a str,
}

/// Pushes `commit` to `git_ref` of `custody` over git's smart HTTP
/// receive-pack protocol, spoken here rather than by `git push`: each request
/// needs a holder proof of its own (the vault spends a proof's nonce on the
/// request it admits), and stock git repeats one static header on every
/// request of a push. So the ref advertisement and the push each carry the
/// slip and a fresh proof; the pack is `git pack-objects` of what the commit
/// reaches and the advertised refs do not. The ref is the conversation's own
/// hand-off ref, so a later hand-off of it replaces it whatever it held. The
/// repo's pre-push hook does not run: it guards pushes to the user's own
/// remotes, and a hand-off ref is none of them.
pub(crate) fn push(
    top: &Path,
    custody: &CustodyRepo<'_>,
    commit: &str,
    git_ref: &str,
) -> anyhow::Result<()> {
    let base = format!(
        "{}/git/{}.git",
        custody.origin.trim_end_matches('/'),
        custody.repo
    );
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(30))
        .timeout(PUSH_TIMEOUT)
        .build()?;
    let proven = |request: reqwest::blocking::RequestBuilder| -> anyhow::Result<_> {
        Ok(request
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", custody.token),
            )
            .header(
                BINDING_HEADER,
                signed_binding_for_seed(custody.token, custody.seed)?,
            ))
    };

    let answer =
        proven(client.get(format!("{base}/info/refs?service=git-receive-pack")))?.send()?;
    let advertised = advertisement(answered(answer, ADVERTISEMENT_TYPE)?)?;
    let old = advertised
        .refs
        .iter()
        .find(|(_, name)| name == git_ref)
        .map_or_else(|| "0".repeat(commit.len()), |(oid, _)| oid.clone());
    if old == commit {
        return Ok(());
    }

    let mut pack = Command::new("git")
        .arg("-C")
        .arg(top)
        .args(["pack-objects", "--stdout", "--revs", "--delta-base-offset"])
        .arg(if std::io::stderr().is_terminal() {
            "--progress"
        } else {
            "-q"
        })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut revisions = format!("{commit}\n");
    for oid in held(top, advertised.refs.iter().map(|(oid, _)| oid.as_str()))? {
        revisions.push_str(&format!("^{oid}\n"));
    }
    pack.stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stdin for git pack-objects"))?
        .write_all(revisions.as_bytes())?;
    let objects = pack
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stdout for git pack-objects"))?;
    let mut commands = pkt_line(&format!(
        "{old} {commit} {git_ref}\0report-status agent={AGENT}"
    ));
    commands.extend_from_slice(FLUSH);
    let body = reqwest::blocking::Body::new(std::io::Cursor::new(commands).chain(objects));
    let sent = proven(
        client
            .post(format!("{base}/git-receive-pack"))
            .header(reqwest::header::CONTENT_TYPE, REQUEST_TYPE)
            .header(reqwest::header::ACCEPT, RESULT_TYPE)
            .body(body),
    )?
    .send();
    let packed = pack.wait()?;
    let report = answered(sent?, RESULT_TYPE)?;
    anyhow::ensure!(packed.success(), "git pack-objects failed ({packed})");
    pushed(&report, git_ref)
}

/// The receive-pack advertisement's content type.
const ADVERTISEMENT_TYPE: &str = "application/x-git-receive-pack-advertisement";
/// The receive-pack request's content type.
const REQUEST_TYPE: &str = "application/x-git-receive-pack-request";
/// The receive-pack result's content type.
const RESULT_TYPE: &str = "application/x-git-receive-pack-result";
/// The agent the push names itself as.
const AGENT: &str = "oneiron-continue/1";
/// A pkt-line flush.
const FLUSH: &[u8] = b"0000";
/// The most of an advertisement or a report read.
const MAX_ANSWER_BYTES: u64 = 8 << 20;
/// How long one request of the push may take, the pack's upload included.
const PUSH_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// The refs a receive-pack advertisement names, `(oid, name)`.
struct Advertisement {
    refs: Vec<(String, String)>,
}

/// `answer`'s body when it succeeded with `content_type`, else an error
/// naming its status and the start of what it said.
fn answered(answer: reqwest::blocking::Response, content_type: &str) -> anyhow::Result<Vec<u8>> {
    let status = answer.status();
    let typed = answer
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with(content_type));
    let mut body = Vec::new();
    answer.take(MAX_ANSWER_BYTES).read_to_end(&mut body)?;
    if status.is_success() && typed {
        return Ok(body);
    }
    let said: String = String::from_utf8_lossy(&body).chars().take(300).collect();
    anyhow::bail!(
        "the custody repo refused the push ({status}): {}",
        said.trim()
    )
}

/// The refs of a receive-pack advertisement: its service line and flush,
/// then one pkt-line per ref, the first with the capabilities after a NUL.
fn advertisement(body: Vec<u8>) -> anyhow::Result<Advertisement> {
    let mut lines = pkt_lines(&body)?.into_iter();
    anyhow::ensure!(
        matches!(lines.next(), Some(Some(line)) if line == b"# service=git-receive-pack"),
        "the custody repo answered no receive-pack advertisement"
    );
    let mut refs = Vec::new();
    for line in lines.flatten() {
        let line = line.split(|&byte| byte == 0).next().unwrap_or_default();
        let line = String::from_utf8_lossy(line);
        if let Some((oid, name)) = line.split_once(' ')
            && name != "capabilities^{}"
        {
            refs.push((oid.to_owned(), name.to_owned()));
        }
    }
    Ok(Advertisement { refs })
}

/// Whether the report says the pack unpacked and `git_ref` moved.
fn pushed(report: &[u8], git_ref: &str) -> anyhow::Result<()> {
    let lines: Vec<String> = pkt_lines(report)?
        .into_iter()
        .flatten()
        .map(|line| String::from_utf8_lossy(&line).into_owned())
        .collect();
    let unpacked = lines.iter().find_map(|line| line.strip_prefix("unpack "));
    anyhow::ensure!(
        unpacked == Some("ok"),
        "the custody repo did not unpack the push: {}",
        unpacked.unwrap_or("no report")
    );
    if lines.iter().any(|line| line == &format!("ok {git_ref}")) {
        return Ok(());
    }
    let refused = lines
        .iter()
        .find_map(|line| line.strip_prefix(&format!("ng {git_ref} ")))
        .unwrap_or("no reason given");
    anyhow::bail!("the custody repo refused {git_ref}: {refused}")
}

/// `body` as pkt-lines: `Some(payload)` without its newline, `None` for a
/// flush.
fn pkt_lines(body: &[u8]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
    let mut lines = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let size = rest
            .get(..4)
            .and_then(|head| std::str::from_utf8(head).ok())
            .and_then(|head| usize::from_str_radix(head, 16).ok())
            .ok_or_else(|| anyhow::anyhow!("the custody repo answered a broken pkt-line"))?;
        if size == 0 {
            lines.push(None);
            rest = &rest[4..];
            continue;
        }
        let line = rest
            .get(4..size)
            .filter(|_| size >= 4)
            .ok_or_else(|| anyhow::anyhow!("the custody repo answered a broken pkt-line"))?;
        lines.push(Some(line.strip_suffix(b"\n").unwrap_or(line).to_vec()));
        rest = &rest[size..];
    }
    Ok(lines)
}

/// `payload` as one pkt-line.
fn pkt_line(payload: &str) -> Vec<u8> {
    let mut line = format!("{:04x}", payload.len() + 5).into_bytes();
    line.extend_from_slice(payload.as_bytes());
    line.push(b'\n');
    line
}

/// Which of `oids` this repo holds as commits, so the pack leaves out what
/// they reach.
fn held<'a>(top: &Path, oids: impl Iterator<Item = &'a str>) -> anyhow::Result<Vec<String>> {
    let asked: String = oids.map(|oid| format!("{oid}^{{commit}}\n")).collect();
    if asked.is_empty() {
        return Ok(Vec::new());
    }
    let mut check = Command::new("git")
        .arg("-C")
        .arg(top)
        .args(["cat-file", "--batch-check=%(objectname) %(objecttype)"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = check
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stdin for git cat-file"))?;
    // Fed apart from the read, so a long answer never stalls the question.
    let fed = std::thread::spawn(move || stdin.write_all(asked.as_bytes()));
    let output = check.wait_with_output()?;
    fed.join()
        .map_err(|_| anyhow::anyhow!("feeding git cat-file failed"))??;
    anyhow::ensure!(
        output.status.success(),
        "git cat-file failed ({})",
        output.status
    );
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_suffix(" commit"))
        .map(str::to_owned)
        .collect())
}

/// HEAD's commit, `None` on a branch with no commit yet.
fn head(top: &Path) -> anyhow::Result<Option<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(top)
        .args(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])
        .stdin(Stdio::null())
        .output()?;
    Ok(output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned()))
}

/// The author and committer git would write, or [`FALLBACK_NAME`] for both
/// when the repo's config and environment name none.
fn identity(top: &Path) -> Vec<(OsString, OsString)> {
    let named = ["GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"]
        .into_iter()
        .all(|ident| git(top, ["var", ident], &[]).is_ok());
    if named {
        return Vec::new();
    }
    [
        ("GIT_AUTHOR_NAME", FALLBACK_NAME),
        ("GIT_AUTHOR_EMAIL", FALLBACK_EMAIL),
        ("GIT_COMMITTER_NAME", FALLBACK_NAME),
        ("GIT_COMMITTER_EMAIL", FALLBACK_EMAIL),
    ]
    .into_iter()
    .map(|(name, value)| (name.into(), value.into()))
    .collect()
}

/// `git -C dir <args>` with `env` added, its trimmed stdout; a failure
/// names git's own words.
fn git<I, S>(dir: &Path, args: I, env: &[(OsString, OsString)]) -> anyhow::Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .envs(env.iter().map(|(name, value)| (name, value)))
        .stdin(Stdio::null())
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "git: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
