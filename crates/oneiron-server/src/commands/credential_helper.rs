//! `oneiron credential-helper` (FIX 10624 step 2; ARCH-0069 T1, the
//! credential-helper shim): the git credential helper an official CLI seat
//! runs. git calls it at the moment it needs a credential for a context the
//! seat host bound; it asks this host for the value and prints it for git on
//! its own stdout, never into the CLI's environment.
//!
//! git appends the operation (`get`, `store` or `erase`) and writes the
//! context as `key=value` lines on stdin. Only `get` asks: `store` and
//! `erase` read their input and keep nothing, since this helper stores no
//! credential. The ask carries the run's seat-child slip and a fresh holder
//! proof from the seat host's variables (never an argument), to the
//! loopback origin the host named, through the host's curl on its config
//! channel.

use std::io::{Read as _, Write as _};

use crate::auth::{SEAT_CREDENTIAL_HELPER_PATH, SEAT_SLIP_HEADER};
use crate::cli::CredentialHelperArgs;
use crate::runtime::{SEAT_BINDING_KEY_ENV, SEAT_SLIP_ENV, SEAT_URL_ENV};

use super::api::{
    CurlRequest, curl_header_line, normalized_base, run_curl_capture, signed_binding_for_seed,
};

/// The most of git's input the helper reads.
const INPUT_LIMIT: u64 = 64 * 1024;

/// What the host answers.
#[derive(serde::Deserialize)]
struct HelperAnswer {
    username: String,
    password: String,
}

pub fn credential_helper(args: CredentialHelperArgs) -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin()
        .take(INPUT_LIMIT)
        .read_to_string(&mut input)?;
    if args.operation != "get" {
        return Ok(());
    }
    let (mut protocol, mut host, mut path) = (None, None, None);
    for line in input.lines() {
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "protocol" => protocol = Some(value.to_owned()),
            "host" => host = Some(value.to_owned()),
            "path" => path = Some(value.to_owned()),
            _ => {}
        }
    }
    let (Some(protocol), Some(host)) = (protocol, host) else {
        anyhow::bail!("git named no protocol and host; nothing was asked");
    };
    let read = |name: &str| {
        std::env::var(name).map_err(|_| anyhow::anyhow!("{name} is not set; nothing was asked"))
    };
    let slip = zeroize::Zeroizing::new(read(SEAT_SLIP_ENV)?);
    let seed = zeroize::Zeroizing::new(read(SEAT_BINDING_KEY_ENV)?);
    let base = normalized_base(&read(SEAT_URL_ENV)?)?;
    let binding = signed_binding_for_seed(&slip, &seed)?;
    let mut config = curl_header_line(SEAT_SLIP_HEADER, &slip)?;
    config.push_str(&curl_header_line(
        oneiron_vault_contract::BINDING_HEADER,
        &binding,
    )?);
    let body = serde_json::json!({
        "destination": args.destination,
        "protocol": protocol,
        "host": host,
        "path": path,
    });
    let request = CurlRequest {
        method: "POST".to_owned(),
        url: format!("{base}{SEAT_CREDENTIAL_HELPER_PATH}"),
        body: Some(serde_json::to_vec(&body)?),
        content_type: Some("application/json".to_owned()),
    };
    let output = zeroize::Zeroizing::new(
        run_curl_capture(
            &request,
            &config,
            &[SEAT_SLIP_ENV.to_owned(), SEAT_BINDING_KEY_ENV.to_owned()],
        )?
        .stdout,
    );
    let answer: HelperAnswer = serde_json::from_slice(&output)
        .map_err(|_| anyhow::anyhow!("the host answered no credential"))?;
    let password = zeroize::Zeroizing::new(answer.password);
    anyhow::ensure!(
        !answer.username.contains(['\n', '\r', '\0']) && !password.contains(['\n', '\r', '\0']),
        "the host's answer is not one line each; nothing was printed"
    );
    let mut stdout = std::io::stdout().lock();
    write!(
        stdout,
        "username={}\npassword={}\n",
        answer.username,
        password.as_str()
    )?;
    stdout.flush()?;
    Ok(())
}
