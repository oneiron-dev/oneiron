//! A device's enrolment with its home (ARCH-0023b: "a device connects the
//! moment it is enrolled"). `oneiron device enrol` redeems the owner's
//! machine pairing link on this stopped vault. The home adds this machine and
//! pairs its owner-grade credential, and this install keeps what it dials
//! with: the home's MACHINE, sync node id and `/ws` URL, the credential, and
//! the authority checkpoint pin the link named (OF-469), which the first
//! connection adopts.
//!
//! The record and the credential sit beside this install's key directory,
//! outside the vault, one pair per vault id, so a copy of the vault never
//! carries this machine's credential.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::commands::credential_file;
use crate::config::KeystoreConfig;
use crate::config::device_sync::{parse_machine, validate_home_url};

/// What a device keeps from its enrolment, beside its credential.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceEnrolment {
    /// The home's MACHINE id, hex.
    pub(crate) home_machine: String,
    /// The home's sync node id: the home this machine holds as elected.
    pub(crate) home_node_id: u64,
    /// The home's sync endpoint, from the link's origin: `ws(s)://…/ws`.
    pub(crate) home_url: String,
    /// The checkpoint the link pinned, when the home had an attested one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority_checkpoint_pin: Option<oneiron::authority::AuthorityCheckpointPin>,
}

impl DeviceEnrolment {
    fn validate(&self) -> anyhow::Result<()> {
        parse_machine(&self.home_machine)?;
        validate_home_url(&self.home_url)?;
        anyhow::ensure!(self.home_node_id != 0, "the home's sync node id is never 0");
        Ok(())
    }
}

/// Where one vault's enrolment lives on this install.
pub(crate) struct EnrolmentFiles {
    /// The [`DeviceEnrolment`], as JSON.
    pub(crate) record: PathBuf,
    /// The paired credential, in the `v2.cred.` one-string form.
    pub(crate) credential: PathBuf,
}

impl EnrolmentFiles {
    /// `device-sync/<vault id>.json` and `.cred`, beside the key directory.
    pub(crate) fn for_vault(
        keystore: &KeystoreConfig,
        vault: &oneiron::Vault,
    ) -> anyhow::Result<Self> {
        let keys = match &keystore.dir {
            Some(dir) => dir.clone(),
            None => oneiron_keystore::default_key_dir().ok_or_else(|| {
                anyhow::anyhow!(
                    "no directory for this machine's enrolment: neither XDG_STATE_HOME nor HOME \
                     names an absolute directory; set keystore.dir (ONEIRON_KEYSTORE_DIR)"
                )
            })?,
        };
        let dir = keys.parent().unwrap_or(&keys).join("device-sync");
        let vault_id = hex(&vault.vault_key_vault_id());
        Ok(Self {
            record: dir.join(format!("{vault_id}.json")),
            credential: dir.join(format!("{vault_id}.cred")),
        })
    }

    /// The stored enrolment, or `None` before this machine enrolled.
    pub(crate) fn read(&self) -> anyhow::Result<Option<DeviceEnrolment>> {
        let text = match std::fs::read_to_string(&self.record) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => anyhow::bail!("read {}: {error}", self.record.display()),
        };
        let record: DeviceEnrolment = serde_json::from_str(&text).map_err(|error| {
            anyhow::anyhow!(
                "{} is not a device enrolment: {error}",
                self.record.display()
            )
        })?;
        record
            .validate()
            .map_err(|error| anyhow::anyhow!("{}: {error}", self.record.display()))?;
        Ok(Some(record))
    }

    /// Writes the credential, then the record that publishes it, each a new
    /// file only its owner may read. A record that fails takes the
    /// credential with it.
    fn write(&self, credential: &str, record: &DeviceEnrolment) -> anyhow::Result<()> {
        if let Some(dir) = self.record.parent() {
            create_private_dir(dir)?;
        }
        write_new(&self.credential, credential.as_bytes())?;
        if let Err(error) = write_new(&self.record, &serde_json::to_vec_pretty(record)?) {
            let _ = std::fs::remove_file(&self.credential);
            return Err(error);
        }
        Ok(())
    }
}

/// The redeem route's success body, as a device reads it.
#[derive(Deserialize)]
struct Paired {
    token: String,
    #[serde(default)]
    pin: Option<oneiron::authority::AuthorityCheckpointPin>,
    #[serde(default)]
    home: Option<PairedHome>,
}

#[derive(Deserialize)]
struct PairedHome {
    machine: String,
    sync_node_id: u64,
}

/// How long the home has to answer the redeem.
const REDEEM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Redeems the owner's machine pairing `link` for this vault's machine, then
/// stores the enrolment and its credential in `files`. The link is spent once
/// the home answers. The fresh connection key signs the link's code, holder
/// and pin reference; this machine's key signs its enrolment request, and a
/// pin the home returns must be exactly the one the link names.
pub(crate) fn enrol(
    vault: &oneiron::Vault,
    files: &EnrolmentFiles,
    link: &str,
) -> anyhow::Result<DeviceEnrolment> {
    use base64::Engine as _;
    use ed25519_dalek::Signer;

    anyhow::ensure!(
        !files.record.exists() && !files.credential.exists(),
        "this machine is already enrolled for this vault; remove {} and {} to enrol again",
        files.record.display(),
        files.credential.display()
    );
    // The link and its code are never echoed: the code is the enrolment
    // grant until it is spent.
    let (origin, code, holder_ref, pin_ref) =
        oneiron::authority::parse_pinned_pairing_link(link.trim()).map_err(|_| {
            anyhow::anyhow!(
                "the pairing link does not parse; pass the one-line link `oneiron token pair \
                 --machine yours` printed on the home"
            )
        })?;
    let mut base = reqwest::Url::parse(&origin)
        .map_err(|_| anyhow::anyhow!("the pairing link's origin is not a URL"))?;
    let home_url = home_url(&base)?;
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    let vault_id = vault.authority_fold()?.vault_id.ok_or_else(|| {
        anyhow::anyhow!(
            "this vault has no authority root yet, so it is not the home's vault; a device \
             enrols a copy of its home's vault"
        )
    })?;
    let request =
        vault.machine_enrolment_request(vault_id, vault.machine_encryption_key(vault_id)?)?;
    let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let binding_key = key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &code,
        &binding_key,
        &holder_ref,
        pin_ref.as_ref(),
    )?;
    let body = serde_json::json!({
        "code": code,
        "holder_ref": holder_ref,
        "binding_key": hex(&binding_key),
        "signature": hex(&key.sign(&transcript).to_bytes()),
        "machine": {
            "vault_id": hex(&request.vault_id),
            "machine": request.machine.to_hex(),
            "machine_key": hex(&request.machine_key),
            "encryption_suite": request.encryption_key.suite,
            "encryption_key": base64::engine::general_purpose::STANDARD
                .encode(&request.encryption_key.key),
            "machine_proof": hex(&request.machine_proof),
        },
    });
    let response = reqwest::blocking::Client::builder()
        .timeout(REDEEM_TIMEOUT)
        .build()?
        .post(base.join("v1/core/pairing/redeem")?)
        .json(&body)
        .send()
        .map_err(|error| anyhow::anyhow!("redeem the pairing link at {origin}: {error}"))?;
    let status = response.status();
    let text = response.text().unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!(
            "the home refused the enrolment ({status}): {}; a refused link may be spent, so \
             ask the owner for a new one",
            text.chars().take(400).collect::<String>()
        );
    }
    let paired: Paired = serde_json::from_str(&text)
        .map_err(|_| anyhow::anyhow!("the home answered {status} with no slip"))?;
    let slip = paired
        .token
        .strip_prefix("v2.slip.")
        .ok_or_else(|| anyhow::anyhow!("the home answered {status} with no slip"))?;
    let pinned = match (&pin_ref, &paired.pin) {
        (None, None) => true,
        (Some(named), Some(pin)) => named.names(pin),
        _ => false,
    };
    anyhow::ensure!(
        pinned,
        "the home's checkpoint pin is not the one the pairing link names; enrol again with a \
         new link from the owner"
    );
    let home = paired.home.ok_or_else(|| {
        anyhow::anyhow!(
            "the home named neither its MACHINE nor its sync node id; pass a link made with \
             `oneiron token pair --machine yours`"
        )
    })?;
    let record = DeviceEnrolment {
        home_machine: home.machine,
        home_node_id: home.sync_node_id,
        home_url,
        authority_checkpoint_pin: paired.pin,
    };
    record.validate()?;
    files.write(&format!("v2.cred.{slip}.{}", hex(key.as_bytes())), &record)?;
    Ok(record)
}

/// The home's sync endpoint at the link's origin: `wss` for `https`, `ws` for
/// `http`, at `/ws`.
fn home_url(origin: &reqwest::Url) -> anyhow::Result<String> {
    let scheme = match origin.scheme() {
        "https" => "wss",
        "http" => "ws",
        other => anyhow::bail!("the pairing link's origin is {other}://, not http(s)://"),
    };
    let host = origin
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("the pairing link's origin names no host"))?;
    Ok(match origin.port() {
        Some(port) => format!("{scheme}://{host}:{port}/ws"),
        None => format!("{scheme}://{host}/ws"),
    })
}

/// Creates `dir` and its parents; a new `dir` only its owner may enter.
fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(dir)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", dir.display()))
}

/// Writes `bytes` and a newline to a new owner-only file, synced to disk.
fn write_new(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = credential_file::create(path)?;
    if let Err(error) = file
        .write_all(bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = std::fs::remove_file(path);
        anyhow::bail!("write {}: {error}", path.display());
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
