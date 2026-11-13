//! The Google Drive wire of a Drive source (MAIL-GOOGLE = A, ARCH-0027
//! #mail-drive): Drive v3 REST over `reqwest::blocking`.
//!
//! Each call reads the source's credential at its door, effector
//! `connector:google_drive`: the custody record the owner named at attach,
//! whose bindings admit Drive. HTTPS only, no redirects; the Bearer header
//! exists only inside the door callback, marked sensitive. A stored grant
//! that can refresh is exchanged for a fresh access token once per wire.
//! Inside each door, before the credential presented there reads anything,
//! the wire checks that it reads the account the source names
//! (`about.user.emailAddress`), once per credential: a credential for one
//! account never fills another account's source.
//!
//! The wire declares Drive's per-user quota ([`GOOGLE_DRIVE_QUOTA`]), so a
//! step paces within it; a 429, or a 403 for a usage limit, answers
//! [`DRIVE_WIRE_RATE_LIMITED`].
//!
//! Call it from a blocking context: `reqwest::blocking` owns its own runtime.

use std::cell::Cell;

use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde_json::Value;

use super::quota::MAIL_WIRE_RATE_LIMITED;
use super::rest::{
    self, FreshGoogleTokens, RestAnswer, VerifiedCredentials, array, refused, text_of,
};
use crate::consent::AuthenticatedOwner;
use crate::note::{
    DRIVE_WIRE_RATE_LIMITED, DriveChange, DriveChangesPage, DriveFileMeta, DriveOrigin, DriveQuota,
    DriveStepBudget, DriveStepReport, DriveWire, MAX_DRIVE_DOWNLOAD_BYTES,
};
use crate::{Error, Result, Vault};

/// The custody effector a Google Drive credential is bound to.
pub const GOOGLE_DRIVE_CONNECTOR_EFFECTOR: &str = "connector:google_drive";

/// Drive's limits for one user and its calls' costs (RESEARCH-1393 #drive,
/// which ARCH-0027 #mail-drive cites): 325,000 units a minute per user; a
/// listing 100, a metadata read 5, a download or an export 200.
pub const GOOGLE_DRIVE_QUOTA: DriveQuota = DriveQuota {
    units_per_minute: 325_000,
    list: 100,
    get: 5,
    content: 200,
};

const DRIVE_API_URL: &str = "https://www.googleapis.com/drive/v3";

/// The metadata every read asks for.
const DRIVE_FILE_FIELDS: &str = "id,name,mimeType,modifiedTime,size,trashed";

/// Changes one feed page holds.
const CHANGES_PAGE_SIZE: u32 = 100;

/// The longest file id a URL names.
const MAX_FILE_ID_BYTES: usize = 320;

/// Host-side Google Drive wire over `reqwest::blocking`, for the Drive
/// sources of one vault.
pub struct HttpGoogleDriveWire<'v> {
    vault: &'v Vault,
    client: reqwest::blocking::Client,
    /// The answer bytes read from Drive so far.
    read_bytes: Cell<u64>,
    /// The credentials this wire has seen read their source's account.
    verified: VerifiedCredentials,
    /// The fresh access tokens its sources' stored grants were exchanged
    /// for.
    tokens: FreshGoogleTokens,
}

impl<'v> HttpGoogleDriveWire<'v> {
    /// Builds the wire: HTTPS only, no redirects, a 60 s timeout.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the TLS client cannot be built.
    pub fn new(vault: &'v Vault) -> Result<Self> {
        Ok(Self {
            vault,
            client: rest::https_client()?,
            read_bytes: Cell::new(0),
            verified: VerifiedCredentials::new(),
            tokens: FreshGoogleTokens::new(),
        })
    }

    /// Runs `send` with the Bearer header of `origin`'s credential, read at
    /// its door, once the credential is seen to read `origin`'s account.
    fn with_bearer<A>(
        &self,
        origin: &DriveOrigin,
        mut send: impl FnMut(HeaderValue) -> Result<RestAnswer<A>>,
    ) -> Result<RestAnswer<A>> {
        let source = origin.source_id()?;
        let mut answer: Option<RestAnswer<A>> = None;
        let _receipt = self.vault.inject_secret_at_door(
            &origin.custody_ref,
            GOOGLE_DRIVE_CONNECTOR_EFFECTOR,
            &mut |token: &[u8]| {
                let auth = self.tokens.bearer(&self.client, source, token)?;
                // The credential presented here is the one checked.
                if !self.verified.holds(source, token) {
                    let request = self
                        .client
                        .get(format!("{DRIVE_API_URL}/about"))
                        .query(&[("fields", "user(emailAddress)")])
                        .header(AUTHORIZATION, auth.clone());
                    let about = rate_limited(rest::send_counted(request, &self.read_bytes)?)?
                        .found_or_gone("google_drive")?
                        .ok_or_else(|| refused("google_drive_account_not_found"))?;
                    let address = about
                        .pointer("/user/emailAddress")
                        .and_then(Value::as_str)
                        .map(str::trim);
                    if !address
                        .is_some_and(|address| address.eq_ignore_ascii_case(origin.account.trim()))
                    {
                        return Err(refused("google_drive_credential_reads_another_account"));
                    }
                    self.verified.insert(source, token);
                }
                answer = Some(send(auth)?);
                Ok(())
            },
        )?;
        rate_limited(answer.ok_or_else(|| refused("google_drive_credential_door_refused"))?)
    }

    /// One JSON read; `None` for Drive's "not found".
    fn get_json(
        &self,
        origin: &DriveOrigin,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<Option<Value>> {
        self.with_bearer(origin, |auth| {
            rest::send_counted(
                self.client
                    .get(url)
                    .query(query)
                    .header(AUTHORIZATION, auth),
                &self.read_bytes,
            )
        })?
        .found_or_gone("google_drive")
    }

    /// One read of a file's own bytes; `None` for Drive's "not found".
    fn get_bytes(
        &self,
        origin: &DriveOrigin,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<Option<Vec<u8>>> {
        self.with_bearer(origin, |auth| {
            rest::send_bytes(
                self.client
                    .get(url)
                    .query(query)
                    .header(AUTHORIZATION, auth),
                &self.read_bytes,
                MAX_DRIVE_DOWNLOAD_BYTES,
            )
        })?
        .found_or_gone("google_drive")
    }
}

impl DriveWire for HttpGoogleDriveWire<'_> {
    fn start_page_token(&self, origin: &DriveOrigin) -> Result<String> {
        let answer = self
            .get_json(
                origin,
                &format!("{DRIVE_API_URL}/changes/startPageToken"),
                &[("supportsAllDrives", "true".to_owned())],
            )?
            .ok_or_else(|| refused("google_drive_start_page_token_not_found"))?;
        text_of(answer.get("startPageToken"))
            .ok_or_else(|| refused("google_drive_start_page_token_unreadable"))
    }

    fn changes(&self, origin: &DriveOrigin, token: &str) -> Result<DriveChangesPage> {
        let fields = format!(
            "nextPageToken,newStartPageToken,changes(changeType,fileId,removed,file({DRIVE_FILE_FIELDS}))"
        );
        let page = self
            .get_json(
                origin,
                &format!("{DRIVE_API_URL}/changes"),
                &[
                    ("pageToken", token.to_owned()),
                    ("pageSize", CHANGES_PAGE_SIZE.to_string()),
                    ("includeRemoved", "true".to_owned()),
                    ("includeItemsFromAllDrives", "true".to_owned()),
                    ("supportsAllDrives", "true".to_owned()),
                    ("fields", fields),
                ],
            )?
            .ok_or_else(|| refused("google_drive_changes_token_unknown"))?;
        let changes = array(&page, "changes")
            .iter()
            .filter(|change| {
                change
                    .get("changeType")
                    .and_then(Value::as_str)
                    .is_none_or(|kind| kind == "file")
            })
            .filter_map(|change| {
                Some(DriveChange {
                    file_id: text_of(change.get("fileId"))?,
                    removed: change
                        .get("removed")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    file: change.get("file").and_then(file_meta),
                })
            })
            .collect();
        Ok(DriveChangesPage {
            changes,
            next_page: text_of(page.get("nextPageToken")),
            new_start: text_of(page.get("newStartPageToken")),
        })
    }

    fn file(&self, origin: &DriveOrigin, id: &str) -> Result<Option<DriveFileMeta>> {
        let Some(file) = self.get_json(
            origin,
            &file_url(id)?,
            &[
                ("fields", DRIVE_FILE_FIELDS.to_owned()),
                ("supportsAllDrives", "true".to_owned()),
            ],
        )?
        else {
            return Ok(None);
        };
        file_meta(&file)
            .map(Some)
            .ok_or_else(|| refused("google_drive_file_unreadable"))
    }

    fn download(&self, origin: &DriveOrigin, id: &str) -> Result<Option<Vec<u8>>> {
        self.get_bytes(
            origin,
            &file_url(id)?,
            &[
                ("alt", "media".to_owned()),
                ("supportsAllDrives", "true".to_owned()),
            ],
        )
    }

    fn export(&self, origin: &DriveOrigin, id: &str, mime_type: &str) -> Result<Option<Vec<u8>>> {
        self.get_bytes(
            origin,
            &format!("{}/export", file_url(id)?),
            &[("mimeType", mime_type.to_owned())],
        )
    }

    fn quota(&self) -> Option<DriveQuota> {
        Some(GOOGLE_DRIVE_QUOTA)
    }
}

impl Vault {
    /// One bounded step of the Drive source attached as `folder`, read over
    /// this host's HTTPS: [`Vault::drive_sync_step`] through
    /// [`HttpGoogleDriveWire`]. It reads over blocking HTTP: call it off any
    /// async runtime.
    ///
    /// # Errors
    /// As [`Vault::drive_sync_step`], or a TLS client that cannot be built.
    pub fn drive_source_sync_step(
        &self,
        owner: &AuthenticatedOwner,
        folder: &str,
        budget: DriveStepBudget,
    ) -> Result<DriveStepReport> {
        let wire = HttpGoogleDriveWire::new(self)?;
        self.drive_sync_step(owner, folder, &wire, budget)
    }
}

/// The answer, unless Drive answered that its rate is spent: that one is
/// [`DRIVE_WIRE_RATE_LIMITED`], which rests the source rather than failing
/// its step.
fn rate_limited<T>(answer: RestAnswer<T>) -> Result<RestAnswer<T>> {
    answer.unless_rate_limited().map_err(|error| match error {
        Error::InvalidConfig(code) if code == MAIL_WIRE_RATE_LIMITED => {
            refused(DRIVE_WIRE_RATE_LIMITED)
        }
        other => other,
    })
}

/// The URL of the file `id`: a plain Drive id only.
fn file_url(id: &str) -> Result<String> {
    if id.is_empty()
        || id.len() > MAX_FILE_ID_BYTES
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(refused("google_drive_file_id_not_plain"));
    }
    Ok(format!("{DRIVE_API_URL}/files/{id}"))
}

/// A file's metadata as Drive answers it; none without an id.
fn file_meta(file: &Value) -> Option<DriveFileMeta> {
    Some(DriveFileMeta {
        id: text_of(file.get("id"))?,
        name: text_of(file.get("name")).unwrap_or_default(),
        mime_type: text_of(file.get("mimeType")).unwrap_or_default(),
        modified_at: file
            .get("modifiedTime")
            .and_then(Value::as_str)
            .and_then(|time| chrono::DateTime::parse_from_rfc3339(time.trim()).ok())
            .and_then(|time| u64::try_from(time.timestamp()).ok())
            .unwrap_or(0),
        // Drive answers a size as a decimal string.
        size: file.get("size").and_then(|size| {
            size.as_str()
                .and_then(|size| size.parse().ok())
                .or_else(|| size.as_u64())
        }),
        trashed: file
            .get("trashed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}
