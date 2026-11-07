//! The host's precision recalculator (ARCH-0075 xlsx row; FIX 2462,
//! OF-505 = A): LibreOffice Calc headless recalculates a workbook the native
//! formula engine refuses, and only the values it computed for the formula
//! cells come back, written into the original package in place
//! ([`write_cached_values`]). LibreOffice writes a package of its own when it
//! saves, so its file is never the output: every part the values do not
//! touch keeps its bytes, an external link's target among them.
//!
//! Each run takes the host's own turn in the renderer line
//! (`limits.renderer_work`), behind every caller, as the review renderer's
//! own wakes do; runs in a fresh private directory of the vault disk's spool
//! with its own user profile ([`PROFILE_SETTINGS`]); claims its room on that
//! disk's floor before each write; and leases the memory it reads back
//! before it reads it. The version LibreOffice names is looked for once, in
//! the first run's turn. The server installs it on its vault when `soffice`
//! is on PATH ([`install`]).
//! Entry: `install`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::office_body::{
    ContractError, DocumentLocationArgs, ErrorCode, PackageLimits, RecalcClockArgs, RecalcPort,
    Recalculated, ResourceRefusal, document_resources, write_cached_values,
};
use oneiron::origin::smart_http::SpillFloor;

use crate::admission::Admission;
use crate::libreoffice::{Ran, Scratch, Soffice, Under, on_path, profile_arg, run};
use crate::machine::{DiskClaim, DiskFloor, MachineMemory, MemoryLease, MemoryRefusal};
use crate::server::SyncServer;

/// The calculator a recalculated version names.
const ENGINE: &str = "libreoffice";
/// A version stamp holds at most this many bytes.
const MAX_VERSION_BYTES: usize = 128;
/// One recalculation's whole run, from its turn: LibreOffice's start, load,
/// recalculation and save. An engine call (CALLS, FIX 2462).
const RECALC_TIME: Duration = Duration::from_secs(120);
/// The disk a recalculation claims before LibreOffice runs: four times the
/// workbook's bytes and 128 MiB more, for its saved copy, its private
/// profile and the temp files it writes to the scratch, as a deck's export
/// claims. An engine call (CALLS, FIX 2462).
const RECALC_DISK_FACTOR: u64 = 4;
const RECALC_DISK_BYTES: u64 = 128 << 20;
/// The export filter: Calc's Office Open XML workbook.
const XLSX_FILTER: &str = "xlsx:Calc MS Excel 2007 XML";

/// The settings each run's fresh user profile starts from, its
/// `user/registrymodifications.xcu`. An engine call (CALLS, FIX 2462):
/// - every OOXML and ODF workbook recalculates on load, always
///   (`/org.openoffice.Office.Calc/Formula/Load`: `OOXMLRecalcMode` and
///   `ODFRecalcMode` 0, "always");
/// - no external link updates (`/org.openoffice.Office.Calc/Content/Update`:
///   `Link` 1, "never"), so a link's cached values stand;
/// - no macros run (`/org.openoffice.Office.Common/Security/Scripting`:
///   `MacroSecurityLevel` 3, "very high"; `DisableMacrosExecution` true), and
///   links from untrusted locations are blocked (`BlockUntrustedRefererLinks`
///   true);
/// - no network: a manual proxy (`/org.openoffice.Inet/Settings`:
///   `ooInetProxyType` 1) for HTTP, HTTPS and FTP at 127.0.0.1 port 1, where
///   nothing answers, with no exceptions (`ooInetNoProxy` empty), so
///   WEBSERVICE and linked data fetch nothing.
const PROFILE_SETTINGS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<oor:items xmlns:oor="http://openoffice.org/2001/registry" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<item oor:path="/org.openoffice.Office.Calc/Formula/Load"><prop oor:name="OOXMLRecalcMode" oor:op="fuse"><value>0</value></prop></item>
<item oor:path="/org.openoffice.Office.Calc/Formula/Load"><prop oor:name="ODFRecalcMode" oor:op="fuse"><value>0</value></prop></item>
<item oor:path="/org.openoffice.Office.Calc/Content/Update"><prop oor:name="Link" oor:op="fuse"><value>1</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="MacroSecurityLevel" oor:op="fuse"><value>3</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="DisableMacrosExecution" oor:op="fuse"><value>true</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="BlockUntrustedRefererLinks" oor:op="fuse"><value>true</value></prop></item>
<item oor:path="/org.openoffice.Inet/Settings"><prop oor:name="ooInetProxyType" oor:op="fuse"><value>1</value></prop></item>
<item oor:path="/org.openoffice.Inet/Settings"><prop oor:name="ooInetHTTPProxyName" oor:op="fuse"><value>127.0.0.1</value></prop></item>
<item oor:path="/org.openoffice.Inet/Settings"><prop oor:name="ooInetHTTPProxyPort" oor:op="fuse"><value>1</value></prop></item>
<item oor:path="/org.openoffice.Inet/Settings"><prop oor:name="ooInetHTTPSProxyName" oor:op="fuse"><value>127.0.0.1</value></prop></item>
<item oor:path="/org.openoffice.Inet/Settings"><prop oor:name="ooInetHTTPSProxyPort" oor:op="fuse"><value>1</value></prop></item>
<item oor:path="/org.openoffice.Inet/Settings"><prop oor:name="ooInetFTPProxyName" oor:op="fuse"><value>127.0.0.1</value></prop></item>
<item oor:path="/org.openoffice.Inet/Settings"><prop oor:name="ooInetFTPProxyPort" oor:op="fuse"><value>1</value></prop></item>
<item oor:path="/org.openoffice.Inet/Settings"><prop oor:name="ooInetNoProxy" oor:op="fuse"><value></value></prop></item>
</oor:items>
"#;

/// Installs the host's precision recalculator on `server`'s vault when
/// `soffice` is on PATH. With none the vault has no recalculator, and a
/// workbook the native engine refuses is marked to recalculate when it is
/// opened, as before.
pub(crate) fn install(server: &SyncServer) {
    if on_path("soffice").is_none() {
        return;
    }
    server
        .vault
        .install_xlsx_precision_recalc(Arc::new(LibreOfficeRecalc {
            line: server.renderer_turns.clone(),
            memory: server.memory.clone(),
            disk: server.transfers.disk.clone(),
            soffice: OnceLock::new(),
        }));
}

/// LibreOffice headless as the vault's precision recalculator.
struct LibreOfficeRecalc {
    /// The host's renderer line, whose own turn each run takes.
    line: Admission<EntityId>,
    memory: MachineMemory,
    /// The vault disk's floor, whose private spool holds each run's scratch.
    disk: DiskFloor,
    /// The host's LibreOffice, looked for once, in the first run's turn.
    soffice: OnceLock<Option<Soffice>>,
}

impl RecalcPort for LibreOfficeRecalc {
    fn recalculate(
        &self,
        workbook: &[u8],
        limits: PackageLimits,
        clock: &RecalcClockArgs,
        location: Option<&DocumentLocationArgs>,
    ) -> Result<Recalculated, ContractError> {
        self.recalculate_in_zone(workbook, limits, clock, location, None)
    }

    /// `workbook` recalculated by LibreOffice in the caller's local time
    /// ([`zone_variable`]), its values written into `workbook` itself. The
    /// caller's instant and seed do not reach it: LibreOffice reads NOW()
    /// and TODAY() from the host's clock and draws its own random numbers,
    /// an engine call (CALLS, FIX 2462). Nor does `location`: a formula that
    /// reads the file's location keeps the value it cached.
    fn recalculate_in_zone(
        &self,
        workbook: &[u8],
        limits: PackageLimits,
        clock: &RecalcClockArgs,
        _location: Option<&DocumentLocationArgs>,
        zone: Option<&str>,
    ) -> Result<Recalculated, ContractError> {
        let _turn = self
            .line
            .admit_background_blocking()
            .map_err(|_| ContractError::resource(ResourceRefusal::Deadline))?;
        let deadline = Instant::now() + RECALC_TIME;
        let spool = self.disk.spool_dir().ok_or_else(|| {
            unavailable("the vault disk keeps no spool to recalculate a workbook in")
        })?;
        let soffice = self
            .soffice
            .get_or_init(|| Soffice::find(&spool))
            .as_ref()
            .ok_or_else(|| unavailable("LibreOffice (soffice) names no version on this host"))?;
        let mut lease = self.memory.empty_lease();
        let tz = zone_variable(clock.utc_offset_minutes, zone);
        let computed = self.convert(soffice, &spool, workbook, &tz, deadline, &mut lease)?;
        let written = write_cached_values(workbook, &computed, limits, &document_resources())
            .map_err(|error| match error.resource() {
                Some(refusal) => ContractError::resource(refusal),
                None => ContractError::new(
                    ErrorCode::Internal,
                    format!("the recalculated values could not be written back: {error}"),
                ),
            })?;
        Ok(Recalculated {
            bytes: written.bytes,
            engine: ENGINE.to_owned(),
            version: stamp_version(&soffice.version),
            formula_count: written.formula_count,
        })
    }
}

impl LibreOfficeRecalc {
    /// `workbook` as LibreOffice saves it again, recalculated on load, in a
    /// fresh private directory of `spool`, in local zone `tz`, by
    /// `deadline`. Each write claims its room on the vault disk's floor
    /// first, the floor is checked again once LibreOffice wrote, and the
    /// saved copy's bytes are leased under `lease` before they are read.
    fn convert(
        &self,
        soffice: &Soffice,
        spool: &Path,
        workbook: &[u8],
        tz: &str,
        deadline: Instant,
        lease: &mut MemoryLease,
    ) -> Result<Vec<u8>, ContractError> {
        let scratch = Scratch::new(spool, "oneiron-xlsx-recalc").map_err(internal)?;
        let input = scratch.path.join("book.xlsx");
        let out = scratch.path.join("out");
        let book_bytes = u64::try_from(workbook.len()).unwrap_or(u64::MAX);
        let writing = self.claim(book_bytes)?;
        std::fs::write(&input, workbook).map_err(internal)?;
        drop(writing);
        let running = self.claim(
            book_bytes
                .saturating_mul(RECALC_DISK_FACTOR)
                .saturating_add(RECALC_DISK_BYTES),
        )?;
        let user = scratch.path.join("profile").join("user");
        std::fs::create_dir_all(&user).map_err(internal)?;
        std::fs::write(user.join("registrymodifications.xcu"), PROFILE_SETTINGS)
            .map_err(internal)?;
        std::fs::create_dir(&out).map_err(internal)?;
        // Only the standard descriptors reach LibreOffice.
        let mut convert = oneiron_spawn::command(&soffice.path);
        convert
            .arg(profile_arg(&scratch.path))
            .args([
                "--headless",
                "--invisible",
                "--nologo",
                "--norestore",
                "--nodefault",
                "--nolockcheck",
                "--convert-to",
                XLSX_FILTER,
                "--outdir",
            ])
            .arg(&out)
            .arg(&input)
            // LibreOffice's own temp files land in the scratch, on the
            // floored disk.
            .env("TMPDIR", &scratch.path)
            .env("TZ", tz)
            .stdout(Stdio::null());
        let stop = AtomicBool::new(false);
        let under = Under {
            deadline,
            stop: &stop,
        };
        let ran = run(
            convert,
            RECALC_TIME,
            &under,
            "the LibreOffice recalculation",
        )
        .map_err(internal)?;
        drop(running);
        if ran == Ran::Cut {
            return Err(ContractError::resource(ResourceRefusal::Deadline));
        }
        if !self.disk.has_room_for(0) {
            return Err(disk_floor());
        }
        let saved = out.join("book.xlsx");
        let size = std::fs::metadata(&saved).map_or(0, |meta| meta.len());
        if size == 0 {
            return Err(ContractError::new(
                ErrorCode::Internal,
                "LibreOffice wrote no recalculated workbook",
            ));
        }
        let stopped = || false;
        lease.grow(size, deadline, &stopped).map_err(|refused| {
            ContractError::resource(match refused {
                MemoryRefusal::Floor { needed, available } => {
                    ResourceRefusal::MemoryFloor { needed, available }
                }
                MemoryRefusal::WaitedOut { .. } => ResourceRefusal::Deadline,
            })
        })?;
        let bytes = std::fs::read(&saved).map_err(internal)?;
        lease.materialized(size, u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        Ok(bytes)
    }

    /// Room for `bytes` the run is about to write, claimed on the vault
    /// disk's floor past its reserve and every other claim. Dropped once the
    /// bytes are written, when the disk itself shows them.
    fn claim(&self, bytes: u64) -> Result<Arc<DiskClaim>, ContractError> {
        let claim = self.disk.claim();
        if self.disk.hold(&claim, bytes) {
            Ok(claim)
        } else {
            Err(disk_floor())
        }
    }
}

/// The `TZ` a run reads NOW() and TODAY() in. An engine call (CALLS, FIX
/// 2462): the caller's IANA zone when it names one this host holds the rules
/// for ([`held_zone`]), else its offset as a POSIX zone, whose sign is the
/// inverse of the offset's (`<+0900>-09:00` is nine hours east of UTC).
fn zone_variable(offset_minutes: i16, zone: Option<&str>) -> String {
    if let Some(name) = zone.filter(|name| held_zone(name)) {
        return name.to_owned();
    }
    let minutes = offset_minutes.unsigned_abs();
    let (hours, minutes) = (minutes / 60, minutes % 60);
    let (label, posix) = if offset_minutes < 0 {
        ('-', '+')
    } else {
        ('+', '-')
    };
    format!("<{label}{hours:02}{minutes:02}>{posix}{hours:02}:{minutes:02}")
}

/// Whether `name` reads as an IANA zone name (`Asia/Tokyo`) whose rules this
/// host holds, under `TZDIR` or `/usr/share/zoneinfo`.
fn held_zone(name: &str) -> bool {
    let shaped = name.len() <= 64
        && name.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+'))
        });
    shaped
        && std::env::var_os("TZDIR")
            .map_or_else(|| PathBuf::from("/usr/share/zoneinfo"), PathBuf::from)
            .join(name)
            .is_file()
}

/// `version` within a version stamp's bytes.
fn stamp_version(version: &str) -> String {
    let mut end = version.len().min(MAX_VERSION_BYTES);
    while !version.is_char_boundary(end) {
        end -= 1;
    }
    version[..end].trim_end().to_owned()
}

fn unavailable(detail: &str) -> ContractError {
    ContractError::new(ErrorCode::Unavailable, detail)
}

fn disk_floor() -> ContractError {
    unavailable(
        "the vault's disk is at its free-space reserve (limits.disk_reserve_bytes), and the workbook recalculation writes its scratch there",
    )
}

fn internal(error: impl std::fmt::Display) -> ContractError {
    ContractError::new(ErrorCode::Internal, error.to_string())
}
