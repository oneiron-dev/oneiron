//! The per-request door-owned hook directory and the vetted pre-receive script it
//! carries.

use std::fs;
use std::path::{Path, PathBuf};

use super::paths::{DOOR_MAX_SCAN_BYTES, DOOR_PRE_RECEIVE_HOOK_NAME};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The vetted `pre-receive` hook.
///
/// It is the ONLY executable the door-owned directory carries, and it is the
/// only hook any serve invocation can reach. It enumerates the pushed blobs
/// with git plumbing *inside the quarantine window*, hands them to the door
/// through the request file, and blocks on the verdict. Every failure path
/// exits non-zero: a door that cannot answer refuses the push.
///
/// The enumeration is the RAW diff, never a text patch. `--raw` names every
/// added or modified entry with its post-image oid whether or not the entry has
/// a printable patch, and each named blob is emitted WHOLE and length-framed,
/// so binary content, NUL-carrying content and content whose lines begin with
/// `+` all reach the door as the exact bytes the push would make durable. A
/// blob the hook cannot size or read ends the push right here, under `set -e`,
/// while the objects are still quarantined.
///
/// The tip diff alone would miss what a push carries in between: a blob one
/// commit adds and a later commit reverts or deletes leaves no trace in the
/// endpoint diff, yet it stays durable in history. So the hook also walks
/// every object the new tips reach that no existing ref already reaches, and
/// frames each blob the tip diffs did not, once, into a second stream the door
/// scans the same way. Both streams together are capped at
/// [`DOOR_MAX_SCAN_BYTES`], substituted for `@DOOR_MAX_SCAN_BYTES@` when the
/// hook is written; a push past it is refused, never scanned in part.
pub(super) const DOOR_PRE_RECEIVE_HOOK: &str = r#"#!/bin/sh
# Vetted door hook (ONE-1908). Repository-supplied hooks never run: every serve
# invocation pins core.hooksPath in argv to this door-owned directory.
#
# This runs inside git's quarantine window: the received objects are still under
# GIT_QUARANTINE_PATH, so a non-zero exit leaves refs unmoved and the objects
# unreachable.
#
# The blob stream is length-framed: "blob <oid> <bytes> <path>\n" followed by
# exactly <bytes> raw bytes. Framing rather than patch text is what makes the
# extraction total -- there is no line shape a blob can carry that hides it.
#
# The history stream frames every OTHER blob the new tips reach that no existing
# ref already reaches, so a blob an intermediate commit adds and a later one
# reverts or deletes is scanned too. Its records come from cat-file --batch:
# the same header and bytes, then one "\n".
#
# Every git below reads TRUE object bytes: replacement lookup is disabled by the
# exported GIT_NO_REPLACE_OBJECTS (which reaches any git a git spawns) and again
# by --no-replace-objects in each argv. A planted refs/replace/<oid> would
# otherwise hand this scan a benign substitute while the original object is what
# the push makes durable.
set -eu
GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_REPLACE_OBJECTS
dir=${0%/*}
req="$dir/pre-receive.request"
part="$dir/pre-receive.request.part"
blobs="$dir/pre-receive.blobs"
blobspart="$dir/pre-receive.blobs.part"
history="$dir/pre-receive.history"
historypart="$dir/pre-receive.history.part"
entries="$dir/pre-receive.entries"
objects="$dir/pre-receive.objects"
typed="$dir/pre-receive.typed"
listed="$dir/pre-receive.listed"
seen="$dir/pre-receive.seen"
verdict="$dir/pre-receive.verdict"
# Both streams together carry at most this many blob bytes. Past it the push is
# refused whole, never scanned in part.
max=@DOOR_MAX_SCAN_BYTES@
total=0
tips=
too_large() {
	echo "oneiron door: this push carries more than $max blob bytes to scan; push its history in smaller parts" >&2
	exit 1
}
tab=$(printf '\t')
: > "$part"
: > "$blobspart"
: > "$historypart"
: > "$seen"
printf 'quarantine %s\n' "${GIT_QUARANTINE_PATH-}" >> "$part"
empty=$(git --no-replace-objects hash-object -t tree /dev/null)
while read -r old new ref; do
	# Bind the intent to the actual pre-image before any ref can move. Otherwise
	# a declined creation of an already-existing ref could masquerade as a
	# crash-recovered effect merely because its post-image already exists.
	if actual=$(git --no-replace-objects rev-parse --verify -q --end-of-options "$ref"); then
		[ "$actual" = "$old" ] || exit 1
	else
		code=$?
		[ "$code" -eq 1 ] || exit 1
		case "$old" in *[!0]*) exit 1 ;; esac
	fi
	printf 'ref %s %s %s\n' "$old" "$new" "$ref" >> "$part"
	case "$new" in
		*[!0]*) ;;
		*) continue ;;
	esac
	tips="$tips $new"
	case "$old" in
		*[!0]*) base=$old ;;
		*) base=$empty ;;
	esac
	# Written to a file, never piped: a diff-tree that fails must fail the
	# hook, and the left-hand side of a pipeline cannot do that in POSIX sh.
	git --no-replace-objects diff-tree -r --raw --no-abbrev --no-commit-id \
		--diff-filter=AMT "$base" "$new" > "$entries"
	# ":<srcmode> <dstmode> <srcoid> <dstoid> <status><tab><path>"
	while IFS= read -r entry; do
		meta=${entry%%"$tab"*}
		path=${entry#*"$tab"}
		set -- $meta
		mode=$2
		oid=$4
		# A gitlink names a commit in another repository: this push makes no
		# bytes of it durable here, and there is no blob to read.
		case "$mode" in
			160000) continue ;;
		esac
		case "$oid" in
			*[!0]*) ;;
			*) continue ;;
		esac
		size=$(git --no-replace-objects cat-file -s "$oid")
		total=$((total + size))
		[ "$total" -le "$max" ] || too_large
		printf 'blob %s %s %s\n' "$oid" "$size" "$path" >> "$blobspart"
		git --no-replace-objects cat-file blob "$oid" >> "$blobspart"
		printf '%s\n' "$oid" >> "$seen"
	done < "$entries"
done
if [ -n "$tips" ]; then
	git --no-replace-objects rev-list --objects $tips --not --all > "$objects"
	git --no-replace-objects cat-file \
		--batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' \
		< "$objects" > "$typed"
	# Keeps each blob the tip diffs did not frame, once, under the first path
	# rev-list named it by, made printable: the path only labels a refusal.
	# Any line that is not a typed object fails the hook.
	status=0
	LC_ALL=C awk -v total="$total" -v max="$max" '
		FILENAME == ARGV[1] { seen[$0] = 1; next }
		NF < 3 || $1 !~ /^(blob|tree|commit|tag)$/ { exit 4 }
		$1 != "blob" || ($2 in seen) { next }
		{
			seen[$2] = 1
			total += $3
			if (total > max) exit 3
			path = $0
			sub(/^[^ ]* [^ ]* [^ ]* /, "", path)
			gsub(/[^ -~]/, "?", path)
			print $2 " " path
		}
	' "$seen" "$typed" > "$listed" || status=$?
	case "$status" in
		0) ;;
		3) too_large ;;
		*) exit 1 ;;
	esac
	git --no-replace-objects cat-file \
		--batch='blob %(objectname) %(objectsize) %(rest)' \
		< "$listed" > "$historypart"
fi
printf 'end\n' >> "$part"
rm -f "$entries" "$objects" "$typed" "$listed" "$seen"
mv -f "$historypart" "$history"
mv -f "$blobspart" "$blobs"
mv -f "$part" "$req"
waited=0
while [ ! -f "$verdict" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 120000 ]; then
		echo "oneiron door: verdict window closed without an answer" >&2
		exit 1
	fi
	sleep 0.005 2>/dev/null || sleep 1
done
answer=$(cat "$verdict")
if [ "$answer" = "ok" ]; then
	exit 0
fi
printf '%s\n' "$answer" >&2
exit 1
"#;

/// One per-request directory that `core.hooksPath` points at.
///
/// It is created by the origin, holds exactly one vetted `pre-receive` script,
/// and is removed when the request ends. A repository can neither add to it nor
/// redirect away from it.
#[derive(Debug)]
pub struct DoorHooksDir {
    path: PathBuf,
}

impl DoorHooksDir {
    /// Materializes a fresh door-owned directory under `root`.
    pub fn materialize(root: &Path) -> Result<Self> {
        Self::materialize_with_scan_cap(root, DOOR_MAX_SCAN_BYTES)
    }

    /// Materializes the directory with the hook's blob-byte cap set to
    /// `max_scan_bytes`.
    pub(super) fn materialize_with_scan_cap(root: &Path, max_scan_bytes: u64) -> Result<Self> {
        let path = root.join(EntityId::now().to_hex());
        fs::create_dir_all(&path)?;
        let hook = path.join(DOOR_PRE_RECEIVE_HOOK_NAME);
        let script =
            DOOR_PRE_RECEIVE_HOOK.replace("@DOOR_MAX_SCAN_BYTES@", &max_scan_bytes.to_string());
        fs::write(&hook, script.as_bytes())?;
        set_executable(&hook)?;
        Ok(Self {
            path: path.canonicalize()?,
        })
    }

    /// The directory every serve invocation pins in argv.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn request_path(&self) -> PathBuf {
        self.path.join("pre-receive.request")
    }

    /// The length-framed blob stream the hook emits, moved into place before
    /// the request file it announces.
    pub(super) fn blobs_path(&self) -> PathBuf {
        self.path.join("pre-receive.blobs")
    }

    /// The framed history stream: the blobs the new tips reach that the tip
    /// diffs did not frame. Moved into place before the blob stream.
    pub(super) fn history_path(&self) -> PathBuf {
        self.path.join("pre-receive.history")
    }

    pub(super) fn verdict_path(&self) -> PathBuf {
        self.path.join("pre-receive.verdict")
    }

    /// Publishes the verdict the blocked hook is waiting on. The write is
    /// rename-atomic, so the hook can never read half an answer.
    pub(super) fn publish_verdict(&self, verdict: &str) -> Result<()> {
        let staged = self.path.join("pre-receive.verdict.part");
        fs::write(&staged, verdict.as_bytes())?;
        fs::rename(&staged, self.verdict_path())?;
        Ok(())
    }
}

impl Drop for DoorHooksDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}
