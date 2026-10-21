//! The per-request door-owned hook directory and the vetted pre-receive script it
//! carries.

use std::fs;
use std::path::{Path, PathBuf};

use super::bounds::ScanBounds;
use super::paths::{DOOR_BLOB_TOO_LARGE, DOOR_DISK_FLOOR, DOOR_PRE_RECEIVE_HOOK_NAME};
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
/// while the objects are still quarantined. Each move's blobs follow a line
/// naming the move, so the door holds each ref to the pointers its own move
/// brings.
///
/// The tip diff alone would miss what a push carries in between: a blob one
/// commit adds and a later commit reverts or deletes leaves no trace in the
/// endpoint diff, yet it stays durable in history. So the hook also walks
/// every object the new tips reach that no existing ref already reaches, and
/// frames each blob the tip diffs did not, once, into a second stream the door
/// scans the same way. The walk alone would still miss a blob the pack carries
/// that no tip reaches: receive-pack moves the whole quarantine into the store
/// once the hook admits, so every object in the quarantine is listed too, and
/// one rev-list named no path for is labelled by its oid.
///
/// No push is too large as a whole. Each blob is held to the scan's per-blob
/// bound, and the framed bytes of both streams, headers included, to the free
/// disk above its floor, read once when the hook starts ([`ScanBounds`],
/// substituted when the hook is written). Past either the push is refused
/// whole, never scanned in part, with a reason that names the bound's key.
///
/// A checkout push (G1-PUSH) also lists, per move, every path the move
/// changes, deletes and both names of a rename included, into a third
/// stream the final intent writer judges under the run's Grant; the list is
/// charged to the same disk budget. Every other push lists none.
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
# Each move's records follow one "move <old> <new>\n" line naming it, so the
# door knows which refs a blob reaches.
#
# The history stream frames every OTHER blob the new tips reach that no existing
# ref already reaches, so a blob an intermediate commit adds and a later one
# reverts or deletes is scanned too, and every other blob the quarantine holds,
# because receive-pack migrates the whole quarantine, reachable or not. Its
# records come from cat-file --batch: the same header and bytes, then one "\n".
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
pairs="$dir/pre-receive.pairs"
tips="$dir/pre-receive.tips"
objects="$dir/pre-receive.objects"
typed="$dir/pre-receive.typed"
listed="$dir/pre-receive.listed"
seen="$dir/pre-receive.seen"
verdict="$dir/pre-receive.verdict"
paths="$dir/pre-receive.paths"
pathspart="$dir/pre-receive.paths.part"
names="$dir/pre-receive.names"
listpaths=@DOOR_LIST_CHANGED_PATHS@
# The door holds one blob whole while it scans it, so no blob may carry more
# than this. The streams are written to this directory's disk, which keeps this
# floor free: its free space is read once, here, and every framed byte, headers
# included, is charged against what lies above the floor. Past either bound the
# push is refused whole, never scanned in part.
blobmax=@DOOR_SCAN_BLOB_BYTES@
floor=@DOOR_SCAN_DISK_FLOOR_BYTES@
blob_too_large() {
	echo "oneiron door refused this push: @DOOR_BLOB_TOO_LARGE@" >&2
	exit 1
}
disk_floor() {
	echo "oneiron door refused this push: @DOOR_DISK_FLOOR@" >&2
	exit 1
}
# A df that fails, or prints no row this can read, refuses the push. The
# available column is the field before the capacity, since a filesystem or
# mount name may itself hold spaces. df prints each of those columns as a
# number, a negative one, or `-` when unknown, so the row's own columns always
# match below. A name that matches too makes two places they could start, and
# the push is refused, as it is when the space available is negative or unknown.
space=$(df -Pk "$dir") || exit 1
free=$(printf '%s\n' "$space" | LC_ALL=C awk 'NR == 2 {
	for (i = 5; i <= NF; i++)
		if ($i ~ /^(-?[0-9]+%|-)$/ && $(i - 1) ~ /^(-?[0-9]+|-)$/ && $(i - 2) ~ /^(-?[0-9]+|-)$/ && $(i - 3) ~ /^(-?[0-9]+|-)$/) {
			found++
			free = $(i - 1)
		}
	if (found == 1) print free
}')
case "$free" in
	'' | *[!0-9]*) exit 1 ;;
esac
# Fifteen digits of KiB keep the product below the shell's integer range, and
# the budget is held to 2^53, where awk's doubles still compare exactly.
[ "${#free}" -le 15 ] || exit 1
max=$((free * 1024 - floor))
[ "$max" -ge 0 ] || disk_floor
[ "$max" -le 9007199254740992 ] || max=9007199254740992
total=0
tab=$(printf '\t')
: > "$part"
: > "$pairs"
: > "$blobspart"
: > "$historypart"
: > "$pathspart"
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
	printf '%s %s\n' "$old" "$new" >> "$pairs"
done
# Many refs can name one move: each distinct move is diffed and its blobs
# framed once, so a push's cost follows what it makes durable, not how many
# names it gives it.
sort -u -o "$pairs" "$pairs"
while read -r old new; do
	case "$old" in
		*[!0]*) base=$old ;;
		*) base=$empty ;;
	esac
	# Written to a file, never piped: a diff-tree that fails must fail the
	# hook, and the left-hand side of a pipeline cannot do that in POSIX sh.
	git --no-replace-objects diff-tree -r --raw --no-abbrev --no-commit-id \
		--diff-filter=AMT "$base" "$new" > "$entries"
	total=$((total + ${#old} + ${#new} + 7))
	[ "$total" -le "$max" ] || disk_floor
	printf 'move %s %s\n' "$old" "$new" >> "$blobspart"
	# A checkout push's changed paths, NUL-terminated after one framed
	# "move <old> <new> <bytes>" line, every status and both rename names.
	if [ "$listpaths" = 1 ]; then
		git --no-replace-objects diff-tree -r -z --name-only --no-renames \
			--no-commit-id "$base" "$new" > "$names"
		size=$(($(wc -c < "$names")))
		total=$((total + size + ${#old} + ${#new} + 32))
		[ "$total" -le "$max" ] || disk_floor
		printf 'move %s %s %s\n' "$old" "$new" "$size" >> "$pathspart"
		cat "$names" >> "$pathspart"
	fi
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
		[ "$size" -le "$blobmax" ] || blob_too_large
		# The record's header: its fixed fields and the path.
		total=$((total + size + 128 + ${#path}))
		[ "$total" -le "$max" ] || disk_floor
		printf 'blob %s %s %s\n' "$oid" "$size" "$path" >> "$blobspart"
		git --no-replace-objects cat-file blob "$oid" >> "$blobspart"
		printf '%s\n' "$oid" >> "$seen"
	done < "$entries"
done < "$pairs"
# The tips go to rev-list on its stdin, never its argv, which a push of many
# refs would outgrow.
awk '{ print $2 }' "$pairs" > "$tips"
: > "$objects"
if [ -s "$tips" ]; then
	git --no-replace-objects rev-list --objects --stdin --not --all \
		< "$tips" > "$objects"
fi
# The pack can carry objects no tip reaches, and receive-pack migrates the whole
# quarantine once this hook admits. So every object in it is listed as well,
# after the walk, so a path rev-list named is the label kept. With the
# alternates unset the listing is the quarantine's alone, not the store's.
if [ -n "${GIT_QUARANTINE_PATH-}" ]; then
	(
		unset GIT_ALTERNATE_OBJECT_DIRECTORIES
		git --no-replace-objects cat-file --batch-all-objects \
			--batch-check='%(objectname)'
	) >> "$objects"
fi
if [ -s "$objects" ]; then
	git --no-replace-objects cat-file \
		--batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' \
		< "$objects" > "$typed"
	# Keeps each blob the tip diffs did not frame, once, under the first path
	# rev-list named it by, made printable: the path only labels a refusal.
	# A blob with no usable path (a quarantine-only object, or a name rev-list
	# cut at a newline or cat-file read as blank) is labelled by its oid.
	# Any line that is not a typed object fails the hook.
	status=0
	LC_ALL=C awk -v total="$total" -v max="$max" -v blobmax="$blobmax" '
		FILENAME == ARGV[1] { seen[$0] = 1; next }
		NF < 3 || $1 !~ /^(blob|tree|commit|tag)$/ { exit 4 }
		$1 != "blob" || ($2 in seen) { next }
		{
			seen[$2] = 1
			if ($3 > blobmax) exit 5
			path = $0
			sub(/^[^ ]* [^ ]* [^ ]* /, "", path)
			gsub(/[^ -~]/, "?", path)
			if (path !~ /[^ ]/) path = $2
			total += $3 + 128 + length(path)
			if (total > max) exit 3
			print $2 " " path
		}
	' "$seen" "$typed" > "$listed" || status=$?
	case "$status" in
		0) ;;
		3) disk_floor ;;
		5) blob_too_large ;;
		*) exit 1 ;;
	esac
	git --no-replace-objects cat-file \
		--batch='blob %(objectname) %(objectsize) %(rest)' \
		< "$listed" > "$historypart"
fi
printf 'end\n' >> "$part"
rm -f "$entries" "$pairs" "$tips" "$objects" "$typed" "$listed" "$seen" "$names"
mv -f "$pathspart" "$paths"
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
        Self::materialize_with(root, ScanBounds::default())
    }

    /// Materializes the directory with the hook keeping `scan`'s bounds.
    pub(super) fn materialize_with(root: &Path, scan: ScanBounds) -> Result<Self> {
        Self::materialize_listing(root, scan, false)
    }

    /// [`Self::materialize_with`], the hook also listing each move's
    /// changed paths when `list_paths` (a checkout push, G1-PUSH).
    pub(super) fn materialize_listing(
        root: &Path,
        scan: ScanBounds,
        list_paths: bool,
    ) -> Result<Self> {
        let path = root.join(EntityId::now().to_hex());
        fs::create_dir_all(&path)?;
        let hook = path.join(DOOR_PRE_RECEIVE_HOOK_NAME);
        let script = DOOR_PRE_RECEIVE_HOOK
            .replace("@DOOR_SCAN_BLOB_BYTES@", &scan.blob_bytes().to_string())
            .replace(
                "@DOOR_SCAN_DISK_FLOOR_BYTES@",
                &scan.disk_floor_bytes().to_string(),
            )
            .replace("@DOOR_BLOB_TOO_LARGE@", DOOR_BLOB_TOO_LARGE)
            .replace("@DOOR_DISK_FLOOR@", DOOR_DISK_FLOOR)
            .replace(
                "@DOOR_LIST_CHANGED_PATHS@",
                if list_paths { "1" } else { "0" },
            );
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

    /// The changed-path stream of a checkout push, moved into place before
    /// the history stream.
    pub(super) fn paths_path(&self) -> PathBuf {
        self.path.join("pre-receive.paths")
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
