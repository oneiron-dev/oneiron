# Windows keystore temporary files

The DPAPI backend keeps its existing per-slot sealed files and temporary names.
A persistent `.<slot>.lock` file contains no key. Its OS-held exclusive lock
coordinates create, replace, temporary cleanup and deletion across processes.
Do not unlink these lock files while a keystore process can still run.

Opening the store attempts orphan cleanup only when the slot lock is immediately
available. Cleanup does not promote a temporary file to a slot. A busy publisher
or a cleanup failure does not prevent existing reads. `get` still reads only the
published slot file.

Create, replace and delete clean matching orphan temporary files while holding
the same slot lock. Matching parses the numeric process id and timestamp from
the right, preserving the entire slot name, including dots. Other slots' files
are not removed. Cleanup errors propagate from these mutations. A successful
delete removed both its matching temporary files and its published slot; it does
not prevent a later explicit create.

The final hard-link/rename publication, DPAPI entropy, key size and sealed-file
limit are unchanged. This source change does not establish Windows runtime or
native-build proof.
