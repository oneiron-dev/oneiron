# Attempt metadata cleanup

When the attempt queue removes a settled retry or an older compacted try, the
same transaction deletes that attempt's private Dreamer lineage-origin and
selection-scope rows through the queue's deleted-record index hook.

Cleanup uses only the removed attempt's exact id. It does not scan for other
rows whose values name that id. Retained retry successors keep their own pinned
lineage origin and copied scope, and no retained attempt's authority is rebuilt
or widened. Existing prune and compaction eligibility is unchanged.

The hook also applies to any selected archived-attempt deletion that uses the
same deleted-record hook. It does not resolve live-child parent availability or
make an archived deletion safe by reconstructing authority from metadata.
