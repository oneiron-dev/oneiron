#!/usr/bin/env bash
# The workload of the credential probe (FIX NODE-JOB-CREDENTIALS): it proves on a node what the code only reads from
# systemd.exec(5) -- that the job unit loads the staged directory before root's prepare step, that a file `probe` in it
# arrives as `$CREDENTIALS_DIRECTORY/job_probe`, and that the workload reads it through its file wall. It prints the
# first 16 hex digits of the file's sha256 and its size, never the bytes, and writes nothing.
#
# The template on the node (root's /etc/oneiron/execution-node.toml), beside the first harmless job's:
#   [execution_node.templates.credential-probe]
#   repo = "<the node's mirror of this repository>"
#   entries = ["scripts/execution-node/field/credential_probe.sh"]
#   interpreter = ["/usr/bin/bash"]
#   max_secs = 120
#   memory_gib = 1
#   disk_gib = 1
#   credentials = { probe = "/etc/oneiron/credentials/credential-probe/probe" }
# with the file made by root:  head -c 32 /dev/urandom | install -m 0400 -o root -g root /dev/stdin <that path>
# then `oneiron execution-node install` again. Compare the printed digest with root's own:
#   sha256sum /etc/oneiron/credentials/credential-probe/probe | cut -c1-16
#
# usage (the template's entry): credential_probe.sh
set -u
dir=${CREDENTIALS_DIRECTORY:-}
if [ -z "$dir" ]; then
  echo "credential_probe: no CREDENTIALS_DIRECTORY: the job got no credentials"
  exit 3
fi
file=$dir/job_probe
if [ ! -r "$file" ]; then
  echo "credential_probe: $file is not readable; the directory holds: $(ls -A "$dir" 2>&1 | tr '\n' ' ')"
  exit 4
fi
digest=$(sha256sum < "$file" | cut -c1-16)
size=$(wc -c < "$file")
echo "credential_probe: job_probe sha256 $digest bytes $size"
