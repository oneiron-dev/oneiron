# Git push path header framing

The receive-pack door reads the fixed fields of its length-framed blob header
as bytes. A path label that is valid UTF-8 stays byte-identical for the scanner,
secret marks and path-dependent dotenv rules.

When a raw path contains non-UTF-8 bytes, the door first removes any Git
C-quoting already present, then makes a printable Git C-quoted label from the
actual path bytes. The existing pointer attribution reader decodes that label
back to those exact bytes before matching the ref tree. This also covers
`core.quotePath=false` paths whose high bytes remain inside C quotes.

The hook commands, repository config, blob contents, object IDs, per-move
attribution, scan limits, history stream and NUL-framed checkout path stream
are unchanged. Existing UTF-8 labels are not normalized or unquoted for the
scanner. This repair does not claim a runtime push proof or change secret
scan disposition rules.
