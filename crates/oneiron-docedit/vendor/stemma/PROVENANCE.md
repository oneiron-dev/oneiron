# Stemma stateless source fork

- Upstream: https://github.com/stemma-sh/stemma
- Tag: `v0.6.0`
- Commit: `ad1e70deac0a828d5162ac3b3f2186c2bb0c075e`
- Copyright (c) 2026 Stemma.
- Taken under **Apache-2.0** from the upstream MIT OR Apache-2.0 grant.
  Both upstream license texts are retained. Upstream has no NOTICE file.
- Package: `oneiron-stemma 0.6.0-oneiron.1`, a private path dependency of
  `oneiron-docedit`. No dependency on the storage engine.

## Source and changes

This is a source fork, not a licence-only pin. `docx_validate_annotations.rs`
and `xml_attrs.rs` are copied from `stemma-engine/src` at the exact commit.
`docx_validate.rs` retains the upstream finding/severity types. `domain.rs`
retains upstream RevisionInfo, StackedRevision and TrackingStatus. `parse.rs`
retains the upstream depth preflight, changes its error representation, caps
nesting at 128, and additionally rejects malformed XML and DTDs before xmltree.
`UPSTREAM-SHA256.json` records the complete original files for these extracts.

Oneiron's native revision writer constructs this fork's typed TrackingStatus
and RevisionInfo to emit the native carriers. Every docx output must pass this
fork's real post-serialization tracked-change/annotation checks, including the
paragraph-mark deletion content model. The retained writer preserves untouched
XML instead of taking upstream's whole-document rebuild path.

The workspace, MCP/API/CLI servers, stateful runtime, diff/inference subsystem,
whole-document import/materializer and unused serializers are deliberately
cut. No upstream benchmark result is claimed for this narrower fork. The
upstream annotation unit tests remain in the copied source. Word/LibreOffice
comparison and the full conformance corpus belong to the coordinator oracle.

Dependencies introduced by this fork: xmltree-ns 0.13.0 (MIT), quick-xml 0.41
(MIT; already resolved in the workspace), serde 1 (MIT OR Apache-2.0).

The read-only checker fork omits unused attribute-write/capture helpers and their namespace constants. The source hashes above identify the upstream inputs, not our modified files.

The retained finding type derives `Debug`, as required by the retained upstream annotation tests. The measured conformance scope is the stateless retained fork, not upstream's removed application/runtime suite.
