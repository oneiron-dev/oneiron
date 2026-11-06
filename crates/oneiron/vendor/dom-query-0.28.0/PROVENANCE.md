# dom_query 0.28.0 production snapshot

Source: crates.io dom_query 0.28.0, registry archive SHA-256
`fac5fca71e65e94cc718a6e2af65d6e0f9c6027751c2aa562fbb5087fda639bc`.
The original MIT license, README, package VCS metadata and included Examples.md
are retained. Examples.md is crate documentation included by src/lib.rs, not an
example target. No example, benchmark or test target or dev dependency is packaged.
Six trailing cfg(test) modules are omitted from this new production snapshot.
Other production source is unchanged except for the native arena reservation API
in src/dom_tree/arena.rs and its exports. Existing dependency versions and features
are unchanged. In particular dom_query 0.27.0 and html5ever 0.38.0 stay on the registry.

The added API reserves the actual Vec<TreeNode> capacity on a caller-provided guard
before allocation, settles allocator-reported capacity, and frees old storage before
returning a replacement guard. The parser caller owns that guard for the arena's
lifetime. It does not admit attributes, text tendrils or any transitive node heap.
It adds no node-count or input-size limit.
