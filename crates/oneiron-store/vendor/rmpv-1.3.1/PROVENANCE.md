# rmpv 1.3.1 local capacity accessor

Source: crates.io `rmpv` 1.3.1, archive SHA-256
`7a4e1d4b9b938a26d2996af33229f0ca0956c652c1375067f0b45291c1df8417`.
Repository: https://github.com/3Hren/msgpack-rust. License: MIT (`LICENSE`).

The production sources are the locked upstream release, with one additive
`Utf8String::capacity` method in `src/lib.rs`. It borrows the existing owned
String or invalid-UTF-8 Vec and reports its actual capacity. It changes no
bytes, decoder, encoder, layout, UTF-8 error or ownership. The canonical claim
reader uses it to keep a retained value's memory charge with that value.

The manifest is the normalized upstream manifest with only declarations for
uncopied test and bench targets removed. Production dependencies, features,
version and MSRV are unchanged. Tests and benches are not vendored or run.
The workspace dependency and both crates.io patches select this same directory.
This vendor is excluded from the workspace, like the other local patches.

## Unmodified upstream file hashes (SHA-256)

- `LICENSE`: `979d35e1d157289100ba2a7eb13fffe4e7a1b93506c755c4c66890918e467c4e`
- `README.md`: `e6044427cdb5062dd2a0b78571ea6c06b8badd97c99e497245c2711f29e646cd`
- `src/decode/mod.rs`: `e707d57ee3b5d8029836549b6174d44ec73700b0f063f0e42f7ff1a0e51dcdf1`
- `src/decode/value.rs`: `a7f1f5a4618e20a888a1050b62dd8e37072cd2a26c29a698f1f9e749c89bdd3e`
- `src/decode/value_ref.rs`: `2841cd0172e75bcfafe4c59d333e08ab1ea71400e03e8862c5c05570a08c4a61`
- `src/encode/mod.rs`: `c1e5192904e8ff7fb87aad90c0fdf1a37e6a0512caab5d15775e746b065f52f6`
- `src/encode/value.rs`: `9eecf8ac4da775a8805ee898a553e4b45e7d6d9aba16d95a803292ee7618b686`
- `src/encode/value_ref.rs`: `0c8ee2851e93d04add5bc503d3dac5b6b389d290c511f06a95732faa81319b28`
- `src/ext/de.rs`: `3481a7b845bcc8bb315af2b6fd86d768c6bd01d55af576e2e7cb96caf3ea9e56`
- `src/ext/mod.rs`: `6350370b422ebc9cc21c3e065efa2e7425b6caf355ac6e0c8061775a3a02a432`
- `src/ext/se.rs`: `7e375ab659a97ee6dd85cc66077f299af5a4cdb359c4c32b124fe9c7636d1344`
- `src/lib.rs`: `47826e29a6bc89eeb9d28062672cb4e62cfffd2953d83552589b6c4cf351ad09`

Only `src/lib.rs` differs from its listed upstream hash, by the accessor above.
Capacity is allocated backing, not wire length. Recursive value accounting,
field-lifetime custody and progress remain responsibilities of the caller.
