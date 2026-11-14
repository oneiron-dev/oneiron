# Third-party notices

This file lists the third-party works carried in this repository outside
`Cargo.lock` (vendored bytes, ported algorithms and rule tables). Each entry
names the project, its URL and upstream commit, its licence and copyright,
and the files of ours that carry it.

## 1. google/myanmar-tools

- Project: google/myanmar-tools
- URL: <https://github.com/google/myanmar-tools>
- Upstream commit: master `13e4af6aaac63849fa122374f93bc77a42674027` (model
  file last changed upstream in `7d7f7316bd5f`, 2020-07-20)
- Licence: Apache-2.0
- Copyright: Copyright 2017 Google LLC
- Our files:
  - `crates/oneiron-retrieval/vendor/myanmar-tools/zawgyiUnicodeModel.dat`
    (the model bytes; header in
    `crates/oneiron-retrieval/vendor/myanmar-tools/LICENSE.md`, full text in
    the repo root `LICENSE`)
  - `crates/oneiron-retrieval/src/analyzer/zawgyi.rs` (the detector port)
  - `crates/oneiron-retrieval/src/analyzer/zawgyi/tests.rs` (the 50
    compatibility vectors and the nine mmgov corpus lines in the zg2uni cases)

## 2. Rabbit-Converter/Rabbit

- Project: Rabbit-Converter/Rabbit
- URL: <https://github.com/Rabbit-Converter/Rabbit>
- Upstream commit: `081d464a91ab4dde14b799a54d1e89dde55b438e` (`rabbit.js`)
- Licence: WTFPL v2
- Copyright: none stated for `rabbit.js`; the licence text is Copyright (C)
  2004 Sam Hocevar
- Our files:
  - `crates/oneiron-retrieval/src/analyzer/zawgyi/rules.rs` (the zg2uni rule
    list, 118 rules in Rabbit's order; nine hand-coded)

WTFPL v2 (<http://www.wtfpl.net/>) asks for no notice; this entry records
where the rule list comes from.

## 3. UTN #61 reference normalizer khnormal

- Project: UTN #61 reference normalizer khnormal
- URL: <https://www.unicode.org/notes/tn61/> (UTN #61 v2, M. Hosken,
  2025-02-06)
- Upstream commit: UTN #61 v2 (2025-02-06)
- Licence: MIT
- Copyright: Copyright (c) 2021-2024, SIL Global
- Our files:
  - `crates/oneiron-retrieval/src/analyzer/khmer.rs` (the port)

The full standard MIT licence text:

```
MIT License

Copyright (c) 2021-2024, SIL Global

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
