# Forked dependencies

Two third-party crates carry changes of ours. Neither is vendored: each is a git dependency on a
fork under `github.com/oneiron-dev`, pinned by a full commit `rev`, never by a branch or a tag.
The fork branch holds upstream's release commit plus our commits, one per change, each message
saying what it changes and why. Upstream licence files and copyright notices stay untouched on
the fork.

| crate | upstream base | fork branch | pinned rev | licence |
|---|---|---|---|---|
| `sudachi` 0.6.11 | [WorksApplications/sudachi.rs](https://github.com/WorksApplications/sudachi.rs) tag `v0.6.11`, `90fd6068c80c2fc3b63e0dbab0e341475bad4d8f` | [`oneiron/v0.6.11`](https://github.com/oneiron-dev/sudachi.rs/tree/oneiron/v0.6.11) | `d8cba3609521805ebf35bfc2b71d8099a13befef` | Apache-2.0 |
| `formualizer-common`, `-parse` 3.1.2; `formualizer-eval`, `-macros`, `-workbook` 0.9.3 | [psu3d0/formualizer](https://github.com/psu3d0/formualizer) `362becffa029d8f77349c2c477fc39eff7fc52d5` (the commit the five crates.io archives name; tag `v0.9.3` is an annotated tag on it) | [`oneiron/parity`](https://github.com/oneiron-dev/formualizer/tree/oneiron/parity) | `b0695cb4c768139b650d27b49d825661442581bf` | MIT OR Apache-2.0 |

## Changing a forked crate

1. Commit the change on the fork branch (or on a new `oneiron/<upstream version>` branch cut from
   the next upstream release), with a message that names the change and the reason.
2. Push the branch and move the `rev` in the manifest to the new branch head.
3. Update the table above. `deny.toml` allows each fork URL in `[sources] allow-git`;
   `unknown-git` stays `deny`.
4. `python3 -m unittest discover -s scripts/ci -p 'test_vendor_pins.py'` and
   `cargo-deny --locked check` must pass.

## sudachi

`crates/oneiron/Cargo.toml`:

```toml
sudachi = { git = "https://github.com/oneiron-dev/sudachi.rs", rev = "d8cba3609521805ebf35bfc2b71d8099a13befef" }
```

Fork commits on `oneiron/v0.6.11`, over upstream `v0.6.11`:

- `baa525f0` names Android plugins `lib<name>.so`: `target_os = "android"` joins the
  Linux/FreeBSD branch of `make_system_specific_name` in `sudachi/src/plugin/loader.rs`. Without
  it the crate does not build for Android (E0425). The Android embedded workflow depends on it.
- `d8cba360` gives each bare `#[allow]` in `sudachi/src` and `sudachi/tests` a `reason` (24),
  removes two that no lint needed, and raises the workspace `rust-version` to 1.81, the release
  that stabilised lint reasons.

The earlier vendored snapshot also trimmed the CLI, fuzz and Python members from the root
workspace. The fork does not: Cargo reads the full upstream workspace as a git dependency, as
it did when main pinned upstream `v0.6.11` by tag.

## formualizer

A dependency on main since ONE-2608: `crates/oneiron-xlsx-formula` links the five crates, and
nothing of formualizer is vendored (the W7 copy under `crates/oneiron-xlsx-formula/vendor/`
never landed). Its manifest keeps the exact `=0.9.3` and `=3.1.2` requirements; the root
`Cargo.toml` patches all five to the fork by rev:

```toml
[patch.crates-io]
formualizer-common = { git = "https://github.com/oneiron-dev/formualizer", rev = "b0695cb4c768139b650d27b49d825661442581bf" }
formualizer-eval = { git = "https://github.com/oneiron-dev/formualizer", rev = "b0695cb4c768139b650d27b49d825661442581bf" }
formualizer-macros = { git = "https://github.com/oneiron-dev/formualizer", rev = "b0695cb4c768139b650d27b49d825661442581bf" }
formualizer-parse = { git = "https://github.com/oneiron-dev/formualizer", rev = "b0695cb4c768139b650d27b49d825661442581bf" }
formualizer-workbook = { git = "https://github.com/oneiron-dev/formualizer", rev = "b0695cb4c768139b650d27b49d825661442581bf" }
```

Fork branch `oneiron/parity` (0.9.3-oneiron.5), over `362becff`:

- `adc4743f` "Owned evaluator patch 0.9.3-oneiron.1" (the `oneiron/0.9.3` branch head):
  `formualizer-eval/src/interpreter.rs` propagates a typed error on either side of `&`, in both
  the AST and the arena paths, before text coercion. Literal text `"#N/A"` stays text.
  `crates/oneiron-xlsx-formula/tests/error_concat.rs` pins it.
- `adc4743f..57a7f6cb`, 68 commits (ONE-2700 part 1, the Excel parity loop, September 2026):
  Excel semantics in general, never a per-case answer, each kept only when neither score
  dropped. At `57a7f6cb` the fork matches Excel 16.112 on 809 of the 811 pinned cases (754 at
  `adc4743f`) and on 2,700 of the 2,951 SpreadsheetBench workbooks (753 at `adc4743f`, where
  xlsx admission refused most of the corpus: Office growth-hint ZIP extras, single-cell array
  and dynamic-array formulas). The two pinned misses are recording artifacts (DOLLAR carries
  the recording Mac's yen locale; a FILTER `#CALC!` cached as `#VALUE!` in the xlsx). Examples:
  UNIQUE by column, CELL("filename"), trimmed text criteria, ROUND on 15-digit decimals,
  HYPERLINK numeric friendly names, TREND/GROWTH result shapes.
- `57a7f6cb..e29e4ee7` (ONE-2700 part 3, the second parity loop, October 2026): 25 rounds of
  one cause each, every one kept only when neither score dropped and reviewed against Excel's
  documented behaviour. Owner rulings: where Excel for Windows and Excel for Mac differ the fork
  follows Windows, so CHAR and CODE read Windows-1252 and FILTERXML is implemented (XPath 1.0
  over quick-xml; WEBSERVICE and ENCODEURL stay `#NAME?`). `oneiron-xlsx-formula`'s
  `mac_parity.rs` masks only ENCODEURL and WEBSERVICE since 2026-10-02, so FILTERXML reaches
  the fork. The fresh-Excel truth gained 31
  workbooks (timed-out rows re-run on Excel 16.113.2; the six `.xlsm` files of task 395-17 and
  three FILTERXML answers recorded on Excel for Windows 16.0.20430). At `e29e4ee7` the fork
  matches 2,866 of the 2,982 SpreadsheetBench workbooks (2,835 of the original 2,951; all 31
  added rows match) and 808 of the 811 pinned cases against the Mac goldens. On 2026-10-02
  the goldens were re-recorded on Excel for Windows 16.0.20430 (en-US region; `scripts/office/win_excel_cases.py`
  on the Windows VM, pinned by `collect_excel_goldens.py` as before): 7 of 834 values changed
  (DOLLAR in dollars, TRIM with the real non-breaking space, VALUE of a currency string, and
  the four NOW/TODAY/RAND cases that never score). Against them the fork matches 809 of 811;
  the two misses are FILTER's `#CALC!`, which Excel caches as `#VALUE!` on both platforms, and
  VALUE("$1,000"), which is 1000 in the en-US region while the fork answers `#VALUE!`. Examples: implicit intersection in formulas
  saved without the array flag, OFFSET/INDIRECT arrays of references, SUBTOTAL skipping
  filter-hidden rows, Excel's calculate-always flags on save, `.xlsm`/`.xltx` admission,
  INDEX array and omitted-column forms, date text and two-digit years, unknown functions as
  `#NAME?` values.
- `e29e4ee7..158cee8f` (ONE-2700, the third parity loop, October 2026, against Excel for Windows): on
  2026-10-02 the whole SpreadsheetBench truth was re-recorded on Excel for Windows 16.0.20430
  (en-US region; numeric date text reads M/d/yyyy) and the scorer skips cells downstream of
  NOW/TODAY/RAND (#1280), so `e29e4ee7` starts at 2,883 of 2,967 and 809 of 811 pinned. 24
  rounds of one cause each, every one kept only when neither score dropped, plus follow-ups
  for each round's post-landing review (sol). At `158cee8f` the fork matches 2,960 of the 2,967
  SpreadsheetBench workbooks and all 811 pinned goldens. Excel saves `#CALC!`, `#SPILL!` and the
  other errors newer than the file format as a legacy `#VALUE!` cell plus an `xl/richData` record;
  since 2026-10-03 the goldens reader (`cached_cells` in `scripts/office/run_excel_oracle.py`,
  copied into `win_excel_cases.py`) resolves that record, so FILTER's `#CALC!` reads as `#CALC!`
  (the recorded workbooks are unchanged; `scripts/tests/fixtures/excel-windows-spill-error.xlsx`
  pins `#SPILL!`). The seven bench misses are four external-link cells and the three answers of
  task 42110, where Excel turns a row number such as 1.9999999985 into row 2 inside INDEX. A probe
  on Excel for Windows 16.0.20430 (2026-10-03) pinned the rule: INDEX (row and column), VLOOKUP and
  HLOOKUP index, ADDRESS row and DATE month read an integer argument as floor(x + 2^-22): 2 - 2.38E-7
  is row 2 and 2 - 2.39E-7 is row 1, the same absolute window at 1999 and at 100000; OFFSET, CHOOSE,
  SMALL, MID and REPT truncate without the snap and LARGE rounds. The fork still truncated INDEX's
  row_num at `158cee8f`; the fourth loop fixed it. Examples: date and time text in
  number arguments, criteria and en-US currency text (VALUE("$1,000") = 1000), numbers as text
  with 15 significant digits and criteria compared to 15 digits, approximate lookups over
  unsorted data, negative zero, AGGREGATE array k and FREQUENCY bins, INDEX area_num and
  structured references, rich-value error caches (#SPILL!/#CALC!), circular references keeping
  their last value with iteration off, and Excel's zero snap of a final + or - and of SUM.
- `158cee8f..b0695cb4` (ONE-2700, the fourth parity loop, rounds 1 and 2, October 2026): how Excel for
  Windows 16.0.20430 reads a whole-number argument given a fraction, from six probes on the
  Windows VM (2026-10-03; `ops/excel-int-coercion-probe-20261003.md` in the calc workspace, 79
  cases in probes 4-6). One reader, floor(x + 2^-22) with negatives floored, serves INDEX row,
  column and area, VLOOKUP/HLOOKUP index, ADDRESS row, column and abs_num, DATE year, month and
  day, SEQUENCE rows and columns and LEFT/RIGHT num_chars (`INDEX({10;20;30},-0.5)` is `#VALUE!`,
  `DATE(2026,-0.5,1)` is 1 November 2025); ROUND's digits snap the same way but otherwise go
  toward zero (`ROUND(1234.5,-0.5)` is 1235); LARGE and AGGREGATE 14 take the ceiling of k
  after checking k as given; OFFSET, CHOOSE, SMALL, AGGREGATE 15, MID, REPT, ROUNDUP and
  ROUNDDOWN truncate without the window. The dependency plan and the result-extent code read
  INDEX's constant selectors the same way. Cycle detection now defaults to runtime detection:
  a formula is circular only when it reads its own cell, so `=INDEX(F:F,2-1E-7)+1` in F1 is 1
  while `=INDEX(F:F,1)+1` stays `#CIRC!` (static detection remains an opt-in). At `b0695cb4`
  the fork matches 2,963 of the 2,967 SpreadsheetBench workbooks (task 42110's three answers
  now match; the four misses left are external-link cells) and all 811 pinned goldens.

`deny.toml` allows `https://github.com/oneiron-dev/formualizer` in `allow-git`, and CC0-1.0
(owner ruling 2026-09-26) for `tiny-keccak` 2.0.2, which `formualizer-eval` pulls in at build
time through `arrow` → `ahash` → `const-random`. The engine stamps recalculated versions
`oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.5`.

## Licences and attribution

No source of either project is copied into this repository; the upstream licence texts ship in
the forks and in every Cargo checkout of them.

- sudachi.rs: Apache License 2.0, `LICENSE` at the repository root. Copyright (c) 2021 Works
  Applications Co., Ltd.
- formualizer: MIT OR Apache-2.0, `LICENSE-MIT` and `LICENSE-APACHE` at the repository root.
  Copyright (c) 2025-2026 Frank Colson and Formualizer contributors.
