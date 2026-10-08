# Forked dependencies

Two third-party crates carry changes of ours. Neither is vendored: each is a git dependency on a
fork under `github.com/oneiron-dev`, pinned by a full commit `rev`, never by a branch or a tag.
The fork branch holds upstream's release commit plus our commits, one per change, each message
saying what it changes and why. Upstream licence files and copyright notices stay untouched on
the fork.

| crate | upstream base | fork branch | pinned rev | licence |
|---|---|---|---|---|
| `sudachi` 0.6.11 | [WorksApplications/sudachi.rs](https://github.com/WorksApplications/sudachi.rs) tag `v0.6.11`, `90fd6068c80c2fc3b63e0dbab0e341475bad4d8f` | [`oneiron/v0.6.11`](https://github.com/oneiron-dev/sudachi.rs/tree/oneiron/v0.6.11) | `d8cba3609521805ebf35bfc2b71d8099a13befef` | Apache-2.0 |
| `formualizer-common`, `-parse` 3.1.2; `formualizer-eval`, `-macros`, `-workbook` 0.9.3 | [psu3d0/formualizer](https://github.com/psu3d0/formualizer) `362becffa029d8f77349c2c477fc39eff7fc52d5` (the commit the five crates.io archives name; tag `v0.9.3` is an annotated tag on it) | [`oneiron/parity`](https://github.com/oneiron-dev/formualizer/tree/oneiron/parity) | `953fbbb1138ad2ccda9a188e67d2a3cf49570143` | MIT OR Apache-2.0 |

## Changing a forked crate

1. Commit the change on the fork branch (or on a new `oneiron/<upstream version>` branch cut from
   the next upstream release), with a message that names the change and the reason.
2. Push the branch and move the `rev` in the manifest to the new branch head.
3. Update the table above. `deny.toml` allows each fork URL in `[sources] allow-git`;
   `unknown-git` stays `deny`.
4. `python3 -m unittest discover -s scripts/ci -p 'test_vendor_pins.py'` and
   `cargo-deny --locked check` must pass.

## sudachi

`crates/oneiron-retrieval/Cargo.toml` (the multilingual analyzer's crate):

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
formualizer-common = { git = "https://github.com/oneiron-dev/formualizer", rev = "953fbbb1138ad2ccda9a188e67d2a3cf49570143" }
formualizer-eval = { git = "https://github.com/oneiron-dev/formualizer", rev = "953fbbb1138ad2ccda9a188e67d2a3cf49570143" }
formualizer-macros = { git = "https://github.com/oneiron-dev/formualizer", rev = "953fbbb1138ad2ccda9a188e67d2a3cf49570143" }
formualizer-parse = { git = "https://github.com/oneiron-dev/formualizer", rev = "953fbbb1138ad2ccda9a188e67d2a3cf49570143" }
formualizer-workbook = { git = "https://github.com/oneiron-dev/formualizer", rev = "953fbbb1138ad2ccda9a188e67d2a3cf49570143" }
```

Fork branch `oneiron/parity` (0.9.3-oneiron.11), over `362becff`:

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
- `b0695cb4..d598ad05` (ONE-2700, the fourth parity loop, round 3, October 2026): what two more
  probes on the Windows VM recorded (2026-10-04, 42 cases in probes 7-8 of the same note).
  ROUND's digits snap on their magnitude and then go toward zero, sign(x) * trunc(abs(x) +
  2^-22): `ROUND(1234.5678,-1.9999999)` is 1200, where round 2 gave 1230. VLOOKUP and HLOOKUP
  look up before they check the index: a miss is `#N/A` whatever the index, and on a match an
  index below 1 is `#VALUE!` and one past the table `#REF!`. ADDRESS reads its row, column and
  abs_num as number arguments (`TRUE` is 1, a blank cell 0, numeric text converts) and a1 as a
  logical (any non-zero number is TRUE, a blank cell FALSE, numeric text `#VALUE!`); an empty
  abs_num or a1 argument (`ADDRESS(1,1,)`, `ADDRESS(1,1,,)`) is the default, and a date is its
  serial in the workbook's date system. A negative INDEX position is `#VALUE!` in the reference
  form as well, as the fork already did. The scores at `d598ad05` are unchanged: 2,963 of the
  2,967 SpreadsheetBench workbooks and all 811 pinned goldens.
- `d598ad05..c9d441cd` (ONE-2700, the fourth parity loop, round 3 follow-up, October 2026): an
  18-case probe on the Windows VM (2026-10-06, probe 9 of the same note) confirmed round 3's
  inferred readings (`FALSE` as an ADDRESS row, column or abs_num is `#VALUE!`, a date as a1 is
  TRUE, a text VLOOKUP or HLOOKUP index is `#VALUE!` even when the lookup misses) and found one
  difference: ADDRESS's sheet_text from a blank cell is the empty name, so
  `ADDRESS(1,1,1,TRUE,A1)` with A1 blank is `!$A$1`, while an empty argument is still no sheet.
  The scores at `c9d441cd` are unchanged: 2,963 of 2,967 and 811/811.
- `c9d441cd..63e2ec69` (ONE-2700, the fifth parity loop, rounds 1 and 2, October 2026): Excel's
  compatibility names for the distributions, with their legacy signatures. Twenty were unregistered
  (`#NAME?`) and are registered now: BETADIST, BETAINV, BINOMDIST, CHIDIST, CHIINV, EXPONDIST,
  FDIST, FINV, GAMMADIST, HYPGEOMDIST, LOGINV, LOGNORMDIST, NEGBINOMDIST, NORMDIST, NORMINV,
  NORMSDIST, NORMSINV, POISSON, TDIST and WEIBULL (NORMSDIST(z) is NORM.S.DIST(z,TRUE),
  LOGNORMDIST is cumulative, CHIDIST and FDIST are right-tailed, TDIST takes 1 or 2 tails). Six
  existing aliases followed a wrong target and now match Excel: CHITEST, CRITBINOM, GAMMAINV,
  ZTEST, TINV and CONFIDENCE. A probe on the Windows VM (2026-10-06, 445 scored cases,
  `ops/excel-legacy-functions-probe-20261006.md` in the calc workspace) agrees on 442 rows (84 at
  `c9d441cd`); the other 3 are Excel's own precision loss at 1E10 to 1E11 degrees of freedom, and
  the tests assert the true quantile there. The scores at `2bdd595d` are unchanged: 2,963 of 2,967
  and 811/811. Round 2 (`2bdd595d..63e2ec69`) follows a review of round 1 and two more probes
  (probes 6 and 7 of the same note: 224 scored rows, 105 agreeing at `2bdd595d`, 204 now). Every
  current distribution name and alias lifts its single values over arrays
  (`SUM(T.DIST({0,1},10,TRUE))` is 1.3295534338489701; it read the first element only). Small x
  far below the centre of a large gamma or beta shape keeps its precision
  (`GAMMA.DIST(1E-20,10,1,TRUE)` is 2.7557319223985218E-207, was 0), and BETA.DIST's density
  divides before it underflows (`BETA.DIST(1E-200,2,3,FALSE)` is 1.2E-199). NORM.S.INV refines its
  far tail (`NORM.S.INV(2.225074E-308)` is -37.519379345450844), and a distribution argument below
  the smallest number is 0. NORMSDIST, NORMSINV, NORM.S.INV, PHI and GAUSS take exactly one
  argument (`#VALUE!` for more). The T and F far tails overflow and underflow where Excel's do
  (`#NUM!`, 0 or `#DIV/0!`), and T.INV solves its far tail (`T.INV(1E-160,1)` is
  -3.1830988618379068E159, was `#NUM!`). BINOM.INV and CRITBINOM bisect on BINOM.DIST, the
  smallest k whose cumulative reaches alpha: 63 of Excel's 81 boundary rows agree, and the other
  18 differ in the last bit of the cumulative. The scores at `63e2ec69` are unchanged: 2,963 of
  2,967 and 811/811.
- `63e2ec69..cf3d5f5d` (stage 2, linked workbooks, October 2026): references into a closed linked
  workbook (`[1]Sheet!A1`) as Excel for Windows 16.0.20430 reads them from the values the link part
  saves, from three probes on the Windows VM (2026-10-06, 192 cases,
  `ops/excel-extlinks-probe-20261006.md` in the calc workspace; 173 agree, 94 at `63e2ec69`). On a
  sheet Excel could not read at its last refresh (`refreshError="1"`), or one the link saves no
  values for, every cell not saved is `#REF!`, element by element in ranges (`COUNTA` counts them,
  the lookups skip them, `SUM` returns the error); a saved blank stays blank, and an open range
  there keeps one `#REF!` row past the last saved cell. ROW, COLUMN, ROWS and COLUMNS give the
  position a linked reference is written with (`ROW([1]DATI!$K$2:$K$999)` is `{2;...;999}`, it
  read `{1;...;998}`); INDEX over a linked range selects a reference into the linked sheet; an
  ordinary (legacy) formula intersects a linked range with its own cell; ISREF of a linked
  reference is TRUE and ISFORMULA, FORMULATEXT, SHEET and SHEETS of one are `#N/A`; IFERROR and
  IFNA catch the error of a one-cell range. At `cf3d5f5d` the fork matches all 2,967
  SpreadsheetBench workbooks (the four misses were linked workbooks: 55965 twice, 59932 twice; 0 of
  1,193,688 scored cells differ) and all 811 pinned goldens.
- `cf3d5f5d..91599813` (stage 2, October 2026): the other stage-2 lanes landed in between, and this
  pin carries them: `88f30164` (round 6 finance: the 23 financial functions the fork read as
  `#NAME?`, on one coupon and day-count module, and PRICE, YIELD, ACCRINT, ACCRINTM, DDB and the
  T-bill functions fixed against Excel probes; `ops/excel-finance-probe-20261006.md`) and `c67530db`
  (round 6 functions: MDETERM and MINVERSE, MUNIT, PERMUTATIONA, PROB, PERCENTOF, AREAS, ISOMITTED
  with optional LAMBDA parameters, ENCODEURL, BAHTTEXT, TRIMRANGE and the trim operators, the
  REGEX functions on a PCRE2-compatible matcher (`regex-syntax` for its Unicode tables), and
  FORECAST.ETS only where its fit is exact). `91599813` is the linked-workbook review: a reversed
  linked range reads in order (`INDEX([1]Ok!A5:A1,1)` is 1, `ROWS` 5) and a large one keeps its
  `#REF!` past the saved cells, and a saved value in a CDATA section is its text (probes 4 and 5 of
  the linked-workbook note). At `91599813` the fork matches all 2,967 SpreadsheetBench workbooks
  and all 811 pinned goldens.
- `91599813..5b520963` (ONE-2700, stage 2 of the LibreOffice retirement, round 6, October 2026):
  each kept only with 811/811 pinned and nothing lost on SpreadsheetBench. Probe 4 of the finance
  note as tests (`5149f170`, AMORLINC and AMORDEGRC bought on the first period's end). Caller
  context (`d4959b40`, `5b520963`), from eight probes on the Windows VM (2026-10-06, 466 scored
  rows, `ops/excel-context-probe-20261006.md` in the calc workspace, 451 agree): INDIRECT reads R1C1
  text with `a1` FALSE (absolute, relative to the formula's cell and wrapping at the grid's edge,
  whole rows and columns, ranges, sheets), and A1 and R1C1 text take the spaces Excel accepts
  (trailing, after the sheet's `!`, around the `:` between two cells). OFFSET's far edge is
  trunc(size) - 1 from the moved corner for a positive size and + 1 for a negative one
  (`OFFSET(B2,0,0,-2,-2)` is A1:B2). RANDBETWEEN and RANDARRAY read and check their arguments as
  Excel does (`RANDBETWEEN(1.2,1.8)` is 2; a logical bound is `#VALUE!`; `RANDARRAY(0)` is
  `#CALC!`), every random call in a cell draws its own value (`RAND()=RAND()` is FALSE), and NOW
  keeps hundredths of a second. TEXT reads `!` as a character of its own, not an escape
  (`TEXT(203,"!r0c00")` is `!r2c03`), and shows a number under a text section as General. At
  `5b520963` the fork matches 2,967 of the 2,967 SpreadsheetBench workbooks and all 811 pinned
  goldens.
- `67f19c08` (review of oneiron #1295, 2026-10-07): a defined name evaluates for the formula
  that uses it, as Excel evaluates it. Relative R1C1 text, ROW() and `#This Row` in a name read
  the calling cell (`Prev = INDIRECT("RC[-1]",FALSE)` in B2 reads A2; the name was read from A1,
  whose previous column wraps to XFD1). A random call in a name is one more draw of the calling
  formula: resolving a name no longer restarts the cell's draws
  (`RAND()+ROW(Anchor)-RAND()` was exactly 1), and a name's own graph vertex draws apart from
  every cell, so the same seed gives the same caches however the cells are scheduled. INDIRECT
  text that names a workbook (`'[Book.xlsx]Sheet1'!A1`, `Book.xlsx!Total` where no sheet has
  that name) gives the closed workbook's `#REF!` and is recorded
  (`Engine::text_named_workbook`); the cache writer then refuses the workbook ("INDIRECT text
  that names a workbook"), since Excel reads such text from the open workbook of that name,
  this one included under its saved name. Still 2,967 of 2,967 and 811/811.
- `67f19c08..562f4863` (re-check of oneiron #1295, 2026-10-07): what a defined name reads, the
  formula that uses it reads. Dependency and circular-reference discovery evaluate a name for its
  calling formula, through the context that records that formula's reads:
  `Loop = INDIRECT("RC",FALSE)+1` used in B2 is circular like `=INDIRECT("RC",FALSE)+1` written in
  B2 (with iteration off B2 keeps its last value; it cached 1), a formula reading a cell through a name
  calculates after that cell, and a formula using a name whose formula holds INDIRECT or OFFSET,
  itself or through another name, is dynamic like one holding the call. Resolving a name as a
  reference only to see whether it is one no longer spends the calling formula's random draws
  when the result is dropped, so `Pick+0` with `Pick = OFFSET(Sheet1!$C$1,RANDBETWEEN(0,1),0)`
  draws what `OFFSET(Sheet1!$C$1,RANDBETWEEN(0,1),0)+0` draws (20 for seed 7; it gave 10). Still
  2,967 of 2,967 and 811/811.
- `562f4863..953fbbb1` (stage 2, upstream commits, 2026-10-08): six commits picked from upstream's
  `main` (`a1425480`) with `git cherry-pick -x`, each kept only on Excel's values or a measured
  benefit. Parity, against Excel for Windows 16.0.20430 (`ops/excel-upstream-picks-probe-20261008.md`
  in the calc workspace, 201 cases; the fork before differed on 119): `2475598b` makes `^` group
  left to right (`=2^3^2` is 64; it gave 512); `a3a5d796` refuses a ragged array literal
  (`={1,2;3}`), as Excel refuses it as a formula and as a defined name; `c2c724d7` makes XLOOKUP
  compare the lengths its lookup and return arrays declare before it searches, whatever
  `if_not_found` says (`XLOOKUP(2,A1:A6,B1:B5)` is `#VALUE!` with A6 blank, and so is `A:A`
  against `B1:B10`, through LET, LAMBDA, OFFSET and defined names alike). Where Excel disagrees
  with `c2c724d7` the fork follows Excel (`f5080f0b`): a single-cell lookup array pairs with a
  one-row or a one-column return array (`XLOOKUP(1,A1,B1:B2)` spills {10;20}; upstream gave
  `#VALUE!`), and an error XLOOKUP gives is the result of a range operator built on it
  (`SUM(XLOOKUP(2,A1:A3,B1:B4):B5)` is `#VALUE!`, not `#REF!`). A review of the pin added a third
  probe (48 cases) and `faf71fdc`: a reference a function returns keeps the extent it declares
  (`XLOOKUP(2,INDIRECT("A:A"),B:B)` is 20, and `#VALUE!` against `B1:B5`), an approximate match keeps
  a single cell's pairing (`SUM(XLOOKUP(1,A1,B1:B2,,-1))` is 30), and the range operator over a
  function that gives a value is that value's error or `#VALUE!` (`SUM(IF(TRUE,5):B5)`; it gave
  `#REF!`), resolving the function once (`20ccd28e` and `25bce03f`, re-reviews: a branch IF selects,
  or an argument INDEX read before declining, is not evaluated again for the value), a LET-bound
  LAMBDA's call included (`953fbbb1`). Performance, release builds against `562f4863` on 20 large SpreadsheetBench workbooks
  and filled-column stress cases (interleaved fresh-process runs timing load, first calculation,
  an edit's recalculation and `recalculate_xlsx_bytes`, with peak memory): `e3ca8218` provisions the Arrow ingest lane
  builders lazily (peak memory 15-42% lower on four of the twenty workbooks) and `6669bbcc`
  finishes CoordHasher with a full avalanche (a filled column of 50,000 or 200,000 formulas loads
  17-19% faster; first calculation 37% faster on one workbook, `recalculate_xlsx_bytes` 36% faster
  on another). `b65931ef` (lock-free repeated builtin loading) was picked and reverted
  (`08ae49a2`): no measured benefit, in a fresh process or over five recalculations in one.
  Still 2,967 of 2,967 and 811/811.

`deny.toml` allows `https://github.com/oneiron-dev/formualizer` in `allow-git`, and CC0-1.0
(owner ruling 2026-09-26) for `tiny-keccak` 2.0.2, which `formualizer-eval` pulls in at build
time through `arrow` → `ahash` → `const-random`. The engine stamps recalculated versions
`oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.11`.

## Licences and attribution

No source of either project is copied into this repository; the upstream licence texts ship in
the forks and in every Cargo checkout of them.

- sudachi.rs: Apache License 2.0, `LICENSE` at the repository root. Copyright (c) 2021 Works
  Applications Co., Ltd.
- formualizer: MIT OR Apache-2.0, `LICENSE-MIT` and `LICENSE-APACHE` at the repository root.
  Copyright (c) 2025-2026 Frank Colson and Formualizer contributors.
