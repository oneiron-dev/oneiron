//! Rabbit zg2uni rules in order (Rabbit-Converter/Rabbit `rabbit.js`, commit
//! 081d464a91ab, WTFPL v2).
//!
//! Order matters: each step takes the current text and gives the next, exactly
//! as Rabbit's global replaces do. Nine rules are hand-coded: 0 uses a
//! backreference (`\1`) and 60, 64, 65, 66, 68, 79 and 117 use lookaround
//! (`(?=` / `(?!`), which the `regex` crate lacks; 69 ends in `$`, written out
//! so its reading is explicit (the text's end only, as in JS, not also before a
//! final line break as in Python). 65 is anchored with `^` to the text's start.
//! Each hand-coded scan moves left to right as a JS global replace does: on a
//! match it emits the replacement and continues after the consumed part, never
//! after a lookahead char; on no match it copies one char.

use std::borrow::Cow;
use std::sync::LazyLock;

/// One Rabbit rule: a regex + replacement, or a hand-coded scan for the
/// patterns the `regex` crate cannot express.
enum Rule {
    Pattern(&'static str, &'static str),
    Custom(fn(&str) -> Option<String>),
}

const RULES: [Rule; 118] = [
    // 0
    Rule::Custom(collapse_repeated_marks),
    // 1
    Rule::Pattern("\u{200B}", ""),
    // 2
    Rule::Pattern("\u{103D}\u{103C}", "\u{108A}"),
    // 3
    Rule::Pattern("(\u{103D}|\u{1087})", "\u{103E}"),
    // 4
    Rule::Pattern("\u{103C}", "\u{103D}"),
    // 5
    Rule::Pattern(
        "(\u{103B}|\u{107E}|\u{107F}|\u{1080}|\u{1081}|\u{1082}|\u{1083}|\u{1084})",
        "\u{103C}",
    ),
    // 6
    Rule::Pattern("(\u{103A}|\u{107D})", "\u{103B}"),
    // 7
    Rule::Pattern("\u{1039}", "\u{103A}"),
    // 8
    Rule::Pattern("(\u{1066}|\u{1067})", "\u{1039}\u{1006}"),
    // 9
    Rule::Pattern("\u{106A}", "\u{1009}"),
    // 10
    Rule::Pattern("\u{106B}", "\u{100A}"),
    // 11
    Rule::Pattern("\u{106C}", "\u{1039}\u{100B}"),
    // 12
    Rule::Pattern("\u{106D}", "\u{1039}\u{100C}"),
    // 13
    Rule::Pattern("\u{106E}", "\u{100D}\u{1039}\u{100D}"),
    // 14
    Rule::Pattern("\u{106F}", "\u{100D}\u{1039}\u{100E}"),
    // 15
    Rule::Pattern("\u{1070}", "\u{1039}\u{100F}"),
    // 16
    Rule::Pattern("(\u{1071}|\u{1072})", "\u{1039}\u{1010}"),
    // 17
    Rule::Pattern("\u{1060}", "\u{1039}\u{1000}"),
    // 18
    Rule::Pattern("\u{1061}", "\u{1039}\u{1001}"),
    // 19
    Rule::Pattern("\u{1062}", "\u{1039}\u{1002}"),
    // 20
    Rule::Pattern("\u{1063}", "\u{1039}\u{1003}"),
    // 21
    Rule::Pattern("\u{1065}", "\u{1039}\u{1005}"),
    // 22
    Rule::Pattern("\u{1068}", "\u{1039}\u{1007}"),
    // 23
    Rule::Pattern("\u{1069}", "\u{1039}\u{1008}"),
    // 24
    Rule::Pattern("(\u{1073}|\u{1074})", "\u{1039}\u{1011}"),
    // 25
    Rule::Pattern("\u{1075}", "\u{1039}\u{1012}"),
    // 26
    Rule::Pattern("\u{1076}", "\u{1039}\u{1013}"),
    // 27
    Rule::Pattern("\u{1077}", "\u{1039}\u{1014}"),
    // 28
    Rule::Pattern("\u{1078}", "\u{1039}\u{1015}"),
    // 29
    Rule::Pattern("\u{1079}", "\u{1039}\u{1016}"),
    // 30
    Rule::Pattern("\u{107A}", "\u{1039}\u{1017}"),
    // 31
    Rule::Pattern("\u{107C}", "\u{1039}\u{1019}"),
    // 32
    Rule::Pattern("\u{1085}", "\u{1039}\u{101C}"),
    // 33
    Rule::Pattern("\u{1033}", "\u{102F}"),
    // 34
    Rule::Pattern("\u{1034}", "\u{1030}"),
    // 35
    Rule::Pattern("\u{103F}", "\u{1030}"),
    // 36
    Rule::Pattern("\u{1086}", "\u{103F}"),
    // 37
    Rule::Pattern("\u{1036}\u{1088}", "\u{1088}\u{1036}"),
    // 38
    Rule::Pattern("\u{1088}", "\u{103E}\u{102F}"),
    // 39
    Rule::Pattern("\u{1089}", "\u{103E}\u{1030}"),
    // 40
    Rule::Pattern("\u{108A}", "\u{103D}\u{103E}"),
    // 41
    Rule::Pattern("\u{103B}\u{1064}", "\u{1064}\u{103B}"),
    // 42
    Rule::Pattern(
        "\u{103C}([\u{1000}-\u{1021}])([\u{1064}\u{108B}\u{108D}])",
        "${1}\u{103C}${2}",
    ),
    // 43
    Rule::Pattern(
        "(\u{1031})?([\u{1000}-\u{1021}\u{1040}-\u{1049}])(\u{103C})?\u{1064}",
        "\u{1004}\u{103A}\u{1039}${1}${2}${3}",
    ),
    // 44
    Rule::Pattern(
        "(\u{1031})?([\u{1000}-\u{1021}])(\u{103B}|\u{103C})?\u{108B}",
        "\u{1004}\u{103A}\u{1039}${1}${2}${3}\u{102D}",
    ),
    // 45
    Rule::Pattern(
        "(\u{1031})?([\u{1000}-\u{1021}])(\u{103B})?\u{108C}",
        "\u{1004}\u{103A}\u{1039}${1}${2}${3}\u{102E}",
    ),
    // 46
    Rule::Pattern(
        "(\u{1031})?([\u{1000}-\u{1021}])([\u{103B}\u{103C}])?\u{108D}",
        "\u{1004}\u{103A}\u{1039}${1}${2}${3}\u{1036}",
    ),
    // 47
    Rule::Pattern("\u{108E}", "\u{102D}\u{1036}"),
    // 48
    Rule::Pattern("\u{108F}", "\u{1014}"),
    // 49
    Rule::Pattern("\u{1090}", "\u{101B}"),
    // 50
    Rule::Pattern("\u{1091}", "\u{100F}\u{1039}\u{100D}"),
    // 51
    Rule::Pattern("\u{1092}", "\u{100B}\u{1039}\u{100C}"),
    // 52
    Rule::Pattern(
        "\u{1019}\u{102C}(\u{107B}|\u{1093})",
        "\u{1019}\u{1039}\u{1018}\u{102C}",
    ),
    // 53
    Rule::Pattern("(\u{107B}|\u{1093})", "\u{1039}\u{1018}"),
    // 54
    Rule::Pattern("(\u{1094}|\u{1095})", "\u{1037}"),
    // 55
    Rule::Pattern(
        "([\u{1000}-\u{1021}])\u{1037}\u{1032}",
        "${1}\u{1032}\u{1037}",
    ),
    // 56
    Rule::Pattern("\u{1096}", "\u{1039}\u{1010}\u{103D}"),
    // 57
    Rule::Pattern("\u{1097}", "\u{100B}\u{1039}\u{100B}"),
    // 58
    Rule::Pattern(
        "\u{103C}([\u{1000}-\u{1021}])([\u{1000}-\u{1021}])?",
        "${1}\u{103C}${2}",
    ),
    // 59
    Rule::Pattern(
        "([\u{1000}-\u{1021}])\u{103C}\u{103A}",
        "\u{103C}${1}\u{103A}",
    ),
    // 60
    Rule::Custom(seven_before_vowel_is_ra),
    // 61
    Rule::Pattern("\u{1031}\u{1047}", "\u{1031}\u{101B}"),
    // 62
    Rule::Pattern(
        "\u{1040}(\u{102E}|\u{102F}|\u{102D}\u{102F}|\u{1030}|\u{1036}|\u{103D}|\u{103E})",
        "\u{101D}${1}",
    ),
    // 63
    Rule::Pattern(
        "([^\u{1040}\u{1041}\u{1042}\u{1043}\u{1044}\u{1045}\u{1046}\u{1047}\u{1048}\u{1049}])\u{1040}\u{102B}",
        "${1}\u{101D}\u{102B}",
    ),
    // 64
    Rule::Custom(zero_after_digit_before_aa_is_wa),
    // 65
    Rule::Custom(leading_zero_before_aa_is_wa),
    // 66
    Rule::Custom(zero_before_i_is_wa),
    // 67
    Rule::Pattern(
        "([^\u{1040}-\u{1049}])\u{1040}([^\u{1040}-\u{1049} ]|[\u{104A}\u{104B}])",
        "${1}\u{101D}${2}",
    ),
    // 68
    Rule::Custom(zero_before_line_break_is_wa),
    // 69
    Rule::Custom(final_zero_is_wa),
    // 70
    Rule::Pattern(
        "\u{1031}([\u{1000}-\u{1021}\u{103F}])(\u{103E})?(\u{103B})?",
        "${1}${2}${3}\u{1031}",
    ),
    // 71
    Rule::Pattern(
        "([\u{1000}-\u{1021}])\u{1031}([\u{103B}\u{103C}\u{103D}\u{103E}]+)",
        "${1}${2}\u{1031}",
    ),
    // 72
    Rule::Pattern("\u{1032}\u{103D}", "\u{103D}\u{1032}"),
    // 73
    Rule::Pattern("([\u{102D}\u{102E}])\u{103B}", "\u{103B}${1}"),
    // 74
    Rule::Pattern("\u{103D}\u{103B}", "\u{103B}\u{103D}"),
    // 75
    Rule::Pattern("\u{103A}\u{1037}", "\u{1037}\u{103A}"),
    // 76
    Rule::Pattern(
        "\u{102F}(\u{102D}|\u{102E}|\u{1036}|\u{1037})\u{102F}",
        "\u{102F}${1}",
    ),
    // 77
    Rule::Pattern("(\u{102F}|\u{1030})(\u{102D}|\u{102E})", "${2}${1}"),
    // 78
    Rule::Pattern("(\u{103E})(\u{103B}|\u{103C})", "${2}${1}"),
    // 79
    Rule::Custom(u_before_asat_or_aa_is_nya),
    // 80
    Rule::Pattern("\u{1025}\u{102E}", "\u{1026}"),
    // 81
    Rule::Pattern("\u{1005}\u{103B}", "\u{1008}"),
    // 82
    Rule::Pattern("\u{1036}(\u{102F}|\u{1030})", "${1}\u{1036}"),
    // 83
    Rule::Pattern("\u{1031}\u{1037}\u{103E}", "\u{103E}\u{1031}\u{1037}"),
    // 84
    Rule::Pattern("\u{1031}\u{103E}\u{102C}", "\u{103E}\u{1031}\u{102C}"),
    // 85
    Rule::Pattern("\u{105A}", "\u{102B}\u{103A}"),
    // 86
    Rule::Pattern("\u{1031}\u{103B}\u{103E}", "\u{103B}\u{103E}\u{1031}"),
    // 87
    Rule::Pattern("(\u{102D}|\u{102E})(\u{103D}|\u{103E})", "${2}${1}"),
    // 88
    Rule::Pattern(
        "\u{102C}\u{1039}([\u{1000}-\u{1021}])",
        "\u{1039}${1}\u{102C}",
    ),
    // 89
    Rule::Pattern(
        "\u{1039}\u{103C}\u{103A}\u{1039}([\u{1000}-\u{1021}])",
        "\u{103A}\u{1039}${1}\u{103C}",
    ),
    // 90
    Rule::Pattern(
        "\u{103C}\u{1039}([\u{1000}-\u{1021}])",
        "\u{1039}${1}\u{103C}",
    ),
    // 91
    Rule::Pattern(
        "\u{1036}\u{1039}([\u{1000}-\u{1021}])",
        "\u{1039}${1}\u{1036}",
    ),
    // 92
    Rule::Pattern("\u{104E}", "\u{104E}\u{1004}\u{103A}\u{1038}"),
    // 93
    Rule::Pattern("\u{1040}(\u{102B}|\u{102C}|\u{1036})", "\u{101D}${1}"),
    // 94
    Rule::Pattern("\u{1025}\u{1039}", "\u{1009}\u{1039}"),
    // 95
    Rule::Pattern(
        "([\u{1000}-\u{1021}])\u{103C}\u{1031}\u{103D}",
        "${1}\u{103C}\u{103D}\u{1031}",
    ),
    // 96
    Rule::Pattern(
        "([\u{1000}-\u{1021}])\u{103B}\u{1031}\u{103D}(\u{103E})?",
        "${1}\u{103B}\u{103D}${2}\u{1031}",
    ),
    // 97
    Rule::Pattern(
        "([\u{1000}-\u{1021}])\u{103D}\u{1031}\u{103B}",
        "${1}\u{103B}\u{103D}\u{1031}",
    ),
    // 98
    Rule::Pattern(
        "([\u{1000}-\u{1021}])\u{1031}(\u{1039}[\u{1000}-\u{1021}]\u{103D}?)",
        "${1}${2}\u{1031}",
    ),
    // 99
    Rule::Pattern("\u{1038}\u{103A}", "\u{103A}\u{1038}"),
    // 100
    Rule::Pattern("\u{102D}\u{103A}|\u{103A}\u{102D}", "\u{102D}"),
    // 101
    Rule::Pattern("\u{102D}\u{102F}\u{103A}", "\u{102D}\u{102F}"),
    // 102
    Rule::Pattern(" \u{1037}", "\u{1037}"),
    // 103
    Rule::Pattern("\u{1037}\u{1036}", "\u{1036}\u{1037}"),
    // 104
    Rule::Pattern("[\u{102D}]+", "\u{102D}"),
    // 105
    Rule::Pattern("[\u{103A}]+", "\u{103A}"),
    // 106
    Rule::Pattern("[\u{103D}]+", "\u{103D}"),
    // 107
    Rule::Pattern("[\u{1037}]+", "\u{1037}"),
    // 108
    Rule::Pattern("[\u{102E}]+", "\u{102E}"),
    // 109
    Rule::Pattern("\u{102D}\u{102E}|\u{102E}\u{102D}", "\u{102E}"),
    // 110
    Rule::Pattern("\u{102F}\u{102D}", "\u{102D}\u{102F}"),
    // 111
    Rule::Pattern("\u{1037}\u{1037}", "\u{1037}"),
    // 112
    Rule::Pattern("\u{1032}\u{1032}", "\u{1032}"),
    // 113
    Rule::Pattern(
        "\u{1044}\u{1004}\u{103A}\u{1038}",
        "\u{104E}\u{1004}\u{103A}\u{1038}",
    ),
    // 114
    Rule::Pattern(
        "([\u{102D}\u{102E}])\u{1039}([\u{1000}-\u{1021}])",
        "\u{1039}${2}${1}",
    ),
    // 115
    Rule::Pattern(
        "(\u{103C}\u{1031})\u{1039}([\u{1000}-\u{1021}])",
        "\u{1039}${2}${1}",
    ),
    // 116
    Rule::Pattern("\u{1036}\u{103D}", "\u{103D}\u{1036}"),
    // 117
    Rule::Custom(seven_before_final_or_vowel_is_ra),
];

/// A compiled rule: a regex with its replacement, or a hand-coded scan.
pub(super) enum Step {
    Pattern(regex::Regex, &'static str),
    Custom(fn(&str) -> Option<String>),
}

/// All 118 rules compiled in Rabbit's order; `None` when any pattern fails
/// to compile (conversion then fails closed).
pub(super) static STEPS: LazyLock<Option<Vec<Step>>> = LazyLock::new(compile_steps);

/// Compiles every [`Rule::Pattern`] in `RULES`; any compile error gives `None`.
fn compile_steps() -> Option<Vec<Step>> {
    let mut steps = Vec::with_capacity(RULES.len());
    for rule in &RULES {
        match rule {
            Rule::Pattern(pattern, replacement) => {
                let regex = regex::Regex::new(*pattern).ok()?;
                steps.push(Step::Pattern(regex, *replacement));
            }
            Rule::Custom(func) => {
                steps.push(Step::Custom(*func));
            }
        }
    }
    Some(steps)
}

impl Step {
    /// Applies one step; `None` when the text is unchanged.
    pub(super) fn apply(&self, text: &str) -> Option<String> {
        match self {
            Self::Pattern(regex, replacement) => match regex.replace_all(text, *replacement) {
                Cow::Owned(next) if next.as_str() != text => Some(next),
                _ => None,
            },
            Self::Custom(func) => func(text),
        }
    }
}

/// Rule 0: `([U+102D U+102E U+103D U+102F U+1037 U+1095])\1+` -> `$1`: each
/// run of two or more of the same char from that set becomes one.
pub(super) fn collapse_repeated_marks(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    let mut changed = false;
    while index < chars.len() {
        let current = chars[index];
        if matches!(
            u32::from(current),
            0x102D | 0x102E | 0x103D | 0x102F | 0x1037 | 0x1095
        ) {
            let mut end = index + 1;
            while end < chars.len() && chars[end] == current {
                end += 1;
            }
            if end - index >= 2 {
                out.push(current);
                changed = true;
                index = end;
                continue;
            }
        }
        out.push(current);
        index += 1;
    }
    if changed { Some(out) } else { None }
}

/// Rule 60: `U+1047(?=[U+102C-U+1030 U+1032 U+1036-U+1038 U+103D])` ->
/// `U+101B`: a seven before a vowel reads as RA.
pub(super) fn seven_before_vowel_is_ra(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    let mut index = 0;
    while index < chars.len() {
        let current = chars[index];
        let lookahead = chars.get(index + 1).is_some_and(|&next| {
            matches!(
                u32::from(next),
                0x102C..=0x1030 | 0x1032 | 0x1036..=0x1038 | 0x103D
            )
        });
        if current == '\u{1047}' && lookahead {
            out.push('\u{101B}');
            changed = true;
        } else {
            out.push(current);
        }
        index += 1;
    }
    if changed { Some(out) } else { None }
}

/// Rule 64: `([U+1040-U+1049])U+1040 U+102B(?!U+1038)` -> `$1 U+101D U+102B`:
/// a zero after a digit and before AA reads as WA, unless ASAT follows.
pub(super) fn zero_after_digit_before_aa_is_wa(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    let mut changed = false;
    while index < chars.len() {
        let first_is_digit = matches!(u32::from(chars[index]), 0x1040..=0x1049);
        let second_is_zero = chars.get(index + 1) == Some(&'\u{1040}');
        let third_is_aa = chars.get(index + 2) == Some(&'\u{102B}');
        let blocked = chars.get(index + 3).is_some_and(|&c| c == '\u{1038}');
        if first_is_digit && second_is_zero && third_is_aa && !blocked {
            out.push(chars[index]);
            out.push('\u{101D}');
            out.push('\u{102B}');
            changed = true;
            index += 3;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    if changed { Some(out) } else { None }
}

/// Rule 65: `^U+1040(?=U+102B)` -> `U+101D`: a leading zero before AA reads
/// as WA. Only at index 0 of the text.
pub(super) fn leading_zero_before_aa_is_wa(text: &str) -> Option<String> {
    let rest = text.strip_prefix('\u{1040}')?;
    rest.starts_with('\u{102B}')
        .then(|| format!("\u{101D}{rest}"))
}

/// Rule 66: `U+1040 U+102D(?! ?/)` -> `U+101D U+102D`: a zero before I reads
/// as WA, not when followed by `/` or by space then `/`.
pub(super) fn zero_before_i_is_wa(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    let mut changed = false;
    while index < chars.len() {
        let is_zero_i = chars[index] == '\u{1040}' && chars.get(index + 1) == Some(&'\u{102D}');
        let after = index + 2;
        let blocked = chars.get(after) == Some(&'/')
            || (chars.get(after) == Some(&' ') && chars.get(after + 1) == Some(&'/'));
        if is_zero_i && !blocked {
            out.push('\u{101D}');
            out.push('\u{102D}');
            changed = true;
            index += 2;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    if changed { Some(out) } else { None }
}

/// Rule 68: `([^U+1040-U+1049])U+1040(?=[\f\n\r])` -> `$1 U+101D`: a zero
/// after a non-digit and before a line break reads as WA.
pub(super) fn zero_before_line_break_is_wa(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    let mut changed = false;
    while index < chars.len() {
        let first_ok = !matches!(u32::from(chars[index]), 0x1040..=0x1049);
        let second_is_zero = chars.get(index + 1) == Some(&'\u{1040}');
        let third_is_break = chars
            .get(index + 2)
            .is_some_and(|&c| matches!(c, '\u{C}' | '\n' | '\r'));
        if first_ok && second_is_zero && third_is_break {
            out.push(chars[index]);
            out.push('\u{101D}');
            changed = true;
            index += 2;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    if changed { Some(out) } else { None }
}

/// Rule 69: `([^U+1040-U+1049])U+1040$` -> `$1 U+101D`: a word-final zero
/// reads as WA. The last two chars of the text only.
pub(super) fn final_zero_is_wa(text: &str) -> Option<String> {
    let head = text.strip_suffix('\u{1040}')?;
    let previous = head.chars().next_back()?;
    (!matches!(u32::from(previous), 0x1040..=0x1049)).then(|| format!("{head}\u{101D}"))
}

/// Rule 79: `U+1025(?=U+1037?[U+103A U+102C])` -> `U+1009`: a U before ASAT
/// or AA (with an optional AUKMYINT between) reads as NYA.
pub(super) fn u_before_asat_or_aa_is_nya(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    let mut index = 0;
    while index < chars.len() {
        let current = chars[index];
        let next_is_aukmyint = chars.get(index + 1) == Some(&'\u{1037}');
        let target = if next_is_aukmyint {
            index + 2
        } else {
            index + 1
        };
        let lookahead = chars
            .get(target)
            .is_some_and(|&c| matches!(c, '\u{103A}' | '\u{102C}'));
        if current == '\u{1025}' && lookahead {
            out.push('\u{1009}');
            changed = true;
        } else {
            out.push(current);
        }
        index += 1;
    }
    if changed { Some(out) } else { None }
}

/// Rule 117: `U+1047((?=[U+1000-U+1021]U+103A)|(?=[U+102C-U+1030 U+1032
/// U+1036-U+1038 U+103D U+103E]))` -> `U+101B`: a seven before a kinzi or a
/// vowel reads as RA.
pub(super) fn seven_before_final_or_vowel_is_ra(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    let mut index = 0;
    while index < chars.len() {
        let current = chars[index];
        let kinzi = chars
            .get(index + 1)
            .is_some_and(|&c| matches!(u32::from(c), 0x1000..=0x1021))
            && chars.get(index + 2) == Some(&'\u{103A}');
        let vowel = chars.get(index + 1).is_some_and(|&c| {
            matches!(
                u32::from(c),
                0x102C..=0x1030 | 0x1032 | 0x1036..=0x1038 | 0x103D | 0x103E
            )
        });
        if current == '\u{1047}' && (kinzi || vowel) {
            out.push('\u{101B}');
            changed = true;
        } else {
            out.push(current);
        }
        index += 1;
    }
    if changed { Some(out) } else { None }
}
