//! The Mandarin reading (`cmn`): Han characters through their pinyin (the
//! `pinyin` crate's data, MIT), and Latin words that parse as pinyin
//! syllables. Toneless: PanPhon's features carry no tone (CROSS-ARCH-0013
//! `#intl-cautions`). Han is read as Mandarin only, tagged so; it is not "the
//! Han sound" (no Cantonese or Japanese reading is guessed).

use pinyin::{Pinyin, ToPinyinMulti};

use super::super::features::{Segment, ipa_segments};
use super::MAX_READINGS;

/// Initials, longest first, with their IPA.
const INITIALS: [(&str, &str); 21] = [
    ("zh", "ʈ͡ʂ"),
    ("ch", "ʈ͡ʂʰ"),
    ("sh", "ʂ"),
    ("b", "p"),
    ("p", "pʰ"),
    ("m", "m"),
    ("f", "f"),
    ("d", "t"),
    ("t", "tʰ"),
    ("n", "n"),
    ("l", "l"),
    ("g", "k"),
    ("k", "kʰ"),
    ("h", "x"),
    ("j", "t͡ɕ"),
    ("q", "t͡ɕʰ"),
    ("x", "ɕ"),
    ("r", "ʐ"),
    ("z", "t͡s"),
    ("c", "t͡sʰ"),
    ("s", "s"),
];

/// Finals as the pinyin table writes them (before the y-, w- and iu, ui, un
/// spellings), with their IPA.
const FINALS: [(&str, &str); 39] = [
    ("a", "a"),
    ("o", "o"),
    ("e", "ɤ"),
    ("ê", "ɛ"),
    ("ai", "ai"),
    ("ei", "ei"),
    ("ao", "au"),
    ("ou", "ou"),
    ("an", "an"),
    ("en", "ən"),
    ("ang", "aŋ"),
    ("eng", "əŋ"),
    ("ong", "ʊŋ"),
    ("er", "əɻ"),
    ("i", "i"),
    ("ia", "ja"),
    ("io", "jo"),
    ("ie", "je"),
    ("iao", "jau"),
    ("iou", "jou"),
    ("ian", "jɛn"),
    ("in", "in"),
    ("iang", "jaŋ"),
    ("ing", "iŋ"),
    ("iong", "jʊŋ"),
    ("u", "u"),
    ("ua", "wa"),
    ("uo", "wo"),
    ("uai", "wai"),
    ("uei", "wei"),
    ("uan", "wan"),
    ("uen", "wən"),
    ("uang", "waŋ"),
    ("ueng", "wəŋ"),
    ("uong", "wʊŋ"),
    ("ü", "y"),
    ("üe", "ɥe"),
    ("üan", "ɥɛn"),
    ("ün", "yn"),
];

/// Syllables that are a sound of their own: syllabic nasals and ê.
const WHOLE_SYLLABLES: [(&str, &str); 6] = [
    ("m", "m"),
    ("n", "n"),
    ("ng", "ŋ"),
    ("hm", "hm"),
    ("hng", "hŋ"),
    ("ê", "ɛ"),
];

/// Whether `c` has a Mandarin reading: a Han character.
pub(super) fn has_mandarin_reading(c: char) -> bool {
    c.to_pinyin_multi().is_some()
}

/// Up to [`MAX_READINGS`] readings of a run of Han characters: every
/// character's first reading, then one other reading of one character at a
/// time, in order.
pub(super) fn han_readings(han: &str) -> Vec<Vec<Segment>> {
    let choices: Vec<Vec<Vec<Segment>>> = han
        .chars()
        .filter_map(|c| c.to_pinyin_multi())
        .map(|readings| {
            let mut distinct: Vec<Vec<Segment>> = Vec::new();
            for segments in readings
                .into_iter()
                .filter_map(|reading| syllable_segments(Pinyin::plain(reading)))
            {
                if !distinct.contains(&segments) {
                    distinct.push(segments);
                }
            }
            distinct
        })
        .filter(|distinct| !distinct.is_empty())
        .collect();
    if choices.is_empty() {
        return Vec::new();
    }
    let with_choice = |swapped: usize, choice: usize| -> Vec<Segment> {
        choices
            .iter()
            .enumerate()
            .flat_map(|(at, character)| &character[if at == swapped { choice } else { 0 }])
            .copied()
            .collect()
    };
    let mut readings = vec![with_choice(0, 0)];
    for (swapped, character) in choices.iter().enumerate() {
        for choice in 1..character.len() {
            if readings.len() == MAX_READINGS {
                return readings;
            }
            readings.push(with_choice(swapped, choice));
        }
    }
    readings
}

/// The reading of Latin words when every one of them parses as pinyin
/// syllables, `None` otherwise. `v` stands for ü.
pub(super) fn latin_reading(words: &[&str]) -> Option<Vec<Segment>> {
    let mut segments = Vec::new();
    for word in words {
        segments.extend(word_reading(word)?);
    }
    (!segments.is_empty()).then_some(segments)
}

/// One word read as pinyin syllables: at each position the longest syllable
/// after which the rest of the word still parses.
fn word_reading(word: &str) -> Option<Vec<Segment>> {
    if !word.is_ascii() {
        return None;
    }
    // parsed[i]: the reading of word[i..], when it parses.
    let mut parsed: Vec<Option<Vec<Segment>>> = vec![None; word.len() + 1];
    parsed[word.len()] = Some(Vec::new());
    for start in (0..word.len()).rev() {
        let rest = &word[start..];
        let mut syllables: Vec<&str> = LATIN_SYLLABLES
            .iter()
            .copied()
            .filter(|syllable| rest.starts_with(*syllable))
            .collect();
        syllables.sort_by_key(|syllable| std::cmp::Reverse(syllable.len()));
        parsed[start] = syllables.into_iter().find_map(|syllable| {
            let tail = parsed[start + syllable.len()].as_ref()?;
            let mut segments = syllable_segments(syllable)?;
            segments.extend(tail);
            Some(segments)
        });
    }
    parsed[0].take().filter(|segments| !segments.is_empty())
}

/// The segments of one toneless pinyin syllable.
fn syllable_segments(syllable: &str) -> Option<Vec<Segment>> {
    let syllable = syllable.replace('v', "ü");
    if let Some((_, ipa)) = WHOLE_SYLLABLES.iter().find(|(whole, _)| *whole == syllable) {
        return ipa_segments(ipa);
    }
    let (initial, initial_ipa) = INITIALS
        .into_iter()
        .find(|(name, _)| syllable.starts_with(*name))
        .unwrap_or(("", ""));
    let spelled = standard_final(initial, &syllable[initial.len()..]);
    let final_ipa = match (initial, spelled.as_str()) {
        ("z" | "c" | "s", "i") => "ɹ̩",
        ("zh" | "ch" | "sh" | "r", "i") => "ɻ̩",
        (_, spelled) => FINALS.iter().find(|(name, _)| *name == spelled)?.1,
    };
    ipa_segments(&format!("{initial_ipa}{final_ipa}"))
}

/// The final as the pinyin table writes it: y- and w- spell a glide, u after
/// j, q, x and y is ü, and iu, ui and un stand for iou, uei and uen.
fn standard_final(initial: &str, rest: &str) -> String {
    if initial.is_empty() {
        if let Some(after) = rest.strip_prefix('y') {
            return match after.strip_prefix('u') {
                Some(after_u) => format!("ü{after_u}"),
                None if after.starts_with('i') => after.to_owned(),
                None => format!("i{after}"),
            };
        }
        if let Some(after) = rest.strip_prefix('w') {
            return if after == "u" {
                after.to_owned()
            } else {
                format!("u{after}")
            };
        }
        return rest.to_owned();
    }
    if matches!(initial, "j" | "q" | "x")
        && let Some(after_u) = rest.strip_prefix('u')
    {
        return format!("ü{after_u}");
    }
    match rest {
        "iu" => "iou",
        "ui" => "uei",
        "un" => "uen",
        _ => rest,
    }
    .to_owned()
}

/// Every pinyin syllable the `pinyin` crate's data reads a character as,
/// toneless, ü written v, without the syllabic nasals and ê: the syllables a
/// Latin word is read in.
const LATIN_SYLLABLES: [&str; 420] = [
    "a", "ai", "an", "ang", "ao", "ba", "bai", "ban", "bang", "bao", "bei", "ben", "beng", "bi",
    "bian", "biang", "biao", "bie", "bin", "bing", "bo", "bong", "bu", "ca", "cai", "can", "cang",
    "cao", "ce", "cei", "cen", "ceng", "cha", "chai", "chan", "chang", "chao", "che", "chen",
    "cheng", "chi", "chong", "chou", "chu", "chua", "chuai", "chuan", "chuang", "chui", "chun",
    "chuo", "ci", "cong", "cou", "cu", "cuan", "cui", "cun", "cuo", "da", "dai", "dan", "dang",
    "dao", "de", "dei", "den", "deng", "di", "dia", "dian", "diao", "die", "din", "ding", "diu",
    "dong", "dou", "du", "duan", "dui", "dun", "duo", "e", "ei", "en", "eng", "er", "fa", "fan",
    "fang", "fei", "fen", "feng", "fiao", "fo", "fou", "fu", "ga", "gai", "gan", "gang", "gao",
    "ge", "gei", "gen", "geng", "gong", "gou", "gu", "gua", "guai", "guan", "guang", "gui", "gun",
    "guo", "ha", "hai", "han", "hang", "hao", "he", "hei", "hen", "heng", "hong", "hou", "hu",
    "hua", "huai", "huan", "huang", "hui", "hun", "huo", "ji", "jia", "jian", "jiang", "jiao",
    "jie", "jin", "jing", "jiong", "jiu", "ju", "juan", "jue", "jun", "ka", "kai", "kan", "kang",
    "kao", "ke", "kei", "ken", "keng", "kong", "kou", "ku", "kua", "kuai", "kuan", "kuang", "kui",
    "kun", "kuo", "la", "lai", "lan", "lang", "lao", "le", "lei", "len", "leng", "li", "lia",
    "lian", "liang", "liao", "lie", "lin", "ling", "liu", "lo", "long", "lou", "lu", "luan", "lun",
    "luo", "lv", "lve", "ma", "mai", "man", "mang", "mao", "me", "mei", "men", "meng", "mi",
    "mian", "miao", "mie", "min", "ming", "miu", "mo", "mou", "mu", "na", "nai", "nan", "nang",
    "nao", "ne", "nei", "nen", "neng", "ni", "nia", "nian", "niang", "niao", "nie", "nin", "ning",
    "niu", "nong", "nou", "nu", "nuan", "nun", "nuo", "nv", "nve", "o", "ou", "pa", "pai", "pan",
    "pang", "pao", "pei", "pen", "peng", "pi", "pian", "piao", "pie", "pin", "ping", "po", "pou",
    "pu", "qi", "qia", "qian", "qiang", "qiao", "qie", "qin", "qing", "qiong", "qiu", "qu", "quan",
    "que", "qun", "ran", "rang", "rao", "re", "ren", "reng", "ri", "rong", "rou", "ru", "rua",
    "ruan", "rui", "run", "ruo", "sa", "sai", "san", "sang", "sao", "se", "sen", "seng", "sha",
    "shai", "shan", "shang", "shao", "she", "shei", "shen", "sheng", "shi", "shou", "shu", "shua",
    "shuai", "shuan", "shuang", "shui", "shun", "shuo", "si", "song", "sou", "su", "suan", "sui",
    "sun", "suo", "ta", "tai", "tan", "tang", "tao", "te", "tei", "teng", "ti", "tian", "tiao",
    "tie", "ting", "tong", "tou", "tu", "tuan", "tui", "tun", "tuo", "wa", "wai", "wan", "wang",
    "wei", "wen", "weng", "wo", "wong", "wu", "xi", "xia", "xian", "xiang", "xiao", "xie", "xin",
    "xing", "xiong", "xiu", "xu", "xuan", "xue", "xun", "ya", "yan", "yang", "yao", "ye", "yi",
    "yin", "ying", "yo", "yong", "you", "yu", "yuan", "yue", "yun", "za", "zai", "zan", "zang",
    "zao", "ze", "zei", "zen", "zeng", "zha", "zhai", "zhan", "zhang", "zhao", "zhe", "zhei",
    "zhen", "zheng", "zhi", "zhong", "zhou", "zhu", "zhua", "zhuai", "zhuan", "zhuang", "zhui",
    "zhun", "zhuo", "zi", "zong", "zou", "zu", "zuan", "zui", "zun", "zuo",
];
