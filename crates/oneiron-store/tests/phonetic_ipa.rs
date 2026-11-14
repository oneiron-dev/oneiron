//! L10-08 (CROSS-ARCH-0013 `#ladder` rung 1, G2P → IPA → NPD): the readings
//! of a name and the Normalized Phonetic Distance between two readings. On
//! main the new names do not exist, so this file's red there is a compile
//! red.

use oneiron_base::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SECRET_CUSTODY};
use oneiron_store::batch::phonetic_codes::{
    NPD_CAP, NPD_KEEP_RATIO, NPD_THRESHOLD, Segment, codes_for_body, ipa_segments, npd,
    phonetic_readings, strip_org_suffix,
};

/// The reading of `name` in `lang`; the test fails when there is none.
fn reading(name: &str, lang: &str) -> Vec<Segment> {
    phonetic_readings(name)
        .into_iter()
        .find(|reading| reading.lang == lang)
        .map(|reading| reading.segments)
        .unwrap_or_else(|| {
            panic!(
                "{name:?} has no {lang} reading: {:?}",
                phonetic_readings(name)
            )
        })
}

/// The segments of an IPA string; the test fails when it does not parse.
fn segments(ipa: &str) -> Vec<Segment> {
    ipa_segments(ipa).unwrap_or_else(|| panic!("{ipa:?} does not parse"))
}

#[test]
fn the_pinyin_spelling_reads_as_its_han_name() {
    let latin = reading("Xiaoming", "cmn");
    let han = reading("小明", "cmn");
    assert_eq!(latin, segments("ɕjaumiŋ"));
    assert_eq!(latin, han);
    assert_eq!(npd(&latin, &han), 0.0);
}

#[test]
fn l_and_r_are_near_and_t_and_k_are_far() {
    let near = npd(&segments("eili"), &segments("eiɾi"));
    let far = npd(&segments("eiti"), &segments("eiki"));
    assert!(near < far, "l/ɾ {near} against t/k {far}");
    assert!(near < 0.05, "l/ɾ {near}");
    assert_eq!(npd(&segments("eili"), &segments("eili")), 0.0);
}

#[test]
fn kana_long_vowels_and_romaji_agree() {
    let kana = reading("さとう", "jpn");
    assert_eq!(kana, segments("satoː"));
    assert_eq!(kana, reading("Satou", "jpn"));
    assert_eq!(reading("サトウ", "jpn"), kana);
}

#[test]
fn an_org_suffix_carries_no_sound() {
    let kana = reading("株式会社みらい", "jpn");
    assert_eq!(kana, segments("miɾai"));
    assert_eq!(reading("Mirai KK", "jpn"), kana);
    assert_eq!(reading("Mirai Inc.", "jpn"), kana);
    assert_eq!(strip_org_suffix("Mirai Inc."), "Mirai");
    assert_eq!(strip_org_suffix("株式会社"), "株式会社");
    assert!(!phonetic_readings("株式会社").is_empty());
}

#[test]
fn hangul_reads_by_jamo() {
    assert_eq!(reading("한글", "kor"), segments("hanɡɯl"));
}

#[test]
fn secret_custody_gets_no_sound_key() {
    let body = rmp_serde::to_vec_named(&serde_json::json!({ "name": "小明" })).expect("body");
    assert!(codes_for_body(ENTITY_TYPE_SECRET_CUSTODY, &body).is_empty());
    let person = codes_for_body(ENTITY_TYPE_PERSON, &body);
    assert!(
        person.iter().any(|code| code.starts_with("ipa:cmn:")),
        "{person:?}"
    );
}

#[test]
fn english_reads_by_the_nrl_rules() {
    assert_eq!(reading("Smith", "eng"), segments("smɪθ"));
    assert_eq!(reading("Showming", "eng"), segments("ʃoʊmɪŋ"));
}

#[test]
fn a_misheard_name_is_near_and_another_name_is_far() {
    let name = reading("さとう", "jpn");
    let misheard = npd(&reading("Sadou", "jpn"), &name);
    let other = npd(&reading("Takeshi", "jpn"), &name);
    assert!(misheard < NPD_THRESHOLD, "Sadou {misheard}");
    assert!(other > NPD_THRESHOLD, "Takeshi {other}");
    assert_eq!((NPD_THRESHOLD, NPD_KEEP_RATIO, NPD_CAP), (0.2, 1.2, 10));
}

#[test]
fn han_heteronyms_give_at_most_four_readings() {
    let readings: Vec<String> = phonetic_readings("重行")
        .into_iter()
        .map(|reading| format!("{}:{}", reading.lang, reading.ipa()))
        .collect();
    assert_eq!(
        readings,
        ["cmn:ʈ͡ʂʊŋɕiŋ", "cmn:ʈ͡ʂʰʊŋɕiŋ", "cmn:tʰʊŋɕiŋ", "cmn:ʈ͡ʂʊŋxaŋ"]
    );
}

#[test]
fn runs_of_two_scripts_join_as_one_mixed_reading() {
    let readings = phonetic_readings("トヨタ自動車");
    assert!(!readings.is_empty());
    assert!(
        readings.iter().all(|reading| reading.lang == "mul"),
        "{readings:?}"
    );
    assert!(readings[0].ipa().starts_with("tojota"), "{readings:?}");
}

#[test]
fn every_kana_syllable_reads() {
    for kana in [
        "あいうえお かきくけこ がぎぐげご さしすせそ ざじずぜぞ たちつてと だぢづでど",
        "なにぬねの はひふへほ ばびぶべぼ ぱぴぷぺぽ まみむめも やゆよ らりるれろ わをん ゔ",
        "きゃきゅきょ しゃしゅしょ ちゃちゅちょ にゃりゅぴょ じゃじゅじょ",
        "ふぁふぃふぇふぉ てぃでぃ とぅどぅ うぃうぇうぉ つぁつぉ くぁぐぉ",
        "がっこう いっしょ まっちゃ らーめん ヴァイオリン カタカナ",
    ] {
        for word in kana.split(' ') {
            reading(word, "jpn");
        }
    }
}

#[test]
fn every_pinyin_syllable_reads() {
    for syllable in PINYIN_SYLLABLES.split_whitespace() {
        reading(syllable, "cmn");
    }
}

/// Every syllable the `pinyin` crate's data writes, toneless, ü as v, without
/// the syllabic nasals and ê.
const PINYIN_SYLLABLES: &str = "
    a ai an ang ao ba bai ban bang bao bei ben beng bi bian biang biao bie
    bin bing bo bong bu ca cai can cang cao ce cei cen ceng cha chai chan chang chao che
    chen cheng chi chong chou chu chua chuai chuan chuang chui chun chuo ci cong cou cu
    cuan cui cun cuo da dai dan dang dao de dei den deng di dia dian diao die din ding diu
    dong dou du duan dui dun duo e ei en eng er fa fan fang fei fen feng fiao fo fou fu ga
    gai gan gang gao ge gei gen geng gong gou gu gua guai guan guang gui gun guo ha hai han
    hang hao he hei hen heng hong hou hu hua huai huan huang hui hun huo ji jia jian jiang
    jiao jie jin jing jiong jiu ju juan jue jun ka kai kan kang kao ke kei ken keng kong
    kou ku kua kuai kuan kuang kui kun kuo la lai lan lang lao le lei len leng li lia lian
    liang liao lie lin ling liu lo long lou lu luan lun luo lv lve ma mai man mang mao me
    mei men meng mi mian miao mie min ming miu mo mou mu na nai nan nang nao ne nei nen
    neng ni nia nian niang niao nie nin ning niu nong nou nu nuan nun nuo nv nve o ou pa
    pai pan pang pao pei pen peng pi pian piao pie pin ping po pou pu qi qia qian qiang
    qiao qie qin qing qiong qiu qu quan que qun ran rang rao re ren reng ri rong rou ru rua
    ruan rui run ruo sa sai san sang sao se sen seng sha shai shan shang shao she shei shen
    sheng shi shou shu shua shuai shuan shuang shui shun shuo si song sou su suan sui sun
    suo ta tai tan tang tao te tei teng ti tian tiao tie ting tong tou tu tuan tui tun tuo
    wa wai wan wang wei wen weng wo wong wu xi xia xian xiang xiao xie xin xing xiong xiu
    xu xuan xue xun ya yan yang yao ye yi yin ying yo yong you yu yuan yue yun za zai zan
    zang zao ze zei zen zeng zha zhai zhan zhang zhao zhe zhei zhen zheng zhi zhong zhou
    zhu zhua zhuai zhuan zhuang zhui zhun zhuo zi zong zou zu zuan zui zun zuo
";
