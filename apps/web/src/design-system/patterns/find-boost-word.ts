/* Finds a boost word in the text being written: a word (or phrase) that
   asks for more thought on this message. Pure, so it is tested without a
   DOM. */

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/* The first of `words` that stands in `text` as a whole word, ignoring
   case: no letter, digit or underscore touches it on either side. Returns
   the word as given in `words` (the one that starts earliest in the text,
   the longer on a tie), or null. Blank words never match. */
export function findBoostWord(text: string, words: readonly string[]): string | null {
  let best: { word: string; at: number } | null = null
  for (const raw of words) {
    const word = raw.trim()
    if (!word) continue
    const pattern = new RegExp(`(?<![\\p{L}\\p{N}_])${escapeRegExp(word)}(?![\\p{L}\\p{N}_])`, 'iu')
    const match = pattern.exec(text)
    if (!match) continue
    if (!best || match.index < best.at || (match.index === best.at && word.length > best.word.length)) {
      best = { word: raw, at: match.index }
    }
  }
  return best?.word ?? null
}
