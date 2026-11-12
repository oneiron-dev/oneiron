/* What a key does in a write box, and what a send carries. Pure, so the
   rules can be tested without a page. */

export interface ComposerKeyState {
  shiftKey: boolean
  /* An input method is composing (a kana or pinyin candidate is open). */
  isComposing: boolean
}

/* Enter sends; Shift+Enter is a new line (in a field that has lines);
   Enter while an input method composes belongs to the input method. */
export function composerKeySends(key: string, state: ComposerKeyState): boolean {
  return key === 'Enter' && !state.shiftKey && !state.isComposing
}

/* The text a send carries: trimmed, or null when there is nothing to send. */
export function composerSendText(value: string): string | null {
  const text = value.trim()
  return text ? text : null
}
