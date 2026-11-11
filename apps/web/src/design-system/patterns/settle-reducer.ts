/* The state machine of one answer. `open` waits for an answer; a pick moves
   it to `pending`, where it can still be undone; when the undo window ends
   it `settled` and stays settled. Pure: the caller owns the timer. */

export type SettleKind = 'answer' | 'later'

export type SettleState =
  | { status: 'open' }
  | { status: 'pending'; value: string; kind: SettleKind }
  | { status: 'settled'; value: string; kind: SettleKind }

export type SettleAction =
  /* An answer was chosen (a pick or a written answer), or the item was set aside. */
  | { type: 'pick'; value: string; kind?: SettleKind }
  /* Undo inside the window: back to open with no answer. */
  | { type: 'undo' }
  /* The window ended: the pending answer stands. */
  | { type: 'commit' }

export const SETTLE_OPEN: SettleState = { status: 'open' }

export function settleReducer(state: SettleState, action: SettleAction): SettleState {
  switch (action.type) {
    case 'pick':
      return state.status === 'open' ? { status: 'pending', value: action.value, kind: action.kind ?? 'answer' } : state
    case 'undo':
      return state.status === 'pending' ? SETTLE_OPEN : state
    case 'commit':
      return state.status === 'pending' ? { status: 'settled', value: state.value, kind: state.kind } : state
  }
}
