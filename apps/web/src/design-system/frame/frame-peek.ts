/* The peek of a folded sidebar, as state: which microsidebar item's
   sidebar shows over the work area, and which item the pointer rests on
   while the delay runs. Pure, so it is tested without a DOM; the frame
   runs the timer and reads the pointer and the layer stack. */

/* How long the pointer rests on an item before its sidebar shows. The
   delay applies to the first show only. */
export const PEEK_DELAY_MS = 150
/* Within this long of a peek hiding because the pointer moved on (onto an
   item without a sidebar, across a gap in the strip), the next item's
   sidebar shows at once. */
export const PEEK_WARM_MS = 400

export interface PeekState {
  /* The item whose sidebar shows over the work area. */
  shownId: string | null
  /* The item the pointer rests on, waiting out the delay. */
  waitingId: string | null
  /* A peek hid a moment ago: the next item shows without the delay. */
  warm: boolean
}

export const PEEK_CLOSED: PeekState = { shownId: null, waitingId: null, warm: false }

/* The pointer moved on from a shown peek: it hides, and stays warm. */
const PEEK_HIDDEN_WARM: PeekState = { shownId: null, waitingId: null, warm: true }

export type PeekAction =
  /* The pointer came onto an item. `canPeek`: the sidebar is folded and
     the item has a sidebar to show. `held`: a menu or popover opened from
     inside the shown peek is open, so the peek stays as it is. */
  | { type: 'enter'; id: string; canPeek: boolean; held?: boolean }
  /* The delay ran out while the pointer stayed on the item. */
  | { type: 'elapsed'; id: string }
  /* The pointer left an item or the overlay: into the overlay, onto
     another item (whose enter follows), or anywhere else. `held` as for
     enter. */
  | { type: 'leave'; to: 'overlay' | 'item' | 'outside'; held?: boolean }
  /* The warm window ran out. */
  | { type: 'cool' }
  /* A press on an item: the pointer is acting, not resting. */
  | { type: 'press' }
  /* ArrowRight on a focused item, or a tap: show at once. */
  | { type: 'open'; id: string; canPeek: boolean }
  /* Escape, a press outside, focus leaving, the sidebar opening. */
  | { type: 'close' }

export function peekReducer(state: PeekState, action: PeekAction): PeekState {
  switch (action.type) {
    case 'enter':
      if (action.held && state.shownId !== null) return state
      if (!action.canPeek) {
        /* An item without a sidebar shows its tooltip and no peek. */
        if (state.shownId !== null) return PEEK_HIDDEN_WARM
        return state.waitingId === null ? state : { ...state, waitingId: null }
      }
      /* A peek that shows, or hid a moment ago, switches at once to the
         item now under the pointer; otherwise the delay starts. */
      if (state.shownId !== null || state.warm) {
        return state.shownId === action.id ? state : { shownId: action.id, waitingId: null, warm: false }
      }
      return state.waitingId === action.id ? state : { ...state, waitingId: action.id }
    case 'elapsed':
      return state.waitingId === action.id ? { shownId: action.id, waitingId: null, warm: false } : state
    case 'leave':
      if (action.held && state.shownId !== null) return state
      if (action.to === 'outside') {
        if (state.shownId !== null) return PEEK_HIDDEN_WARM
        return state.waitingId === null ? state : { ...state, waitingId: null }
      }
      if (action.to === 'overlay') return state.waitingId === null ? state : { ...state, waitingId: null }
      return state
    case 'cool':
      return state.warm ? { ...state, warm: false } : state
    case 'press':
      return state.waitingId === null ? state : { ...state, waitingId: null }
    case 'open':
      if (!action.canPeek) return state
      return state.shownId === action.id && state.waitingId === null
        ? state
        : { shownId: action.id, waitingId: null, warm: false }
    case 'close':
      return state === PEEK_CLOSED ? state : PEEK_CLOSED
  }
}
