/* The peek of a folded sidebar, as state: which microsidebar item's
   sidebar shows over the work area, and which item the pointer rests on
   while the delay runs. Pure, so it is tested without a DOM; the frame
   runs the timer and reads the pointer. */

/* How long the pointer rests on an item before its sidebar shows. */
export const PEEK_DELAY_MS = 150

export interface PeekState {
  /* The item whose sidebar shows over the work area. */
  shownId: string | null
  /* The item the pointer rests on, waiting out the delay. */
  waitingId: string | null
}

export const PEEK_CLOSED: PeekState = { shownId: null, waitingId: null }

export type PeekAction =
  /* The pointer came onto an item. `canPeek`: the sidebar is folded and
     the item has a sidebar to show. */
  | { type: 'enter'; id: string; canPeek: boolean }
  /* The delay ran out while the pointer stayed on the item. */
  | { type: 'elapsed'; id: string }
  /* The pointer left an item or the overlay: into the overlay, onto
     another item (whose enter follows), or anywhere else. */
  | { type: 'leave'; to: 'overlay' | 'item' | 'outside' }
  /* A press on an item: the pointer is acting, not resting. */
  | { type: 'press' }
  /* ArrowRight on a focused item, or a tap: show at once. */
  | { type: 'open'; id: string; canPeek: boolean }
  /* Escape, a press outside, focus leaving, the sidebar opening. */
  | { type: 'close' }

export function peekReducer(state: PeekState, action: PeekAction): PeekState {
  switch (action.type) {
    case 'enter':
      if (!action.canPeek) return state === PEEK_CLOSED ? state : PEEK_CLOSED
      /* An overlay already up switches at once to the item now under the
         pointer; otherwise the delay starts. */
      if (state.shownId !== null) return state.shownId === action.id ? state : { shownId: action.id, waitingId: null }
      return state.waitingId === action.id ? state : { shownId: null, waitingId: action.id }
    case 'elapsed':
      return state.waitingId === action.id ? { shownId: action.id, waitingId: null } : state
    case 'leave':
      if (action.to === 'outside') return state === PEEK_CLOSED ? state : PEEK_CLOSED
      if (action.to === 'overlay') return state.waitingId === null ? state : { ...state, waitingId: null }
      return state
    case 'press':
      return state.waitingId === null ? state : { ...state, waitingId: null }
    case 'open':
      if (!action.canPeek) return state
      return state.shownId === action.id && state.waitingId === null ? state : { shownId: action.id, waitingId: null }
    case 'close':
      return state === PEEK_CLOSED ? state : PEEK_CLOSED
  }
}
